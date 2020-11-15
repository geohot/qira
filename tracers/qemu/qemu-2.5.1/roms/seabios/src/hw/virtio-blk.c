// Virtio block boot support.
//
// Copyright (C) 2010 Red Hat Inc.
//
// Authors:
//  Gleb Natapov <gnatapov@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBALFLAT
#include "config.h" // CONFIG_*
#include "block.h" // struct drive_s
#include "malloc.h" // free
#include "output.h" // dprintf
#include "pci.h" // foreachpci
#include "pci_ids.h" // PCI_DEVICE_ID_VIRTIO_BLK
#include "pci_regs.h" // PCI_VENDOR_ID
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "util.h" // usleep
#include "virtio-pci.h"
#include "virtio-ring.h"
#include "virtio-blk.h"

struct virtiodrive_s {
    struct drive_s drive;
    struct vring_virtqueue *vq;
    u16 ioaddr;
};

static int
virtio_blk_op(struct disk_op_s *op, int write)
{
    struct virtiodrive_s *vdrive_gf =
        container_of(op->drive_gf, struct virtiodrive_s, drive);
    struct vring_virtqueue *vq = GET_GLOBALFLAT(vdrive_gf->vq);
    struct virtio_blk_outhdr hdr = {
        .type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN,
        .ioprio = 0,
        .sector = op->lba,
    };
    u8 status = VIRTIO_BLK_S_UNSUPP;
    struct vring_list sg[] = {
        {
            .addr       = MAKE_FLATPTR(GET_SEG(SS), &hdr),
            .length     = sizeof(hdr),
        },
        {
            .addr       = op->buf_fl,
            .length     = GET_GLOBALFLAT(vdrive_gf->drive.blksize) * op->count,
        },
        {
            .addr       = MAKE_FLATPTR(GET_SEG(SS), &status),
            .length     = sizeof(status),
        },
    };

    /* Add to virtqueue and kick host */
    if (write)
        vring_add_buf(vq, sg, 2, 1, 0, 0);
    else
        vring_add_buf(vq, sg, 1, 2, 0, 0);
    vring_kick(GET_GLOBALFLAT(vdrive_gf->ioaddr), vq, 1);

    /* Wait for reply */
    while (!vring_more_used(vq))
        usleep(5);

    /* Reclaim virtqueue element */
    vring_get_buf(vq, NULL);

    /* Clear interrupt status register.  Avoid leaving interrupts stuck if
     * VRING_AVAIL_F_NO_INTERRUPT was ignored and interrupts were raised.
     */
    vp_get_isr(GET_GLOBALFLAT(vdrive_gf->ioaddr));

    return status == VIRTIO_BLK_S_OK ? DISK_RET_SUCCESS : DISK_RET_EBADTRACK;
}

int
process_virtio_blk_op(struct disk_op_s *op)
{
    if (! CONFIG_VIRTIO_BLK)
        return 0;
    switch (op->command) {
    case CMD_READ:
        return virtio_blk_op(op, 0);
    case CMD_WRITE:
        return virtio_blk_op(op, 1);
    case CMD_FORMAT:
    case CMD_RESET:
    case CMD_ISREADY:
    case CMD_VERIFY:
    case CMD_SEEK:
        return DISK_RET_SUCCESS;
    default:
        return DISK_RET_EPARAM;
    }
}

static void
init_virtio_blk(struct pci_device *pci)
{
    u16 bdf = pci->bdf;
    dprintf(1, "found virtio-blk at %x:%x\n", pci_bdf_to_bus(bdf),
            pci_bdf_to_dev(bdf));
    struct virtiodrive_s *vdrive = malloc_fseg(sizeof(*vdrive));
    if (!vdrive) {
        warn_noalloc();
        return;
    }
    memset(vdrive, 0, sizeof(*vdrive));
    vdrive->drive.type = DTYPE_VIRTIO_BLK;
    vdrive->drive.cntl_id = bdf;

    u16 ioaddr = vp_init_simple(bdf);
    vdrive->ioaddr = ioaddr;
    if (vp_find_vq(ioaddr, 0, &vdrive->vq) < 0 ) {
        dprintf(1, "fail to find vq for virtio-blk %x:%x\n",
                pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf));
        goto fail;
    }

    struct virtio_blk_config cfg;
    vp_get(ioaddr, 0, &cfg, sizeof(cfg));

    u32 f = vp_get_features(ioaddr);
    vdrive->drive.blksize = (f & (1 << VIRTIO_BLK_F_BLK_SIZE)) ?
        cfg.blk_size : DISK_SECTOR_SIZE;

    vdrive->drive.sectors = cfg.capacity;
    dprintf(3, "virtio-blk %x:%x blksize=%d sectors=%u\n",
            pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf),
            vdrive->drive.blksize, (u32)vdrive->drive.sectors);

    if (vdrive->drive.blksize != DISK_SECTOR_SIZE) {
        dprintf(1, "virtio-blk %x:%x block size %d is unsupported\n",
                pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf),
                vdrive->drive.blksize);
        goto fail;
    }

    vdrive->drive.pchs.cylinder = cfg.cylinders;
    vdrive->drive.pchs.head = cfg.heads;
    vdrive->drive.pchs.sector = cfg.sectors;
    char *desc = znprintf(MAXDESCSIZE, "Virtio disk PCI:%x:%x",
                          pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf));

    boot_add_hd(&vdrive->drive, desc, bootprio_find_pci_device(pci));

    vp_set_status(ioaddr, VIRTIO_CONFIG_S_ACKNOWLEDGE |
                  VIRTIO_CONFIG_S_DRIVER | VIRTIO_CONFIG_S_DRIVER_OK);
    return;

fail:
    vp_reset(ioaddr);
    free(vdrive->vq);
    free(vdrive);
}

void
virtio_blk_setup(void)
{
    ASSERT32FLAT();
    if (! CONFIG_VIRTIO_BLK)
        return;

    dprintf(3, "init virtio-blk\n");

    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->vendor != PCI_VENDOR_ID_REDHAT_QUMRANET
            || pci->device != PCI_DEVICE_ID_VIRTIO_BLK)
            continue;
        init_virtio_blk(pci);
    }
}
