// (qemu-emulated) lsi53c895a boot support.
//
// Copyright (C) 2012 Red Hat Inc.
//
// Authors:
//  Gerd Hoffmann <kraxel@redhat.com>
//
// based on virtio-scsi.c which is written by:
//  Paolo Bonzini <pbonzini@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBALFLAT
#include "block.h" // struct drive_s
#include "blockcmd.h" // scsi_drive_setup
#include "config.h" // CONFIG_*
#include "fw/paravirt.h" // runningOnQEMU
#include "malloc.h" // free
#include "output.h" // dprintf
#include "pci.h" // foreachpci
#include "pci_ids.h" // PCI_DEVICE_ID_VIRTIO_BLK
#include "pci_regs.h" // PCI_VENDOR_ID
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "util.h" // usleep

#define LSI_REG_DSTAT     0x0c
#define LSI_REG_ISTAT0    0x14
#define LSI_REG_DSP0      0x2c
#define LSI_REG_DSP1      0x2d
#define LSI_REG_DSP2      0x2e
#define LSI_REG_DSP3      0x2f
#define LSI_REG_SIST0     0x42
#define LSI_REG_SIST1     0x43

#define LSI_ISTAT0_DIP    0x01
#define LSI_ISTAT0_SIP    0x02
#define LSI_ISTAT0_INTF   0x04
#define LSI_ISTAT0_CON    0x08
#define LSI_ISTAT0_SEM    0x10
#define LSI_ISTAT0_SIGP   0x20
#define LSI_ISTAT0_SRST   0x40
#define LSI_ISTAT0_ABRT   0x80

struct lsi_lun_s {
    struct drive_s drive;
    struct pci_device *pci;
    u32 iobase;
    u8 target;
    u8 lun;
};

static int
lsi_scsi_cmd(struct lsi_lun_s *llun_gf, struct disk_op_s *op,
             void *cdbcmd, u16 target, u16 lun, u16 blocksize)
{
    u32 iobase = GET_GLOBALFLAT(llun_gf->iobase);
    u32 dma = ((cdb_is_read(cdbcmd, blocksize) ? 0x01000000 : 0x00000000) |
               (op->count * blocksize));
    u8 msgout[] = {
        0x80 | lun,                 // select lun
        0x08,
    };
    u8 status = 0xff;
    u8 msgin_tmp[2];
    u8 msgin = 0xff;

    u32 script[] = {
        /* select target, send scsi command */
        0x40000000 | target << 16,  // select target
        0x00000000,
        0x06000001,                 // msgout
        (u32)MAKE_FLATPTR(GET_SEG(SS), &msgout),
        0x02000010,                 // scsi command
        (u32)MAKE_FLATPTR(GET_SEG(SS), cdbcmd),

        /* handle disconnect */
        0x87820000,                 // phase == msgin ?
        0x00000018,
        0x07000002,                 // msgin
        (u32)MAKE_FLATPTR(GET_SEG(SS), &msgin_tmp),
        0x50000000,                 // re-select
        0x00000000,
        0x07000002,                 // msgin
        (u32)MAKE_FLATPTR(GET_SEG(SS), &msgin_tmp),

        /* dma data, get status, raise irq */
        dma,                        // dma data
        (u32)op->buf_fl,
        0x03000001,                 // status
        (u32)MAKE_FLATPTR(GET_SEG(SS), &status),
        0x07000001,                 // msgin
        (u32)MAKE_FLATPTR(GET_SEG(SS), &msgin),
        0x98080000,                 // dma irq
        0x00000000,
    };
    u32 dsp = (u32)MAKE_FLATPTR(GET_SEG(SS), &script);

    outb(dsp         & 0xff, iobase + LSI_REG_DSP0);
    outb((dsp >>  8) & 0xff, iobase + LSI_REG_DSP1);
    outb((dsp >> 16) & 0xff, iobase + LSI_REG_DSP2);
    outb((dsp >> 24) & 0xff, iobase + LSI_REG_DSP3);

    for (;;) {
        u8 dstat = inb(iobase + LSI_REG_DSTAT);
        u8 sist0 = inb(iobase + LSI_REG_SIST0);
        u8 sist1 = inb(iobase + LSI_REG_SIST1);
        if (sist0 || sist1) {
            goto fail;
        }
        if (dstat & 0x04) {
            break;
        }
        usleep(5);
    }

    if (msgin == 0 && status == 0) {
        return DISK_RET_SUCCESS;
    }

fail:
    return DISK_RET_EBADTRACK;
}

int
lsi_scsi_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize)
{
    if (!CONFIG_LSI_SCSI)
        return DISK_RET_EBADTRACK;

    struct lsi_lun_s *llun_gf =
        container_of(op->drive_gf, struct lsi_lun_s, drive);

    return lsi_scsi_cmd(llun_gf, op, cdbcmd,
                        GET_GLOBALFLAT(llun_gf->target),
                        GET_GLOBALFLAT(llun_gf->lun),
                        blocksize);
}

static int
lsi_scsi_add_lun(struct pci_device *pci, u32 iobase, u8 target, u8 lun)
{
    struct lsi_lun_s *llun = malloc_fseg(sizeof(*llun));
    if (!llun) {
        warn_noalloc();
        return -1;
    }
    memset(llun, 0, sizeof(*llun));
    llun->drive.type = DTYPE_LSI_SCSI;
    llun->drive.cntl_id = pci->bdf;
    llun->pci = pci;
    llun->target = target;
    llun->lun = lun;
    llun->iobase = iobase;

    char *name = znprintf(16, "lsi %02x:%02x.%x %d:%d",
                          pci_bdf_to_bus(pci->bdf), pci_bdf_to_dev(pci->bdf),
                          pci_bdf_to_fn(pci->bdf), target, lun);
    int prio = bootprio_find_scsi_device(pci, target, lun);
    int ret = scsi_drive_setup(&llun->drive, name, prio);
    free(name);
    if (ret)
        goto fail;
    return 0;

fail:
    free(llun);
    return -1;
}

static void
lsi_scsi_scan_target(struct pci_device *pci, u32 iobase, u8 target)
{
    /* TODO: send REPORT LUNS.  For now, only LUN 0 is recognized.  */
    lsi_scsi_add_lun(pci, iobase, target, 0);
}

static void
init_lsi_scsi(struct pci_device *pci)
{
    u16 bdf = pci->bdf;
    u32 iobase = pci_config_readl(pci->bdf, PCI_BASE_ADDRESS_0)
        & PCI_BASE_ADDRESS_IO_MASK;

    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_MASTER);

    dprintf(1, "found lsi53c895a at %02x:%02x.%x, io @ %x\n",
            pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf),
            pci_bdf_to_fn(bdf), iobase);

    // reset
    outb(LSI_ISTAT0_SRST, iobase + LSI_REG_ISTAT0);

    int i;
    for (i = 0; i < 7; i++)
        lsi_scsi_scan_target(pci, iobase, i);

    return;
}

void
lsi_scsi_setup(void)
{
    ASSERT32FLAT();
    if (!CONFIG_LSI_SCSI || !runningOnQEMU())
        return;

    dprintf(3, "init lsi53c895a\n");

    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->vendor != PCI_VENDOR_ID_LSI_LOGIC
            || pci->device != PCI_DEVICE_ID_LSI_53C895A)
            continue;
        init_lsi_scsi(pci);
    }
}
