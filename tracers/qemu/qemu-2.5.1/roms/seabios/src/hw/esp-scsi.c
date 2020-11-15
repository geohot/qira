// AMD PCscsi boot support.
//
// Copyright (C) 2012 Red Hat Inc.
//
// Authors:
//  Paolo Bonzini <pbonzini@redhat.com>
//
// based on lsi-scsi.c which is written by:
//  Gerd Hoffman <kraxel@redhat.com>
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
#include "pci_ids.h" // PCI_DEVICE_ID
#include "pci_regs.h" // PCI_VENDOR_ID
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "util.h" // usleep

#define ESP_TCLO      0x00
#define ESP_TCMID     0x04
#define ESP_FIFO      0x08
#define ESP_CMD       0x0c
#define ESP_WBUSID    0x10
#define ESP_TCHI      0x38

#define ESP_RSTAT     0x10
#define ESP_RINTR     0x14
#define ESP_RFLAGS    0x1c

#define ESP_DMA_CMD   0x40
#define ESP_DMA_STC   0x44
#define ESP_DMA_SPA   0x48
#define ESP_DMA_WBC   0x4c
#define ESP_DMA_WAC   0x50
#define ESP_DMA_STAT  0x54
#define ESP_DMA_SMDLA 0x58
#define ESP_DMA_WMAC  0x58c

#define ESP_CMD_DMA      0x80
#define ESP_CMD_RESET    0x02
#define ESP_CMD_TI       0x10
#define ESP_CMD_ICCS     0x11
#define ESP_CMD_SELATN   0x42

#define ESP_STAT_DI      0x01
#define ESP_STAT_CD      0x02
#define ESP_STAT_MSG     0x04
#define ESP_STAT_TC      0x10

#define ESP_INTR_DC      0x20

struct esp_lun_s {
    struct drive_s drive;
    struct pci_device *pci;
    u32 iobase;
    u8 target;
    u8 lun;
};

static void
esp_scsi_dma(u32 iobase, u32 buf, u32 len, int read)
{
    outb(len         & 0xff, iobase + ESP_TCLO);
    outb((len >> 8)  & 0xff, iobase + ESP_TCMID);
    outb((len >> 16) & 0xff, iobase + ESP_TCHI);
    outl(buf,                iobase + ESP_DMA_SPA);
    outl(len,                iobase + ESP_DMA_STC);
    outb(read ? 0x83 : 0x03, iobase + ESP_DMA_CMD);
}

static int
esp_scsi_cmd(struct esp_lun_s *llun_gf, struct disk_op_s *op,
             u8 *cdbcmd, u16 target, u16 lun, u16 blocksize)
{
    u32 iobase = GET_GLOBALFLAT(llun_gf->iobase);
    int i, state;
    u8 status;

    outb(target, iobase + ESP_WBUSID);

    /*
     * We need to pass the LUN at the beginning of the command, and the FIFO
     * is only 16 bytes, so we cannot support 16-byte CDBs.  The alternative
     * would be to use DMA for the 17-byte command too, which is quite
     * overkill.
     */
    outb(lun, iobase + ESP_FIFO);
    cdbcmd[1] &= 0x1f;
    cdbcmd[1] |= lun << 5;
    for (i = 0; i < 12; i++)
        outb(cdbcmd[i], iobase + ESP_FIFO);
    outb(ESP_CMD_SELATN, iobase + ESP_CMD);

    for (state = 0;;) {
        u8 stat = inb(iobase + ESP_RSTAT);

        /* Detect disconnected device.  */
        if (state == 0 && (inb(iobase + ESP_RINTR) & ESP_INTR_DC)) {
            return DISK_RET_ENOTREADY;
        }

        /* HBA reads command, clears CD, sets TC -> do DMA if needed.  */
        if (state == 0 && (stat & ESP_STAT_TC)) {
            state++;
            if (op->count && blocksize) {
                /* Data phase.  */
                u32 count = (u32)op->count * blocksize;
                esp_scsi_dma(iobase, (u32)op->buf_fl, count,
                             cdb_is_read(cdbcmd, blocksize));
                outb(ESP_CMD_TI | ESP_CMD_DMA, iobase + ESP_CMD);
                continue;
            }
        }

        /* At end of DMA TC is set again -> complete command.  */
        if (state == 1 && (stat & ESP_STAT_TC)) {
            state++;
            outb(ESP_CMD_ICCS, iobase + ESP_CMD);
            continue;
        }

        /* Finally read data from the message in phase.  */
        if (state == 2 && (stat & ESP_STAT_MSG)) {
            state++;
            status = inb(iobase + ESP_FIFO);
            inb(iobase + ESP_FIFO);
            break;
        }
        usleep(5);
    }

    if (status == 0) {
        return DISK_RET_SUCCESS;
    }

    return DISK_RET_EBADTRACK;
}

int
esp_scsi_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize)
{
    if (!CONFIG_ESP_SCSI)
        return DISK_RET_EBADTRACK;

    struct esp_lun_s *llun_gf =
        container_of(op->drive_gf, struct esp_lun_s, drive);

    return esp_scsi_cmd(llun_gf, op, cdbcmd,
                        GET_GLOBALFLAT(llun_gf->target),
                        GET_GLOBALFLAT(llun_gf->lun),
                        blocksize);
}

static int
esp_scsi_add_lun(struct pci_device *pci, u32 iobase, u8 target, u8 lun)
{
    struct esp_lun_s *llun = malloc_fseg(sizeof(*llun));
    if (!llun) {
        warn_noalloc();
        return -1;
    }
    memset(llun, 0, sizeof(*llun));
    llun->drive.type = DTYPE_ESP_SCSI;
    llun->drive.cntl_id = pci->bdf;
    llun->pci = pci;
    llun->target = target;
    llun->lun = lun;
    llun->iobase = iobase;

    char *name = znprintf(16, "esp %02x:%02x.%x %d:%d",
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
esp_scsi_scan_target(struct pci_device *pci, u32 iobase, u8 target)
{
    esp_scsi_add_lun(pci, iobase, target, 0);
}

static void
init_esp_scsi(struct pci_device *pci)
{
    u16 bdf = pci->bdf;
    u32 iobase = pci_config_readl(pci->bdf, PCI_BASE_ADDRESS_0)
        & PCI_BASE_ADDRESS_IO_MASK;

    dprintf(1, "found esp at %02x:%02x.%x, io @ %x\n",
            pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf),
            pci_bdf_to_fn(bdf), iobase);

    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_MASTER);

    // reset
    outb(ESP_CMD_RESET, iobase + ESP_CMD);

    int i;
    for (i = 0; i <= 7; i++)
        esp_scsi_scan_target(pci, iobase, i);

    return;
}

void
esp_scsi_setup(void)
{
    ASSERT32FLAT();
    if (!CONFIG_ESP_SCSI || !runningOnQEMU())
        return;

    dprintf(3, "init esp\n");

    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->vendor != PCI_VENDOR_ID_AMD
            || pci->device != PCI_DEVICE_ID_AMD_SCSI)
            continue;
        init_esp_scsi(pci);
    }
}
