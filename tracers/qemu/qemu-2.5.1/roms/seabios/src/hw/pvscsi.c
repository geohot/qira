// QEMU VMWARE Paravirtualized SCSI boot support.
//
// Copyright (c) 2013 Ravello Systems LTD (http://ravellosystems.com)
//
// Authors:
//  Evgeny Budilovsky <evgeny.budilovsky@ravellosystems.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "block.h" // struct drive_s
#include "blockcmd.h" // scsi_drive_setup
#include "config.h" // CONFIG_*
#include "malloc.h" // free
#include "output.h" // dprintf
#include "pci.h" // foreachpci
#include "pci_ids.h" // PCI_DEVICE_ID_VMWARE_PVSCSI
#include "pci_regs.h" // PCI_VENDOR_ID
#include "pvscsi.h" // pvscsi_setup
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "util.h" // usleep
#include "virtio-ring.h" // PAGE_SHIFT, virt_to_phys
#include "x86.h" // writel

#define MASK(n) ((1 << (n)) - 1)

#define SIMPLE_QUEUE_TAG 0x20

#define PVSCSI_INTR_CMPL_0                 (1 << 0)
#define PVSCSI_INTR_CMPL_1                 (1 << 1)
#define PVSCSI_INTR_CMPL_MASK              MASK(2)

#define PVSCSI_INTR_MSG_0                  (1 << 2)
#define PVSCSI_INTR_MSG_1                  (1 << 3)
#define PVSCSI_INTR_MSG_MASK               (MASK(2) << 2)
#define PVSCSI_INTR_ALL_SUPPORTED          MASK(4)

#define PVSCSI_FLAG_CMD_WITH_SG_LIST       (1 << 0)
#define PVSCSI_FLAG_CMD_OUT_OF_BAND_CDB    (1 << 1)
#define PVSCSI_FLAG_CMD_DIR_NONE           (1 << 2)
#define PVSCSI_FLAG_CMD_DIR_TOHOST         (1 << 3)
#define PVSCSI_FLAG_CMD_DIR_TODEVICE       (1 << 4)

enum PVSCSIRegOffset {
    PVSCSI_REG_OFFSET_COMMAND        =    0x0,
    PVSCSI_REG_OFFSET_COMMAND_DATA   =    0x4,
    PVSCSI_REG_OFFSET_COMMAND_STATUS =    0x8,
    PVSCSI_REG_OFFSET_LAST_STS_0     =  0x100,
    PVSCSI_REG_OFFSET_LAST_STS_1     =  0x104,
    PVSCSI_REG_OFFSET_LAST_STS_2     =  0x108,
    PVSCSI_REG_OFFSET_LAST_STS_3     =  0x10c,
    PVSCSI_REG_OFFSET_INTR_STATUS    = 0x100c,
    PVSCSI_REG_OFFSET_INTR_MASK      = 0x2010,
    PVSCSI_REG_OFFSET_KICK_NON_RW_IO = 0x3014,
    PVSCSI_REG_OFFSET_DEBUG          = 0x3018,
    PVSCSI_REG_OFFSET_KICK_RW_IO     = 0x4018,
};

enum PVSCSICommands {
    PVSCSI_CMD_FIRST             = 0,
    PVSCSI_CMD_ADAPTER_RESET     = 1,
    PVSCSI_CMD_ISSUE_SCSI        = 2,
    PVSCSI_CMD_SETUP_RINGS       = 3,
    PVSCSI_CMD_RESET_BUS         = 4,
    PVSCSI_CMD_RESET_DEVICE      = 5,
    PVSCSI_CMD_ABORT_CMD         = 6,
    PVSCSI_CMD_CONFIG            = 7,
    PVSCSI_CMD_SETUP_MSG_RING    = 8,
    PVSCSI_CMD_DEVICE_UNPLUG     = 9,
    PVSCSI_CMD_LAST              = 10
};

#define PVSCSI_SETUP_RINGS_MAX_NUM_PAGES        32
struct PVSCSICmdDescSetupRings {
    u32    reqRingNumPages;
    u32    cmpRingNumPages;
    u64    ringsStatePPN;
    u64    reqRingPPNs[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
    u64    cmpRingPPNs[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
} PACKED;

struct PVSCSIRingCmpDesc {
    u64    context;
    u64    dataLen;
    u32    senseLen;
    u16    hostStatus;
    u16    scsiStatus;
    u32    pad[2];
} PACKED;

struct PVSCSIRingsState {
    u32    reqProdIdx;
    u32    reqConsIdx;
    u32    reqNumEntriesLog2;

    u32    cmpProdIdx;
    u32    cmpConsIdx;
    u32    cmpNumEntriesLog2;

    u8     pad[104];

    u32    msgProdIdx;
    u32    msgConsIdx;
    u32    msgNumEntriesLog2;
} PACKED;

struct PVSCSIRingReqDesc {
    u64    context;
    u64    dataAddr;
    u64    dataLen;
    u64    senseAddr;
    u32    senseLen;
    u32    flags;
    u8     cdb[16];
    u8     cdbLen;
    u8     lun[8];
    u8     tag;
    u8     bus;
    u8     target;
    u8     vcpuHint;
    u8     unused[59];
} PACKED;

struct pvscsi_ring_dsc_s {
    struct PVSCSIRingsState *ring_state;
    struct PVSCSIRingReqDesc *ring_reqs;
    struct PVSCSIRingCmpDesc *ring_cmps;
};

struct pvscsi_lun_s {
    struct drive_s drive;
    void *iobase;
    u8 target;
    u8 lun;
    struct pvscsi_ring_dsc_s *ring_dsc;
};

static void
pvscsi_write_cmd_desc(void *iobase, u32 cmd, const void *desc, size_t len)
{
    const u32 *ptr = desc;
    size_t i;

    len /= sizeof(*ptr);
    writel(iobase + PVSCSI_REG_OFFSET_COMMAND, cmd);
    for (i = 0; i < len; i++)
        writel(iobase + PVSCSI_REG_OFFSET_COMMAND_DATA, ptr[i]);
}

static void
pvscsi_kick_rw_io(void *iobase)
{
    writel(iobase + PVSCSI_REG_OFFSET_KICK_RW_IO, 0);
}

static void
pvscsi_wait_intr_cmpl(void *iobase)
{
    while (!(readl(iobase + PVSCSI_REG_OFFSET_INTR_STATUS) & PVSCSI_INTR_CMPL_MASK))
        usleep(5);
    writel(iobase + PVSCSI_REG_OFFSET_INTR_STATUS, PVSCSI_INTR_CMPL_MASK);
}

static void
pvscsi_init_rings(void *iobase, struct pvscsi_ring_dsc_s **ring_dsc)
{
    struct PVSCSICmdDescSetupRings cmd = {0,};

    struct pvscsi_ring_dsc_s *dsc = memalign_low(sizeof(*dsc), PAGE_SIZE);
    if (!dsc) {
        warn_noalloc();
        return;
    }

    dsc->ring_state =
        (struct PVSCSIRingsState *)memalign_low(PAGE_SIZE, PAGE_SIZE);
    dsc->ring_reqs =
        (struct PVSCSIRingReqDesc *)memalign_low(PAGE_SIZE, PAGE_SIZE);
    dsc->ring_cmps =
        (struct PVSCSIRingCmpDesc *)memalign_low(PAGE_SIZE, PAGE_SIZE);
    if (!dsc->ring_state || !dsc->ring_reqs || !dsc->ring_cmps) {
        warn_noalloc();
        return;
    }
    memset(dsc->ring_state, 0, PAGE_SIZE);
    memset(dsc->ring_reqs, 0, PAGE_SIZE);
    memset(dsc->ring_cmps, 0, PAGE_SIZE);

    cmd.reqRingNumPages = 1;
    cmd.cmpRingNumPages = 1;
    cmd.ringsStatePPN = virt_to_phys(dsc->ring_state) >> PAGE_SHIFT;
    cmd.reqRingPPNs[0] = virt_to_phys(dsc->ring_reqs) >> PAGE_SHIFT;
    cmd.cmpRingPPNs[0] = virt_to_phys(dsc->ring_cmps) >> PAGE_SHIFT;

    pvscsi_write_cmd_desc(iobase, PVSCSI_CMD_SETUP_RINGS,
                          &cmd, sizeof(cmd));
    *ring_dsc = dsc;
}

static void pvscsi_fill_req(struct PVSCSIRingsState *s,
                            struct PVSCSIRingReqDesc *req,
                            u16 target, u16 lun, void *cdbcmd, u16 blocksize,
                            struct disk_op_s *op)
{
    req->bus = 0;
    req->target = target;
    memset(req->lun, 0, sizeof(req->lun));
    req->lun[1] = lun;
    req->senseLen = 0;
    req->senseAddr = 0;
    req->cdbLen = 16;
    req->vcpuHint = 0;
    memcpy(req->cdb, cdbcmd, 16);
    req->tag = SIMPLE_QUEUE_TAG;
    req->flags = cdb_is_read(cdbcmd, blocksize) ?
        PVSCSI_FLAG_CMD_DIR_TOHOST : PVSCSI_FLAG_CMD_DIR_TODEVICE;

    req->dataLen = op->count * blocksize;
    req->dataAddr = (u32)op->buf_fl;
    s->reqProdIdx = s->reqProdIdx + 1;
}

static u32
pvscsi_get_rsp(struct PVSCSIRingsState *s,
               struct PVSCSIRingCmpDesc *rsp)
{
    u32 status = rsp->hostStatus;
    s->cmpConsIdx = s->cmpConsIdx + 1;
    return status;
}

static int
pvscsi_cmd(struct pvscsi_lun_s *plun, struct disk_op_s *op,
           void *cdbcmd, u16 target, u16 lun, u16 blocksize)
{
    struct pvscsi_ring_dsc_s *ring_dsc = plun->ring_dsc;
    struct PVSCSIRingsState *s = ring_dsc->ring_state;
    u32 req_entries = s->reqNumEntriesLog2;
    u32 cmp_entries = s->cmpNumEntriesLog2;
    struct PVSCSIRingReqDesc *req;
    struct PVSCSIRingCmpDesc *rsp;
    u32 status;

    if (s->reqProdIdx - s->cmpConsIdx >= 1 << req_entries) {
        dprintf(1, "pvscsi: ring full: reqProdIdx=%d cmpConsIdx=%d\n",
                s->reqProdIdx, s->cmpConsIdx);
        return DISK_RET_EBADTRACK;
    }

    req = ring_dsc->ring_reqs + (s->reqProdIdx & MASK(req_entries));
    pvscsi_fill_req(s, req, target, lun, cdbcmd, blocksize, op);

    pvscsi_kick_rw_io(plun->iobase);
    pvscsi_wait_intr_cmpl(plun->iobase);

    rsp = ring_dsc->ring_cmps + (s->cmpConsIdx & MASK(cmp_entries));
    status = pvscsi_get_rsp(s, rsp);

    return status == 0 ? DISK_RET_SUCCESS : DISK_RET_EBADTRACK;
}

int
pvscsi_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize)
{
    if (!CONFIG_PVSCSI)
        return DISK_RET_EBADTRACK;

    struct pvscsi_lun_s *plun =
        container_of(op->drive_gf, struct pvscsi_lun_s, drive);

    return pvscsi_cmd(plun, op, cdbcmd, plun->target, plun->lun, blocksize);
}

static int
pvscsi_add_lun(struct pci_device *pci, void *iobase,
               struct pvscsi_ring_dsc_s *ring_dsc, u8 target, u8 lun)
{
    struct pvscsi_lun_s *plun = malloc_fseg(sizeof(*plun));
    if (!plun) {
        warn_noalloc();
        return -1;
    }
    memset(plun, 0, sizeof(*plun));
    plun->drive.type = DTYPE_PVSCSI;
    plun->drive.cntl_id = pci->bdf;
    plun->target = target;
    plun->lun = lun;
    plun->iobase = iobase;
    plun->ring_dsc = ring_dsc;

    char *name = znprintf(16, "pvscsi %02x:%02x.%x %d:%d",
                          pci_bdf_to_bus(pci->bdf), pci_bdf_to_dev(pci->bdf),
                          pci_bdf_to_fn(pci->bdf), target, lun);
    int prio = bootprio_find_scsi_device(pci, target, lun);
    int ret = scsi_drive_setup(&plun->drive, name, prio);
    free(name);
    if (ret)
        goto fail;
    return 0;

fail:
    free(plun);
    return -1;
}

static void
pvscsi_scan_target(struct pci_device *pci, void *iobase,
                   struct pvscsi_ring_dsc_s *ring_dsc, u8 target)
{
    /* TODO: send REPORT LUNS.  For now, only LUN 0 is recognized.  */
    pvscsi_add_lun(pci, iobase, ring_dsc, target, 0);
}

static void
init_pvscsi(struct pci_device *pci)
{
    struct pvscsi_ring_dsc_s *ring_dsc = NULL;
    int i;
    u16 bdf = pci->bdf;
    void *iobase = (void*)(pci_config_readl(pci->bdf, PCI_BASE_ADDRESS_0)
                           & PCI_BASE_ADDRESS_MEM_MASK);

    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_MASTER);

    dprintf(1, "found pvscsi at %02x:%02x.%x, io @ %p\n",
            pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf),
            pci_bdf_to_fn(bdf), iobase);

    pvscsi_write_cmd_desc(iobase, PVSCSI_CMD_ADAPTER_RESET, NULL, 0);

    pvscsi_init_rings(iobase, &ring_dsc);
    for (i = 0; i < 7; i++)
        pvscsi_scan_target(pci, iobase, ring_dsc, i);

    return;
}

void
pvscsi_setup(void)
{
    ASSERT32FLAT();
    if (! CONFIG_PVSCSI)
        return;

    dprintf(3, "init pvscsi\n");

    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->vendor != PCI_VENDOR_ID_VMWARE
            || pci->device != PCI_DEVICE_ID_VMWARE_PVSCSI)
            continue;
        init_pvscsi(pci);
    }
}
