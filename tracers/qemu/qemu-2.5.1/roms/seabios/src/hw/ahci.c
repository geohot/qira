// Low level AHCI disk access
//
// Copyright (C) 2010 Gerd Hoffmann <kraxel@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "ahci.h" // CDB_CMD_READ_10
#include "ata.h" // ATA_CB_STAT
#include "biosvar.h" // GET_GLOBAL
#include "blockcmd.h" // CDB_CMD_READ_10
#include "malloc.h" // free
#include "output.h" // dprintf
#include "pci.h" // foreachpci
#include "pci_ids.h" // PCI_CLASS_STORAGE_OTHER
#include "pci_regs.h" // PCI_INTERRUPT_LINE
#include "stacks.h" // yield
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "util.h" // timer_calc
#include "x86.h" // inb

#define AHCI_REQUEST_TIMEOUT 32000 // 32 seconds max for IDE ops
#define AHCI_RESET_TIMEOUT     500 // 500 miliseconds
#define AHCI_LINK_TIMEOUT       10 // 10 miliseconds

// prepare sata command fis
static void sata_prep_simple(struct sata_cmd_fis *fis, u8 command)
{
    memset_fl(fis, 0, sizeof(*fis));
    fis->command = command;
}

static void sata_prep_readwrite(struct sata_cmd_fis *fis,
                                struct disk_op_s *op, int iswrite)
{
    u64 lba = op->lba;
    u8 command;

    memset_fl(fis, 0, sizeof(*fis));

    if (op->count >= (1<<8) || lba + op->count >= (1<<28)) {
        fis->sector_count2 = op->count >> 8;
        fis->lba_low2      = lba >> 24;
        fis->lba_mid2      = lba >> 32;
        fis->lba_high2     = lba >> 40;
        lba &= 0xffffff;
        command = (iswrite ? ATA_CMD_WRITE_DMA_EXT
                   : ATA_CMD_READ_DMA_EXT);
    } else {
        command = (iswrite ? ATA_CMD_WRITE_DMA
                   : ATA_CMD_READ_DMA);
    }
    fis->feature      = 1; /* dma */
    fis->command      = command;
    fis->sector_count = op->count;
    fis->lba_low      = lba;
    fis->lba_mid      = lba >> 8;
    fis->lba_high     = lba >> 16;
    fis->device       = ((lba >> 24) & 0xf) | ATA_CB_DH_LBA;
}

static void sata_prep_atapi(struct sata_cmd_fis *fis, u16 blocksize)
{
    memset_fl(fis, 0, sizeof(*fis));
    fis->command  = ATA_CMD_PACKET;
    fis->feature  = 1; /* dma */
    fis->lba_mid  = blocksize;
    fis->lba_high = blocksize >> 8;
}

// ahci register access helpers
static u32 ahci_ctrl_readl(struct ahci_ctrl_s *ctrl, u32 reg)
{
    u32 addr = ctrl->iobase + reg;
    return readl((void*)addr);
}

static void ahci_ctrl_writel(struct ahci_ctrl_s *ctrl, u32 reg, u32 val)
{
    u32 addr = ctrl->iobase + reg;
    writel((void*)addr, val);
}

static u32 ahci_port_to_ctrl(u32 pnr, u32 port_reg)
{
    u32 ctrl_reg = 0x100;
    ctrl_reg += pnr * 0x80;
    ctrl_reg += port_reg;
    return ctrl_reg;
}

static u32 ahci_port_readl(struct ahci_ctrl_s *ctrl, u32 pnr, u32 reg)
{
    u32 ctrl_reg = ahci_port_to_ctrl(pnr, reg);
    return ahci_ctrl_readl(ctrl, ctrl_reg);
}

static void ahci_port_writel(struct ahci_ctrl_s *ctrl, u32 pnr, u32 reg, u32 val)
{
    u32 ctrl_reg = ahci_port_to_ctrl(pnr, reg);
    ahci_ctrl_writel(ctrl, ctrl_reg, val);
}

// submit ahci command + wait for result
static int ahci_command(struct ahci_port_s *port_gf, int iswrite, int isatapi,
                        void *buffer, u32 bsize)
{
    u32 val, status, success, flags, intbits, error;
    struct ahci_ctrl_s *ctrl = port_gf->ctrl;
    struct ahci_cmd_s  *cmd  = port_gf->cmd;
    struct ahci_fis_s  *fis  = port_gf->fis;
    struct ahci_list_s *list = port_gf->list;
    u32 pnr                  = port_gf->pnr;

    cmd->fis.reg       = 0x27;
    cmd->fis.pmp_type  = 1 << 7; /* cmd fis */
    cmd->prdt[0].base  = (u32)buffer;
    cmd->prdt[0].baseu = 0;
    cmd->prdt[0].flags = bsize-1;

    flags = ((1 << 16) | /* one prd entry */
             (iswrite ? (1 << 6) : 0) |
             (isatapi ? (1 << 5) : 0) |
             (5 << 0)); /* fis length (dwords) */
    list[0].flags  = flags;
    list[0].bytes  = 0;
    list[0].base   = (u32)(cmd);
    list[0].baseu  = 0;

    dprintf(8, "AHCI/%d: send cmd ...\n", pnr);
    intbits = ahci_port_readl(ctrl, pnr, PORT_IRQ_STAT);
    if (intbits)
        ahci_port_writel(ctrl, pnr, PORT_IRQ_STAT, intbits);
    ahci_port_writel(ctrl, pnr, PORT_SCR_ACT, 1);
    ahci_port_writel(ctrl, pnr, PORT_CMD_ISSUE, 1);

    u32 end = timer_calc(AHCI_REQUEST_TIMEOUT);
    do {
        for (;;) {
            intbits = ahci_port_readl(ctrl, pnr, PORT_IRQ_STAT);
            if (intbits) {
                ahci_port_writel(ctrl, pnr, PORT_IRQ_STAT, intbits);
                if (intbits & 0x02) {
                    status = GET_LOWFLAT(fis->psfis[2]);
                    error  = GET_LOWFLAT(fis->psfis[3]);
                    break;
                }
                if (intbits & 0x01) {
                    status = GET_LOWFLAT(fis->rfis[2]);
                    error  = GET_LOWFLAT(fis->rfis[3]);
                    break;
                }
            }
            if (timer_check(end)) {
                warn_timeout();
                return -1;
            }
            yield();
        }
        dprintf(8, "AHCI/%d: ... intbits 0x%x, status 0x%x ...\n",
                pnr, intbits, status);
    } while (status & ATA_CB_STAT_BSY);

    success = (0x00 == (status & (ATA_CB_STAT_BSY | ATA_CB_STAT_DF |
                                  ATA_CB_STAT_ERR)) &&
               ATA_CB_STAT_RDY == (status & (ATA_CB_STAT_RDY)));
    if (success) {
        dprintf(8, "AHCI/%d: ... finished, status 0x%x, OK\n", pnr,
                status);
    } else {
        dprintf(2, "AHCI/%d: ... finished, status 0x%x, ERROR 0x%x\n", pnr,
                status, error);

        // non-queued error recovery (AHCI 1.3 section 6.2.2.1)
        // Clears PxCMD.ST to 0 to reset the PxCI register
        val = ahci_port_readl(ctrl, pnr, PORT_CMD);
        ahci_port_writel(ctrl, pnr, PORT_CMD, val & ~PORT_CMD_START);

        // waits for PxCMD.CR to clear to 0
        while (1) {
            val = ahci_port_readl(ctrl, pnr, PORT_CMD);
            if ((val & PORT_CMD_LIST_ON) == 0)
                break;
            yield();
        }

        // Clears any error bits in PxSERR to enable capturing new errors
        val = ahci_port_readl(ctrl, pnr, PORT_SCR_ERR);
        ahci_port_writel(ctrl, pnr, PORT_SCR_ERR, val);

        // Clears status bits in PxIS as appropriate
        val = ahci_port_readl(ctrl, pnr, PORT_IRQ_STAT);
        ahci_port_writel(ctrl, pnr, PORT_IRQ_STAT, val);

        // If PxTFD.STS.BSY or PxTFD.STS.DRQ is set to 1, issue
        // a COMRESET to the device to put it in an idle state
        val = ahci_port_readl(ctrl, pnr, PORT_TFDATA);
        if (val & (ATA_CB_STAT_BSY | ATA_CB_STAT_DRQ)) {
            dprintf(2, "AHCI/%d: issue comreset\n", pnr);
            val = ahci_port_readl(ctrl, pnr, PORT_SCR_CTL);
            // set Device Detection Initialization (DET) to 1 for 1 ms for comreset
            ahci_port_writel(ctrl, pnr, PORT_SCR_CTL, val | 1);
            mdelay (1);
            ahci_port_writel(ctrl, pnr, PORT_SCR_CTL, val);
        }

        // Sets PxCMD.ST to 1 to enable issuing new commands
        val = ahci_port_readl(ctrl, pnr, PORT_CMD);
        ahci_port_writel(ctrl, pnr, PORT_CMD, val | PORT_CMD_START);
    }
    return success ? 0 : -1;
}

#define CDROM_CDB_SIZE 12

int ahci_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize)
{
    if (! CONFIG_AHCI)
        return 0;

    struct ahci_port_s *port_gf = container_of(
        op->drive_gf, struct ahci_port_s, drive);
    struct ahci_cmd_s *cmd = port_gf->cmd;
    u8 *atapi = cdbcmd;
    int i, rc;

    sata_prep_atapi(&cmd->fis, blocksize);
    for (i = 0; i < CDROM_CDB_SIZE; i++) {
        cmd->atapi[i] = atapi[i];
    }
    rc = ahci_command(port_gf, 0, 1, op->buf_fl,
                      op->count * blocksize);
    if (rc < 0)
        return DISK_RET_EBADTRACK;
    return DISK_RET_SUCCESS;
}

// read/write count blocks from a harddrive, op->buf_fl must be word aligned
static int
ahci_disk_readwrite_aligned(struct disk_op_s *op, int iswrite)
{
    struct ahci_port_s *port_gf = container_of(
        op->drive_gf, struct ahci_port_s, drive);
    struct ahci_cmd_s *cmd = port_gf->cmd;
    int rc;

    sata_prep_readwrite(&cmd->fis, op, iswrite);
    rc = ahci_command(port_gf, iswrite, 0, op->buf_fl,
                      op->count * DISK_SECTOR_SIZE);
    dprintf(8, "ahci disk %s, lba %6x, count %3x, buf %p, rc %d\n",
            iswrite ? "write" : "read", (u32)op->lba, op->count, op->buf_fl, rc);
    if (rc < 0)
        return DISK_RET_EBADTRACK;
    return DISK_RET_SUCCESS;
}

// read/write count blocks from a harddrive.
static int
ahci_disk_readwrite(struct disk_op_s *op, int iswrite)
{
    // if caller's buffer is word aligned, use it directly
    if (((u32) op->buf_fl & 1) == 0)
        return ahci_disk_readwrite_aligned(op, iswrite);

    // Use a word aligned buffer for AHCI I/O
    int rc;
    struct disk_op_s localop = *op;
    u8 *alignedbuf_fl = bounce_buf_fl;
    u8 *position = op->buf_fl;

    localop.buf_fl = alignedbuf_fl;
    localop.count = 1;

    if (iswrite) {
        u16 block;
        for (block = 0; block < op->count; block++) {
            memcpy_fl (alignedbuf_fl, position, DISK_SECTOR_SIZE);
            rc = ahci_disk_readwrite_aligned (&localop, 1);
            if (rc)
                return rc;
            position += DISK_SECTOR_SIZE;
            localop.lba++;
        }
    } else { // read
        u16 block;
        for (block = 0; block < op->count; block++) {
            rc = ahci_disk_readwrite_aligned (&localop, 0);
            if (rc)
                return rc;
            memcpy_fl (position, alignedbuf_fl, DISK_SECTOR_SIZE);
            position += DISK_SECTOR_SIZE;
            localop.lba++;
        }
    }
    return DISK_RET_SUCCESS;
}

// command demuxer
int VISIBLE32FLAT
process_ahci_op(struct disk_op_s *op)
{
    if (!CONFIG_AHCI)
        return 0;
    switch (op->command) {
    case CMD_READ:
        return ahci_disk_readwrite(op, 0);
    case CMD_WRITE:
        return ahci_disk_readwrite(op, 1);
    case CMD_FORMAT:
    case CMD_RESET:
    case CMD_ISREADY:
    case CMD_VERIFY:
    case CMD_SEEK:
        return DISK_RET_SUCCESS;
    default:
        dprintf(1, "AHCI: unknown disk command %d\n", op->command);
        return DISK_RET_EPARAM;
    }
}

static void
ahci_port_reset(struct ahci_ctrl_s *ctrl, u32 pnr)
{
    u32 val;

    /* disable FIS + CMD */
    u32 end = timer_calc(AHCI_RESET_TIMEOUT);
    for (;;) {
        val = ahci_port_readl(ctrl, pnr, PORT_CMD);
        if (!(val & (PORT_CMD_FIS_RX | PORT_CMD_START |
                     PORT_CMD_FIS_ON | PORT_CMD_LIST_ON)))
            break;
        val &= ~(PORT_CMD_FIS_RX | PORT_CMD_START);
        ahci_port_writel(ctrl, pnr, PORT_CMD, val);
        if (timer_check(end)) {
            warn_timeout();
            break;
        }
        yield();
    }

    /* disable + clear IRQs */
    ahci_port_writel(ctrl, pnr, PORT_IRQ_MASK, 0);
    val = ahci_port_readl(ctrl, pnr, PORT_IRQ_STAT);
    if (val)
        ahci_port_writel(ctrl, pnr, PORT_IRQ_STAT, val);
}

static struct ahci_port_s*
ahci_port_alloc(struct ahci_ctrl_s *ctrl, u32 pnr)
{
    struct ahci_port_s *port = malloc_tmp(sizeof(*port));

    if (!port) {
        warn_noalloc();
        return NULL;
    }
    port->pnr = pnr;
    port->ctrl = ctrl;
    port->list = memalign_tmp(1024, 1024);
    port->fis = memalign_tmp(256, 256);
    port->cmd = memalign_tmp(256, 256);
    if (port->list == NULL || port->fis == NULL || port->cmd == NULL) {
        warn_noalloc();
        return NULL;
    }
    memset(port->list, 0, 1024);
    memset(port->fis, 0, 256);
    memset(port->cmd, 0, 256);

    ahci_port_writel(ctrl, pnr, PORT_LST_ADDR, (u32)port->list);
    ahci_port_writel(ctrl, pnr, PORT_FIS_ADDR, (u32)port->fis);
    return port;
}

static void ahci_port_release(struct ahci_port_s *port)
{
    ahci_port_reset(port->ctrl, port->pnr);
    free(port->list);
    free(port->fis);
    free(port->cmd);
    free(port);
}

static struct ahci_port_s* ahci_port_realloc(struct ahci_port_s *port)
{
    struct ahci_port_s *tmp;
    u32 cmd;

    tmp = malloc_fseg(sizeof(*port));
    if (!tmp) {
        warn_noalloc();
        ahci_port_release(port);
        return NULL;
    }
    *tmp = *port;
    free(port);
    port = tmp;

    ahci_port_reset(port->ctrl, port->pnr);

    free(port->list);
    free(port->fis);
    free(port->cmd);
    port->list = memalign_high(1024, 1024);
    port->fis = memalign_high(256, 256);
    port->cmd = memalign_high(256, 256);

    ahci_port_writel(port->ctrl, port->pnr, PORT_LST_ADDR, (u32)port->list);
    ahci_port_writel(port->ctrl, port->pnr, PORT_FIS_ADDR, (u32)port->fis);

    cmd = ahci_port_readl(port->ctrl, port->pnr, PORT_CMD);
    cmd |= (PORT_CMD_FIS_RX|PORT_CMD_START);
    ahci_port_writel(port->ctrl, port->pnr, PORT_CMD, cmd);

    return port;
}

#define MAXMODEL 40

/* See ahci spec chapter 10.1 "Software Initialization of HBA" */
static int ahci_port_setup(struct ahci_port_s *port)
{
    struct ahci_ctrl_s *ctrl = port->ctrl;
    u32 pnr = port->pnr;
    char model[MAXMODEL+1];
    u16 buffer[256];
    u32 cmd, stat, err, tf;
    int rc;

    /* enable FIS recv */
    cmd = ahci_port_readl(ctrl, pnr, PORT_CMD);
    cmd |= PORT_CMD_FIS_RX;
    ahci_port_writel(ctrl, pnr, PORT_CMD, cmd);

    /* spin up */
    cmd |= PORT_CMD_SPIN_UP;
    ahci_port_writel(ctrl, pnr, PORT_CMD, cmd);
    u32 end = timer_calc(AHCI_LINK_TIMEOUT);
    for (;;) {
        stat = ahci_port_readl(ctrl, pnr, PORT_SCR_STAT);
        if ((stat & 0x07) == 0x03) {
            dprintf(2, "AHCI/%d: link up\n", port->pnr);
            break;
        }
        if (timer_check(end)) {
            dprintf(2, "AHCI/%d: link down\n", port->pnr);
            return -1;
        }
        yield();
    }

    /* clear error status */
    err = ahci_port_readl(ctrl, pnr, PORT_SCR_ERR);
    if (err)
        ahci_port_writel(ctrl, pnr, PORT_SCR_ERR, err);

    /* wait for device becoming ready */
    end = timer_calc(AHCI_REQUEST_TIMEOUT);
    for (;;) {
        tf = ahci_port_readl(ctrl, pnr, PORT_TFDATA);
        if (!(tf & (ATA_CB_STAT_BSY |
                    ATA_CB_STAT_DRQ)))
            break;
        if (timer_check(end)) {
            warn_timeout();
            dprintf(1, "AHCI/%d: device not ready (tf 0x%x)\n", port->pnr, tf);
            return -1;
        }
        yield();
    }

    /* start device */
    cmd |= PORT_CMD_START;
    ahci_port_writel(ctrl, pnr, PORT_CMD, cmd);

    sata_prep_simple(&port->cmd->fis, ATA_CMD_IDENTIFY_PACKET_DEVICE);
    rc = ahci_command(port, 0, 0, buffer, sizeof(buffer));
    if (rc == 0) {
        port->atapi = 1;
    } else {
        port->atapi = 0;
        sata_prep_simple(&port->cmd->fis, ATA_CMD_IDENTIFY_DEVICE);
        rc = ahci_command(port, 0, 0, buffer, sizeof(buffer));
        if (rc < 0)
            return -1;
    }

    port->drive.cntl_id = pnr;
    port->drive.removable = (buffer[0] & 0x80) ? 1 : 0;

    if (!port->atapi) {
        // found disk (ata)
        port->drive.type = DTYPE_AHCI;
        port->drive.blksize = DISK_SECTOR_SIZE;
        port->drive.pchs.cylinder = buffer[1];
        port->drive.pchs.head = buffer[3];
        port->drive.pchs.sector = buffer[6];

        u64 sectors;
        if (buffer[83] & (1 << 10)) // word 83 - lba48 support
            sectors = *(u64*)&buffer[100]; // word 100-103
        else
            sectors = *(u32*)&buffer[60]; // word 60 and word 61
        port->drive.sectors = sectors;
        u64 adjsize = sectors >> 11;
        char adjprefix = 'M';
        if (adjsize >= (1 << 16)) {
            adjsize >>= 10;
            adjprefix = 'G';
        }
        port->desc = znprintf(MAXDESCSIZE
                              , "AHCI/%d: %s ATA-%d Hard-Disk (%u %ciBytes)"
                              , port->pnr
                              , ata_extract_model(model, MAXMODEL, buffer)
                              , ata_extract_version(buffer)
                              , (u32)adjsize, adjprefix);
        port->prio = bootprio_find_ata_device(ctrl->pci_tmp, pnr, 0);
    } else {
        // found cdrom (atapi)
        port->drive.type = DTYPE_AHCI_ATAPI;
        port->drive.blksize = CDROM_SECTOR_SIZE;
        port->drive.sectors = (u64)-1;
        u8 iscd = ((buffer[0] >> 8) & 0x1f) == 0x05;
        if (!iscd) {
            dprintf(1, "AHCI/%d: atapi device isn't a cdrom\n", port->pnr);
            return -1;
        }
        port->desc = znprintf(MAXDESCSIZE
                              , "DVD/CD [AHCI/%d: %s ATAPI-%d DVD/CD]"
                              , port->pnr
                              , ata_extract_model(model, MAXMODEL, buffer)
                              , ata_extract_version(buffer));
        port->prio = bootprio_find_ata_device(ctrl->pci_tmp, pnr, 0);
    }
    return 0;
}

// Detect any drives attached to a given controller.
static void
ahci_port_detect(void *data)
{
    struct ahci_port_s *port = data;
    int rc;

    dprintf(2, "AHCI/%d: probing\n", port->pnr);
    ahci_port_reset(port->ctrl, port->pnr);
    rc = ahci_port_setup(port);
    if (rc < 0)
        ahci_port_release(port);
    else {
        port = ahci_port_realloc(port);
        if (port == NULL)
            return;
        dprintf(1, "AHCI/%d: registering: \"%s\"\n", port->pnr, port->desc);
        if (!port->atapi) {
            // Register with bcv system.
            boot_add_hd(&port->drive, port->desc, port->prio);
        } else {
            // fill cdidmap
            boot_add_cd(&port->drive, port->desc, port->prio);
        }
    }
}

// Initialize an ata controller and detect its drives.
static void
ahci_controller_setup(struct pci_device *pci)
{
    struct ahci_ctrl_s *ctrl = malloc_fseg(sizeof(*ctrl));
    struct ahci_port_s *port;
    u16 bdf = pci->bdf;
    u32 val, pnr, max;

    if (!ctrl) {
        warn_noalloc();
        return;
    }

    if (create_bounce_buf() < 0) {
        warn_noalloc();
        free(ctrl);
        return;
    }

    ctrl->pci_tmp = pci;
    ctrl->pci_bdf = bdf;
    ctrl->iobase = pci_config_readl(bdf, PCI_BASE_ADDRESS_5);
    ctrl->irq = pci_config_readb(bdf, PCI_INTERRUPT_LINE);
    dprintf(1, "AHCI controller at %02x.%x, iobase %x, irq %d\n",
            bdf >> 3, bdf & 7, ctrl->iobase, ctrl->irq);

    pci_config_maskw(bdf, PCI_COMMAND, 0,
                     PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

    val = ahci_ctrl_readl(ctrl, HOST_CTL);
    ahci_ctrl_writel(ctrl, HOST_CTL, val | HOST_CTL_AHCI_EN);

    ctrl->caps = ahci_ctrl_readl(ctrl, HOST_CAP);
    ctrl->ports = ahci_ctrl_readl(ctrl, HOST_PORTS_IMPL);
    dprintf(2, "AHCI: cap 0x%x, ports_impl 0x%x\n",
            ctrl->caps, ctrl->ports);

    max = 0x1f;
    for (pnr = 0; pnr <= max; pnr++) {
        if (!(ctrl->ports & (1 << pnr)))
            continue;
        port = ahci_port_alloc(ctrl, pnr);
        if (port == NULL)
            continue;
        run_thread(ahci_port_detect, port);
    }
}

// Locate and init ahci controllers.
static void
ahci_scan(void)
{
    // Scan PCI bus for ATA adapters
    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->class != PCI_CLASS_STORAGE_SATA)
            continue;
        if (pci->prog_if != 1 /* AHCI rev 1 */)
            continue;
        ahci_controller_setup(pci);
    }
}

void
ahci_setup(void)
{
    ASSERT32FLAT();
    if (!CONFIG_AHCI)
        return;

    dprintf(3, "init ahci\n");
    ahci_scan();
}
