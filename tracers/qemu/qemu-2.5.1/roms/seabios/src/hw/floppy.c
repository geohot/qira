// 16bit code to access floppy drives.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // SET_BDA
#include "block.h" // struct drive_s
#include "bregs.h" // struct bregs
#include "config.h" // CONFIG_FLOPPY
#include "malloc.h" // malloc_fseg
#include "output.h" // dprintf
#include "pci.h" // pci_to_bdf
#include "pci_ids.h" // PCI_CLASS_BRIDGE_ISA
#include "pic.h" // pic_eoi1
#include "romfile.h" // romfile_loadint
#include "rtc.h" // rtc_read
#include "stacks.h" // yield
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "util.h" // timer_calc

#define PORT_FD_BASE           0x03f0
#define PORT_FD_DOR            0x03f2
#define PORT_FD_STATUS         0x03f4
#define PORT_FD_DATA           0x03f5
#define PORT_FD_DIR            0x03f7

#define FLOPPY_SIZE_CODE 0x02 // 512 byte sectors
#define FLOPPY_DATALEN 0xff   // Not used - because size code is 0x02
#define FLOPPY_MOTOR_TICKS 37 // ~2 seconds
#define FLOPPY_FILLBYTE 0xf6
#define FLOPPY_GAPLEN 0x1B
#define FLOPPY_FORMAT_GAPLEN 0x6c
#define FLOPPY_PIO_TIMEOUT 1000

// New diskette parameter table adding 3 parameters from IBM
// Since no provisions are made for multiple drive types, most
// values in this table are ignored.  I set parameters for 1.44M
// floppy here
struct floppy_ext_dbt_s diskette_param_table2 VARFSEG = {
    .dbt = {
        .specify1       = 0xAF, // step rate 12ms, head unload 240ms
        .specify2       = 0x02, // head load time 4ms, DMA used
        .shutoff_ticks  = FLOPPY_MOTOR_TICKS, // ~2 seconds
        .bps_code       = FLOPPY_SIZE_CODE,
        .sectors        = 18,
        .interblock_len = FLOPPY_GAPLEN,
        .data_len       = FLOPPY_DATALEN,
        .gap_len        = FLOPPY_FORMAT_GAPLEN,
        .fill_byte      = FLOPPY_FILLBYTE,
        .settle_time    = 0x0F, // 15ms
        .startup_time   = 0x08, // 1 second
    },
    .max_track      = 79,   // maximum track
    .data_rate      = 0,    // data transfer rate
    .drive_type     = 4,    // drive type in cmos
};

struct floppyinfo_s {
    struct chs_s chs;
    u8 floppy_size;
    u8 data_rate;
};

#define FLOPPY_SIZE_525 0x01
#define FLOPPY_SIZE_350 0x02

#define FLOPPY_RATE_500K 0x00
#define FLOPPY_RATE_300K 0x01
#define FLOPPY_RATE_250K 0x02
#define FLOPPY_RATE_1M   0x03

struct floppyinfo_s FloppyInfo[] VARFSEG = {
    // Unknown
    { {0, 0, 0}, 0x00, 0x00},
    // 1 - 360KB, 5.25" - 2 heads, 40 tracks, 9 sectors
    { {2, 40, 9}, FLOPPY_SIZE_525, FLOPPY_RATE_300K},
    // 2 - 1.2MB, 5.25" - 2 heads, 80 tracks, 15 sectors
    { {2, 80, 15}, FLOPPY_SIZE_525, FLOPPY_RATE_500K},
    // 3 - 720KB, 3.5"  - 2 heads, 80 tracks, 9 sectors
    { {2, 80, 9}, FLOPPY_SIZE_350, FLOPPY_RATE_250K},
    // 4 - 1.44MB, 3.5" - 2 heads, 80 tracks, 18 sectors
    { {2, 80, 18}, FLOPPY_SIZE_350, FLOPPY_RATE_500K},
    // 5 - 2.88MB, 3.5" - 2 heads, 80 tracks, 36 sectors
    { {2, 80, 36}, FLOPPY_SIZE_350, FLOPPY_RATE_1M},
    // 6 - 160k, 5.25"  - 1 heads, 40 tracks, 8 sectors
    { {1, 40, 8}, FLOPPY_SIZE_525, FLOPPY_RATE_250K},
    // 7 - 180k, 5.25"  - 1 heads, 40 tracks, 9 sectors
    { {1, 40, 9}, FLOPPY_SIZE_525, FLOPPY_RATE_300K},
    // 8 - 320k, 5.25"  - 2 heads, 40 tracks, 8 sectors
    { {2, 40, 8}, FLOPPY_SIZE_525, FLOPPY_RATE_250K},
};

struct drive_s *
init_floppy(int floppyid, int ftype)
{
    if (ftype <= 0 || ftype >= ARRAY_SIZE(FloppyInfo)) {
        dprintf(1, "Bad floppy type %d\n", ftype);
        return NULL;
    }

    struct drive_s *drive = malloc_fseg(sizeof(*drive));
    if (!drive) {
        warn_noalloc();
        return NULL;
    }
    memset(drive, 0, sizeof(*drive));
    drive->cntl_id = floppyid;
    drive->type = DTYPE_FLOPPY;
    drive->blksize = DISK_SECTOR_SIZE;
    drive->floppy_type = ftype;
    drive->sectors = (u64)-1;

    memcpy(&drive->lchs, &FloppyInfo[ftype].chs
           , sizeof(FloppyInfo[ftype].chs));
    return drive;
}

static void
addFloppy(int floppyid, int ftype)
{
    struct drive_s *drive = init_floppy(floppyid, ftype);
    if (!drive)
        return;
    char *desc = znprintf(MAXDESCSIZE, "Floppy [drive %c]", 'A' + floppyid);
    struct pci_device *pci = pci_find_class(PCI_CLASS_BRIDGE_ISA); /* isa-to-pci bridge */
    int prio = bootprio_find_fdc_device(pci, PORT_FD_BASE, floppyid);
    boot_add_floppy(drive, desc, prio);
}

void
floppy_setup(void)
{
    memcpy(&diskette_param_table, &diskette_param_table2
           , sizeof(diskette_param_table));
    SET_IVT(0x1E, SEGOFF(SEG_BIOS
                         , (u32)&diskette_param_table2 - BUILD_BIOS_ADDR));

    if (! CONFIG_FLOPPY)
        return;
    dprintf(3, "init floppy drives\n");

    if (CONFIG_QEMU) {
        u8 type = rtc_read(CMOS_FLOPPY_DRIVE_TYPE);
        if (type & 0xf0)
            addFloppy(0, type >> 4);
        if (type & 0x0f)
            addFloppy(1, type & 0x0f);
    } else {
        u8 type = romfile_loadint("etc/floppy0", 0);
        if (type)
            addFloppy(0, type);
        type = romfile_loadint("etc/floppy1", 0);
        if (type)
            addFloppy(1, type);
    }

    enable_hwirq(6, FUNC16(entry_0e));
}

// Find a floppy type that matches a given image size.
int
find_floppy_type(u32 size)
{
    int i;
    for (i=1; i<ARRAY_SIZE(FloppyInfo); i++) {
        struct chs_s *c = &FloppyInfo[i].chs;
        if (c->cylinder * c->head * c->sector * DISK_SECTOR_SIZE == size)
            return i;
    }
    return -1;
}


/****************************************************************
 * Low-level floppy IO
 ****************************************************************/

u8 FloppyDOR VARLOW;

static inline void
floppy_dor_write(u8 val)
{
    outb(val, PORT_FD_DOR);
    SET_LOW(FloppyDOR, val);
}

static void
floppy_disable_controller(void)
{
    dprintf(2, "Floppy_disable_controller\n");
    floppy_dor_write(0x00);
}

static int
floppy_wait_irq(void)
{
    u8 frs = GET_BDA(floppy_recalibration_status);
    SET_BDA(floppy_recalibration_status, frs & ~FRS_IRQ);
    for (;;) {
        if (!GET_BDA(floppy_motor_counter)) {
            warn_timeout();
            floppy_disable_controller();
            return DISK_RET_ETIMEOUT;
        }
        frs = GET_BDA(floppy_recalibration_status);
        if (frs & FRS_IRQ)
            break;
        // Could use yield_toirq() here, but that causes issues on
        // bochs, so use yield() instead.
        yield();
    }

    SET_BDA(floppy_recalibration_status, frs & ~FRS_IRQ);
    return DISK_RET_SUCCESS;
}

// Floppy commands
#define FCF_WAITIRQ 0x10000
#define FC_CHECKIRQ    (0x08 | (0<<8) | (2<<12))
#define FC_SEEK        (0x0f | (2<<8) | (0<<12) | FCF_WAITIRQ)
#define FC_RECALIBRATE (0x07 | (1<<8) | (0<<12) | FCF_WAITIRQ)
#define FC_READID      (0x4a | (1<<8) | (7<<12) | FCF_WAITIRQ)
#define FC_READ        (0xe6 | (8<<8) | (7<<12) | FCF_WAITIRQ)
#define FC_WRITE       (0xc5 | (8<<8) | (7<<12) | FCF_WAITIRQ)
#define FC_FORMAT      (0x4d | (5<<8) | (7<<12) | FCF_WAITIRQ)

// Send the specified command and it's parameters to the floppy controller.
static int
floppy_pio(int command, u8 *param)
{
    dprintf(9, "Floppy pio command %x\n", command);
    // Send command and parameters to controller.
    u32 end = timer_calc(FLOPPY_PIO_TIMEOUT);
    int send = (command >> 8) & 0xf;
    int i = 0;
    for (;;) {
        u8 sts = inb(PORT_FD_STATUS);
        if (!(sts & 0x80)) {
            if (timer_check(end)) {
                warn_timeout();
                floppy_disable_controller();
                return DISK_RET_ETIMEOUT;
            }
            yield();
            continue;
        }
        if (sts & 0x40) {
            floppy_disable_controller();
            return DISK_RET_ECONTROLLER;
        }
        if (i == 0)
            outb(command & 0xff, PORT_FD_DATA);
        else
            outb(param[i-1], PORT_FD_DATA);
        if (i++ >= send)
            break;
    }

    // Wait for command to complete.
    if (command & FCF_WAITIRQ) {
        int ret = floppy_wait_irq();
        if (ret)
            return ret;
    }

    // Read response from controller.
    end = timer_calc(FLOPPY_PIO_TIMEOUT);
    int receive = (command >> 12) & 0xf;
    i = 0;
    for (;;) {
        u8 sts = inb(PORT_FD_STATUS);
        if (!(sts & 0x80)) {
            if (timer_check(end)) {
                warn_timeout();
                floppy_disable_controller();
                return DISK_RET_ETIMEOUT;
            }
            yield();
            continue;
        }
        if (i >= receive) {
            if (sts & 0x40) {
                floppy_disable_controller();
                return DISK_RET_ECONTROLLER;
            }
            break;
        }
        if (!(sts & 0x40)) {
            floppy_disable_controller();
            return DISK_RET_ECONTROLLER;
        }
        param[i++] = inb(PORT_FD_DATA);
    }

    return DISK_RET_SUCCESS;
}

static int
floppy_enable_controller(void)
{
    dprintf(2, "Floppy_enable_controller\n");
    SET_BDA(floppy_motor_counter, FLOPPY_MOTOR_TICKS);
    floppy_dor_write(0x00);
    floppy_dor_write(0x0c);
    int ret = floppy_wait_irq();
    if (ret)
        return ret;

    u8 param[2];
    return floppy_pio(FC_CHECKIRQ, param);
}

// Activate a drive and send a command to it.
static int
floppy_drive_pio(u8 floppyid, int command, u8 *param)
{
    // Enable controller if it isn't running.
    if (!(GET_LOW(FloppyDOR) & 0x04)) {
        int ret = floppy_enable_controller();
        if (ret)
            return ret;
    }

    // reset the disk motor timeout value of INT 08
    SET_BDA(floppy_motor_counter, FLOPPY_MOTOR_TICKS);

    // Turn on motor of selected drive, DMA & int enabled, normal operation
    floppy_dor_write((floppyid ? 0x20 : 0x10) | 0x0c | floppyid);

    // Send command.
    int ret = floppy_pio(command, param);
    if (ret)
        return ret;

    // Check IRQ command is needed after irq commands with no results
    if ((command & FCF_WAITIRQ) && ((command >> 12) & 0xf) == 0)
        return floppy_pio(FC_CHECKIRQ, param);
    return DISK_RET_SUCCESS;
}


/****************************************************************
 * Floppy media sense and seeking
 ****************************************************************/

static int
floppy_drive_recal(u8 floppyid)
{
    dprintf(2, "Floppy_drive_recal %d\n", floppyid);
    // send Recalibrate command to controller
    u8 param[2];
    param[0] = floppyid;
    int ret = floppy_drive_pio(floppyid, FC_RECALIBRATE, param);
    if (ret)
        return ret;

    u8 frs = GET_BDA(floppy_recalibration_status);
    SET_BDA(floppy_recalibration_status, frs | (1<<floppyid));
    SET_BDA(floppy_track[floppyid], 0);
    return DISK_RET_SUCCESS;
}

static int
floppy_drive_readid(u8 floppyid, u8 data_rate, u8 head)
{
    // Set data rate.
    outb(data_rate, PORT_FD_DIR);

    // send Read Sector Id command
    u8 param[7];
    param[0] = (head << 2) | floppyid; // HD DR1 DR2
    int ret = floppy_drive_pio(floppyid, FC_READID, param);
    if (ret)
        return ret;
    if (param[0] & 0xc0)
        return -1;
    return 0;
}

static int
floppy_media_sense(struct drive_s *drive_gf)
{
    u8 ftype = GET_GLOBALFLAT(drive_gf->floppy_type), stype = ftype;
    u8 floppyid = GET_GLOBALFLAT(drive_gf->cntl_id);

    u8 data_rate = GET_GLOBAL(FloppyInfo[stype].data_rate);
    int ret = floppy_drive_readid(floppyid, data_rate, 0);
    if (ret) {
        // Attempt media sense.
        for (stype=1; ; stype++) {
            if (stype >= ARRAY_SIZE(FloppyInfo))
                return DISK_RET_EMEDIA;
            if (stype==ftype
                || (GET_GLOBAL(FloppyInfo[stype].floppy_size)
                    != GET_GLOBAL(FloppyInfo[ftype].floppy_size))
                || (GET_GLOBAL(FloppyInfo[stype].chs.head)
                    > GET_GLOBAL(FloppyInfo[ftype].chs.head))
                || (GET_GLOBAL(FloppyInfo[stype].chs.cylinder)
                    > GET_GLOBAL(FloppyInfo[ftype].chs.cylinder))
                || (GET_GLOBAL(FloppyInfo[stype].chs.sector)
                    > GET_GLOBAL(FloppyInfo[ftype].chs.sector)))
                continue;
            data_rate = GET_GLOBAL(FloppyInfo[stype].data_rate);
            ret = floppy_drive_readid(floppyid, data_rate, 0);
            if (!ret)
                break;
        }
    }
    dprintf(2, "Floppy_media_sense on drive %d found rate %d\n"
            , floppyid, data_rate);

    u8 old_data_rate = GET_BDA(floppy_media_state[floppyid]) >> 6;
    SET_BDA(floppy_last_data_rate, (old_data_rate<<2) | (data_rate<<6));
    u8 media = (stype == 1 ? 0x04 : (stype == 2 ? 0x05 : 0x07));
    u8 fms = (data_rate<<6) | FMS_MEDIA_DRIVE_ESTABLISHED | media;
    if (GET_GLOBAL(FloppyInfo[stype].chs.cylinder)
        < GET_GLOBAL(FloppyInfo[ftype].chs.cylinder))
        fms |= FMS_DOUBLE_STEPPING;
    SET_BDA(floppy_media_state[floppyid], fms);

    return DISK_RET_SUCCESS;
}

// Prepare a floppy for a data transfer.
static int
floppy_prep(struct drive_s *drive_gf, u8 cylinder)
{
    u8 floppyid = GET_GLOBALFLAT(drive_gf->cntl_id);
    if (!(GET_BDA(floppy_recalibration_status) & (1<<floppyid)) ||
        !(GET_BDA(floppy_media_state[floppyid]) & FMS_MEDIA_DRIVE_ESTABLISHED)) {
        // Recalibrate drive.
        int ret = floppy_drive_recal(floppyid);
        if (ret)
            return ret;

        // Sense media.
        ret = floppy_media_sense(drive_gf);
        if (ret)
            return ret;
    }

    // Seek to cylinder if needed.
    u8 lastcyl = GET_BDA(floppy_track[floppyid]);
    if (cylinder != lastcyl) {
        u8 param[2];
        param[0] = floppyid;
        param[1] = cylinder;
        int ret = floppy_drive_pio(floppyid, FC_SEEK, param);
        if (ret)
            return ret;
        SET_BDA(floppy_track[floppyid], cylinder);
    }

    return DISK_RET_SUCCESS;
}


/****************************************************************
 * Floppy DMA transfer
 ****************************************************************/

// Perform a floppy transfer command (setup DMA and issue PIO).
static int
floppy_dma_cmd(struct disk_op_s *op, int count, int command, u8 *param)
{
    // Setup DMA controller
    int isWrite = command != FC_READ;
    int ret = dma_floppy((u32)op->buf_fl, count, isWrite);
    if (ret)
        return DISK_RET_EBOUNDARY;

    // Invoke floppy controller
    u8 floppyid = GET_GLOBALFLAT(op->drive_gf->cntl_id);
    ret = floppy_drive_pio(floppyid, command, param);
    if (ret)
        return ret;

    // Populate floppy_return_status in BDA
    int i;
    for (i=0; i<7; i++)
        SET_BDA(floppy_return_status[i], param[i]);

    if (param[0] & 0xc0) {
        if (param[1] & 0x02)
            return DISK_RET_EWRITEPROTECT;
        dprintf(1, "floppy error: %02x %02x %02x %02x %02x %02x %02x\n"
                , param[0], param[1], param[2], param[3]
                , param[4], param[5], param[6]);
        return DISK_RET_ECONTROLLER;
    }

    return DISK_RET_SUCCESS;
}


/****************************************************************
 * Floppy handlers
 ****************************************************************/

static struct chs_s
lba2chs(struct disk_op_s *op)
{
    struct chs_s res = { };

    u32 tmp = op->lba;
    u16 nls = GET_GLOBALFLAT(op->drive_gf->lchs.sector);
    res.sector = (tmp % nls) + 1;

    tmp /= nls;
    u16 nlh = GET_GLOBALFLAT(op->drive_gf->lchs.head);
    res.head = tmp % nlh;

    tmp /= nlh;
    res.cylinder = tmp;

    return res;
}

// diskette controller reset
static int
floppy_reset(struct disk_op_s *op)
{
    SET_BDA(floppy_recalibration_status, 0);
    SET_BDA(floppy_media_state[0], 0);
    SET_BDA(floppy_media_state[1], 0);
    SET_BDA(floppy_track[0], 0);
    SET_BDA(floppy_track[1], 0);
    SET_BDA(floppy_last_data_rate, 0);
    floppy_disable_controller();
    return floppy_enable_controller();
}

// Read Diskette Sectors
static int
floppy_read(struct disk_op_s *op)
{
    struct chs_s chs = lba2chs(op);
    int ret = floppy_prep(op->drive_gf, chs.cylinder);
    if (ret)
        return ret;

    // send read-normal-data command to controller
    u8 floppyid = GET_GLOBALFLAT(op->drive_gf->cntl_id);
    u8 param[8];
    param[0] = (chs.head << 2) | floppyid; // HD DR1 DR2
    param[1] = chs.cylinder;
    param[2] = chs.head;
    param[3] = chs.sector;
    param[4] = FLOPPY_SIZE_CODE;
    param[5] = chs.sector + op->count - 1; // last sector to read on track
    param[6] = FLOPPY_GAPLEN;
    param[7] = FLOPPY_DATALEN;
    return floppy_dma_cmd(op, op->count * DISK_SECTOR_SIZE, FC_READ, param);
}

// Write Diskette Sectors
static int
floppy_write(struct disk_op_s *op)
{
    struct chs_s chs = lba2chs(op);
    int ret = floppy_prep(op->drive_gf, chs.cylinder);
    if (ret)
        return ret;

    // send write-normal-data command to controller
    u8 floppyid = GET_GLOBALFLAT(op->drive_gf->cntl_id);
    u8 param[8];
    param[0] = (chs.head << 2) | floppyid; // HD DR1 DR2
    param[1] = chs.cylinder;
    param[2] = chs.head;
    param[3] = chs.sector;
    param[4] = FLOPPY_SIZE_CODE;
    param[5] = chs.sector + op->count - 1; // last sector to write on track
    param[6] = FLOPPY_GAPLEN;
    param[7] = FLOPPY_DATALEN;
    return floppy_dma_cmd(op, op->count * DISK_SECTOR_SIZE, FC_WRITE, param);
}

// Verify Diskette Sectors
static int
floppy_verify(struct disk_op_s *op)
{
    struct chs_s chs = lba2chs(op);
    int ret = floppy_prep(op->drive_gf, chs.cylinder);
    if (ret)
        return ret;

    // This command isn't implemented - just return success.
    return DISK_RET_SUCCESS;
}

// format diskette track
static int
floppy_format(struct disk_op_s *op)
{
    struct chs_s chs = lba2chs(op);
    int ret = floppy_prep(op->drive_gf, chs.cylinder);
    if (ret)
        return ret;

    // send format-track command to controller
    u8 floppyid = GET_GLOBALFLAT(op->drive_gf->cntl_id);
    u8 param[7];
    param[0] = (chs.head << 2) | floppyid; // HD DR1 DR2
    param[1] = FLOPPY_SIZE_CODE;
    param[2] = op->count; // number of sectors per track
    param[3] = FLOPPY_FORMAT_GAPLEN;
    param[4] = FLOPPY_FILLBYTE;
    return floppy_dma_cmd(op, op->count * 4, FC_FORMAT, param);
}

int
process_floppy_op(struct disk_op_s *op)
{
    if (!CONFIG_FLOPPY)
        return 0;

    switch (op->command) {
    case CMD_RESET:
        return floppy_reset(op);
    case CMD_READ:
        return floppy_read(op);
    case CMD_WRITE:
        return floppy_write(op);
    case CMD_VERIFY:
        return floppy_verify(op);
    case CMD_FORMAT:
        return floppy_format(op);
    default:
        return DISK_RET_EPARAM;
    }
}


/****************************************************************
 * HW irqs
 ****************************************************************/

// INT 0Eh Diskette Hardware ISR Entry Point
void VISIBLE16
handle_0e(void)
{
    if (! CONFIG_FLOPPY)
        return;
    debug_isr(DEBUG_ISR_0e);

    // diskette interrupt has occurred
    u8 frs = GET_BDA(floppy_recalibration_status);
    SET_BDA(floppy_recalibration_status, frs | FRS_IRQ);

    pic_eoi1();
}

// Called from int08 handler.
void
floppy_tick(void)
{
    if (! CONFIG_FLOPPY)
        return;

    // time to turn off drive(s)?
    u8 fcount = GET_BDA(floppy_motor_counter);
    if (fcount) {
        fcount--;
        SET_BDA(floppy_motor_counter, fcount);
        if (fcount == 0)
            // turn motor(s) off
            floppy_dor_write(GET_LOW(FloppyDOR) & ~0xf0);
    }
}
