#include "config.h"
#include "libopenbios/bindings.h"
#include "kernel/kernel.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "drivers/drivers.h"

#include "timer.h"

/* DECLARE data structures for the nodes.  */
DECLARE_UNNAMED_NODE( ob_floppy, INSTALL_OPEN, 2*sizeof(int) );

#ifdef CONFIG_DEBUG_FLOPPY
#define printk_info printk
#define printk_debug printk
#else
#define printk_info(x ...)
#define printk_debug(x ...)
#endif
#define printk_err printk

#define FD_DRIVE 0


#define FD_STATUS_A     (0)             /* Status register A */
#define FD_STATUS_B     (1)             /* Status register B */
#define FD_DOR          (2)             /* Digital Output Register */
#define FD_TDR          (3)             /* Tape Drive Register */
#define FD_STATUS       (4)             /* Main Status Register */
#define FD_DSR          (4)             /* Data Rate Select Register (old) */
#define FD_DATA         (5)             /* Data Transfer (FIFO) register */
#define FD_DIR          (7)             /* Digital Input Register (read) */
#define FD_DCR          (7)             /* Diskette Control Register (write)*/

/* Bit of FD_STATUS_A */
#define	STA_INT_PENDING	0x80		/* Interrupt Pending */

/* DOR */
#define DOR_DRIVE0	0x00
#define DOR_DRIVE1	0x01
#define DOR_DRIVE2	0x02
#define DOR_DRIVE3	0x03
#define DOR_DRIVE_MASK	0x03
#define DOR_NO_RESET	0x04
#define DOR_DMA_EN	0x08
#define DOR_MOT_EN0	0x10
#define DOR_MOT_EN1	0x20
#define DOR_MOT_EN2	0x40
#define DOR_MOT_EN3	0x80

/* Bits of main status register */
#define STATUS_BUSYMASK	0x0F		/* drive busy mask */
#define STATUS_BUSY	0x10		/* FDC busy */
#define STATUS_NON_DMA	0x20		/* 0- DMA mode */
#define STATUS_DIR	0x40		/* 0- cpu->fdc */
#define STATUS_READY	0x80		/* Data reg ready */

/* Bits of FD_ST0 */
#define ST0_DS		0x03		/* drive select mask */
#define ST0_HA		0x04		/* Head (Address) */
#define ST0_NR		0x08		/* Not Ready */
#define ST0_ECE		0x10		/* Equipment check error */
#define ST0_SE		0x20		/* Seek end */
#define ST0_INTR	0xC0		/* Interrupt code mask */
#define ST0_INTR_OK		(0 << 6)
#define ST0_INTR_ERROR		(1 << 6)
#define ST0_INTR_INVALID	(2 << 6)
#define ST0_INTR_POLL_ERROR 	(3 << 6)

/* Bits of FD_ST1 */
#define ST1_MAM		0x01		/* Missing Address Mark */
#define ST1_WP		0x02		/* Write Protect */
#define ST1_ND		0x04		/* No Data - unreadable */
#define ST1_OR		0x10		/* OverRun */
#define ST1_CRC		0x20		/* CRC error in data or addr */
#define ST1_EOC		0x80		/* End Of Cylinder */

/* Bits of FD_ST2 */
#define ST2_MAM		0x01		/* Missing Address Mark (again) */
#define ST2_BC		0x02		/* Bad Cylinder */
#define ST2_SNS		0x04		/* Scan Not Satisfied */
#define ST2_SEH		0x08		/* Scan Equal Hit */
#define ST2_WC		0x10		/* Wrong Cylinder */
#define ST2_CRC		0x20		/* CRC error in data field */
#define ST2_CM		0x40		/* Control Mark = deleted */

/* Bits of FD_ST3 */
#define ST3_HA		0x04		/* Head (Address) */
#define ST3_DS		0x08		/* drive is double-sided */
#define ST3_TZ		0x10		/* Track Zero signal (1=track 0) */
#define ST3_RY		0x20		/* drive is ready */
#define ST3_WP		0x40		/* Write Protect */
#define ST3_FT		0x80		/* Drive Fault */

/* Values for FD_COMMAND */
#define FD_RECALIBRATE		0x07	/* move to track 0 */
#define FD_SEEK			0x0F	/* seek track */
#define FD_READ			0xA6	/* read with MT, SKip deleted */
#define FD_WRITE		0xC5	/* write with MT, MFM */
#define FD_SENSEI		0x08	/* Sense Interrupt Status */
#define FD_SPECIFY		0x03	/* specify HUT etc */
#define FD_FORMAT		0x4D	/* format one track */
#define FD_VERSION		0x10	/* get version code */
#define FD_CONFIGURE		0x13	/* configure FIFO operation */
#define FD_PERPENDICULAR	0x12	/* perpendicular r/w mode */
#define FD_GETSTATUS		0x04	/* read ST3 */
#define FD_DUMPREGS		0x0E	/* dump the contents of the fdc regs */
#define FD_READID		0xEA	/* prints the header of a sector */
#define FD_UNLOCK		0x14	/* Fifo config unlock */
#define FD_LOCK			0x94	/* Fifo config lock */
#define FD_RSEEK_OUT		0x8f	/* seek out (i.e. to lower tracks) */
#define FD_RSEEK_IN		0xcf	/* seek in (i.e. to higher tracks) */


/* the following commands are new in the 82078. They are not used in the
 * floppy driver, except the first three. These commands may be useful for apps
 * which use the FDRAWCMD interface. For doc, get the 82078 spec sheets at
 * http://www-techdoc.intel.com/docs/periph/fd_contr/datasheets/ */

#define FD_PARTID		0x18	/* part id ("extended" version cmd) */
#define FD_SAVE			0x2e	/* save fdc regs for later restore */
#define FD_DRIVESPEC		0x8e	/* drive specification: Access to the
					 * 2 Mbps data transfer rate for tape
					 * drives */

#define FD_RESTORE		0x4e    /* later restore */
#define FD_POWERDOWN		0x27	/* configure FDC's powersave features */
#define FD_FORMAT_N_WRITE	0xef    /* format and write in one go. */
#define FD_OPTION		0x33	/* ISO format (which is a clean way to
					 * pack more sectors on a track) */

/* FDC version return types */
#define FDC_NONE	0x00
#define FDC_UNKNOWN	0x10	/* DO NOT USE THIS TYPE EXCEPT IF IDENTIFICATION
				   FAILS EARLY */
#define FDC_8272A	0x20	/* Intel 8272a, NEC 765 */
#define FDC_765ED	0x30	/* Non-Intel 1MB-compatible FDC, can't detect */
#define FDC_82072	0x40	/* Intel 82072; 8272a + FIFO + DUMPREGS */
#define FDC_82072A	0x45	/* 82072A (on Sparcs) */
#define FDC_82077_ORIG	0x51	/* Original version of 82077AA, sans LOCK */
#define FDC_82077	0x52	/* 82077AA-1 */
#define FDC_82078_UNKN	0x5f	/* Unknown 82078 variant */
#define FDC_82078	0x60	/* 44pin 82078 or 64pin 82078SL */
#define FDC_82078_1	0x61	/* 82078-1 (2Mbps fdc) */
#define FDC_S82078B	0x62	/* S82078B (first seen on Adaptec AVA-2825 VLB
				 * SCSI/EIDE/Floppy controller) */
#define FDC_87306	0x63	/* National Semiconductor PC 87306 */

/*
 * Beware: the fdc type list is roughly sorted by increasing features.
 * Presence of features is tested by comparing the FDC version id with the
 * "oldest" version that has the needed feature.
 * If during FDC detection, an obscure test fails late in the sequence, don't
 * assign FDC_UNKNOWN. Else the FDC will be treated as a dumb 8272a, or worse.
 * This is especially true if the tests are unneeded.
 */

/* Parameters for a 1.44 3.5" disk */
#define DISK_H1440_SIZE       2880
#define DISK_H1440_SECT       18
#define DISK_H1440_HEAD       2
#define DISK_H1440_TRACK      80
#define DISK_H1440_STRETCH    0
#define DISK_H1440_GAP        0x1B
#define DISK_H1440_RATE       0x00
#define DISK_H1440_SPEC1      0xCF
#define DISK_H1440_FMT_GAP    0x6C

/* Parameters for a 1.44 3.5" drive */
#define DRIVE_H1440_MAX_DTR          500
#define DRIVE_H1440_HLT              16   /* ms */
#define DRIVE_H1440_HUT              16   /* ms */
#define DRIVE_H1440_SRT              4000 /* us */
#define DRIVE_H1440_SPINUP           400  /* ms */
#define DRIVE_H1440_SPINDOWN         3000 /* ms */
#define DRIVE_H1440_SPINDOWN_OFFSET  10
#define DRIVE_H1440_SELECT_DELAY     20  /* ms */
#define DRIVE_H1440_RPS              5
#define DRIVE_H1440_TRACKS           83
#define DRIVE_H1440_TIMEOUT          3000 /* ms */
#define DRIVE_H1440_INTERLEAVE_SECT  20

/* Floppy drive configuration */
#define FIFO_DEPTH            10
#define USE_IMPLIED_SEEK      0
#define USE_FIFO              1
#define FIFO_THRESHOLD        10
#define TRACK_PRECOMPENSATION 0

#define SLOW_FLOPPY 0

#define FD_RESET_DELAY 20 /* microseconds */

/*
 * FDC state
 */
static struct drive_state {
	unsigned track;
} drive_state[1];

static struct floppy_fdc_state {
	int in_sync;
	int spec1;		/* spec1 value last used */
	int spec2;		/* spec2 value last used */
	int dtr;
	unsigned char dor;
	unsigned char version;	/* FDC version code */
        void (*fdc_outb)(unsigned char data, unsigned long port);
        unsigned char (*fdc_inb)(unsigned long port);
        unsigned long io_base;
        unsigned long mmio_base;
} fdc_state;

/* Synchronization of FDC access. */
#define FD_COMMAND_NONE -1
#define FD_COMMAND_ERROR 2
#define FD_COMMAND_OKAY 3

/*
 * globals used by 'result()'
 */
#define MAX_REPLIES 16

static void show_floppy(void);
static void floppy_reset(void);

/*
 * IO port operations
 */
static unsigned char
ob_fdc_inb(unsigned long port)
{
    return inb(fdc_state.io_base + port);
}

static void
ob_fdc_outb(unsigned char data, unsigned long port)
{
    outb(data, fdc_state.io_base + port);
}

/*
 * MMIO operations
 */
static unsigned char
ob_fdc_mmio_readb(unsigned long port)
{
    return *(unsigned char *)(fdc_state.mmio_base + port);
}

static void
ob_fdc_mmio_writeb(unsigned char data, unsigned long port)
{
    *(unsigned char *)(fdc_state.mmio_base + port) = data;
}

static int set_dor(char mask, char data)
{
	unsigned char newdor,olddor;

	olddor = fdc_state.dor;
	newdor =  (olddor & mask) | data;
	if (newdor != olddor){
		fdc_state.dor = newdor;
                fdc_state.fdc_outb(newdor, FD_DOR);
	}
	return olddor;
}

/* waits until the fdc becomes ready */
static int wait_til_ready(void)
{
	int counter, status;
	for (counter = 0; counter < 10000; counter++) {
                status = fdc_state.fdc_inb(FD_STATUS);
		if (status & STATUS_READY) {
			return status;
		}
	}
	printk_debug("Getstatus times out (%x)\n", status);
	show_floppy();
	return -3;
}


/* sends a command byte to the fdc */
static int output_byte(unsigned char byte)
{
	int status;

	if ((status = wait_til_ready()) < 0)
		return status;
	if ((status & (STATUS_READY|STATUS_DIR|STATUS_NON_DMA)) == STATUS_READY){
                fdc_state.fdc_outb(byte,FD_DATA);
		return 0;
	}
	printk_debug("Unable to send byte %x to FDC_STATE. Status=%x\n",
		byte, status);

	show_floppy();
	return -2;
}

/* gets the response from the fdc */
static int result(unsigned char *reply_buffer, int max_replies)
{
	int i, status=0;

	for(i=0; i < max_replies; i++) {
		if ((status = wait_til_ready()) < 0)
			break;
		status &= STATUS_DIR|STATUS_READY|STATUS_BUSY|STATUS_NON_DMA;
		if ((status & ~STATUS_BUSY) == STATUS_READY){
			return i;
		}
		if (status == (STATUS_DIR|STATUS_READY|STATUS_BUSY))
                        reply_buffer[i] = fdc_state.fdc_inb(FD_DATA);
		else
			break;
	}
	if (i == max_replies)
		return i;
	printk_debug("get result error. Last status=%x Read bytes=%d\n",
		status, i);
	show_floppy();
	return -1;
}
#define MORE_OUTPUT -2
/* does the fdc need more output? */
static int need_more_output(void)
{
	unsigned char reply_buffer[MAX_REPLIES];
	int status;
	if ((status = wait_til_ready()) < 0)
		return -1;
	if ((status & (STATUS_READY|STATUS_DIR|STATUS_NON_DMA)) == STATUS_READY)
		return MORE_OUTPUT;
	return result(reply_buffer, MAX_REPLIES);
}

static int output_command(unsigned char *cmd, int count)
{
	int i, status;
	for(i = 0; i < count; i++) {
		if ((status = output_byte(cmd[i])) < 0) {
			printk_err("full command not acceppted, status =%x\n",
				status);
			return -1;
		}
	}
	return 0;
}

static int output_new_command(unsigned char *cmd, int count)
{
	int i, status;
	if ((status = output_byte(cmd[0])) < 0)
		return -1;
	if (need_more_output() != MORE_OUTPUT)
		return -1;
	for(i = 1; i < count; i++) {
		if ((status = output_byte(cmd[i])) < 0) {
			printk_err("full new command not acceppted, status =%d\n",
				status);
			return -1;
		}
	}
	return 0;
}


/* Collect pending interrupt status */
static unsigned char collect_interrupt(void)
{
	unsigned char pcn = 0xff;
	unsigned char reply_buffer[MAX_REPLIES];
        int nr;
#ifdef CONFIG_DEBUG_FLOPPY
        int i, status;
#endif
	nr = result(reply_buffer, MAX_REPLIES);
	if (nr != 0) {
		printk_debug("SENSEI\n");
	}
	else {
		int max_sensei = 4;
		do {
			if (output_byte(FD_SENSEI) < 0)
				break;
			nr = result(reply_buffer, MAX_REPLIES);
			if (nr == 2) {
				pcn = reply_buffer[1];
				printk_debug("SENSEI %02x %02x\n",
					reply_buffer[0], reply_buffer[1]);
			}
                        max_sensei--;
		}while(((reply_buffer[0] & 0x83) != FD_DRIVE) && (nr == 2) && max_sensei);
#ifdef CONFIG_DEBUG_FLOPPY
                status = fdc_state.fdc_inb(FD_STATUS);
		printk_debug("status = %x, reply_buffer=", status);
		for(i = 0; i < nr; i++) {
			printk_debug(" %x",
				reply_buffer[i]);
		}
		printk_debug("\n");
#else
                fdc_state.fdc_inb(FD_STATUS);
#endif
	}

	return pcn;
}


/* selects the fdc and drive, and enables the fdc's input/dma, and it's motor. */
static void set_drive(int drive)
{
	int fdc = (drive >> 2) & 1;
	int status;
	unsigned new_dor;
	if (drive > 3) {
		printk_err("bad drive value\n");
		return;
	}
	if (fdc != 0) {
		printk_err("bad fdc value\n");
		return;
	}
	drive &= 3;
#if 0
	new_dor = 8; /* Enable the controller */
#else
	new_dor = 0; /* Don't enable DMA on the controller */
#endif
	new_dor |= (1 << (drive + 4)); /* Spinup the selected drive */
	new_dor |= drive; /* Select the drive for commands as well */
        set_dor(0xc, new_dor);

	mdelay(DRIVE_H1440_SPINUP);

        status = fdc_state.fdc_inb(FD_STATUS);
	printk_debug("set_drive status = %02x, new_dor = %02x\n",
		status, new_dor);
	if (status != STATUS_READY) {
		printk_err("set_drive bad status\n");
	}
}


/* Disable the motor for a given floppy drive */
static void floppy_motor_off(int drive)
{
	unsigned mask;
	printk_debug("floppy_motor_off\n");
	/* fix the number of drives */
	drive &= 3;
	/* Clear the bit for the drive we care about */
	mask = 0xff;
	mask &= ~(1 << (drive +4));
	/* Now clear the bit in the Digital Output Register */
        set_dor(mask, 0);
}

/* Set the FDC's data transfer rate on behalf of the specified drive.
 * NOTE: with 82072/82077 FDCs, changing the data rate requires a reissue
 * of the specify command (i.e. using the fdc_specify function).
 */
static void fdc_dtr(unsigned rate)
{
	rate &= 3;
	/* If data rate not already set to desired value, set it. */
	if (fdc_state.in_sync && (rate == fdc_state.dtr))
		return;

	/* Set dtr */
        fdc_state.fdc_outb(rate, FD_DCR);

	/* TODO: some FDC/drive combinations (C&T 82C711 with TEAC 1.2MB)
	 * need a stabilization period of several milliseconds to be
	 * enforced after data rate changes before R/W operations.
	 * Pause 5 msec to avoid trouble. (Needs to be 2 jiffies)
	 */
	fdc_state.dtr = rate & 3;
	mdelay(5);
} /* fdc_dtr */

static int fdc_configure(int use_implied_seek, int use_fifo,
	unsigned fifo_threshold, unsigned precompensation)
{
	unsigned config_bits;
	unsigned char cmd[4];
	/* 0 EIS EFIFO POLL FIFOOTHR[4] */

	/* santize parameters */
	config_bits = fifo_threshold & 0xf;
	config_bits |= (1 << 4); /* Always disable background floppy poll */
	config_bits |= (!use_fifo) << 5;
	config_bits |= (!!use_implied_seek) << 6;

	precompensation &= 0xff; /* pre-compensation from track 0 upwards */

	cmd[0] = FD_CONFIGURE;
	cmd[1] = 0;
	cmd[2] = config_bits;
	cmd[3] = precompensation;

	/* Turn on FIFO */
	if (output_new_command(cmd, 4) < 0)
		return 0;
	return 1;
}

#define NOMINAL_DTR 500
/* Issue a "SPECIFY" command to set the step rate time, head unload time,
 * head load time, and DMA disable flag to values needed by floppy.
 *
 * The value "dtr" is the data transfer rate in Kbps.  It is needed
 * to account for the data rate-based scaling done by the 82072 and 82077
 * FDC types.  This parameter is ignored for other types of FDCs (i.e.
 * 8272a).
 *
 * Note that changing the data transfer rate has a (probably deleterious)
 * effect on the parameters subject to scaling for 82072/82077 FDCs, so
 * fdc_specify is called again after each data transfer rate
 * change.
 *
 * srt: 1000 to 16000 in microseconds
 * hut: 16 to 240 milliseconds
 * hlt: 2 to 254 milliseconds
 *
 * These values are rounded up to the next highest available delay time.
 */
static void fdc_specify(
	unsigned head_load_time, unsigned head_unload_time, unsigned step_rate)
{
	unsigned char cmd[3];
	unsigned long srt, hlt, hut;
	unsigned long dtr = NOMINAL_DTR;
	unsigned long scale_dtr = NOMINAL_DTR;
	int hlt_max_code = 0x7f;
	int hut_max_code = 0xf;

	printk_debug("fdc_specify\n");

	switch (DISK_H1440_RATE & 0x03) {
		case 3:
			dtr = 1000;
			break;
		case 1:
			dtr = 300;
			if (fdc_state.version >= FDC_82078) {
				/* chose the default rate table, not the one
				 * where 1 = 2 Mbps */
				cmd[0] = FD_DRIVESPEC;
				cmd[1] = FD_DRIVE & 3;
				cmd[2] = 0xc0;
				output_new_command(cmd,3);
				/* FIXME how do I handle errors here? */
			}
			break;
		case 2:
			dtr = 250;
			break;
	}


	if (fdc_state.version >= FDC_82072) {
		scale_dtr = dtr;
		hlt_max_code = 0x00; /* 0==256msec*dtr0/dtr (not linear!) */
		hut_max_code = 0x0; /* 0==256msec*dtr0/dtr (not linear!) */
	}

	/* Convert step rate from microseconds to milliseconds and 4 bits */
	srt = 16 - (step_rate*scale_dtr/1000 + NOMINAL_DTR - 1)/NOMINAL_DTR;
	if (SLOW_FLOPPY) {
		srt = srt / 4;
	}
	if (srt > 0xf) {
		srt = 0xf;
	}

	hlt = (head_load_time*scale_dtr/2 + NOMINAL_DTR - 1)/NOMINAL_DTR;
	if (hlt < 0x01)
		hlt = 0x01;
	else if (hlt > 0x7f)
		hlt = hlt_max_code;

	hut = (head_unload_time*scale_dtr/16 + NOMINAL_DTR - 1)/NOMINAL_DTR;
	if (hut < 0x1)
		hut = 0x1;
	else if (hut > 0xf)
		hut = hut_max_code;

	cmd[0] = FD_SPECIFY;
	cmd[1] = (srt << 4) | hut;
	cmd[2] = (hlt << 1) | 1; /* Always disable DMA */

	/* If these parameters did not change, just return with success */
	if (!fdc_state.in_sync || fdc_state.spec1 != cmd[1] || fdc_state.spec2 != cmd[2]) {
		/* Go ahead and set spec1 and spec2 */
		output_command(cmd, 3);
		/* FIXME how do I handle errors here... */
		printk_info("FD_SPECIFY(%02x, %02x)\n", cmd[1], cmd[2]);
	}
} /* fdc_specify */


/*
 * reset is done by pulling bit 2 of DOR low for a while (old FDCs),
 * or by setting the self clearing bit 7 of STATUS (newer FDCs)
 */
static void reset_fdc(void)
{
	unsigned char reply[MAX_REPLIES];

	fdc_state.in_sync = 0;

	/* Pseudo-DMA may intercept 'reset finished' interrupt.  */
	/* Irrelevant for systems with true DMA (i386).          */

	if (fdc_state.version >= FDC_82072A)
                fdc_state.fdc_outb(0x80 | (fdc_state.dtr &3), FD_DSR);
	else {
                fdc_state.fdc_outb(fdc_state.dor & ~DOR_NO_RESET, FD_DOR);
		udelay(FD_RESET_DELAY);
                fdc_state.fdc_outb(fdc_state.dor, FD_DOR);
	}
	result(reply, MAX_REPLIES);
}



static void show_floppy(void)
{

	printk_debug("\n");
	printk_debug("floppy driver state\n");
	printk_debug("-------------------\n");

	printk_debug("fdc_bytes: %02x %02x xx %02x %02x %02x xx %02x\n",
                     fdc_state.fdc_inb(FD_STATUS_A),
                     fdc_state.fdc_inb(FD_STATUS_B),
                     fdc_state.fdc_inb(FD_TDR),
                     fdc_state.fdc_inb(FD_STATUS),
                     fdc_state.fdc_inb(FD_DATA),
                     fdc_state.fdc_inb(FD_DIR));

        printk_debug("status=%x\n", fdc_state.fdc_inb(FD_STATUS));
	printk_debug("\n");
}

static void floppy_recalibrate(void)
{
	unsigned char cmd[2];
	unsigned char reply[MAX_REPLIES];
	int nr, success;
	success = 0;
	do {
		printk_debug("floppy_recalibrate\n");
		/* Send the recalibrate command to the controller.
		 * We don't have interrupts or anything we can poll
		 * so we have to guess when it is done.
		 */
		cmd[0] = FD_RECALIBRATE;
		cmd[1] = 0;
		if (output_command(cmd, 2) < 0)
			continue;

		/* Sleep for the maximum time the recalibrate command
		 * can run.
		 */
		mdelay(80*DRIVE_H1440_SRT/1000);

		/* Now call FD_SENSEI to end the command
		 * and collect up the reply.
		 */
		if (output_byte(FD_SENSEI) < 0)
			continue;
		nr = result(reply, MAX_REPLIES);

		/* Now see if we have succeeded in our seek */
		success =
			/* We have the right size result */
			(nr == 2) &&
			/* The command didn't terminate in error */
			((reply[0] & ST0_INTR) == ST0_INTR_OK) &&
			/* We finished a seek */
			(reply[0] & ST0_SE) &&
			/* We are at cylinder 0 */
			(reply[1] == 0);
	} while(!success);
	/* Remember we are at track 0 */
	drive_state[FD_DRIVE].track = 0;
}


static int floppy_seek(unsigned track)
{
	unsigned char cmd[3];
	unsigned char reply[MAX_REPLIES];
	int nr, success;
	unsigned distance, old_track;

	/* Look up the old track and see if we need to
	 * do anything.
	 */
	old_track = drive_state[FD_DRIVE].track;
	if (old_track == track) {
		return 1;
	}

	/* Compute the distance we are about to move,
	 * We need to know this so we know how long to sleep...
	 */
	distance = (old_track > track)?(old_track - track):(track - old_track);
	distance += 1;


	/* Send the seek command to the controller.
	 * We don't have interrupts or anything we can poll
	 * so we have to guess when it is done.
	 */
	cmd[0] = FD_SEEK;
	cmd[1] = FD_DRIVE;
	cmd[2] = track;
	if (output_command(cmd, 3) < 0)
		return 0;

	/* Sleep for the time it takes to step throuhg distance tracks.
	 */
	mdelay(distance*DRIVE_H1440_SRT/1000);

	/* Now call FD_SENSEI to end the command
	 * and collect up the reply.
	 */
	cmd[0] = FD_SENSEI;
	if (output_command(cmd, 1) < 0)
		return 0;
	nr = result(reply, MAX_REPLIES);

	/* Now see if we have succeeded in our seek */
	success =
		/* We have the right size result */
		(nr == 2) &&
		/* The command didn't terminate in error */
		((reply[0] & ST0_INTR) == ST0_INTR_OK) &&
		/* We finished a seek */
		(reply[0] & ST0_SE) &&
		/* We are at cylinder 0 */
		(reply[1] == track);
	if (success)
		drive_state[FD_DRIVE].track = track;
	else {
		printk_debug("seek failed\n");
		printk_debug("nr = %d\n", nr);
		printk_debug("ST0 = %02x\n", reply[0]);
		printk_debug("PCN = %02x\n", reply[1]);
                printk_debug("status = %d\n", fdc_state.fdc_inb(FD_STATUS));
	}
	return success;
}

static int read_ok(unsigned head)
{
	unsigned char results[7];
	int result_ok;
	int nr;

	/* read back the read results */
	nr = result(results, 7);

	/* Now see if they say we are o.k. */
	result_ok = 0;
	/* Are my result bytes o.k.? */
	if (nr == 7) {
		/* Are we o.k. */
		if ((results[0] & ST0_INTR) == ST0_INTR_OK) {
			result_ok = 1;
		}
		/* Or did we get just an overflow error */
		else if (((results[0] & ST0_INTR) == ST0_INTR_ERROR) &&
			(results[1]== ST1_OR) &&
			(results[2] == 0)) {
			result_ok = 1;
		}
		/* Verify the reply had the correct head */
		if (((results[0] & ST0_HA) >> 2) != head) {
			result_ok = 0;
		}
		/* Verify the reply had the correct drive */
		if (((results[0] & ST0_DS) != FD_DRIVE)) {
			result_ok = 0;
		}
	}
	if (!result_ok) {
		printk_debug("result_bytes = %d\n", nr);
		printk_debug("ST0 = %02x\n", results[0]);
		printk_debug("ST1 = %02x\n", results[1]);
		printk_debug("ST2 = %02x\n", results[2]);
		printk_debug("  C = %02x\n", results[3]);
		printk_debug("  H = %02x\n", results[4]);
		printk_debug("  R = %02x\n", results[5]);
		printk_debug("  N = %02x\n", results[6]);
	}
	return result_ok;
}

static int floppy_read_sectors(
	char *dest, unsigned byte_offset, unsigned length,
	unsigned sector, unsigned head, unsigned track)
{
	/* MT  == Multitrack */
	/* MFM == MFM or FM Mode */
	/* SK  == Skip deleted data addres Mark */
	/* HDS == Head number select */
	/* DS0 == Disk Drive Select 0 */
	/* DS1 == Disk Drive Select 1 */
	/* C   == Cylinder number 0 - 255 */
	/* H   == Head number */
	/* R   == Record */
	/* N   == The number of data bytes written in a sector */
	/* EOT == End of Track */
	/* GPL == Gap Length */
	/* DTL == Data Length */
	/* MT MFM  SK  0 1 1   0   0 */
	/* 0  0    0   0 0 HDS DS1 DS0 */
	/* C, H, R, N, EOT, GPL, DTL */

	int i, status, result_ok;
	int max_bytes, bytes_read;
	int ret;
	unsigned char cmd[9];
	unsigned end_offset;

	end_offset = byte_offset + length;
	max_bytes = 512*(DISK_H1440_SECT - sector + 1);

	if (byte_offset >= max_bytes) {
		return 0;
	}
	cmd[0] = FD_READ | (((DISK_H1440_HEAD ==2)?1:0) << 6);
	cmd[1] = (head << 2) | FD_DRIVE;
	cmd[2] = track;
	cmd[3] = head;
	cmd[4] = sector;
	cmd[5] = 2; /* 2^N *128 == Sector size.  Hard coded to 512 bytes */
	cmd[6] = DISK_H1440_SECT;
	cmd[7] = DISK_H1440_GAP;
	cmd[8] = 0xff;

	/* Output the command bytes */
	if (output_command(cmd, 9) < 0)
		return -1;

	/* The execution stage begins when STATUS_READY&STATUS_NON_DMA is set */
	do {
                status = fdc_state.fdc_inb(FD_STATUS);
		status &= STATUS_READY | STATUS_NON_DMA;
	} while(status != (STATUS_READY|STATUS_NON_DMA));

	for(i = 0; i < max_bytes; i++) {
		unsigned char byte;
		if ((status = wait_til_ready()) < 0) {
			break;
		}
		status &= STATUS_READY|STATUS_DIR|STATUS_NON_DMA;
		if (status != (STATUS_READY|STATUS_DIR|STATUS_NON_DMA)) {
			break;
		}
                byte = fdc_state.fdc_inb(FD_DATA);
		if ((i >= byte_offset) && (i < end_offset)) {
			dest[i - byte_offset] = byte;
		}
	}
	bytes_read = i;

	/* The result stage begins when STATUS_NON_DMA is cleared */
        while((status = fdc_state.fdc_inb(FD_STATUS)) & STATUS_NON_DMA) {
		/* We get extra bytes in the fifo  past
		 * the end of the sector and drop them on the floor.
		 * Otherwise the fifo is polluted.
		 */
                fdc_state.fdc_inb(FD_DATA);
	}
	/* Did I get an error? */
	result_ok = read_ok(head);
	/* Did I read enough bytes? */
	ret = -1;
	if (result_ok && (bytes_read == max_bytes)) {
		ret = bytes_read - byte_offset;
		if (ret > length) {
			ret = length;
		}
	}

	if (ret < 0) {
		printk_debug("ret = %d\n", ret);
		printk_debug("bytes_read = %d\n", bytes_read);
		printk_debug("status = %x\n", status);
	}
	return ret;
}


static int __floppy_read(char *dest, unsigned long offset, unsigned long length)
{
	unsigned head, track, sector, byte_offset, sector_offset;
	int ret;

	/* break the offset up into sectors and bytes */
	byte_offset = offset % 512;
	sector_offset = offset / 512;

	/* Find the disk block we are starting with... */
	sector = (sector_offset % DISK_H1440_SECT) + 1;
	head = (sector_offset / DISK_H1440_SECT) % DISK_H1440_HEAD;
	track = (sector_offset / (DISK_H1440_SECT *DISK_H1440_HEAD))% DISK_H1440_TRACK;

	/* First seek to our start track */
	if (!floppy_seek(track)) {
		return -1;
	}
	/* Then read the data */
	ret = floppy_read_sectors(dest, byte_offset, length, sector, head, track);
	if (ret >= 0) {
		return ret;
	}
	/* If we failed reset the fdc... */
	floppy_reset();
	return -1;
}

static int floppy_read(char *dest, unsigned long offset, unsigned long length)
{
        int fr_result, bytes_read;;

	printk_debug("floppy_read\n");
	bytes_read = 0;
	do {
		int max_errors = 3;
		do {
                        fr_result = __floppy_read(dest + bytes_read, offset,
                                                  length - bytes_read);
			if (max_errors-- == 0) {
				return (bytes_read)?bytes_read: -1;
			}
                } while (fr_result <= 0);
                offset += fr_result;
                bytes_read += fr_result;
	} while(bytes_read < length);
	return bytes_read;
}

/* Determine the floppy disk controller type */
/* This routine was written by David C. Niemi */
static char get_fdc_version(void)
{
	int bytes, ret;
	unsigned char reply_buffer[MAX_REPLIES];

	ret = output_byte(FD_DUMPREGS); /* 82072 and better know DUMPREGS */
	if (ret < 0)
		return FDC_NONE;
	if ((bytes = result(reply_buffer, MAX_REPLIES)) <= 0x00)
		return FDC_NONE;	/* No FDC present ??? */
	if ((bytes==1) && (reply_buffer[0] == 0x80)){
		printk_info("FDC is an 8272A\n");
		return FDC_8272A;	/* 8272a/765 don't know DUMPREGS */
	}
	if (bytes != 10) {
		printk_debug("init: DUMPREGS: unexpected return of %d bytes.\n",
			bytes);
		return FDC_UNKNOWN;
	}
	if (!fdc_configure(USE_IMPLIED_SEEK, USE_FIFO, FIFO_THRESHOLD,
		TRACK_PRECOMPENSATION)) {
		printk_info("FDC is an 82072\n");
		return FDC_82072;      	/* 82072 doesn't know CONFIGURE */
	}

	output_byte(FD_PERPENDICULAR);
	if (need_more_output() == MORE_OUTPUT) {
		output_byte(0);
	} else {
		printk_info("FDC is an 82072A\n");
		return FDC_82072A;	/* 82072A as found on Sparcs. */
	}

	output_byte(FD_UNLOCK);
	bytes = result(reply_buffer, MAX_REPLIES);
	if ((bytes == 1) && (reply_buffer[0] == 0x80)){
		printk_info("FDC is a pre-1991 82077\n");
		return FDC_82077_ORIG;	/* Pre-1991 82077, doesn't know
					 * LOCK/UNLOCK */
	}
	if ((bytes != 1) || (reply_buffer[0] != 0x00)) {
		printk_debug("FDC init: UNLOCK: unexpected return of %d bytes.\n",
			bytes);
		return FDC_UNKNOWN;
	}
	output_byte(FD_PARTID);
	bytes = result(reply_buffer, MAX_REPLIES);
	if (bytes != 1) {
		printk_debug("FDC init: PARTID: unexpected return of %d bytes.\n",
			bytes);
		return FDC_UNKNOWN;
	}
	if (reply_buffer[0] == 0x80) {
		printk_info("FDC is a post-1991 82077\n");
		return FDC_82077;	/* Revised 82077AA passes all the tests */
	}
	switch (reply_buffer[0] >> 5) {
	case 0x0:
		/* Either a 82078-1 or a 82078SL running at 5Volt */
		printk_info("FDC is an 82078.\n");
		return FDC_82078;
	case 0x1:
		printk_info("FDC is a 44pin 82078\n");
		return FDC_82078;
	case 0x2:
		printk_info("FDC is a S82078B\n");
		return FDC_S82078B;
	case 0x3:
		printk_info("FDC is a National Semiconductor PC87306\n");
		return FDC_87306;
	default:
		printk_info("FDC init: 82078 variant with unknown PARTID=%d.\n",
			reply_buffer[0] >> 5);
		return FDC_82078_UNKN;
	}
} /* get_fdc_version */


static int floppy_init(unsigned long io_base, unsigned long mmio_base)
{
	printk_debug("floppy_init\n");
	fdc_state.in_sync = 0;
	fdc_state.spec1 = -1;
	fdc_state.spec2 = -1;
	fdc_state.dtr = -1;
	fdc_state.dor = DOR_NO_RESET;
	fdc_state.version = FDC_UNKNOWN;
        if (mmio_base) {
            fdc_state.fdc_inb = ob_fdc_mmio_readb;
            fdc_state.fdc_outb = ob_fdc_mmio_writeb;
        } else {
            fdc_state.fdc_inb = ob_fdc_inb;
            fdc_state.fdc_outb = ob_fdc_outb;
        }
        fdc_state.io_base = io_base;
        fdc_state.mmio_base = mmio_base;
	reset_fdc();
	/* Try to determine the floppy controller type */
	fdc_state.version = get_fdc_version();
	if (fdc_state.version == FDC_NONE) {
		return -1;
	}
	floppy_reset();
	printk_info("fdc_state.version = %04x\n", fdc_state.version);
	return 0;
}

static void floppy_reset(void)
{
	printk_debug("floppy_reset\n");
	floppy_motor_off(FD_DRIVE);
	reset_fdc();
	fdc_dtr(DISK_H1440_RATE);
	/* program data rate via ccr */
	collect_interrupt();
	fdc_configure(USE_IMPLIED_SEEK, USE_FIFO, FIFO_THRESHOLD,
		TRACK_PRECOMPENSATION);
	fdc_specify(DRIVE_H1440_HLT, DRIVE_H1440_HUT, DRIVE_H1440_SRT);
	set_drive(FD_DRIVE);
	floppy_recalibrate();
	fdc_state.in_sync = 1;
}

static void
ob_floppy_initialize(const char *path)
{
        int props[3];
        phandle_t ph = find_dev(path);

        set_property(ph, "device_type", "block", sizeof("block"));

	// Set dummy reg properties
        props[0] = __cpu_to_be32(0); props[1] = __cpu_to_be32(0); props[2] = __cpu_to_be32(0);
        set_property(ph, "reg", (char *)&props, 3*sizeof(int));

        fword("is-deblocker");
}


static void
ob_floppy_open(int *idx)
{
        int ret = 1;
        phandle_t ph;

        fword("my-unit");
        idx[0]=POP();

        fword("my-parent");
        fword("ihandle>phandle");
        ph=(phandle_t)POP();

        selfword("open-deblocker");

        /* interpose disk-label */
        ph = find_dev("/packages/disk-label");
        fword("my-args");
        PUSH_ph( ph );
        fword("interpose");

        RET ( -ret );
}

static void
ob_floppy_close(int *idx)
{
        selfword("close-deblocker");
}

static void
ob_floppy_read_blocks(int *idx)
{
        cell cnt = POP();
        ucell blk = POP();
        char *dest = (char*)POP();
	floppy_read(dest, blk*512, cnt*512);
	PUSH(cnt);
}


static void
ob_floppy_block_size(int *idx)
{
        PUSH(512);
}

static void
ob_floppy_max_transfer(int *idx)
{
	// Fixme
        PUSH(18 * 512);
}

NODE_METHODS(ob_floppy) = {
        { "open",               ob_floppy_open             },
        { "close",              ob_floppy_close            },
        { "read-blocks",        ob_floppy_read_blocks      },
        { "block-size",         ob_floppy_block_size       },
        { "max-transfer",       ob_floppy_max_transfer     },
};


int ob_floppy_init(const char *path, const char *dev_name,
                   unsigned long io_base, unsigned long mmio_base)
{
        char nodebuff[128];
	phandle_t aliases;

        snprintf(nodebuff, sizeof(nodebuff), "%s/%s", path, dev_name);
        if (!mmio_base) {
            REGISTER_NAMED_NODE(ob_floppy, nodebuff);
            ob_floppy_initialize(nodebuff);
        } else {
            // Already in tree and mapped
            REGISTER_NODE_METHODS(ob_floppy, nodebuff);
        }
        floppy_init(io_base, mmio_base);

	aliases = find_dev("/aliases");
	set_property(aliases, "floppy", nodebuff, strlen(nodebuff) + 1);

	return 0;
}
