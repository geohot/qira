/*
 *   OpenBIOS polled ide driver
 *
 *   Copyright (C) 2004 Jens Axboe <axboe@suse.de>
 *   Copyright (C) 2005 Stefan Reinauer <stepan@openbios.org>
 *
 *   Credit goes to Hale Landis for his excellent ata demo software
 *   OF node handling and some fixes by Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "kernel/kernel.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "drivers/drivers.h"
#include "ide.h"
#include "hdreg.h"
#include "timer.h"

#ifdef CONFIG_DEBUG_IDE
#define IDE_DPRINTF(fmt, args...) \
do { printk("IDE - %s: " fmt, __func__ , ##args); } while (0)
#else
#define IDE_DPRINTF(fmt, args...) do { } while (0)
#endif

/* DECLARE data structures for the nodes.  */
DECLARE_UNNAMED_NODE( ob_ide, INSTALL_OPEN, sizeof(struct ide_drive*) );
DECLARE_UNNAMED_NODE( ob_ide_ctrl, INSTALL_OPEN, sizeof(int));

/*
 * define to 2 for the standard 2 channels only
 */
#ifndef CONFIG_IDE_NUM_CHANNELS
#define IDE_NUM_CHANNELS 4
#else
#define IDE_NUM_CHANNELS CONFIG_IDE_NUM_CHANNELS
#endif
#define IDE_MAX_CHANNELS 4

#ifndef CONFIG_IDE_FIRST_UNIT
#define FIRST_UNIT 0
#else
#define FIRST_UNIT CONFIG_IDE_FIRST_UNIT
#endif

#ifndef CONFIG_IDE_DEV_TYPE
#define DEV_TYPE "ide"
#else
#define DEV_TYPE CONFIG_IDE_DEV_TYPE
#endif

#ifndef CONFIG_IDE_DEV_NAME
#define DEV_NAME "ide%d"
#else
#define DEV_NAME CONFIG_IDE_DEV_NAME
#endif

static int current_channel = FIRST_UNIT;

static struct ide_channel *channels = NULL;

static inline void ide_add_channel(struct ide_channel *chan)
{
	chan->next = channels;
	channels = chan;
}

static struct ide_channel *ide_seek_channel(const char *name)
{
	struct ide_channel *current;

	current = channels;
	while (current) {
		if (!strcmp(current->name, name))
			return current;
		current = current->next;
	}
	return NULL;
}

/*
 * don't be pedantic
 */
#undef ATA_PEDANTIC

static void dump_drive(struct ide_drive *drive)
{
#ifdef CONFIG_DEBUG_IDE
	printk("IDE DRIVE @%lx:\n", (unsigned long)drive);
	printk("unit: %d\n",drive->unit);
	printk("present: %d\n",drive->present);
	printk("type: %d\n",drive->type);
	printk("media: %d\n",drive->media);
	printk("model: %s\n",drive->model);
	printk("nr: %d\n",drive->nr);
	printk("cyl: %d\n",drive->cyl);
	printk("head: %d\n",drive->head);
	printk("sect: %d\n",drive->sect);
	printk("bs: %d\n",drive->bs);
#endif
}

/*
 * old style io port operations
 */
static unsigned char
ob_ide_inb(struct ide_channel *chan, unsigned int port)
{
	return inb(chan->io_regs[port]);
}

static void
ob_ide_outb(struct ide_channel *chan, unsigned char data, unsigned int port)
{
	outb(data, chan->io_regs[port]);
}

static void
ob_ide_insw(struct ide_channel *chan,
	    unsigned int port, unsigned char *addr, unsigned int count)
{
	insw(chan->io_regs[port], addr, count);
}

static void
ob_ide_outsw(struct ide_channel *chan,
	     unsigned int port, unsigned char *addr, unsigned int count)
{
	outsw(chan->io_regs[port], addr, count);
}

static inline unsigned char
ob_ide_pio_readb(struct ide_drive *drive, unsigned int offset)
{
	struct ide_channel *chan = drive->channel;

	return chan->obide_inb(chan, offset);
}

static inline void
ob_ide_pio_writeb(struct ide_drive *drive, unsigned int offset,
		  unsigned char data)
{
	struct ide_channel *chan = drive->channel;

	chan->obide_outb(chan, data, offset);
}

static inline void
ob_ide_pio_insw(struct ide_drive *drive, unsigned int offset,
		unsigned char *addr, unsigned int len)
{
	struct ide_channel *chan = drive->channel;

	if (len & 1) {
		IDE_DPRINTF("%d: command not word aligned\n", drive->nr);
		return;
	}

	chan->obide_insw(chan, offset, addr, len / 2);
}

static inline void
ob_ide_pio_outsw(struct ide_drive *drive, unsigned int offset,
		unsigned char *addr, unsigned int len)
{
	struct ide_channel *chan = drive->channel;

	if (len & 1) {
		IDE_DPRINTF("%d: command not word aligned\n", drive->nr);
		return;
	}

	chan->obide_outsw(chan, offset, addr, len / 2);
}

static void
ob_ide_400ns_delay(struct ide_drive *drive)
{
	(void) ob_ide_pio_readb(drive, IDEREG_ASTATUS);
	(void) ob_ide_pio_readb(drive, IDEREG_ASTATUS);
	(void) ob_ide_pio_readb(drive, IDEREG_ASTATUS);
	(void) ob_ide_pio_readb(drive, IDEREG_ASTATUS);

	udelay(1);
}

static void
ob_ide_error(struct ide_drive *drive, unsigned char stat, const char *msg)
{
#ifdef CONFIG_DEBUG_IDE
	struct ide_channel *chan = drive->channel;
	unsigned char err;
#endif

	if (!stat)
		stat = ob_ide_pio_readb(drive, IDEREG_STATUS);

	IDE_DPRINTF("ob_ide_error drive<%d>: %s:\n", drive->nr, msg);
	IDE_DPRINTF("    cmd=%x, stat=%x", chan->ata_cmd.command, stat);

	if ((stat & (BUSY_STAT | ERR_STAT)) == ERR_STAT) {
#ifdef CONFIG_DEBUG_IDE
                err =
#endif
                    ob_ide_pio_readb(drive, IDEREG_ERROR);
		IDE_DPRINTF(", err=%x", err);
	}
	IDE_DPRINTF("\n");

#ifdef CONFIG_DEBUG_IDE
	/*
	 * see if sense is valid and dump that
	 */
	if (chan->ata_cmd.command == WIN_PACKET) {
		struct atapi_command *cmd = &chan->atapi_cmd;
		unsigned char old_cdb = cmd->cdb[0];

		if (cmd->cdb[0] == ATAPI_REQ_SENSE) {
			old_cdb = cmd->old_cdb;

			IDE_DPRINTF("    atapi opcode=%02x", old_cdb);
		} else {
			int i;

			IDE_DPRINTF("    cdb: ");
			for (i = 0; i < sizeof(cmd->cdb); i++)
				IDE_DPRINTF("%02x ", cmd->cdb[i]);
		}
		if (cmd->sense_valid)
			IDE_DPRINTF(", sense: %02x/%02x/%02x",
                                    cmd->sense.sense_key, cmd->sense.asc,
                                    cmd->sense.ascq);
		else
			IDE_DPRINTF(", no sense");
		IDE_DPRINTF("\n");
	}
#endif
}

/*
 * wait for 'stat' to be set. returns 1 if failed, 0 if succesful
 */
static int
ob_ide_wait_stat(struct ide_drive *drive, unsigned char ok_stat,
                 unsigned char bad_stat, unsigned char *ret_stat)
{
	unsigned char stat;
	int i;

	ob_ide_400ns_delay(drive);

	for (i = 0; i < 5000; i++) {
		stat = ob_ide_pio_readb(drive, IDEREG_STATUS);
		if (!(stat & BUSY_STAT))
			break;

		udelay(1000);
	}

	if (ret_stat)
		*ret_stat = stat;

	if (stat & bad_stat)
		return 1;

	if ((stat & ok_stat) || !ok_stat)
		return 0;

	return 1;
}

static int
ob_ide_select_drive(struct ide_drive *drive)
{
	struct ide_channel *chan = drive->channel;
	unsigned char control = IDEHEAD_DEV0;

	if (ob_ide_wait_stat(drive, 0, BUSY_STAT, NULL)) {
		IDE_DPRINTF("select_drive: timed out\n");
		return 1;
	}

	/*
	 * don't select drive if already active. Note: we always
	 * wait for BUSY clear
	 */
	if (drive->unit == chan->selected)
		return 0;

	if (drive->unit)
		control = IDEHEAD_DEV1;

	ob_ide_pio_writeb(drive, IDEREG_CURRENT, control);
	ob_ide_400ns_delay(drive);

	if (ob_ide_wait_stat(drive, 0, BUSY_STAT, NULL)) {
		IDE_DPRINTF("select_drive: timed out\n");
		return 1;
	}

	chan->selected = drive->unit;
	return 0;
}

static void
ob_ide_write_tasklet(struct ide_drive *drive, struct ata_command *cmd)
{
	ob_ide_pio_writeb(drive, IDEREG_FEATURE, cmd->task[1]);
	ob_ide_pio_writeb(drive, IDEREG_NSECTOR, cmd->task[3]);
	ob_ide_pio_writeb(drive, IDEREG_SECTOR, cmd->task[7]);
	ob_ide_pio_writeb(drive, IDEREG_LCYL, cmd->task[8]);
	ob_ide_pio_writeb(drive, IDEREG_HCYL, cmd->task[9]);

	ob_ide_pio_writeb(drive, IDEREG_FEATURE, cmd->task[0]);
	ob_ide_pio_writeb(drive, IDEREG_NSECTOR, cmd->task[2]);
	ob_ide_pio_writeb(drive, IDEREG_SECTOR, cmd->task[4]);
	ob_ide_pio_writeb(drive, IDEREG_LCYL, cmd->task[5]);
	ob_ide_pio_writeb(drive, IDEREG_HCYL, cmd->task[6]);

	if (drive->unit)
		cmd->device_head |= IDEHEAD_DEV1;

	ob_ide_pio_writeb(drive, IDEREG_CURRENT, cmd->device_head);

	ob_ide_pio_writeb(drive, IDEREG_COMMAND, cmd->command);
	ob_ide_400ns_delay(drive);
}

static void
ob_ide_write_registers(struct ide_drive *drive, struct ata_command *cmd)
{
	/*
	 * we are _always_ polled
	 */
	ob_ide_pio_writeb(drive, IDEREG_CONTROL, cmd->control | IDECON_NIEN);

	ob_ide_pio_writeb(drive, IDEREG_FEATURE, cmd->feature);
	ob_ide_pio_writeb(drive, IDEREG_NSECTOR, cmd->nsector);
	ob_ide_pio_writeb(drive, IDEREG_SECTOR, cmd->sector);
	ob_ide_pio_writeb(drive, IDEREG_LCYL, cmd->lcyl);
	ob_ide_pio_writeb(drive, IDEREG_HCYL, cmd->hcyl);

	if (drive->unit)
		cmd->device_head |= IDEHEAD_DEV1;

	ob_ide_pio_writeb(drive, IDEREG_CURRENT, cmd->device_head);

	ob_ide_pio_writeb(drive, IDEREG_COMMAND, cmd->command);
	ob_ide_400ns_delay(drive);
}

/*
 * execute command with "pio non data" protocol
 */
#if 0
static int
ob_ide_pio_non_data(struct ide_drive *drive, struct ata_command *cmd)
{
	if (ob_ide_select_drive(drive))
		return 1;

	ob_ide_write_registers(drive, cmd);

	if (ob_ide_wait_stat(drive, 0, BUSY_STAT, NULL))
		return 1;

	return 0;
}
#endif

/*
 * execute given command with a pio data-in phase.
 */
static int
ob_ide_pio_data_in(struct ide_drive *drive, struct ata_command *cmd)
{
	unsigned char stat;
	unsigned int bytes, timeout;

	if (ob_ide_select_drive(drive))
		return 1;

	/*
	 * ATA must set ready and seek stat, ATAPI need only clear busy
	 */
	timeout = 0;
	do {
		stat = ob_ide_pio_readb(drive, IDEREG_STATUS);

		if (drive->type == ide_type_ata) {
			/*
			 * this is BIOS code, don't be too pedantic
			 */
#ifdef ATA_PEDANTIC
			if ((stat & (BUSY_STAT | READY_STAT | SEEK_STAT)) ==
			    (READY_STAT | SEEK_STAT))
				break;
#else
			if ((stat & (BUSY_STAT | READY_STAT)) == READY_STAT)
				break;
#endif
		} else {
			if (!(stat & BUSY_STAT))
				break;
		}
		ob_ide_400ns_delay(drive);
	} while (timeout++ < 1000);

	if (timeout >= 1000) {
		ob_ide_error(drive, stat, "drive timed out");
		cmd->stat = stat;
		return 1;
	}

	ob_ide_write_registers(drive, cmd);

	/*
	 * now read the data
	 */
	bytes = cmd->buflen;
	do {
		unsigned count = cmd->buflen;

		if (count > drive->bs)
			count = drive->bs;

		/* delay 100ms for ATAPI? */

		/*
		 * wait for BUSY clear
		 */
		if (ob_ide_wait_stat(drive, 0, BUSY_STAT | ERR_STAT, &stat)) {
			ob_ide_error(drive, stat, "timed out waiting for BUSY clear");
			cmd->stat = stat;
			break;
		}

		/*
		 * transfer the data
		 */
		if ((stat & (BUSY_STAT | DRQ_STAT)) == DRQ_STAT) {
			ob_ide_pio_insw(drive, IDEREG_DATA, cmd->buffer, count);
			cmd->bytes -= count;
			cmd->buffer += count;
			bytes -= count;

			ob_ide_400ns_delay(drive);
		}

		if (stat & (BUSY_STAT | WRERR_STAT | ERR_STAT)) {
			cmd->stat = stat;
			break;
		}

		if (!(stat & DRQ_STAT)) {
			cmd->stat = stat;
			break;
		}
	} while (bytes);

	if (bytes)
		IDE_DPRINTF("bytes=%d, stat=%x\n", bytes, stat);

	return bytes ? 1 : 0;
}

/*
 * execute ata command with pio packet protocol
 */
static int
ob_ide_pio_packet(struct ide_drive *drive, struct atapi_command *cmd)
{
	unsigned char stat, reason, lcyl, hcyl;
	struct ata_command *acmd = &drive->channel->ata_cmd;
	unsigned char *buffer;
	unsigned int bytes;

	if (ob_ide_select_drive(drive))
		return 1;

	if (cmd->buflen && cmd->data_direction == atapi_ddir_none)
		IDE_DPRINTF("non-zero buflen but no data direction\n");

	memset(acmd, 0, sizeof(*acmd));
	acmd->lcyl = cmd->buflen & 0xff;
	acmd->hcyl = (cmd->buflen >> 8) & 0xff;
	acmd->command = WIN_PACKET;
	ob_ide_write_registers(drive, acmd);

	/*
	 * BUSY must be set, _or_ DRQ | ERR
	 */
	stat = ob_ide_pio_readb(drive, IDEREG_ASTATUS);
	if ((stat & BUSY_STAT) == 0) {
		if (!(stat & (DRQ_STAT | ERR_STAT))) {
			ob_ide_error(drive, stat, "bad stat in atapi cmd");
			cmd->stat = stat;
			return 1;
		}
	}

	if (ob_ide_wait_stat(drive, 0, BUSY_STAT | ERR_STAT, &stat)) {
		ob_ide_error(drive, stat, "timeout, ATAPI BUSY clear");
		cmd->stat = stat;
		return 1;
	}

	if ((stat & (BUSY_STAT | DRQ_STAT | ERR_STAT)) != DRQ_STAT) {
		/*
		 * if command isn't request sense, then we have a problem. if
		 * we are doing a sense, ERR_STAT == CHECK_CONDITION
		 */
		if (cmd->cdb[0] != ATAPI_REQ_SENSE) {
			IDE_DPRINTF("odd, drive didn't want to transfer %x\n",
                                     stat);
			return 1;
		}
	}

	/*
	 * transfer cdb
	 */
	ob_ide_pio_outsw(drive, IDEREG_DATA, cmd->cdb,sizeof(cmd->cdb));
	ob_ide_400ns_delay(drive);

	/*
	 * ok, cdb was sent to drive, now do data transfer (if any)
	 */
	bytes = cmd->buflen;
	buffer = cmd->buffer;
	do {
		unsigned int bc;

		if (ob_ide_wait_stat(drive, 0, BUSY_STAT | ERR_STAT, &stat)) {
			ob_ide_error(drive, stat, "busy not clear after cdb");
			cmd->stat = stat;
			break;
		}

		/*
		 * transfer complete!
		 */
		if ((stat & (BUSY_STAT | DRQ_STAT)) == 0)
			break;

		if ((stat & (BUSY_STAT | DRQ_STAT)) != DRQ_STAT)
			break;

		reason = ob_ide_pio_readb(drive, IDEREG_NSECTOR);
		lcyl = ob_ide_pio_readb(drive, IDEREG_LCYL);
		hcyl = ob_ide_pio_readb(drive, IDEREG_HCYL);

		/*
		 * check if the drive wants to transfer data in the same
		 * direction as we do...
		 */
		if ((reason & IREASON_CD) && cmd->data_direction != atapi_ddir_read) {
			ob_ide_error(drive, stat, "atapi, bad transfer ddir");
			break;
		}

		bc = (hcyl << 8) | lcyl;
		if (!bc)
			break;

		if (bc > bytes)
			bc = bytes;

		if (cmd->data_direction == atapi_ddir_read)
			ob_ide_pio_insw(drive, IDEREG_DATA, buffer, bc);
		else
			ob_ide_pio_outsw(drive, IDEREG_DATA, buffer, bc);

		bytes -= bc;
		buffer += bc;

		ob_ide_400ns_delay(drive);
	} while (bytes);

	if (cmd->data_direction != atapi_ddir_none)
		(void) ob_ide_wait_stat(drive, 0, BUSY_STAT, &stat);

	if (bytes)
		IDE_DPRINTF("cdb failed, bytes=%d, stat=%x\n", bytes, stat);

	return (stat & ERR_STAT) || bytes;
}

/*
 * execute a packet command, with retries if appropriate
 */
static int
ob_ide_atapi_packet(struct ide_drive *drive, struct atapi_command *cmd)
{
	int retries = 5, ret;

	if (drive->type != ide_type_atapi)
		return 1;
	if (cmd->buflen > 0xffff)
		return 1;

	/*
	 * retry loop
	 */
	do {
		ret = ob_ide_pio_packet(drive, cmd);
		if (!ret)
			break;

		/*
		 * request sense failed, bummer
		 */
		if (cmd->cdb[0] == ATAPI_REQ_SENSE)
			break;

		if (ob_ide_atapi_request_sense(drive))
			break;

		/*
		 * we know sense is valid. retry if the drive isn't ready,
		 * otherwise don't bother.
		 */
		if (cmd->sense.sense_key != ATAPI_SENSE_NOT_READY)
			break;
		/*
		 * ... except 'medium not present'
		 */
		if (cmd->sense.asc == 0x3a)
			break;

		udelay(1000000);
	} while (retries--);

	if (ret)
		ob_ide_error(drive, 0, "atapi command");

	return ret;
}

static int
ob_ide_atapi_request_sense(struct ide_drive *drive)
{
	struct atapi_command *cmd = &drive->channel->atapi_cmd;
	unsigned char old_cdb;

	/*
	 * save old cdb for debug error
	 */
	old_cdb = cmd->cdb[0];

	memset(cmd, 0, sizeof(*cmd));
	cmd->cdb[0] = ATAPI_REQ_SENSE;
	cmd->cdb[4] = 18;
	cmd->buffer = (unsigned char *) &cmd->sense;
	cmd->buflen = 18;
	cmd->data_direction = atapi_ddir_read;
	cmd->old_cdb = old_cdb;

	if (ob_ide_atapi_packet(drive, cmd))
		return 1;

	cmd->sense_valid = 1;
	return 0;
}

/*
 * make sure drive is ready and media loaded
 */
static int
ob_ide_atapi_drive_ready(struct ide_drive *drive)
{
	struct atapi_command *cmd = &drive->channel->atapi_cmd;
	struct atapi_capacity cap;

	IDE_DPRINTF("ob_ide_atapi_drive_ready\n");

	/*
	 * Test Unit Ready is like a ping
	 */
	memset(cmd, 0, sizeof(*cmd));
	cmd->cdb[0] = ATAPI_TUR;

	if (ob_ide_atapi_packet(drive, cmd)) {
		IDE_DPRINTF("%d: TUR failed\n", drive->nr);
		return 1;
	}

	/*
	 * don't force load of tray (bit 2 in byte 4 of cdb), it's
	 * annoying and we don't want to deal with errors from drives
	 * that cannot do it
	 */
	memset(cmd, 0, sizeof(*cmd));
	cmd->cdb[0] = ATAPI_START_STOP_UNIT;
	cmd->cdb[4] = 0x01;

	if (ob_ide_atapi_packet(drive, cmd)) {
		IDE_DPRINTF("%d: START_STOP unit failed\n", drive->nr);
		return 1;
	}

	/*
	 * finally, get capacity and block size
	 */
	memset(cmd, 0, sizeof(*cmd));
	memset(&cap, 0, sizeof(cap));

	cmd->cdb[0] = ATAPI_READ_CAPACITY;
	cmd->buffer = (unsigned char *) &cap;
	cmd->buflen = sizeof(cap);
	cmd->data_direction = atapi_ddir_read;

	if (ob_ide_atapi_packet(drive, cmd)) {
		drive->sectors = 0x1fffff;
		drive->bs = 2048;
		return 1;
	}

	drive->sectors = __be32_to_cpu(cap.lba) + 1;
	drive->bs = __be32_to_cpu(cap.block_size);
	return 0;
}

/*
 * read from an atapi device, using READ_10
 */
static int
ob_ide_read_atapi(struct ide_drive *drive, unsigned long long block,
                  unsigned char *buf, unsigned int sectors)
{
	struct atapi_command *cmd = &drive->channel->atapi_cmd;

	if (ob_ide_atapi_drive_ready(drive))
		return 1;

	memset(cmd, 0, sizeof(*cmd));

	/*
	 * READ_10 should work on generally any atapi device
	 */
	cmd->cdb[0] = ATAPI_READ_10;
	cmd->cdb[2] = (block >> 24) & 0xff;
	cmd->cdb[3] = (block >> 16) & 0xff;
	cmd->cdb[4] = (block >>  8) & 0xff;
	cmd->cdb[5] = block & 0xff;
	cmd->cdb[7] = (sectors >> 8) & 0xff;
	cmd->cdb[8] = sectors & 0xff;

	cmd->buffer = buf;
	cmd->buflen = sectors * 2048;
	cmd->data_direction = atapi_ddir_read;

	return ob_ide_atapi_packet(drive, cmd);
}

static int
ob_ide_read_ata_chs(struct ide_drive *drive, unsigned long long block,
                    unsigned char *buf, unsigned int sectors)
{
	struct ata_command *cmd = &drive->channel->ata_cmd;
	unsigned int track = (block / drive->sect);
	unsigned int sect = (block % drive->sect) + 1;
	unsigned int head = (track % drive->head);
	unsigned int cyl = (track / drive->head);

	/*
	 * fill in chs command to read from disk at given location
	 */
	cmd->buffer = buf;
	cmd->buflen = sectors * 512;

	cmd->nsector = sectors & 0xff;
	cmd->sector = sect;
	cmd->lcyl = cyl;
	cmd->hcyl = cyl >> 8;
	cmd->device_head = head;

	cmd->command = WIN_READ;

	return ob_ide_pio_data_in(drive, cmd);
}

static int
ob_ide_read_ata_lba28(struct ide_drive *drive, unsigned long long block,
                      unsigned char *buf, unsigned int sectors)
{
	struct ata_command *cmd = &drive->channel->ata_cmd;

	memset(cmd, 0, sizeof(*cmd));

	/*
	 * fill in 28-bit lba command to read from disk at given location
	 */
	cmd->buffer = buf;
	cmd->buflen = sectors * 512;

	cmd->nsector = sectors;
	cmd->sector = block;
	cmd->lcyl = block >>= 8;
	cmd->hcyl = block >>= 8;
	cmd->device_head = ((block >> 8) & 0x0f);
	cmd->device_head |= (1 << 6);

	cmd->command = WIN_READ;

	return ob_ide_pio_data_in(drive, cmd);
}

static int
ob_ide_read_ata_lba48(struct ide_drive *drive, unsigned long long block,
                      unsigned char *buf, unsigned int sectors)
{
	struct ata_command *cmd = &drive->channel->ata_cmd;

	memset(cmd, 0, sizeof(*cmd));

	cmd->buffer = buf;
	cmd->buflen = sectors * 512;

	/*
	 * we are using tasklet addressing here
	 */
	cmd->task[2] = sectors;
	cmd->task[3] = sectors >> 8;
	cmd->task[4] = block;
	cmd->task[5] = block >>  8;
	cmd->task[6] = block >> 16;
	cmd->task[7] = block >> 24;
	cmd->task[8] = (u64) block >> 32;
	cmd->task[9] = (u64) block >> 40;

	cmd->command = WIN_READ_EXT;

	ob_ide_write_tasklet(drive, cmd);

	return ob_ide_pio_data_in(drive, cmd);
}
/*
 * read 'sectors' sectors from ata device
 */
static int
ob_ide_read_ata(struct ide_drive *drive, unsigned long long block,
                unsigned char *buf, unsigned int sectors)
{
	unsigned long long end_block = block + sectors;
	const int need_lba48 = (end_block > (1ULL << 28)) || (sectors > 255);

	if (end_block > drive->sectors)
		return 1;
	if (need_lba48 && drive->addressing != ide_lba48)
		return 1;

	/*
	 * use lba48 if we have to, otherwise use the faster lba28
	 */
	if (need_lba48)
		return ob_ide_read_ata_lba48(drive, block, buf, sectors);
	else if (drive->addressing != ide_chs)
		return ob_ide_read_ata_lba28(drive, block, buf, sectors);

	return ob_ide_read_ata_chs(drive, block, buf, sectors);
}

static int
ob_ide_read_sectors(struct ide_drive *drive, unsigned long long block,
                    unsigned char *buf, unsigned int sectors)
{
	if (!sectors)
		return 1;
	if (block + sectors > drive->sectors)
		return 1;

	IDE_DPRINTF("ob_ide_read_sectors: block=%lu sectors=%u\n",
	            (unsigned long) block, sectors);

	if (drive->type == ide_type_ata)
		return ob_ide_read_ata(drive, block, buf, sectors);
	else
		return ob_ide_read_atapi(drive, block, buf, sectors);
}

/*
 * byte swap the string if necessay, and strip leading/trailing blanks
 */
static void
ob_ide_fixup_string(unsigned char *s, unsigned int len)
{
	unsigned char *p = s, *end = &s[len & ~1];

	/*
	 * if big endian arch, byte swap the string
	 */
#ifdef CONFIG_BIG_ENDIAN
	for (p = end ; p != s;) {
		unsigned short *pp = (unsigned short *) (p -= 2);
		*pp = __le16_to_cpu(*pp);
	}
#endif

	while (s != end && *s == ' ')
		++s;
	while (s != end && *s)
		if (*s++ != ' ' || (s != end && *s && *s != ' '))
			*p++ = *(s-1);
	while (p != end)
		*p++ = '\0';
}

/*
 * it's big endian, we need to swap (if on little endian) the items we use
 */
static int
ob_ide_fixup_id(struct hd_driveid *id)
{
	ob_ide_fixup_string(id->model, 40);
	id->config = __le16_to_cpu(id->config);
	id->lba_capacity = __le32_to_cpu(id->lba_capacity);
	id->cyls = __le16_to_cpu(id->cyls);
	id->heads = __le16_to_cpu(id->heads);
	id->sectors = __le16_to_cpu(id->sectors);
	id->command_set_2 = __le16_to_cpu(id->command_set_2);
	id->cfs_enable_2 = __le16_to_cpu(id->cfs_enable_2);

	return 0;
}

static int
ob_ide_identify_drive(struct ide_drive *drive)
{
	struct ata_command *cmd = &drive->channel->ata_cmd;
	struct hd_driveid id;

	memset(cmd, 0, sizeof(*cmd));
	cmd->buffer = (unsigned char *) &id;
	cmd->buflen = 512;

	if (drive->type == ide_type_ata)
		cmd->command = WIN_IDENTIFY;
	else if (drive->type == ide_type_atapi)
		cmd->command = WIN_IDENTIFY_PACKET;
	else {
		IDE_DPRINTF("%s: called with bad device type %d\n",
                            __FUNCTION__, drive->type);
		return 1;
	}

	if (ob_ide_pio_data_in(drive, cmd))
		return 1;

	ob_ide_fixup_id(&id);

	if (drive->type == ide_type_atapi) {
		drive->media = (id.config >> 8) & 0x1f;
		drive->sectors = 0x7fffffff;
		drive->bs = 2048;
		drive->max_sectors = 31;
	} else {
		drive->media = ide_media_disk;
		drive->sectors = id.lba_capacity;
		drive->bs = 512;
		drive->max_sectors = 255;

#ifdef CONFIG_IDE_LBA48
		if ((id.command_set_2 & 0x0400) && (id.cfs_enable_2 & 0x0400)) {
			drive->addressing = ide_lba48;
			drive->max_sectors = 65535;
		} else
#endif
		if (id.capability & 2)
			drive->addressing = ide_lba28;
		else {
			drive->addressing = ide_chs;
		}

		/* only set these in chs mode? */
		drive->cyl = id.cyls;
		drive->head = id.heads;
		drive->sect = id.sectors;
	}

	strncpy(drive->model, (char*)id.model, sizeof(id.model));
	drive->model[40] = '\0';
	return 0;
}

/*
 * identify type of devices on channel. must have already been probed.
 */
static void
ob_ide_identify_drives(struct ide_channel *chan)
{
	struct ide_drive *drive;
	int i;

	for (i = 0; i < 2; i++) {
		drive = &chan->drives[i];

		if (!drive->present)
			continue;

		ob_ide_identify_drive(drive);
	}
}

/*
 * software reset (ATA-4, section 8.3)
 */
static void
ob_ide_software_reset(struct ide_drive *drive)
{
	struct ide_channel *chan = drive->channel;

	ob_ide_pio_writeb(drive, IDEREG_CONTROL, IDECON_NIEN | IDECON_SRST);
	ob_ide_400ns_delay(drive);
	ob_ide_pio_writeb(drive, IDEREG_CONTROL, IDECON_NIEN);
	ob_ide_400ns_delay(drive);

	/*
	 * if master is present, wait for BUSY clear
	 */
	if (chan->drives[0].present)
		ob_ide_wait_stat(drive, 0, BUSY_STAT, NULL);

	/*
	 * if slave is present, wait until it allows register access
	 */
	if (chan->drives[1].present) {
		unsigned char sectorn, sectorc;
		int timeout = 1000;

		do {
			/*
			 * select it
			 */
			ob_ide_pio_writeb(drive, IDEREG_CURRENT, IDEHEAD_DEV1);
			ob_ide_400ns_delay(drive);

			sectorn = ob_ide_pio_readb(drive, IDEREG_SECTOR);
			sectorc = ob_ide_pio_readb(drive, IDEREG_NSECTOR);

			if (sectorc == 0x01 && sectorn == 0x01)
				break;

		} while (--timeout);
	}

	/*
	 * reset done, reselect original device
	 */
	drive->channel->selected = -1;
	ob_ide_select_drive(drive);
}

/*
 * this serves as both a device check, and also to verify that the drives
 * we initially "found" are really there
 */
static void
ob_ide_device_type_check(struct ide_drive *drive)
{
	unsigned char sc, sn, cl, ch, st;

	if (ob_ide_select_drive(drive))
		return;

	sc = ob_ide_pio_readb(drive, IDEREG_NSECTOR);
	sn = ob_ide_pio_readb(drive, IDEREG_SECTOR);

	if (sc == 0x01 && sn == 0x01) {
		/*
		 * read device signature
		 */
		cl = ob_ide_pio_readb(drive, IDEREG_LCYL);
		ch = ob_ide_pio_readb(drive, IDEREG_HCYL);
		st = ob_ide_pio_readb(drive, IDEREG_STATUS);
		if (cl == 0x14 && ch == 0xeb)
			drive->type = ide_type_atapi;
		else if (cl == 0x00 && ch == 0x00 && st != 0x00)
			drive->type = ide_type_ata;
		else
			drive->present = 0;
	} else
		drive->present = 0;
}

/*
 * pure magic
 */
static void
ob_ide_device_check(struct ide_drive *drive)
{
	unsigned char sc, sn;

	/*
	 * non-existing io port should return 0xff, don't probe this
	 * channel at all then
	 */
	if (ob_ide_pio_readb(drive, IDEREG_STATUS) == 0xff) {
		drive->channel->present = 0;
		return;
	}

	if (ob_ide_select_drive(drive))
		return;

	ob_ide_pio_writeb(drive, IDEREG_NSECTOR, 0x55);
	ob_ide_pio_writeb(drive, IDEREG_SECTOR, 0xaa);
	ob_ide_pio_writeb(drive, IDEREG_NSECTOR, 0xaa);
	ob_ide_pio_writeb(drive, IDEREG_SECTOR, 0x55);
	ob_ide_pio_writeb(drive, IDEREG_NSECTOR, 0x55);
	ob_ide_pio_writeb(drive, IDEREG_SECTOR, 0xaa);

	sc = ob_ide_pio_readb(drive, IDEREG_NSECTOR);
	sn = ob_ide_pio_readb(drive, IDEREG_SECTOR);

	/*
	 * we _think_ the device is there, we will make sure later
	 */
	if (sc == 0x55 && sn == 0xaa) {
		drive->present = 1;
		drive->type = ide_type_unknown;
	}
}

/*
 * probe the legacy ide ports and find attached devices.
 */
static void
ob_ide_probe(struct ide_channel *chan)
{
	struct ide_drive *drive;
	int i;

	for (i = 0; i < 2; i++) {
		drive = &chan->drives[i];

		ob_ide_device_check(drive);

		/*
		 * no point in continuing
		 */
		if (!chan->present)
			break;

		if (!drive->present)
			continue;

		/*
		 * select and reset device
		 */
		if (ob_ide_select_drive(drive))
			continue;

		ob_ide_software_reset(drive);

		ob_ide_device_type_check(drive);
	}
}

/*
 * The following functions are interfacing with OpenBIOS. They
 * are device node methods. Thus they have to do proper stack handling.
 *
 */

/*
 * 255 sectors for ata lba28, 65535 for lba48, and 31 sectors for atapi
 */
static void
ob_ide_max_transfer(int *idx)
{
	struct ide_drive *drive = *(struct ide_drive **)idx;

	IDE_DPRINTF("max_transfer %x\n", drive->max_sectors * drive->bs);

	PUSH(drive->max_sectors * drive->bs);
}

static void
ob_ide_read_blocks(int *idx)
{
	cell n = POP(), cnt=n;
	ucell blk = POP();
	unsigned char *dest = (unsigned char *)cell2pointer(POP());
	struct ide_drive *drive = *(struct ide_drive **)idx;

        IDE_DPRINTF("ob_ide_read_blocks %lx block=%ld n=%ld\n",
                    (unsigned long)dest, (unsigned long)blk, (long)n);

	while (n) {
		int len = n;
		if (len > drive->max_sectors)
			len = drive->max_sectors;

		if (ob_ide_read_sectors(drive, blk, dest, len)) {
			IDE_DPRINTF("ob_ide_read_blocks: error\n");
			RET(0);
		}

		dest += len * drive->bs;
		n -= len;
		blk += len;
	}

	PUSH(cnt);
}

static void
ob_ide_block_size(int *idx)
{
	struct ide_drive *drive = *(struct ide_drive **)idx;

	IDE_DPRINTF("ob_ide_block_size: block size %x\n", drive->bs);

	PUSH(drive->bs);
}

static void
ob_ide_initialize(int *idx)
{
	int props[3];
	phandle_t ph=get_cur_dev();

	push_str("block");
	fword("device-type");

	// Set dummy reg properties

	set_int_property(ph, "#address-cells", 1);
	set_int_property(ph, "#size-cells", 0);

	props[0] = __cpu_to_be32(0); props[1] = __cpu_to_be32(0); props[2] = __cpu_to_be32(0);
	set_property(ph, "reg", (char *)&props, 3*sizeof(int));

	fword("is-deblocker");
}

static void
ob_ide_open(int *idx)
{
	int ret=1, len;
	phandle_t ph;
	struct ide_drive *drive;
	struct ide_channel *chan;
	char *idename;
	int unit;

	fword("my-unit");
	unit = POP();

	fword("my-parent");
	fword("ihandle>phandle");
	ph=(phandle_t)POP();
	idename=get_property(ph, "name", &len);

	chan = ide_seek_channel(idename);
	drive = &chan->drives[unit];
	*(struct ide_drive **)idx = drive;

	IDE_DPRINTF("opening channel %d unit %d\n", idx[1], idx[0]);
	dump_drive(drive);

	if (drive->type != ide_type_ata)
		ret= !ob_ide_atapi_drive_ready(drive);

	selfword("open-deblocker");

	/* interpose disk-label */
	ph = find_dev("/packages/disk-label");
	fword("my-args");
	PUSH_ph( ph );
	fword("interpose");

	RET ( -ret );
}

static void
ob_ide_close(struct ide_drive *drive)
{
	selfword("close-deblocker");
}

NODE_METHODS(ob_ide) = {
	{ NULL,			ob_ide_initialize	},
	{ "open",		ob_ide_open		},
	{ "close",		ob_ide_close		},
	{ "read-blocks",	ob_ide_read_blocks	},
	{ "block-size",		ob_ide_block_size	},
	{ "max-transfer",	ob_ide_max_transfer	},
};

static void
ob_ide_ctrl_initialize(int *idx)
{
	phandle_t ph=get_cur_dev();

	/* set device type */
	push_str(DEV_TYPE);
	fword("device-type");

	set_int_property(ph, "#address-cells", 1);
	set_int_property(ph, "#size-cells", 0);
}

static void
ob_ide_ctrl_decodeunit(int *idx)
{
	fword("parse-hex");
}

NODE_METHODS(ob_ide_ctrl) = {
	{ NULL,			ob_ide_ctrl_initialize	},
	{ "decode-unit",	ob_ide_ctrl_decodeunit  },
};

static void set_cd_alias(const char *path)
{
	phandle_t aliases;

	aliases = find_dev("/aliases");

	if (get_property(aliases, "cd", NULL))
		return;

	set_property(aliases, "cd", path, strlen(path) + 1);
	set_property(aliases, "cdrom", path, strlen(path) + 1);
}

static void set_hd_alias(const char *path)
{
	phandle_t aliases;

	aliases = find_dev("/aliases");

	if (get_property(aliases, "hd", NULL))
		return;

	set_property(aliases, "hd", path, strlen(path) + 1);
	set_property(aliases, "disk", path, strlen(path) + 1);
}

static void set_ide_alias(const char *path)
{
	phandle_t aliases;
	static int ide_counter = 0;
	char idestr[8];

	aliases = find_dev("/aliases");

	snprintf(idestr, sizeof(idestr), "ide%d", ide_counter++);
	set_property(aliases, idestr, path, strlen(path) + 1);
}

int ob_ide_init(const char *path, uint32_t io_port0, uint32_t ctl_port0,
		uint32_t io_port1, uint32_t ctl_port1)
{
	int i, j;
	char nodebuff[128];
	phandle_t dnode;
	struct ide_channel *chan;
	int io_ports[IDE_MAX_CHANNELS];
	int ctl_ports[IDE_MAX_CHANNELS];
	u32 props[6];

	io_ports[0] = io_port0;
	ctl_ports[0] = ctl_port0;
	io_ports[1] = io_port1;
	ctl_ports[1] = ctl_port1;

	for (i = 0; i < IDE_NUM_CHANNELS; i++, current_channel++) {

		chan = malloc(sizeof(struct ide_channel));

		snprintf(chan->name, sizeof(chan->name),
			 DEV_NAME, current_channel);

		chan->mmio = 0;

		for (j = 0; j < 8; j++)
			chan->io_regs[j] = io_ports[i] + j;

		chan->io_regs[8] = ctl_ports[i];
		chan->io_regs[9] = ctl_ports[i] + 1;

		chan->obide_inb = ob_ide_inb;
		chan->obide_insw = ob_ide_insw;
		chan->obide_outb = ob_ide_outb;
		chan->obide_outsw = ob_ide_outsw;

		chan->selected = -1;

		/*
		 * assume it's there, if not io port dead check will clear
		 */
		chan->present = 1;

		for (j = 0; j < 2; j++) {
			chan->drives[j].present = 0;
			chan->drives[j].unit = j;
			chan->drives[j].channel = chan;
			/* init with a decent value */
			chan->drives[j].bs = 512;

			chan->drives[j].nr = i * 2 + j;
		}

		ide_add_channel(chan);

		ob_ide_probe(chan);

		if (!chan->present)
			continue;

		ob_ide_identify_drives(chan);

                snprintf(nodebuff, sizeof(nodebuff), "%s/" DEV_NAME, path,
                         current_channel);
		REGISTER_NAMED_NODE(ob_ide_ctrl, nodebuff);

		dnode = find_dev(nodebuff);

#if !defined(CONFIG_PPC) && !defined(CONFIG_SPARC64)
		props[0]=14; props[1]=0;
		set_property(dnode, "interrupts",
			     (char *)&props, 2*sizeof(props[0]));
#endif

		props[0] = __cpu_to_be32(chan->io_regs[0]);
		props[1] = __cpu_to_be32(1); props[2] = __cpu_to_be32(8);
		props[3] = __cpu_to_be32(chan->io_regs[8]);
		props[4] = __cpu_to_be32(1); props[5] = __cpu_to_be32(2);
		set_property(dnode, "reg", (char *)&props, 6*sizeof(props[0]));

		IDE_DPRINTF(DEV_NAME": [io ports 0x%x-0x%x,0x%x]\n",
		            current_channel, chan->io_regs[0],
		            chan->io_regs[0] + 7, chan->io_regs[8]);

		for (j = 0; j < 2; j++) {
			struct ide_drive *drive = &chan->drives[j];
                        const char *media = "UNKNOWN";

			if (!drive->present)
				continue;

			IDE_DPRINTF("    drive%d [ATA%s ", j,
			            drive->type == ide_type_atapi ? "PI" : "");
			switch (drive->media) {
				case ide_media_floppy:
					media = "floppy";
					break;
				case ide_media_cdrom:
					media = "cdrom";
					break;
				case ide_media_optical:
					media = "mo";
					break;
				case ide_media_disk:
					media = "disk";
					break;
			}
			IDE_DPRINTF("%s]: %s\n", media, drive->model);
                        snprintf(nodebuff, sizeof(nodebuff),
                                 "%s/" DEV_NAME "/%s", path, current_channel,
                                 media);
			REGISTER_NAMED_NODE(ob_ide, nodebuff);
			dnode=find_dev(nodebuff);
			set_int_property(dnode, "reg", j);

			/* create aliases */

			set_ide_alias(nodebuff);
			if (drive->media == ide_media_cdrom)
				set_cd_alias(nodebuff);
			if (drive->media == ide_media_disk)
				set_hd_alias(nodebuff);
		}
	}

	return 0;
}

void ob_ide_quiesce(void)
{
	struct ide_channel *channel;
	int i;

	channel = channels;
	while (channel) {
		for (i = 0; i < 2; i++) {
			struct ide_drive *drive = &channel->drives[i];

			if (!drive->present)
				continue;

			ob_ide_select_drive(drive);
			ob_ide_software_reset(drive);
			ob_ide_device_type_check(drive);
		}

		channel = channel->next;
	}
}

#if defined(CONFIG_DRIVER_MACIO)
static unsigned char
macio_ide_inb(struct ide_channel *chan, unsigned int port)
{
	return in_8((unsigned char*)(chan->mmio + (port << 4)));
}

static void
macio_ide_outb(struct ide_channel *chan, unsigned char data, unsigned int port)
{
	out_8((unsigned char*)(chan->mmio + (port << 4)), data);
}

static void
macio_ide_insw(struct ide_channel *chan,
	       unsigned int port, unsigned char *addr, unsigned int count)
{
	_insw((uint16_t*)(chan->mmio + (port << 4)), addr, count);
}

static void
macio_ide_outsw(struct ide_channel *chan,
		unsigned int port, unsigned char *addr, unsigned int count)
{
	_outsw((uint16_t*)(chan->mmio + (port << 4)), addr, count);
}

#define MACIO_IDE_OFFSET	0x00020000
#define MACIO_IDE_SIZE		0x00001000

int macio_ide_init(const char *path, uint32_t addr, int nb_channels)
{
	int i, j;
	char nodebuff[128];
	phandle_t dnode;
	u32 props[8];
	struct ide_channel *chan;

	/* IDE ports on Macs are numbered from 3.
	 * Also see comments in macio.c:openpic_init() */
	current_channel = 3;

	for (i = 0; i < nb_channels; i++, current_channel++) {

		chan = malloc(sizeof(struct ide_channel));

		snprintf(chan->name, sizeof(chan->name),
			 DEV_NAME, current_channel);

		chan->mmio = addr + MACIO_IDE_OFFSET + i * MACIO_IDE_SIZE;

		chan->obide_inb = macio_ide_inb;
		chan->obide_insw = macio_ide_insw;
		chan->obide_outb = macio_ide_outb;
		chan->obide_outsw = macio_ide_outsw;

		chan->selected = -1;

		/*
		 * assume it's there, if not io port dead check will clear
		 */
		chan->present = 1;

		for (j = 0; j < 2; j++) {
			chan->drives[j].present = 0;
			chan->drives[j].unit = j;
			chan->drives[j].channel = chan;
			/* init with a decent value */
			chan->drives[j].bs = 512;

			chan->drives[j].nr = i * 2 + j;
		}

		ob_ide_probe(chan);

		if (!chan->present) {
			free(chan);
			continue;
		}

		ide_add_channel(chan);

		ob_ide_identify_drives(chan);

                snprintf(nodebuff, sizeof(nodebuff), "%s/" DEV_NAME, path,
                         current_channel);
		REGISTER_NAMED_NODE(ob_ide_ctrl, nodebuff);

		dnode = find_dev(nodebuff);

		set_property(dnode, "compatible", (is_oldworld() ?
			     "heathrow-ata" : "keylargo-ata"), 13);

		set_property(dnode, "model", ((current_channel == 3) ?
			     "ata-3" : "ata-4"), strlen("ata-*") + 1);

		set_property(dnode, "AAPL,connector", "ata",
                             strlen("ata") + 1);

		props[0] = 0x00000526;
		props[1] = 0x00000085;
		props[2] = 0x00000025;
		props[3] = 0x00000025;
		props[4] = 0x00000025;
		props[5] = 0x00000000;
		props[6] = 0x00000000;
		props[7] = 0x00000000;
		set_property(dnode, "AAPL,pio-timing",
				      (char *)&props, 8*sizeof(props[0]));

		/* The first interrupt entry is the ide interrupt, the second
		   the dbdma interrupt */
		switch (i) {
		case 0:
			props[0] = 0x0000000d;
			props[2] = 0x00000002;
			break;
		case 1:
			props[0] = 0x0000000e;
			props[2] = 0x00000003;
			break;
		case 2:
			props[0] = 0x0000000f;
			props[2] = 0x00000004;
			break;
		default:
			props[0] = 0x00000000;
			props[2] = 0x00000000;
			break;
		}
		props[1] = 0x00000000; /* XXX level triggered on real hw */
		props[3] = 0x00000000;
		NEWWORLD(set_property(dnode, "interrupts",
			     (char *)&props, 4*sizeof(props[0])));
		NEWWORLD(set_int_property(dnode, "#interrupt-cells", 2));

		props[1] = props[2];
		OLDWORLD(set_property(dnode, "AAPL,interrupts",
				      (char *)&props, 2*sizeof(props[0])));

		props[0] = MACIO_IDE_OFFSET + i * MACIO_IDE_SIZE;
		props[1] = MACIO_IDE_SIZE;
		props[2] = 0x00008b00 + i * 0x0200;
		props[3] = 0x0200;
		set_property(dnode, "reg", (char *)&props, 4*sizeof(props[0]));

		props[0] = addr + MACIO_IDE_OFFSET  + i * MACIO_IDE_SIZE;
		props[1] = addr + 0x00008b00 + i * 0x0200;
		OLDWORLD(set_property(dnode, "AAPL,address",
				      (char *)&props, 2*sizeof(props[0])));

		props[0] = 0;
		set_property(dnode, "AAPL,bus-id", (char*)props,
			 1 * sizeof(props[0]));
		IDE_DPRINTF(DEV_NAME": [io ports 0x%lx]\n",
		            current_channel, chan->mmio);

		for (j = 0; j < 2; j++) {
			struct ide_drive *drive = &chan->drives[j];
                        const char *media = "UNKNOWN";

			if (!drive->present)
				continue;

			IDE_DPRINTF("    drive%d [ATA%s ", j,
			            drive->type == ide_type_atapi ? "PI" : "");
			switch (drive->media) {
				case ide_media_floppy:
					media = "floppy";
					break;
				case ide_media_cdrom:
					media = "cdrom";
					break;
				case ide_media_optical:
					media = "mo";
					break;
				case ide_media_disk:
					media = "disk";
					break;
			}
			IDE_DPRINTF("%s]: %s\n", media, drive->model);
                        snprintf(nodebuff, sizeof(nodebuff),
                                 "%s/" DEV_NAME "/%s", path, current_channel,
                                 media);
			REGISTER_NAMED_NODE(ob_ide, nodebuff);
			dnode = find_dev(nodebuff);
			set_int_property(dnode, "reg", j);

			/* create aliases */

			set_ide_alias(nodebuff);
			if (drive->media == ide_media_cdrom)
				set_cd_alias(nodebuff);
			if (drive->media == ide_media_disk)
				set_hd_alias(nodebuff);
		}
	}

	return 0;
}
#endif /* CONFIG_DRIVER_MACIO */
