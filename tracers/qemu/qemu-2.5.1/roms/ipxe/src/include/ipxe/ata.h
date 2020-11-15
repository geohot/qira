#ifndef _IPXE_ATA_H
#define _IPXE_ATA_H

#include <stdint.h>
#include <ipxe/uaccess.h>
#include <ipxe/interface.h>

/** @file
 *
 * ATA devices
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * An ATA Logical Block Address
 *
 * ATA controllers have three byte-wide registers for specifying the
 * block address: LBA Low, LBA Mid and LBA High.  This allows for a
 * 24-bit address.  Some devices support the "48-bit address feature
 * set" (LBA48), in which case each of these byte-wide registers is
 * actually a two-entry FIFO, and the "previous" byte pushed into the
 * FIFO is used as the corresponding high-order byte.  So, to set up
 * the 48-bit address 0x123456abcdef, you would issue
 *
 *     0x56 -> LBA Low register
 *     0xef -> LBA Low register
 *     0x34 -> LBA Mid register
 *     0xcd -> LBA Mid register
 *     0x12 -> LBA High register
 *     0xab -> LBA High register
 *
 * This structure encapsulates this information by providing a single
 * 64-bit integer in native byte order, unioned with bytes named so
 * that the sequence becomes
 *
 *     low_prev  -> LBA Low register
 *     low_cur   -> LBA Low register
 *     mid_prev  -> LBA Mid register
 *     mid_cur   -> LBA Mid register
 *     high_prev -> LBA High register
 *     high_cur  -> LBA High register
 *
 * Just to complicate matters further, in non-LBA48 mode it is
 * possible to have a 28-bit address, in which case bits 27:24 must be
 * written into the low four bits of the Device register.
 */
union ata_lba {
	/** LBA as a 64-bit integer in native-endian order */
	uint64_t native;
	/** ATA registers */
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint8_t low_cur;
		uint8_t mid_cur;
		uint8_t high_cur;
		uint8_t low_prev;
		uint8_t mid_prev;
		uint8_t high_prev;
		uint16_t pad;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint16_t pad;
		uint8_t high_prev;
		uint8_t mid_prev;
		uint8_t low_prev;
		uint8_t high_cur;
		uint8_t mid_cur;
		uint8_t low_cur;
#else
#error "I need a byte order"
#endif
	} bytes;
};

/** An ATA 2-byte FIFO register */
union ata_fifo {
	/** Value in native-endian order */
	uint16_t native;
	/** ATA registers */
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint8_t cur;
		uint8_t prev;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint8_t prev;
		uint8_t cur;
#else
#error "I need a byte order"
#endif
	} bytes;
};

/** ATA command block */
struct ata_cb {
	/** Logical block address */
	union ata_lba lba;
	/** Sector count */
	union ata_fifo count;
	/** Error/feature register */
	union ata_fifo err_feat;
	/** Device register */
	uint8_t device;
	/** Command/status register */
	uint8_t cmd_stat;
	/** Use LBA48 extended addressing */
	int lba48;
};

/** Obsolete bits in the ATA device register */
#define ATA_DEV_OBSOLETE 0xa0

/** LBA flag in the ATA device register */
#define ATA_DEV_LBA 0x40

/** Slave ("device 1") flag in the ATA device register */
#define ATA_DEV_SLAVE 0x10

/** Master ("device 0") flag in the ATA device register */
#define ATA_DEV_MASTER 0x00

/** Mask of non-LBA portion of device register */
#define ATA_DEV_MASK 0xf0

/** "Read sectors" command */
#define ATA_CMD_READ 0x20

/** "Read sectors (ext)" command */
#define ATA_CMD_READ_EXT 0x24

/** "Write sectors" command */
#define ATA_CMD_WRITE 0x30

/** "Write sectors (ext)" command */
#define ATA_CMD_WRITE_EXT 0x34

/** "Identify" command */
#define ATA_CMD_IDENTIFY 0xec

/** Command completed in error */
#define ATA_STAT_ERR 0x01

/**
 * Structure returned by ATA IDENTIFY command
 *
 * This is a huge structure with many fields that we don't care about,
 * so we implement only a few fields.
 */
struct ata_identity {
	uint16_t ignore_a[27]; /* words 0-26 */
	uint16_t model[20]; /* words 27-46 */
	uint16_t ignore_b[13]; /* words 47-59 */
	uint32_t lba_sectors; /* words 60-61 */
	uint16_t ignore_c[21]; /* words 62-82 */
	uint16_t supports_lba48; /* word 83 */
	uint16_t ignore_d[16]; /* words 84-99 */
	uint64_t lba48_sectors; /* words 100-103 */
	uint16_t ignore_e[152]; /* words 104-255 */
};

/** Supports LBA48 flag */
#define ATA_SUPPORTS_LBA48 ( 1 << 10 )

/** ATA sector size */
#define ATA_SECTOR_SIZE 512

/** An ATA command information unit */
struct ata_cmd {
	/** ATA command block */
	struct ata_cb cb;
	/** Data-out buffer (may be NULL)
	 *
	 * If non-NULL, this buffer must be ata_command::cb::count
	 * sectors in size.
	 */
	userptr_t data_out;
	/** Data-out buffer length
	 *
	 * Must be zero if @c data_out is NULL
	 */
	size_t data_out_len;
	/** Data-in buffer (may be NULL)
	 *
	 * If non-NULL, this buffer must be ata_command::cb::count
	 * sectors in size.
	 */
	userptr_t data_in;
	/** Data-in buffer length
	 *
	 * Must be zero if @c data_in is NULL
	 */
	size_t data_in_len;
};

extern int ata_command ( struct interface *control, struct interface *data,
			 struct ata_cmd *command );
#define ata_command_TYPE( object_type )					\
	typeof ( int ( object_type, struct interface *data,		\
		       struct ata_cmd *command ) )

extern int ata_open ( struct interface *block, struct interface *ata,
		      unsigned int device, unsigned int max_count );

#endif /* _IPXE_ATA_H */
