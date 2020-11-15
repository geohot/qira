/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <byteswap.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/list.h>
#include <ipxe/blockdev.h>
#include <ipxe/io.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/process.h>
#include <ipxe/xfer.h>
#include <ipxe/retry.h>
#include <ipxe/timer.h>
#include <ipxe/acpi.h>
#include <ipxe/sanboot.h>
#include <ipxe/device.h>
#include <ipxe/pci.h>
#include <ipxe/iso9660.h>
#include <ipxe/eltorito.h>
#include <realmode.h>
#include <bios.h>
#include <biosint.h>
#include <bootsector.h>
#include <int13.h>

/** @file
 *
 * INT 13 emulation
 *
 * This module provides a mechanism for exporting block devices via
 * the BIOS INT 13 disk interrupt interface.  
 *
 */

/**
 * Overall timeout for INT 13 commands (independent of underlying device
 *
 * Underlying devices should ideally never become totally stuck.
 * However, if they do, then the INT 13 mechanism provides no means
 * for the caller to cancel the operation, and the machine appears to
 * hang.  Use an overall timeout for all commands to avoid this
 * problem and bounce timeout failures to the caller.
 */
#define INT13_COMMAND_TIMEOUT ( 15 * TICKS_PER_SEC )

/** An INT 13 emulated drive */
struct int13_drive {
	/** Reference count */
	struct refcnt refcnt;
	/** List of all registered drives */
	struct list_head list;

	/** Block device URI */
	struct uri *uri;
	/** Underlying block device interface */
	struct interface block;

	/** BIOS in-use drive number (0x00-0xff) */
	unsigned int drive;
	/** BIOS natural drive number (0x00-0xff)
	 *
	 * This is the drive number that would have been assigned by
	 * 'naturally' appending the drive to the end of the BIOS
	 * drive list.
	 *
	 * If the emulated drive replaces a preexisting drive, this is
	 * the drive number that the preexisting drive gets remapped
	 * to.
	 */
	unsigned int natural_drive;

	/** Block device capacity */
	struct block_device_capacity capacity;
	/** INT 13 emulated blocksize shift
	 *
	 * To allow for emulation of CD-ROM access, this represents
	 * the left-shift required to translate from INT 13 blocks to
	 * underlying blocks.
	 */
	unsigned int blksize_shift;

	/** Number of cylinders
	 *
	 * The cylinder number field in an INT 13 call is ten bits
	 * wide, giving a maximum of 1024 cylinders.  Conventionally,
	 * when the 7.8GB limit of a CHS address is exceeded, it is
	 * the number of cylinders that is increased beyond the
	 * addressable limit.
	 */
	unsigned int cylinders;
	/** Number of heads
	 *
	 * The head number field in an INT 13 call is eight bits wide,
	 * giving a maximum of 256 heads.  However, apparently all
	 * versions of MS-DOS up to and including Win95 fail with 256
	 * heads, so the maximum encountered in practice is 255.
	 */
	unsigned int heads;
	/** Number of sectors per track
	 *
	 * The sector number field in an INT 13 call is six bits wide,
	 * giving a maximum of 63 sectors, since sector numbering
	 * (unlike head and cylinder numbering) starts at 1, not 0.
	 */
	unsigned int sectors_per_track;

	/** Drive is a CD-ROM */
	int is_cdrom;
	/** Address of El Torito boot catalog (if any) */
	unsigned int boot_catalog;

	/** Underlying device status, if in error */
	int block_rc;
	/** Status of last operation */
	int last_status;
};

/** Vector for chaining to other INT 13 handlers */
static struct segoff __text16 ( int13_vector );
#define int13_vector __use_text16 ( int13_vector )

/** Assembly wrapper */
extern void int13_wrapper ( void );

/** Dummy floppy disk parameter table */
static struct int13_fdd_parameters __data16 ( int13_fdd_params ) = {
	/* 512 bytes per sector */
	.bytes_per_sector = 0x02,
	/* Highest sectors per track that we ever return */
	.sectors_per_track = 48,
};
#define int13_fdd_params __use_data16 ( int13_fdd_params )

/** List of registered emulated drives */
static LIST_HEAD ( int13s );

/**
 * Equipment word
 *
 * This is a cached copy of the BIOS Data Area equipment word at
 * 40:10.
 */
static uint16_t equipment_word;

/**
 * Number of BIOS floppy disk drives
 *
 * This is derived from the equipment word.  It is held in .text16 to
 * allow for easy access by the INT 13,08 wrapper.
 */
static uint8_t __text16 ( num_fdds );
#define num_fdds __use_text16 ( num_fdds )

/**
 * Number of BIOS hard disk drives
 *
 * This is a cached copy of the BIOS Data Area number of hard disk
 * drives at 40:75.  It is held in .text16 to allow for easy access by
 * the INT 13,08 wrapper.
 */
static uint8_t __text16 ( num_drives );
#define num_drives __use_text16 ( num_drives )

/**
 * Calculate INT 13 drive sector size
 *
 * @v int13		Emulated drive
 * @ret blksize		Sector size
 */
static inline size_t int13_blksize ( struct int13_drive *int13 ) {
	return ( int13->capacity.blksize << int13->blksize_shift );
}

/**
 * Calculate INT 13 drive capacity
 *
 * @v int13		Emulated drive
 * @ret blocks		Number of blocks
 */
static inline uint64_t int13_capacity ( struct int13_drive *int13 ) {
	return ( int13->capacity.blocks >> int13->blksize_shift );
}

/**
 * Calculate INT 13 drive capacity (limited to 32 bits)
 *
 * @v int13		Emulated drive
 * @ret blocks		Number of blocks
 */
static inline uint32_t int13_capacity32 ( struct int13_drive *int13 ) {
	uint64_t capacity = int13_capacity ( int13 );
	return ( ( capacity <= 0xffffffffUL ) ? capacity : 0xffffffff );
}

/**
 * Test if INT 13 drive is a floppy disk drive
 *
 * @v int13		Emulated drive
 * @ret is_fdd		Emulated drive is a floppy disk
 */
static inline int int13_is_fdd ( struct int13_drive *int13 ) {
	return ( ! ( int13->drive & 0x80 ) );
}

/** An INT 13 command */
struct int13_command {
	/** Status */
	int rc;
	/** INT 13 drive */
	struct int13_drive *int13;
	/** Underlying block device interface */
	struct interface block;
	/** Command timeout timer */
	struct retry_timer timer;
};

/**
 * Record INT 13 drive capacity
 *
 * @v command		INT 13 command
 * @v capacity		Block device capacity
 */
static void int13_command_capacity ( struct int13_command *command,
				     struct block_device_capacity *capacity ) {
	memcpy ( &command->int13->capacity, capacity,
		 sizeof ( command->int13->capacity ) );
}

/**
 * Close INT 13 command
 *
 * @v command		INT 13 command
 * @v rc		Reason for close
 */
static void int13_command_close ( struct int13_command *command, int rc ) {
	intf_restart ( &command->block, rc );
	stop_timer ( &command->timer );
	command->rc = rc;
}

/**
 * Handle INT 13 command timer expiry
 *
 * @v timer		Timer
 */
static void int13_command_expired ( struct retry_timer *timer,
				    int over __unused ) {
	struct int13_command *command =
		container_of ( timer, struct int13_command, timer );

	int13_command_close ( command, -ETIMEDOUT );
}

/** INT 13 command interface operations */
static struct interface_operation int13_command_op[] = {
	INTF_OP ( intf_close, struct int13_command *, int13_command_close ),
	INTF_OP ( block_capacity, struct int13_command *,
		  int13_command_capacity ),
};

/** INT 13 command interface descriptor */
static struct interface_descriptor int13_command_desc =
	INTF_DESC ( struct int13_command, block, int13_command_op );

/**
 * Open (or reopen) INT 13 emulated drive underlying block device
 *
 * @v int13		Emulated drive
 * @ret rc		Return status code
 */
static int int13_reopen_block ( struct int13_drive *int13 ) {
	int rc;

	/* Close any existing block device */
	intf_restart ( &int13->block, -ECONNRESET );

	/* Open block device */
	if ( ( rc = xfer_open_uri ( &int13->block, int13->uri ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x could not reopen block "
		       "device: %s\n", int13->drive, strerror ( rc ) );
		int13->block_rc = rc;
		return rc;
	}

	/* Clear block device error status */
	int13->block_rc = 0;

	return 0;
}

/**
 * Prepare to issue INT 13 command
 *
 * @v command		INT 13 command
 * @v int13		Emulated drive
 * @ret rc		Return status code
 */
static int int13_command_start ( struct int13_command *command,
				 struct int13_drive *int13 ) {
	int rc;

	/* Sanity check */
	assert ( command->int13 == NULL );
	assert ( ! timer_running ( &command->timer ) );

	/* Reopen block device if necessary */
	if ( ( int13->block_rc != 0 ) &&
	     ( ( rc = int13_reopen_block ( int13 ) ) != 0 ) )
		return rc;

	/* Initialise command */
	command->rc = -EINPROGRESS;
	command->int13 = int13;
	start_timer_fixed ( &command->timer, INT13_COMMAND_TIMEOUT );

	/* Wait for block control interface to become ready */
	while ( ( command->rc == -EINPROGRESS ) &&
		( xfer_window ( &int13->block ) == 0 ) ) {
		step();
	}

	return ( ( command->rc == -EINPROGRESS ) ?
		 int13->block_rc : command->rc );
}

/**
 * Wait for INT 13 command to complete
 *
 * @v command		INT 13 command
 * @ret rc		Return status code
 */
static int int13_command_wait ( struct int13_command *command ) {

	/* Sanity check */
	assert ( timer_running ( &command->timer ) );

	/* Wait for command to complete */
	while ( command->rc == -EINPROGRESS )
		step();

	assert ( ! timer_running ( &command->timer ) );
	return command->rc;
}

/**
 * Terminate INT 13 command
 *
 * @v command		INT 13 command
 */
static void int13_command_stop ( struct int13_command *command ) {
	stop_timer ( &command->timer );
	command->int13 = NULL;
}

/** The single active INT 13 command */
static struct int13_command int13_command = {
	.block = INTF_INIT ( int13_command_desc ),
	.timer = TIMER_INIT ( int13_command_expired ),
};

/**
 * Read from or write to INT 13 drive
 *
 * @v int13		Emulated drive
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v block_rw		Block read/write method
 * @ret rc		Return status code
 */
static int int13_rw ( struct int13_drive *int13, uint64_t lba,
		      unsigned int count, userptr_t buffer,
		      int ( * block_rw ) ( struct interface *control,
					   struct interface *data,
					   uint64_t lba, unsigned int count,
					   userptr_t buffer, size_t len ) ) {
	struct int13_command *command = &int13_command;
	unsigned int frag_count;
	size_t frag_len;
	int rc;

	/* Translate to underlying blocksize */
	lba <<= int13->blksize_shift;
	count <<= int13->blksize_shift;

	while ( count ) {

		/* Determine fragment length */
		frag_count = count;
		if ( frag_count > int13->capacity.max_count )
			frag_count = int13->capacity.max_count;
		frag_len = ( int13->capacity.blksize * frag_count );

		/* Issue command */
		if ( ( ( rc = int13_command_start ( command, int13 ) ) != 0 ) ||
		     ( ( rc = block_rw ( &int13->block, &command->block, lba,
					 frag_count, buffer,
					 frag_len ) ) != 0 ) ||
		     ( ( rc = int13_command_wait ( command ) ) != 0 ) ) {
			int13_command_stop ( command );
			return rc;
		}
		int13_command_stop ( command );

		/* Move to next fragment */
		lba += frag_count;
		count -= frag_count;
		buffer = userptr_add ( buffer, frag_len );
	}

	return 0;
}

/**
 * Read INT 13 drive capacity
 *
 * @v int13		Emulated drive
 * @ret rc		Return status code
 */
static int int13_read_capacity ( struct int13_drive *int13 ) {
	struct int13_command *command = &int13_command;
	int rc;

	/* Issue command */
	if ( ( ( rc = int13_command_start ( command, int13 ) ) != 0 ) ||
	     ( ( rc = block_read_capacity ( &int13->block,
					    &command->block ) ) != 0 ) ||
	     ( ( rc = int13_command_wait ( command ) ) != 0 ) ) {
		int13_command_stop ( command );
		return rc;
	}

	int13_command_stop ( command );
	return 0;
}

/**
 * Parse ISO9660 parameters
 *
 * @v int13		Emulated drive
 * @v scratch		Scratch area for single-sector reads
 * @ret rc		Return status code
 *
 * Reads and parses ISO9660 parameters, if present.
 */
static int int13_parse_iso9660 ( struct int13_drive *int13, void *scratch ) {
	static const struct iso9660_primary_descriptor_fixed primary_check = {
		.type = ISO9660_TYPE_PRIMARY,
		.id = ISO9660_ID,
	};
	struct iso9660_primary_descriptor *primary = scratch;
	static const struct eltorito_descriptor_fixed boot_check = {
		.type = ISO9660_TYPE_BOOT,
		.id = ISO9660_ID,
		.version = 1,
		.system_id = "EL TORITO SPECIFICATION",
	};
	struct eltorito_descriptor *boot = scratch;
	unsigned int blksize;
	unsigned int blksize_shift;
	int rc;

	/* Calculate required blocksize shift */
	blksize = int13_blksize ( int13 );
	blksize_shift = 0;
	while ( blksize < ISO9660_BLKSIZE ) {
		blksize <<= 1;
		blksize_shift++;
	}
	if ( blksize > ISO9660_BLKSIZE ) {
		/* Do nothing if the blksize is invalid for CD-ROM access */
		return 0;
	}

	/* Read primary volume descriptor */
	if ( ( rc = int13_rw ( int13,
			       ( ISO9660_PRIMARY_LBA << blksize_shift ), 1,
			       virt_to_user ( primary ), block_read ) ) != 0 ){
		DBGC ( int13, "INT13 drive %02x could not read ISO9660 "
		       "primary volume descriptor: %s\n",
		       int13->drive, strerror ( rc ) );
		return rc;
	}

	/* Do nothing unless this is an ISO image */
	if ( memcmp ( primary, &primary_check, sizeof ( primary_check ) ) != 0 )
		return 0;
	DBGC ( int13, "INT13 drive %02x contains an ISO9660 filesystem; "
	       "treating as CD-ROM\n", int13->drive );
	int13->is_cdrom = 1;

	/* Read boot record volume descriptor */
	if ( ( rc = int13_rw ( int13,
			       ( ELTORITO_LBA << blksize_shift ), 1,
			       virt_to_user ( boot ), block_read ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x could not read El Torito boot "
		       "record volume descriptor: %s\n",
		       int13->drive, strerror ( rc ) );
		return rc;
	}

	/* Check for an El Torito boot catalog */
	if ( memcmp ( boot, &boot_check, sizeof ( boot_check ) ) == 0 ) {
		int13->boot_catalog = boot->sector;
		DBGC ( int13, "INT13 drive %02x has an El Torito boot catalog "
		       "at LBA %08x\n", int13->drive, int13->boot_catalog );
	} else {
		DBGC ( int13, "INT13 drive %02x has no El Torito boot "
		       "catalog\n", int13->drive );
	}

	/* Configure drive for no-emulation CD-ROM access */
	int13->blksize_shift += blksize_shift;

	return 0;
}

/**
 * Guess INT 13 hard disk drive geometry
 *
 * @v int13		Emulated drive
 * @v scratch		Scratch area for single-sector reads
 * @ret heads		Guessed number of heads
 * @ret sectors		Guessed number of sectors per track
 * @ret rc		Return status code
 *
 * Guesses the drive geometry by inspecting the partition table.
 */
static int int13_guess_geometry_hdd ( struct int13_drive *int13, void *scratch,
				      unsigned int *heads,
				      unsigned int *sectors ) {
	struct master_boot_record *mbr = scratch;
	struct partition_table_entry *partition;
	unsigned int i;
	int rc;

	/* Default guess is xx/255/63 */
	*heads = 255;
	*sectors = 63;

	/* Read partition table */
	if ( ( rc = int13_rw ( int13, 0, 1, virt_to_user ( mbr ),
			       block_read ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x could not read "
		       "partition table to guess geometry: %s\n",
		       int13->drive, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( int13, "INT13 drive %02x has MBR:\n", int13->drive );
	DBGC2_HDA ( int13, 0, mbr, sizeof ( *mbr ) );
	DBGC ( int13, "INT13 drive %02x has signature %08x\n",
	       int13->drive, mbr->signature );

	/* Scan through partition table and modify guesses for
	 * heads and sectors_per_track if we find any used
	 * partitions.
	 */
	for ( i = 0 ; i < 4 ; i++ ) {
		partition = &mbr->partitions[i];
		if ( ! partition->type )
			continue;
		*heads = ( PART_HEAD ( partition->chs_end ) + 1 );
		*sectors = PART_SECTOR ( partition->chs_end );
		DBGC ( int13, "INT13 drive %02x guessing C/H/S xx/%d/%d based "
		       "on partition %d\n",
		       int13->drive, *heads, *sectors, ( i + 1 ) );
	}

	return 0;
}

/** Recognised floppy disk geometries */
static const struct int13_fdd_geometry int13_fdd_geometries[] = {
	INT13_FDD_GEOMETRY ( 40, 1, 8 ),
	INT13_FDD_GEOMETRY ( 40, 1, 9 ),
	INT13_FDD_GEOMETRY ( 40, 2, 8 ),
	INT13_FDD_GEOMETRY ( 40, 1, 9 ),
	INT13_FDD_GEOMETRY ( 80, 2, 8 ),
	INT13_FDD_GEOMETRY ( 80, 2, 9 ),
	INT13_FDD_GEOMETRY ( 80, 2, 15 ),
	INT13_FDD_GEOMETRY ( 80, 2, 18 ),
	INT13_FDD_GEOMETRY ( 80, 2, 20 ),
	INT13_FDD_GEOMETRY ( 80, 2, 21 ),
	INT13_FDD_GEOMETRY ( 82, 2, 21 ),
	INT13_FDD_GEOMETRY ( 83, 2, 21 ),
	INT13_FDD_GEOMETRY ( 80, 2, 22 ),
	INT13_FDD_GEOMETRY ( 80, 2, 23 ),
	INT13_FDD_GEOMETRY ( 80, 2, 24 ),
	INT13_FDD_GEOMETRY ( 80, 2, 36 ),
	INT13_FDD_GEOMETRY ( 80, 2, 39 ),
	INT13_FDD_GEOMETRY ( 80, 2, 40 ),
	INT13_FDD_GEOMETRY ( 80, 2, 44 ),
	INT13_FDD_GEOMETRY ( 80, 2, 48 ),
};

/**
 * Guess INT 13 floppy disk drive geometry
 *
 * @v int13		Emulated drive
 * @ret heads		Guessed number of heads
 * @ret sectors		Guessed number of sectors per track
 * @ret rc		Return status code
 *
 * Guesses the drive geometry by inspecting the disk size.
 */
static int int13_guess_geometry_fdd ( struct int13_drive *int13,
				      unsigned int *heads,
				      unsigned int *sectors ) {
	unsigned int blocks = int13_capacity ( int13 );
	const struct int13_fdd_geometry *geometry;
	unsigned int cylinders;
	unsigned int i;

	/* Look for a match against a known geometry */
	for ( i = 0 ; i < ( sizeof ( int13_fdd_geometries ) /
			    sizeof ( int13_fdd_geometries[0] ) ) ; i++ ) {
		geometry = &int13_fdd_geometries[i];
		cylinders = INT13_FDD_CYLINDERS ( geometry );
		*heads = INT13_FDD_HEADS ( geometry );
		*sectors = INT13_FDD_SECTORS ( geometry );
		if ( ( cylinders * (*heads) * (*sectors) ) == blocks ) {
			DBGC ( int13, "INT13 drive %02x guessing C/H/S "
			       "%d/%d/%d based on size %dK\n", int13->drive,
			       cylinders, *heads, *sectors, ( blocks / 2 ) );
			return 0;
		}
	}

	/* Otherwise, assume a partial disk image in the most common
	 * format (1440K, 80/2/18).
	 */
	*heads = 2;
	*sectors = 18;
	DBGC ( int13, "INT13 drive %02x guessing C/H/S xx/%d/%d based on size "
	       "%dK\n", int13->drive, *heads, *sectors, ( blocks / 2 ) );
	return 0;
}

/**
 * Guess INT 13 drive geometry
 *
 * @v int13		Emulated drive
 * @v scratch		Scratch area for single-sector reads
 * @ret rc		Return status code
 */
static int int13_guess_geometry ( struct int13_drive *int13, void *scratch ) {
	unsigned int guessed_heads;
	unsigned int guessed_sectors;
	unsigned int blocks;
	unsigned int blocks_per_cyl;
	int rc;

	/* Don't even try when the blksize is invalid for C/H/S access */
	if ( int13_blksize ( int13 ) != INT13_BLKSIZE )
		return 0;

	/* Guess geometry according to drive type */
	if ( int13_is_fdd ( int13 ) ) {
		if ( ( rc = int13_guess_geometry_fdd ( int13, &guessed_heads,
						       &guessed_sectors )) != 0)
			return rc;
	} else {
		if ( ( rc = int13_guess_geometry_hdd ( int13, scratch,
						       &guessed_heads,
						       &guessed_sectors )) != 0)
			return rc;
	}

	/* Apply guesses if no geometry already specified */
	if ( ! int13->heads )
		int13->heads = guessed_heads;
	if ( ! int13->sectors_per_track )
		int13->sectors_per_track = guessed_sectors;
	if ( ! int13->cylinders ) {
		/* Avoid attempting a 64-bit divide on a 32-bit system */
		blocks = int13_capacity32 ( int13 );
		blocks_per_cyl = ( int13->heads * int13->sectors_per_track );
		assert ( blocks_per_cyl != 0 );
		int13->cylinders = ( blocks / blocks_per_cyl );
		if ( int13->cylinders > 1024 )
			int13->cylinders = 1024;
	}

	return 0;
}

/**
 * Update BIOS drive count
 */
static void int13_sync_num_drives ( void ) {
	struct int13_drive *int13;
	uint8_t *counter;
	uint8_t max_drive;
	uint8_t required;

	/* Get current drive counts */
	get_real ( equipment_word, BDA_SEG, BDA_EQUIPMENT_WORD );
	get_real ( num_drives, BDA_SEG, BDA_NUM_DRIVES );
	num_fdds = ( ( equipment_word & 0x0001 ) ?
		     ( ( ( equipment_word >> 6 ) & 0x3 ) + 1 ) : 0 );

	/* Ensure count is large enough to cover all of our emulated drives */
	list_for_each_entry ( int13, &int13s, list ) {
		counter = ( int13_is_fdd ( int13 ) ? &num_fdds : &num_drives );
		max_drive = int13->drive;
		if ( max_drive < int13->natural_drive )
			max_drive = int13->natural_drive;
		required = ( ( max_drive & 0x7f ) + 1 );
		if ( *counter < required ) {
			*counter = required;
			DBGC ( int13, "INT13 drive %02x added to drive count: "
			       "%d HDDs, %d FDDs\n",
			       int13->drive, num_drives, num_fdds );
		}
	}

	/* Update current drive count */
	equipment_word &= ~( ( 0x3 << 6 ) | 0x0001 );
	if ( num_fdds ) {
		equipment_word |= ( 0x0001 |
				    ( ( ( num_fdds - 1 ) & 0x3 ) << 6 ) );
	}
	put_real ( equipment_word, BDA_SEG, BDA_EQUIPMENT_WORD );
	put_real ( num_drives, BDA_SEG, BDA_NUM_DRIVES );
}

/**
 * Check number of drives
 */
static void int13_check_num_drives ( void ) {
	uint16_t check_equipment_word;
	uint8_t check_num_drives;

	get_real ( check_equipment_word, BDA_SEG, BDA_EQUIPMENT_WORD );
	get_real ( check_num_drives, BDA_SEG, BDA_NUM_DRIVES );
	if ( ( check_equipment_word != equipment_word ) ||
	     ( check_num_drives != num_drives ) ) {
		int13_sync_num_drives();
	}
}

/**
 * INT 13, 00 - Reset disk system
 *
 * @v int13		Emulated drive
 * @ret status		Status code
 */
static int int13_reset ( struct int13_drive *int13,
			 struct i386_all_regs *ix86 __unused ) {
	int rc;

	DBGC2 ( int13, "Reset drive\n" );

	/* Reopen underlying block device */
	if ( ( rc = int13_reopen_block ( int13 ) ) != 0 )
		return -INT13_STATUS_RESET_FAILED;

	/* Check that block device is functional */
	if ( ( rc = int13_read_capacity ( int13 ) ) != 0 )
		return -INT13_STATUS_RESET_FAILED;

	return 0;
}

/**
 * INT 13, 01 - Get status of last operation
 *
 * @v int13		Emulated drive
 * @ret status		Status code
 */
static int int13_get_last_status ( struct int13_drive *int13,
				   struct i386_all_regs *ix86 __unused ) {
	DBGC2 ( int13, "Get status of last operation\n" );
	return int13->last_status;
}

/**
 * Read / write sectors
 *
 * @v int13		Emulated drive
 * @v al		Number of sectors to read or write (must be nonzero)
 * @v ch		Low bits of cylinder number
 * @v cl (bits 7:6)	High bits of cylinder number
 * @v cl (bits 5:0)	Sector number
 * @v dh		Head number
 * @v es:bx		Data buffer
 * @v block_rw		Block read/write method
 * @ret status		Status code
 * @ret al		Number of sectors read or written
 */
static int int13_rw_sectors ( struct int13_drive *int13,
			      struct i386_all_regs *ix86,
			      int ( * block_rw ) ( struct interface *control,
						   struct interface *data,
						   uint64_t lba,
						   unsigned int count,
						   userptr_t buffer,
						   size_t len ) ) {
	unsigned int cylinder, head, sector;
	unsigned long lba;
	unsigned int count;
	userptr_t buffer;
	int rc;

	/* Validate blocksize */
	if ( int13_blksize ( int13 ) != INT13_BLKSIZE ) {
		DBGC ( int13, "\nINT 13 drive %02x invalid blocksize (%zd) "
		       "for non-extended read/write\n",
		       int13->drive, int13_blksize ( int13 ) );
		return -INT13_STATUS_INVALID;
	}

	/* Calculate parameters */
	cylinder = ( ( ( ix86->regs.cl & 0xc0 ) << 2 ) | ix86->regs.ch );
	head = ix86->regs.dh;
	sector = ( ix86->regs.cl & 0x3f );
	if ( ( cylinder >= int13->cylinders ) ||
	     ( head >= int13->heads ) ||
	     ( sector < 1 ) || ( sector > int13->sectors_per_track ) ) {
		DBGC ( int13, "C/H/S %d/%d/%d out of range for geometry "
		       "%d/%d/%d\n", cylinder, head, sector, int13->cylinders,
		       int13->heads, int13->sectors_per_track );
		return -INT13_STATUS_INVALID;
	}
	lba = ( ( ( ( cylinder * int13->heads ) + head )
		  * int13->sectors_per_track ) + sector - 1 );
	count = ix86->regs.al;
	buffer = real_to_user ( ix86->segs.es, ix86->regs.bx );

	DBGC2 ( int13, "C/H/S %d/%d/%d = LBA %08lx <-> %04x:%04x (count %d)\n",
		cylinder, head, sector, lba, ix86->segs.es, ix86->regs.bx,
		count );

	/* Read from / write to block device */
	if ( ( rc = int13_rw ( int13, lba, count, buffer, block_rw ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x I/O failed: %s\n",
		       int13->drive, strerror ( rc ) );
		return -INT13_STATUS_READ_ERROR;
	}

	return 0;
}

/**
 * INT 13, 02 - Read sectors
 *
 * @v int13		Emulated drive
 * @v al		Number of sectors to read (must be nonzero)
 * @v ch		Low bits of cylinder number
 * @v cl (bits 7:6)	High bits of cylinder number
 * @v cl (bits 5:0)	Sector number
 * @v dh		Head number
 * @v es:bx		Data buffer
 * @ret status		Status code
 * @ret al		Number of sectors read
 */
static int int13_read_sectors ( struct int13_drive *int13,
				struct i386_all_regs *ix86 ) {
	DBGC2 ( int13, "Read: " );
	return int13_rw_sectors ( int13, ix86, block_read );
}

/**
 * INT 13, 03 - Write sectors
 *
 * @v int13		Emulated drive
 * @v al		Number of sectors to write (must be nonzero)
 * @v ch		Low bits of cylinder number
 * @v cl (bits 7:6)	High bits of cylinder number
 * @v cl (bits 5:0)	Sector number
 * @v dh		Head number
 * @v es:bx		Data buffer
 * @ret status		Status code
 * @ret al		Number of sectors written
 */
static int int13_write_sectors ( struct int13_drive *int13,
				 struct i386_all_regs *ix86 ) {
	DBGC2 ( int13, "Write: " );
	return int13_rw_sectors ( int13, ix86, block_write );
}

/**
 * INT 13, 08 - Get drive parameters
 *
 * @v int13		Emulated drive
 * @ret status		Status code
 * @ret ch		Low bits of maximum cylinder number
 * @ret cl (bits 7:6)	High bits of maximum cylinder number
 * @ret cl (bits 5:0)	Maximum sector number
 * @ret dh		Maximum head number
 * @ret dl		Number of drives
 */
static int int13_get_parameters ( struct int13_drive *int13,
				  struct i386_all_regs *ix86 ) {
	unsigned int max_cylinder = int13->cylinders - 1;
	unsigned int max_head = int13->heads - 1;
	unsigned int max_sector = int13->sectors_per_track; /* sic */

	DBGC2 ( int13, "Get drive parameters\n" );

	/* Validate blocksize */
	if ( int13_blksize ( int13 ) != INT13_BLKSIZE ) {
		DBGC ( int13, "\nINT 13 drive %02x invalid blocksize (%zd) "
		       "for non-extended parameters\n",
		       int13->drive, int13_blksize ( int13 ) );
		return -INT13_STATUS_INVALID;
	}

	/* Common parameters */
	ix86->regs.ch = ( max_cylinder & 0xff );
	ix86->regs.cl = ( ( ( max_cylinder >> 8 ) << 6 ) | max_sector );
	ix86->regs.dh = max_head;
	ix86->regs.dl = ( int13_is_fdd ( int13 ) ? num_fdds : num_drives );

	/* Floppy-specific parameters */
	if ( int13_is_fdd ( int13 ) ) {
		ix86->regs.bl = INT13_FDD_TYPE_1M44;
		ix86->segs.es = rm_ds;
		ix86->regs.di = __from_data16 ( &int13_fdd_params );
	}

	return 0;
}

/**
 * INT 13, 15 - Get disk type
 *
 * @v int13		Emulated drive
 * @ret ah		Type code
 * @ret cx:dx		Sector count
 * @ret status		Status code / disk type
 */
static int int13_get_disk_type ( struct int13_drive *int13,
				 struct i386_all_regs *ix86 ) {
	uint32_t blocks;

	DBGC2 ( int13, "Get disk type\n" );

	if ( int13_is_fdd ( int13 ) ) {
		return INT13_DISK_TYPE_FDD;
	} else {
		blocks = int13_capacity32 ( int13 );
		ix86->regs.cx = ( blocks >> 16 );
		ix86->regs.dx = ( blocks & 0xffff );
		return INT13_DISK_TYPE_HDD;
	}
}

/**
 * INT 13, 41 - Extensions installation check
 *
 * @v int13		Emulated drive
 * @v bx		0x55aa
 * @ret bx		0xaa55
 * @ret cx		Extensions API support bitmap
 * @ret status		Status code / API version
 */
static int int13_extension_check ( struct int13_drive *int13 __unused,
				   struct i386_all_regs *ix86 ) {
	if ( ix86->regs.bx == 0x55aa ) {
		DBGC2 ( int13, "INT13 extensions installation check\n" );
		ix86->regs.bx = 0xaa55;
		ix86->regs.cx = ( INT13_EXTENSION_LINEAR |
				  INT13_EXTENSION_EDD |
				  INT13_EXTENSION_64BIT );
		return INT13_EXTENSION_VER_3_0;
	} else {
		return -INT13_STATUS_INVALID;
	}
}

/**
 * Extended read / write
 *
 * @v int13		Emulated drive
 * @v ds:si		Disk address packet
 * @v block_rw		Block read/write method
 * @ret status		Status code
 */
static int int13_extended_rw ( struct int13_drive *int13,
			       struct i386_all_regs *ix86,
			       int ( * block_rw ) ( struct interface *control,
						    struct interface *data,
						    uint64_t lba,
						    unsigned int count,
						    userptr_t buffer,
						    size_t len ) ) {
	struct int13_disk_address addr;
	uint8_t bufsize;
	uint64_t lba;
	unsigned long count;
	userptr_t buffer;
	int rc;

	/* Extended reads are not allowed on floppy drives.
	 * ELTORITO.SYS seems to assume that we are really a CD-ROM if
	 * we support extended reads for a floppy drive.
	 */
	if ( int13_is_fdd ( int13 ) )
		return -INT13_STATUS_INVALID;

	/* Get buffer size */
	get_real ( bufsize, ix86->segs.ds,
		   ( ix86->regs.si + offsetof ( typeof ( addr ), bufsize ) ) );
	if ( bufsize < offsetof ( typeof ( addr ), buffer_phys ) ) {
		DBGC2 ( int13, "<invalid buffer size %#02x\n>\n", bufsize );
		return -INT13_STATUS_INVALID;
	}

	/* Read parameters from disk address structure */
	memset ( &addr, 0, sizeof ( addr ) );
	copy_from_real ( &addr, ix86->segs.ds, ix86->regs.si, bufsize );
	lba = addr.lba;
	DBGC2 ( int13, "LBA %08llx <-> ", ( ( unsigned long long ) lba ) );
	if ( ( addr.count == 0xff ) ||
	     ( ( addr.buffer.segment == 0xffff ) &&
	       ( addr.buffer.offset == 0xffff ) ) ) {
		buffer = phys_to_user ( addr.buffer_phys );
		DBGC2 ( int13, "%08llx",
			( ( unsigned long long ) addr.buffer_phys ) );
	} else {
		buffer = real_to_user ( addr.buffer.segment,
					addr.buffer.offset );
		DBGC2 ( int13, "%04x:%04x", addr.buffer.segment,
			addr.buffer.offset );
	}
	if ( addr.count <= 0x7f ) {
		count = addr.count;
	} else if ( addr.count == 0xff ) {
		count = addr.long_count;
	} else {
		DBGC2 ( int13, " <invalid count %#02x>\n", addr.count );
		return -INT13_STATUS_INVALID;
	}
	DBGC2 ( int13, " (count %ld)\n", count );

	/* Read from / write to block device */
	if ( ( rc = int13_rw ( int13, lba, count, buffer, block_rw ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x extended I/O failed: %s\n",
		       int13->drive, strerror ( rc ) );
		/* Record that no blocks were transferred successfully */
		addr.count = 0;
		put_real ( addr.count, ix86->segs.ds,
			   ( ix86->regs.si +
			     offsetof ( typeof ( addr ), count ) ) );
		return -INT13_STATUS_READ_ERROR;
	}

	return 0;
}

/**
 * INT 13, 42 - Extended read
 *
 * @v int13		Emulated drive
 * @v ds:si		Disk address packet
 * @ret status		Status code
 */
static int int13_extended_read ( struct int13_drive *int13,
				 struct i386_all_regs *ix86 ) {
	DBGC2 ( int13, "Extended read: " );
	return int13_extended_rw ( int13, ix86, block_read );
}

/**
 * INT 13, 43 - Extended write
 *
 * @v int13		Emulated drive
 * @v ds:si		Disk address packet
 * @ret status		Status code
 */
static int int13_extended_write ( struct int13_drive *int13,
				  struct i386_all_regs *ix86 ) {
	DBGC2 ( int13, "Extended write: " );
	return int13_extended_rw ( int13, ix86, block_write );
}

/**
 * INT 13, 44 - Verify sectors
 *
 * @v int13		Emulated drive
 * @v ds:si		Disk address packet
 * @ret status		Status code
 */
static int int13_extended_verify ( struct int13_drive *int13,
				   struct i386_all_regs *ix86 ) {
	struct int13_disk_address addr;
	uint64_t lba;
	unsigned long count;

	/* Read parameters from disk address structure */
	if ( DBG_EXTRA ) {
		copy_from_real ( &addr, ix86->segs.ds, ix86->regs.si,
				 sizeof ( addr ));
		lba = addr.lba;
		count = addr.count;
		DBGC2 ( int13, "Verify: LBA %08llx (count %ld)\n",
			( ( unsigned long long ) lba ), count );
	}

	/* We have no mechanism for verifying sectors */
	return -INT13_STATUS_INVALID;
}

/**
 * INT 13, 44 - Extended seek
 *
 * @v int13		Emulated drive
 * @v ds:si		Disk address packet
 * @ret status		Status code
 */
static int int13_extended_seek ( struct int13_drive *int13,
				 struct i386_all_regs *ix86 ) {
	struct int13_disk_address addr;
	uint64_t lba;
	unsigned long count;

	/* Read parameters from disk address structure */
	if ( DBG_EXTRA ) {
		copy_from_real ( &addr, ix86->segs.ds, ix86->regs.si,
				 sizeof ( addr ));
		lba = addr.lba;
		count = addr.count;
		DBGC2 ( int13, "Seek: LBA %08llx (count %ld)\n",
			( ( unsigned long long ) lba ), count );
	}

	/* Ignore and return success */
	return 0;
}

/**
 * Build device path information
 *
 * @v int13		Emulated drive
 * @v dpi		Device path information
 * @ret rc		Return status code
 */
static int int13_device_path_info ( struct int13_drive *int13,
				    struct edd_device_path_information *dpi ) {
	struct device *device;
	struct device_description *desc;
	unsigned int i;
	uint8_t sum = 0;
	int rc;

	/* Reopen block device if necessary */
	if ( ( int13->block_rc != 0 ) &&
	     ( ( rc = int13_reopen_block ( int13 ) ) != 0 ) )
		return rc;

	/* Get underlying hardware device */
	device = identify_device ( &int13->block );
	if ( ! device ) {
		DBGC ( int13, "INT13 drive %02x cannot identify hardware "
		       "device\n", int13->drive );
		return -ENODEV;
	}

	/* Fill in bus type and interface path */
	desc = &device->desc;
	switch ( desc->bus_type ) {
	case BUS_TYPE_PCI:
		dpi->host_bus_type.type = EDD_BUS_TYPE_PCI;
		dpi->interface_path.pci.bus = PCI_BUS ( desc->location );
		dpi->interface_path.pci.slot = PCI_SLOT ( desc->location );
		dpi->interface_path.pci.function = PCI_FUNC ( desc->location );
		dpi->interface_path.pci.channel = 0xff; /* unused */
		break;
	default:
		DBGC ( int13, "INT13 drive %02x unrecognised bus type %d\n",
		       int13->drive, desc->bus_type );
		return -ENOTSUP;
	}

	/* Get EDD block device description */
	if ( ( rc = edd_describe ( &int13->block, &dpi->interface_type,
				   &dpi->device_path ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x cannot identify block device: "
		       "%s\n", int13->drive, strerror ( rc ) );
		return rc;
	}

	/* Fill in common fields and fix checksum */
	dpi->key = EDD_DEVICE_PATH_INFO_KEY;
	dpi->len = sizeof ( *dpi );
	for ( i = 0 ; i < sizeof ( *dpi ) ; i++ )
		sum += *( ( ( uint8_t * ) dpi ) + i );
	dpi->checksum -= sum;

	return 0;
}

/**
 * INT 13, 48 - Get extended parameters
 *
 * @v int13		Emulated drive
 * @v ds:si		Drive parameter table
 * @ret status		Status code
 */
static int int13_get_extended_parameters ( struct int13_drive *int13,
					   struct i386_all_regs *ix86 ) {
	struct int13_disk_parameters params;
	struct segoff address;
	size_t len = sizeof ( params );
	uint16_t bufsize;
	int rc;

	/* Get buffer size */
	get_real ( bufsize, ix86->segs.ds,
		   ( ix86->regs.si + offsetof ( typeof ( params ), bufsize )));

	DBGC2 ( int13, "Get extended drive parameters to %04x:%04x+%02x\n",
		ix86->segs.ds, ix86->regs.si, bufsize );

	/* Build drive parameters */
	memset ( &params, 0, sizeof ( params ) );
	params.flags = INT13_FL_DMA_TRANSPARENT;
	if ( ( int13->cylinders < 1024 ) &&
	     ( int13_capacity ( int13 ) <= INT13_MAX_CHS_SECTORS ) ) {
		params.flags |= INT13_FL_CHS_VALID;
	}
	params.cylinders = int13->cylinders;
	params.heads = int13->heads;
	params.sectors_per_track = int13->sectors_per_track;
	params.sectors = int13_capacity ( int13 );
	params.sector_size = int13_blksize ( int13 );
	memset ( &params.dpte, 0xff, sizeof ( params.dpte ) );
	if ( ( rc = int13_device_path_info ( int13, &params.dpi ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x could not provide device "
		       "path information: %s\n",
		       int13->drive, strerror ( rc ) );
		len = offsetof ( typeof ( params ), dpi );
	}

	/* Calculate returned "buffer size" (which will be less than
	 * the length actually copied if device path information is
	 * present).
	 */
	if ( bufsize < offsetof ( typeof ( params ), dpte ) )
		return -INT13_STATUS_INVALID;
	if ( bufsize < offsetof ( typeof ( params ), dpi ) ) {
		params.bufsize = offsetof ( typeof ( params ), dpte );
	} else {
		params.bufsize = offsetof ( typeof ( params ), dpi );
	}

	DBGC ( int13, "INT 13 drive %02x described using extended "
	       "parameters:\n", int13->drive );
	address.segment = ix86->segs.ds;
	address.offset = ix86->regs.si;
	DBGC_HDA ( int13, address, &params, len );

	/* Return drive parameters */
	if ( len > bufsize )
		len = bufsize;
	copy_to_real ( ix86->segs.ds, ix86->regs.si, &params, len );

	return 0;
}

/**
 * INT 13, 4b - Get status or terminate CD-ROM emulation
 *
 * @v int13		Emulated drive
 * @v ds:si		Specification packet
 * @ret status		Status code
 */
static int int13_cdrom_status_terminate ( struct int13_drive *int13,
					  struct i386_all_regs *ix86 ) {
	struct int13_cdrom_specification specification;

	DBGC2 ( int13, "Get CD-ROM emulation status to %04x:%04x%s\n",
		ix86->segs.ds, ix86->regs.si,
		( ix86->regs.al ? "" : " and terminate" ) );

	/* Fail if we are not a CD-ROM */
	if ( ! int13->is_cdrom ) {
		DBGC ( int13, "INT13 drive %02x is not a CD-ROM\n",
		       int13->drive );
		return -INT13_STATUS_INVALID;
	}

	/* Build specification packet */
	memset ( &specification, 0, sizeof ( specification ) );
	specification.size = sizeof ( specification );
	specification.drive = int13->drive;

	/* Return specification packet */
	copy_to_real ( ix86->segs.ds, ix86->regs.si, &specification,
		       sizeof ( specification ) );

	return 0;
}


/**
 * INT 13, 4d - Read CD-ROM boot catalog
 *
 * @v int13		Emulated drive
 * @v ds:si		Command packet
 * @ret status		Status code
 */
static int int13_cdrom_read_boot_catalog ( struct int13_drive *int13,
					   struct i386_all_regs *ix86 ) {
	struct int13_cdrom_boot_catalog_command command;
	int rc;

	/* Read parameters from command packet */
	copy_from_real ( &command, ix86->segs.ds, ix86->regs.si,
			 sizeof ( command ) );
	DBGC2 ( int13, "Read CD-ROM boot catalog to %08x\n", command.buffer );

	/* Fail if we have no boot catalog */
	if ( ! int13->boot_catalog ) {
		DBGC ( int13, "INT13 drive %02x has no boot catalog\n",
		       int13->drive );
		return -INT13_STATUS_INVALID;
	}

	/* Read from boot catalog */
	if ( ( rc = int13_rw ( int13, ( int13->boot_catalog + command.start ),
			       command.count, phys_to_user ( command.buffer ),
			       block_read ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x could not read boot catalog: "
		       "%s\n", int13->drive, strerror ( rc ) );
		return -INT13_STATUS_READ_ERROR;
	}

	return 0;
}

/**
 * INT 13 handler
 *
 */
static __asmcall void int13 ( struct i386_all_regs *ix86 ) {
	int command = ix86->regs.ah;
	unsigned int bios_drive = ix86->regs.dl;
	struct int13_drive *int13;
	int status;

	/* Check BIOS hasn't killed off our drive */
	int13_check_num_drives();

	list_for_each_entry ( int13, &int13s, list ) {

		if ( bios_drive != int13->drive ) {
			/* Remap any accesses to this drive's natural number */
			if ( bios_drive == int13->natural_drive ) {
				DBGC2 ( int13, "INT13,%02x (%02x) remapped to "
					"(%02x)\n", ix86->regs.ah,
					bios_drive, int13->drive );
				ix86->regs.dl = int13->drive;
				return;
			} else if ( ( ( bios_drive & 0x7f ) == 0x7f ) &&
				    ( command == INT13_CDROM_STATUS_TERMINATE )
				    && int13->is_cdrom ) {
				/* Catch non-drive-specific CD-ROM calls */
			} else {
				continue;
			}
		}
		
		DBGC2 ( int13, "INT13,%02x (%02x): ",
			ix86->regs.ah, bios_drive );

		switch ( command ) {
		case INT13_RESET:
			status = int13_reset ( int13, ix86 );
			break;
		case INT13_GET_LAST_STATUS:
			status = int13_get_last_status ( int13, ix86 );
			break;
		case INT13_READ_SECTORS:
			status = int13_read_sectors ( int13, ix86 );
			break;
		case INT13_WRITE_SECTORS:
			status = int13_write_sectors ( int13, ix86 );
			break;
		case INT13_GET_PARAMETERS:
			status = int13_get_parameters ( int13, ix86 );
			break;
		case INT13_GET_DISK_TYPE:
			status = int13_get_disk_type ( int13, ix86 );
			break;
		case INT13_EXTENSION_CHECK:
			status = int13_extension_check ( int13, ix86 );
			break;
		case INT13_EXTENDED_READ:
			status = int13_extended_read ( int13, ix86 );
			break;
		case INT13_EXTENDED_WRITE:
			status = int13_extended_write ( int13, ix86 );
			break;
		case INT13_EXTENDED_VERIFY:
			status = int13_extended_verify ( int13, ix86 );
			break;
		case INT13_EXTENDED_SEEK:
			status = int13_extended_seek ( int13, ix86 );
			break;
		case INT13_GET_EXTENDED_PARAMETERS:
			status = int13_get_extended_parameters ( int13, ix86 );
			break;
		case INT13_CDROM_STATUS_TERMINATE:
			status = int13_cdrom_status_terminate ( int13, ix86 );
			break;
		case INT13_CDROM_READ_BOOT_CATALOG:
			status = int13_cdrom_read_boot_catalog ( int13, ix86 );
			break;
		default:
			DBGC2 ( int13, "*** Unrecognised INT13 ***\n" );
			status = -INT13_STATUS_INVALID;
			break;
		}

		/* Store status for INT 13,01 */
		int13->last_status = status;

		/* Negative status indicates an error */
		if ( status < 0 ) {
			status = -status;
			DBGC ( int13, "INT13,%02x (%02x) failed with status "
			       "%02x\n", ix86->regs.ah, int13->drive, status );
		} else {
			ix86->flags &= ~CF;
		}
		ix86->regs.ah = status;

		/* Set OF to indicate to wrapper not to chain this call */
		ix86->flags |= OF;

		return;
	}
}

/**
 * Hook INT 13 handler
 *
 */
static void int13_hook_vector ( void ) {
	/* Assembly wrapper to call int13().  int13() sets OF if we
	 * should not chain to the previous handler.  (The wrapper
	 * clears CF and OF before calling int13()).
	 */
	__asm__  __volatile__ (
	       TEXT16_CODE ( "\nint13_wrapper:\n\t"
			     /* Preserve %ax and %dx for future reference */
			     "pushw %%bp\n\t"
			     "movw %%sp, %%bp\n\t"			     
			     "pushw %%ax\n\t"
			     "pushw %%dx\n\t"
			     /* Clear OF, set CF, call int13() */
			     "orb $0, %%al\n\t" 
			     "stc\n\t"
			     "pushl %0\n\t"
			     "pushw %%cs\n\t"
			     "call prot_call\n\t"
			     /* Chain if OF not set */
			     "jo 1f\n\t"
			     "pushfw\n\t"
			     "lcall *%%cs:int13_vector\n\t"
			     "\n1:\n\t"
			     /* Overwrite flags for iret */
			     "pushfw\n\t"
			     "popw 6(%%bp)\n\t"
			     /* Fix up %dl:
			      *
			      * INT 13,15 : do nothing if hard disk
			      * INT 13,08 : load with number of drives
			      * all others: restore original value
			      */
			     "cmpb $0x15, -1(%%bp)\n\t"
			     "jne 2f\n\t"
			     "testb $0x80, -4(%%bp)\n\t"
			     "jnz 3f\n\t"
			     "\n2:\n\t"
			     "movb -4(%%bp), %%dl\n\t"
			     "cmpb $0x08, -1(%%bp)\n\t"
			     "jne 3f\n\t"
			     "testb $0x80, %%dl\n\t"
			     "movb %%cs:num_drives, %%dl\n\t"
			     "jnz 3f\n\t"
			     "movb %%cs:num_fdds, %%dl\n\t"
			     /* Return */
			     "\n3:\n\t"
			     "movw %%bp, %%sp\n\t"
			     "popw %%bp\n\t"
			     "iret\n\t" )
	       : : "i" ( int13 ) );

	hook_bios_interrupt ( 0x13, ( unsigned int ) int13_wrapper,
			      &int13_vector );
}

/**
 * Unhook INT 13 handler
 */
static void int13_unhook_vector ( void ) {
	unhook_bios_interrupt ( 0x13, ( unsigned int ) int13_wrapper,
				&int13_vector );
}

/**
 * Check INT13 emulated drive flow control window
 *
 * @v int13		Emulated drive
 */
static size_t int13_block_window ( struct int13_drive *int13 __unused ) {

	/* We are never ready to receive data via this interface.
	 * This prevents objects that support both block and stream
	 * interfaces from attempting to send us stream data.
	 */
	return 0;
}

/**
 * Handle INT 13 emulated drive underlying block device closing
 *
 * @v int13		Emulated drive
 * @v rc		Reason for close
 */
static void int13_block_close ( struct int13_drive *int13, int rc ) {

	/* Any closing is an error from our point of view */
	if ( rc == 0 )
		rc = -ENOTCONN;

	DBGC ( int13, "INT13 drive %02x went away: %s\n",
	       int13->drive, strerror ( rc ) );

	/* Record block device error code */
	int13->block_rc = rc;

	/* Shut down interfaces */
	intf_restart ( &int13->block, rc );
}

/** INT 13 drive interface operations */
static struct interface_operation int13_block_op[] = {
	INTF_OP ( xfer_window, struct int13_drive *, int13_block_window ),
	INTF_OP ( intf_close, struct int13_drive *, int13_block_close ),
};

/** INT 13 drive interface descriptor */
static struct interface_descriptor int13_block_desc =
	INTF_DESC ( struct int13_drive, block, int13_block_op );

/**
 * Free INT 13 emulated drive
 *
 * @v refcnt		Reference count
 */
static void int13_free ( struct refcnt *refcnt ) {
	struct int13_drive *int13 =
		container_of ( refcnt, struct int13_drive, refcnt );

	uri_put ( int13->uri );
	free ( int13 );
}

/**
 * Hook INT 13 emulated drive
 *
 * @v uri		URI
 * @v drive		Drive number
 * @ret rc		Return status code
 *
 * Registers the drive with the INT 13 emulation subsystem, and hooks
 * the INT 13 interrupt vector (if not already hooked).
 */
static int int13_hook ( struct uri *uri, unsigned int drive ) {
	struct int13_drive *int13;
	unsigned int natural_drive;
	void *scratch;
	int rc;

	/* Calculate natural drive number */
	int13_sync_num_drives();
	natural_drive = ( ( drive & 0x80 ) ? ( num_drives | 0x80 ) : num_fdds );

	/* Check that drive number is not in use */
	list_for_each_entry ( int13, &int13s, list ) {
		if ( int13->drive == drive ) {
			rc = -EADDRINUSE;
			goto err_in_use;
		}
	}

	/* Allocate and initialise structure */
	int13 = zalloc ( sizeof ( *int13 ) );
	if ( ! int13 ) {
		rc = -ENOMEM;
		goto err_zalloc;
	}
	ref_init ( &int13->refcnt, int13_free );
	intf_init ( &int13->block, &int13_block_desc, &int13->refcnt );
	int13->uri = uri_get ( uri );
	int13->drive = drive;
	int13->natural_drive = natural_drive;

	/* Open block device interface */
	if ( ( rc = int13_reopen_block ( int13 ) ) != 0 )
		goto err_reopen_block;

	/* Read device capacity */
	if ( ( rc = int13_read_capacity ( int13 ) ) != 0 )
		goto err_read_capacity;

	/* Allocate scratch area */
	scratch = malloc ( int13_blksize ( int13 ) );
	if ( ! scratch )
		goto err_alloc_scratch;

	/* Parse parameters, if present */
	if ( ( rc = int13_parse_iso9660 ( int13, scratch ) ) != 0 )
		goto err_parse_iso9660;

	/* Give drive a default geometry */
	if ( ( rc = int13_guess_geometry ( int13, scratch ) ) != 0 )
		goto err_guess_geometry;

	DBGC ( int13, "INT13 drive %02x (naturally %02x) registered with C/H/S "
	       "geometry %d/%d/%d\n", int13->drive, int13->natural_drive,
	       int13->cylinders, int13->heads, int13->sectors_per_track );

	/* Hook INT 13 vector if not already hooked */
	if ( list_empty ( &int13s ) ) {
		int13_hook_vector();
		devices_get();
	}

	/* Add to list of emulated drives */
	list_add ( &int13->list, &int13s );

	/* Update BIOS drive count */
	int13_sync_num_drives();

	free ( scratch );
	return 0;

 err_guess_geometry:
 err_parse_iso9660:
	free ( scratch );
 err_alloc_scratch:
 err_read_capacity:
 err_reopen_block:
	intf_shutdown ( &int13->block, rc );
	ref_put ( &int13->refcnt );
 err_zalloc:
 err_in_use:
	return rc;
}

/**
 * Find INT 13 emulated drive by drive number
 *
 * @v drive		Drive number
 * @ret int13		Emulated drive, or NULL
 */
static struct int13_drive * int13_find ( unsigned int drive ) {
	struct int13_drive *int13;

	list_for_each_entry ( int13, &int13s, list ) {
		if ( int13->drive == drive )
			return int13;
	}
	return NULL;
}

/**
 * Unhook INT 13 emulated drive
 *
 * @v drive		Drive number
 *
 * Unregisters the drive from the INT 13 emulation subsystem.  If this
 * is the last emulated drive, the INT 13 vector is unhooked (if
 * possible).
 */
static void int13_unhook ( unsigned int drive ) {
	struct int13_drive *int13;

	/* Find drive */
	int13 = int13_find ( drive );
	if ( ! int13 ) {
		DBG ( "INT13 cannot find emulated drive %02x\n", drive );
		return;
	}

	/* Shut down interfaces */
	intf_shutdown ( &int13->block, 0 );

	/* Remove from list of emulated drives */
	list_del ( &int13->list );

	/* Should adjust BIOS drive count, but it's difficult
	 * to do so reliably.
	 */

	DBGC ( int13, "INT13 drive %02x unregistered\n", int13->drive );

	/* Unhook INT 13 vector if no more drives */
	if ( list_empty ( &int13s ) ) {
		devices_put();
		int13_unhook_vector();
	}

	/* Drop list's reference to drive */
	ref_put ( &int13->refcnt );
}

/**
 * Load and verify master boot record from INT 13 drive
 *
 * @v drive		Drive number
 * @v address		Boot code address to fill in
 * @ret rc		Return status code
 */
static int int13_load_mbr ( unsigned int drive, struct segoff *address ) {
	uint8_t status;
	int discard_b, discard_c, discard_d;
	uint16_t magic;

	/* Use INT 13, 02 to read the MBR */
	address->segment = 0;
	address->offset = 0x7c00;
	__asm__ __volatile__ ( REAL_CODE ( "pushw %%es\n\t"
					   "pushl %%ebx\n\t"
					   "popw %%bx\n\t"
					   "popw %%es\n\t"
					   "stc\n\t"
					   "sti\n\t"
					   "int $0x13\n\t"
					   "sti\n\t" /* BIOS bugs */
					   "jc 1f\n\t"
					   "xorw %%ax, %%ax\n\t"
					   "\n1:\n\t"
					   "popw %%es\n\t" )
			       : "=a" ( status ), "=b" ( discard_b ),
				 "=c" ( discard_c ), "=d" ( discard_d )
			       : "a" ( 0x0201 ), "b" ( *address ),
				 "c" ( 1 ), "d" ( drive ) );
	if ( status ) {
		DBG ( "INT13 drive %02x could not read MBR (status %02x)\n",
		      drive, status );
		return -EIO;
	}

	/* Check magic signature */
	get_real ( magic, address->segment,
		   ( address->offset +
		     offsetof ( struct master_boot_record, magic ) ) );
	if ( magic != INT13_MBR_MAGIC ) {
		DBG ( "INT13 drive %02x does not contain a valid MBR\n",
		      drive );
		return -ENOEXEC;
	}

	return 0;
}

/** El Torito boot catalog command packet */
static struct int13_cdrom_boot_catalog_command __data16 ( eltorito_cmd ) = {
	.size = sizeof ( struct int13_cdrom_boot_catalog_command ),
	.count = 1,
	.buffer = 0x7c00,
	.start = 0,
};
#define eltorito_cmd __use_data16 ( eltorito_cmd )

/** El Torito disk address packet */
static struct int13_disk_address __bss16 ( eltorito_address );
#define eltorito_address __use_data16 ( eltorito_address )

/**
 * Load and verify El Torito boot record from INT 13 drive
 *
 * @v drive		Drive number
 * @v address		Boot code address to fill in
 * @ret rc		Return status code
 */
static int int13_load_eltorito ( unsigned int drive, struct segoff *address ) {
	struct {
		struct eltorito_validation_entry valid;
		struct eltorito_boot_entry boot;
	} __attribute__ (( packed )) catalog;
	uint8_t status;

	/* Use INT 13, 4d to read the boot catalog */
	__asm__ __volatile__ ( REAL_CODE ( "stc\n\t"
					   "sti\n\t"
					   "int $0x13\n\t"
					   "sti\n\t" /* BIOS bugs */
					   "jc 1f\n\t"
					   "xorw %%ax, %%ax\n\t"
					   "\n1:\n\t" )
			       : "=a" ( status )
			       : "a" ( 0x4d00 ), "d" ( drive ),
				 "S" ( __from_data16 ( &eltorito_cmd ) ) );
	if ( status ) {
		DBG ( "INT13 drive %02x could not read El Torito boot catalog "
		      "(status %02x)\n", drive, status );
		return -EIO;
	}
	copy_from_user ( &catalog, phys_to_user ( eltorito_cmd.buffer ), 0,
			 sizeof ( catalog ) );

	/* Sanity checks */
	if ( catalog.valid.platform_id != ELTORITO_PLATFORM_X86 ) {
		DBG ( "INT13 drive %02x El Torito specifies unknown platform "
		      "%02x\n", drive, catalog.valid.platform_id );
		return -ENOEXEC;
	}
	if ( catalog.boot.indicator != ELTORITO_BOOTABLE ) {
		DBG ( "INT13 drive %02x El Torito is not bootable\n", drive );
		return -ENOEXEC;
	}
	if ( catalog.boot.media_type != ELTORITO_NO_EMULATION ) {
		DBG ( "INT13 drive %02x El Torito requires emulation "
		       "type %02x\n", drive, catalog.boot.media_type );
		return -ENOTSUP;
	}
	DBG ( "INT13 drive %02x El Torito boot image at LBA %08x (count %d)\n",
	      drive, catalog.boot.start, catalog.boot.length );
	address->segment = ( catalog.boot.load_segment ?
			     catalog.boot.load_segment : 0x7c0 );
	address->offset = 0;
	DBG ( "INT13 drive %02x El Torito boot image loads at %04x:%04x\n",
	      drive, address->segment, address->offset );

	/* Use INT 13, 42 to read the boot image */
	eltorito_address.bufsize =
		offsetof ( typeof ( eltorito_address ), buffer_phys );
	eltorito_address.count = catalog.boot.length;
	eltorito_address.buffer = *address;
	eltorito_address.lba = catalog.boot.start;
	__asm__ __volatile__ ( REAL_CODE ( "stc\n\t"
					   "sti\n\t"
					   "int $0x13\n\t"
					   "sti\n\t" /* BIOS bugs */
					   "jc 1f\n\t"
					   "xorw %%ax, %%ax\n\t"
					   "\n1:\n\t" )
			       : "=a" ( status )
			       : "a" ( 0x4200 ), "d" ( drive ),
				 "S" ( __from_data16 ( &eltorito_address ) ) );
	if ( status ) {
		DBG ( "INT13 drive %02x could not read El Torito boot image "
		      "(status %02x)\n", drive, status );
		return -EIO;
	}

	return 0;
}

/**
 * Attempt to boot from an INT 13 drive
 *
 * @v drive		Drive number
 * @ret rc		Return status code
 *
 * This boots from the specified INT 13 drive by loading the Master
 * Boot Record to 0000:7c00 and jumping to it.  INT 18 is hooked to
 * capture an attempt by the MBR to boot the next device.  (This is
 * the closest thing to a return path from an MBR).
 *
 * Note that this function can never return success, by definition.
 */
static int int13_boot ( unsigned int drive ) {
	struct memory_map memmap;
	struct segoff address;
	int rc;

	/* Look for a usable boot sector */
	if ( ( ( rc = int13_load_mbr ( drive, &address ) ) != 0 ) &&
	     ( ( rc = int13_load_eltorito ( drive, &address ) ) != 0 ) )
		return rc;

	/* Dump out memory map prior to boot, if memmap debugging is
	 * enabled.  Not required for program flow, but we have so
	 * many problems that turn out to be memory-map related that
	 * it's worth doing.
	 */
	get_memmap ( &memmap );

	/* Jump to boot sector */
	if ( ( rc = call_bootsector ( address.segment, address.offset,
				      drive ) ) != 0 ) {
		DBG ( "INT13 drive %02x boot returned: %s\n",
		      drive, strerror ( rc ) );
		return rc;
	}

	return -ECANCELED; /* -EIMPOSSIBLE */
}

/** A boot firmware table generated by iPXE */
union xbft_table {
	/** ACPI header */
	struct acpi_description_header acpi;
	/** Padding */
	char pad[768];
};

/** The boot firmware table generated by iPXE */
static union xbft_table __bss16 ( xbftab ) __attribute__ (( aligned ( 16 ) ));
#define xbftab __use_data16 ( xbftab )

/**
 * Describe INT 13 emulated drive for SAN-booted operating system
 *
 * @v drive		Drive number
 * @ret rc		Return status code
 */
static int int13_describe ( unsigned int drive ) {
	struct int13_drive *int13;
	struct segoff xbft_address;
	int rc;

	/* Find drive */
	int13 = int13_find ( drive );
	if ( ! int13 ) {
		DBG ( "INT13 cannot find emulated drive %02x\n", drive );
		return -ENODEV;
	}

	/* Reopen block device if necessary */
	if ( ( int13->block_rc != 0 ) &&
	     ( ( rc = int13_reopen_block ( int13 ) ) != 0 ) )
		return rc;

	/* Clear table */
	memset ( &xbftab, 0, sizeof ( xbftab ) );

	/* Fill in common parameters */
	strncpy ( xbftab.acpi.oem_id, "FENSYS",
		  sizeof ( xbftab.acpi.oem_id ) );
	strncpy ( xbftab.acpi.oem_table_id, "iPXE",
		  sizeof ( xbftab.acpi.oem_table_id ) );

	/* Fill in remaining parameters */
	if ( ( rc = acpi_describe ( &int13->block, &xbftab.acpi,
				    sizeof ( xbftab ) ) ) != 0 ) {
		DBGC ( int13, "INT13 drive %02x could not create ACPI "
		       "description: %s\n", int13->drive, strerror ( rc ) );
		return rc;
	}

	/* Fix up ACPI checksum */
	acpi_fix_checksum ( &xbftab.acpi );
	xbft_address.segment = rm_ds;
	xbft_address.offset = __from_data16 ( &xbftab );
	DBGC ( int13, "INT13 drive %02x described using boot firmware "
	       "table:\n", int13->drive );
	DBGC_HDA ( int13, xbft_address, &xbftab,
		   le32_to_cpu ( xbftab.acpi.length ) );

	return 0;
}

PROVIDE_SANBOOT_INLINE ( pcbios, san_default_drive );
PROVIDE_SANBOOT ( pcbios, san_hook, int13_hook );
PROVIDE_SANBOOT ( pcbios, san_unhook, int13_unhook );
PROVIDE_SANBOOT ( pcbios, san_boot, int13_boot );
PROVIDE_SANBOOT ( pcbios, san_describe, int13_describe );
