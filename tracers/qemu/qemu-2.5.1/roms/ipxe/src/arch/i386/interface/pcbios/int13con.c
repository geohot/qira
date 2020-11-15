/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
#include <string.h>
#include <errno.h>
#include <ipxe/console.h>
#include <ipxe/init.h>
#include <realmode.h>
#include <int13.h>
#include <config/console.h>

/** @file
 *
 * INT13 disk log console
 *
 */

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_INT13 ) && CONSOLE_EXPLICIT ( CONSOLE_INT13 ) )
#undef CONSOLE_INT13
#define CONSOLE_INT13 ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_LOG )
#endif

/** Disk drive number */
#define INT13CON_DRIVE 0x80

/** Log partition type */
#define INT13CON_PARTITION_TYPE 0xe0

/** Maximum number of outstanding unwritten characters */
#define INT13CON_MAX_UNWRITTEN 64

/** Log partition header */
struct int13con_header {
	/** Magic signature */
	char magic[10];
} __attribute__ (( packed ));

/** Log partition magic signature */
#define INT13CON_MAGIC "iPXE LOG\n\n"

/** Sector buffer */
static uint8_t __bss16_array ( int13con_buffer, [INT13_BLKSIZE] );
#define int13con_buffer __use_data16 ( int13con_buffer )

/** Disk address packet */
static struct int13_disk_address __bss16 ( int13con_address );
#define int13con_address __use_data16 ( int13con_address )

/** Current LBA */
static uint64_t int13con_lba;

/** Maximum LBA */
static uint64_t int13con_max_lba;

/** Current offset within sector */
static size_t int13con_offset;

/** Number of unwritten characters */
static size_t int13con_unwritten;

struct console_driver int13con __console_driver;

/**
 * Read/write disk sector
 *
 * @v op		Operation
 * @v lba		Logical block address
 * @ret rc		Return status code
 */
static int int13con_rw ( unsigned int op, uint64_t lba ) {
	uint8_t error;

	/* Construct disk address packet */
	int13con_address.bufsize = sizeof ( int13con_address );
	int13con_address.count = 1;
	int13con_address.buffer.segment = rm_ds;
	int13con_address.buffer.offset = __from_data16 ( int13con_buffer );
	int13con_address.lba = lba;

	/* Issue INT13 */
	__asm__ ( REAL_CODE ( "int $0x13\n\t" )
		  : "=a" ( error )
		  : "0" ( op << 8 ), "d" ( INT13CON_DRIVE ),
		    "S" ( __from_data16 ( &int13con_address ) ) );
	if ( error ) {
		DBG ( "INT13CON operation %04x failed: %02x\n",
		      op, error );
		return -EIO;
	}

	return 0;
}

/**
 * Write character to console
 *
 * @v character		Character
 */
static void int13con_putchar ( int character ) {
	static int busy;
	int rc;

	/* Ignore if we are already mid-logging */
	if ( busy )
		return;
	busy = 1;

	/* Write character to buffer */
	int13con_buffer[int13con_offset++] = character;
	int13con_unwritten++;

	/* Write sector to disk, if applicable */
	if ( ( int13con_offset == INT13_BLKSIZE ) ||
	     ( int13con_unwritten == INT13CON_MAX_UNWRITTEN ) ||
	     ( character == '\n' ) ) {

		/* Write sector to disk */
		if ( ( rc = int13con_rw ( INT13_EXTENDED_WRITE,
					  int13con_lba ) ) != 0 ) {
			DBG ( "INT13CON could not write log\n" );
			/* Ignore and continue; there's nothing we can do */
		}

		/* Reset count of unwritten characters */
		int13con_unwritten = 0;
	}

	/* Move to next sector, if applicable */
	if ( int13con_offset == INT13_BLKSIZE ) {

		/* Disable console if we have run out of space */
		if ( int13con_lba >= int13con_max_lba )
			int13con.disabled = 1;

		/* Clear log buffer */
		memset ( int13con_buffer, 0, sizeof ( int13con_buffer ) );
		int13con_offset = 0;

		/* Move to next sector */
		int13con_lba++;
	}

	/* Clear busy flag */
	busy = 0;
}

/**
 * Find log partition
 *
 * @ret rc		Return status code
 */
static int int13con_find ( void ) {
	struct master_boot_record *mbr =
		( ( struct master_boot_record * ) int13con_buffer );
	struct int13con_header *hdr =
		( ( struct int13con_header * ) int13con_buffer );
	struct partition_table_entry part[4];
	unsigned int i;
	int rc;

	/* Read MBR */
	if ( ( rc = int13con_rw ( INT13_EXTENDED_READ, 0 ) ) != 0 ) {
		DBG ( "INT13CON could not read MBR: %s\n", strerror ( rc ) );
		return rc;
	}

	/* Check MBR magic */
	if ( mbr->magic != INT13_MBR_MAGIC ) {
		DBG ( "INT13CON incorrect MBR magic\n" );
		DBG2_HDA ( 0, mbr, sizeof ( *mbr ) );
		return -EINVAL;
	}

	/* Look for magic partition */
	memcpy ( part, mbr->partitions, sizeof ( part ) );
	for ( i = 0 ; i < ( sizeof ( part ) / sizeof ( part[0] ) ) ; i++ ) {

		/* Skip partitions of the wrong type */
		if ( part[i].type != INT13CON_PARTITION_TYPE )
			continue;

		/* Read partition header */
		if ( ( rc = int13con_rw ( INT13_EXTENDED_READ,
					  part[i].start ) ) != 0 ) {
			DBG ( "INT13CON partition %d could not read header: "
			      "%s\n", ( i + 1 ), strerror ( rc ) );
			continue;
		}

		/* Check partition header */
		if ( memcmp ( hdr->magic, INT13CON_MAGIC,
			      sizeof ( hdr->magic ) ) != 0 ) {
			DBG ( "INT13CON partition %d bad magic\n", ( i + 1 ) );
			DBG2_HDA ( 0, hdr, sizeof ( *hdr ) );
			continue;
		}

		/* Found log partition */
		DBG ( "INT13CON partition %d at [%08x,%08x)\n", ( i + 1 ),
		      part[i].start, ( part[i].start + part[i].length ) );
		int13con_lba = part[i].start;
		int13con_max_lba = ( part[i].start + part[i].length - 1 );

		/* Initialise log buffer */
		memset ( &int13con_buffer[ sizeof ( *hdr ) ], 0,
			 ( sizeof ( int13con_buffer ) - sizeof ( *hdr ) ) );
		int13con_offset = sizeof ( hdr->magic );

		return 0;
	}

	DBG ( "INT13CON found no log partition\n" );
	return -ENOENT;
}

/**
 * Initialise INT13 console
 *
 */
static void int13con_init ( void ) {
	uint8_t error;
	uint16_t check;
	unsigned int discard_c;
	unsigned int discard_d;
	int rc;

	/* Check for INT13 extensions */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x13\n\t"
					   "setc %%al\n\t" )
			       : "=a" ( error ), "=b" ( check ),
				 "=c" ( discard_c ), "=d" ( discard_d )
			       : "0" ( INT13_EXTENSION_CHECK << 8 ),
				 "1" ( 0x55aa ), "3" ( INT13CON_DRIVE ) );
	if ( error || ( check != 0xaa55 ) ) {
		DBG ( "INT13CON missing extensions (%02x,%04x)\n",
		      error, check );
		return;
	}

	/* Locate log partition */
	if ( ( rc = int13con_find() ) != 0)
		return;

	/* Enable console */
	int13con.disabled = 0;
}

/**
 * INT13 console initialisation function
 */
struct init_fn int13con_init_fn __init_fn ( INIT_CONSOLE ) = {
	.initialise = int13con_init,
};

/** INT13 console driver */
struct console_driver int13con __console_driver = {
	.putchar = int13con_putchar,
	.disabled = CONSOLE_DISABLED,
	.usage = CONSOLE_INT13,
};
