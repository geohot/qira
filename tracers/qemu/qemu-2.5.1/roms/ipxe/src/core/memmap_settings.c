/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/init.h>
#include <ipxe/settings.h>
#include <ipxe/io.h>

/** @file
 *
 * Memory map settings
 *
 * Memory map settings are numerically encoded as:
 *
 *  Bits 31-24	Number of regions, minus one
 *  Bits 23-16	Starting region
 *  Bits 15-11	Unused
 *  Bit  10	Ignore non-existent regions (rather than generating an error)
 *  Bit  9	Include length
 *  Bit  8	Include start address
 *  Bits 7-6	Unused
 *  Bits 5-0	Scale factor (i.e. right shift count)
 */

/**
 * Construct memory map setting tag
 *
 * @v start		Starting region
 * @v count		Number of regions
 * @v include_start	Include start address
 * @v include_length	Include length
 * @v ignore		Ignore non-existent regions
 * @v scale		Scale factor
 * @ret tag		Setting tag
 */
#define MEMMAP_TAG( start, count, include_start, include_length,	\
		    ignore, scale )					\
	( ( (start) << 16 ) | ( ( (count) - 1 ) << 24 ) |		\
	  ( (ignore) << 10 ) | ( (include_length) << 9 ) |		\
	  ( (include_start) << 8 ) | (scale) )

/**
 * Extract number of regions from setting tag
 *
 * @v tag		Setting tag
 * @ret count		Number of regions
 */
#define MEMMAP_COUNT( tag ) ( ( ( (tag) >> 24 ) & 0xff ) + 1 )

/**
 * Extract starting region from setting tag
 *
 * @v tag		Setting tag
 * @ret start		Starting region
 */
#define MEMMAP_START( tag ) ( ( (tag) >> 16 ) & 0xff )

/**
 * Extract ignore flag from setting tag
 *
 * @v tag		Setting tag
 * @ret ignore		Ignore non-existent regions
 */
#define MEMMAP_IGNORE_NONEXISTENT( tag ) ( (tag) & 0x00000400UL )

/**
 * Extract length inclusion flag from setting tag
 *
 * @v tag		Setting tag
 * @ret include_length	Include length
 */
#define MEMMAP_INCLUDE_LENGTH( tag ) ( (tag) & 0x00000200UL )

/**
 * Extract start address inclusion flag from setting tag
 *
 * @v tag		Setting tag
 * @ret include_start	Include start address
 */
#define MEMMAP_INCLUDE_START( tag ) ( (tag) & 0x00000100UL )

/**
 * Extract scale factor from setting tag
 *
 * @v tag		Setting tag
 * @v scale		Scale factor
 */
#define MEMMAP_SCALE( tag ) ( (tag) & 0x3f )

/** Memory map settings scope */
static const struct settings_scope memmap_settings_scope;

/**
 * Check applicability of memory map setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int memmap_settings_applies ( struct settings *settings __unused,
				     const struct setting *setting ) {

	return ( setting->scope == &memmap_settings_scope );
}

/**
 * Fetch value of memory map setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int memmap_settings_fetch ( struct settings *settings,
				   struct setting *setting,
				   void *data, size_t len ) {
	struct memory_map memmap;
	struct memory_region *region;
	uint64_t result = 0;
	unsigned int i;
	unsigned int count;

	DBGC ( settings, "MEMMAP start %d count %d %s%s%s%s scale %d\n",
	       MEMMAP_START ( setting->tag ), MEMMAP_COUNT ( setting->tag ),
	       ( MEMMAP_INCLUDE_START ( setting->tag ) ? "start" : "" ),
	       ( ( MEMMAP_INCLUDE_START ( setting->tag ) &&
		   MEMMAP_INCLUDE_LENGTH ( setting->tag ) ) ? "+" : "" ),
	       ( MEMMAP_INCLUDE_LENGTH ( setting->tag ) ? "length" : "" ),
	       ( MEMMAP_IGNORE_NONEXISTENT ( setting->tag ) ? " ignore" : "" ),
	       MEMMAP_SCALE ( setting->tag ) );

	/* Fetch memory map */
	get_memmap ( &memmap );

	/* Extract results from memory map */
	count = MEMMAP_COUNT ( setting->tag );
	for ( i = MEMMAP_START ( setting->tag ) ; count-- ; i++ ) {

		/* Check that region exists */
		if ( i >= memmap.count ) {
			if ( MEMMAP_IGNORE_NONEXISTENT ( setting->tag ) ) {
				continue;
			} else {
				DBGC ( settings, "MEMMAP region %d does not "
				       "exist\n", i );
				return -ENOENT;
			}
		}

		/* Extract results from this region */
		region = &memmap.regions[i];
		if ( MEMMAP_INCLUDE_START ( setting->tag ) ) {
			result += region->start;
			DBGC ( settings, "MEMMAP %d start %08llx\n",
			       i, region->start );
		}
		if ( MEMMAP_INCLUDE_LENGTH ( setting->tag ) ) {
			result += ( region->end - region->start );
			DBGC ( settings, "MEMMAP %d length %08llx\n",
			       i, ( region->end - region->start ) );
		}
	}

	/* Scale result */
	result >>= MEMMAP_SCALE ( setting->tag );

	/* Return result */
	result = cpu_to_be64 ( result );
	if ( len > sizeof ( result ) )
		len = sizeof ( result );
	memcpy ( data, &result, len );

	/* Set type if not already specified */
	if ( ! setting->type )
		setting->type = &setting_type_hexraw;

	return sizeof ( result );
}

/** Memory map settings operations */
static struct settings_operations memmap_settings_operations = {
	.applies = memmap_settings_applies,
	.fetch = memmap_settings_fetch,
};

/** Memory map settings */
static struct settings memmap_settings = {
	.refcnt = NULL,
	.siblings = LIST_HEAD_INIT ( memmap_settings.siblings ),
	.children = LIST_HEAD_INIT ( memmap_settings.children ),
	.op = &memmap_settings_operations,
	.default_scope = &memmap_settings_scope,
};

/** Initialise memory map settings */
static void memmap_settings_init ( void ) {
	int rc;

	if ( ( rc = register_settings ( &memmap_settings, NULL,
					"memmap" ) ) != 0 ) {
		DBG ( "MEMMAP could not register settings: %s\n",
		      strerror ( rc ) );
		return;
	}
}

/** Memory map settings initialiser */
struct init_fn memmap_settings_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = memmap_settings_init,
};

/** Memory map predefined settings */
const struct setting memsize_setting __setting ( SETTING_MISC, memsize ) = {
	.name = "memsize",
	.description = "Memory size (in MB)",
	.tag = MEMMAP_TAG ( 0, 0x100, 0, 1, 1, 20 ),
	.type = &setting_type_int32,
	.scope = &memmap_settings_scope,
};
