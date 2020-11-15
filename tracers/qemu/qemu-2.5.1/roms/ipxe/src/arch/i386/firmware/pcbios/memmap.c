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
#include <errno.h>
#include <realmode.h>
#include <bios.h>
#include <memsizes.h>
#include <ipxe/io.h>

/**
 * @file
 *
 * Memory mapping
 *
 */

/** Magic value for INT 15,e820 calls */
#define SMAP ( 0x534d4150 )

/** An INT 15,e820 memory map entry */
struct e820_entry {
	/** Start of region */
	uint64_t start;
	/** Length of region */
	uint64_t len;
	/** Type of region */
	uint32_t type;
	/** Extended attributes (optional) */
	uint32_t attrs;
} __attribute__ (( packed ));

#define E820_TYPE_RAM		1 /**< Normal memory */
#define E820_TYPE_RESERVED	2 /**< Reserved and unavailable */
#define E820_TYPE_ACPI		3 /**< ACPI reclaim memory */
#define E820_TYPE_NVS		4 /**< ACPI NVS memory */

#define E820_ATTR_ENABLED	0x00000001UL
#define E820_ATTR_NONVOLATILE	0x00000002UL
#define E820_ATTR_UNKNOWN	0xfffffffcUL

#define E820_MIN_SIZE		20

/** Buffer for INT 15,e820 calls */
static struct e820_entry __bss16 ( e820buf );
#define e820buf __use_data16 ( e820buf )

/** We are running during POST; inhibit INT 15,e820 and INT 15,e801 */
uint8_t __bss16 ( memmap_post );
#define memmap_post __use_data16 ( memmap_post )

/**
 * Get size of extended memory via INT 15,e801
 *
 * @ret extmem		Extended memory size, in kB, or 0
 */
static unsigned int extmemsize_e801 ( void ) {
	uint16_t extmem_1m_to_16m_k, extmem_16m_plus_64k;
	uint16_t confmem_1m_to_16m_k, confmem_16m_plus_64k;
	unsigned int flags;
	unsigned int extmem;

	/* Inhibit INT 15,e801 during POST */
	if ( memmap_post ) {
		DBG ( "INT 15,e801 not available during POST\n" );
		return 0;
	}

	__asm__ __volatile__ ( REAL_CODE ( "stc\n\t"
					   "int $0x15\n\t"
					   "pushfw\n\t"
					   "popw %w0\n\t" )
			       : "=r" ( flags ),
				 "=a" ( extmem_1m_to_16m_k ),
				 "=b" ( extmem_16m_plus_64k ),
				 "=c" ( confmem_1m_to_16m_k ),
				 "=d" ( confmem_16m_plus_64k )
			       : "a" ( 0xe801 ) );

	if ( flags & CF ) {
		DBG ( "INT 15,e801 failed with CF set\n" );
		return 0;
	}

	if ( ! ( extmem_1m_to_16m_k | extmem_16m_plus_64k ) ) {
		DBG ( "INT 15,e801 extmem=0, using confmem\n" );
		extmem_1m_to_16m_k = confmem_1m_to_16m_k;
		extmem_16m_plus_64k = confmem_16m_plus_64k;
	}

	extmem = ( extmem_1m_to_16m_k + ( extmem_16m_plus_64k * 64 ) );
	DBG ( "INT 15,e801 extended memory size %d+64*%d=%d kB "
	      "[100000,%llx)\n", extmem_1m_to_16m_k, extmem_16m_plus_64k,
	      extmem, ( 0x100000 + ( ( ( uint64_t ) extmem ) * 1024 ) ) );

	/* Sanity check.  Some BIOSes report the entire 4GB address
	 * space as available, which cannot be correct (since that
	 * would leave no address space available for 32-bit PCI
	 * BARs).
	 */
	if ( extmem == ( 0x400000 - 0x400 ) ) {
		DBG ( "INT 15,e801 reported whole 4GB; assuming insane\n" );
		return 0;
	}

	return extmem;
}

/**
 * Get size of extended memory via INT 15,88
 *
 * @ret extmem		Extended memory size, in kB
 */
static unsigned int extmemsize_88 ( void ) {
	uint16_t extmem;

	/* Ignore CF; it is not reliable for this call */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x15" )
			       : "=a" ( extmem ) : "a" ( 0x8800 ) );

	DBG ( "INT 15,88 extended memory size %d kB [100000, %x)\n",
	      extmem, ( 0x100000 + ( extmem * 1024 ) ) );
	return extmem;
}

/**
 * Get size of extended memory
 *
 * @ret extmem		Extended memory size, in kB
 *
 * Note that this is only an approximation; for an accurate picture,
 * use the E820 memory map obtained via get_memmap();
 */
unsigned int extmemsize ( void ) {
	unsigned int extmem_e801;
	unsigned int extmem_88;

	/* Try INT 15,e801 first, then fall back to INT 15,88 */
	extmem_88 = extmemsize_88();
	extmem_e801 = extmemsize_e801();
	return ( extmem_e801 ? extmem_e801 : extmem_88 );
}

/**
 * Get e820 memory map
 *
 * @v memmap		Memory map to fill in
 * @ret rc		Return status code
 */
static int meme820 ( struct memory_map *memmap ) {
	struct memory_region *region = memmap->regions;
	struct memory_region *prev_region = NULL;
	uint32_t next = 0;
	uint32_t smap;
	size_t size;
	unsigned int flags;
	unsigned int discard_D;

	/* Inhibit INT 15,e820 during POST */
	if ( memmap_post ) {
		DBG ( "INT 15,e820 not available during POST\n" );
		return -ENOTTY;
	}

	/* Clear the E820 buffer.  Do this once before starting,
	 * rather than on each call; some BIOSes rely on the contents
	 * being preserved between calls.
	 */
	memset ( &e820buf, 0, sizeof ( e820buf ) );

	do {
		/* Some BIOSes corrupt %esi for fun. Guard against
		 * this by telling gcc that all non-output registers
		 * may be corrupted.
		 */
		__asm__ __volatile__ ( REAL_CODE ( "pushl %%ebp\n\t"
						   "stc\n\t"
						   "int $0x15\n\t"
						   "pushfw\n\t"
						   "popw %%dx\n\t"
						   "popl %%ebp\n\t" )
				       : "=a" ( smap ), "=b" ( next ),
					 "=c" ( size ), "=d" ( flags ),
					 "=D" ( discard_D )
				       : "a" ( 0xe820 ), "b" ( next ),
					 "D" ( __from_data16 ( &e820buf ) ),
					 "c" ( sizeof ( e820buf ) ),
					 "d" ( SMAP )
				       : "esi", "memory" );

		if ( smap != SMAP ) {
			DBG ( "INT 15,e820 failed SMAP signature check\n" );
			return -ENOTSUP;
		}

		if ( size < E820_MIN_SIZE ) {
			DBG ( "INT 15,e820 returned only %zd bytes\n", size );
			return -EINVAL;
		}

		if ( flags & CF ) {
			DBG ( "INT 15,e820 terminated on CF set\n" );
			break;
		}

		/* If first region is not RAM, assume map is invalid */
		if ( ( memmap->count == 0 ) &&
		     ( e820buf.type != E820_TYPE_RAM ) ) {
		       DBG ( "INT 15,e820 failed, first entry not RAM\n" );
		       return -EINVAL;
		}

		DBG ( "INT 15,e820 region [%llx,%llx) type %d",
		      e820buf.start, ( e820buf.start + e820buf.len ),
		      ( int ) e820buf.type );
		if ( size > offsetof ( typeof ( e820buf ), attrs ) ) {
			DBG ( " (%s", ( ( e820buf.attrs & E820_ATTR_ENABLED )
					? "enabled" : "disabled" ) );
			if ( e820buf.attrs & E820_ATTR_NONVOLATILE )
				DBG ( ", non-volatile" );
			if ( e820buf.attrs & E820_ATTR_UNKNOWN )
				DBG ( ", other [%08x]", e820buf.attrs );
			DBG ( ")" );
		}
		DBG ( "\n" );

		/* Discard non-RAM regions */
		if ( e820buf.type != E820_TYPE_RAM )
			continue;

		/* Check extended attributes, if present */
		if ( size > offsetof ( typeof ( e820buf ), attrs ) ) {
			if ( ! ( e820buf.attrs & E820_ATTR_ENABLED ) )
				continue;
			if ( e820buf.attrs & E820_ATTR_NONVOLATILE )
				continue;
		}

		region->start = e820buf.start;
		region->end = e820buf.start + e820buf.len;

		/* Check for adjacent regions and merge them */
		if ( prev_region && ( region->start == prev_region->end ) ) {
			prev_region->end = region->end;
		} else {
			prev_region = region;
			region++;
			memmap->count++;
		}

		if ( memmap->count >= ( sizeof ( memmap->regions ) /
					sizeof ( memmap->regions[0] ) ) ) {
			DBG ( "INT 15,e820 too many regions returned\n" );
			/* Not a fatal error; what we've got so far at
			 * least represents valid regions of memory,
			 * even if we couldn't get them all.
			 */
			break;
		}
	} while ( next != 0 );

	/* Sanity checks.  Some BIOSes report complete garbage via INT
	 * 15,e820 (especially at POST time), despite passing the
	 * signature checks.  We currently check for a base memory
	 * region (starting at 0) and at least one high memory region
	 * (starting at 0x100000).
	 */
	if ( memmap->count < 2 ) {
		DBG ( "INT 15,e820 returned only %d regions; assuming "
		      "insane\n", memmap->count );
		return -EINVAL;
	}
	if ( memmap->regions[0].start != 0 ) {
		DBG ( "INT 15,e820 region 0 starts at %llx (expected 0); "
		      "assuming insane\n", memmap->regions[0].start );
		return -EINVAL;
	}
	if ( memmap->regions[1].start != 0x100000 ) {
		DBG ( "INT 15,e820 region 1 starts at %llx (expected 100000); "
		      "assuming insane\n", memmap->regions[0].start );
		return -EINVAL;
	}

	return 0;
}

/**
 * Get memory map
 *
 * @v memmap		Memory map to fill in
 */
void x86_get_memmap ( struct memory_map *memmap ) {
	unsigned int basemem, extmem;
	int rc;

	DBG ( "Fetching system memory map\n" );

	/* Clear memory map */
	memset ( memmap, 0, sizeof ( *memmap ) );

	/* Get base and extended memory sizes */
	basemem = basememsize();
	DBG ( "FBMS base memory size %d kB [0,%x)\n",
	      basemem, ( basemem * 1024 ) );
	extmem = extmemsize();
	
	/* Try INT 15,e820 first */
	if ( ( rc = meme820 ( memmap ) ) == 0 ) {
		DBG ( "Obtained system memory map via INT 15,e820\n" );
		return;
	}

	/* Fall back to constructing a map from basemem and extmem sizes */
	DBG ( "INT 15,e820 failed; constructing map\n" );
	memmap->regions[0].end = ( basemem * 1024 );
	memmap->regions[1].start = 0x100000;
	memmap->regions[1].end = 0x100000 + ( extmem * 1024 );
	memmap->count = 2;
}

PROVIDE_IOAPI ( x86, get_memmap, x86_get_memmap );
