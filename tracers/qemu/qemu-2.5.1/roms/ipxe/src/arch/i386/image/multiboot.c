/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * Multiboot image format
 *
 */

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <realmode.h>
#include <multiboot.h>
#include <ipxe/uaccess.h>
#include <ipxe/image.h>
#include <ipxe/segment.h>
#include <ipxe/io.h>
#include <ipxe/elf.h>
#include <ipxe/init.h>
#include <ipxe/features.h>
#include <ipxe/uri.h>
#include <ipxe/version.h>

FEATURE ( FEATURE_IMAGE, "MBOOT", DHCP_EB_FEATURE_MULTIBOOT, 1 );

/**
 * Maximum number of modules we will allow for
 *
 * If this has bitten you: sorry.  I did have a perfect scheme with a
 * dynamically allocated list of modules on the protected-mode stack,
 * but it was incompatible with some broken OSes that can only access
 * low memory at boot time (even though we kindly set up 4GB flat
 * physical addressing as per the multiboot specification.
 *
 */
#define MAX_MODULES 8

/**
 * Maximum combined length of command lines
 *
 * Again; sorry.  Some broken OSes zero out any non-base memory that
 * isn't part of the loaded module set, so we can't just use
 * virt_to_phys(cmdline) to point to the command lines, even though
 * this would comply with the Multiboot spec.
 */
#define MB_MAX_CMDLINE 512

/** Multiboot flags that we support */
#define MB_SUPPORTED_FLAGS ( MB_FLAG_PGALIGN | MB_FLAG_MEMMAP | \
			     MB_FLAG_VIDMODE | MB_FLAG_RAW )

/** Compulsory feature multiboot flags */
#define MB_COMPULSORY_FLAGS 0x0000ffff

/** Optional feature multiboot flags */
#define MB_OPTIONAL_FLAGS 0xffff0000

/**
 * Multiboot flags that we don't support
 *
 * We only care about the compulsory feature flags (bits 0-15); we are
 * allowed to ignore the optional feature flags.
 */
#define MB_UNSUPPORTED_FLAGS ( MB_COMPULSORY_FLAGS & ~MB_SUPPORTED_FLAGS )

/** A multiboot header descriptor */
struct multiboot_header_info {
	/** The actual multiboot header */
	struct multiboot_header mb;
	/** Offset of header within the multiboot image */
	size_t offset;
};

/** Multiboot module command lines */
static char __bss16_array ( mb_cmdlines, [MB_MAX_CMDLINE] );
#define mb_cmdlines __use_data16 ( mb_cmdlines )

/** Offset within module command lines */
static unsigned int mb_cmdline_offset;

/**
 * Build multiboot memory map
 *
 * @v image		Multiboot image
 * @v mbinfo		Multiboot information structure
 * @v mbmemmap		Multiboot memory map
 * @v limit		Maxmimum number of memory map entries
 */
static void multiboot_build_memmap ( struct image *image,
				     struct multiboot_info *mbinfo,
				     struct multiboot_memory_map *mbmemmap,
				     unsigned int limit ) {
	struct memory_map memmap;
	unsigned int i;

	/* Get memory map */
	get_memmap ( &memmap );

	/* Translate into multiboot format */
	memset ( mbmemmap, 0, sizeof ( *mbmemmap ) );
	for ( i = 0 ; i < memmap.count ; i++ ) {
		if ( i >= limit ) {
			DBGC ( image, "MULTIBOOT %p limit of %d memmap "
			       "entries reached\n", image, limit );
			break;
		}
		mbmemmap[i].size = ( sizeof ( mbmemmap[i] ) -
				     sizeof ( mbmemmap[i].size ) );
		mbmemmap[i].base_addr = memmap.regions[i].start;
		mbmemmap[i].length = ( memmap.regions[i].end -
				       memmap.regions[i].start );
		mbmemmap[i].type = MBMEM_RAM;
		mbinfo->mmap_length += sizeof ( mbmemmap[i] );
		if ( memmap.regions[i].start == 0 )
			mbinfo->mem_lower = ( memmap.regions[i].end / 1024 );
		if ( memmap.regions[i].start == 0x100000 )
			mbinfo->mem_upper = ( ( memmap.regions[i].end -
						0x100000 ) / 1024 );
	}
}

/**
 * Add command line in base memory
 *
 * @v image		Image
 * @ret physaddr	Physical address of command line
 */
static physaddr_t multiboot_add_cmdline ( struct image *image ) {
	char *mb_cmdline = ( mb_cmdlines + mb_cmdline_offset );
	size_t remaining = ( sizeof ( mb_cmdlines ) - mb_cmdline_offset );
	char *buf = mb_cmdline;
	size_t len;

	/* Copy image URI to base memory buffer as start of command line */
	len = ( format_uri ( image->uri, buf, remaining ) + 1 /* NUL */ );
	if ( len > remaining )
		len = remaining;
	mb_cmdline_offset += len;
	buf += len;
	remaining -= len;

	/* Copy command line to base memory buffer, if present */
	if ( image->cmdline ) {
		mb_cmdline_offset--; /* Strip NUL */
		buf--;
		remaining++;
		len = ( snprintf ( buf, remaining, " %s",
				   image->cmdline ) + 1 /* NUL */ );
		if ( len > remaining )
			len = remaining;
		mb_cmdline_offset += len;
	}

	return virt_to_phys ( mb_cmdline );
}

/**
 * Add multiboot modules
 *
 * @v image		Multiboot image
 * @v start		Start address for modules
 * @v mbinfo		Multiboot information structure
 * @v modules		Multiboot module list
 * @ret rc		Return status code
 */
static int multiboot_add_modules ( struct image *image, physaddr_t start,
				   struct multiboot_info *mbinfo,
				   struct multiboot_module *modules,
				   unsigned int limit ) {
	struct image *module_image;
	struct multiboot_module *module;
	int rc;

	/* Add each image as a multiboot module */
	for_each_image ( module_image ) {

		if ( mbinfo->mods_count >= limit ) {
			DBGC ( image, "MULTIBOOT %p limit of %d modules "
			       "reached\n", image, limit );
			break;
		}

		/* Do not include kernel image itself as a module */
		if ( module_image == image )
			continue;

		/* Page-align the module */
		start = ( ( start + 0xfff ) & ~0xfff );

		/* Prepare segment */
		if ( ( rc = prep_segment ( phys_to_user ( start ),
					   module_image->len,
					   module_image->len ) ) != 0 ) {
			DBGC ( image, "MULTIBOOT %p could not prepare module "
			       "%s: %s\n", image, module_image->name,
			       strerror ( rc ) );
			return rc;
		}

		/* Copy module */
		memcpy_user ( phys_to_user ( start ), 0,
			      module_image->data, 0, module_image->len );

		/* Add module to list */
		module = &modules[mbinfo->mods_count++];
		module->mod_start = start;
		module->mod_end = ( start + module_image->len );
		module->string = multiboot_add_cmdline ( module_image );
		module->reserved = 0;
		DBGC ( image, "MULTIBOOT %p module %s is [%x,%x)\n",
		       image, module_image->name, module->mod_start,
		       module->mod_end );
		start += module_image->len;
	}

	return 0;
}

/**
 * The multiboot information structure
 *
 * Kept in base memory because some OSes won't find it elsewhere,
 * along with the other structures belonging to the Multiboot
 * information table.
 */
static struct multiboot_info __bss16 ( mbinfo );
#define mbinfo __use_data16 ( mbinfo )

/** The multiboot bootloader name */
static char __bss16_array ( mb_bootloader_name, [32] );
#define mb_bootloader_name __use_data16 ( mb_bootloader_name )

/** The multiboot memory map */
static struct multiboot_memory_map
	__bss16_array ( mbmemmap, [MAX_MEMORY_REGIONS] );
#define mbmemmap __use_data16 ( mbmemmap )

/** The multiboot module list */
static struct multiboot_module __bss16_array ( mbmodules, [MAX_MODULES] );
#define mbmodules __use_data16 ( mbmodules )

/**
 * Find multiboot header
 *
 * @v image		Multiboot file
 * @v hdr		Multiboot header descriptor to fill in
 * @ret rc		Return status code
 */
static int multiboot_find_header ( struct image *image,
				   struct multiboot_header_info *hdr ) {
	uint32_t buf[64];
	size_t offset;
	unsigned int buf_idx;
	uint32_t checksum;

	/* Scan through first 8kB of image file 256 bytes at a time.
	 * (Use the buffering to avoid the overhead of a
	 * copy_from_user() for every dword.)
	 */
	for ( offset = 0 ; offset < 8192 ; offset += sizeof ( buf[0] ) ) {
		/* Check for end of image */
		if ( offset > image->len )
			break;
		/* Refill buffer if applicable */
		buf_idx = ( ( offset % sizeof ( buf ) ) / sizeof ( buf[0] ) );
		if ( buf_idx == 0 ) {
			copy_from_user ( buf, image->data, offset,
					 sizeof ( buf ) );
		}
		/* Check signature */
		if ( buf[buf_idx] != MULTIBOOT_HEADER_MAGIC )
			continue;
		/* Copy header and verify checksum */
		copy_from_user ( &hdr->mb, image->data, offset,
				 sizeof ( hdr->mb ) );
		checksum = ( hdr->mb.magic + hdr->mb.flags +
			     hdr->mb.checksum );
		if ( checksum != 0 )
			continue;
		/* Record offset of multiboot header and return */
		hdr->offset = offset;
		return 0;
	}

	/* No multiboot header found */
	return -ENOEXEC;
}

/**
 * Load raw multiboot image into memory
 *
 * @v image		Multiboot file
 * @v hdr		Multiboot header descriptor
 * @ret entry		Entry point
 * @ret max		Maximum used address
 * @ret rc		Return status code
 */
static int multiboot_load_raw ( struct image *image,
				struct multiboot_header_info *hdr,
				physaddr_t *entry, physaddr_t *max ) {
	size_t offset;
	size_t filesz;
	size_t memsz;
	userptr_t buffer;
	int rc;

	/* Sanity check */
	if ( ! ( hdr->mb.flags & MB_FLAG_RAW ) ) {
		DBGC ( image, "MULTIBOOT %p is not flagged as a raw image\n",
		       image );
		return -EINVAL;
	}

	/* Verify and prepare segment */
	offset = ( hdr->offset - hdr->mb.header_addr + hdr->mb.load_addr );
	filesz = ( hdr->mb.load_end_addr ?
		   ( hdr->mb.load_end_addr - hdr->mb.load_addr ) :
		   ( image->len - offset ) );
	memsz = ( hdr->mb.bss_end_addr ?
		  ( hdr->mb.bss_end_addr - hdr->mb.load_addr ) : filesz );
	buffer = phys_to_user ( hdr->mb.load_addr );
	if ( ( rc = prep_segment ( buffer, filesz, memsz ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT %p could not prepare segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	/* Copy image to segment */
	memcpy_user ( buffer, 0, image->data, offset, filesz );

	/* Record execution entry point and maximum used address */
	*entry = hdr->mb.entry_addr;
	*max = ( hdr->mb.load_addr + memsz );

	return 0;
}

/**
 * Load ELF multiboot image into memory
 *
 * @v image		Multiboot file
 * @ret entry		Entry point
 * @ret max		Maximum used address
 * @ret rc		Return status code
 */
static int multiboot_load_elf ( struct image *image, physaddr_t *entry,
				physaddr_t *max ) {
	int rc;

	/* Load ELF image*/
	if ( ( rc = elf_load ( image, entry, max ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT %p ELF image failed to load: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Execute multiboot image
 *
 * @v image		Multiboot image
 * @ret rc		Return status code
 */
static int multiboot_exec ( struct image *image ) {
	struct multiboot_header_info hdr;
	physaddr_t entry;
	physaddr_t max;
	int rc;

	/* Locate multiboot header, if present */
	if ( ( rc = multiboot_find_header ( image, &hdr ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT %p has no multiboot header\n",
		       image );
		return rc;
	}

	/* Abort if we detect flags that we cannot support */
	if ( hdr.mb.flags & MB_UNSUPPORTED_FLAGS ) {
		DBGC ( image, "MULTIBOOT %p flags %08x not supported\n",
		       image, ( hdr.mb.flags & MB_UNSUPPORTED_FLAGS ) );
		return -ENOTSUP;
	}

	/* There is technically a bit MB_FLAG_RAW to indicate whether
	 * this is an ELF or a raw image.  In practice, grub will use
	 * the ELF header if present, and Solaris relies on this
	 * behaviour.
	 */
	if ( ( ( rc = multiboot_load_elf ( image, &entry, &max ) ) != 0 ) &&
	     ( ( rc = multiboot_load_raw ( image, &hdr, &entry, &max ) ) != 0 ))
		return rc;

	/* Populate multiboot information structure */
	memset ( &mbinfo, 0, sizeof ( mbinfo ) );
	mbinfo.flags = ( MBI_FLAG_LOADER | MBI_FLAG_MEM | MBI_FLAG_MMAP |
			 MBI_FLAG_CMDLINE | MBI_FLAG_MODS );
	mb_cmdline_offset = 0;
	mbinfo.cmdline = multiboot_add_cmdline ( image );
	mbinfo.mods_addr = virt_to_phys ( mbmodules );
	mbinfo.mmap_addr = virt_to_phys ( mbmemmap );
	snprintf ( mb_bootloader_name, sizeof ( mb_bootloader_name ),
		   "iPXE %s", product_version );
	mbinfo.boot_loader_name = virt_to_phys ( mb_bootloader_name );
	if ( ( rc = multiboot_add_modules ( image, max, &mbinfo, mbmodules,
					    ( sizeof ( mbmodules ) /
					      sizeof ( mbmodules[0] ) ) ) ) !=0)
		return rc;

	/* Multiboot images may not return and have no callback
	 * interface, so shut everything down prior to booting the OS.
	 */
	shutdown_boot();

	/* Build memory map after unhiding bootloader memory regions as part of
	 * shutting everything down.
	 */
	multiboot_build_memmap ( image, &mbinfo, mbmemmap,
				 ( sizeof(mbmemmap) / sizeof(mbmemmap[0]) ) );

	/* Jump to OS with flat physical addressing */
	DBGC ( image, "MULTIBOOT %p starting execution at %lx\n",
	       image, entry );
	__asm__ __volatile__ ( PHYS_CODE ( "pushl %%ebp\n\t"
					   "call *%%edi\n\t"
					   "popl %%ebp\n\t" )
			       : : "a" ( MULTIBOOT_BOOTLOADER_MAGIC ),
			           "b" ( virt_to_phys ( &mbinfo ) ),
			           "D" ( entry )
			       : "ecx", "edx", "esi", "memory" );

	DBGC ( image, "MULTIBOOT %p returned\n", image );

	/* It isn't safe to continue after calling shutdown() */
	while ( 1 ) {}

	return -ECANCELED;  /* -EIMPOSSIBLE, anyone? */
}

/**
 * Probe multiboot image
 *
 * @v image		Multiboot file
 * @ret rc		Return status code
 */
static int multiboot_probe ( struct image *image ) {
	struct multiboot_header_info hdr;
	int rc;

	/* Locate multiboot header, if present */
	if ( ( rc = multiboot_find_header ( image, &hdr ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT %p has no multiboot header\n",
		       image );
		return rc;
	}
	DBGC ( image, "MULTIBOOT %p found header with flags %08x\n",
	       image, hdr.mb.flags );

	return 0;
}

/** Multiboot image type */
struct image_type multiboot_image_type __image_type ( PROBE_MULTIBOOT ) = {
	.name = "Multiboot",
	.probe = multiboot_probe,
	.exec = multiboot_exec,
};
