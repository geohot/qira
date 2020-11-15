/*
 * Copyright (C) 2008 Daniel Verkamp <daniel@drv.nu>.
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
 */

/**
 * @file
 *
 * SYSLINUX COM32 image format
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <realmode.h>
#include <basemem.h>
#include <comboot.h>
#include <ipxe/uaccess.h>
#include <ipxe/image.h>
#include <ipxe/segment.h>
#include <ipxe/init.h>
#include <ipxe/io.h>

/**
 * Execute COMBOOT image
 *
 * @v image		COM32 image
 * @ret rc		Return status code
 */
static int com32_exec_loop ( struct image *image ) {
	struct memory_map memmap;
	unsigned int i;
	int state;
	uint32_t avail_mem_top;

	state = rmsetjmp ( comboot_return );

	switch ( state ) {
	case 0: /* First time through; invoke COM32 program */

		/* Get memory map */
		get_memmap ( &memmap );

		/* Find end of block covering COM32 image loading area */
		for ( i = 0, avail_mem_top = 0 ; i < memmap.count ; i++ ) {
			if ( (memmap.regions[i].start <= COM32_START_PHYS) &&
			     (memmap.regions[i].end > COM32_START_PHYS + image->len) ) {
				avail_mem_top = memmap.regions[i].end;
				break;
			}
		}

		DBGC ( image, "COM32 %p: available memory top = 0x%x\n",
		       image, avail_mem_top );

		assert ( avail_mem_top != 0 );

		com32_external_esp = phys_to_virt ( avail_mem_top );

		/* Hook COMBOOT API interrupts */
		hook_comboot_interrupts();

		/* Unregister image, so that a "boot" command doesn't
		 * throw us into an execution loop.  We never
		 * reregister ourselves; COMBOOT images expect to be
		 * removed on exit.
		 */
		unregister_image ( image );

		__asm__ __volatile__ (
			"movl %%esp, (com32_internal_esp)\n\t" /* Save internal virtual address space ESP */
			"movl (com32_external_esp), %%esp\n\t" /* Switch to COM32 ESP (top of available memory) */
			"call _virt_to_phys\n\t"               /* Switch to flat physical address space */
			"sti\n\t"			       /* Enable interrupts */
			"pushl %0\n\t"                         /* Pointer to CDECL helper function */
			"pushl %1\n\t"                         /* Pointer to FAR call helper function */
			"pushl %2\n\t"                         /* Size of low memory bounce buffer */
			"pushl %3\n\t"                         /* Pointer to low memory bounce buffer */
			"pushl %4\n\t"                         /* Pointer to INT call helper function */
			"pushl %5\n\t"                         /* Pointer to the command line arguments */
			"pushl $6\n\t"                         /* Number of additional arguments */
			"call *%6\n\t"                         /* Execute image */
			"cli\n\t"			       /* Disable interrupts */
			"call _phys_to_virt\n\t"               /* Switch back to internal virtual address space */
			"movl (com32_internal_esp), %%esp\n\t" /* Switch back to internal stack */
		:
		:
			/* %0 */ "r" ( virt_to_phys ( com32_cfarcall_wrapper ) ),
			/* %1 */ "r" ( virt_to_phys ( com32_farcall_wrapper ) ),
			/* %2 */ "r" ( get_fbms() * 1024 - (COM32_BOUNCE_SEG << 4) ),
			/* %3 */ "i" ( COM32_BOUNCE_SEG << 4 ),
			/* %4 */ "r" ( virt_to_phys ( com32_intcall_wrapper ) ),
			/* %5 */ "r" ( virt_to_phys ( image->cmdline ?
						      image->cmdline : "" ) ),
			/* %6 */ "r" ( COM32_START_PHYS )
		:
			"memory" );
		DBGC ( image, "COM32 %p: returned\n", image );
		break;

	case COMBOOT_EXIT:
		DBGC ( image, "COM32 %p: exited\n", image );
		break;

	case COMBOOT_EXIT_RUN_KERNEL:
		assert ( image->replacement );
		DBGC ( image, "COM32 %p: exited to run kernel %s\n",
		       image, image->replacement->name );
		break;

	case COMBOOT_EXIT_COMMAND:
		DBGC ( image, "COM32 %p: exited after executing command\n",
		       image );
		break;

	default:
		assert ( 0 );
		break;
	}

	unhook_comboot_interrupts();
	comboot_force_text_mode();

	return 0;
}

/**
 * Check image name extension
 * 
 * @v image		COM32 image
 * @ret rc		Return status code
 */
static int com32_identify ( struct image *image ) {
	const char *ext;
	static const uint8_t magic[] = { 0xB8, 0xFF, 0x4C, 0xCD, 0x21 };
	uint8_t buf[5];
	
	if ( image->len >= 5 ) {
		/* Check for magic number
		 * mov eax,21cd4cffh
		 * B8 FF 4C CD 21
		 */
		copy_from_user ( buf, image->data, 0, sizeof(buf) );
		if ( ! memcmp ( buf, magic, sizeof(buf) ) ) {
			DBGC ( image, "COM32 %p: found magic number\n",
			       image );
			return 0;
		}
	}

	/* Magic number not found; check filename extension */

	ext = strrchr( image->name, '.' );

	if ( ! ext ) {
		DBGC ( image, "COM32 %p: no extension\n",
		       image );
		return -ENOEXEC;
	}

	++ext;

	if ( strcasecmp( ext, "c32" ) ) {
		DBGC ( image, "COM32 %p: unrecognized extension %s\n",
		       image, ext );
		return -ENOEXEC;
	}

	return 0;
}


/**
 * Load COM32 image into memory
 * @v image		COM32 image
 * @ret rc		Return status code
 */
static int com32_load_image ( struct image *image ) {
	size_t filesz, memsz;
	userptr_t buffer;
	int rc;

	filesz = image->len;
	memsz = filesz;
	buffer = phys_to_user ( COM32_START_PHYS );
	if ( ( rc = prep_segment ( buffer, filesz, memsz ) ) != 0 ) {
		DBGC ( image, "COM32 %p: could not prepare segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	/* Copy image to segment */
	memcpy_user ( buffer, 0, image->data, 0, filesz );

	return 0;
}

/**
 * Prepare COM32 low memory bounce buffer
 * @v image		COM32 image
 * @ret rc		Return status code
 */
static int com32_prepare_bounce_buffer ( struct image * image ) {
	unsigned int seg;
	userptr_t seg_userptr;
	size_t filesz, memsz;
	int rc;

	seg = COM32_BOUNCE_SEG;
	seg_userptr = real_to_user ( seg, 0 );

	/* Ensure the entire 64k segment is free */
	memsz = 0xFFFF;
	filesz = 0;

	/* Prepare, verify, and load the real-mode segment */
	if ( ( rc = prep_segment ( seg_userptr, filesz, memsz ) ) != 0 ) {
		DBGC ( image, "COM32 %p: could not prepare bounce buffer segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Probe COM32 image
 *
 * @v image		COM32 image
 * @ret rc		Return status code
 */
static int com32_probe ( struct image *image ) {
	int rc;

	DBGC ( image, "COM32 %p: name '%s'\n", image, image->name );

	/* Check if this is a COMBOOT image */
	if ( ( rc = com32_identify ( image ) ) != 0 ) {
		return rc;
	}

	return 0;
}

/**
 * Execute COMBOOT image
 *
 * @v image		COM32 image
 * @ret rc		Return status code
 */
static int com32_exec ( struct image *image ) {
	int rc;

	/* Load image */
	if ( ( rc = com32_load_image ( image ) ) != 0 ) {
		return rc;
	}

	/* Prepare bounce buffer segment */
	if ( ( rc = com32_prepare_bounce_buffer ( image ) ) != 0 ) {
		return rc;
	}

	return com32_exec_loop ( image );
}

/** SYSLINUX COM32 image type */
struct image_type com32_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "COM32",
	.probe = com32_probe,
	.exec = com32_exec,
};
