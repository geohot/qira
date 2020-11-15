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
 * @file SYSLINUX COMBOOT API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <errno.h>
#include <realmode.h>
#include <biosint.h>
#include <ipxe/console.h>
#include <stdlib.h>
#include <comboot.h>
#include <bzimage.h>
#include <pxe_call.h>
#include <setjmp.h>
#include <string.h>
#include <ipxe/posix_io.h>
#include <ipxe/process.h>
#include <ipxe/serial.h>
#include <ipxe/init.h>
#include <ipxe/image.h>
#include <ipxe/version.h>
#include <usr/imgmgmt.h>

/** The "SYSLINUX" version string */
static char __bss16_array ( syslinux_version, [32] );
#define syslinux_version __use_data16 ( syslinux_version )

/** The "SYSLINUX" copyright string */
static char __data16_array ( syslinux_copyright, [] ) = " http://ipxe.org";
#define syslinux_copyright __use_data16 ( syslinux_copyright )

static char __data16_array ( syslinux_configuration_file, [] ) = "";
#define syslinux_configuration_file __use_data16 ( syslinux_configuration_file )

/** Feature flags */
static uint8_t __data16 ( comboot_feature_flags ) = COMBOOT_FEATURE_IDLE_LOOP;
#define comboot_feature_flags __use_data16 ( comboot_feature_flags )

typedef union {
	syslinux_pm_regs pm; syslinux_rm_regs rm;
} syslinux_regs;

/** Initial register values for INT 22h AX=1Ah and 1Bh */
static syslinux_regs __text16 ( comboot_initial_regs );
#define comboot_initial_regs __use_text16 ( comboot_initial_regs )

static struct segoff __text16 ( int20_vector );
#define int20_vector __use_text16 ( int20_vector )

static struct segoff __text16 ( int21_vector );
#define int21_vector __use_text16 ( int21_vector )

static struct segoff __text16 ( int22_vector );
#define int22_vector __use_text16 ( int22_vector )

extern void int20_wrapper ( void );
extern void int21_wrapper ( void );
extern void int22_wrapper ( void );

/* setjmp/longjmp context buffer used to return after loading an image */
rmjmp_buf comboot_return;

/* Mode flags set by INT 22h AX=0017h */
static uint16_t comboot_graphics_mode = 0;

/**
 * Print a string with a particular terminator
 */
static void print_user_string ( unsigned int segment, unsigned int offset, char terminator ) {
	int i = 0;
	char c;
	userptr_t str = real_to_user ( segment, offset );
	for ( ; ; ) {
		copy_from_user ( &c, str, i, 1 );
		if ( c == terminator ) break;
		putchar ( c );
		i++;
	}
}


/**
 * Perform a series of memory copies from a list in low memory
 */
static void shuffle ( unsigned int list_segment, unsigned int list_offset, unsigned int count )
{
	comboot_shuffle_descriptor shuf[COMBOOT_MAX_SHUFFLE_DESCRIPTORS];
	unsigned int i;

	/* Copy shuffle descriptor list so it doesn't get overwritten */
	copy_from_user ( shuf, real_to_user ( list_segment, list_offset ), 0,
	                 count * sizeof( comboot_shuffle_descriptor ) );

	/* Do the copies */
	for ( i = 0; i < count; i++ ) {
		userptr_t src_u = phys_to_user ( shuf[ i ].src );
		userptr_t dest_u = phys_to_user ( shuf[ i ].dest );

		if ( shuf[ i ].src == 0xFFFFFFFF ) {
			/* Fill with 0 instead of copying */
			memset_user ( dest_u, 0, 0, shuf[ i ].len );
		} else if ( shuf[ i ].dest == 0xFFFFFFFF ) {
			/* Copy new list of descriptors */
			count = shuf[ i ].len / sizeof( comboot_shuffle_descriptor );
			assert ( count <= COMBOOT_MAX_SHUFFLE_DESCRIPTORS );
			copy_from_user ( shuf, src_u, 0, shuf[ i ].len );
			i = -1;
		} else {
			/* Regular copy */
			memmove_user ( dest_u, 0, src_u, 0, shuf[ i ].len );
		}
	}
}


/**
 * Set default text mode
 */
void comboot_force_text_mode ( void ) {
	if ( comboot_graphics_mode & COMBOOT_VIDEO_VESA ) {
		/* Set VGA mode 3 via VESA VBE mode set */
		__asm__ __volatile__ (
			REAL_CODE (
				"mov $0x4F02, %%ax\n\t"
				"mov $0x03, %%bx\n\t"
				"int $0x10\n\t"
			)
		: : );
	} else if ( comboot_graphics_mode & COMBOOT_VIDEO_GRAPHICS ) {
		/* Set VGA mode 3 via standard VGA mode set */
		__asm__ __volatile__ (
			REAL_CODE (
				"mov $0x03, %%ax\n\t"
				"int $0x10\n\t"
			)
		: : );
	}

	comboot_graphics_mode = 0;
}


/**
 * Fetch kernel and optional initrd
 */
static int comboot_fetch_kernel ( char *kernel_file, char *cmdline ) {
	struct image *kernel;
	struct image *initrd;
	char *initrd_file;
	int rc;

	/* Find initrd= parameter, if any */
	if ( ( initrd_file = strstr ( cmdline, "initrd=" ) ) != NULL ) {
		char *initrd_end;

		/* skip "initrd=" */
		initrd_file += 7;

		/* Find terminating space, if any, and replace with NUL */
		initrd_end = strchr ( initrd_file, ' ' );
		if ( initrd_end )
			*initrd_end = '\0';

		DBG ( "COMBOOT: fetching initrd '%s'\n", initrd_file );

		/* Fetch initrd */
		if ( ( rc = imgdownload_string ( initrd_file, 0,
						 &initrd ) ) != 0 ) {
			DBG ( "COMBOOT: could not fetch initrd: %s\n",
			      strerror ( rc ) );
			return rc;
		}

		/* Restore space after initrd name, if applicable */
		if ( initrd_end )
			*initrd_end = ' ';
	}

	DBG ( "COMBOOT: fetching kernel '%s'\n", kernel_file );

	/* Fetch kernel */
	if ( ( rc = imgdownload_string ( kernel_file, 0, &kernel ) ) != 0 ) {
		DBG ( "COMBOOT: could not fetch kernel: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	/* Replace comboot image with kernel */
	if ( ( rc = image_replace ( kernel ) ) != 0 ) {
		DBG ( "COMBOOT: could not replace with kernel: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	return 0;
}


/**
 * Terminate program interrupt handler
 */
static __asmcall void int20 ( struct i386_all_regs *ix86 __unused ) {
	rmlongjmp ( comboot_return, COMBOOT_EXIT );
}


/**
 * DOS-compatible API
 */
static __asmcall void int21 ( struct i386_all_regs *ix86 ) {
	ix86->flags |= CF;

	switch ( ix86->regs.ah ) {
	case 0x00:
	case 0x4C: /* Terminate program */
		rmlongjmp ( comboot_return, COMBOOT_EXIT );
		break;

	case 0x01: /* Get Key with Echo */
	case 0x08: /* Get Key without Echo */
		/* TODO: handle extended characters? */
		ix86->regs.al = getchar( );

		/* Enter */
		if ( ix86->regs.al == 0x0A )
			ix86->regs.al = 0x0D;

		if ( ix86->regs.ah == 0x01 )
			putchar ( ix86->regs.al );

		ix86->flags &= ~CF;
		break;

	case 0x02: /* Write Character */
		putchar ( ix86->regs.dl );
		ix86->flags &= ~CF;
		break;

	case 0x04: /* Write Character to Serial Port */
		if ( serial_console.base ) {
			uart_transmit ( &serial_console, ix86->regs.dl );
			ix86->flags &= ~CF;
		}
		break;

	case 0x09: /* Write DOS String to Console */
		print_user_string ( ix86->segs.ds, ix86->regs.dx, '$' );
		ix86->flags &= ~CF;
		break;

	case 0x0B: /* Check Keyboard */
		if ( iskey() )
			ix86->regs.al = 0xFF;
		else
			ix86->regs.al = 0x00;

		ix86->flags &= ~CF;
		break;

	case 0x30: /* Check DOS Version */
		/* Bottom halves all 0; top halves spell "SYSLINUX" */
		ix86->regs.eax = 0x59530000;
		ix86->regs.ebx = 0x4C530000;
		ix86->regs.ecx = 0x4E490000;
		ix86->regs.edx = 0x58550000;
		ix86->flags &= ~CF;
		break;

	default:
		DBG ( "COMBOOT unknown int21 function %02x\n", ix86->regs.ah );
		break;
	}
}


/**
 * Dispatch PXE API call weakly
 *
 * @v ix86		Registers for PXE call
 * @ret present		Zero if the PXE stack is present, nonzero if not
 *
 * A successful return only indicates that the PXE stack was available
 * for dispatching the call; it says nothing about the success of
 * whatever the call asked for.
 */
__weak int pxe_api_call_weak ( struct i386_all_regs *ix86 __unused ) {
	return -1;
}

/**
 * SYSLINUX API
 */
static __asmcall void int22 ( struct i386_all_regs *ix86 ) {
	ix86->flags |= CF;

	switch ( ix86->regs.ax ) {
	case 0x0001: /* Get Version */

		/* Number of INT 22h API functions available */
		ix86->regs.ax = 0x001D;

		/* SYSLINUX version number */
		ix86->regs.ch = 0; /* major */
		ix86->regs.cl = 0; /* minor */

		/* SYSLINUX derivative ID */
		ix86->regs.dl = BZI_LOADER_TYPE_IPXE;

		/* SYSLINUX version */
		snprintf ( syslinux_version, sizeof ( syslinux_version ),
			   "\r\niPXE %s", product_version );

		/* SYSLINUX version and copyright strings */
		ix86->segs.es = rm_ds;
		ix86->regs.si = ( ( unsigned ) __from_data16 ( syslinux_version ) );
		ix86->regs.di = ( ( unsigned ) __from_data16 ( syslinux_copyright ) );

		ix86->flags &= ~CF;
		break;

	case 0x0002: /* Write String */
		print_user_string ( ix86->segs.es, ix86->regs.bx, '\0' );
		ix86->flags &= ~CF;
		break;

	case 0x0003: /* Run command */
		{
			userptr_t cmd_u = real_to_user ( ix86->segs.es, ix86->regs.bx );
			int len = strlen_user ( cmd_u, 0 );
			char cmd[len + 1];
			copy_from_user ( cmd, cmd_u, 0, len + 1 );
			DBG ( "COMBOOT: executing command '%s'\n", cmd );
			system ( cmd );
			DBG ( "COMBOOT: exiting after executing command...\n" );
			rmlongjmp ( comboot_return, COMBOOT_EXIT_COMMAND );
		}
		break;

	case 0x0004: /* Run default command */
		/* FIXME: just exit for now */
		rmlongjmp ( comboot_return, COMBOOT_EXIT_COMMAND );
		break;

	case 0x0005: /* Force text mode */
		comboot_force_text_mode ( );
		ix86->flags &= ~CF;
		break;

	case 0x0006: /* Open file */
		{
			int fd;
			userptr_t file_u = real_to_user ( ix86->segs.es, ix86->regs.si );
			int len = strlen_user ( file_u, 0 );
			char file[len + 1];

			copy_from_user ( file, file_u, 0, len + 1 );

			if ( file[0] == '\0' ) {
				DBG ( "COMBOOT: attempted open with empty file name\n" );
				break;
			}

			DBG ( "COMBOOT: opening file '%s'\n", file );

			fd = open ( file );

			if ( fd < 0 ) {
				DBG ( "COMBOOT: error opening file %s\n", file );
				break;
			}

			/* This relies on the fact that a iPXE POSIX fd will
			 * always fit in 16 bits.
			 */
#if (POSIX_FD_MAX > 65535)
#error POSIX_FD_MAX too large
#endif
			ix86->regs.si = (uint16_t) fd;

			ix86->regs.cx = COMBOOT_FILE_BLOCKSZ;
			ix86->regs.eax = fsize ( fd );
			ix86->flags &= ~CF;
		}
		break;

	case 0x0007: /* Read file */
		{
			int fd = ix86->regs.si;
			int len = ix86->regs.cx * COMBOOT_FILE_BLOCKSZ;
			int rc;
			fd_set fds;
			userptr_t buf = real_to_user ( ix86->segs.es, ix86->regs.bx );

			/* Wait for data ready to read */
			FD_ZERO ( &fds );
			FD_SET ( fd, &fds );

			select ( &fds, 1 );

			rc = read_user ( fd, buf, 0, len );
			if ( rc < 0 ) {
				DBG ( "COMBOOT: read failed\n" );
				ix86->regs.si = 0;
				break;
			}

			ix86->regs.ecx = rc;
			ix86->flags &= ~CF;
		}
		break;

	case 0x0008: /* Close file */
		{
			int fd = ix86->regs.si;
			close ( fd );
			ix86->flags &= ~CF;
		}
		break;

	case 0x0009: /* Call PXE Stack */
		if ( pxe_api_call_weak ( ix86 ) != 0 )
			ix86->flags |= CF;
		else
			ix86->flags &= ~CF;
		break;

	case 0x000A: /* Get Derivative-Specific Information */

		/* iPXE has its own derivative ID, so there is no defined
		 * output here; just return AL for now */
		ix86->regs.al = BZI_LOADER_TYPE_IPXE;
		ix86->flags &= ~CF;
		break;

	case 0x000B: /* Get Serial Console Configuration */
		if ( serial_console.base ) {
			ix86->regs.dx = ( ( intptr_t ) serial_console.base );
			ix86->regs.cx = serial_console.divisor;
			ix86->regs.bx = 0;
			ix86->flags &= ~CF;
		}
		break;

	case 0x000C: /* Perform final cleanup */
		shutdown_boot();
		break;

	case 0x000E: /* Get configuration file name */
		/* FIXME: stub */
		ix86->segs.es = rm_ds;
		ix86->regs.bx = ( ( unsigned ) __from_data16 ( syslinux_configuration_file ) );
		ix86->flags &= ~CF;
		break;

	case 0x000F: /* Get IPAPPEND strings */
		/* FIXME: stub */
		ix86->regs.cx = 0;
		ix86->segs.es = 0;
		ix86->regs.bx = 0;
		ix86->flags &= ~CF;
		break;

	case 0x0010: /* Resolve hostname */
		{
			userptr_t hostname_u = real_to_user ( ix86->segs.es, ix86->regs.bx );
			int len = strlen_user ( hostname_u, 0 );
			char hostname[len];
			struct in_addr addr;

			copy_from_user ( hostname, hostname_u, 0, len + 1 );
			
			/* TODO:
			 * "If the hostname does not contain a dot (.), the
			 * local domain name is automatically appended."
			 */

			comboot_resolv ( hostname, &addr );

			ix86->regs.eax = addr.s_addr;
			ix86->flags &= ~CF;
		}
		break;

	case 0x0011: /* Maximum number of shuffle descriptors */
		ix86->regs.cx = COMBOOT_MAX_SHUFFLE_DESCRIPTORS;
		ix86->flags &= ~CF;
		break;

	case 0x0012: /* Cleanup, shuffle and boot */
		if ( ix86->regs.cx > COMBOOT_MAX_SHUFFLE_DESCRIPTORS )
			break;

		/* Perform final cleanup */
		shutdown_boot();

		/* Perform sequence of copies */
		shuffle ( ix86->segs.es, ix86->regs.di, ix86->regs.cx );

		/* Jump to real-mode entry point */
		__asm__ __volatile__ (
			REAL_CODE ( 
				"pushw %0\n\t"
				"popw %%ds\n\t"
				"pushl %1\n\t"
				"lret\n\t"
			)
			:
			: "r" ( ix86->segs.ds ),
			  "r" ( ix86->regs.ebp ),
			  "d" ( ix86->regs.ebx ),
			  "S" ( ix86->regs.esi ) );

		assert ( 0 ); /* Execution should never reach this point */

		break;

	case 0x0013: /* Idle loop call */
		step ( );
		ix86->flags &= ~CF;
		break;

	case 0x0015: /* Get feature flags */
		ix86->segs.es = rm_ds;
		ix86->regs.bx = ( ( unsigned ) __from_data16 ( &comboot_feature_flags ) );
		ix86->regs.cx = 1; /* Number of feature flag bytes */
		ix86->flags &= ~CF;
		break;

	case 0x0016: /* Run kernel image */
		{
			userptr_t file_u = real_to_user ( ix86->segs.ds, ix86->regs.si );
			userptr_t cmd_u = real_to_user ( ix86->segs.es, ix86->regs.bx );
			int file_len = strlen_user ( file_u, 0 );
			int cmd_len = strlen_user ( cmd_u, 0 );
			char file[file_len + 1];
			char cmd[cmd_len + 1];

			copy_from_user ( file, file_u, 0, file_len + 1 );
			copy_from_user ( cmd, cmd_u, 0, cmd_len + 1 );

			DBG ( "COMBOOT: run kernel %s %s\n", file, cmd );
			comboot_fetch_kernel ( file, cmd );
			/* Technically, we should return if we
			 * couldn't load the kernel, but it's not safe
			 * to do that since we have just overwritten
			 * part of the COMBOOT program's memory space.
			 */
			DBG ( "COMBOOT: exiting to run kernel...\n" );
			rmlongjmp ( comboot_return, COMBOOT_EXIT_RUN_KERNEL );
		}
		break;

	case 0x0017: /* Report video mode change */
		comboot_graphics_mode = ix86->regs.bx;
		ix86->flags &= ~CF;
		break;

	case 0x0018: /* Query custom font */
		/* FIXME: stub */
		ix86->regs.al = 0;
		ix86->segs.es = 0;
		ix86->regs.bx = 0;
		ix86->flags &= ~CF;
		break;

	case 0x001B: /* Cleanup, shuffle and boot to real mode */
		if ( ix86->regs.cx > COMBOOT_MAX_SHUFFLE_DESCRIPTORS )
			break;

		/* Perform final cleanup */
		shutdown_boot();

		/* Perform sequence of copies */
		shuffle ( ix86->segs.es, ix86->regs.di, ix86->regs.cx );

		/* Copy initial register values to .text16 */
		memcpy_user ( real_to_user ( rm_cs, (unsigned) __from_text16 ( &comboot_initial_regs ) ), 0,
		              real_to_user ( ix86->segs.ds, ix86->regs.si ), 0,
		              sizeof(syslinux_rm_regs) );

		/* Load initial register values */
		__asm__ __volatile__ (
			REAL_CODE (
				/* Point SS:SP at the register value structure */
				"pushw %%cs\n\t"
				"popw %%ss\n\t"
				"movw $comboot_initial_regs, %%sp\n\t"

				/* Segment registers */
				"popw %%es\n\t"
				"popw %%ax\n\t" /* Skip CS */
				"popw %%ds\n\t"
				"popw %%ax\n\t" /* Skip SS for now */
				"popw %%fs\n\t"
				"popw %%gs\n\t"

				/* GP registers */
				"popl %%eax\n\t"
				"popl %%ecx\n\t"
				"popl %%edx\n\t"
				"popl %%ebx\n\t"
				"popl %%ebp\n\t" /* Skip ESP for now */
				"popl %%ebp\n\t"
				"popl %%esi\n\t"
				"popl %%edi\n\t"

				/* Load correct SS:ESP */
				"movw $(comboot_initial_regs + 6), %%sp\n\t"
				"popw %%ss\n\t"
				"movl %%cs:(comboot_initial_regs + 28), %%esp\n\t"

				"ljmp *%%cs:(comboot_initial_regs + 44)\n\t"
			)
			: : );

		break;

	case 0x001C: /* Get pointer to auxilliary data vector */
		/* FIXME: stub */
		ix86->regs.cx = 0; /* Size of the ADV */
		ix86->flags &= ~CF;
		break;

	case 0x001D: /* Write auxilliary data vector */
		/* FIXME: stub */
		ix86->flags &= ~CF;
		break;

	default:
		DBG ( "COMBOOT unknown int22 function %04x\n", ix86->regs.ax );
		break;
	}
}

/**
 * Hook BIOS interrupts related to COMBOOT API (INT 20h, 21h, 22h)
 */
void hook_comboot_interrupts ( ) {

	__asm__ __volatile__ (
		TEXT16_CODE ( "\nint20_wrapper:\n\t"
		              "pushl %0\n\t"
		              "pushw %%cs\n\t"
		              "call prot_call\n\t"
		              "addw $4, %%sp\n\t"
			      "call patch_cf\n\t"
		              "iret\n\t" )
		          : : "i" ( int20 ) );

	hook_bios_interrupt ( 0x20, ( unsigned int ) int20_wrapper,
		                      &int20_vector );

	__asm__ __volatile__ (
		TEXT16_CODE ( "\nint21_wrapper:\n\t"
		              "pushl %0\n\t"
		              "pushw %%cs\n\t"
		              "call prot_call\n\t"
		              "addw $4, %%sp\n\t"
			      "call patch_cf\n\t"
		              "iret\n\t" )
		          : : "i" ( int21 ) );

	hook_bios_interrupt ( 0x21, ( unsigned int ) int21_wrapper,
	                      &int21_vector );

	__asm__  __volatile__ (
		TEXT16_CODE ( "\nint22_wrapper:\n\t"
		              "pushl %0\n\t"
		              "pushw %%cs\n\t"
		              "call prot_call\n\t"
		              "addw $4, %%sp\n\t"
			      "call patch_cf\n\t"
		              "iret\n\t" )
		          : : "i" ( int22) );

	hook_bios_interrupt ( 0x22, ( unsigned int ) int22_wrapper,
	                      &int22_vector );
}

/**
 * Unhook BIOS interrupts related to COMBOOT API (INT 20h, 21h, 22h)
 */
void unhook_comboot_interrupts ( ) {

	unhook_bios_interrupt ( 0x20, ( unsigned int ) int20_wrapper,
				&int20_vector );

	unhook_bios_interrupt ( 0x21, ( unsigned int ) int21_wrapper,
				&int21_vector );

	unhook_bios_interrupt ( 0x22, ( unsigned int ) int22_wrapper,
				&int22_vector );
}

/* Avoid dragging in serial console support unconditionally */
struct uart serial_console __attribute__ (( weak ));
