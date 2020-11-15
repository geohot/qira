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

/** @file
 *
 * VESA frame buffer console
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <realmode.h>
#include <ipxe/console.h>
#include <ipxe/io.h>
#include <ipxe/ansicol.h>
#include <ipxe/fbcon.h>
#include <ipxe/vesafb.h>
#include <config/console.h>

/* Avoid dragging in BIOS console if not otherwise used */
extern struct console_driver bios_console;
struct console_driver bios_console __attribute__ (( weak ));

/* Disambiguate the various error causes */
#define EIO_FAILED __einfo_error ( EINFO_EIO_FAILED )
#define EINFO_EIO_FAILED						\
	__einfo_uniqify ( EINFO_EIO, 0x01,				\
			  "Function call failed" )
#define EIO_HARDWARE __einfo_error ( EINFO_EIO_HARDWARE )
#define EINFO_EIO_HARDWARE						\
	__einfo_uniqify ( EINFO_EIO, 0x02,				\
			  "Not supported in current configuration" )
#define EIO_MODE __einfo_error ( EINFO_EIO_MODE )
#define EINFO_EIO_MODE							\
	__einfo_uniqify ( EINFO_EIO, 0x03,				\
			  "Invalid in current video mode" )
#define EIO_VBE( code )							\
	EUNIQ ( EINFO_EIO, (code), EIO_FAILED, EIO_HARDWARE, EIO_MODE )

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_VESAFB ) && CONSOLE_EXPLICIT ( CONSOLE_VESAFB ) )
#undef CONSOLE_VESAFB
#define CONSOLE_VESAFB ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_LOG )
#endif

/** Font corresponding to selected character width and height */
#define VESAFB_FONT VBE_FONT_8x16

/* Forward declaration */
struct console_driver vesafb_console __console_driver;

/** A VESA frame buffer */
struct vesafb {
	/** Frame buffer console */
	struct fbcon fbcon;
	/** Physical start address */
	physaddr_t start;
	/** Pixel geometry */
	struct fbcon_geometry pixel;
	/** Margin */
	struct fbcon_margin margin;
	/** Colour mapping */
	struct fbcon_colour_map map;
	/** Font definition */
	struct fbcon_font font;
	/** Saved VGA mode */
	uint8_t saved_mode;
};

/** The VESA frame buffer */
static struct vesafb vesafb;

/** Base memory buffer used for VBE calls */
union vbe_buffer {
	/** VBE controller information block */
	struct vbe_controller_info controller;
	/** VBE mode information block */
	struct vbe_mode_info mode;
};
static union vbe_buffer __bss16 ( vbe_buf );
#define vbe_buf __use_data16 ( vbe_buf )

/**
 * Convert VBE status code to iPXE status code
 *
 * @v status		VBE status code
 * @ret rc		Return status code
 */
static int vesafb_rc ( unsigned int status ) {
	unsigned int code;

	if ( ( status & 0xff ) != 0x4f )
		return -ENOTSUP;
	code = ( ( status >> 8 ) & 0xff );
	return ( code ? -EIO_VBE ( code ) : 0 );
}

/**
 * Get font definition
 *
 */
static void vesafb_font ( void ) {
	struct segoff font;

	/* Get font information
	 *
	 * Working around gcc bugs is icky here.  The value we want is
	 * returned in %ebp, but there's no way to specify %ebp in an
	 * output constraint.  We can't put %ebp in the clobber list,
	 * because this tends to cause random build failures on some
	 * gcc versions.  We can't manually push/pop %ebp and return
	 * the value via a generic register output constraint, because
	 * gcc might choose to use %ebp to satisfy that constraint
	 * (and we have no way to prevent it from so doing).
	 *
	 * Work around this hideous mess by using %ecx and %edx as the
	 * output registers, since they get clobbered anyway.
	 */
	__asm__ __volatile__ ( REAL_CODE ( "pushw %%bp\n\t" /* gcc bug */
					   "int $0x10\n\t"
					   "movw %%es, %%cx\n\t"
					   "movw %%bp, %%dx\n\t"
					   "popw %%bp\n\t" /* gcc bug */ )
			       : "=c" ( font.segment ),
				 "=d" ( font.offset )
			       : "a" ( VBE_GET_FONT ),
				 "b" ( VESAFB_FONT ) );
	DBGC ( &vbe_buf, "VESAFB has font %04x at %04x:%04x\n",
	       VESAFB_FONT, font.segment, font.offset );
	vesafb.font.start = real_to_user ( font.segment, font.offset );
}

/**
 * Get VBE mode list
 *
 * @ret mode_numbers	Mode number list (terminated with VBE_MODE_END)
 * @ret rc		Return status code
 *
 * The caller is responsible for eventually freeing the mode list.
 */
static int vesafb_mode_list ( uint16_t **mode_numbers ) {
	struct vbe_controller_info *controller = &vbe_buf.controller;
	userptr_t video_mode_ptr;
	uint16_t mode_number;
	uint16_t status;
	size_t len;
	int rc;

	/* Avoid returning uninitialised data on error */
	*mode_numbers = NULL;

	/* Get controller information block */
	controller->vbe_signature = 0;
	__asm__ __volatile__ ( REAL_CODE ( "int $0x10" )
			       : "=a" ( status )
			       : "a" ( VBE_CONTROLLER_INFO ),
				 "D" ( __from_data16 ( controller ) )
			       : "memory", "ebx", "edx" );
	if ( ( rc = vesafb_rc ( status ) ) != 0 ) {
		DBGC ( &vbe_buf, "VESAFB could not get controller information: "
		       "[%04x] %s\n", status, strerror ( rc ) );
		return rc;
	}
	if ( controller->vbe_signature != VBE_CONTROLLER_SIGNATURE ) {
		DBGC ( &vbe_buf, "VESAFB invalid controller signature "
		       "\"%c%c%c%c\"\n", ( controller->vbe_signature >> 0 ),
		       ( controller->vbe_signature >> 8 ),
		       ( controller->vbe_signature >> 16 ),
		       ( controller->vbe_signature >> 24 ) );
		DBGC_HDA ( &vbe_buf, 0, controller, sizeof ( *controller ) );
		return -EINVAL;
	}
	DBGC ( &vbe_buf, "VESAFB found VBE version %d.%d with mode list at "
	       "%04x:%04x\n", controller->vbe_major_version,
	       controller->vbe_minor_version,
	       controller->video_mode_ptr.segment,
	       controller->video_mode_ptr.offset );

	/* Calculate length of mode list */
	video_mode_ptr = real_to_user ( controller->video_mode_ptr.segment,
					controller->video_mode_ptr.offset );
	len = 0;
	do {
		copy_from_user ( &mode_number, video_mode_ptr, len,
				 sizeof ( mode_number ) );
		len += sizeof ( mode_number );
	} while ( mode_number != VBE_MODE_END );

	/* Allocate and fill mode list */
	*mode_numbers = malloc ( len );
	if ( ! *mode_numbers )
		return -ENOMEM;
	copy_from_user ( *mode_numbers, video_mode_ptr, 0, len );

	return 0;
}

/**
 * Get video mode information
 *
 * @v mode_number	Mode number
 * @ret rc		Return status code
 */
static int vesafb_mode_info ( unsigned int mode_number ) {
	struct vbe_mode_info *mode = &vbe_buf.mode;
	uint16_t status;
	int rc;

	/* Get mode information */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x10" )
			       : "=a" ( status )
			       : "a" ( VBE_MODE_INFO ),
				 "c" ( mode_number ),
				 "D" ( __from_data16 ( mode ) )
			       : "memory" );
	if ( ( rc = vesafb_rc ( status ) ) != 0 ) {
		DBGC ( &vbe_buf, "VESAFB could not get mode %04x information: "
		       "[%04x] %s\n", mode_number, status, strerror ( rc ) );
		return rc;
	}
	DBGC ( &vbe_buf, "VESAFB mode %04x %dx%d %dbpp(%d:%d:%d:%d) model "
	       "%02x [x%d]%s%s%s%s%s\n", mode_number, mode->x_resolution,
	       mode->y_resolution, mode->bits_per_pixel, mode->rsvd_mask_size,
	       mode->red_mask_size, mode->green_mask_size, mode->blue_mask_size,
	       mode->memory_model, ( mode->number_of_image_pages + 1 ),
	       ( ( mode->mode_attributes & VBE_MODE_ATTR_SUPPORTED ) ?
		 "" : " [unsupported]" ),
	       ( ( mode->mode_attributes & VBE_MODE_ATTR_TTY ) ?
		 " [tty]" : "" ),
	       ( ( mode->mode_attributes & VBE_MODE_ATTR_GRAPHICS ) ?
		 "" : " [text]" ),
	       ( ( mode->mode_attributes & VBE_MODE_ATTR_LINEAR ) ?
		 "" : " [nonlinear]" ),
	       ( ( mode->mode_attributes & VBE_MODE_ATTR_TRIPLE_BUF ) ?
		 " [buf]" : "" ) );

	return 0;
}

/**
 * Set video mode
 *
 * @v mode_number	Mode number
 * @ret rc		Return status code
 */
static int vesafb_set_mode ( unsigned int mode_number ) {
	struct vbe_mode_info *mode = &vbe_buf.mode;
	uint16_t status;
	int rc;

	/* Get mode information */
	if ( ( rc = vesafb_mode_info ( mode_number ) ) != 0 )
		return rc;

	/* Record mode parameters */
	vesafb.start = mode->phys_base_ptr;
	vesafb.pixel.width = mode->x_resolution;
	vesafb.pixel.height = mode->y_resolution;
	vesafb.pixel.len = ( ( mode->bits_per_pixel + 7 ) / 8 );
	vesafb.pixel.stride = mode->bytes_per_scan_line;
	DBGC ( &vbe_buf, "VESAFB mode %04x has frame buffer at %08x\n",
	       mode_number, mode->phys_base_ptr );

	/* Initialise font colours */
	vesafb.map.red_scale = ( 8 - mode->red_mask_size );
	vesafb.map.green_scale = ( 8 - mode->green_mask_size );
	vesafb.map.blue_scale = ( 8 - mode->blue_mask_size );
	vesafb.map.red_lsb = mode->red_field_position;
	vesafb.map.green_lsb = mode->green_field_position;
	vesafb.map.blue_lsb = mode->blue_field_position;

	/* Select this mode */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x10" )
			       : "=a" ( status )
			       : "a" ( VBE_SET_MODE ),
				 "b" ( mode_number ) );
	if ( ( rc = vesafb_rc ( status ) ) != 0 ) {
		DBGC ( &vbe_buf, "VESAFB could not set mode %04x: [%04x] %s\n",
		       mode_number, status, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Select video mode
 *
 * @v mode_numbers	Mode number list (terminated with VBE_MODE_END)
 * @v min_width		Minimum required width (in pixels)
 * @v min_height	Minimum required height (in pixels)
 * @v min_bpp		Minimum required colour depth (in bits per pixel)
 * @ret mode_number	Mode number, or negative error
 */
static int vesafb_select_mode ( const uint16_t *mode_numbers,
				unsigned int min_width, unsigned int min_height,
				unsigned int min_bpp ) {
	struct vbe_mode_info *mode = &vbe_buf.mode;
	int best_mode_number = -ENOENT;
	unsigned int best_score = INT_MAX;
	unsigned int score;
	uint16_t mode_number;
	int rc;

	/* Find the first suitable mode */
	while ( ( mode_number = *(mode_numbers++) ) != VBE_MODE_END ) {

		/* Force linear mode variant */
		mode_number |= VBE_MODE_LINEAR;

		/* Get mode information */
		if ( ( rc = vesafb_mode_info ( mode_number ) ) != 0 )
			continue;

		/* Skip unusable modes */
		if ( ( mode->mode_attributes & ( VBE_MODE_ATTR_SUPPORTED |
						 VBE_MODE_ATTR_GRAPHICS |
						 VBE_MODE_ATTR_LINEAR ) ) !=
		     ( VBE_MODE_ATTR_SUPPORTED | VBE_MODE_ATTR_GRAPHICS |
		       VBE_MODE_ATTR_LINEAR ) ) {
			continue;
		}
		if ( mode->memory_model != VBE_MODE_MODEL_DIRECT_COLOUR )
			continue;

		/* Skip modes not meeting the requirements */
		if ( ( mode->x_resolution < min_width ) ||
		     ( mode->y_resolution < min_height ) ||
		     ( mode->bits_per_pixel < min_bpp ) ) {
			continue;
		}

		/* Select this mode if it has the best (i.e. lowest)
		 * score.  We choose the scoring system to favour
		 * modes close to the specified width and height;
		 * within modes of the same width and height we prefer
		 * a higher colour depth.
		 */
		score = ( ( mode->x_resolution * mode->y_resolution ) -
			  mode->bits_per_pixel );
		if ( score < best_score ) {
			best_mode_number = mode_number;
			best_score = score;
		}
	}

	if ( best_mode_number >= 0 ) {
		DBGC ( &vbe_buf, "VESAFB selected mode %04x\n",
		       best_mode_number );
	} else {
		DBGC ( &vbe_buf, "VESAFB found no suitable mode\n" );
	}

	return best_mode_number;
}

/**
 * Restore video mode
 *
 */
static void vesafb_restore ( void ) {
	uint32_t discard_a;

	/* Restore saved VGA mode */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x10" )
			       : "=a" ( discard_a )
			       : "a" ( VBE_SET_VGA_MODE | vesafb.saved_mode ) );
	DBGC ( &vbe_buf, "VESAFB restored VGA mode %#02x\n",
	       vesafb.saved_mode );
}

/**
 * Initialise VESA frame buffer
 *
 * @v config		Console configuration, or NULL to reset
 * @ret rc		Return status code
 */
static int vesafb_init ( struct console_configuration *config ) {
	uint32_t discard_b;
	uint16_t *mode_numbers;
	unsigned int xgap;
	unsigned int ygap;
	unsigned int left;
	unsigned int right;
	unsigned int top;
	unsigned int bottom;
	int mode_number;
	int rc;

	/* Record current VGA mode */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x10" )
			       : "=a" ( vesafb.saved_mode ), "=b" ( discard_b )
			       : "a" ( VBE_GET_VGA_MODE ) );
	DBGC ( &vbe_buf, "VESAFB saved VGA mode %#02x\n", vesafb.saved_mode );

	/* Get VESA mode list */
	if ( ( rc = vesafb_mode_list ( &mode_numbers ) ) != 0 )
		goto err_mode_list;

	/* Select mode */
	if ( ( mode_number = vesafb_select_mode ( mode_numbers, config->width,
						  config->height,
						  config->depth ) ) < 0 ) {
		rc = mode_number;
		goto err_select_mode;
	}

	/* Set mode */
	if ( ( rc = vesafb_set_mode ( mode_number ) ) != 0 )
		goto err_set_mode;

	/* Calculate margin.  If the actual screen size is larger than
	 * the requested screen size, then update the margins so that
	 * the margin remains relative to the requested screen size.
	 * (As an exception, if a zero margin was specified then treat
	 * this as meaning "expand to edge of actual screen".)
	 */
	xgap = ( vesafb.pixel.width - config->width );
	ygap = ( vesafb.pixel.height - config->height );
	left = ( xgap / 2 );
	right = ( xgap - left );
	top = ( ygap / 2 );
	bottom = ( ygap - top );
	vesafb.margin.left = ( config->left + ( config->left ? left : 0 ) );
	vesafb.margin.right = ( config->right + ( config->right ? right : 0 ) );
	vesafb.margin.top = ( config->top + ( config->top ? top : 0 ) );
	vesafb.margin.bottom =
		( config->bottom + ( config->bottom ? bottom : 0 ) );

	/* Get font data */
	vesafb_font();

	/* Initialise frame buffer console */
	if ( ( rc = fbcon_init ( &vesafb.fbcon, phys_to_user ( vesafb.start ),
				 &vesafb.pixel, &vesafb.margin, &vesafb.map,
				 &vesafb.font, config->pixbuf ) ) != 0 )
		goto err_fbcon_init;

	free ( mode_numbers );
	return 0;

	fbcon_fini ( &vesafb.fbcon );
 err_fbcon_init:
 err_set_mode:
	vesafb_restore();
 err_select_mode:
	free ( mode_numbers );
 err_mode_list:
	return rc;
}

/**
 * Finalise VESA frame buffer
 *
 */
static void vesafb_fini ( void ) {

	/* Finalise frame buffer console */
	fbcon_fini ( &vesafb.fbcon );

	/* Restore saved VGA mode */
	vesafb_restore();
}

/**
 * Print a character to current cursor position
 *
 * @v character		Character
 */
static void vesafb_putchar ( int character ) {

	fbcon_putchar ( &vesafb.fbcon, character );
}

/**
 * Configure console
 *
 * @v config		Console configuration, or NULL to reset
 * @ret rc		Return status code
 */
static int vesafb_configure ( struct console_configuration *config ) {
	int rc;

	/* Reset console, if applicable */
	if ( ! vesafb_console.disabled ) {
		vesafb_fini();
		bios_console.disabled &= ~CONSOLE_DISABLED_OUTPUT;
		ansicol_reset_magic();
	}
	vesafb_console.disabled = CONSOLE_DISABLED;

	/* Do nothing more unless we have a usable configuration */
	if ( ( config == NULL ) ||
	     ( config->width == 0 ) || ( config->height == 0 ) ) {
		return 0;
	}

	/* Initialise VESA frame buffer */
	if ( ( rc = vesafb_init ( config ) ) != 0 )
		return rc;

	/* Mark console as enabled */
	vesafb_console.disabled = 0;
	bios_console.disabled |= CONSOLE_DISABLED_OUTPUT;

	/* Set magic colour to transparent if we have a background picture */
	if ( config->pixbuf )
		ansicol_set_magic_transparent();

	return 0;
}

/** VESA frame buffer console driver */
struct console_driver vesafb_console __console_driver = {
	.usage = CONSOLE_VESAFB,
	.putchar = vesafb_putchar,
	.configure = vesafb_configure,
	.disabled = CONSOLE_DISABLED,
};
