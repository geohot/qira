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
 * Frame buffer console
 *
 */

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/ansiesc.h>
#include <ipxe/image.h>
#include <ipxe/pixbuf.h>
#include <ipxe/umalloc.h>
#include <ipxe/console.h>
#include <ipxe/fbcon.h>

/**
 * Calculate raw colour value
 *
 * @v fbcon		Frame buffer console
 * @v rgb		24-bit RGB value
 * @ret raw		Raw colour
 */
static uint32_t fbcon_colour ( struct fbcon *fbcon, uint32_t rgb ) {
	struct fbcon_colour_map *map = fbcon->map;
	uint8_t red = ( rgb >> 16 );
	uint8_t green = ( rgb >> 8 );
	uint8_t blue = ( rgb >> 0 );
	uint32_t mapped;

	mapped = ( ( ( red >> map->red_scale ) << map->red_lsb ) |
		   ( ( green >> map->green_scale ) << map->green_lsb ) |
		   ( ( blue >> map->blue_scale ) << map->blue_lsb ) );
	return cpu_to_le32 ( mapped );
}

/**
 * Calculate ANSI font colour
 *
 * @v fbcon		Frame buffer console
 * @v ansicol		ANSI colour value (0-based)
 * @ret colour		Raw colour
 */
static uint32_t fbcon_ansi_colour ( struct fbcon *fbcon,
				    unsigned int ansicol ) {
	uint32_t rgb;

	/* Treat ansicol as 3-bit BGR with intensity 0xaa */
	rgb = ( ( ( ansicol & ( 1 << 0 ) ) ? 0xaa0000 : 0 ) |
		( ( ansicol & ( 1 << 1 ) ) ? 0x00aa00 : 0 ) |
		( ( ansicol & ( 1 << 2 ) ) ? 0x0000aa : 0 ) );

	return fbcon_colour ( fbcon, rgb );
}

/**
 * Set default foreground colour
 *
 * @v fbcon		Frame buffer console
 */
static void fbcon_set_default_foreground ( struct fbcon *fbcon ) {

	/* Default to non-bold white foreground */
	fbcon->foreground = fbcon_ansi_colour ( fbcon, 0x7 );
	fbcon->bold = 0;
}

/**
 * Set default background colour
 *
 * @v fbcon		Frame buffer console
 */
static void fbcon_set_default_background ( struct fbcon *fbcon ) {

	/* Default to transparent background */
	fbcon->background = FBCON_TRANSPARENT;
}

/**
 * Clear rows of characters
 *
 * @v fbcon		Frame buffer console
 * @v ypos		Starting Y position
 */
static void fbcon_clear ( struct fbcon *fbcon, unsigned int ypos ) {
	struct fbcon_text_cell cell = {
		.foreground = fbcon->foreground,
		.background = fbcon->background,
		.character = ' ',
	};
	size_t offset;
	unsigned int xpos;

	/* Clear stored character array */
	for ( ; ypos < fbcon->character.height ; ypos++ ) {
		offset = ( ypos * fbcon->character.width * sizeof ( cell ) );
		for ( xpos = 0 ; xpos < fbcon->character.width ; xpos++ ) {
			copy_to_user ( fbcon->text.start, offset, &cell,
				       sizeof ( cell ) );
			offset += sizeof ( cell );
		}
	}
}

/**
 * Store character at specified position
 *
 * @v fbcon		Frame buffer console
 * @v cell		Text cell
 * @v xpos		X position
 * @v ypos		Y position
 */
static void fbcon_store ( struct fbcon *fbcon, struct fbcon_text_cell *cell,
			  unsigned int xpos, unsigned int ypos ) {
	size_t offset;

	/* Store cell */
	offset = ( ( ( ypos * fbcon->character.width ) + xpos ) *
		   sizeof ( *cell ) );
	copy_to_user ( fbcon->text.start, offset, cell, sizeof ( *cell ) );
}

/**
 * Draw character at specified position
 *
 * @v fbcon		Frame buffer console
 * @v cell		Text cell
 * @v xpos		X position
 * @v ypos		Y position
 */
static void fbcon_draw ( struct fbcon *fbcon, struct fbcon_text_cell *cell,
			 unsigned int xpos, unsigned int ypos ) {
	struct fbcon_font_glyph glyph;
	size_t offset;
	size_t pixel_len;
	size_t skip_len;
	unsigned int row;
	unsigned int column;
	uint8_t bitmask;
	int transparent;
	void *src;

	/* Get font character */
	copy_from_user ( &glyph, fbcon->font->start,
			 ( cell->character * sizeof ( glyph ) ),
			 sizeof ( glyph ) );

	/* Calculate pixel geometry */
	offset = ( fbcon->indent +
		   ( ypos * fbcon->character.stride ) +
		   ( xpos * fbcon->character.len ) );
	pixel_len = fbcon->pixel->len;
	skip_len = ( fbcon->pixel->stride - fbcon->character.len );

	/* Check for transparent background colour */
	transparent = ( cell->background == FBCON_TRANSPARENT );

	/* Draw character rows */
	for ( row = 0 ; row < FBCON_CHAR_HEIGHT ; row++ ) {

		/* Draw background picture, if applicable */
		if ( transparent ) {
			if ( fbcon->picture.start ) {
				memcpy_user ( fbcon->start, offset,
					      fbcon->picture.start, offset,
					      fbcon->character.len );
			} else {
				memset_user ( fbcon->start, offset, 0,
					      fbcon->character.len );
			}
		}

		/* Draw character row */
		for ( column = FBCON_CHAR_WIDTH, bitmask = glyph.bitmask[row] ;
		      column ; column--, bitmask <<= 1, offset += pixel_len ) {
			if ( bitmask & 0x80 ) {
				src = &cell->foreground;
			} else if ( ! transparent ) {
				src = &cell->background;
			} else {
				continue;
			}
			copy_to_user ( fbcon->start, offset, src, pixel_len );
		}

		/* Move to next row */
		offset += skip_len;
	}
}

/**
 * Redraw all characters
 *
 * @v fbcon		Frame buffer console
 */
static void fbcon_redraw ( struct fbcon *fbcon ) {
	struct fbcon_text_cell cell;
	size_t offset = 0;
	unsigned int xpos;
	unsigned int ypos;

	/* Redraw characters */
	for ( ypos = 0 ; ypos < fbcon->character.height ; ypos++ ) {
		for ( xpos = 0 ; xpos < fbcon->character.width ; xpos++ ) {
			copy_from_user ( &cell, fbcon->text.start, offset,
					 sizeof ( cell ) );
			fbcon_draw ( fbcon, &cell, xpos, ypos );
			offset += sizeof ( cell );
		}
	}
}

/**
 * Scroll screen
 *
 * @v fbcon		Frame buffer console
 */
static void fbcon_scroll ( struct fbcon *fbcon ) {
	size_t row_len;

	/* Sanity check */
	assert ( fbcon->ypos == fbcon->character.height );

	/* Scroll up character array */
	row_len = ( fbcon->character.width * sizeof ( struct fbcon_text_cell ));
	memmove_user ( fbcon->text.start, 0, fbcon->text.start, row_len,
		       ( row_len * ( fbcon->character.height - 1 ) ) );
	fbcon_clear ( fbcon, ( fbcon->character.height - 1 ) );

	/* Update cursor position */
	fbcon->ypos--;

	/* Redraw all characters */
	fbcon_redraw ( fbcon );
}

/**
 * Draw character at cursor position
 *
 * @v fbcon		Frame buffer console
 * @v show_cursor	Show cursor
 */
static void fbcon_draw_cursor ( struct fbcon *fbcon, int show_cursor ) {
	struct fbcon_text_cell cell;
	size_t offset;

	offset = ( ( ( fbcon->ypos * fbcon->character.width ) + fbcon->xpos ) *
		   sizeof ( cell ) );
	copy_from_user ( &cell, fbcon->text.start, offset, sizeof ( cell ) );
	if ( show_cursor ) {
		cell.background = fbcon->foreground;
		cell.foreground = ( ( fbcon->background == FBCON_TRANSPARENT ) ?
				    0 : fbcon->background );
	}
	fbcon_draw ( fbcon, &cell, fbcon->xpos, fbcon->ypos );
}

/**
 * Handle ANSI CUP (cursor position)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params[0]		Row (1 is top)
 * @v params[1]		Column (1 is left)
 */
static void fbcon_handle_cup ( struct ansiesc_context *ctx,
			       unsigned int count __unused, int params[] ) {
	struct fbcon *fbcon = container_of ( ctx, struct fbcon, ctx );
	int cx = ( params[1] - 1 );
	int cy = ( params[0] - 1 );

	fbcon_draw_cursor ( fbcon, 0 );
	fbcon->xpos = cx;
	if ( fbcon->xpos >= fbcon->character.width )
		fbcon->xpos = 0;
	fbcon->ypos = cy;
	if ( fbcon->ypos >= fbcon->character.height )
		fbcon->ypos = 0;
	fbcon_draw_cursor ( fbcon, fbcon->show_cursor );
}

/**
 * Handle ANSI ED (erase in page)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params[0]		Region to erase
 */
static void fbcon_handle_ed ( struct ansiesc_context *ctx,
			      unsigned int count __unused,
			      int params[] __unused ) {
	struct fbcon *fbcon = container_of ( ctx, struct fbcon, ctx );

	/* We assume that we always clear the whole screen */
	assert ( params[0] == ANSIESC_ED_ALL );

	/* Clear character array */
	fbcon_clear ( fbcon, 0 );

	/* Redraw all characters */
	fbcon_redraw ( fbcon );

	/* Reset cursor position */
	fbcon->xpos = 0;
	fbcon->ypos = 0;
	fbcon_draw_cursor ( fbcon, fbcon->show_cursor );
}

/**
 * Handle ANSI SGR (set graphics rendition)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void fbcon_handle_sgr ( struct ansiesc_context *ctx, unsigned int count,
			       int params[] ) {
	struct fbcon *fbcon = container_of ( ctx, struct fbcon, ctx );
	uint32_t *custom = NULL;
	uint32_t rgb;
	unsigned int end;
	unsigned int i;
	int aspect;

	for ( i = 0 ; i < count ; i++ ) {

		/* Process aspect */
		aspect = params[i];
		if ( aspect == 0 ) {
			fbcon_set_default_foreground ( fbcon );
			fbcon_set_default_background ( fbcon );
		} else if ( aspect == 1 ) {
			fbcon->bold = fbcon_colour ( fbcon, FBCON_BOLD );
		} else if ( aspect == 22 ) {
			fbcon->bold = 0;
		} else if ( ( aspect >= 30 ) && ( aspect <= 37 ) ) {
			fbcon->foreground =
				fbcon_ansi_colour ( fbcon, aspect - 30 );
		} else if ( aspect == 38 ) {
			custom = &fbcon->foreground;
		} else if ( aspect == 39 ) {
			fbcon_set_default_foreground ( fbcon );
		} else if ( ( aspect >= 40 ) && ( aspect <= 47 ) ) {
			fbcon->background =
				fbcon_ansi_colour ( fbcon, aspect - 40 );
		} else if ( aspect == 48 ) {
			custom = &fbcon->background;
		} else if ( aspect == 49 ) {
			fbcon_set_default_background ( fbcon );
		}

		/* Process custom RGB colour, if applicable
		 *
		 * We support the xterm-compatible
		 * "<ESC>[38;2;<red>;<green>;<blue>m" and
		 * "<ESC>[48;2;<red>;<green>;<blue>m" sequences.
		 */
		if ( custom ) {
			rgb = 0;
			end = ( i + 5 );
			for ( ; ( i < count ) && ( i < end ) ; i++ )
				rgb = ( ( rgb << 8 ) | params[i] );
			*custom = fbcon_colour ( fbcon, rgb );
			custom = NULL;
		}
	}
}

/**
 * Handle ANSI DECTCEM set (show cursor)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void fbcon_handle_dectcem_set ( struct ansiesc_context *ctx,
				       unsigned int count __unused,
				       int params[] __unused ) {
	struct fbcon *fbcon = container_of ( ctx, struct fbcon, ctx );

	fbcon->show_cursor = 1;
	fbcon_draw_cursor ( fbcon, 1 );
}

/**
 * Handle ANSI DECTCEM reset (hide cursor)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void fbcon_handle_dectcem_reset ( struct ansiesc_context *ctx,
					 unsigned int count __unused,
					 int params[] __unused ) {
	struct fbcon *fbcon = container_of ( ctx, struct fbcon, ctx );

	fbcon->show_cursor = 0;
	fbcon_draw_cursor ( fbcon, 0 );
}

/** ANSI escape sequence handlers */
static struct ansiesc_handler fbcon_ansiesc_handlers[] = {
	{ ANSIESC_CUP, fbcon_handle_cup },
	{ ANSIESC_ED, fbcon_handle_ed },
	{ ANSIESC_SGR, fbcon_handle_sgr },
	{ ANSIESC_DECTCEM_SET, fbcon_handle_dectcem_set },
	{ ANSIESC_DECTCEM_RESET, fbcon_handle_dectcem_reset },
	{ 0, NULL }
};

/**
 * Print a character to current cursor position
 *
 * @v fbcon		Frame buffer console
 * @v character		Character
 */
void fbcon_putchar ( struct fbcon *fbcon, int character ) {
	struct fbcon_text_cell cell;

	/* Intercept ANSI escape sequences */
	character = ansiesc_process ( &fbcon->ctx, character );
	if ( character < 0 )
		return;

	/* Handle control characters */
	switch ( character ) {
	case '\r':
		fbcon_draw_cursor ( fbcon, 0 );
		fbcon->xpos = 0;
		break;
	case '\n':
		fbcon_draw_cursor ( fbcon, 0 );
		fbcon->xpos = 0;
		fbcon->ypos++;
		break;
	case '\b':
		fbcon_draw_cursor ( fbcon, 0 );
		if ( fbcon->xpos ) {
			fbcon->xpos--;
		} else if ( fbcon->ypos ) {
			fbcon->xpos = ( fbcon->character.width - 1 );
			fbcon->ypos--;
		}
		break;
	default:
		/* Print character at current cursor position */
		cell.foreground = ( fbcon->foreground | fbcon->bold );
		cell.background = fbcon->background;
		cell.character = character;
		fbcon_store ( fbcon, &cell, fbcon->xpos, fbcon->ypos );
		fbcon_draw ( fbcon, &cell, fbcon->xpos, fbcon->ypos );

		/* Advance cursor */
		fbcon->xpos++;
		if ( fbcon->xpos >= fbcon->character.width ) {
			fbcon->xpos = 0;
			fbcon->ypos++;
		}
		break;
	}

	/* Scroll screen if necessary */
	if ( fbcon->ypos >= fbcon->character.height )
		fbcon_scroll ( fbcon );

	/* Show cursor */
	fbcon_draw_cursor ( fbcon, fbcon->show_cursor );
}

/**
 * Initialise background picture
 *
 * @v fbcon		Frame buffer console
 * @v pixbuf		Background picture
 * @ret rc		Return status code
 */
static int fbcon_picture_init ( struct fbcon *fbcon,
				struct pixel_buffer *pixbuf ) {
	struct fbcon_geometry *pixel = fbcon->pixel;
	struct fbcon_picture *picture = &fbcon->picture;
	size_t len;
	size_t pixbuf_stride;
	size_t indent;
	size_t pixbuf_indent;
	size_t offset;
	size_t pixbuf_offset;
	uint32_t rgb;
	uint32_t raw;
	unsigned int x;
	unsigned int y;
	unsigned int width;
	unsigned int height;
	int xgap;
	int ygap;
	int rc;

	/* Allocate buffer */
	len = ( pixel->height * pixel->stride );
	picture->start = umalloc ( len );
	if ( ! picture->start ) {
		DBGC ( fbcon, "FBCON %p could not allocate %zd bytes for "
		       "picture\n", fbcon, len );
		rc = -ENOMEM;
		goto err_umalloc;
	}

	/* Centre picture on console */
	pixbuf_stride = ( pixbuf->width * sizeof ( rgb ) );
	xgap = ( ( ( int ) ( pixel->width - pixbuf->width ) ) / 2 );
	ygap = ( ( ( int ) ( pixel->height - pixbuf->height ) ) / 2 );
	indent = ( ( ( ( ygap >= 0 ) ? ygap : 0 ) * pixel->stride ) +
		   ( ( ( xgap >= 0 ) ? xgap : 0 ) * pixel->len ) );
	pixbuf_indent =	( ( ( ( ygap < 0 ) ? -ygap : 0 ) * pixbuf_stride ) +
			  ( ( ( xgap < 0 ) ? -xgap : 0 ) * sizeof ( rgb ) ) );
	width = pixbuf->width;
	if ( width > pixel->width )
		width = pixel->width;
	height = pixbuf->height;
	if ( height > pixel->height )
		height = pixel->height;
	DBGC ( fbcon, "FBCON %p picture is pixel %dx%d at [%d,%d),[%d,%d)\n",
	       fbcon, width, height, xgap, ( xgap + pixbuf->width ), ygap,
	       ( ygap + pixbuf->height ) );

	/* Convert to frame buffer raw format */
	memset_user ( picture->start, 0, 0, len );
	for ( y = 0 ; y < height ; y++ ) {
		offset = ( indent + ( y * pixel->stride ) );
		pixbuf_offset = ( pixbuf_indent + ( y * pixbuf_stride ) );
		for ( x = 0 ; x < width ; x++ ) {
			copy_from_user ( &rgb, pixbuf->data, pixbuf_offset,
					 sizeof ( rgb ) );
			raw = fbcon_colour ( fbcon, rgb );
			copy_to_user ( picture->start, offset, &raw,
				       pixel->len );
			offset += pixel->len;
			pixbuf_offset += sizeof ( rgb );
		}
	}

	return 0;

	ufree ( picture->start );
 err_umalloc:
	return rc;
}

/**
 * Initialise frame buffer console
 *
 * @v fbcon		Frame buffer console
 * @v start		Start address
 * @v pixel		Pixel geometry
 * @v margin		Minimum margin
 * @v map		Colour mapping
 * @v font		Font definition
 * @v pixbuf		Background picture (if any)
 * @ret rc		Return status code
 */
int fbcon_init ( struct fbcon *fbcon, userptr_t start,
		 struct fbcon_geometry *pixel,
		 struct fbcon_margin *margin,
		 struct fbcon_colour_map *map,
		 struct fbcon_font *font,
		 struct pixel_buffer *pixbuf ) {
	int width;
	int height;
	unsigned int xgap;
	unsigned int ygap;
	int rc;

	/* Initialise data structure */
	memset ( fbcon, 0, sizeof ( *fbcon ) );
	fbcon->start = start;
	fbcon->pixel = pixel;
	assert ( pixel->len <= sizeof ( uint32_t ) );
	fbcon->map = map;
	fbcon->font = font;
	fbcon->ctx.handlers = fbcon_ansiesc_handlers;
	fbcon->show_cursor = 1;

	/* Derive overall length */
	fbcon->len = ( pixel->height * pixel->stride );
	DBGC ( fbcon, "FBCON %p at [%08lx,%08lx)\n", fbcon,
	       user_to_phys ( fbcon->start, 0 ),
	       user_to_phys ( fbcon->start, fbcon->len ) );

	/* Expand margin to accommodate whole characters */
	width = ( pixel->width - margin->left - margin->right );
	height = ( pixel->height - margin->top - margin->bottom );
	if ( ( width < FBCON_CHAR_WIDTH ) || ( height < FBCON_CHAR_HEIGHT ) ) {
		DBGC ( fbcon, "FBCON %p has unusable character area "
		       "[%d-%d),[%d-%d)\n", fbcon,
		       margin->left, ( pixel->width - margin->right ),
		       margin->top, ( pixel->height - margin->bottom ) );
		rc = -EINVAL;
		goto err_margin;
	}
	xgap = ( width % FBCON_CHAR_WIDTH );
	ygap = ( height % FBCON_CHAR_HEIGHT );
	fbcon->margin.left = ( margin->left + ( xgap / 2 ) );
	fbcon->margin.top = ( margin->top + ( ygap / 2 ) );
	fbcon->margin.right = ( margin->right + ( xgap - ( xgap / 2 ) ) );
	fbcon->margin.bottom = ( margin->bottom + ( ygap - ( ygap / 2 ) ) );
	fbcon->indent = ( ( fbcon->margin.top * pixel->stride ) +
			  ( fbcon->margin.left * pixel->len ) );

	/* Derive character geometry from pixel geometry */
	fbcon->character.width = ( width / FBCON_CHAR_WIDTH );
	fbcon->character.height = ( height / FBCON_CHAR_HEIGHT );
	fbcon->character.len = ( pixel->len * FBCON_CHAR_WIDTH );
	fbcon->character.stride = ( pixel->stride * FBCON_CHAR_HEIGHT );
	DBGC ( fbcon, "FBCON %p is pixel %dx%d, char %dx%d at "
	       "[%d-%d),[%d-%d)\n", fbcon, fbcon->pixel->width,
	       fbcon->pixel->height, fbcon->character.width,
	       fbcon->character.height, fbcon->margin.left,
	       ( fbcon->pixel->width - fbcon->margin.right ),
	       fbcon->margin.top,
	       ( fbcon->pixel->height - fbcon->margin.bottom ) );

	/* Set default colours */
	fbcon_set_default_foreground ( fbcon );
	fbcon_set_default_background ( fbcon );

	/* Allocate and initialise stored character array */
	fbcon->text.start = umalloc ( fbcon->character.width *
				      fbcon->character.height *
				      sizeof ( struct fbcon_text_cell ) );
	if ( ! fbcon->text.start ) {
		rc = -ENOMEM;
		goto err_text;
	}
	fbcon_clear ( fbcon, 0 );

	/* Set framebuffer to all black (including margins) */
	memset_user ( fbcon->start, 0, 0, fbcon->len );

	/* Generate pixel buffer from background image, if applicable */
	if ( pixbuf && ( ( rc = fbcon_picture_init ( fbcon, pixbuf ) ) != 0 ) )
		goto err_picture;

	/* Draw background picture (including margins), if applicable */
	if ( fbcon->picture.start ) {
		memcpy_user ( fbcon->start, 0, fbcon->picture.start, 0,
			      fbcon->len );
	}

	/* Update console width and height */
	console_set_size ( fbcon->character.width, fbcon->character.height );

	return 0;

	ufree ( fbcon->picture.start );
 err_picture:
	ufree ( fbcon->text.start );
 err_text:
 err_margin:
	return rc;
}

/**
 * Finalise frame buffer console
 *
 * @v fbcon		Frame buffer console
 */
void fbcon_fini ( struct fbcon *fbcon ) {

	ufree ( fbcon->text.start );
	ufree ( fbcon->picture.start );
}
