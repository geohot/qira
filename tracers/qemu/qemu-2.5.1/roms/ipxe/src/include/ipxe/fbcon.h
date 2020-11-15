#ifndef _IPXE_FBCON_H
#define _IPXE_FBCON_H

/** @file
 *
 * Frame buffer console
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/ansiesc.h>
#include <ipxe/uaccess.h>

struct pixel_buffer;

/** Character width, in pixels */
#define FBCON_CHAR_WIDTH 9

/** Character height, in pixels */
#define FBCON_CHAR_HEIGHT 16

/** Bold colour modifier (RGB value) */
#define FBCON_BOLD 0x555555

/** Transparent background magic colour (raw colour value) */
#define FBCON_TRANSPARENT 0xffffffff

/** A font glyph */
struct fbcon_font_glyph {
	/** Row bitmask */
	uint8_t bitmask[FBCON_CHAR_HEIGHT];
} __attribute__ (( packed ));

/** A font definition */
struct fbcon_font {
	/** Character glyphs */
	userptr_t start;
} __attribute__ (( packed ));

/** A frame buffer geometry
 *
 * The geometry is defined in terms of "entities" (which can be either
 * pixels or characters).
 */
struct fbcon_geometry {
	/** Width (number of entities per displayed row) */
	unsigned int width;
	/** Height (number of entities per displayed column) */
	unsigned int height;
	/** Length of a single entity */
	size_t len;
	/** Stride (offset between vertically adjacent entities) */
	size_t stride;
};

/** A frame buffer margin */
struct fbcon_margin {
	/** Left margin */
	unsigned int left;
	/** Right margin */
	unsigned int right;
	/** Top margin */
	unsigned int top;
	/** Bottom margin */
	unsigned int bottom;
};

/** A frame buffer colour mapping */
struct fbcon_colour_map {
	/** Red scale (right shift amount from 24-bit RGB) */
	uint8_t red_scale;
	/** Green scale (right shift amount from 24-bit RGB) */
	uint8_t green_scale;
	/** Blue scale (right shift amount from 24-bit RGB) */
	uint8_t blue_scale;
	/** Red LSB */
	uint8_t red_lsb;
	/** Green LSB */
	uint8_t green_lsb;
	/** Blue LSB */
	uint8_t blue_lsb;
};

/** A frame buffer text cell */
struct fbcon_text_cell {
	/** Foreground colour */
	uint32_t foreground;
	/** Background colour */
	uint32_t background;
	/** Character */
	unsigned int character;
};

/** A frame buffer text array */
struct fbcon_text {
	/** Stored text cells */
	userptr_t start;
};

/** A frame buffer background picture */
struct fbcon_picture {
	/** Start address */
	userptr_t start;
};

/** A frame buffer console */
struct fbcon {
	/** Start address */
	userptr_t start;
	/** Length of one complete displayed screen */
	size_t len;
	/** Pixel geometry */
	struct fbcon_geometry *pixel;
	/** Character geometry */
	struct fbcon_geometry character;
	/** Margin */
	struct fbcon_margin margin;
	/** Indent to first character (in bytes) */
	size_t indent;
	/** Colour mapping */
	struct fbcon_colour_map *map;
	/** Font definition */
	struct fbcon_font *font;
	/** Text foreground raw colour */
	uint32_t foreground;
	/** Text background raw colour */
	uint32_t background;
	/** Bold colour modifier raw colour */
	uint32_t bold;
	/** Text cursor X position */
	unsigned int xpos;
	/** Text cursor Y position */
	unsigned int ypos;
	/** ANSI escape sequence context */
	struct ansiesc_context ctx;
	/** Text array */
	struct fbcon_text text;
	/** Background picture */
	struct fbcon_picture picture;
	/** Display cursor */
	int show_cursor;
};

extern int fbcon_init ( struct fbcon *fbcon, userptr_t start,
			struct fbcon_geometry *pixel,
			struct fbcon_margin *margin,
			struct fbcon_colour_map *map,
			struct fbcon_font *font,
			struct pixel_buffer *pixbuf );
extern void fbcon_fini ( struct fbcon *fbcon );
extern void fbcon_putchar ( struct fbcon *fbcon, int character );

#endif /* _IPXE_FBCON_H */
