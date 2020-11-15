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

#include <assert.h>
#include <realmode.h>
#include <bios.h>
#include <ipxe/console.h>
#include <ipxe/ansiesc.h>
#include <ipxe/keymap.h>
#include <config/console.h>

#define ATTR_BOLD		0x08

#define ATTR_FCOL_MASK		0x07
#define ATTR_FCOL_BLACK		0x00
#define ATTR_FCOL_BLUE		0x01
#define ATTR_FCOL_GREEN		0x02
#define ATTR_FCOL_CYAN		0x03
#define ATTR_FCOL_RED		0x04
#define ATTR_FCOL_MAGENTA	0x05
#define ATTR_FCOL_YELLOW	0x06
#define ATTR_FCOL_WHITE		0x07

#define ATTR_BLINK		0x80

#define ATTR_BCOL_MASK		0x70
#define ATTR_BCOL_BLACK		0x00
#define ATTR_BCOL_BLUE		0x10
#define ATTR_BCOL_GREEN		0x20
#define ATTR_BCOL_CYAN		0x30
#define ATTR_BCOL_RED		0x40
#define ATTR_BCOL_MAGENTA	0x50
#define ATTR_BCOL_YELLOW	0x60
#define ATTR_BCOL_WHITE		0x70

#define ATTR_DEFAULT		ATTR_FCOL_WHITE

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_PCBIOS ) && CONSOLE_EXPLICIT ( CONSOLE_PCBIOS ) )
#undef CONSOLE_PCBIOS
#define CONSOLE_PCBIOS ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_LOG )
#endif

/** Current character attribute */
static unsigned int bios_attr = ATTR_DEFAULT;

/**
 * Handle ANSI CUP (cursor position)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params[0]		Row (1 is top)
 * @v params[1]		Column (1 is left)
 */
static void bios_handle_cup ( struct ansiesc_context *ctx __unused,
			      unsigned int count __unused, int params[] ) {
	int cx = ( params[1] - 1 );
	int cy = ( params[0] - 1 );

	if ( cx < 0 )
		cx = 0;
	if ( cy < 0 )
		cy = 0;

	__asm__ __volatile__ ( REAL_CODE ( "sti\n\t"
					   "int $0x10\n\t"
					   "cli\n\t" )
			       : : "a" ( 0x0200 ), "b" ( 1 ),
			           "d" ( ( cy << 8 ) | cx ) );
}

/**
 * Handle ANSI ED (erase in page)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params[0]		Region to erase
 */
static void bios_handle_ed ( struct ansiesc_context *ctx __unused,
			     unsigned int count __unused,
			     int params[] __unused ) {
	/* We assume that we always clear the whole screen */
	assert ( params[0] == ANSIESC_ED_ALL );

	__asm__ __volatile__ ( REAL_CODE ( "sti\n\t"
					   "int $0x10\n\t"
					   "cli\n\t" )
			       : : "a" ( 0x0600 ), "b" ( bios_attr << 8 ),
				   "c" ( 0 ),
				   "d" ( ( ( console_height - 1 ) << 8 ) |
					 ( console_width - 1 ) ) );
}

/**
 * Handle ANSI SGR (set graphics rendition)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void bios_handle_sgr ( struct ansiesc_context *ctx __unused,
			      unsigned int count, int params[] ) {
	static const uint8_t bios_attr_fcols[10] = {
		ATTR_FCOL_BLACK, ATTR_FCOL_RED, ATTR_FCOL_GREEN,
		ATTR_FCOL_YELLOW, ATTR_FCOL_BLUE, ATTR_FCOL_MAGENTA,
		ATTR_FCOL_CYAN, ATTR_FCOL_WHITE,
		ATTR_FCOL_WHITE, ATTR_FCOL_WHITE /* defaults */
	};
	static const uint8_t bios_attr_bcols[10] = {
		ATTR_BCOL_BLACK, ATTR_BCOL_RED, ATTR_BCOL_GREEN,
		ATTR_BCOL_YELLOW, ATTR_BCOL_BLUE, ATTR_BCOL_MAGENTA,
		ATTR_BCOL_CYAN, ATTR_BCOL_WHITE,
		ATTR_BCOL_BLACK, ATTR_BCOL_BLACK /* defaults */
	};
	unsigned int i;
	int aspect;

	for ( i = 0 ; i < count ; i++ ) {
		aspect = params[i];
		if ( aspect == 0 ) {
			bios_attr = ATTR_DEFAULT;
		} else if ( aspect == 1 ) {
			bios_attr |= ATTR_BOLD;
		} else if ( aspect == 5 ) {
			bios_attr |= ATTR_BLINK;
		} else if ( aspect == 22 ) {
			bios_attr &= ~ATTR_BOLD;
		} else if ( aspect == 25 ) {
			bios_attr &= ~ATTR_BLINK;
		} else if ( ( aspect >= 30 ) && ( aspect <= 39 ) ) {
			bios_attr &= ~ATTR_FCOL_MASK;
			bios_attr |= bios_attr_fcols[ aspect - 30 ];
		} else if ( ( aspect >= 40 ) && ( aspect <= 49 ) ) {
			bios_attr &= ~ATTR_BCOL_MASK;
			bios_attr |= bios_attr_bcols[ aspect - 40 ];
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
static void bios_handle_dectcem_set ( struct ansiesc_context *ctx __unused,
				      unsigned int count __unused,
				      int params[] __unused ) {
	uint8_t height;

	/* Get character height */
	get_real ( height, BDA_SEG, BDA_CHAR_HEIGHT );

	__asm__ __volatile__ ( REAL_CODE ( "sti\n\t"
					   "int $0x10\n\t"
					   "cli\n\t" )
			       : : "a" ( 0x0100 ),
				   "c" ( ( ( height - 2 ) << 8 ) |
					 ( height - 1 ) ) );
}

/**
 * Handle ANSI DECTCEM reset (hide cursor)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void bios_handle_dectcem_reset ( struct ansiesc_context *ctx __unused,
					unsigned int count __unused,
					int params[] __unused ) {

	__asm__ __volatile__ ( REAL_CODE ( "sti\n\t"
					   "int $0x10\n\t"
					   "cli\n\t" )
			       : : "a" ( 0x0100 ), "c" ( 0x2000 ) );
}

/** BIOS console ANSI escape sequence handlers */
static struct ansiesc_handler bios_ansiesc_handlers[] = {
	{ ANSIESC_CUP, bios_handle_cup },
	{ ANSIESC_ED, bios_handle_ed },
	{ ANSIESC_SGR, bios_handle_sgr },
	{ ANSIESC_DECTCEM_SET, bios_handle_dectcem_set },
	{ ANSIESC_DECTCEM_RESET, bios_handle_dectcem_reset },
	{ 0, NULL }
};

/** BIOS console ANSI escape sequence context */
static struct ansiesc_context bios_ansiesc_ctx = {
	.handlers = bios_ansiesc_handlers,
};

/**
 * Print a character to BIOS console
 *
 * @v character		Character to be printed
 */
static void bios_putchar ( int character ) {
	int discard_a, discard_b, discard_c;

	/* Intercept ANSI escape sequences */
	character = ansiesc_process ( &bios_ansiesc_ctx, character );
	if ( character < 0 )
		return;

	/* Print character with attribute */
	__asm__ __volatile__ ( REAL_CODE ( "pushl %%ebp\n\t" /* gcc bug */
					   "sti\n\t"
					   /* Skip non-printable characters */
					   "cmpb $0x20, %%al\n\t"
					   "jb 1f\n\t"
					   /* Read attribute */
					   "movb %%al, %%cl\n\t"
					   "movb $0x08, %%ah\n\t"
					   "int $0x10\n\t"
					   "xchgb %%al, %%cl\n\t"
					   /* Skip if attribute matches */
					   "cmpb %%ah, %%bl\n\t"
					   "je 1f\n\t"
					   /* Set attribute */
					   "movw $0x0001, %%cx\n\t"
					   "movb $0x09, %%ah\n\t"
					   "int $0x10\n\t"
					   "\n1:\n\t"
					   /* Print character */
					   "xorw %%bx, %%bx\n\t"
					   "movb $0x0e, %%ah\n\t"
					   "int $0x10\n\t"
					   "cli\n\t"
					   "popl %%ebp\n\t" /* gcc bug */ )
			       : "=a" ( discard_a ), "=b" ( discard_b ),
			         "=c" ( discard_c )
			       : "a" ( character ), "b" ( bios_attr ) );
}

/**
 * Pointer to current ANSI output sequence
 *
 * While we are in the middle of returning an ANSI sequence for a
 * special key, this will point to the next character to return.  When
 * not in the middle of such a sequence, this will point to a NUL
 * (note: not "will be NULL").
 */
static const char *ansi_input = "";

/** A mapping from a BIOS scan code to an ANSI escape sequence */
#define BIOS_KEY( key, ansi ) key ansi "\0"

/** Mapping from BIOS scan codes to ANSI escape sequences */
static const char ansi_sequences[] = {
	BIOS_KEY ( "\x53", "[3~" )	/* Delete */
	BIOS_KEY ( "\x48", "[A" )	/* Up arrow */
	BIOS_KEY ( "\x50", "[B" )	/* Down arrow */
	BIOS_KEY ( "\x4b", "[D" )	/* Left arrow */
	BIOS_KEY ( "\x4d", "[C" )	/* Right arrow */
	BIOS_KEY ( "\x47", "[H" )	/* Home */
	BIOS_KEY ( "\x4f", "[F" )	/* End */
	BIOS_KEY ( "\x49", "[5~" )	/* Page up */
	BIOS_KEY ( "\x51", "[6~" )	/* Page down */
	BIOS_KEY ( "\x3f", "[15~" )	/* F5 */
	BIOS_KEY ( "\x40", "[17~" )	/* F6 */
	BIOS_KEY ( "\x41", "[18~" )	/* F7 */
	BIOS_KEY ( "\x42", "[19~" )	/* F8 (required for PXE) */
	BIOS_KEY ( "\x43", "[20~" )	/* F9 */
	BIOS_KEY ( "\x44", "[21~" )	/* F10 */
	BIOS_KEY ( "\x85", "[23~" )	/* F11 */
	BIOS_KEY ( "\x86", "[24~" )	/* F12 */
};

/**
 * Get ANSI escape sequence corresponding to BIOS scancode
 *
 * @v scancode		BIOS scancode
 * @ret ansi_seq	ANSI escape sequence, if any, otherwise NULL
 */
static const char * scancode_to_ansi_seq ( unsigned int scancode ) {
	const char *seq = ansi_sequences;

	while ( *seq ) {
		if ( *(seq++) == ( ( char ) scancode ) )
			return seq;
		seq += ( strlen ( seq ) + 1 );
	}
	DBG ( "Unrecognised BIOS scancode %02x\n", scancode );
	return NULL;
}

/**
 * Map a key
 *
 * @v character		Character read from console
 * @ret character	Mapped character
 */
static int bios_keymap ( unsigned int character ) {
	struct key_mapping *mapping;

	for_each_table_entry ( mapping, KEYMAP ) {
		if ( mapping->from == character )
			return mapping->to;
	}
	return character;
}

/**
 * Get character from BIOS console
 *
 * @ret character	Character read from console
 */
static int bios_getchar ( void ) {
	uint16_t keypress;
	unsigned int character;
	const char *ansi_seq;

	/* If we are mid-sequence, pass out the next byte */
	if ( ( character = *ansi_input ) ) {
		ansi_input++;
		return character;
	}

	/* Read character from real BIOS console */
	__asm__ __volatile__ ( REAL_CODE ( "sti\n\t"
					   "int $0x16\n\t"
					   "cli\n\t" )
			       : "=a" ( keypress ) : "a" ( 0x1000 ) );
	character = ( keypress & 0xff );

	/* If it's a normal character, just map and return it */
	if ( character && ( character < 0x80 ) )
		return bios_keymap ( character );

	/* Otherwise, check for a special key that we know about */
	if ( ( ansi_seq = scancode_to_ansi_seq ( keypress >> 8 ) ) ) {
		/* Start of escape sequence: return ESC (0x1b) */
		ansi_input = ansi_seq;
		return 0x1b;
	}

	return 0;
}

/**
 * Check for character ready to read from BIOS console
 *
 * @ret True		Character available to read
 * @ret False		No character available to read
 */
static int bios_iskey ( void ) {
	unsigned int discard_a;
	unsigned int flags;

	/* If we are mid-sequence, we are always ready */
	if ( *ansi_input )
		return 1;

	/* Otherwise check the real BIOS console */
	__asm__ __volatile__ ( REAL_CODE ( "sti\n\t"
					   "int $0x16\n\t"
					   "pushfw\n\t"
					   "popw %w0\n\t"
					   "cli\n\t" )
			       : "=r" ( flags ), "=a" ( discard_a )
			       : "a" ( 0x1100 ) );
	return ( ! ( flags & ZF ) );
}

struct console_driver bios_console __console_driver = {
	.putchar = bios_putchar,
	.getchar = bios_getchar,
	.iskey = bios_iskey,
	.usage = CONSOLE_PCBIOS,
};
