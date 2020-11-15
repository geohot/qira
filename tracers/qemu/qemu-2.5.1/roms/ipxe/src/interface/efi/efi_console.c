/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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

FILE_LICENCE ( GPL2_OR_LATER );

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/ConsoleControl/ConsoleControl.h>
#include <ipxe/ansiesc.h>
#include <ipxe/console.h>
#include <ipxe/init.h>
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
#if ! ( defined ( CONSOLE_EFI ) && CONSOLE_EXPLICIT ( CONSOLE_EFI ) )
#undef CONSOLE_EFI
#define CONSOLE_EFI ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_LOG )
#endif

/** Current character attribute */
static unsigned int efi_attr = ATTR_DEFAULT;

/** Console control protocol */
static EFI_CONSOLE_CONTROL_PROTOCOL *conctrl;
EFI_REQUEST_PROTOCOL ( EFI_CONSOLE_CONTROL_PROTOCOL, &conctrl );

/**
 * Handle ANSI CUP (cursor position)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params[0]		Row (1 is top)
 * @v params[1]		Column (1 is left)
 */
static void efi_handle_cup ( struct ansiesc_context *ctx __unused,
			     unsigned int count __unused, int params[] ) {
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout = efi_systab->ConOut;
	int cx = ( params[1] - 1 );
	int cy = ( params[0] - 1 );

	if ( cx < 0 )
		cx = 0;
	if ( cy < 0 )
		cy = 0;

	conout->SetCursorPosition ( conout, cx, cy );
}

/**
 * Handle ANSI ED (erase in page)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params[0]		Region to erase
 */
static void efi_handle_ed ( struct ansiesc_context *ctx __unused,
			    unsigned int count __unused,
			    int params[] __unused ) {
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout = efi_systab->ConOut;

	/* We assume that we always clear the whole screen */
	assert ( params[0] == ANSIESC_ED_ALL );

	conout->ClearScreen ( conout );
}

/**
 * Handle ANSI SGR (set graphics rendition)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void efi_handle_sgr ( struct ansiesc_context *ctx __unused,
			     unsigned int count, int params[] ) {
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout = efi_systab->ConOut;
	static const uint8_t efi_attr_fcols[10] = {
		ATTR_FCOL_BLACK, ATTR_FCOL_RED, ATTR_FCOL_GREEN,
		ATTR_FCOL_YELLOW, ATTR_FCOL_BLUE, ATTR_FCOL_MAGENTA,
		ATTR_FCOL_CYAN, ATTR_FCOL_WHITE,
		ATTR_FCOL_WHITE, ATTR_FCOL_WHITE /* defaults */
	};
	static const uint8_t efi_attr_bcols[10] = {
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
			efi_attr = ATTR_DEFAULT;
		} else if ( aspect == 1 ) {
			efi_attr |= ATTR_BOLD;
		} else if ( aspect == 22 ) {
			efi_attr &= ~ATTR_BOLD;
		} else if ( ( aspect >= 30 ) && ( aspect <= 39 ) ) {
			efi_attr &= ~ATTR_FCOL_MASK;
			efi_attr |= efi_attr_fcols[ aspect - 30 ];
		} else if ( ( aspect >= 40 ) && ( aspect <= 49 ) ) {
			efi_attr &= ~ATTR_BCOL_MASK;
			efi_attr |= efi_attr_bcols[ aspect - 40 ];
		}
	}

	conout->SetAttribute ( conout, efi_attr );
}

/**
 * Handle ANSI DECTCEM set (show cursor)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void efi_handle_dectcem_set ( struct ansiesc_context *ctx __unused,
				     unsigned int count __unused,
				     int params[] __unused ) {
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout = efi_systab->ConOut;

	conout->EnableCursor ( conout, TRUE );
}

/**
 * Handle ANSI DECTCEM reset (hide cursor)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void efi_handle_dectcem_reset ( struct ansiesc_context *ctx __unused,
				       unsigned int count __unused,
				       int params[] __unused ) {
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout = efi_systab->ConOut;

	conout->EnableCursor ( conout, FALSE );
}

/** EFI console ANSI escape sequence handlers */
static struct ansiesc_handler efi_ansiesc_handlers[] = {
	{ ANSIESC_CUP, efi_handle_cup },
	{ ANSIESC_ED, efi_handle_ed },
	{ ANSIESC_SGR, efi_handle_sgr },
	{ ANSIESC_DECTCEM_SET, efi_handle_dectcem_set },
	{ ANSIESC_DECTCEM_RESET, efi_handle_dectcem_reset },
	{ 0, NULL }
};

/** EFI console ANSI escape sequence context */
static struct ansiesc_context efi_ansiesc_ctx = {
	.handlers = efi_ansiesc_handlers,
};

/**
 * Print a character to EFI console
 *
 * @v character		Character to be printed
 */
static void efi_putchar ( int character ) {
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout = efi_systab->ConOut;
	wchar_t wstr[] = { character, 0 };

	/* Intercept ANSI escape sequences */
	character = ansiesc_process ( &efi_ansiesc_ctx, character );
	if ( character < 0 )
		return;

	conout->OutputString ( conout, wstr );
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

/** Mapping from EFI scan codes to ANSI escape sequences */
static const char *ansi_sequences[] = {
	[SCAN_UP] = "[A",
	[SCAN_DOWN] = "[B",
	[SCAN_RIGHT] = "[C",
	[SCAN_LEFT] = "[D",
	[SCAN_HOME] = "[H",
	[SCAN_END] = "[F",
	[SCAN_INSERT] = "[2~",
	/* EFI translates an incoming backspace via the serial console
	 * into a SCAN_DELETE.  There's not much we can do about this.
	 */
	[SCAN_DELETE] = "[3~",
	[SCAN_PAGE_UP] = "[5~",
	[SCAN_PAGE_DOWN] = "[6~",
	/* EFI translates some (but not all) incoming escape sequences
	 * via the serial console into equivalent scancodes.  When it
	 * doesn't recognise a sequence, it helpfully(!) translates
	 * the initial ESC and passes the remainder through verbatim.
	 * Treating SCAN_ESC as equivalent to an empty escape sequence
	 * works around this bug.
	 */
	[SCAN_ESC] = "",
};

/**
 * Get ANSI escape sequence corresponding to EFI scancode
 *
 * @v scancode		EFI scancode
 * @ret ansi_seq	ANSI escape sequence, if any, otherwise NULL
 */
static const char * scancode_to_ansi_seq ( unsigned int scancode ) {
	if ( scancode < ( sizeof ( ansi_sequences ) /
			  sizeof ( ansi_sequences[0] ) ) ) {
		return ansi_sequences[scancode];
	}
	return NULL;
}

/**
 * Get character from EFI console
 *
 * @ret character	Character read from console
 */
static int efi_getchar ( void ) {
	EFI_SIMPLE_TEXT_INPUT_PROTOCOL *conin = efi_systab->ConIn;
	const char *ansi_seq;
	EFI_INPUT_KEY key;
	EFI_STATUS efirc;
	int rc;

	/* If we are mid-sequence, pass out the next byte */
	if ( *ansi_input )
		return *(ansi_input++);

	/* Read key from real EFI console */
	if ( ( efirc = conin->ReadKeyStroke ( conin, &key ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBG ( "EFI could not read keystroke: %s\n", strerror ( rc ) );
		return 0;
	}
	DBG2 ( "EFI read key stroke with unicode %04x scancode %04x\n",
	       key.UnicodeChar, key.ScanCode );

	/* If key has a Unicode representation, return it */
	if ( key.UnicodeChar )
		return key.UnicodeChar;

	/* Otherwise, check for a special key that we know about */
	if ( ( ansi_seq = scancode_to_ansi_seq ( key.ScanCode ) ) ) {
		/* Start of escape sequence: return ESC (0x1b) */
		ansi_input = ansi_seq;
		return 0x1b;
	}

	return 0;
}

/**
 * Check for character ready to read from EFI console
 *
 * @ret True		Character available to read
 * @ret False		No character available to read
 */
static int efi_iskey ( void ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_SIMPLE_TEXT_INPUT_PROTOCOL *conin = efi_systab->ConIn;
	EFI_STATUS efirc;

	/* If we are mid-sequence, we are always ready */
	if ( *ansi_input )
		return 1;

	/* Check to see if the WaitForKey event has fired */
	if ( ( efirc = bs->CheckEvent ( conin->WaitForKey ) ) == 0 )
		return 1;

	return 0;
}

/** EFI console driver */
struct console_driver efi_console __console_driver = {
	.putchar = efi_putchar,
	.getchar = efi_getchar,
	.iskey = efi_iskey,
	.usage = CONSOLE_EFI,
};

/**
 * Initialise EFI console
 *
 */
static void efi_console_init ( void ) {
	EFI_CONSOLE_CONTROL_SCREEN_MODE mode;

	/* On some older EFI 1.10 implementations, we must use the
	 * (now obsolete) EFI_CONSOLE_CONTROL_PROTOCOL to switch the
	 * console into text mode.
	 */
	if ( conctrl ) {
		conctrl->GetMode ( conctrl, &mode, NULL, NULL );
		if ( mode != EfiConsoleControlScreenText ) {
			conctrl->SetMode ( conctrl,
					   EfiConsoleControlScreenText );
		}
	}
}

/**
 * EFI console initialisation function
 */
struct init_fn efi_console_init_fn __init_fn ( INIT_EARLY ) = {
	.initialise = efi_console_init,
};
