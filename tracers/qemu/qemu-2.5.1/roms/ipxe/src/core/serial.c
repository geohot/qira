/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Serial console
 *
 */

#include <stddef.h>
#include <ipxe/init.h>
#include <ipxe/uart.h>
#include <ipxe/console.h>
#include <ipxe/serial.h>
#include <config/console.h>
#include <config/serial.h>

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_SERIAL ) && CONSOLE_EXPLICIT ( CONSOLE_SERIAL ) )
#undef CONSOLE_SERIAL
#define CONSOLE_SERIAL ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_LOG )
#endif

/* UART port number */
#ifdef COMCONSOLE
#define CONSOLE_PORT COMCONSOLE
#else
#define CONSOLE_PORT 0
#endif

/* UART baud rate */
#ifdef COMPRESERVE
#define CONSOLE_BAUD 0
#else
#define CONSOLE_BAUD COMSPEED
#endif

/* UART line control register value */
#ifdef COMPRESERVE
#define CONSOLE_LCR 0
#else
#define CONSOLE_LCR UART_LCR_WPS ( COMDATA, COMPARITY, COMSTOP )
#endif

/** Serial console UART */
struct uart serial_console;

/**
 * Print a character to serial console
 *
 * @v character		Character to be printed
 */
static void serial_putchar ( int character ) {

	/* Do nothing if we have no UART */
	if ( ! serial_console.base )
		return;

	/* Transmit character */
	uart_transmit ( &serial_console, character );
}

/**
 * Get character from serial console
 *
 * @ret character	Character read from console
 */
static int serial_getchar ( void ) {
	uint8_t data;

	/* Do nothing if we have no UART */
	if ( ! serial_console.base )
		return 0;

	/* Wait for data to be ready */
	while ( ! uart_data_ready ( &serial_console ) ) {}

	/* Receive data */
	data = uart_receive ( &serial_console );

	/* Strip any high bit and convert DEL to backspace */
	data &= 0x7f;
	if ( data == 0x7f )
		data = 0x08;

	return data;
}

/**
 * Check for character ready to read from serial console
 *
 * @ret True		Character available to read
 * @ret False		No character available to read
 */
static int serial_iskey ( void ) {

	/* Do nothing if we have no UART */
	if ( ! serial_console.base )
		return 0;

	/* Check UART */
	return uart_data_ready ( &serial_console );
}

/** Serial console */
struct console_driver serial_console_driver __console_driver = {
	.putchar = serial_putchar,
	.getchar = serial_getchar,
	.iskey = serial_iskey,
	.usage = CONSOLE_SERIAL,
};

/** Initialise serial console */
static void serial_init ( void ) {
	int rc;

	/* Do nothing if we have no default port */
	if ( ! CONSOLE_PORT )
		return;

	/* Select UART */
	if ( ( rc = uart_select ( &serial_console, CONSOLE_PORT ) ) != 0 ) {
		DBG ( "Could not select UART %d: %s\n",
		      CONSOLE_PORT, strerror ( rc ) );
		return;
	}

	/* Initialise UART */
	if ( ( rc = uart_init ( &serial_console, CONSOLE_BAUD,
				CONSOLE_LCR ) ) != 0 ) {
		DBG ( "Could not initialise UART %d baud %d LCR %#02x: %s\n",
		      CONSOLE_PORT, CONSOLE_BAUD, CONSOLE_LCR, strerror ( rc ));
		return;
	}
}

/**
 * Shut down serial console
 *
 * @v flags		Shutdown flags
 */
static void serial_shutdown ( int flags __unused ) {

	/* Do nothing if we have no UART */
	if ( ! serial_console.base )
		return;

	/* Flush any pending output */
	uart_flush ( &serial_console );

	/* Leave console enabled; it's still usable */
}

/** Serial console initialisation function */
struct init_fn serial_console_init_fn __init_fn ( INIT_CONSOLE ) = {
	.initialise = serial_init,
};

/** Serial console startup function */
struct startup_fn serial_startup_fn __startup_fn ( STARTUP_EARLY ) = {
	.shutdown = serial_shutdown,
};
