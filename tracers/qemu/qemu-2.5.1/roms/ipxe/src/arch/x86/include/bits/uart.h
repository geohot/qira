#ifndef _BITS_UART_H
#define _BITS_UART_H

/** @file
 *
 * 16550-compatible UART
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/io.h>

/**
 * Write to UART register
 *
 * @v uart		UART
 * @v addr		Register address
 * @v data		Data
 */
static inline __attribute__ (( always_inline )) void
uart_write ( struct uart *uart, unsigned int addr, uint8_t data ) {
	outb ( data, ( uart->base + addr ) );
}

/**
 * Read from UART register
 *
 * @v uart		UART
 * @v addr		Register address
 * @ret data		Data
 */
static inline __attribute__ (( always_inline )) uint8_t
uart_read ( struct uart *uart, unsigned int addr ) {
	return inb ( uart->base + addr );
}

extern int uart_select ( struct uart *uart, unsigned int port );

#endif /* _BITS_UART_H */
