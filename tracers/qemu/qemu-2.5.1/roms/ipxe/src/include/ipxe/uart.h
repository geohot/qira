#ifndef _IPXE_UART_H
#define _IPXE_UART_H

/** @file
 *
 * 16550-compatible UART
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/** Transmitter holding register */
#define UART_THR 0x00

/** Receiver buffer register */
#define UART_RBR 0x00

/** Interrupt enable register */
#define UART_IER 0x01

/** FIFO control register */
#define UART_FCR 0x02
#define UART_FCR_FE	0x01	/**< FIFO enable */

/** Line control register */
#define UART_LCR 0x03
#define UART_LCR_WLS0	0x01	/**< Word length select bit 0 */
#define UART_LCR_WLS1	0x02	/**< Word length select bit 1 */
#define UART_LCR_STB	0x04	/**< Number of stop bits */
#define UART_LCR_PEN	0x08	/**< Parity enable */
#define UART_LCR_EPS	0x10	/**< Even parity select */
#define UART_LCR_DLAB	0x80	/**< Divisor latch access bit */

#define UART_LCR_WORD_LEN(x)	( ( (x) - 5 ) << 0 )	/**< Word length */
#define UART_LCR_STOP_BITS(x)	( ( (x) - 1 ) << 2 )	/**< Stop bits */
#define UART_LCR_PARITY(x)	( ( (x) - 0 ) << 3 )	/**< Parity */

/**
 * Calculate line control register value
 *
 * @v word_len		Word length (5-8)
 * @v parity		Parity (0=none, 1=odd, 3=even)
 * @v stop_bits		Stop bits (1-2)
 * @ret lcr		Line control register value
 */
#define UART_LCR_WPS( word_len, parity, stop_bits )	\
	( UART_LCR_WORD_LEN ( (word_len) ) |		\
	  UART_LCR_PARITY ( (parity) ) |		\
	  UART_LCR_STOP_BITS ( (stop_bits) ) )

/** Default LCR value: 8 data bits, no parity, one stop bit */
#define UART_LCR_8N1 UART_LCR_WPS ( 8, 0, 1 )

/** Modem control register */
#define UART_MCR 0x04
#define UART_MCR_DTR	0x01	/**< Data terminal ready */
#define UART_MCR_RTS	0x02	/**< Request to send */

/** Line status register */
#define UART_LSR 0x05
#define UART_LSR_DR	0x01	/**< Data ready */
#define UART_LSR_THRE	0x20	/**< Transmitter holding register empty */
#define UART_LSR_TEMT	0x40	/**< Transmitter empty */

/** Scratch register */
#define UART_SCR 0x07

/** Divisor latch (least significant byte) */
#define UART_DLL 0x00

/** Divisor latch (most significant byte) */
#define UART_DLM 0x01

/** Maximum baud rate */
#define UART_MAX_BAUD 115200

/** A 16550-compatible UART */
struct uart {
	/** I/O port base address */
	void *base;
	/** Baud rate divisor */
	uint16_t divisor;
	/** Line control register */
	uint8_t lcr;
};

/** Symbolic names for port indexes */
enum uart_port {
	COM1 = 1,
	COM2 = 2,
	COM3 = 3,
	COM4 = 4,
};

#include <bits/uart.h>

void uart_write ( struct uart *uart, unsigned int addr, uint8_t data );
uint8_t uart_read ( struct uart *uart, unsigned int addr );
int uart_select ( struct uart *uart, unsigned int port );

/**
 * Check if received data is ready
 *
 * @v uart		UART
 * @ret ready		Data is ready
 */
static inline int uart_data_ready ( struct uart *uart ) {
	uint8_t lsr;

	lsr = uart_read ( uart, UART_LSR );
	return ( lsr & UART_LSR_DR );
}

/**
 * Receive data
 *
 * @v uart		UART
 * @ret data		Data
 */
static inline uint8_t uart_receive ( struct uart *uart ) {

	return uart_read ( uart, UART_RBR );
}

extern void uart_transmit ( struct uart *uart, uint8_t data );
extern void uart_flush ( struct uart *uart );
extern int uart_exists ( struct uart *uart );
extern int uart_init ( struct uart *uart, unsigned int baud, uint8_t lcr );

#endif /* _IPXE_UART_H */
