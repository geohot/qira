/*****************************************************************************

       Copyright © 1995, 1996 Digital Equipment Corporation,
                       Maynard, Massachusetts.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, provided  
that the copyright notice and this permission notice appear in all copies  
of software and supporting documentation, and that the name of Digital not  
be used in advertising or publicity pertaining to distribution of the software 
without specific, written prior permission. Digital grants this permission 
provided that you prominently mark, as not part of the original, any 
modifications made to this software or documentation.

Digital Equipment Corporation disclaims all warranties and/or guarantees  
with regard to this software, including all implied warranties of fitness for 
a particular purpose and merchantability, and makes no representations 
regarding the use of, or the results of the use of, the software and 
documentation in terms of correctness, accuracy, reliability, currentness or
otherwise; and you rely on the software, documentation and results solely at 
your own risk. 

******************************************************************************/

/*
 * david.rusling@reo.mts.dec.com
 *
 * Modified for QEMU PALcode by rth@twiddle.net.
 */

#include "protos.h"
#include "uart.h"

#ifndef SERIAL_SPEED
#define SERIAL_SPEED 9600
#endif

int
uart_charav(int offset)
{
	return inb(com2Lsr + offset) & 1;
}

int
uart_getchar(int offset)
{
	/* If interrupts are enabled, use wtint assuming that either the
	   device itself will wake us, or that a clock interrupt will.  */
	if ((rdps() & 7) == 0) {
	    while (!uart_charav(offset)) {
		wtint(0);
	    }
	} else {
	    while (!uart_charav(offset))
	        continue;
	}

	return inb(com2Rbr + offset);
}

void
uart_putchar_raw(int offset, char c)
{
	while ((inb(com2Lsr + offset) & 0x20) == 0)
		continue;
	outb(c, com2Thr + offset);
}

void
uart_putchar(int offset, char c)
{
	if (c == '\n')
		uart_putchar_raw(offset, '\r');
	uart_putchar_raw(offset, c);
}

void
uart_puts(int offset, const char *s)
{
	while (*s != '\0')
		uart_putchar(offset, *s++);
}

void
uart_init_line(int offset, int baud)
{
	int i;
	int baudconst;

	switch (baud) {
	case 56000:
		baudconst = 2;
		break;
	case 38400:
		baudconst = 3;
		break;
	case 19200:
		baudconst = 6;
		break;
	case 9600:
		baudconst = 12;
		break;
	case 4800:
		baudconst = 24;
		break;
	case 2400:
		baudconst = 48;
		break;
	case 1200:
		baudconst = 96;
		break;
	case 300:
		baudconst = 384;
		break;
	case 150:
		baudconst = 768;
		break;
	default:
		baudconst = 12;
		break;
	}


	outb(0x87, com2Lcr + offset);
	outb(0, com2Dlm + offset);
	outb(baudconst, com2Dll + offset);
	outb(0x07, com2Lcr + offset);
	outb(0x0F, com2Mcr + offset);

	for (i = 10; i > 0; i--) {
		if (inb(com2Lsr + offset) == 0)
			break;
		inb(com2Rbr + offset);
	}
}

void uart_init(void)
{
	uart_init_line(COM1, SERIAL_SPEED);
	/* uart_init_line(COM2, SERIAL_SPEED); */
}
