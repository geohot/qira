/*
 *   Creation Date: <2004/08/28 18:38:22 greg>
 *   Time-stamp: <2004/08/28 18:38:22 greg>
 *
 *	<pearpc.c>
 *
 *   Copyright (C) 2004, Greg Watson
 *
 *   derived from mol.c
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "kernel/kernel.h"
#include "arch/common/nvram.h"
#include "libc/vsprintf.h"
#include "libc/string.h"
#include "pearpc/pearpc.h"
#include <stdarg.h>

#define UART_BASE 0x3f8

// FIXME
unsigned long virt_offset = 0;


void
exit( int status )
{
	for (;;);
}

void
fatal_error( const char *err )
{
	printk("Fatal error: %s\n", err );
	exit(0);
}

void
panic( const char *err )
{
	printk("Panic: %s\n", err );
	exit(0);

	/* won't come here... this keeps the gcc happy */
	for( ;; )
		;
}


/************************************************************************/
/*	print using OSI interface					*/
/************************************************************************/

static int do_indent;

int
printk( const char *fmt, ... )
{
        char *p, buf[1024];
	va_list args;
	int i;

	va_start(args, fmt);
        i = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	for( p=buf; *p; p++ ) {
		if( *p == '\n' )
			do_indent = 0;
		if( do_indent++ == 1 ) {
			putchar( '>' );
			putchar( '>' );
			putchar( ' ' );
		}
		putchar( *p );
	}
	return i;
}


/************************************************************************/
/*	TTY iface							*/
/************************************************************************/

static int ttychar = -1;

static int
tty_avail( void )
{
	return 1;
}

static int
tty_putchar( int c )
{
	if( tty_avail() ) {
		while (!(inb(UART_BASE + 0x05) & 0x20))
			;
		outb(c, UART_BASE);
		while (!(inb(UART_BASE + 0x05) & 0x40))
			;
	}
	return c;
}

int
availchar( void )
{
	if( !tty_avail() )
		return 0;

	if( ttychar < 0 )
		ttychar = inb(UART_BASE);
	return (ttychar >= 0);
}

int
getchar( void )
{
	int ch;

	if( !tty_avail() )
		return 0;

	if( ttychar < 0 )
		return inb(UART_BASE);
	ch = ttychar;
	ttychar = -1;
	return ch;
}

int
putchar( int c )
{
	if (c == '\n')
		tty_putchar('\r');
	return tty_putchar(c);
}


/************************************************************************/
/*	briQ specific stuff						*/
/************************************************************************/

#define IO_NVRAM_PA_START 0x80860000
#define IO_NVRAM_PA_END 0x80880000

static char *nvram=(char *)IO_NVRAM_PA_START;

void
dump_nvram(void)
{
  static char hexdigit[] = "0123456789abcdef";
  int i;
  for (i = 0; i < 16*4; i++)
    {
      printk ("%c", hexdigit[nvram[i<<4] >> 4]);
      printk ("%c", hexdigit[nvram[i<<4] % 16]);
      if (!((i + 1) % 16))
        {
          printk ("\n");
        }
      else
        {
          printk (" ");
        }
    }
}


int
arch_nvram_size( void )
{
	return (IO_NVRAM_PA_END-IO_NVRAM_PA_START)>>4;
}

void
arch_nvram_put( char *buf )
{
	int i;
	for (i=0; i<(IO_NVRAM_PA_END-IO_NVRAM_PA_START)>>4; i++)
		nvram[i<<4]=buf[i];
	// memcpy(nvram, buf, IO_NVRAM_PA_END-IO_NVRAM_PA_START);
	printk("new nvram:\n");
	dump_nvram();
}

void
arch_nvram_get( char *buf )
{
	int i;
	for (i=0; i<(IO_NVRAM_PA_END-IO_NVRAM_PA_START)>>4; i++)
		buf[i]=nvram[i<<4];

	//memcpy(buf, nvram, IO_NVRAM_PA_END-IO_NVRAM_PA_START);
	printk("current nvram:\n");
	dump_nvram();
}
