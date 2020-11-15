/*
 *   Creation Date: <2003/12/19 18:46:21 samuel>
 *   Time-stamp: <2004/04/12 16:27:12 samuel>
 *
 *	<mol.c>
 *
 *
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
#include "mol/mol.h"
#include "osi_calls.h"
#include <stdarg.h>

void
exit( int status )
{
	OSI_Exit();
}

void
fatal_error( const char *err )
{
	printk("Fatal error: %s\n", err );
	OSI_Exit();
}

void
panic( const char *err )
{
	printk("Panic: %s\n", err );
	OSI_Exit();

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
        i = vnsprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	for( p=buf; *p; p++ ) {
		if( *p == '\n' )
			do_indent = 0;
		if( do_indent++ == 1 ) {
			OSI_PutC( '>' );
			OSI_PutC( '>' );
			OSI_PutC( ' ' );
		}
		OSI_PutC( *p );
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
	return OSI_CallAvailable( OSI_TTY_GETC );
}

int
availchar( void )
{
	if( !tty_avail() )
		return 0;

	if( ttychar < 0 )
		ttychar = OSI_TTYGetc();
	if( ttychar < 0 )
		OSI_USleep(1);
	return (ttychar >= 0);
}

int
getchar( void )
{
	int ch;

	if( !tty_avail() )
		return 0;

	if( ttychar < 0 )
		return OSI_TTYGetc();
	ch = ttychar;
	ttychar = -1;
	return ch;
}

int
putchar( int c )
{
	printk("%c", c );

	if( tty_avail() )
		OSI_TTYPutc( c );
	return c;
}


/************************************************************************/
/*	MOL specific stuff						*/
/************************************************************************/

int
arch_nvram_size( void )
{
	return OSI_NVRamSize();
}

void
arch_nvram_put( char *buf )
{
	int i, size = arch_nvram_size();

	for( i=0; i<size; i++ )
		OSI_WriteNVRamByte( i, buf[i] );
}

void
arch_nvram_get( char *buf )
{
	int i, size = arch_nvram_size();

	/* support for zapping the nvram */
	if( get_bool_res("zap_nvram") == 1 ) {
		memset( buf, 0, size );
		return;
	}

	for( i=0; i<size; i++ )
		buf[i] = OSI_ReadNVRamByte( i );
}
