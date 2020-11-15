/*
 *   Creation Date: <2004/08/28 18:38:22 greg>
 *   Time-stamp: <2004/08/28 18:38:22 greg>
 *
 *	<qemu.c>
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
#include "libopenbios/bindings.h"
#include "drivers/drivers.h"
#include "libc/vsprintf.h"
#include "libc/string.h"
#include "libc/byteorder.h"
#include "qemu/qemu.h"
#include <stdarg.h>

//#define DUMP_NVRAM

unsigned long virt_offset = 0;

void
exit( int status __attribute__ ((unused)))
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
}

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

int arch_nvram_size(void)
{
    if (is_apple()) {
        return macio_get_nvram_size();
    } else {
        // not implemented
    }
    return 0;
}

void arch_nvram_put(char *buf)
{
    if (is_apple()) {
        macio_nvram_put(buf);
    } else {
        // not implemented
    }
}

void arch_nvram_get(char *buf)
{
    if (is_apple()) {
        macio_nvram_get(buf);
    } else {
        // not implemented
    }
}
