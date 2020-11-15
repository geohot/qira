/* lib.c
 * tag: simple function library
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "asm/types.h"
#include <stdarg.h>
#include "libc/stdlib.h"
#include "libc/vsprintf.h"
#include "kernel/kernel.h"

/* Format a string and print it on the screen, just like the libc
 * function printf.
 */
int printk( const char *fmt, ... )
{
        char *p, buf[512];
	va_list args;
	int i;

	va_start(args, fmt);
        i = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	for( p=buf; *p; p++ )
		putchar(*p);
	return i;
}

// dumb quick memory allocator until we get a decent thing here.

#define MEMSIZE 128*1024
static char memory[MEMSIZE];
static void *memptr=memory;
static int memsize=MEMSIZE;

void *malloc(int size)
{
	void *ret=(void *)0;
	if(memsize>=size) {
		memsize-=size;
		ret=memptr;
		memptr = (void *)((unsigned long)memptr + size);
	}
	return ret;
}

void free(void *ptr)
{
	/* Nothing yet */
}
