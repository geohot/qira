/*
 *   Creation Date: <2003/10/18 13:52:32 samuel>
 *   Time-stamp: <2003/10/18 13:54:24 samuel>
 *
 *	<extra.c>
 *
 *	Libc extras
 *
 *   Copyright (C) 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libc/string.h"
#include "libc/vsprintf.h"
#include "libopenbios/bindings.h"

/* strncpy without 0-pad */
char *
strncpy_nopad( char *dest, const char *src, size_t n )
{
	int len = MIN( n, strlen(src)+1 );
	return memcpy( dest, src, len );
}

/* printf */

int forth_printf( const char *fmt, ... )
{
	char buf[512];
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	PUSH(pointer2cell(buf));
	PUSH(i);
	fword("type");

	return i;
}


