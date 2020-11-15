/*
 * <stdio.h>
 *
 * Open Hack'Ware BIOS: subset of POSIX stdio definitions
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if !defined (__OHW_STDIO_H__)
#define __OHW_STDIO_H__

/* va_list is defined here */
#include <stdarg.h>
/* size_t is defined here */
#include <stddef.h>

#define EOF ((int)-1)

int printf (const char *format, ...);
int dprintf (const char *format, ...);
int sprintf (char *str, const char *format, ...);
int snprintf (char *str, size_t size, const char *format, ...);
int vprintf (const char *format, va_list ap);
int vdprintf (const char *format, va_list ap);
int vsprintf (char *str, const char *format, va_list ap);
int vsnprintf (char *str, size_t size, const char *format, va_list ap);

int rename (const char *oldpath, const char *newpath);

#endif /* !defined (__OHW_STDIO_H__) */
