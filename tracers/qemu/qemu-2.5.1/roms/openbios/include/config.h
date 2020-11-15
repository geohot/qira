/*
 *   Creation Date: <2003/12/20 00:07:16 samuel>
 *   Time-stamp: <2004/01/19 17:40:26 stepan>
 *
 *	<config.h>
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

#ifndef _H_CONFIG
#define _H_CONFIG

#include "autoconf.h"
#include "mconfig.h"
#include "asm/types.h"

#define PROGRAM_NAME "OpenBIOS"

#ifndef BOOTSTRAP

#ifndef NULL
#define	NULL		((void*)0)
#endif

typedef unsigned int	size_t;
typedef unsigned int	usize_t;
typedef signed int	ssize_t;
typedef signed int	off_t;

typedef unsigned int	time_t;

#define UINT_MAX	((unsigned int)-1)

#define ENOMEM		1
#define EIO		2
#define EINVAL		3
#define ENOENT		4
#define ENOTDIR		5
#define EISDIR		6
#define ENAMETOOLONG	7

#define SEEK_CUR	1
#define SEEK_SET	2
#define SEEK_END	3

#endif /* BOOTSTRAP */

#include "sysinclude.h"

#ifndef MIN
#define MIN(x,y)	(((x) < (y)) ? (x) : (y))
#define MAX(x,y)	(((x) > (y)) ? (x) : (y))
#endif

/* errno is a macro on some systems, which might cause nasty problems.
 * We try to cope with this here.
 */
#undef errno
#define errno errno_int

#endif   /* _H_CONFIG */
