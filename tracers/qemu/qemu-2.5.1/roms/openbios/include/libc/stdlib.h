/*
 *   Creation Date: <2003/12/19 18:52:20 samuel>
 *   Time-stamp: <2003/12/19 18:52:21 samuel>
 *
 *	<stdlib.h>
 *
 *
 *   Copyright (C) 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#ifndef _H_STDLIB
#define _H_STDLIB

extern void	*malloc( int size );
extern void	free( void *ptr );
extern void	*realloc( void *ptr, size_t size );

/* should perhaps go somewhere else... */
extern void	qsort( void *base, size_t nmemb, size_t size, int (*compar)(const void*, const void*));

#endif   /* _H_STDLIB */
