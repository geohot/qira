/*
 *   Creation Date: <2003/12/20 01:04:25 samuel>
 *   Time-stamp: <2004/01/07 19:59:11 samuel>
 *
 *	<nvram.h>
 *
 *	arch NVRAM interface
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#ifndef _H_NVRAM
#define _H_NVRAM

extern int	arch_nvram_size( void );
extern void	arch_nvram_get( char *buf );
extern void	arch_nvram_put( char *buf );

#endif   /* _H_NVRAM */
