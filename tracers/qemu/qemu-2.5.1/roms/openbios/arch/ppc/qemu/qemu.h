/*
 *   Creation Date: <2004/08/28 17:50:12 stepan>
 *   Time-stamp: <2004/08/28 17:50:12 stepan>
 *
 *	<qemu.h>
 *
 *   Copyright (C) 2005 Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#ifndef _H_QEMU
#define _H_QEMU

/* vfd.c */
extern int		vfd_draw_str( const char *str );
extern void		vfd_close( void );

#include "kernel.h"

#endif   /* _H_QEMU */
