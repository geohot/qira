/*
 *   Creation Date: <2004/08/28 17:29:43 greg>
 *   Time-stamp: <2004/08/28 17:29:43 greg>
 *
 *	<vfd.c>
 *
 *	Simple text console
 *
 *   Copyright (C) 2004 Greg Watson
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "pearpc/pearpc.h"

static int vfd_is_open;

static int
vfd_init( void )
{
	vfd_is_open = 1;
	return 0;
}

void
vfd_close( void )
{
}

int
vfd_draw_str( const char *str )
{
	if (!vfd_is_open)
		vfd_init();

	return 0;
}
