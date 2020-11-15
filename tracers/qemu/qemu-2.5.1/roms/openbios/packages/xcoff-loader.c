/*
 *
 *       <xcoff-loader.c>
 *
 *       XCOFF file loader
 *
 *   Copyright (C) 2009 Laurent Vivier (Laurent@vivier.eu)
 *
 *   from original XCOFF loader by Steven Noonan <steven@uplinklabs.net>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/xcoff_load.h"
#include "packages.h"

DECLARE_NODE(xcoff_loader, INSTALL_OPEN, 0, "+/packages/xcoff-loader" );

NODE_METHODS( xcoff_loader ) = {
	{ "init-program", xcoff_init_program },
};

void xcoff_loader_init( void )
{
	REGISTER_NODE( xcoff_loader );
}
