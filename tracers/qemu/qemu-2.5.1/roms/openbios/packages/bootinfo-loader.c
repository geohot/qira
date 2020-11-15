/*
 *
 *       <bootinfo-loader.c>
 *
 *       bootinfo file loader
 *
 *   Copyright (C) 2009 Laurent Vivier (Laurent@vivier.eu)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/bootinfo_load.h"
#include "packages.h"

DECLARE_NODE(bootinfo_loader, INSTALL_OPEN, 0, "+/packages/bootinfo-loader" );

NODE_METHODS( bootinfo_loader ) = {
	{ "init-program", bootinfo_init_program },
};

void bootinfo_loader_init( void )
{
	REGISTER_NODE( bootinfo_loader );
}
