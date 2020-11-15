/*
 *
 *       <elf-loader.c>
 *
 *       ELF file loader
 *
 *   Copyright (C) 2009 Laurent Vivier (Laurent@vivier.eu)
 *
 *   Some parts Copyright (C) 2002, 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/elf_load.h"
#include "packages.h"

DECLARE_NODE(elf_loader, INSTALL_OPEN, 0, "+/packages/elf-loader" );

NODE_METHODS( elf_loader ) = {
	{ "init-program", elf_init_program },
};

void elf_loader_init( void )
{
	REGISTER_NODE( elf_loader );
}
