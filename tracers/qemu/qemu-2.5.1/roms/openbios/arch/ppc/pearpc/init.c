/*
 *   Creation Date: <2004/08/28 18:38:22 greg>
 *   Time-stamp: <2004/08/28 18:38:22 greg>
 *
 *	<init.c>
 *
 *	Initialization for pearpc
 *
 *   Copyright (C) 2004 Greg Watson
 *   Copyright (C) 2005 Stefan Reinauer
 *
 *   based on mol/init.c:
 *
 *   Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004 Samuel & David Rydh
 *      (samuel@ibrium.se, dary@lindesign.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/openbios.h"
#include "libopenbios/bindings.h"
#include "arch/common/nvram.h"
#include "pearpc/pearpc.h"
#include "libopenbios/ofmem.h"
#include "openbios-version.h"

extern void unexpected_excep( int vector );
extern void ob_pci_init( void );
extern void ob_adb_init( void );
extern void setup_timers( void );

#if 0
int
get_bool_res( const char *res )
{
	char buf[8], *p;

	p = BootHGetStrRes( res, buf, sizeof(buf) );
	if( !p )
		return -1;
	if( !strcasecmp(p,"true") || !strcasecmp(p,"yes") || !strcasecmp(p,"1") )
		return 1;
	return 0;
}
#endif

void
unexpected_excep( int vector )
{
	printk("openbios panic: Unexpected exception %x\n", vector );
	for( ;; )
		;
}

unsigned long isa_io_base;

void
entry( void )
{
	isa_io_base = 0x80000000;

	printk("\n");
	printk("=============================================================\n");
        printk(PROGRAM_NAME " " OPENBIOS_VERSION_STR " [%s]\n",
               OPENBIOS_BUILD_DATE);

	ofmem_init();
	initialize_forth();
	/* won't return */

	printk("of_startup returned!\n");
	for( ;; )
		;
}

static void
setenv( char *env, char *value )
{
	push_str( value );
	push_str( env );
	fword("$setenv");
}

void
arch_of_init( void )
{
#if CONFIG_RTAS
	phandle_t ph;
#endif
	int autoboot;

	devtree_init();
	nvram_init("/pci/mac-io/nvram");
	openbios_init();
	modules_init();
        setup_timers();
#ifdef CONFIG_DRIVER_PCI
	ob_pci_init();
#endif
	node_methods_init();
	init_video();

#if CONFIG_RTAS
	if( !(ph=find_dev("/rtas")) )
		printk("Warning: No /rtas node\n");
	else {
		unsigned long size = 0x1000;
		while( size < (unsigned long)of_rtas_end - (unsigned long)of_rtas_start )
			size *= 2;
		set_property( ph, "rtas-size", (char*)&size, sizeof(size) );
	}
#endif

#if 0
	/* tweak boot settings */
	autoboot = !!get_bool_res("autoboot");
#endif
	autoboot = 0;
	if( !autoboot )
		printk("Autobooting disabled - dropping into OpenFirmware\n");
	setenv("auto-boot?", autoboot ? "true" : "false" );
	setenv("boot-command", "pearpcboot");

#if 0
	if( get_bool_res("tty-interface") == 1 )
#endif
		fword("activate-tty-interface");

	/* hack */
	device_end();
	bind_func("pearpcboot", boot );
}
