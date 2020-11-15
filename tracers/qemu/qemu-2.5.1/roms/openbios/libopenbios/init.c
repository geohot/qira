/*
 *   Creation Date: <2010/04/02 12:00:00 mcayland>
 *   Time-stamp: <2010/04/02 12:00:00 mcayland>
 *
 *	<init.c>
 *
 *	OpenBIOS intialization
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/openbios.h"
#include "libopenbios/bindings.h"
#include "libopenbios/initprogram.h"

void
openbios_init( void )
{
	// Bind the C implementation of (init-program) into Forth
	bind_func("(init-program)", init_program);
}
