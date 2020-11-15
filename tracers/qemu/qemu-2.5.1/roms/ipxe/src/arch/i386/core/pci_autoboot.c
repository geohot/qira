/*
 * Copyright (C) 2014 Red Hat Inc.
 *	Alex Williamson <alex.williamson@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/device.h>
#include <ipxe/init.h>
#include <realmode.h>
#include <usr/autoboot.h>

uint16_t __bss16 ( autoboot_busdevfn );
#define autoboot_busdevfn __use_data16 ( autoboot_busdevfn )

/**
 * Initialise PCI autoboot device
 */
static void pci_autoboot_init ( void ) {

	if ( autoboot_busdevfn )
		set_autoboot_busloc ( BUS_TYPE_PCI, autoboot_busdevfn );
}

/** PCI autoboot device initialisation function */
struct init_fn pci_autoboot_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = pci_autoboot_init,
};
