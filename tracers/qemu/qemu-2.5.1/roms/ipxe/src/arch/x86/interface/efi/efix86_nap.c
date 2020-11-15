/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <ipxe/nap.h>
#include <ipxe/efi/efi.h>

/** @file
 *
 * iPXE CPU sleeping API for EFI
 *
 */

/**
 * Sleep until next interrupt
 *
 */
static void efix86_cpu_nap ( void ) {
	/*
	 * I can't find any EFI API that allows us to put the CPU to
	 * sleep.  The CpuSleep() function is defined in CpuLib.h, but
	 * isn't part of any exposed protocol so we have no way to
	 * call it.
	 *
	 * The EFI shell doesn't seem to bother sleeping the CPU; it
	 * just sits there idly burning power.
	 *
	 */
	__asm__ __volatile__ ( "hlt" );
}

PROVIDE_NAP ( efix86, cpu_nap, efix86_cpu_nap );
