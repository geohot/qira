/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <realmode.h>
#include <bios.h>
#include <basemem.h>
#include <ipxe/hidemem.h>

/** @file
 *
 * Base memory allocation
 *
 */

/**
 * Set the BIOS free base memory counter
 *
 * @v new_fbms		New free base memory counter (in kB)
 */
void set_fbms ( unsigned int new_fbms ) {
	uint16_t fbms = new_fbms;

	/* Update the BIOS memory counter */
	put_real ( fbms, BDA_SEG, BDA_FBMS );

	/* Update our hidden memory region map */
	hide_basemem();
}
