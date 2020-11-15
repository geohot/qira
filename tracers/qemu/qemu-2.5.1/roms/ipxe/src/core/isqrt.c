/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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

/** @file
 *
 * Integer square root
 *
 */

#include <ipxe/isqrt.h>

/**
 * Find integer square root
 *
 * @v value		Value
 * @v isqrt		Integer square root of value
 */
unsigned long isqrt ( unsigned long value ) {
	unsigned long result = 0;
	unsigned long bit = ( 1UL << ( ( 8 * sizeof ( bit ) ) - 2 ) );

	while ( bit > value )
		bit >>= 2;
	while ( bit ) {
		if ( value >= ( result + bit ) ) {
			value -= ( result + bit );
			result = ( ( result >> 1 ) + bit );
		} else {
			result >>= 1;
		}
		bit >>= 2;
	}
	return result;
}
