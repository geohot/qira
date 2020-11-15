/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <stdlib.h>
#include <errno.h>
#include <ipxe/fault.h>

/** @file
 *
 * Fault injection
 *
 */

/**
 * Inject fault with a specified probability
 *
 * @v rate		Reciprocal of fault probability (must be non-zero)
 * @ret rc		Return status code
 */
int inject_fault_nonzero ( unsigned int rate ) {

	/* Do nothing unless we want to inject a fault now */
	if ( ( random() % rate ) != 0 )
		return 0;

	/* Generate error number here so that faults can be injected
	 * into files that don't themselves have error file
	 * identifiers (via errfile.h).
	 */
	return -EFAULT;
}

/**
 * Corrupt data with a specified probability
 *
 * @v rate		Reciprocal of fault probability (must be non-zero)
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
void inject_corruption_nonzero ( unsigned int rate, const void *data,
				 size_t len ) {
	uint8_t *writable;
	size_t offset;

	/* Do nothing if we have no data to corrupt */
	if ( ! len )
		return;

	/* Do nothing unless we want to inject a fault now */
	if ( ! inject_fault_nonzero ( rate ) )
		return;

	/* Get a writable pointer to the nominally read-only data */
	writable = ( ( uint8_t * ) data );

	/* Pick a random victim byte and zap it */
	offset = ( random() % len );
	writable[offset] ^= random();
}
