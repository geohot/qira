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

#include <stdlib.h>
#include <ipxe/refcnt.h>

/** @file
 *
 * Reference counting
 *
 */

/**
 * Increment reference count
 *
 * @v refcnt		Reference counter, or NULL
 *
 * If @c refcnt is NULL, no action is taken.
 */
void ref_increment ( struct refcnt *refcnt ) {

	if ( refcnt ) {
		refcnt->count++;
		DBGC2 ( refcnt, "REFCNT %p incremented to %d\n",
			refcnt, refcnt->count );
	}
}

/**
 * Decrement reference count
 *
 * @v refcnt		Reference counter, or NULL
 *
 * If the reference count decreases below zero, the object's free()
 * method will be called.
 *
 * If @c refcnt is NULL, no action is taken.
 */
void ref_decrement ( struct refcnt *refcnt ) {

	if ( ! refcnt )
		return;

	refcnt->count--;
	DBGC2 ( refcnt, "REFCNT %p decremented to %d\n",
		refcnt, refcnt->count );

	if ( refcnt->count >= 0 )
		return;

	if ( refcnt->count < -1 ) {
		DBGC ( refcnt, "REFCNT %p decremented too far (%d)!\n",
		       refcnt, refcnt->count );
		/* Avoid multiple calls to free(), which typically
		 * result in memory corruption that is very hard to
		 * track down.
		 */
		return;
	}

	if ( refcnt->free ) {
		DBGC ( refcnt, "REFCNT %p being freed via method %p\n",
		       refcnt, refcnt->free );
		refcnt->free ( refcnt );
	} else {
		DBGC ( refcnt, "REFCNT %p being freed\n", refcnt );
		free ( refcnt );
	}
}

/**
 * Do not free reference-counted object
 *
 * @v refcnt		Reference counter
 *
 * This is meant for initializing a reference counter structure in a
 * statically allocated object.
 */
void ref_no_free ( struct refcnt *refcnt __unused ) {
	/* Do nothing */
}
