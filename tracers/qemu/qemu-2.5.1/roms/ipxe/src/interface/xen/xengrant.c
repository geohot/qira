/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/io.h>
#include <ipxe/xen.h>
#include <ipxe/xengrant.h>

/** @file
 *
 * Xen grant tables
 *
 */

/** Grant table version to try setting
 *
 * Using version 1 grant tables limits guests to using 16TB of
 * grantable RAM, and prevents the use of subpage grants.  Some
 * versions of the Xen hypervisor refuse to allow the grant table
 * version to be set after the first grant references have been
 * created, so the loaded operating system may be stuck with whatever
 * choice we make here.  We therefore currently use version 2 grant
 * tables, since they give the most flexibility to the loaded OS.
 *
 * Current versions (7.2.0) of the Windows PV drivers have no support
 * for version 2 grant tables, and will merrily create version 1
 * entries in what the hypervisor believes to be a version 2 table.
 * This causes some confusion.
 *
 * Avoid this problem by attempting to use version 1 tables, since
 * otherwise we may render Windows unable to boot.
 *
 * Play nicely with other potential bootloaders by accepting either
 * version 1 or version 2 grant tables (if we are unable to set our
 * requested version).
 */
#define XENGRANT_TRY_VERSION 1

/**
 * Initialise grant table
 *
 * @v xen		Xen hypervisor
 * @ret rc		Return status code
 */
int xengrant_init ( struct xen_hypervisor *xen ) {
	struct gnttab_query_size size;
	struct gnttab_set_version set_version;
	struct gnttab_get_version get_version;
	struct grant_entry_v1 *v1;
	union grant_entry_v2 *v2;
	unsigned int version;
	int xenrc;
	int rc;

	/* Get grant table size */
	size.dom = DOMID_SELF;
	if ( ( xenrc = xengrant_query_size ( xen, &size ) ) != 0 ) {
		rc = -EXEN ( xenrc );
		DBGC ( xen, "XENGRANT could not get table size: %s\n",
		       strerror ( rc ) );
		return rc;
	}
	xen->grant.len = ( size.nr_frames * PAGE_SIZE );

	/* Set grant table version, if applicable */
	set_version.version = XENGRANT_TRY_VERSION;
	if ( ( xenrc = xengrant_set_version ( xen, &set_version ) ) != 0 ) {
		rc = -EXEN ( xenrc );
		DBGC ( xen, "XENGRANT could not set version %d: %s\n",
		       XENGRANT_TRY_VERSION, strerror ( rc ) );
		/* Continue; use whatever version is current */
	}

	/* Get grant table version */
	get_version.dom = DOMID_SELF;
	get_version.pad = 0;
	if ( ( xenrc = xengrant_get_version ( xen, &get_version ) ) == 0 ) {
		version = get_version.version;
		switch ( version ) {

		case 0:
			/* Version not yet specified: will be version 1 */
			version = 1;
			break;

		case 1 :
			/* Version 1 table: nothing special to do */
			break;

		case 2:
			/* Version 2 table: configure shift appropriately */
			xen->grant.shift = ( fls ( sizeof ( *v2 ) /
						   sizeof ( *v1 ) ) - 1 );
			break;

		default:
			/* Unsupported version */
			DBGC ( xen, "XENGRANT detected unsupported version "
			       "%d\n", version );
			return -ENOTSUP;

		}
	} else {
		rc = -EXEN ( xenrc );
		DBGC ( xen, "XENGRANT could not get version (assuming v1): "
		       "%s\n", strerror ( rc ) );
		version = 1;
	}

	DBGC ( xen, "XENGRANT using v%d table with %d entries\n",
	       version, xengrant_entries ( xen ) );
	return 0;
}

/**
 * Allocate grant references
 *
 * @v xen		Xen hypervisor
 * @v refs		Grant references to fill in
 * @v count		Number of references
 * @ret rc		Return status code
 */
int xengrant_alloc ( struct xen_hypervisor *xen, grant_ref_t *refs,
		     unsigned int count ) {
	struct grant_entry_header *hdr;
	unsigned int entries = xengrant_entries ( xen );
	unsigned int mask = ( entries - 1 );
	unsigned int check = 0;
	unsigned int avail;
	unsigned int ref;

	/* Fail unless we have enough references available */
	avail = ( entries - xen->grant.used - GNTTAB_NR_RESERVED_ENTRIES );
	if ( avail < count ) {
		DBGC ( xen, "XENGRANT cannot allocate %d references (only %d "
		       "of %d available)\n", count, avail, entries );
		return -ENOBUFS;
	}
	DBGC ( xen, "XENGRANT allocating %d references (from %d of %d "
	       "available)\n", count, avail, entries );

	/* Update number of references used */
	xen->grant.used += count;

	/* Find unused references */
	for ( ref = xen->grant.ref ; count ; ref = ( ( ref + 1 ) & mask ) ) {

		/* Sanity check */
		assert ( check++ < entries );

		/* Skip reserved references */
		if ( ref < GNTTAB_NR_RESERVED_ENTRIES )
			continue;

		/* Skip in-use references */
		hdr = xengrant_header ( xen, ref );
		if ( readw ( &hdr->flags ) & GTF_type_mask )
			continue;
		if ( readw ( &hdr->domid ) == DOMID_SELF )
			continue;

		/* Zero reference */
		xengrant_zero ( xen, hdr );

		/* Mark reference as in-use.  We leave the flags as
		 * empty (to avoid creating a valid grant table entry)
		 * and set the domid to DOMID_SELF.
		 */
		writew ( DOMID_SELF, &hdr->domid );
		DBGC2 ( xen, "XENGRANT allocated ref %d\n", ref );

		/* Record reference */
		refs[--count] = ref;
	}

	/* Update cursor */
	xen->grant.ref = ref;

	return 0;
}

/**
 * Free grant references
 *
 * @v xen		Xen hypervisor
 * @v refs		Grant references
 * @v count		Number of references
 */
void xengrant_free ( struct xen_hypervisor *xen, grant_ref_t *refs,
		     unsigned int count ) {
	struct grant_entry_header *hdr;
	unsigned int ref;
	unsigned int i;

	/* Free references */
	for ( i = 0 ; i < count ; i++ ) {

		/* Sanity check */
		ref = refs[i];
		assert ( ref < xengrant_entries ( xen ) );

		/* Zero reference */
		hdr = xengrant_header ( xen, ref );
		xengrant_zero ( xen, hdr );
		DBGC2 ( xen, "XENGRANT freed ref %d\n", ref );
	}
}
