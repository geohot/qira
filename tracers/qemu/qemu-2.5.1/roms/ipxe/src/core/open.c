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

#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ipxe/xfer.h>
#include <ipxe/uri.h>
#include <ipxe/socket.h>
#include <ipxe/open.h>

/** @file
 *
 * Data transfer interface opening
 *
 */

/**
 * Find opener for URI scheme
 *
 * @v scheme		URI scheme
 * @ret opener		Opener, or NULL
 */
struct uri_opener * xfer_uri_opener ( const char *scheme ) {
	struct uri_opener *opener;

	for_each_table_entry ( opener, URI_OPENERS ) {
		if ( strcmp ( scheme, opener->scheme ) == 0 )
			return opener;
	}
	return NULL;
}

/**
 * Open URI
 *
 * @v intf		Data transfer interface
 * @v uri		URI
 * @ret rc		Return status code
 *
 * The URI will be regarded as being relative to the current working
 * URI (see churi()).
 */
int xfer_open_uri ( struct interface *intf, struct uri *uri ) {
	struct uri_opener *opener;
	struct uri *resolved_uri;
	int rc;

	/* Resolve URI */
	resolved_uri = resolve_uri ( cwuri, uri );
	if ( ! resolved_uri ) {
		rc = -ENOMEM;
		goto err_resolve_uri;
	}

	/* Find opener which supports this URI scheme */
	opener = xfer_uri_opener ( resolved_uri->scheme );
	if ( ! opener ) {
		DBGC ( INTF_COL ( intf ), "INTF " INTF_FMT " attempted to open "
		       "unsupported URI scheme \"%s\"\n",
		       INTF_DBG ( intf ), resolved_uri->scheme );
		rc = -ENOTSUP;
		goto err_opener;
	}

	/* Call opener */
	DBGC ( INTF_COL ( intf ), "INTF " INTF_FMT " opening %s URI\n",
	       INTF_DBG ( intf ), resolved_uri->scheme );
	if ( ( rc = opener->open ( intf, resolved_uri ) ) != 0 ) {
		DBGC ( INTF_COL ( intf ), "INTF " INTF_FMT " could not open: "
		       "%s\n", INTF_DBG ( intf ), strerror ( rc ) );
		goto err_open;
	}

 err_open:
 err_opener:
	uri_put ( resolved_uri );
 err_resolve_uri:
	return rc;
}

/**
 * Open URI string
 *
 * @v intf		Data transfer interface
 * @v uri_string	URI string (e.g. "http://ipxe.org/kernel")
 * @ret rc		Return status code
 *
 * The URI will be regarded as being relative to the current working
 * URI (see churi()).
 */
int xfer_open_uri_string ( struct interface *intf,
			   const char *uri_string ) {
	struct uri *uri;
	int rc;

	DBGC ( INTF_COL ( intf ), "INTF " INTF_FMT " opening URI %s\n",
	       INTF_DBG ( intf ), uri_string );

	uri = parse_uri ( uri_string );
	if ( ! uri )
		return -ENOMEM;

	rc = xfer_open_uri ( intf, uri );

	uri_put ( uri );
	return rc;
}

/**
 * Open socket
 *
 * @v intf		Data transfer interface
 * @v semantics		Communication semantics (e.g. SOCK_STREAM)
 * @v peer		Peer socket address
 * @v local		Local socket address, or NULL
 * @ret rc		Return status code
 */
int xfer_open_socket ( struct interface *intf, int semantics,
		       struct sockaddr *peer, struct sockaddr *local ) {
	struct socket_opener *opener;

	DBGC ( INTF_COL ( intf ), "INTF " INTF_FMT " opening (%s,%s) socket\n",
	       INTF_DBG ( intf ), socket_semantics_name ( semantics ),
	       socket_family_name ( peer->sa_family ) );

	for_each_table_entry ( opener, SOCKET_OPENERS ) {
		if ( ( opener->semantics == semantics ) &&
		     ( opener->family == peer->sa_family ) ) {
			return opener->open ( intf, peer, local );
		}
	}

	DBGC ( INTF_COL ( intf ), "INTF " INTF_FMT " attempted to open "
	       "unsupported socket type (%s,%s)\n",
	       INTF_DBG ( intf ), socket_semantics_name ( semantics ),
	       socket_family_name ( peer->sa_family ) );
	return -ENOTSUP;
}

/**
 * Open location
 *
 * @v intf		Data transfer interface
 * @v type		Location type
 * @v args		Remaining arguments depend upon location type
 * @ret rc		Return status code
 */
int xfer_vopen ( struct interface *intf, int type, va_list args ) {
	switch ( type ) {
	case LOCATION_URI_STRING: {
		const char *uri_string = va_arg ( args, const char * );

		return xfer_open_uri_string ( intf, uri_string ); }
	case LOCATION_URI: {
		struct uri *uri = va_arg ( args, struct uri * );

		return xfer_open_uri ( intf, uri ); }
	case LOCATION_SOCKET: {
		int semantics = va_arg ( args, int );
		struct sockaddr *peer = va_arg ( args, struct sockaddr * );
		struct sockaddr *local = va_arg ( args, struct sockaddr * );

		return xfer_open_socket ( intf, semantics, peer, local ); }
	default:
		DBGC ( INTF_COL ( intf ), "INTF " INTF_FMT " attempted to "
		       "open unsupported location type %d\n",
		       INTF_DBG ( intf ), type );
		return -ENOTSUP;
	}
}

/**
 * Open location
 *
 * @v intf		Data transfer interface
 * @v type		Location type
 * @v ...		Remaining arguments depend upon location type
 * @ret rc		Return status code
 */
int xfer_open ( struct interface *intf, int type, ... ) {
	va_list args;
	int rc;

	va_start ( args, type );
	rc = xfer_vopen ( intf, type, args );
	va_end ( args );
	return rc;
}

/**
 * Reopen location
 *
 * @v intf		Data transfer interface
 * @v type		Location type
 * @v args		Remaining arguments depend upon location type
 * @ret rc		Return status code
 *
 * This will close the existing connection and open a new connection
 * using xfer_vopen().  It is intended to be used as a .vredirect
 * method handler.
 */
int xfer_vreopen ( struct interface *intf, int type, va_list args ) {

	/* Close existing connection */
	intf_restart ( intf, 0 );

	/* Open new location */
	return xfer_vopen ( intf, type, args );
}
