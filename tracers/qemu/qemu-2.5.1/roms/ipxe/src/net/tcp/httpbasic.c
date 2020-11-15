/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * Hyper Text Transfer Protocol (HTTP) Basic authentication
 *
 */

#include <stdio.h>
#include <errno.h>
#include <ipxe/uri.h>
#include <ipxe/base64.h>
#include <ipxe/http.h>

/* Disambiguate the various error causes */
#define EACCES_USERNAME __einfo_error ( EINFO_EACCES_USERNAME )
#define EINFO_EACCES_USERNAME						\
	__einfo_uniqify ( EINFO_EACCES, 0x01,				\
			  "No username available for Basic authentication" )

/**
 * Perform HTTP Basic authentication
 *
 * @v http		HTTP transaction
 * @ret rc		Return status code
 */
static int http_basic_authenticate ( struct http_transaction *http ) {
	struct http_request_auth *req = &http->request.auth;

	/* Record username and password */
	if ( ! http->uri->user ) {
		DBGC ( http, "HTTP %p has no username for Basic "
		       "authentication\n", http );
		return -EACCES_USERNAME;
	}
	req->username = http->uri->user;
	req->password = ( http->uri->password ? http->uri->password : "" );

	return 0;
}

/**
 * Construct HTTP "Authorization" header for Basic authentication
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_basic_auth ( struct http_transaction *http,
				    char *buf, size_t len ) {
	struct http_request_auth *req = &http->request.auth;
	size_t user_pw_len = ( strlen ( req->username ) + 1 /* ":" */ +
			       strlen ( req->password ) );
	char user_pw[ user_pw_len + 1 /* NUL */ ];

	/* Sanity checks */
	assert ( req->username != NULL );
	assert ( req->password != NULL );

	/* Construct "user:password" string */
	snprintf ( user_pw, sizeof ( user_pw ), "%s:%s",
		   req->username, req->password );

	/* Construct response */
	return base64_encode ( user_pw, user_pw_len, buf, len );
}

/** HTTP Basic authentication scheme */
struct http_authentication http_basic_auth __http_authentication = {
	.name = "Basic",
	.authenticate = http_basic_authenticate,
	.format = http_format_basic_auth,
};

/* Drag in HTTP authentication support */
REQUIRING_SYMBOL ( http_basic_auth );
REQUIRE_OBJECT ( httpauth );
