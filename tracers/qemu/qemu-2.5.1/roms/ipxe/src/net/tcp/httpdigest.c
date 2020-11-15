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
 * Hyper Text Transfer Protocol (HTTP) Digest authentication
 *
 */

#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <ipxe/uri.h>
#include <ipxe/md5.h>
#include <ipxe/base16.h>
#include <ipxe/vsprintf.h>
#include <ipxe/http.h>

/* Disambiguate the various error causes */
#define EACCES_USERNAME __einfo_error ( EINFO_EACCES_USERNAME )
#define EINFO_EACCES_USERNAME						\
	__einfo_uniqify ( EINFO_EACCES, 0x01,				\
			  "No username available for Digest authentication" )

/**
 * Initialise HTTP Digest
 *
 * @v ctx		Digest context
 * @v string		Initial string
 */
static void http_digest_init ( struct md5_context *ctx ) {

	/* Initialise MD5 digest */
	digest_init ( &md5_algorithm, ctx );
}

/**
 * Update HTTP Digest with new data
 *
 * @v ctx		Digest context
 * @v string		String to append
 */
static void http_digest_update ( struct md5_context *ctx, const char *string ) {
	static const char colon = ':';

	/* Add (possibly colon-separated) field to MD5 digest */
	if ( ctx->len )
		digest_update ( &md5_algorithm, ctx, &colon, sizeof ( colon ) );
	digest_update ( &md5_algorithm, ctx, string, strlen ( string ) );
}

/**
 * Finalise HTTP Digest
 *
 * @v ctx		Digest context
 * @v out		Buffer for digest output
 * @v len		Buffer length
 */
static void http_digest_final ( struct md5_context *ctx, char *out,
				size_t len ) {
	uint8_t digest[MD5_DIGEST_SIZE];

	/* Finalise and base16-encode MD5 digest */
	digest_final ( &md5_algorithm, ctx, digest );
	base16_encode ( digest, sizeof ( digest ), out, len );
}

/**
 * Perform HTTP Digest authentication
 *
 * @v http		HTTP transaction
 * @ret rc		Return status code
 */
static int http_digest_authenticate ( struct http_transaction *http ) {
	struct http_request_auth *req = &http->request.auth;
	struct http_response_auth *rsp = &http->response.auth;
	char ha1[ base16_encoded_len ( MD5_DIGEST_SIZE ) + 1 /* NUL */ ];
	char ha2[ base16_encoded_len ( MD5_DIGEST_SIZE ) + 1 /* NUL */ ];
	static const char md5sess[] = "MD5-sess";
	static const char md5[] = "MD5";
	struct md5_context ctx;

	/* Check for required response parameters */
	if ( ! rsp->realm ) {
		DBGC ( http, "HTTP %p has no realm for Digest authentication\n",
		       http );
		return -EINVAL;
	}
	if ( ! rsp->nonce ) {
		DBGC ( http, "HTTP %p has no nonce for Digest authentication\n",
		       http );
		return -EINVAL;
	}

	/* Record username and password */
	if ( ! http->uri->user ) {
		DBGC ( http, "HTTP %p has no username for Digest "
		       "authentication\n", http );
		return -EACCES_USERNAME;
	}
	req->username = http->uri->user;
	req->password = ( http->uri->password ? http->uri->password : "" );

	/* Handle quality of protection */
	if ( rsp->qop ) {

		/* Use "auth" in subsequent request */
		req->qop = "auth";

		/* Generate a client nonce */
		snprintf ( req->cnonce, sizeof ( req->cnonce ),
			   "%08lx", random() );

		/* Determine algorithm */
		req->algorithm = md5;
		if ( rsp->algorithm &&
		     ( strcasecmp ( rsp->algorithm, md5sess ) == 0 ) ) {
			req->algorithm = md5sess;
		}
	}

	/* Generate HA1 */
	http_digest_init ( &ctx );
	http_digest_update ( &ctx, req->username );
	http_digest_update ( &ctx, rsp->realm );
	http_digest_update ( &ctx, req->password );
	http_digest_final ( &ctx, ha1, sizeof ( ha1 ) );
	if ( req->algorithm == md5sess ) {
		http_digest_init ( &ctx );
		http_digest_update ( &ctx, ha1 );
		http_digest_update ( &ctx, rsp->nonce );
		http_digest_update ( &ctx, req->cnonce );
		http_digest_final ( &ctx, ha1, sizeof ( ha1 ) );
	}

	/* Generate HA2 */
	http_digest_init ( &ctx );
	http_digest_update ( &ctx, http->request.method->name );
	http_digest_update ( &ctx, http->request.uri );
	http_digest_final ( &ctx, ha2, sizeof ( ha2 ) );

	/* Generate response */
	http_digest_init ( &ctx );
	http_digest_update ( &ctx, ha1 );
	http_digest_update ( &ctx, rsp->nonce );
	if ( req->qop ) {
		http_digest_update ( &ctx, HTTP_DIGEST_NC );
		http_digest_update ( &ctx, req->cnonce );
		http_digest_update ( &ctx, req->qop );
	}
	http_digest_update ( &ctx, ha2 );
	http_digest_final ( &ctx, req->response, sizeof ( req->response ) );

	return 0;
}

/**
 * Construct HTTP "Authorization" header for Digest authentication
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_digest_auth ( struct http_transaction *http,
				     char *buf, size_t len ) {
	struct http_request_auth *req = &http->request.auth;
	struct http_response_auth *rsp = &http->response.auth;
	size_t used = 0;

	/* Sanity checks */
	assert ( rsp->realm != NULL );
	assert ( rsp->nonce != NULL );
	assert ( req->username != NULL );
	if ( req->qop ) {
		assert ( req->algorithm != NULL );
		assert ( req->cnonce[0] != '\0' );
	}
	assert ( req->response[0] != '\0' );

	/* Construct response */
	used += ssnprintf ( ( buf + used ), ( len - used ),
			    "realm=\"%s\", nonce=\"%s\", uri=\"%s\", "
			    "username=\"%s\"", rsp->realm, rsp->nonce,
			    http->request.uri, req->username );
	if ( rsp->opaque ) {
		used += ssnprintf ( ( buf + used ), ( len - used ),
				    ", opaque=\"%s\"", rsp->opaque );
	}
	if ( req->qop ) {
		used += ssnprintf ( ( buf + used ), ( len - used ),
				    ", qop=%s, algorithm=%s, cnonce=\"%s\", "
				    "nc=" HTTP_DIGEST_NC, req->qop,
				    req->algorithm, req->cnonce );
	}
	used += ssnprintf ( ( buf + used ), ( len - used ),
			    ", response=\"%s\"", req->response );

	return used;
}

/** HTTP Digest authentication scheme */
struct http_authentication http_digest_auth __http_authentication = {
	.name = "Digest",
	.authenticate = http_digest_authenticate,
	.format = http_format_digest_auth,
};

/* Drag in HTTP authentication support */
REQUIRING_SYMBOL ( http_digest_auth );
REQUIRE_OBJECT ( httpauth );
