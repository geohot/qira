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
 * Hyper Text Transfer Protocol (HTTP) core functionality
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <byteswap.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <ipxe/uri.h>
#include <ipxe/refcnt.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/process.h>
#include <ipxe/retry.h>
#include <ipxe/timer.h>
#include <ipxe/linebuf.h>
#include <ipxe/xferbuf.h>
#include <ipxe/blockdev.h>
#include <ipxe/acpi.h>
#include <ipxe/version.h>
#include <ipxe/params.h>
#include <ipxe/profile.h>
#include <ipxe/vsprintf.h>
#include <ipxe/http.h>

/* Disambiguate the various error causes */
#define EACCES_401 __einfo_error ( EINFO_EACCES_401 )
#define EINFO_EACCES_401 \
	__einfo_uniqify ( EINFO_EACCES, 0x01, "HTTP 401 Unauthorized" )
#define EINVAL_STATUS __einfo_error ( EINFO_EINVAL_STATUS )
#define EINFO_EINVAL_STATUS \
	__einfo_uniqify ( EINFO_EINVAL, 0x01, "Invalid status line" )
#define EINVAL_HEADER __einfo_error ( EINFO_EINVAL_HEADER )
#define EINFO_EINVAL_HEADER \
	__einfo_uniqify ( EINFO_EINVAL, 0x02, "Invalid header" )
#define EINVAL_CONTENT_LENGTH __einfo_error ( EINFO_EINVAL_CONTENT_LENGTH )
#define EINFO_EINVAL_CONTENT_LENGTH \
	__einfo_uniqify ( EINFO_EINVAL, 0x03, "Invalid content length" )
#define EINVAL_CHUNK_LENGTH __einfo_error ( EINFO_EINVAL_CHUNK_LENGTH )
#define EINFO_EINVAL_CHUNK_LENGTH \
	__einfo_uniqify ( EINFO_EINVAL, 0x04, "Invalid chunk length" )
#define EIO_OTHER __einfo_error ( EINFO_EIO_OTHER )
#define EINFO_EIO_OTHER \
	__einfo_uniqify ( EINFO_EIO, 0x01, "Unrecognised HTTP response code" )
#define EIO_CONTENT_LENGTH __einfo_error ( EINFO_EIO_CONTENT_LENGTH )
#define EINFO_EIO_CONTENT_LENGTH \
	__einfo_uniqify ( EINFO_EIO, 0x02, "Content length mismatch" )
#define EIO_4XX __einfo_error ( EINFO_EIO_4XX )
#define EINFO_EIO_4XX \
	__einfo_uniqify ( EINFO_EIO, 0x04, "HTTP 4xx Client Error" )
#define EIO_5XX __einfo_error ( EINFO_EIO_5XX )
#define EINFO_EIO_5XX \
	__einfo_uniqify ( EINFO_EIO, 0x05, "HTTP 5xx Server Error" )
#define ENOENT_404 __einfo_error ( EINFO_ENOENT_404 )
#define EINFO_ENOENT_404 \
	__einfo_uniqify ( EINFO_ENOENT, 0x01, "HTTP 404 Not Found" )
#define ENOTSUP_CONNECTION __einfo_error ( EINFO_ENOTSUP_CONNECTION )
#define EINFO_ENOTSUP_CONNECTION \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01, "Unsupported connection header" )
#define ENOTSUP_TRANSFER __einfo_error ( EINFO_ENOTSUP_TRANSFER )
#define EINFO_ENOTSUP_TRANSFER \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x02, "Unsupported transfer encoding" )
#define EPERM_403 __einfo_error ( EINFO_EPERM_403 )
#define EINFO_EPERM_403 \
	__einfo_uniqify ( EINFO_EPERM, 0x01, "HTTP 403 Forbidden" )
#define EPROTO_UNSOLICITED __einfo_error ( EINFO_EPROTO_UNSOLICITED )
#define EINFO_EPROTO_UNSOLICITED \
	__einfo_uniqify ( EINFO_EPROTO, 0x01, "Unsolicited data" )

/** Retry delay used when we cannot understand the Retry-After header */
#define HTTP_RETRY_SECONDS 5

/** Receive profiler */
static struct profiler http_rx_profiler __profiler = { .name = "http.rx" };

/** Data transfer profiler */
static struct profiler http_xfer_profiler __profiler = { .name = "http.xfer" };

static struct http_state http_request;
static struct http_state http_headers;
static struct http_state http_trailers;
static struct http_transfer_encoding http_transfer_identity;

/******************************************************************************
 *
 * Methods
 *
 ******************************************************************************
 */

/** HTTP HEAD method */
struct http_method http_head = {
	.name = "HEAD",
};

/** HTTP GET method */
struct http_method http_get = {
	.name = "GET",
};

/** HTTP POST method */
struct http_method http_post = {
	.name = "POST",
};

/******************************************************************************
 *
 * Utility functions
 *
 ******************************************************************************
 */

/**
 * Handle received HTTP line-buffered data
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer
 * @v linebuf		Line buffer
 * @ret rc		Return status code
 */
static int http_rx_linebuf ( struct http_transaction *http,
			     struct io_buffer *iobuf,
			     struct line_buffer *linebuf ) {
	int consumed;
	int rc;

	/* Buffer received line */
	consumed = line_buffer ( linebuf, iobuf->data, iob_len ( iobuf ) );
	if ( consumed < 0 ) {
		rc = consumed;
		DBGC ( http, "HTTP %p could not buffer line: %s\n",
		       http, strerror ( rc ) );
		return rc;
	}

	/* Consume line */
	iob_pull ( iobuf, consumed );

	return 0;
}

/**
 * Get HTTP response token
 *
 * @v line		Line position
 * @v value		Token value to fill in (if any)
 * @ret token		Token, or NULL
 */
char * http_token ( char **line, char **value ) {
	char *token;
	char quote = '\0';
	char c;

	/* Avoid returning uninitialised data */
	if ( value )
		*value = NULL;

	/* Skip any initial whitespace */
	while ( isspace ( **line ) )
		(*line)++;

	/* Check for end of line and record token position */
	if ( ! **line )
		return NULL;
	token = *line;

	/* Scan for end of token */
	while ( ( c = **line ) ) {

		/* Terminate if we hit an unquoted whitespace */
		if ( isspace ( c ) && ! quote )
			break;

		/* Terminate if we hit a closing quote */
		if ( c == quote )
			break;

		/* Check for value separator */
		if ( value && ( ! *value ) && ( c == '=' ) ) {

			/* Terminate key portion of token */
			*((*line)++) = '\0';

			/* Check for quote character */
			c = **line;
			if ( ( c == '"' ) || ( c == '\'' ) ) {
				quote = c;
				(*line)++;
			}

			/* Record value portion of token */
			*value = *line;

		} else {

			/* Move to next character */
			(*line)++;
		}
	}

	/* Terminate token, if applicable */
	if ( c )
		*((*line)++) = '\0';

	return token;
}

/******************************************************************************
 *
 * Transactions
 *
 ******************************************************************************
 */

/**
 * Free HTTP transaction
 *
 * @v refcnt		Reference count
 */
static void http_free ( struct refcnt *refcnt ) {
	struct http_transaction *http =
		container_of ( refcnt, struct http_transaction, refcnt );

	empty_line_buffer ( &http->response.headers );
	empty_line_buffer ( &http->linebuf );
	uri_put ( http->uri );
	free ( http );
}

/**
 * Close HTTP transaction
 *
 * @v http		HTTP transaction
 * @v rc		Reason for close
 */
static void http_close ( struct http_transaction *http, int rc ) {

	/* Stop process */
	process_del ( &http->process );

	/* Stop timer */
	stop_timer ( &http->timer );

	/* Close all interfaces, allowing for the fact that the
	 * content-decoded and transfer-decoded interfaces may be
	 * connected to the same object.
	 */
	intf_shutdown ( &http->conn, rc );
	intf_nullify ( &http->transfer );
	intf_shutdown ( &http->content, rc );
	intf_shutdown ( &http->transfer, rc );
	intf_shutdown ( &http->xfer, rc );
}

/**
 * Close HTTP transaction with error (even if none specified)
 *
 * @v http		HTTP transaction
 * @v rc		Reason for close
 */
static void http_close_error ( struct http_transaction *http, int rc ) {

	/* Treat any close as an error */
	http_close ( http, ( rc ? rc : -EPIPE ) );
}

/**
 * Reopen stale HTTP connection
 *
 * @v http		HTTP transaction
 */
static void http_reopen ( struct http_transaction *http ) {
	int rc;

	/* Close existing connection */
	intf_restart ( &http->conn, -ECANCELED );

	/* Reopen connection */
	if ( ( rc = http_connect ( &http->conn, http->uri ) ) != 0 ) {
		DBGC ( http, "HTTP %p could not reconnect: %s\n",
		       http, strerror ( rc ) );
		goto err_connect;
	}

	/* Reset state */
	http->state = &http_request;

	/* Reschedule transmission process */
	process_add ( &http->process );

	return;

 err_connect:
	http_close ( http, rc );
}

/**
 * Handle retry timer expiry
 *
 * @v timer		Retry timer
 * @v over		Failure indicator
 */
static void http_expired ( struct retry_timer *timer, int over __unused ) {
	struct http_transaction *http =
		container_of ( timer, struct http_transaction, timer );

	/* Reopen connection */
	http_reopen ( http );
}

/**
 * HTTP transmit process
 *
 * @v http		HTTP transaction
 */
static void http_step ( struct http_transaction *http ) {
	int rc;

	/* Do nothing if we have nothing to transmit */
	if ( ! http->state->tx )
		return;

	/* Do nothing until connection is ready */
	if ( ! xfer_window ( &http->conn ) )
		return;

	/* Do nothing until data transfer interface is ready */
	if ( ! xfer_window ( &http->xfer ) )
		return;

	/* Transmit data */
	if ( ( rc = http->state->tx ( http ) ) != 0 )
		goto err;

	return;

 err:
	http_close ( http, rc );
}

/**
 * Handle received HTTP data
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer
 * @v meta		Transfer metadata
 * @ret rc		Return status code
 *
 * This function takes ownership of the I/O buffer.
 */
static int http_conn_deliver ( struct http_transaction *http,
			       struct io_buffer *iobuf,
			       struct xfer_metadata *meta __unused ) {
	int rc;

	/* Handle received data */
	profile_start ( &http_rx_profiler );
	while ( iobuf && iob_len ( iobuf ) ) {

		/* Sanity check */
		if ( ( ! http->state ) || ( ! http->state->rx ) ) {
			DBGC ( http, "HTTP %p unexpected data\n", http );
			rc = -EPROTO_UNSOLICITED;
			goto err;
		}

		/* Receive (some) data */
		if ( ( rc = http->state->rx ( http, &iobuf ) ) != 0 )
			goto err;
	}

	/* Free I/O buffer, if applicable */
	free_iob ( iobuf );

	profile_stop ( &http_rx_profiler );
	return 0;

 err:
	free_iob ( iobuf );
	http_close ( http, rc );
	return rc;
}

/**
 * Handle server connection close
 *
 * @v http		HTTP transaction
 * @v rc		Reason for close
 */
static void http_conn_close ( struct http_transaction *http, int rc ) {

	/* Sanity checks */
	assert ( http->state != NULL );
	assert ( http->state->close != NULL );

	/* Restart server connection interface */
	intf_restart ( &http->conn, rc );

	/* Hand off to state-specific method */
	http->state->close ( http, rc );
}

/**
 * Handle received content-decoded data
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 */
static int http_content_deliver ( struct http_transaction *http,
				  struct io_buffer *iobuf,
				  struct xfer_metadata *meta ) {
	int rc;

	/* Ignore content if this is anything other than a successful
	 * transfer.
	 */
	if ( http->response.rc != 0 ) {
		free_iob ( iobuf );
		return 0;
	}

	/* Deliver to data transfer interface */
	profile_start ( &http_xfer_profiler );
	if ( ( rc = xfer_deliver ( &http->xfer, iob_disown ( iobuf ),
				   meta ) ) != 0 )
		return rc;
	profile_stop ( &http_xfer_profiler );

	return 0;
}

/**
 * Get underlying data transfer buffer
 *
 * @v http		HTTP transaction
 * @ret xferbuf		Data transfer buffer, or NULL on error
 */
static struct xfer_buffer *
http_content_buffer ( struct http_transaction *http ) {

	/* Deny access to the data transfer buffer if this is anything
	 * other than a successful transfer.
	 */
	if ( http->response.rc != 0 )
		return NULL;

	/* Hand off to data transfer interface */
	return xfer_buffer ( &http->xfer );
}

/**
 * Read from block device (when HTTP block device support is not present)
 *
 * @v http		HTTP transaction
 * @v data		Data interface
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
__weak int http_block_read ( struct http_transaction *http __unused,
			     struct interface *data __unused,
			     uint64_t lba __unused, unsigned int count __unused,
			     userptr_t buffer __unused, size_t len __unused ) {

	return -ENOTSUP;
}

/**
 * Read block device capacity (when HTTP block device support is not present)
 *
 * @v control		Control interface
 * @v data		Data interface
 * @ret rc		Return status code
 */
__weak int http_block_read_capacity ( struct http_transaction *http __unused,
				      struct interface *data __unused ) {

	return -ENOTSUP;
}

/**
 * Describe device in ACPI table (when HTTP block device support is not present)
 *
 * @v http		HTTP transaction
 * @v acpi		ACPI table
 * @v len		Length of ACPI table
 * @ret rc		Return status code
 */
__weak int http_acpi_describe ( struct http_transaction *http __unused,
				struct acpi_description_header *acpi __unused,
				size_t len __unused ) {

	return -ENOTSUP;
}

/** HTTP data transfer interface operations */
static struct interface_operation http_xfer_operations[] = {
	INTF_OP ( block_read, struct http_transaction *, http_block_read ),
	INTF_OP ( block_read_capacity, struct http_transaction *,
		  http_block_read_capacity ),
	INTF_OP ( acpi_describe, struct http_transaction *,
		  http_acpi_describe ),
	INTF_OP ( xfer_window_changed, struct http_transaction *, http_step ),
	INTF_OP ( intf_close, struct http_transaction *, http_close ),
};

/** HTTP data transfer interface descriptor */
static struct interface_descriptor http_xfer_desc =
	INTF_DESC_PASSTHRU ( struct http_transaction, xfer,
			     http_xfer_operations, content );

/** HTTP content-decoded interface operations */
static struct interface_operation http_content_operations[] = {
	INTF_OP ( xfer_deliver, struct http_transaction *,
		  http_content_deliver ),
	INTF_OP ( xfer_buffer, struct http_transaction *, http_content_buffer ),
	INTF_OP ( intf_close, struct http_transaction *, http_close ),
};

/** HTTP content-decoded interface descriptor */
static struct interface_descriptor http_content_desc =
	INTF_DESC_PASSTHRU ( struct http_transaction, content,
			     http_content_operations, xfer );

/** HTTP transfer-decoded interface operations */
static struct interface_operation http_transfer_operations[] = {
	INTF_OP ( intf_close, struct http_transaction *, http_close ),
};

/** HTTP transfer-decoded interface descriptor */
static struct interface_descriptor http_transfer_desc =
	INTF_DESC_PASSTHRU ( struct http_transaction, transfer,
			     http_transfer_operations, conn );

/** HTTP server connection interface operations */
static struct interface_operation http_conn_operations[] = {
	INTF_OP ( xfer_deliver, struct http_transaction *, http_conn_deliver ),
	INTF_OP ( xfer_window_changed, struct http_transaction *, http_step ),
	INTF_OP ( pool_reopen, struct http_transaction *, http_reopen ),
	INTF_OP ( intf_close, struct http_transaction *, http_conn_close ),
};

/** HTTP server connection interface descriptor */
static struct interface_descriptor http_conn_desc =
	INTF_DESC_PASSTHRU ( struct http_transaction, conn,
			     http_conn_operations, transfer );

/** HTTP process descriptor */
static struct process_descriptor http_process_desc =
	PROC_DESC_ONCE ( struct http_transaction, process, http_step );

/**
 * Open HTTP transaction
 *
 * @v xfer		Data transfer interface
 * @v method		Request method
 * @v uri		Request URI
 * @v range		Content range (if any)
 * @v content		Request content (if any)
 * @ret rc		Return status code
 */
int http_open ( struct interface *xfer, struct http_method *method,
		struct uri *uri, struct http_request_range *range,
		struct http_request_content *content ) {
	struct http_transaction *http;
	struct uri request_uri;
	struct uri request_host;
	size_t request_uri_len;
	size_t request_host_len;
	size_t content_len;
	char *request_uri_string;
	char *request_host_string;
	void *content_data;
	int rc;

	/* Calculate request URI length */
	memset ( &request_uri, 0, sizeof ( request_uri ) );
	request_uri.path = ( uri->path ? uri->path : "/" );
	request_uri.query = uri->query;
	request_uri_len =
		( format_uri ( &request_uri, NULL, 0 ) + 1 /* NUL */);

	/* Calculate host name length */
	memset ( &request_host, 0, sizeof ( request_host ) );
	request_host.host = uri->host;
	request_host.port = uri->port;
	request_host_len =
		( format_uri ( &request_host, NULL, 0 ) + 1 /* NUL */ );

	/* Calculate request content length */
	content_len = ( content ? content->len : 0 );

	/* Allocate and initialise structure */
	http = zalloc ( sizeof ( *http ) + request_uri_len + request_host_len +
			content_len );
	if ( ! http ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	request_uri_string = ( ( ( void * ) http ) + sizeof ( *http ) );
	request_host_string = ( request_uri_string + request_uri_len );
	content_data = ( request_host_string + request_host_len );
	format_uri ( &request_uri, request_uri_string, request_uri_len );
	format_uri ( &request_host, request_host_string, request_host_len );
	ref_init ( &http->refcnt, http_free );
	intf_init ( &http->xfer, &http_xfer_desc, &http->refcnt );
	intf_init ( &http->content, &http_content_desc, &http->refcnt );
	intf_init ( &http->transfer, &http_transfer_desc, &http->refcnt );
	intf_init ( &http->conn, &http_conn_desc, &http->refcnt );
	intf_plug_plug ( &http->transfer, &http->content );
	process_init ( &http->process, &http_process_desc, &http->refcnt );
	timer_init ( &http->timer, http_expired, &http->refcnt );
	http->uri = uri_get ( uri );
	http->request.method = method;
	http->request.uri = request_uri_string;
	http->request.host = request_host_string;
	if ( range ) {
		memcpy ( &http->request.range, range,
			 sizeof ( http->request.range ) );
	}
	if ( content ) {
		http->request.content.type = content->type;
		http->request.content.data = content_data;
		http->request.content.len = content_len;
		memcpy ( content_data, content->data, content_len );
	}
	http->state = &http_request;
	DBGC2 ( http, "HTTP %p %s://%s%s\n", http, http->uri->scheme,
		http->request.host, http->request.uri );

	/* Open connection */
	if ( ( rc = http_connect ( &http->conn, uri ) ) != 0 ) {
		DBGC ( http, "HTTP %p could not connect: %s\n",
		       http, strerror ( rc ) );
		goto err_connect;
	}

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( &http->xfer, xfer );
	ref_put ( &http->refcnt );
	return 0;

 err_connect:
	http_close ( http, rc );
	ref_put ( &http->refcnt );
 err_alloc:
	return rc;
}

/**
 * Handle successful transfer completion
 *
 * @v http		HTTP transaction
 * @ret rc		Return status code
 */
static int http_transfer_complete ( struct http_transaction *http ) {
	struct http_authentication *auth;
	const char *location;
	int rc;

	/* Keep connection alive if applicable */
	if ( http->response.flags & HTTP_RESPONSE_KEEPALIVE )
		pool_recycle ( &http->conn );

	/* Restart server connection interface */
	intf_restart ( &http->conn, 0 );

	/* No more data is expected */
	http->state = NULL;

	/* If transaction is successful, then close the
	 * transfer-decoded interface.  The content encoding may
	 * choose whether or not to immediately terminate the
	 * transaction.
	 */
	if ( http->response.rc == 0 ) {
		intf_shutdown ( &http->transfer, 0 );
		return 0;
	}

	/* Perform redirection, if applicable */
	if ( ( location = http->response.location ) ) {
		DBGC2 ( http, "HTTP %p redirecting to \"%s\"\n",
			http, location );
		if ( ( rc = xfer_redirect ( &http->xfer, LOCATION_URI_STRING,
					    location ) ) != 0 ) {
			DBGC ( http, "HTTP %p could not redirect: %s\n",
			       http, strerror ( rc ) );
			return rc;
		}
		http_close ( http, 0 );
		return 0;
	}

	/* Fail unless a retry is permitted */
	if ( ! ( http->response.flags & HTTP_RESPONSE_RETRY ) )
		return http->response.rc;

	/* Perform authentication, if applicable */
	if ( ( auth = http->response.auth.auth ) ) {
		http->request.auth.auth = auth;
		DBGC2 ( http, "HTTP %p performing %s authentication\n",
			http, auth->name );
		if ( ( rc = auth->authenticate ( http ) ) != 0 ) {
			DBGC ( http, "HTTP %p could not authenticate: %s\n",
			       http, strerror ( rc ) );
			return rc;
		}
	}

	/* Restart content decoding interfaces (which may be attached
	 * to the same object).
	 */
	intf_nullify ( &http->content );
	intf_nullify ( &http->transfer );
	intf_restart ( &http->content, http->response.rc );
	intf_restart ( &http->transfer, http->response.rc );
	http->content.desc = &http_content_desc;
	http->transfer.desc = &http_transfer_desc;
	intf_plug_plug ( &http->transfer, &http->content );
	http->len = 0;
	assert ( http->remaining == 0 );

	/* Start timer to initiate retry */
	DBGC2 ( http, "HTTP %p retrying after %d seconds\n",
		http, http->response.retry_after );
	start_timer_fixed ( &http->timer,
			    ( http->response.retry_after * TICKS_PER_SEC ) );
	return 0;
}

/******************************************************************************
 *
 * Requests
 *
 ******************************************************************************
 */

/**
 * Construct HTTP request headers
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length, or negative error
 */
static int http_format_headers ( struct http_transaction *http, char *buf,
				 size_t len ) {
	struct http_request_header *header;
	size_t used;
	size_t remaining;
	char *line;
	int value_len;
	int rc;

	/* Construct request line */
	used = ssnprintf ( buf, len, "%s %s HTTP/1.1",
			   http->request.method->name, http->request.uri );
	if ( used < len )
		DBGC2 ( http, "HTTP %p TX %s\n", http, buf );
	used += ssnprintf ( ( buf + used ), ( len - used ), "\r\n" );

	/* Construct all headers */
	for_each_table_entry ( header, HTTP_REQUEST_HEADERS ) {

		/* Determine header value length */
		value_len = header->format ( http, NULL, 0 );
		if ( value_len < 0 ) {
			rc = value_len;
			return rc;
		}

		/* Skip zero-length headers */
		if ( ! value_len )
			continue;

		/* Construct header */
		line = ( buf + used );
		used += ssnprintf ( ( buf + used ), ( len - used ), "%s: ",
				    header->name );
		remaining = ( ( used < len ) ? ( len - used ) : 0 );
		used += header->format ( http, ( buf + used ), remaining );
		if ( used < len )
			DBGC2 ( http, "HTTP %p TX %s\n", http, line );
		used += ssnprintf ( ( buf + used ), ( len - used ), "\r\n" );
	}

	/* Construct terminating newline */
	used += ssnprintf ( ( buf + used ), ( len - used ), "\r\n" );

	return used;
}

/**
 * Construct HTTP "Host" header
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_host ( struct http_transaction *http, char *buf,
			      size_t len ) {

	/* Construct host URI */
	return snprintf ( buf, len, "%s", http->request.host );
}

/** HTTP "Host" header "*/
struct http_request_header http_request_host __http_request_header = {
	.name = "Host",
	.format = http_format_host,
};

/**
 * Construct HTTP "User-Agent" header
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_user_agent ( struct http_transaction *http __unused,
				    char *buf, size_t len ) {

	/* Construct user agent */
	return snprintf ( buf, len, "iPXE/%s", product_version );
}

/** HTTP "User-Agent" header */
struct http_request_header http_request_user_agent __http_request_header = {
	.name = "User-Agent",
	.format = http_format_user_agent,
};

/**
 * Construct HTTP "Connection" header
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_connection ( struct http_transaction *http __unused,
				    char *buf, size_t len ) {

	/* Always request keep-alive */
	return snprintf ( buf, len, "keep-alive" );
}

/** HTTP "Connection" header */
struct http_request_header http_request_connection __http_request_header = {
	.name = "Connection",
	.format = http_format_connection,
};

/**
 * Construct HTTP "Range" header
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_range ( struct http_transaction *http,
			       char *buf, size_t len ) {

	/* Construct range, if applicable */
	if ( http->request.range.len ) {
		return snprintf ( buf, len, "bytes=%zd-%zd",
				  http->request.range.start,
				  ( http->request.range.start +
				    http->request.range.len - 1 ) );
	} else {
		return 0;
	}
}

/** HTTP "Range" header */
struct http_request_header http_request_range __http_request_header = {
	.name = "Range",
	.format = http_format_range,
};

/**
 * Construct HTTP "Content-Type" header
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_content_type ( struct http_transaction *http,
				      char *buf, size_t len ) {

	/* Construct content type, if applicable */
	if ( http->request.content.type ) {
		return snprintf ( buf, len, "%s", http->request.content.type );
	} else {
		return 0;
	}
}

/** HTTP "Content-Type" header */
struct http_request_header http_request_content_type __http_request_header = {
	.name = "Content-Type",
	.format = http_format_content_type,
};

/**
 * Construct HTTP "Content-Length" header
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_content_length ( struct http_transaction *http,
					char *buf, size_t len ) {

	/* Construct content length, if applicable */
	if ( http->request.content.len ) {
		return snprintf ( buf, len, "%zd", http->request.content.len );
	} else {
		return 0;
	}
}

/** HTTP "Content-Length" header */
struct http_request_header http_request_content_length __http_request_header = {
	.name = "Content-Length",
	.format = http_format_content_length,
};

/**
 * Construct HTTP "Accept-Encoding" header
 *
 * @v http		HTTP transaction
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of header value, or negative error
 */
static int http_format_accept_encoding ( struct http_transaction *http,
					 char *buf, size_t len ) {
	struct http_content_encoding *encoding;
	const char *sep = "";
	size_t used = 0;

	/* Construct list of content encodings */
	for_each_table_entry ( encoding, HTTP_CONTENT_ENCODINGS ) {
		if ( encoding->supported && ( ! encoding->supported ( http ) ) )
			continue;
		used += ssnprintf ( ( buf + used ), ( len - used ),
				    "%s%s", sep, encoding->name );
		sep = ", ";
	}

	return used;
}

/** HTTP "Accept-Encoding" header */
struct http_request_header http_request_accept_encoding __http_request_header ={
	.name = "Accept-Encoding",
	.format = http_format_accept_encoding,
};

/**
 * Transmit request
 *
 * @v http		HTTP transaction
 * @ret rc		Return status code
 */
static int http_tx_request ( struct http_transaction *http ) {
	struct io_buffer *iobuf;
	int len;
	int check_len;
	int rc;

	/* Calculate request length */
	len = http_format_headers ( http, NULL, 0 );
	if ( len < 0 ) {
		rc = len;
		DBGC ( http, "HTTP %p could not construct request: %s\n",
		       http, strerror ( rc ) );
		goto err_len;
	}

	/* Allocate I/O buffer */
	iobuf = alloc_iob ( len + 1 /* NUL */ + http->request.content.len );
	if ( ! iobuf ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Construct request */
	check_len = http_format_headers ( http, iob_put ( iobuf, len ),
					  ( len + 1 /* NUL */ ) );
	assert ( check_len == len );
	memcpy ( iob_put ( iobuf, http->request.content.len ),
		 http->request.content.data, http->request.content.len );

	/* Deliver request */
	if ( ( rc = xfer_deliver_iob ( &http->conn,
				       iob_disown ( iobuf ) ) ) != 0 ) {
		DBGC ( http, "HTTP %p could not deliver request: %s\n",
		       http, strerror ( rc ) );
		goto err_deliver;
	}

	/* Clear any previous response */
	empty_line_buffer ( &http->response.headers );
	memset ( &http->response, 0, sizeof ( http->response ) );

	/* Move to response headers state */
	http->state = &http_headers;

	return 0;

 err_deliver:
	free_iob ( iobuf );
 err_alloc:
 err_len:
	return rc;
}

/** HTTP request state */
static struct http_state http_request = {
	.tx = http_tx_request,
	.close = http_close_error,
};

/******************************************************************************
 *
 * Response headers
 *
 ******************************************************************************
 */

/**
 * Parse HTTP status line
 *
 * @v http		HTTP transaction
 * @v line		Status line
 * @ret rc		Return status code
 */
static int http_parse_status ( struct http_transaction *http, char *line ) {
	char *endp;
	char *version;
	char *vernum;
	char *status;
	int response_rc;

	DBGC2 ( http, "HTTP %p RX %s\n", http, line );

	/* Parse HTTP version */
	version = http_token ( &line, NULL );
	if ( ( ! version ) || ( strncmp ( version, "HTTP/", 5 ) != 0 ) ) {
		DBGC ( http, "HTTP %p malformed version \"%s\"\n", http, line );
		return -EINVAL_STATUS;
	}

	/* Keepalive is enabled by default for anything newer than HTTP/1.0 */
	vernum = ( version + 5 /* "HTTP/" (presence already checked) */ );
	if ( vernum[0] == '0' ) {
		/* HTTP/0.x : keepalive not enabled by default */
	} else if ( strncmp ( vernum, "1.0", 3 ) == 0 ) {
		/* HTTP/1.0 : keepalive not enabled by default */
	} else {
		/* HTTP/1.1 or newer: keepalive enabled by default */
		http->response.flags |= HTTP_RESPONSE_KEEPALIVE;
	}

	/* Parse status code */
	status = line;
	http->response.status = strtoul ( status, &endp, 10 );
	if ( *endp != ' ' ) {
		DBGC ( http, "HTTP %p malformed status code \"%s\"\n",
		       http, status );
		return -EINVAL_STATUS;
	}

	/* Convert HTTP status code to iPXE return status code */
	if ( status[0] == '2' ) {
		/* 2xx Success */
		response_rc = 0;
	} else if ( status[0] == '3' ) {
		/* 3xx Redirection */
		response_rc = -EXDEV;
	} else if ( http->response.status == 401 ) {
		/* 401 Unauthorized */
		response_rc = -EACCES_401;
	} else if ( http->response.status == 403 ) {
		/* 403 Forbidden */
		response_rc = -EPERM_403;
	} else if ( http->response.status == 404 ) {
		/* 404 Not Found */
		response_rc = -ENOENT_404;
	} else if ( status[0] == '4' ) {
		/* 4xx Client Error (not already specified) */
		response_rc = -EIO_4XX;
	} else if ( status[0] == '5' ) {
		/* 5xx Server Error */
		response_rc = -EIO_5XX;
	} else {
		/* Unrecognised */
		response_rc = -EIO_OTHER;
	}
	http->response.rc = response_rc;

	return 0;
}

/**
 * Parse HTTP header
 *
 * @v http		HTTP transaction
 * @v line		Header line
 * @ret rc		Return status code
 */
static int http_parse_header ( struct http_transaction *http, char *line ) {
	struct http_response_header *header;
	char *name = line;
	char *sep;

	DBGC2 ( http, "HTTP %p RX %s\n", http, line );

	/* Extract header name */
	sep = strstr ( line, ": " );
	if ( ! sep ) {
		DBGC ( http, "HTTP %p malformed header \"%s\"\n", http, line );
		return -EINVAL_HEADER;
	}
	*sep = '\0';
	line = ( sep + 2 /* ": " */ );

	/* Process header, if recognised */
	for_each_table_entry ( header, HTTP_RESPONSE_HEADERS ) {
		if ( strcasecmp ( name, header->name ) == 0 )
			return header->parse ( http, line );
	}

	/* Unrecognised headers should be ignored */
	return 0;
}

/**
 * Parse HTTP response headers
 *
 * @v http		HTTP transaction
 * @ret rc		Return status code
 */
static int http_parse_headers ( struct http_transaction *http ) {
	char *line;
	char *next;
	int rc;

	/* Get status line */
	line = http->response.headers.data;
	assert ( line != NULL );
	next = ( line + strlen ( line ) + 1 /* NUL */ );

	/* Parse status line */
	if ( ( rc = http_parse_status ( http, line ) ) != 0 )
		return rc;

	/* Process header lines */
	while ( 1 ) {

		/* Move to next line */
		line = next;
		next = ( line + strlen ( line ) + 1 /* NUL */ );

		/* Stop on terminating blank line */
		if ( ! line[0] )
			return 0;

		/* Process header line */
		if ( ( rc = http_parse_header ( http, line ) ) != 0 )
			return rc;
	}
}

/**
 * Parse HTTP "Location" header
 *
 * @v http		HTTP transaction
 * @v line		Remaining header line
 * @ret rc		Return status code
 */
static int http_parse_location ( struct http_transaction *http, char *line ) {

	/* Store location */
	http->response.location = line;
	return 0;
}

/** HTTP "Location" header */
struct http_response_header http_response_location __http_response_header = {
	.name = "Location",
	.parse = http_parse_location,
};

/**
 * Parse HTTP "Transfer-Encoding" header
 *
 * @v http		HTTP transaction
 * @v line		Remaining header line
 * @ret rc		Return status code
 */
static int http_parse_transfer_encoding ( struct http_transaction *http,
					  char *line ) {
	struct http_transfer_encoding *encoding;

	/* Check for known transfer encodings */
	for_each_table_entry ( encoding, HTTP_TRANSFER_ENCODINGS ) {
		if ( strcasecmp ( line, encoding->name ) == 0 ) {
			http->response.transfer.encoding = encoding;
			return 0;
		}
	}

	DBGC ( http, "HTTP %p unrecognised Transfer-Encoding \"%s\"\n",
	       http, line );
	return -ENOTSUP_TRANSFER;
}

/** HTTP "Transfer-Encoding" header */
struct http_response_header
http_response_transfer_encoding __http_response_header = {
	.name = "Transfer-Encoding",
	.parse = http_parse_transfer_encoding,
};

/**
 * Parse HTTP "Connection" header
 *
 * @v http		HTTP transaction
 * @v line		Remaining header line
 * @ret rc		Return status code
 */
static int http_parse_connection ( struct http_transaction *http, char *line ) {

	/* Check for known connection intentions */
	if ( strcasecmp ( line, "keep-alive" ) == 0 ) {
		http->response.flags |= HTTP_RESPONSE_KEEPALIVE;
		return 0;
	}
	if ( strcasecmp ( line, "close" ) == 0 ) {
		http->response.flags &= ~HTTP_RESPONSE_KEEPALIVE;
		return 0;
	}

	DBGC ( http, "HTTP %p unrecognised Connection \"%s\"\n", http, line );
	return -ENOTSUP_CONNECTION;
}

/** HTTP "Connection" header */
struct http_response_header http_response_connection __http_response_header = {
	.name = "Connection",
	.parse = http_parse_connection,
};

/**
 * Parse HTTP "Content-Length" header
 *
 * @v http		HTTP transaction
 * @v line		Remaining header line
 * @ret rc		Return status code
 */
static int http_parse_content_length ( struct http_transaction *http,
				       char *line ) {
	char *endp;

	/* Parse length */
	http->response.content.len = strtoul ( line, &endp, 10 );
	if ( *endp != '\0' ) {
		DBGC ( http, "HTTP %p invalid Content-Length \"%s\"\n",
		       http, line );
		return -EINVAL_CONTENT_LENGTH;
	}

	/* Record that we have a content length (since it may be zero) */
	http->response.flags |= HTTP_RESPONSE_CONTENT_LEN;

	return 0;
}

/** HTTP "Content-Length" header */
struct http_response_header
http_response_content_length __http_response_header = {
	.name = "Content-Length",
	.parse = http_parse_content_length,
};

/**
 * Parse HTTP "Content-Encoding" header
 *
 * @v http		HTTP transaction
 * @v line		Remaining header line
 * @ret rc		Return status code
 */
static int http_parse_content_encoding ( struct http_transaction *http,
					 char *line ) {
	struct http_content_encoding *encoding;

	/* Check for known content encodings */
	for_each_table_entry ( encoding, HTTP_CONTENT_ENCODINGS ) {
		if ( encoding->supported && ( ! encoding->supported ( http ) ) )
			continue;
		if ( strcasecmp ( line, encoding->name ) == 0 ) {
			http->response.content.encoding = encoding;
			return 0;
		}
	}

	/* Some servers (e.g. Apache) have a habit of specifying
	 * unwarranted content encodings.  For example, if Apache
	 * detects (via /etc/httpd/conf/magic) that a file's contents
	 * are gzip-compressed, it will set "Content-Encoding: x-gzip"
	 * regardless of the client's Accept-Encoding header.  The
	 * only viable way to handle such servers is to treat unknown
	 * content encodings as equivalent to "identity".
	 */
	DBGC ( http, "HTTP %p unrecognised Content-Encoding \"%s\"\n",
	       http, line );
	return 0;
}

/** HTTP "Content-Encoding" header */
struct http_response_header
http_response_content_encoding __http_response_header = {
	.name = "Content-Encoding",
	.parse = http_parse_content_encoding,
};

/**
 * Parse HTTP "Retry-After" header
 *
 * @v http		HTTP transaction
 * @v line		Remaining header line
 * @ret rc		Return status code
 */
static int http_parse_retry_after ( struct http_transaction *http,
				    char *line ) {
	char *endp;

	/* Try to parse value as a simple number of seconds */
	http->response.retry_after = strtoul ( line, &endp, 10 );
	if ( *endp != '\0' ) {
		/* For any value which is not a simple number of
		 * seconds (e.g. a full HTTP date), just retry after a
		 * fixed delay, since we don't have code able to parse
		 * full HTTP dates.
		 */
		http->response.retry_after = HTTP_RETRY_SECONDS;
		DBGC ( http, "HTTP %p cannot understand Retry-After \"%s\"; "
		       "using %d seconds\n", http, line, HTTP_RETRY_SECONDS );
	}

	/* Allow HTTP request to be retried after specified delay */
	http->response.flags |= HTTP_RESPONSE_RETRY;

	return 0;
}

/** HTTP "Retry-After" header */
struct http_response_header http_response_retry_after __http_response_header = {
	.name = "Retry-After",
	.parse = http_parse_retry_after,
};

/**
 * Handle received HTTP headers
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer (may be claimed)
 * @ret rc		Return status code
 */
static int http_rx_headers ( struct http_transaction *http,
			     struct io_buffer **iobuf ) {
	struct http_transfer_encoding *transfer;
	struct http_content_encoding *content;
	char *line;
	int rc;

	/* Buffer header line */
	if ( ( rc = http_rx_linebuf ( http, *iobuf,
				      &http->response.headers ) ) != 0 )
		return rc;

	/* Wait until we see the empty line marking end of headers */
	line = buffered_line ( &http->response.headers );
	if ( ( line == NULL ) || ( line[0] != '\0' ) )
		return 0;

	/* Process headers */
	if ( ( rc = http_parse_headers ( http ) ) != 0 )
		return rc;

	/* Initialise content encoding, if applicable */
	if ( ( content = http->response.content.encoding ) &&
	     ( ( rc = content->init ( http ) ) != 0 ) ) {
		DBGC ( http, "HTTP %p could not initialise %s content "
		       "encoding: %s\n", http, content->name, strerror ( rc ) );
		return rc;
	}

	/* Presize receive buffer, if we have a content length */
	if ( http->response.content.len ) {
		xfer_seek ( &http->transfer, http->response.content.len );
		xfer_seek ( &http->transfer, 0 );
	}

	/* Complete transfer if this is a HEAD request */
	if ( http->request.method == &http_head ) {
		if ( ( rc = http_transfer_complete ( http ) ) != 0 )
			return rc;
		return 0;
	}

	/* Default to identity transfer encoding, if none specified */
	if ( ! http->response.transfer.encoding )
		http->response.transfer.encoding = &http_transfer_identity;

	/* Move to transfer encoding-specific data state */
	transfer = http->response.transfer.encoding;
	http->state = &transfer->state;

	/* Initialise transfer encoding */
	if ( ( rc = transfer->init ( http ) ) != 0 ) {
		DBGC ( http, "HTTP %p could not initialise %s transfer "
		       "encoding: %s\n", http, transfer->name, strerror ( rc ));
		return rc;
	}

	return 0;
}

/** HTTP response headers state */
static struct http_state http_headers = {
	.rx = http_rx_headers,
	.close = http_close_error,
};

/******************************************************************************
 *
 * Identity transfer encoding
 *
 ******************************************************************************
 */

/**
 * Initialise transfer encoding
 *
 * @v http		HTTP transaction
 * @ret rc		Return status code
 */
static int http_init_transfer_identity ( struct http_transaction *http ) {
	int rc;

	/* Complete transfer immediately if we have a zero content length */
	if ( ( http->response.flags & HTTP_RESPONSE_CONTENT_LEN ) &&
	     ( http->response.content.len == 0 ) &&
	     ( ( rc = http_transfer_complete ( http ) ) != 0 ) )
		return rc;

	return 0;
}

/**
 * Handle received data
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer (may be claimed)
 * @ret rc		Return status code
 */
static int http_rx_transfer_identity ( struct http_transaction *http,
				       struct io_buffer **iobuf ) {
	size_t len = iob_len ( *iobuf );
	int rc;

	/* Update lengths */
	http->len += len;

	/* Fail if this transfer would overrun the expected content
	 * length (if any).
	 */
	if ( ( http->response.flags & HTTP_RESPONSE_CONTENT_LEN ) &&
	     ( http->len > http->response.content.len ) ) {
		DBGC ( http, "HTTP %p content length overrun\n", http );
		return -EIO_CONTENT_LENGTH;
	}

	/* Hand off to content encoding */
	if ( ( rc = xfer_deliver_iob ( &http->transfer,
				       iob_disown ( *iobuf ) ) ) != 0 )
		return rc;

	/* Complete transfer if we have received the expected content
	 * length (if any).
	 */
	if ( ( http->response.flags & HTTP_RESPONSE_CONTENT_LEN ) &&
	     ( http->len == http->response.content.len ) &&
	     ( ( rc = http_transfer_complete ( http ) ) != 0 ) )
		return rc;

	return 0;
}

/**
 * Handle server connection close
 *
 * @v http		HTTP transaction
 * @v rc		Reason for close
 */
static void http_close_transfer_identity ( struct http_transaction *http,
					   int rc ) {

	/* Fail if any error occurred */
	if ( rc != 0 )
		goto err;

	/* Fail if we have a content length (since we would have
	 * already closed the connection if we had received the
	 * correct content length).
	 */
	if ( http->response.flags & HTTP_RESPONSE_CONTENT_LEN ) {
		DBGC ( http, "HTTP %p content length underrun\n", http );
		rc = EIO_CONTENT_LENGTH;
		goto err;
	}

	/* Indicate that transfer is complete */
	if ( ( rc = http_transfer_complete ( http ) ) != 0 )
		goto err;

	return;

 err:
	http_close ( http, rc );
}

/** Identity transfer encoding */
static struct http_transfer_encoding http_transfer_identity = {
	.name = "identity",
	.init = http_init_transfer_identity,
	.state = {
		.rx = http_rx_transfer_identity,
		.close = http_close_transfer_identity,
	},
};

/******************************************************************************
 *
 * Chunked transfer encoding
 *
 ******************************************************************************
 */

/**
 * Initialise transfer encoding
 *
 * @v http		HTTP transaction
 * @ret rc		Return status code
 */
static int http_init_transfer_chunked ( struct http_transaction *http ) {

	/* Sanity checks */
	assert ( http->remaining == 0 );
	assert ( http->linebuf.len == 0 );

	return 0;
}

/**
 * Handle received chunk length
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer (may be claimed)
 * @ret rc		Return status code
 */
static int http_rx_chunk_len ( struct http_transaction *http,
			       struct io_buffer **iobuf ) {
	char *line;
	char *endp;
	size_t len;
	int rc;

	/* Receive into temporary line buffer */
	if ( ( rc = http_rx_linebuf ( http, *iobuf, &http->linebuf ) ) != 0 )
		return rc;

	/* Wait until we receive a non-empty line */
	line = buffered_line ( &http->linebuf );
	if ( ( line == NULL ) || ( line[0] == '\0' ) )
		return 0;

	/* Parse chunk length */
	http->remaining = strtoul ( line, &endp, 16 );
	if ( *endp != '\0' ) {
		DBGC ( http, "HTTP %p invalid chunk length \"%s\"\n",
		       http, line );
		return -EINVAL_CHUNK_LENGTH;
	}

	/* Empty line buffer */
	empty_line_buffer ( &http->linebuf );

	/* Update expected length */
	len = ( http->len + http->remaining );
	xfer_seek ( &http->transfer, len );
	xfer_seek ( &http->transfer, http->len );

	/* If chunk length is zero, then move to response trailers state */
	if ( ! http->remaining )
		http->state = &http_trailers;

	return 0;
}

/**
 * Handle received chunk data
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer (may be claimed)
 * @ret rc		Return status code
 */
static int http_rx_chunk_data ( struct http_transaction *http,
				struct io_buffer **iobuf ) {
	struct io_buffer *payload;
	uint8_t *crlf;
	size_t len;
	int rc;

	/* In the common case of a final chunk in a packet which also
	 * includes the terminating CRLF, strip the terminating CRLF
	 * (which we would ignore anyway) and hence avoid
	 * unnecessarily copying the data.
	 */
	if ( iob_len ( *iobuf ) == ( http->remaining + 2 /* CRLF */ ) ) {
		crlf = ( (*iobuf)->data + http->remaining );
		if ( ( crlf[0] == '\r' ) && ( crlf[1] == '\n' ) )
			iob_unput ( (*iobuf), 2 /* CRLF */ );
	}
	len = iob_len ( *iobuf );

	/* Use whole/partial buffer as applicable */
	if ( len <= http->remaining ) {

		/* Whole buffer is to be consumed: decrease remaining
		 * length and use original I/O buffer as payload.
		 */
		payload = iob_disown ( *iobuf );
		http->len += len;
		http->remaining -= len;

	} else {

		/* Partial buffer is to be consumed: copy data to a
		 * temporary I/O buffer.
		 */
		payload = alloc_iob ( http->remaining );
		if ( ! payload ) {
			rc = -ENOMEM;
			goto err;
		}
		memcpy ( iob_put ( payload, http->remaining ), (*iobuf)->data,
			 http->remaining );
		iob_pull ( *iobuf, http->remaining );
		http->len += http->remaining;
		http->remaining = 0;
	}

	/* Hand off to content encoding */
	if ( ( rc = xfer_deliver_iob ( &http->transfer,
				       iob_disown ( payload ) ) ) != 0 )
		goto err;

	return 0;

 err:
	assert ( payload == NULL );
	return rc;
}

/**
 * Handle received chunked data
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer (may be claimed)
 * @ret rc		Return status code
 */
static int http_rx_transfer_chunked ( struct http_transaction *http,
				      struct io_buffer **iobuf ) {

	/* Handle as chunk length or chunk data as appropriate */
	if ( http->remaining ) {
		return http_rx_chunk_data ( http, iobuf );
	} else {
		return http_rx_chunk_len ( http, iobuf );
	}
}

/** Chunked transfer encoding */
struct http_transfer_encoding http_transfer_chunked __http_transfer_encoding = {
	.name = "chunked",
	.init = http_init_transfer_chunked,
	.state = {
		.rx = http_rx_transfer_chunked,
		.close = http_close_error,
	},
};

/******************************************************************************
 *
 * Response trailers
 *
 ******************************************************************************
 */

/**
 * Handle received HTTP trailer
 *
 * @v http		HTTP transaction
 * @v iobuf		I/O buffer (may be claimed)
 * @ret rc		Return status code
 */
static int http_rx_trailers ( struct http_transaction *http,
			      struct io_buffer **iobuf ) {
	char *line;
	int rc;

	/* Buffer trailer line */
	if ( ( rc = http_rx_linebuf ( http, *iobuf, &http->linebuf ) ) != 0 )
		return rc;

	/* Wait until we see the empty line marking end of trailers */
	line = buffered_line ( &http->linebuf );
	if ( ( line == NULL ) || ( line[0] != '\0' ) )
		return 0;

	/* Empty line buffer */
	empty_line_buffer ( &http->linebuf );

	/* Transfer is complete */
	if ( ( rc = http_transfer_complete ( http ) ) != 0 )
		return rc;

	return 0;
}

/** HTTP response trailers state */
static struct http_state http_trailers = {
	.rx = http_rx_trailers,
	.close = http_close_error,
};

/******************************************************************************
 *
 * Simple URI openers
 *
 ******************************************************************************
 */

/**
 * Construct HTTP parameter list
 *
 * @v params		Parameter list
 * @v buf		Buffer to contain HTTP POST parameters
 * @v len		Length of buffer
 * @ret len		Length of parameter list (excluding terminating NUL)
 */
static size_t http_params ( struct parameters *params, char *buf, size_t len ) {
	struct parameter *param;
	ssize_t remaining = len;
	size_t frag_len;

	/* Add each parameter in the form "key=value", joined with "&" */
	len = 0;
	for_each_param ( param, params ) {

		/* Add the "&", if applicable */
		if ( len ) {
			if ( remaining > 0 )
				*buf = '&';
			buf++;
			len++;
			remaining--;
		}

		/* URI-encode the key */
		frag_len = uri_encode ( param->key, 0, buf, remaining );
		buf += frag_len;
		len += frag_len;
		remaining -= frag_len;

		/* Add the "=" */
		if ( remaining > 0 )
			*buf = '=';
		buf++;
		len++;
		remaining--;

		/* URI-encode the value */
		frag_len = uri_encode ( param->value, 0, buf, remaining );
		buf += frag_len;
		len += frag_len;
		remaining -= frag_len;
	}

	/* Ensure string is NUL-terminated even if no parameters are present */
	if ( remaining > 0 )
		*buf = '\0';

	return len;
}

/**
 * Open HTTP transaction for simple GET URI
 *
 * @v xfer		Data transfer interface
 * @v uri		Request URI
 * @ret rc		Return status code
 */
static int http_open_get_uri ( struct interface *xfer, struct uri *uri ) {

	return http_open ( xfer, &http_get, uri, NULL, NULL );
}

/**
 * Open HTTP transaction for simple POST URI
 *
 * @v xfer		Data transfer interface
 * @v uri		Request URI
 * @ret rc		Return status code
 */
static int http_open_post_uri ( struct interface *xfer, struct uri *uri ) {
	struct parameters *params = uri->params;
	struct http_request_content content;
	void *data;
	size_t len;
	size_t check_len;
	int rc;

	/* Calculate length of parameter list */
	len = http_params ( params, NULL, 0 );

	/* Allocate temporary parameter list */
	data = zalloc ( len + 1 /* NUL */ );
	if ( ! data ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Construct temporary parameter list */
	check_len = http_params ( params, data, ( len + 1 /* NUL */ ) );
	assert ( check_len == len );

	/* Construct request content */
	content.type = "application/x-www-form-urlencoded";
	content.data = data;
	content.len = len;

	/* Open HTTP transaction */
	if ( ( rc = http_open ( xfer, &http_post, uri, NULL, &content ) ) != 0 )
		goto err_open;

 err_open:
	free ( data );
 err_alloc:
	return rc;
}

/**
 * Open HTTP transaction for simple URI
 *
 * @v xfer		Data transfer interface
 * @v uri		Request URI
 * @ret rc		Return status code
 */
int http_open_uri ( struct interface *xfer, struct uri *uri ) {

	/* Open GET/POST URI as applicable */
	if ( uri->params ) {
		return http_open_post_uri ( xfer, uri );
	} else {
		return http_open_get_uri ( xfer, uri );
	}
}

/* Drag in HTTP extensions */
REQUIRING_SYMBOL ( http_open );
REQUIRE_OBJECT ( config_http );
