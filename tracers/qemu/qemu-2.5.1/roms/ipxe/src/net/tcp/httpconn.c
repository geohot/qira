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
 * Hyper Text Transfer Protocol (HTTP) connection management
 *
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/tcpip.h>
#include <ipxe/uri.h>
#include <ipxe/timer.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/pool.h>
#include <ipxe/http.h>

/** HTTP pooled connection expiry time */
#define HTTP_CONN_EXPIRY ( 10 * TICKS_PER_SEC )

/** HTTP connection pool */
static LIST_HEAD ( http_connection_pool );

/**
 * Identify HTTP scheme
 *
 * @v uri		URI
 * @ret scheme		HTTP scheme, or NULL
 */
static struct http_scheme * http_scheme ( struct uri *uri ) {
	struct http_scheme *scheme;

	/* Sanity check */
	if ( ! uri->scheme )
		return NULL;

	/* Identify scheme */
	for_each_table_entry ( scheme, HTTP_SCHEMES ) {
		if ( strcmp ( uri->scheme, scheme->name ) == 0 )
			return scheme;
	}

	return NULL;
}

/**
 * Free HTTP connection
 *
 * @v refcnt		Reference count
 */
static void http_conn_free ( struct refcnt *refcnt ) {
	struct http_connection *conn =
		container_of ( refcnt, struct http_connection, refcnt );

	/* Free connection */
	uri_put ( conn->uri );
	free ( conn );
}

/**
 * Close HTTP connection
 *
 * @v conn		HTTP connection
 * @v rc		Reason for close
 */
static void http_conn_close ( struct http_connection *conn, int rc ) {

	/* Remove from connection pool, if applicable */
	pool_del ( &conn->pool );

	/* Shut down interfaces */
	intf_shutdown ( &conn->socket, rc );
	intf_shutdown ( &conn->xfer, rc );
	if ( rc == 0 ) {
		DBGC2 ( conn, "HTTPCONN %p closed %s://%s\n",
			conn, conn->scheme->name, conn->uri->host );
	} else {
		DBGC ( conn, "HTTPCONN %p closed %s://%s: %s\n",
		       conn, conn->scheme->name, conn->uri->host,
		       strerror ( rc ) );
	}
}

/**
 * Disconnect idle HTTP connection
 *
 * @v pool		Pooled connection
 */
static void http_conn_expired ( struct pooled_connection *pool ) {
	struct http_connection *conn =
		container_of ( pool, struct http_connection, pool );

	/* Close connection */
	http_conn_close ( conn, 0 /* Not an error to close idle connection */ );
}

/**
 * Receive data from transport layer interface
 *
 * @v http		HTTP connection
 * @v iobuf		I/O buffer
 * @v meta		Transfer metadata
 * @ret rc		Return status code
 */
static int http_conn_socket_deliver ( struct http_connection *conn,
				      struct io_buffer *iobuf,
				      struct xfer_metadata *meta ) {

	/* Mark connection as alive */
	pool_alive ( &conn->pool );

	/* Pass on to data transfer interface */
	return xfer_deliver ( &conn->xfer, iobuf, meta );
}

/**
 * Close HTTP connection transport layer interface
 *
 * @v http		HTTP connection
 * @v rc		Reason for close
 */
static void http_conn_socket_close ( struct http_connection *conn, int rc ) {

	/* If we are reopenable (i.e. we are a recycled connection
	 * from the connection pool, and we have received no data from
	 * the underlying socket since we were pooled), then suggest
	 * that the client should reopen the connection.
	 */
	if ( pool_is_reopenable ( &conn->pool ) )
		pool_reopen ( &conn->xfer );

	/* Close the connection */
	http_conn_close ( conn, rc );
}

/**
 * Recycle this connection after closing
 *
 * @v http		HTTP connection
 */
static void http_conn_xfer_recycle ( struct http_connection *conn ) {

	/* Mark connection as recyclable */
	pool_recyclable ( &conn->pool );
	DBGC2 ( conn, "HTTPCONN %p keepalive enabled\n", conn );
}

/**
 * Close HTTP connection data transfer interface
 *
 * @v conn		HTTP connection
 * @v rc		Reason for close
 */
static void http_conn_xfer_close ( struct http_connection *conn, int rc ) {

	/* Add to the connection pool if keepalive is enabled and no
	 * error occurred.
	 */
	if ( ( rc == 0 ) && pool_is_recyclable ( &conn->pool ) ) {
		intf_restart ( &conn->xfer, rc );
		pool_add ( &conn->pool, &http_connection_pool,
			   HTTP_CONN_EXPIRY );
		DBGC2 ( conn, "HTTPCONN %p pooled %s://%s\n",
			conn, conn->scheme->name, conn->uri->host );
		return;
	}

	/* Otherwise, close the connection */
	http_conn_close ( conn, rc );
}

/** HTTP connection socket interface operations */
static struct interface_operation http_conn_socket_operations[] = {
	INTF_OP ( xfer_deliver, struct http_connection *,
		  http_conn_socket_deliver ),
	INTF_OP ( intf_close, struct http_connection *,
		  http_conn_socket_close ),
};

/** HTTP connection socket interface descriptor */
static struct interface_descriptor http_conn_socket_desc =
	INTF_DESC_PASSTHRU ( struct http_connection, socket,
			     http_conn_socket_operations, xfer );

/** HTTP connection data transfer interface operations */
static struct interface_operation http_conn_xfer_operations[] = {
	INTF_OP ( pool_recycle, struct http_connection *,
		  http_conn_xfer_recycle ),
	INTF_OP ( intf_close, struct http_connection *,
		  http_conn_xfer_close ),
};

/** HTTP connection data transfer interface descriptor */
static struct interface_descriptor http_conn_xfer_desc =
	INTF_DESC_PASSTHRU ( struct http_connection, xfer,
			     http_conn_xfer_operations, socket );

/**
 * Connect to an HTTP server
 *
 * @v xfer		Data transfer interface
 * @v uri		Connection URI
 * @ret rc		Return status code
 *
 * HTTP connections are pooled.  The caller should be prepared to
 * receive a pool_reopen() message.
 */
int http_connect ( struct interface *xfer, struct uri *uri ) {
	struct http_connection *conn;
	struct http_scheme *scheme;
	struct sockaddr_tcpip server;
	struct interface *socket;
	int rc;

	/* Identify scheme */
	scheme = http_scheme ( uri );
	if ( ! scheme )
		return -ENOTSUP;

	/* Sanity check */
	if ( ! uri->host )
		return -EINVAL;

	/* Look for a reusable connection in the pool */
	list_for_each_entry ( conn, &http_connection_pool, pool.list ) {

		/* Sanity checks */
		assert ( conn->uri != NULL );
		assert ( conn->uri->host != NULL );

		/* Reuse connection, if possible */
		if ( ( scheme == conn->scheme ) &&
		     ( strcmp ( uri->host, conn->uri->host ) == 0 ) ) {

			/* Remove from connection pool, stop timer,
			 * attach to parent interface, and return.
			 */
			pool_del ( &conn->pool );
			intf_plug_plug ( &conn->xfer, xfer );
			DBGC2 ( conn, "HTTPCONN %p reused %s://%s\n",
				conn, conn->scheme->name, conn->uri->host );
			return 0;
		}
	}

	/* Allocate and initialise structure */
	conn = zalloc ( sizeof ( *conn ) );
	ref_init ( &conn->refcnt, http_conn_free );
	conn->uri = uri_get ( uri );
	conn->scheme = scheme;
	intf_init ( &conn->socket, &http_conn_socket_desc, &conn->refcnt );
	intf_init ( &conn->xfer, &http_conn_xfer_desc, &conn->refcnt );
	pool_init ( &conn->pool, http_conn_expired, &conn->refcnt );

	/* Open socket */
	memset ( &server, 0, sizeof ( server ) );
	server.st_port = htons ( uri_port ( uri, scheme->port ) );
	socket = &conn->socket;
	if ( scheme->filter &&
	     ( ( rc = scheme->filter ( socket, uri->host, &socket ) ) != 0 ) )
		goto err_filter;
	if ( ( rc = xfer_open_named_socket ( socket, SOCK_STREAM,
					     ( struct sockaddr * ) &server,
					     uri->host, NULL ) ) != 0 )
		goto err_open;

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( &conn->xfer, xfer );
	ref_put ( &conn->refcnt );

	DBGC2 ( conn, "HTTPCONN %p created %s://%s:%d\n", conn,
		conn->scheme->name, conn->uri->host, ntohs ( server.st_port ) );
	return 0;

 err_open:
 err_filter:
	DBGC2 ( conn, "HTTPCONN %p could not create %s://%s: %s\n",
		conn, conn->scheme->name, conn->uri->host, strerror ( rc ) );
	http_conn_close ( conn, rc );
	ref_put ( &conn->refcnt );
	return rc;
}
