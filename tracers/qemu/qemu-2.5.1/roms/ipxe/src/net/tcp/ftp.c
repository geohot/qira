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
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <byteswap.h>
#include <ipxe/socket.h>
#include <ipxe/tcpip.h>
#include <ipxe/in.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/features.h>
#include <ipxe/ftp.h>

/** @file
 *
 * File transfer protocol
 *
 */

FEATURE ( FEATURE_PROTOCOL, "FTP", DHCP_EB_FEATURE_FTP, 1 );

/**
 * FTP states
 *
 * These @b must be sequential, i.e. a successful FTP session must
 * pass through each of these states in order.
 */
enum ftp_state {
	FTP_CONNECT = 0,
	FTP_USER,
	FTP_PASS,
	FTP_TYPE,
	FTP_SIZE,
	FTP_PASV,
	FTP_RETR,
	FTP_WAIT,
	FTP_QUIT,
	FTP_DONE,
};

/**
 * An FTP request
 *
 */
struct ftp_request {
	/** Reference counter */
	struct refcnt refcnt;
	/** Data transfer interface */
	struct interface xfer;

	/** URI being fetched */
	struct uri *uri;
	/** FTP control channel interface */
	struct interface control;
	/** FTP data channel interface */
	struct interface data;

	/** Current state */
	enum ftp_state state;
	/** Buffer to be filled with data received via the control channel */
	char *recvbuf;
	/** Remaining size of recvbuf */
	size_t recvsize;
	/** FTP status code, as text */
	char status_text[5];
	/** Passive-mode parameters, as text */
	char passive_text[24]; /* "aaa,bbb,ccc,ddd,eee,fff" */
	/** File size, as text */
	char filesize[20];
};

/**
 * Free FTP request
 *
 * @v refcnt		Reference counter
 */
static void ftp_free ( struct refcnt *refcnt ) {
	struct ftp_request *ftp =
		container_of ( refcnt, struct ftp_request, refcnt );

	DBGC ( ftp, "FTP %p freed\n", ftp );

	uri_put ( ftp->uri );
	free ( ftp );
}

/**
 * Mark FTP operation as complete
 *
 * @v ftp		FTP request
 * @v rc		Return status code
 */
static void ftp_done ( struct ftp_request *ftp, int rc ) {

	DBGC ( ftp, "FTP %p completed (%s)\n", ftp, strerror ( rc ) );

	/* Close all data transfer interfaces */
	intf_shutdown ( &ftp->data, rc );
	intf_shutdown ( &ftp->control, rc );
	intf_shutdown ( &ftp->xfer, rc );
}

/*****************************************************************************
 *
 * FTP control channel
 *
 */

/** An FTP control channel string */
struct ftp_control_string {
	/** Literal portion */
	const char *literal;
	/** Variable portion
	 *
	 * @v ftp	FTP request
	 * @ret string	Variable portion of string
	 */
	const char * ( *variable ) ( struct ftp_request *ftp );
};

/**
 * Retrieve FTP pathname
 *
 * @v ftp		FTP request
 * @ret path		FTP pathname
 */
static const char * ftp_uri_path ( struct ftp_request *ftp ) {
	return ftp->uri->path;
}

/**
 * Retrieve FTP user
 *
 * @v ftp		FTP request
 * @ret user		FTP user
 */
static const char * ftp_user ( struct ftp_request *ftp ) {
	static char *ftp_default_user = "anonymous";
	return ftp->uri->user ? ftp->uri->user : ftp_default_user;
}

/**
 * Retrieve FTP password
 *
 * @v ftp		FTP request
 * @ret password	FTP password
 */
static const char * ftp_password ( struct ftp_request *ftp ) {
	static char *ftp_default_password = "ipxe@ipxe.org";
	return ftp->uri->password ? ftp->uri->password : ftp_default_password;
}

/** FTP control channel strings */
static struct ftp_control_string ftp_strings[] = {
	[FTP_CONNECT]	= { NULL, NULL },
	[FTP_USER]	= { "USER ", ftp_user },
	[FTP_PASS]	= { "PASS ", ftp_password },
	[FTP_TYPE]	= { "TYPE I", NULL },
	[FTP_SIZE]	= { "SIZE ", ftp_uri_path },
	[FTP_PASV]	= { "PASV", NULL },
	[FTP_RETR]	= { "RETR ", ftp_uri_path },
	[FTP_WAIT]	= { NULL, NULL },
	[FTP_QUIT]	= { "QUIT", NULL },
	[FTP_DONE]	= { NULL, NULL },
};

/**
 * Parse FTP byte sequence value
 *
 * @v text		Text string
 * @v value		Value buffer
 * @v len		Length of value buffer
 *
 * This parses an FTP byte sequence value (e.g. the "aaa,bbb,ccc,ddd"
 * form for IP addresses in PORT commands) into a byte sequence.  @c
 * *text will be updated to point beyond the end of the parsed byte
 * sequence.
 *
 * This function is safe in the presence of malformed data, though the
 * output is undefined.
 */
static void ftp_parse_value ( char **text, uint8_t *value, size_t len ) {
	do {
		*(value++) = strtoul ( *text, text, 10 );
		if ( **text )
			(*text)++;
	} while ( --len );
}

/**
 * Move to next state and send the appropriate FTP control string
 *
 * @v ftp		FTP request
 *
 */
static void ftp_next_state ( struct ftp_request *ftp ) {
	struct ftp_control_string *ftp_string;
	const char *literal;
	const char *variable;

	/* Move to next state */
	if ( ftp->state < FTP_DONE )
		ftp->state++;

	/* Send control string if needed */
	ftp_string = &ftp_strings[ftp->state];
	literal = ftp_string->literal;
	variable = ( ftp_string->variable ?
		     ftp_string->variable ( ftp ) : "" );
	if ( literal ) {
		DBGC ( ftp, "FTP %p sending %s%s\n", ftp, literal, variable );
		xfer_printf ( &ftp->control, "%s%s\r\n", literal, variable );
	}
}

/**
 * Handle an FTP control channel response
 *
 * @v ftp		FTP request
 *
 * This is called once we have received a complete response line.
 */
static void ftp_reply ( struct ftp_request *ftp ) {
	char status_major = ftp->status_text[0];
	char separator = ftp->status_text[3];

	DBGC ( ftp, "FTP %p received status %s\n", ftp, ftp->status_text );

	/* Ignore malformed lines */
	if ( separator != ' ' )
		return;

	/* Ignore "intermediate" responses (1xx codes) */
	if ( status_major == '1' )
		return;

	/* If the SIZE command is not supported by the server, we go to
	 * the next step.
	 */
	if ( ( status_major == '5' ) && ( ftp->state == FTP_SIZE ) ) {
		ftp_next_state ( ftp );
		return;
	}

	/* Anything other than success (2xx) or, in the case of a
	 * repsonse to a "USER" command, a password prompt (3xx), is a
	 * fatal error.
	 */
	if ( ! ( ( status_major == '2' ) ||
		 ( ( status_major == '3' ) && ( ftp->state == FTP_USER ) ) ) ){
		/* Flag protocol error and close connections */
		ftp_done ( ftp, -EPROTO );
		return;
	}

	/* Parse file size */
	if ( ftp->state == FTP_SIZE ) {
		size_t filesize;
		char *endptr;

		/* Parse size */
		filesize = strtoul ( ftp->filesize, &endptr, 10 );
		if ( *endptr != '\0' ) {
			DBGC ( ftp, "FTP %p invalid SIZE \"%s\"\n",
			       ftp, ftp->filesize );
			ftp_done ( ftp, -EPROTO );
			return;
		}

		/* Use seek() to notify recipient of filesize */
		DBGC ( ftp, "FTP %p file size is %zd bytes\n", ftp, filesize );
		xfer_seek ( &ftp->xfer, filesize );
		xfer_seek ( &ftp->xfer, 0 );
	}

	/* Open passive connection when we get "PASV" response */
	if ( ftp->state == FTP_PASV ) {
		char *ptr = ftp->passive_text;
		union {
			struct sockaddr_in sin;
			struct sockaddr sa;
		} sa;
		int rc;

		sa.sin.sin_family = AF_INET;
		ftp_parse_value ( &ptr, ( uint8_t * ) &sa.sin.sin_addr,
				  sizeof ( sa.sin.sin_addr ) );
		ftp_parse_value ( &ptr, ( uint8_t * ) &sa.sin.sin_port,
				  sizeof ( sa.sin.sin_port ) );
		if ( ( rc = xfer_open_socket ( &ftp->data, SOCK_STREAM,
					       &sa.sa, NULL ) ) != 0 ) {
			DBGC ( ftp, "FTP %p could not open data connection\n",
			       ftp );
			ftp_done ( ftp, rc );
			return;
		}
	}

	/* Move to next state and send control string */
	ftp_next_state ( ftp );
	
}

/**
 * Handle new data arriving on FTP control channel
 *
 * @v ftp		FTP request
 * @v iob		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 *
 * Data is collected until a complete line is received, at which point
 * its information is passed to ftp_reply().
 */
static int ftp_control_deliver ( struct ftp_request *ftp,
				 struct io_buffer *iobuf,
				 struct xfer_metadata *meta __unused ) {
	char *data = iobuf->data;
	size_t len = iob_len ( iobuf );
	char *recvbuf = ftp->recvbuf;
	size_t recvsize = ftp->recvsize;
	char c;
	
	while ( len-- ) {
		c = *(data++);
		if ( ( c == '\r' ) || ( c == '\n' ) ) {
			/* End of line: call ftp_reply() to handle
			 * completed reply.  Avoid calling ftp_reply()
			 * twice if we receive both \r and \n.
			 */
			if ( recvbuf != ftp->status_text )
				ftp_reply ( ftp );
			/* Start filling up the status code buffer */
			recvbuf = ftp->status_text;
			recvsize = sizeof ( ftp->status_text ) - 1;
		} else if ( ( ftp->state == FTP_PASV ) && ( c == '(' ) ) {
			/* Start filling up the passive parameter buffer */
			recvbuf = ftp->passive_text;
			recvsize = sizeof ( ftp->passive_text ) - 1;
		} else if ( ( ftp->state == FTP_PASV ) && ( c == ')' ) ) {
			/* Stop filling the passive parameter buffer */
			recvsize = 0;
		} else if ( ( ftp->state == FTP_SIZE ) && ( c == ' ' ) ) {
			/* Start filling up the file size buffer */
			recvbuf = ftp->filesize;
			recvsize = sizeof ( ftp->filesize ) - 1;
		} else {
			/* Fill up buffer if applicable */
			if ( recvsize > 0 ) {
				*(recvbuf++) = c;
				recvsize--;
			}
		}
	}

	/* Store for next invocation */
	ftp->recvbuf = recvbuf;
	ftp->recvsize = recvsize;

	/* Free I/O buffer */
	free_iob ( iobuf );

	return 0;
}

/** FTP control channel interface operations */
static struct interface_operation ftp_control_operations[] = {
	INTF_OP ( xfer_deliver, struct ftp_request *, ftp_control_deliver ),
	INTF_OP ( intf_close, struct ftp_request *, ftp_done ),
};

/** FTP control channel interface descriptor */
static struct interface_descriptor ftp_control_desc =
	INTF_DESC ( struct ftp_request, control, ftp_control_operations );

/*****************************************************************************
 *
 * FTP data channel
 *
 */

/**
 * Handle FTP data channel being closed
 *
 * @v ftp		FTP request
 * @v rc		Reason for closure
 *
 * When the data channel is closed, the control channel should be left
 * alone; the server will send a completion message via the control
 * channel which we'll pick up.
 *
 * If the data channel is closed due to an error, we abort the request.
 */
static void ftp_data_closed ( struct ftp_request *ftp, int rc ) {

	DBGC ( ftp, "FTP %p data connection closed: %s\n",
	       ftp, strerror ( rc ) );
	
	/* If there was an error, close control channel and record status */
	if ( rc ) {
		ftp_done ( ftp, rc );
	} else {
		ftp_next_state ( ftp );
	}
}

/** FTP data channel interface operations */
static struct interface_operation ftp_data_operations[] = {
	INTF_OP ( intf_close, struct ftp_request *, ftp_data_closed ),
};

/** FTP data channel interface descriptor */
static struct interface_descriptor ftp_data_desc =
	INTF_DESC_PASSTHRU ( struct ftp_request, data, ftp_data_operations,
			     xfer );

/*****************************************************************************
 *
 * Data transfer interface
 *
 */

/** FTP data transfer interface operations */
static struct interface_operation ftp_xfer_operations[] = {
	INTF_OP ( intf_close, struct ftp_request *, ftp_done ),
};

/** FTP data transfer interface descriptor */
static struct interface_descriptor ftp_xfer_desc =
	INTF_DESC_PASSTHRU ( struct ftp_request, xfer, ftp_xfer_operations,
			     data );

/*****************************************************************************
 *
 * URI opener
 *
 */

/**
 * Check validity of FTP control channel string
 *
 * @v string		String
 * @ret rc		Return status code
 */
static int ftp_check_string ( const char *string ) {
	char c;

	/* The FTP control channel is line-based.  Check for invalid
	 * non-printable characters (e.g. newlines).
	 */
	while ( ( c = *(string++) ) ) {
		if ( ! isprint ( c ) )
			return -EINVAL;
	}
	return 0;
}

/**
 * Initiate an FTP connection
 *
 * @v xfer		Data transfer interface
 * @v uri		Uniform Resource Identifier
 * @ret rc		Return status code
 */
static int ftp_open ( struct interface *xfer, struct uri *uri ) {
	struct ftp_request *ftp;
	struct sockaddr_tcpip server;
	int rc;

	/* Sanity checks */
	if ( ! uri->host )
		return -EINVAL;
	if ( ! uri->path )
		return -EINVAL;
	if ( ( rc = ftp_check_string ( uri->path ) ) != 0 )
		return rc;
	if ( uri->user && ( ( rc = ftp_check_string ( uri->user ) ) != 0 ) )
		return rc;
	if ( uri->password &&
	     ( ( rc = ftp_check_string ( uri->password ) ) != 0 ) )
		return rc;

	/* Allocate and populate structure */
	ftp = zalloc ( sizeof ( *ftp ) );
	if ( ! ftp )
		return -ENOMEM;
	ref_init ( &ftp->refcnt, ftp_free );
	intf_init ( &ftp->xfer, &ftp_xfer_desc, &ftp->refcnt );
	intf_init ( &ftp->control, &ftp_control_desc, &ftp->refcnt );
	intf_init ( &ftp->data, &ftp_data_desc, &ftp->refcnt );
	ftp->uri = uri_get ( uri );
	ftp->recvbuf = ftp->status_text;
	ftp->recvsize = sizeof ( ftp->status_text ) - 1;

	DBGC ( ftp, "FTP %p fetching %s\n", ftp, ftp->uri->path );

	/* Open control connection */
	memset ( &server, 0, sizeof ( server ) );
	server.st_port = htons ( uri_port ( uri, FTP_PORT ) );
	if ( ( rc = xfer_open_named_socket ( &ftp->control, SOCK_STREAM,
					     ( struct sockaddr * ) &server,
					     uri->host, NULL ) ) != 0 )
		goto err;

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( &ftp->xfer, xfer );
	ref_put ( &ftp->refcnt );
	return 0;

 err:
	DBGC ( ftp, "FTP %p could not create request: %s\n", 
	       ftp, strerror ( rc ) );
	ftp_done ( ftp, rc );
	ref_put ( &ftp->refcnt );
	return rc;
}

/** FTP URI opener */
struct uri_opener ftp_uri_opener __uri_opener = {
	.scheme	= "ftp",
	.open	= ftp_open,
};
