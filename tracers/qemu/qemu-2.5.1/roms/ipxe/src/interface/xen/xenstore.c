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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ipxe/io.h>
#include <ipxe/nap.h>
#include <ipxe/malloc.h>
#include <ipxe/xen.h>
#include <ipxe/xenevent.h>
#include <ipxe/xenstore.h>

/*
 * xs_wire.h attempts to define a static error table xsd_errors, which
 * interacts badly with the dynamically generated error numbers used
 * by iPXE.  Prevent this table from being constructed by including
 * errno.h only after including xs_wire.h.
 *
 */
#include <xen/io/xs_wire.h>
#include <errno.h>

/** @file
 *
 * XenStore interface
 *
 */

/** Request identifier */
static uint32_t xenstore_req_id;

/**
 * Send XenStore request raw data
 *
 * @v xen		Xen hypervisor
 * @v data		Data buffer
 * @v len		Length of data
 */
static void xenstore_send ( struct xen_hypervisor *xen, const void *data,
			    size_t len ) {
	struct xenstore_domain_interface *intf = xen->store.intf;
	XENSTORE_RING_IDX prod = readl ( &intf->req_prod );
	XENSTORE_RING_IDX cons;
	XENSTORE_RING_IDX idx;
	const char *bytes = data;
	size_t offset = 0;
	size_t fill;

	DBGCP ( intf, "XENSTORE raw request:\n" );
	DBGCP_HDA ( intf, MASK_XENSTORE_IDX ( prod ), data, len );

	/* Write one byte at a time */
	while ( offset < len ) {

		/* Wait for space to become available */
		while ( 1 ) {
			cons = readl ( &intf->req_cons );
			fill = ( prod - cons );
			if ( fill < XENSTORE_RING_SIZE )
				break;
			DBGC2 ( xen, "." );
			cpu_nap();
			rmb();
		}

		/* Write byte */
		idx = MASK_XENSTORE_IDX ( prod++ );
		writeb ( bytes[offset++], &intf->req[idx] );
	}

	/* Update producer counter */
	wmb();
	writel ( prod, &intf->req_prod );
	wmb();
}

/**
 * Send XenStore request string (excluding terminating NUL)
 *
 * @v xen		Xen hypervisor
 * @v string		String
 */
static void xenstore_send_string ( struct xen_hypervisor *xen,
				   const char *string ) {

	xenstore_send ( xen, string, strlen ( string ) );
}

/**
 * Receive XenStore response raw data
 *
 * @v xen		Xen hypervisor
 * @v data		Data buffer, or NULL to discard data
 * @v len		Length of data
 */
static void xenstore_recv ( struct xen_hypervisor *xen, void *data,
			    size_t len ) {
	struct xenstore_domain_interface *intf = xen->store.intf;
	XENSTORE_RING_IDX cons = readl ( &intf->rsp_cons );
	XENSTORE_RING_IDX prod;
	XENSTORE_RING_IDX idx;
	char *bytes = data;
	size_t offset = 0;
	size_t fill;

	DBGCP ( intf, "XENSTORE raw response:\n" );

	/* Read one byte at a time */
	while ( offset < len ) {

		/* Wait for data to be ready */
		while ( 1 ) {
			prod = readl ( &intf->rsp_prod );
			fill = ( prod - cons );
			if ( fill > 0 )
				break;
			DBGC2 ( xen, "." );
			cpu_nap();
			rmb();
		}

		/* Read byte */
		idx = MASK_XENSTORE_IDX ( cons++ );
		if ( data )
			bytes[offset++] = readb ( &intf->rsp[idx] );
	}
	if ( data )
		DBGCP_HDA ( intf, MASK_XENSTORE_IDX ( cons - len ), data, len );

	/* Update consumer counter */
	writel ( cons, &intf->rsp_cons );
	wmb();
}

/**
 * Send XenStore request
 *
 * @v xen		Xen hypervisor
 * @v type		Message type
 * @v req_id		Request ID
 * @v value		Value, or NULL to omit
 * @v key		Key path components
 * @ret rc		Return status code
 */
static int xenstore_request ( struct xen_hypervisor *xen,
			      enum xsd_sockmsg_type type, uint32_t req_id,
			      const char *value, va_list key ) {
	struct xsd_sockmsg msg;
	struct evtchn_send event;
	const char *string;
	va_list tmp;
	int xenrc;
	int rc;

	/* Construct message header */
	msg.type = type;
	msg.req_id = req_id;
	msg.tx_id = 0;
	msg.len = 0;
	DBGC2 ( xen, "XENSTORE request ID %d type %d ", req_id, type );

	/* Calculate total length */
	va_copy ( tmp, key );
	while ( ( string = va_arg ( tmp, const char * ) ) != NULL ) {
		DBGC2 ( xen, "%s%s", ( msg.len ? "/" : "" ), string );
		msg.len += ( strlen ( string ) + 1 /* '/' or NUL */ );
	}
	va_end ( tmp );
	if ( value ) {
		DBGC2 ( xen, " = \"%s\"", value );
		msg.len += strlen ( value );
	}
	DBGC2 ( xen, "\n" );

	/* Send message */
	xenstore_send ( xen, &msg, sizeof ( msg ) );
	string = va_arg ( key, const char * );
	assert ( string != NULL );
	xenstore_send_string ( xen, string );
	while ( ( string = va_arg ( key, const char * ) ) != NULL ) {
		xenstore_send_string ( xen, "/" );
		xenstore_send_string ( xen, string );
	}
	xenstore_send ( xen, "", 1 ); /* Separating NUL */
	if ( value )
		xenstore_send_string ( xen, value );

	/* Notify the back end */
	event.port = xen->store.port;
	if ( ( xenrc = xenevent_send ( xen, &event ) ) != 0 ) {
		rc = -EXEN ( xenrc );
		DBGC ( xen, "XENSTORE could not notify back end: %s\n",
		       strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Receive XenStore response
 *
 * @v xen		Xen hypervisor
 * @v req_id		Request ID
 * @v value		Value to fill in
 * @v len		Length to fill in
 * @ret rc		Return status code
 *
 * The caller is responsible for eventually calling free() on the
 * returned value.  Note that the value may comprise multiple
 * NUL-terminated strings concatenated together.  A terminating NUL
 * will always be appended to the returned value.
 */
static int xenstore_response ( struct xen_hypervisor *xen, uint32_t req_id,
			       char **value, size_t *len ) {
	struct xsd_sockmsg msg;
	char *string;
	int rc;

	/* Wait for response to become available */
	while ( ! xenevent_pending ( xen, xen->store.port ) )
		cpu_nap();

	/* Receive message header */
	xenstore_recv ( xen, &msg, sizeof ( msg ) );
	*len = msg.len;

	/* Allocate space for response */
	*value = zalloc ( msg.len + 1 /* terminating NUL */ );

	/* Receive data.  Do this even if allocation failed, or if the
	 * request ID was incorrect, to avoid leaving data in the
	 * ring.
	 */
	xenstore_recv ( xen, *value, msg.len );

	/* Validate request ID */
	if ( msg.req_id != req_id ) {
		DBGC ( xen, "XENSTORE response ID mismatch (got %d, expected "
		       "%d)\n", msg.req_id, req_id );
		rc = -EPROTO;
		goto err_req_id;
	}

	/* Check for allocation failure */
	if ( ! *value ) {
		DBGC ( xen, "XENSTORE could not allocate %d bytes for "
		       "response\n", msg.len );
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Check for explicit errors */
	if ( msg.type == XS_ERROR ) {
		DBGC ( xen, "XENSTORE response error \"%s\"\n", *value );
		rc = -EIO;
		goto err_explicit;
	}

	DBGC2 ( xen, "XENSTORE response ID %d\n", req_id );
	if ( DBG_EXTRA ) {
		for ( string = *value ; string < ( *value + msg.len ) ;
		      string += ( strlen ( string ) + 1 /* NUL */ ) ) {
			DBGC2 ( xen, " - \"%s\"\n", string );
		}
	}
	return 0;

 err_explicit:
 err_alloc:
 err_req_id:
	free ( *value );
	*value = NULL;
	return rc;
}

/**
 * Issue a XenStore message
 *
 * @v xen		Xen hypervisor
 * @v type		Message type
 * @v response		Response value to fill in, or NULL to discard
 * @v len		Response length to fill in, or NULL to ignore
 * @v request		Request value, or NULL to omit
 * @v key		Key path components
 * @ret rc		Return status code
 */
static int xenstore_message ( struct xen_hypervisor *xen,
			      enum xsd_sockmsg_type type, char **response,
			      size_t *len, const char *request, va_list key ) {
	char *response_value;
	size_t response_len;
	int rc;

	/* Send request */
	if ( ( rc = xenstore_request ( xen, type, ++xenstore_req_id,
				       request, key ) ) != 0 )
		return rc;

	/* Receive response */
	if ( ( rc = xenstore_response ( xen, xenstore_req_id, &response_value,
					&response_len ) ) != 0 )
		return rc;

	/* Return response, if applicable */
	if ( response ) {
		*response = response_value;
	} else {
		free ( response_value );
	}
	if ( len )
		*len = response_len;

	return 0;
}

/**
 * Read XenStore value
 *
 * @v xen		Xen hypervisor
 * @v value		Value to fill in
 * @v key		Key path components
 * @ret rc		Return status code
 *
 * On a successful return, the caller is responsible for calling
 * free() on the returned value.
 */
static int xenstore_vread ( struct xen_hypervisor *xen, char **value,
			    va_list key ) {

	return xenstore_message ( xen, XS_READ, value, NULL, NULL, key );
}

/**
 * Read XenStore value
 *
 * @v xen		Xen hypervisor
 * @v value		Value to fill in
 * @v ...		Key path components
 * @ret rc		Return status code
 *
 * On a successful return, the caller is responsible for calling
 * free() on the returned value.
 */
__attribute__ (( sentinel )) int
xenstore_read ( struct xen_hypervisor *xen, char **value, ... ) {
	va_list key;
	int rc;

	va_start ( key, value );
	rc = xenstore_vread ( xen, value, key );
	va_end ( key );
	return rc;
}

/**
 * Read XenStore numeric value
 *
 * @v xen		Xen hypervisor
 * @v num		Numeric value to fill in
 * @v ...		Key path components
 * @ret rc		Return status code
 */
__attribute__ (( sentinel )) int
xenstore_read_num ( struct xen_hypervisor *xen, unsigned long *num, ... ) {
	va_list key;
	char *value;
	char *endp;
	int rc;

	/* Try to read text value */
	va_start ( key, num );
	rc = xenstore_vread ( xen, &value, key );
	va_end ( key );
	if ( rc != 0 )
		goto err_read;

	/* Try to parse as numeric value */
	*num = strtoul ( value, &endp, 10 );
	if ( ( *value == '\0' ) || ( *endp != '\0' ) ) {
		DBGC ( xen, "XENSTORE found invalid numeric value \"%s\"\n",
		       value );
		rc = -EINVAL;
		goto err_strtoul;
	}

 err_strtoul:
	free ( value );
 err_read:
	return rc;
}

/**
 * Write XenStore value
 *
 * @v xen		Xen hypervisor
 * @v value		Value
 * @v key		Key path components
 * @ret rc		Return status code
 */
static int xenstore_vwrite ( struct xen_hypervisor *xen, const char *value,
			     va_list key ) {

	return xenstore_message ( xen, XS_WRITE, NULL, NULL, value, key );
}

/**
 * Write XenStore value
 *
 * @v xen		Xen hypervisor
 * @v value		Value
 * @v ...		Key path components
 * @ret rc		Return status code
 */
__attribute__ (( sentinel )) int
xenstore_write ( struct xen_hypervisor *xen, const char *value, ... ) {
	va_list key;
	int rc;

	va_start ( key, value );
	rc = xenstore_vwrite ( xen, value, key );
	va_end ( key );
	return rc;
}

/**
 * Write XenStore numeric value
 *
 * @v xen		Xen hypervisor
 * @v num		Numeric value
 * @v ...		Key path components
 * @ret rc		Return status code
 */
__attribute__ (( sentinel )) int
xenstore_write_num ( struct xen_hypervisor *xen, unsigned long num, ... ) {
	char value[ 21 /* "18446744073709551615" + NUL */ ];
	va_list key;
	int rc;

	/* Construct value */
	snprintf ( value, sizeof ( value ), "%ld", num );

	/* Write value */
	va_start ( key, num );
	rc = xenstore_vwrite ( xen, value, key );
	va_end ( key );
	return rc;
}

/**
 * Delete XenStore value
 *
 * @v xen		Xen hypervisor
 * @v ...		Key path components
 * @ret rc		Return status code
 */
__attribute__ (( sentinel )) int
xenstore_rm ( struct xen_hypervisor *xen, ... ) {
	va_list key;
	int rc;

	va_start ( key, xen );
	rc = xenstore_message ( xen, XS_RM, NULL, NULL, NULL, key );
	va_end ( key );
	return rc;
}

/**
 * Read XenStore directory
 *
 * @v xen		Xen hypervisor
 * @v children		Child key names to fill in
 * @v len		Length of child key names to fill in
 * @v ...		Key path components
 * @ret rc		Return status code
 */
__attribute__ (( sentinel )) int
xenstore_directory ( struct xen_hypervisor *xen, char **children, size_t *len,
		     ... ) {
	va_list key;
	int rc;

	va_start ( key, len );
	rc = xenstore_message ( xen, XS_DIRECTORY, children, len, NULL, key );
	va_end ( key );
	return rc;
}

/**
 * Dump XenStore directory contents (for debugging)
 *
 * @v xen		Xen hypervisor
 * @v key		Key
 */
void xenstore_dump ( struct xen_hypervisor *xen, const char *key ) {
	char *value;
	char *children;
	char *child;
	char *child_key;
	size_t len;
	int rc;

	/* Try to dump current key as a value */
	if ( ( rc = xenstore_read ( xen, &value, key, NULL ) ) == 0 ) {
		DBGC ( xen, "%s = \"%s\"\n", key, value );
		free ( value );
	}

	/* Try to recurse into each child in turn */
	if ( ( rc = xenstore_directory ( xen, &children, &len, key,
					 NULL ) ) == 0 ) {
		for ( child = children ; child < ( children + len ) ;
		      child += ( strlen ( child ) + 1 /* NUL */ ) ) {

			/* Construct child key */
			asprintf ( &child_key, "%s/%s", key, child );
			if ( ! child_key ) {
				DBGC ( xen, "XENSTORE could not allocate child "
				       "key \"%s/%s\"\n", key, child );
				rc = -ENOMEM;
				break;
			}

			/* Recurse into child key, continuing on error */
			xenstore_dump ( xen, child_key );
			free ( child_key );
		}
		free ( children );
	}
}
