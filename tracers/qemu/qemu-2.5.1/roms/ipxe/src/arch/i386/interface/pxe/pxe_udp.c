/** @file
 *
 * PXE UDP API
 *
 */

#include <string.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/udp.h>
#include <ipxe/uaccess.h>
#include <ipxe/process.h>
#include <realmode.h>
#include <pxe.h>

/*
 * Copyright (C) 2004 Michael Brown <mbrown@fensystems.co.uk>.
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

/** A PXE UDP pseudo-header */
struct pxe_udp_pseudo_header {
	/** Source IP address */
	IP4_t src_ip;
	/** Source port */
	UDP_PORT_t s_port;
	/** Destination IP address */
	IP4_t dest_ip;
	/** Destination port */
	UDP_PORT_t d_port;
} __attribute__ (( packed ));

/** A PXE UDP connection */
struct pxe_udp_connection {
	/** Data transfer interface to UDP stack */
	struct interface xfer;
	/** Local address */
	struct sockaddr_in local;
	/** List of received packets */
	struct list_head list;
};

/**
 * Receive PXE UDP data
 *
 * @v pxe_udp			PXE UDP connection
 * @v iobuf			I/O buffer
 * @v meta			Data transfer metadata
 * @ret rc			Return status code
 *
 * Receives a packet as part of the current pxenv_udp_read()
 * operation.
 */
static int pxe_udp_deliver ( struct pxe_udp_connection *pxe_udp,
			     struct io_buffer *iobuf,
			     struct xfer_metadata *meta ) {
	struct pxe_udp_pseudo_header *pshdr;
	struct sockaddr_in *sin_src;
	struct sockaddr_in *sin_dest;
	int rc;

	/* Extract metadata */
	assert ( meta );
	sin_src = ( struct sockaddr_in * ) meta->src;
	assert ( sin_src );
	assert ( sin_src->sin_family == AF_INET );
	sin_dest = ( struct sockaddr_in * ) meta->dest;
	assert ( sin_dest );
	assert ( sin_dest->sin_family == AF_INET );

	/* Construct pseudo-header */
	if ( ( rc = iob_ensure_headroom ( iobuf, sizeof ( *pshdr ) ) ) != 0 ) {
		DBG ( "PXE could not prepend pseudo-header\n" );
		rc = -ENOMEM;
		goto drop;
	}
	pshdr = iob_push ( iobuf, sizeof ( *pshdr ) );
	pshdr->src_ip = sin_src->sin_addr.s_addr;
	pshdr->s_port = sin_src->sin_port;
	pshdr->dest_ip = sin_dest->sin_addr.s_addr;
	pshdr->d_port = sin_dest->sin_port;

	/* Add to queue */
	list_add_tail ( &iobuf->list, &pxe_udp->list );

	return 0;

 drop:
	free_iob ( iobuf );
	return rc;
}

/** PXE UDP data transfer interface operations */
static struct interface_operation pxe_udp_xfer_operations[] = {
	INTF_OP ( xfer_deliver, struct pxe_udp_connection *, pxe_udp_deliver ),
};

/** PXE UDP data transfer interface descriptor */
static struct interface_descriptor pxe_udp_xfer_desc =
	INTF_DESC ( struct pxe_udp_connection, xfer, pxe_udp_xfer_operations );

/** The PXE UDP connection */
static struct pxe_udp_connection pxe_udp = {
	.xfer = INTF_INIT ( pxe_udp_xfer_desc ),
	.local = {
		.sin_family = AF_INET,
	},
	.list = LIST_HEAD_INIT ( pxe_udp.list ),
};

/**
 * UDP OPEN
 *
 * @v pxenv_udp_open			Pointer to a struct s_PXENV_UDP_OPEN
 * @v s_PXENV_UDP_OPEN::src_ip		IP address of this station, or 0.0.0.0
 * @ret #PXENV_EXIT_SUCCESS		Always
 * @ret s_PXENV_UDP_OPEN::Status	PXE status code
 * @err #PXENV_STATUS_UDP_OPEN		UDP connection already open
 * @err #PXENV_STATUS_OUT_OF_RESOURCES	Could not open connection
 *
 * Prepares the PXE stack for communication using pxenv_udp_write()
 * and pxenv_udp_read().
 *
 * The IP address supplied in s_PXENV_UDP_OPEN::src_ip will be
 * recorded and used as the local station's IP address for all further
 * communication, including communication by means other than
 * pxenv_udp_write() and pxenv_udp_read().  (If
 * s_PXENV_UDP_OPEN::src_ip is 0.0.0.0, the local station's IP address
 * will remain unchanged.)
 *
 * You can only have one open UDP connection at a time.  This is not a
 * meaningful restriction, since pxenv_udp_write() and
 * pxenv_udp_read() allow you to specify arbitrary local and remote
 * ports and an arbitrary remote address for each packet.  According
 * to the PXE specifiation, you cannot have a UDP connection open at
 * the same time as a TFTP connection; this restriction does not apply
 * to Etherboot.
 *
 * On x86, you must set the s_PXE::StatusCallout field to a nonzero
 * value before calling this function in protected mode.  You cannot
 * call this function with a 32-bit stack segment.  (See the relevant
 * @ref pxe_x86_pmode16 "implementation note" for more details.)
 *
 * @note The PXE specification does not make it clear whether the IP
 * address supplied in s_PXENV_UDP_OPEN::src_ip should be used only
 * for this UDP connection, or retained for all future communication.
 * The latter seems more consistent with typical PXE stack behaviour.
 *
 * @note Etherboot currently ignores the s_PXENV_UDP_OPEN::src_ip
 * parameter.
 *
 */
static PXENV_EXIT_t pxenv_udp_open ( struct s_PXENV_UDP_OPEN *pxenv_udp_open ) {
	int rc;

	DBG ( "PXENV_UDP_OPEN" );

	/* Record source IP address */
	pxe_udp.local.sin_addr.s_addr = pxenv_udp_open->src_ip;
	DBG ( " %s\n", inet_ntoa ( pxe_udp.local.sin_addr ) );

	/* Open promiscuous UDP connection */
	intf_restart ( &pxe_udp.xfer, 0 );
	if ( ( rc = udp_open_promisc ( &pxe_udp.xfer ) ) != 0 ) {
		DBG ( "PXENV_UDP_OPEN could not open promiscuous socket: %s\n",
		      strerror ( rc ) );
		pxenv_udp_open->Status = PXENV_STATUS ( rc );
		return PXENV_EXIT_FAILURE;
	}

	pxenv_udp_open->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/**
 * UDP CLOSE
 *
 * @v pxenv_udp_close			Pointer to a struct s_PXENV_UDP_CLOSE
 * @ret #PXENV_EXIT_SUCCESS		Always
 * @ret s_PXENV_UDP_CLOSE::Status	PXE status code
 * @err None				-
 *
 * Closes a UDP connection opened with pxenv_udp_open().
 *
 * You can only have one open UDP connection at a time.  You cannot
 * have a UDP connection open at the same time as a TFTP connection.
 * You cannot use pxenv_udp_close() to close a TFTP connection; use
 * pxenv_tftp_close() instead.
 *
 * On x86, you must set the s_PXE::StatusCallout field to a nonzero
 * value before calling this function in protected mode.  You cannot
 * call this function with a 32-bit stack segment.  (See the relevant
 * @ref pxe_x86_pmode16 "implementation note" for more details.)
 *
 */
static PXENV_EXIT_t
pxenv_udp_close ( struct s_PXENV_UDP_CLOSE *pxenv_udp_close ) {
	struct io_buffer *iobuf;
	struct io_buffer *tmp;

	DBG ( "PXENV_UDP_CLOSE\n" );

	/* Close UDP connection */
	intf_restart ( &pxe_udp.xfer, 0 );

	/* Discard any received packets */
	list_for_each_entry_safe ( iobuf, tmp, &pxe_udp.list, list ) {
		list_del ( &iobuf->list );
		free_iob ( iobuf );
	}

	pxenv_udp_close->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/**
 * UDP WRITE
 *
 * @v pxenv_udp_write			Pointer to a struct s_PXENV_UDP_WRITE
 * @v s_PXENV_UDP_WRITE::ip		Destination IP address
 * @v s_PXENV_UDP_WRITE::gw		Relay agent IP address, or 0.0.0.0
 * @v s_PXENV_UDP_WRITE::src_port	Source UDP port, or 0
 * @v s_PXENV_UDP_WRITE::dst_port	Destination UDP port
 * @v s_PXENV_UDP_WRITE::buffer_size	Length of the UDP payload
 * @v s_PXENV_UDP_WRITE::buffer		Address of the UDP payload
 * @ret #PXENV_EXIT_SUCCESS		Packet was transmitted successfully
 * @ret #PXENV_EXIT_FAILURE		Packet could not be transmitted
 * @ret s_PXENV_UDP_WRITE::Status	PXE status code
 * @err #PXENV_STATUS_UDP_CLOSED	UDP connection is not open
 * @err #PXENV_STATUS_UNDI_TRANSMIT_ERROR Could not transmit packet
 *
 * Transmits a single UDP packet.  A valid IP and UDP header will be
 * prepended to the payload in s_PXENV_UDP_WRITE::buffer; the buffer
 * should not contain precomputed IP and UDP headers, nor should it
 * contain space allocated for these headers.  The first byte of the
 * buffer will be transmitted as the first byte following the UDP
 * header.
 *
 * If s_PXENV_UDP_WRITE::gw is 0.0.0.0, normal IP routing will take
 * place.  See the relevant @ref pxe_routing "implementation note" for
 * more details.
 *
 * If s_PXENV_UDP_WRITE::src_port is 0, port 2069 will be used.
 *
 * You must have opened a UDP connection with pxenv_udp_open() before
 * calling pxenv_udp_write().
 *
 * On x86, you must set the s_PXE::StatusCallout field to a nonzero
 * value before calling this function in protected mode.  You cannot
 * call this function with a 32-bit stack segment.  (See the relevant
 * @ref pxe_x86_pmode16 "implementation note" for more details.)
 *
 * @note Etherboot currently ignores the s_PXENV_UDP_WRITE::gw
 * parameter.
 *
 */
static PXENV_EXIT_t
pxenv_udp_write ( struct s_PXENV_UDP_WRITE *pxenv_udp_write ) {
	struct sockaddr_in dest;
	struct xfer_metadata meta = {
		.src = ( struct sockaddr * ) &pxe_udp.local,
		.dest = ( struct sockaddr * ) &dest,
		.netdev = pxe_netdev,
	};
	size_t len;
	struct io_buffer *iobuf;
	userptr_t buffer;
	int rc;

	DBG ( "PXENV_UDP_WRITE" );

	/* Construct destination socket address */
	memset ( &dest, 0, sizeof ( dest ) );
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = pxenv_udp_write->ip;
	dest.sin_port = pxenv_udp_write->dst_port;

	/* Set local (source) port.  PXE spec says source port is 2069
	 * if not specified.  Really, this ought to be set at UDP open
	 * time but hey, we didn't design this API.
	 */
	pxe_udp.local.sin_port = pxenv_udp_write->src_port;
	if ( ! pxe_udp.local.sin_port )
		pxe_udp.local.sin_port = htons ( 2069 );

	/* FIXME: we ignore the gateway specified, since we're
	 * confident of being able to do our own routing.  We should
	 * probably allow for multiple gateways.
	 */

	/* Allocate and fill data buffer */
	len = pxenv_udp_write->buffer_size;
	iobuf = xfer_alloc_iob ( &pxe_udp.xfer, len );
	if ( ! iobuf ) {
		DBG ( " out of memory\n" );
		pxenv_udp_write->Status = PXENV_STATUS_OUT_OF_RESOURCES;
		return PXENV_EXIT_FAILURE;
	}
	buffer = real_to_user ( pxenv_udp_write->buffer.segment,
				pxenv_udp_write->buffer.offset );
	copy_from_user ( iob_put ( iobuf, len ), buffer, 0, len );

	DBG ( " %04x:%04x+%x %d->%s:%d\n", pxenv_udp_write->buffer.segment,
	      pxenv_udp_write->buffer.offset, pxenv_udp_write->buffer_size,
	      ntohs ( pxenv_udp_write->src_port ),
	      inet_ntoa ( dest.sin_addr ),
	      ntohs ( pxenv_udp_write->dst_port ) );
	
	/* Transmit packet */
	if ( ( rc = xfer_deliver ( &pxe_udp.xfer, iobuf, &meta ) ) != 0 ) {
		DBG ( "PXENV_UDP_WRITE could not transmit: %s\n",
		      strerror ( rc ) );
		pxenv_udp_write->Status = PXENV_STATUS ( rc );
		return PXENV_EXIT_FAILURE;
	}

	pxenv_udp_write->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/**
 * UDP READ
 *
 * @v pxenv_udp_read			Pointer to a struct s_PXENV_UDP_READ
 * @v s_PXENV_UDP_READ::dest_ip		Destination IP address, or 0.0.0.0
 * @v s_PXENV_UDP_READ::d_port		Destination UDP port, or 0
 * @v s_PXENV_UDP_READ::buffer_size	Size of the UDP payload buffer
 * @v s_PXENV_UDP_READ::buffer		Address of the UDP payload buffer
 * @ret #PXENV_EXIT_SUCCESS		A packet has been received
 * @ret #PXENV_EXIT_FAILURE		No packet has been received
 * @ret s_PXENV_UDP_READ::Status	PXE status code
 * @ret s_PXENV_UDP_READ::src_ip	Source IP address
 * @ret s_PXENV_UDP_READ::dest_ip	Destination IP address
 * @ret s_PXENV_UDP_READ::s_port	Source UDP port
 * @ret s_PXENV_UDP_READ::d_port	Destination UDP port
 * @ret s_PXENV_UDP_READ::buffer_size	Length of UDP payload
 * @err #PXENV_STATUS_UDP_CLOSED	UDP connection is not open
 * @err #PXENV_STATUS_FAILURE		No packet was ready to read
 *
 * Receive a single UDP packet.  This is a non-blocking call; if no
 * packet is ready to read, the call will return instantly with
 * s_PXENV_UDP_READ::Status==PXENV_STATUS_FAILURE.
 *
 * If s_PXENV_UDP_READ::dest_ip is 0.0.0.0, UDP packets addressed to
 * any IP address will be accepted and may be returned to the caller.
 *
 * If s_PXENV_UDP_READ::d_port is 0, UDP packets addressed to any UDP
 * port will be accepted and may be returned to the caller.
 *
 * You must have opened a UDP connection with pxenv_udp_open() before
 * calling pxenv_udp_read().
 *
 * On x86, you must set the s_PXE::StatusCallout field to a nonzero
 * value before calling this function in protected mode.  You cannot
 * call this function with a 32-bit stack segment.  (See the relevant
 * @ref pxe_x86_pmode16 "implementation note" for more details.)
 *
 * @note The PXE specification (version 2.1) does not state that we
 * should fill in s_PXENV_UDP_READ::dest_ip and
 * s_PXENV_UDP_READ::d_port, but Microsoft Windows' NTLDR program
 * expects us to do so, and will fail if we don't.
 *
 */
static PXENV_EXIT_t pxenv_udp_read ( struct s_PXENV_UDP_READ *pxenv_udp_read ) {
	struct in_addr dest_ip_wanted = { .s_addr = pxenv_udp_read->dest_ip };
	struct in_addr dest_ip;
	struct io_buffer *iobuf;
	struct pxe_udp_pseudo_header *pshdr;
	uint16_t d_port_wanted = pxenv_udp_read->d_port;
	uint16_t d_port;
	userptr_t buffer;
	size_t len;

	/* Try receiving a packet, if the queue is empty */
	if ( list_empty ( &pxe_udp.list ) )
		step();

	/* Remove first packet from the queue */
	iobuf = list_first_entry ( &pxe_udp.list, struct io_buffer, list );
	if ( ! iobuf ) {
		/* No packet received */
		DBG2 ( "PXENV_UDP_READ\n" );
		goto no_packet;
	}
	list_del ( &iobuf->list );

	/* Strip pseudo-header */
	assert ( iob_len ( iobuf ) >= sizeof ( *pshdr ) );
	pshdr = iobuf->data;
	iob_pull ( iobuf, sizeof ( *pshdr ) );
	dest_ip.s_addr = pshdr->dest_ip;
	d_port = pshdr->d_port;
	DBG ( "PXENV_UDP_READ" );

	/* Filter on destination address and/or port */
	if ( dest_ip_wanted.s_addr &&
	     ( dest_ip_wanted.s_addr != dest_ip.s_addr ) ) {
		DBG ( " wrong IP %s", inet_ntoa ( dest_ip ) );
		DBG ( " (wanted %s)\n", inet_ntoa ( dest_ip_wanted ) );
		goto drop;
	}
	if ( d_port_wanted && ( d_port_wanted != d_port ) ) {
		DBG ( " wrong port %d", htons ( d_port ) );
		DBG ( " (wanted %d)\n", htons ( d_port_wanted ) );
		goto drop;
	}

	/* Copy packet to buffer and record length */
	buffer = real_to_user ( pxenv_udp_read->buffer.segment,
				pxenv_udp_read->buffer.offset );
	len = iob_len ( iobuf );
	if ( len > pxenv_udp_read->buffer_size )
		len = pxenv_udp_read->buffer_size;
	copy_to_user ( buffer, 0, iobuf->data, len );
	pxenv_udp_read->buffer_size = len;

	/* Fill in source/dest information */
	pxenv_udp_read->src_ip = pshdr->src_ip;
	pxenv_udp_read->s_port = pshdr->s_port;
	pxenv_udp_read->dest_ip = pshdr->dest_ip;
	pxenv_udp_read->d_port = pshdr->d_port;

	DBG ( " %04x:%04x+%x %s:", pxenv_udp_read->buffer.segment,
	      pxenv_udp_read->buffer.offset, pxenv_udp_read->buffer_size,
	      inet_ntoa ( *( ( struct in_addr * ) &pxenv_udp_read->src_ip ) ));
	DBG ( "%d<-%s:%d\n",  ntohs ( pxenv_udp_read->s_port ),
	      inet_ntoa ( *( ( struct in_addr * ) &pxenv_udp_read->dest_ip ) ),
	      ntohs ( pxenv_udp_read->d_port ) );

	/* Free I/O buffer */
	free_iob ( iobuf );

	pxenv_udp_read->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;

 drop:
	free_iob ( iobuf );
 no_packet:
	pxenv_udp_read->Status = PXENV_STATUS_FAILURE;
	return PXENV_EXIT_FAILURE;
}

/** PXE UDP API */
struct pxe_api_call pxe_udp_api[] __pxe_api_call = {
	PXE_API_CALL ( PXENV_UDP_OPEN, pxenv_udp_open,
		       struct s_PXENV_UDP_OPEN ),
	PXE_API_CALL ( PXENV_UDP_CLOSE, pxenv_udp_close,
		       struct s_PXENV_UDP_CLOSE ),
	PXE_API_CALL ( PXENV_UDP_WRITE, pxenv_udp_write,
		       struct s_PXENV_UDP_WRITE ),
	PXE_API_CALL ( PXENV_UDP_READ, pxenv_udp_read,
		       struct s_PXENV_UDP_READ ),
};
