/*
 * Copyright (c) 2009 Joshua Oreman <oremanj@rwcr.net>.
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

#ifndef _IPXE_EAPOL_H
#define _IPXE_EAPOL_H

/** @file
 *
 * Definitions for EAPOL (Extensible Authentication Protocol over
 * LANs) frames. Definitions for the packets usually encapsulated in
 * them are elsewhere.
 */

#include <ipxe/tables.h>
#include <stdint.h>

FILE_LICENCE ( GPL2_OR_LATER );


/**
 * @defgroup eapol_type EAPOL archetype identifiers
 * @{
 */
#define EAPOL_TYPE_EAP		0 /**< EAP authentication handshake packet */
#define EAPOL_TYPE_START	1 /**< Request by Peer to begin (no data) */
#define EAPOL_TYPE_LOGOFF	2 /**< Request by Peer to terminate (no data) */
#define EAPOL_TYPE_KEY		3 /**< EAPOL-Key packet */
/** @} */

/** Expected EAPOL version field value
 *
 * Version 2 is often seen and has no format differences from version 1;
 * however, many older APs will completely drop version-2 packets, so
 * we advertise ourselves as version 1.
 */
#define EAPOL_THIS_VERSION	1

/** Length of an EAPOL frame header */
#define EAPOL_HDR_LEN		4

/** An EAPOL frame
 *
 * This may encapsulate an eap_pkt, an eapol_key_pkt, or a Start or
 * Logoff request with no data attached. It is transmitted directly in
 * an Ethernet frame, with no IP packet header.
 */
struct eapol_frame
{
	/** EAPOL version identifier, always 1 */
	u8 version;

	/** EAPOL archetype identifier indicating format of payload */
	u8 type;

	/** Length of payload, in network byte order */
	u16 length;

	/** Payload, if @a type is EAP or EAPOL-Key */
	u8 data[0];
} __attribute__ (( packed ));


/** An EAPOL frame type handler
 *
 * Normally there will be at most two of these, one for EAP and one
 * for EAPOL-Key frames. The EAPOL interface code handles Start and
 * Logoff directly.
 */
struct eapol_handler
{
	/** EAPOL archetype identifier for payload this handler will handle */
	u8 type;

	/** Receive EAPOL-encapsulated packet of specified type
	 *
	 * @v iob	I/O buffer containing packet payload
	 * @v netdev	Network device from which packet was received
	 * @V ll_dest	Destination link-layer address
	 * @v ll_source	Source link-layer address
	 * @ret rc	Return status code
	 *
	 * The I/O buffer will have the EAPOL header pulled off it, so
	 * @c iob->data points to the first byte of the payload.
	 *
	 * This function takes ownership of the I/O buffer passed to it.
	 */
	int ( * rx ) ( struct io_buffer *iob, struct net_device *netdev,
		       const void *ll_dest, const void *ll_source );
};

#define EAPOL_HANDLERS	__table ( struct eapol_handler, "eapol_handlers" )
#define __eapol_handler	__table_entry ( EAPOL_HANDLERS, 01 )


extern struct net_protocol eapol_protocol __net_protocol;


#endif /* _IPXE_EAPOL_H */
