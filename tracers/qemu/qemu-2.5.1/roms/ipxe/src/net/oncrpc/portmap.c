/*
 * Copyright (C) 2013 Marin Hannache <ipxe@mareo.fr>.
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
#include <byteswap.h>
#include <ipxe/socket.h>
#include <ipxe/tcpip.h>
#include <ipxe/in.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/features.h>
#include <ipxe/timer.h>
#include <ipxe/oncrpc.h>
#include <ipxe/oncrpc_iob.h>
#include <ipxe/portmap.h>

/** @file
 *
 * PORTMAPPER protocol.
 *
 */

/** PORTMAP GETPORT procedure. */
#define PORTMAP_GETPORT 3

/**
 * Send a GETPORT request
 *
 * @v intf              Interface to send the request on
 * @v session           ONC RPC session
 * @v prog              ONC RPC program number
 * @v vers              ONC RPC rogram version number
 * @v proto             Protocol (TCP or UDP)
 * @ret rc              Return status code
 */
int portmap_getport ( struct interface *intf, struct oncrpc_session *session,
                      uint32_t prog, uint32_t vers, uint32_t proto ) {
	struct oncrpc_field fields[] = {
		ONCRPC_FIELD ( int32, prog ),
		ONCRPC_FIELD ( int32, vers ),
		ONCRPC_FIELD ( int32, proto ),
		ONCRPC_FIELD ( int32, 0 ), /* The port field is only meaningful
		                              in GETPORT reply */
		ONCRPC_FIELD_END,
	};

	return oncrpc_call ( intf, session, PORTMAP_GETPORT, fields );
}

/**
 * Parse a GETPORT reply
 *
 * @v getport_reply     A structure where the data will be saved
 * @v reply             The ONC RPC reply to get data from
 * @ret rc              Return status code
 */
int portmap_get_getport_reply ( struct portmap_getport_reply *getport_reply,
                                struct oncrpc_reply *reply ) {
	if ( ! getport_reply || ! reply )
		return -EINVAL;

	getport_reply->port = oncrpc_iob_get_int ( reply->data );
	if ( getport_reply == 0 || getport_reply->port >= 65536 )
		return -EINVAL;

	return 0;
}
