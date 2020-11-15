/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ipxe/pinger.h>
#include <ipxe/monojob.h>
#include <ipxe/timer.h>
#include <usr/pingmgmt.h>

/** @file
 *
 * ICMP ping management
 *
 */

/**
 * Display ping result
 *
 * @v src		Source socket address, or NULL
 * @v sequence		Sequence number
 * @v len		Payload length
 * @v rc		Status code
 */
static void ping_callback ( struct sockaddr *peer, unsigned int sequence,
			    size_t len, int rc ) {

	/* Display ping response */
	printf ( "%zd bytes from %s: seq=%d",
		 len, ( peer ? sock_ntoa ( peer ) : "<none>" ), sequence );
	if ( rc != 0 )
		printf ( ": %s", strerror ( rc ) );
	printf ( "\n" );
}

/**
 * Ping a host
 *
 * @v hostname		Hostname
 * @v timeout		Timeout between pings, in ticks
 * @v len		Payload length
 * @v count		Number of packets to send (or zero for no limit)
 * @v quiet		Inhibit output
 * @ret rc		Return status code
 */
int ping ( const char *hostname, unsigned long timeout, size_t len,
	   unsigned int count, int quiet ) {
	int rc;

	/* Create pinger */
	if ( ( rc = create_pinger ( &monojob, hostname, timeout, len, count,
				    ( quiet ? NULL : ping_callback ) ) ) != 0 ){
		printf ( "Could not start ping: %s\n", strerror ( rc ) );
		return rc;
	}

	/* Wait for ping to complete */
	if ( ( rc = monojob_wait ( NULL, 0 ) ) != 0 ) {
		if ( ! quiet )
			printf ( "Finished: %s\n", strerror ( rc ) );
		return rc;
	}

	return 0;
}
