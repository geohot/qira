/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/keys.h>
#include <ipxe/console.h>
#include <usr/ifmgmt.h>
#include <usr/lotest.h>

/** @file
 *
 * Loopback testing
 *
 */

/** Current loopback test receiver */
static struct net_device *lotest_receiver;

/** Loopback testing received packets */
static LIST_HEAD ( lotest_queue );

/**
 * Process received packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
static int lotest_rx ( struct io_buffer *iobuf,
		       struct net_device *netdev,
		       const void *ll_dest __unused,
		       const void *ll_source __unused,
		       unsigned int flags __unused ) {

	/* Add to received packet queue if currently performing a test */
	if ( netdev == lotest_receiver ) {
		list_add_tail ( &iobuf->list, &lotest_queue );
	} else {
		free_iob ( iobuf );
	}

	return 0;
}

/**
 * Dequeue received packet
 *
 * @ret iobuf		I/O buffer, or NULL
 */
static struct io_buffer * lotest_dequeue ( void ) {
	struct io_buffer *iobuf;

	/* Remove first packet (if any) from received packet queue */
	iobuf = list_first_entry ( &lotest_queue, struct io_buffer, list );
	if ( ! iobuf )
		return NULL;
	list_del ( &iobuf->list );

	return iobuf;
}

/**
 * Transcribe network-layer address
 *
 * @v net_addr		Network-layer address
 * @ret string		Human-readable transcription of address
 */
static const char * lotest_ntoa ( const void *net_addr __unused ) {
	return "<INVALID>";
}

/**
 * Loopback test network-layer protocol
 *
 * Using a dedicated network-layer protocol avoids problems caused by
 * cards supporting features such as IPv4 checksum offload trying to
 * interpret the (randomly generated) network-layer content.
 */
static struct net_protocol lotest_protocol __net_protocol = {
	.name = "LOTEST",
	.rx = lotest_rx,
	.ntoa = lotest_ntoa,
	.net_proto = htons ( 0x6950 ), /* Not a genuine protocol number */
	.net_addr_len = 0,
};

/**
 * Discard all received loopback test packets
 *
 */
static void lotest_flush ( void ) {
	struct io_buffer *iobuf;

	while ( ( iobuf = lotest_dequeue() ) != NULL )
		free_iob ( iobuf );
}

/**
 * Wait for packet to be received
 *
 * @v data		Expected data
 * @v len		Expected data length
 * @ret rc		Return status code
 */
static int loopback_wait ( void *data, size_t len ) {
	struct io_buffer *iobuf;

	/* Poll until packet arrives */
	while ( 1 ) {

		/* Check for cancellation */
		if ( iskey() && ( getchar() == CTRL_C ) )
			return -ECANCELED;

		/* Poll network devices */
		net_poll();

		/* Dequeue packet, if available */
		iobuf = lotest_dequeue();
		if ( ! iobuf )
			continue;

		/* Check packet length */
		if ( iob_len ( iobuf ) != len ) {
			printf ( "\nLength mismatch: sent %zd, received %zd",
				 len, iob_len ( iobuf ) );
			DBG ( "\nSent:\n" );
			DBG_HDA ( 0, data, len );
			DBG ( "Received:\n" );
			DBG_HDA ( 0, iobuf->data, iob_len ( iobuf ) );
			free_iob ( iob_disown ( iobuf ) );
			return -EINVAL;
		}

		/* Check packet content */
		if ( memcmp ( iobuf->data, data, len ) != 0 ) {
			printf ( "\nContent mismatch" );
			DBG ( "\nSent:\n" );
			DBG_HDA ( 0, data, len );
			DBG ( "Received:\n" );
			DBG_HDA ( 0, iobuf->data, iob_len ( iobuf ) );
			free_iob ( iob_disown ( iobuf ) );
			return -EINVAL;
		}

		/* Discard packet and return */
		free_iob ( iob_disown ( iobuf ) );
		return 0;
	}
}

/**
 * Perform loopback test between two network devices
 *
 * @v sender		Sending network device
 * @v receiver		Received network device
 * @v mtu		Packet size (excluding link-layer headers)
 * @ret rc		Return status code
 */
int loopback_test ( struct net_device *sender, struct net_device *receiver,
		    size_t mtu ) {
	uint8_t *buf;
	uint32_t *seq;
	struct io_buffer *iobuf;
	unsigned int i;
	unsigned int successes;
	int rc;

	/* Open network devices */
	if ( ( rc = ifopen ( sender ) ) != 0 )
		return rc;
	if ( ( rc = ifopen ( receiver ) ) != 0 )
		return rc;

	/* Wait for link-up */
	if ( ( rc = iflinkwait ( sender, 0 ) ) != 0 )
		return rc;
	if ( ( rc = iflinkwait ( receiver, 0 ) ) != 0 )
		return rc;

	/* Allocate data buffer */
	if ( mtu < sizeof ( *seq ) )
		mtu = sizeof ( *seq );
	buf = malloc ( mtu );
	if ( ! buf )
		return -ENOMEM;
	seq = ( ( void * ) buf );

	/* Print initial statistics */
	printf ( "Performing loopback test from %s to %s with %zd byte MTU\n",
		 sender->name, receiver->name, mtu );
	ifstat ( sender );
	ifstat ( receiver );

	/* Start loopback test */
	lotest_flush();
	lotest_receiver = receiver;

	/* Perform loopback test */
	for ( successes = 0 ; ; successes++ ) {

		/* Print running total */
		printf ( "\r%d", successes );

		/* Generate random packet */
		*seq = htonl ( successes );
		for ( i = sizeof ( *seq ) ; i < mtu ; i++ )
			buf[i] = random();
		iobuf = alloc_iob ( MAX_LL_HEADER_LEN + mtu );
		if ( ! iobuf ) {
			printf ( "\nFailed to allocate I/O buffer" );
			rc = -ENOMEM;
			break;
		}
		iob_reserve ( iobuf, MAX_LL_HEADER_LEN );
		memcpy ( iob_put ( iobuf, mtu ), buf, mtu );

		/* Transmit packet */
		if ( ( rc = net_tx ( iob_disown ( iobuf ), sender,
				     &lotest_protocol, receiver->ll_addr,
				     sender->ll_addr ) ) != 0 ) {
			printf ( "\nFailed to transmit packet: %s",
				 strerror ( rc ) );
			break;
		}

		/* Wait for received packet */
		if ( ( rc = loopback_wait ( buf, mtu ) ) != 0 )
			break;
	}

	printf ( "\n");

	/* Stop loopback testing */
	lotest_receiver = NULL;
	lotest_flush();

	/* Dump final statistics */
	ifstat ( sender );
	ifstat ( receiver );

	/* Free buffer */
	free ( buf );

	return 0;
}
