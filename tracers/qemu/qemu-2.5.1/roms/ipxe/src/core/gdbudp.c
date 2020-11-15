/*
 * Copyright (C) 2008 Stefan Hajnoczi <stefanha@gmail.com>.
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

#include <stdio.h>
#include <string.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/in.h>
#include <ipxe/if_arp.h>
#include <ipxe/if_ether.h>
#include <ipxe/ip.h>
#include <ipxe/udp.h>
#include <ipxe/netdevice.h>
#include <ipxe/nap.h>
#include <ipxe/gdbstub.h>
#include <ipxe/gdbudp.h>

/** @file
 *
 * GDB over UDP transport
 *
 */

enum {
	DEFAULT_PORT = 43770, /* UDP listen port */
};

struct gdb_transport udp_gdb_transport __gdb_transport;

static struct net_device *netdev;
static uint8_t dest_eth[ETH_ALEN];
static struct sockaddr_in dest_addr;
static struct sockaddr_in source_addr;

static void gdbudp_ensure_netdev_open ( struct net_device *netdev ) {
	/* The device may have been closed between breakpoints */
	assert ( netdev );
	netdev_open ( netdev );

	/* Strictly speaking, we may need to close the device when leaving the interrupt handler */
}

static size_t gdbudp_recv ( char *buf, size_t len ) {
	struct io_buffer *iob;
	struct ethhdr *ethhdr;
	struct arphdr *arphdr;
	struct iphdr *iphdr;
	struct udp_header *udphdr;
	size_t payload_len;

	gdbudp_ensure_netdev_open ( netdev );

	for ( ; ; ) {
		netdev_poll ( netdev );
		while ( ( iob = netdev_rx_dequeue ( netdev ) ) != NULL ) {
			/* Ethernet header */
			if ( iob_len ( iob ) < sizeof ( *ethhdr ) ) {
				goto bad_packet;
			}
			ethhdr = iob->data;
			iob_pull ( iob, sizeof ( *ethhdr ) );

			/* Handle ARP requests so the client can find our MAC */
			if ( ethhdr->h_protocol == htons ( ETH_P_ARP ) ) {
				arphdr = iob->data;
				if ( iob_len ( iob ) < sizeof ( *arphdr ) + 2 * ( ETH_ALEN + sizeof ( struct in_addr ) ) ||
						arphdr->ar_hrd != htons ( ARPHRD_ETHER ) ||
						arphdr->ar_pro != htons ( ETH_P_IP ) ||
						arphdr->ar_hln != ETH_ALEN ||
						arphdr->ar_pln != sizeof ( struct in_addr ) ||
						arphdr->ar_op != htons ( ARPOP_REQUEST ) ||
						* ( uint32_t * ) arp_target_pa ( arphdr ) != source_addr.sin_addr.s_addr ) {
					goto bad_packet;
				}

				/* Generate an ARP reply */
				arphdr->ar_op = htons ( ARPOP_REPLY );
				memswap ( arp_sender_pa ( arphdr ), arp_target_pa ( arphdr ), sizeof ( struct in_addr ) );
				memcpy ( arp_target_ha ( arphdr ), arp_sender_ha ( arphdr ), ETH_ALEN );
				memcpy ( arp_sender_ha ( arphdr ), netdev->ll_addr, ETH_ALEN );

				/* Fix up ethernet header */
				ethhdr = iob_push ( iob, sizeof ( *ethhdr ) );
				memcpy ( ethhdr->h_dest, ethhdr->h_source, ETH_ALEN );
				memcpy ( ethhdr->h_source, netdev->ll_addr, ETH_ALEN );

				netdev_tx ( netdev, iob );
				continue; /* no need to free iob */
			}

			if ( ethhdr->h_protocol != htons ( ETH_P_IP ) ) {
				goto bad_packet;
			}

			/* IP header */
			if ( iob_len ( iob ) < sizeof ( *iphdr ) ) {
				goto bad_packet;
			}
			iphdr = iob->data;
			iob_pull ( iob, sizeof ( *iphdr ) );
			if ( iphdr->protocol != IP_UDP || iphdr->dest.s_addr != source_addr.sin_addr.s_addr ) {
				goto bad_packet;
			}

			/* UDP header */
			if ( iob_len ( iob ) < sizeof ( *udphdr ) ) {
				goto bad_packet;
			}
			udphdr = iob->data;
			if ( udphdr->dest != source_addr.sin_port ) {
				goto bad_packet;
			}

			/* Learn the remote connection details */
			memcpy ( dest_eth, ethhdr->h_source, ETH_ALEN );
			dest_addr.sin_addr.s_addr = iphdr->src.s_addr;
			dest_addr.sin_port = udphdr->src;

			/* Payload */
			payload_len = ntohs ( udphdr->len );
			if ( payload_len < sizeof ( *udphdr ) || payload_len > iob_len ( iob ) ) {
				goto bad_packet;
			}
			payload_len -= sizeof ( *udphdr );
			iob_pull ( iob, sizeof ( *udphdr ) );
			if ( payload_len > len ) {
				goto bad_packet;
			}
			memcpy ( buf, iob->data, payload_len );

			free_iob ( iob );
			return payload_len;

bad_packet:
			free_iob ( iob );
		}
		cpu_nap();
	}
}

static void gdbudp_send ( const char *buf, size_t len ) {
	struct io_buffer *iob;
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct udp_header *udphdr;

	/* Check that we are connected */
	if ( dest_addr.sin_port == 0 ) {
		return;
	}

	gdbudp_ensure_netdev_open ( netdev );

	iob = alloc_iob ( sizeof ( *ethhdr ) + sizeof ( *iphdr ) + sizeof ( *udphdr ) + len );
	if ( !iob ) {
		return;
	}

	/* Payload */
	iob_reserve ( iob, sizeof ( *ethhdr ) + sizeof ( *iphdr ) + sizeof ( *udphdr ) );
	memcpy ( iob_put ( iob, len ), buf, len );

	/* UDP header */
	udphdr = iob_push ( iob, sizeof ( *udphdr ) );
	udphdr->src = source_addr.sin_port;
	udphdr->dest = dest_addr.sin_port;
	udphdr->len = htons ( iob_len ( iob ) );
	udphdr->chksum = 0; /* optional and we are not using it */

	/* IP header */
	iphdr = iob_push ( iob, sizeof ( *iphdr ) );
	memset ( iphdr, 0, sizeof ( *iphdr ) );
	iphdr->verhdrlen = ( IP_VER | ( sizeof ( *iphdr ) / 4 ) );
	iphdr->service = IP_TOS;
	iphdr->len = htons ( iob_len ( iob ) );	
	iphdr->ttl = IP_TTL;
	iphdr->protocol = IP_UDP;
	iphdr->dest.s_addr = dest_addr.sin_addr.s_addr;
	iphdr->src.s_addr = source_addr.sin_addr.s_addr;
	iphdr->chksum = tcpip_chksum ( iphdr, sizeof ( *iphdr ) );

	/* Ethernet header */
	ethhdr = iob_push ( iob, sizeof ( *ethhdr ) );
	memcpy ( ethhdr->h_dest, dest_eth, ETH_ALEN );
	memcpy ( ethhdr->h_source, netdev->ll_addr, ETH_ALEN );
	ethhdr->h_protocol = htons ( ETH_P_IP );

	netdev_tx ( netdev, iob );
}

struct gdb_transport *gdbudp_configure ( const char *name, struct sockaddr_in *addr ) {
	struct settings *settings;

	/* Release old network device */
	netdev_put ( netdev );

	netdev = find_netdev ( name );
	if ( !netdev ) {
		return NULL;
	}

	/* Hold network device */
	netdev_get ( netdev );

	/* Source UDP port */
	source_addr.sin_port = ( addr && addr->sin_port ) ? addr->sin_port : htons ( DEFAULT_PORT );

	/* Source IP address */
	if ( addr && addr->sin_addr.s_addr ) {
		source_addr.sin_addr.s_addr = addr->sin_addr.s_addr;
	} else {
		settings = netdev_settings ( netdev );
		fetch_ipv4_setting ( settings, &ip_setting, &source_addr.sin_addr );
		if ( source_addr.sin_addr.s_addr == 0 ) {
			netdev_put ( netdev );
			netdev = NULL;
			return NULL;
		}
	}

	return &udp_gdb_transport;
}

static int gdbudp_init ( int argc, char **argv ) {
	if ( argc != 1 ) {
		printf ( "udp: missing <interface> argument\n" );
		return 1;
	}

	if ( !gdbudp_configure ( argv[0], NULL ) ) {
		printf ( "%s: device does not exist or has no IP address\n", argv[0] );
		return 1;
	}
	return 0;
}

struct gdb_transport udp_gdb_transport __gdb_transport = {
	.name = "udp",
	.init = gdbudp_init,
	.send = gdbudp_send,
	.recv = gdbudp_recv,
};
