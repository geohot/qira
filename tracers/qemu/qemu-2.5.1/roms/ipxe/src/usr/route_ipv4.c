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

#include <stdio.h>
#include <ipxe/netdevice.h>
#include <ipxe/ip.h>
#include <usr/route.h>

/** @file
 *
 * IPv4 routing management
 *
 */

/**
 * Print IPv4 routing table
 *
 * @v netdev		Network device
 */
static void route_ipv4_print ( struct net_device *netdev ) {
	struct ipv4_miniroute *miniroute;

	list_for_each_entry ( miniroute, &ipv4_miniroutes, list ) {
		if ( miniroute->netdev != netdev )
			continue;
		printf ( "%s: %s/", netdev->name,
			 inet_ntoa ( miniroute->address ) );
		printf ( "%s", inet_ntoa ( miniroute->netmask ) );
		if ( miniroute->gateway.s_addr )
			printf ( " gw %s", inet_ntoa ( miniroute->gateway ) );
		if ( ! netdev_is_open ( miniroute->netdev ) )
			printf ( " (inaccessible)" );
		printf ( "\n" );
	}
}

/** IPv4 routing family */
struct routing_family ipv4_routing_family __routing_family ( ROUTING_IPV4 ) = {
	.print = route_ipv4_print,
};
