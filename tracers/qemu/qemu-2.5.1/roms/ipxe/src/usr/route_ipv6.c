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
#include <ipxe/ipv6.h>
#include <usr/route.h>

/** @file
 *
 * IPv6 routing management
 *
 */

/**
 * Print IPv6 routing table
 *
 * @v netdev		Network device
 */
static void route_ipv6_print ( struct net_device *netdev ) {
	struct ipv6_miniroute *miniroute;

	list_for_each_entry ( miniroute, &ipv6_miniroutes, list ) {
		if ( miniroute->netdev != netdev )
			continue;
		printf ( "%s: %s/%d", netdev->name,
			 inet6_ntoa ( &miniroute->address ),
			 miniroute->prefix_len );
		if ( miniroute->flags & IPV6_HAS_ROUTER )
			printf ( " gw %s", inet6_ntoa ( &miniroute->router ) );
		if ( ! ( miniroute->flags & IPV6_HAS_ADDRESS ) )
			printf ( " (no address)" );
		if ( ! netdev_is_open ( miniroute->netdev ) )
			printf ( " (inaccessible)" );
		printf ( "\n" );
	}
}

/** IPv6 routing family */
struct routing_family ipv6_routing_family __routing_family ( ROUTING_IPV6 ) = {
	.print = route_ipv6_print,
};
