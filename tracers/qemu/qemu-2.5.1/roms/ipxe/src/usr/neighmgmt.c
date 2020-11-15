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
#include <ipxe/neighbour.h>
#include <usr/neighmgmt.h>

/** @file
 *
 * Neighbour management
 *
 */

/**
 * Print neighbour table
 *
 */
void nstat ( void ) {
	struct neighbour *neighbour;
	struct net_device *netdev;
	struct ll_protocol *ll_protocol;
	struct net_protocol *net_protocol;

	list_for_each_entry ( neighbour, &neighbours, list ) {
		netdev = neighbour->netdev;
		ll_protocol = netdev->ll_protocol;
		net_protocol = neighbour->net_protocol;
		printf ( "%s %s %s is %s %s", netdev->name, net_protocol->name,
			 net_protocol->ntoa ( neighbour->net_dest ),
			 ll_protocol->name,
			 ( neighbour_has_ll_dest ( neighbour ) ?
			   ll_protocol->ntoa ( neighbour->ll_dest ) :
			   "(incomplete)" ) );
		if ( neighbour->discovery )
			printf ( " (%s)", neighbour->discovery->name );
		printf ( "\n" );
	}
}
