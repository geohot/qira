#ifndef _USR_ROUTE_H
#define _USR_ROUTE_H

/** @file
 *
 * Routing management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/tables.h>

/** A routing family */
struct routing_family {
	/**
	 * Print routes for a network device
	 *
	 * @v netdev		Network device
	 */
	void ( * print ) ( struct net_device *netdev );
};

/** Routing family table */
#define ROUTING_FAMILIES __table ( struct routing_family, "routing_families" )

/** Declare a routing family */
#define __routing_family( order ) __table_entry ( ROUTING_FAMILIES, order )

#define ROUTING_IPV4 01
#define ROUTING_IPV6 02

extern void route ( void );

#endif /* _USR_ROUTE_H */
