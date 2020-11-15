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
#include <stdlib.h>
#include <ipxe/dhcppkt.h>
#include <ipxe/init.h>
#include <ipxe/netdevice.h>
#include <realmode.h>
#include <pxe_api.h>

/** @file
 *
 * Cached DHCP packet
 *
 */

/** Cached DHCPACK physical address
 *
 * This can be set by the prefix.
 */
uint32_t __bss16 ( cached_dhcpack_phys );
#define cached_dhcpack_phys __use_data16 ( cached_dhcpack_phys )

/** Colour for debug messages */
#define colour &cached_dhcpack_phys

/** Cached DHCPACK */
static struct dhcp_packet *cached_dhcpack;

/**
 * Cached DHCPACK startup function
 *
 */
static void cachedhcp_init ( void ) {
	struct dhcp_packet *dhcppkt;
	struct dhcp_packet *tmp;
	struct dhcphdr *dhcphdr;
	size_t len;

	/* Do nothing if no cached DHCPACK is present */
	if ( ! cached_dhcpack_phys ) {
		DBGC ( colour, "CACHEDHCP found no cached DHCPACK\n" );
		return;
	}

	/* No reliable way to determine length before parsing packet;
	 * start by assuming maximum length permitted by PXE.
	 */
	len = sizeof ( BOOTPLAYER_t );

	/* Allocate and populate DHCP packet */
	dhcppkt = zalloc ( sizeof ( *dhcppkt ) + len );
	if ( ! dhcppkt ) {
		DBGC ( colour, "CACHEDHCP could not allocate copy\n" );
		return;
	}
	dhcphdr = ( ( ( void * ) dhcppkt ) + sizeof ( *dhcppkt ) );
	copy_from_user ( dhcphdr, phys_to_user ( cached_dhcpack_phys ), 0,
			 len );
	dhcppkt_init ( dhcppkt, dhcphdr, len );

	/* Resize packet to required length.  If reallocation fails,
	 * just continue to use the original packet.
	 */
	len = dhcppkt_len ( dhcppkt );
	tmp = realloc ( dhcppkt, ( sizeof ( *dhcppkt ) + len ) );
	if ( tmp )
		dhcppkt = tmp;

	/* Reinitialise packet at new address */
	dhcphdr = ( ( ( void * ) dhcppkt ) + sizeof ( *dhcppkt ) );
	dhcppkt_init ( dhcppkt, dhcphdr, len );

	/* Store as cached DHCPACK, and mark original copy as consumed */
	DBGC ( colour, "CACHEDHCP found cached DHCPACK at %08x+%zx\n",
	       cached_dhcpack_phys, len );
	cached_dhcpack = dhcppkt;
	cached_dhcpack_phys = 0;
}

/**
 * Cached DHCPACK startup function
 *
 */
static void cachedhcp_startup ( void ) {

	/* If cached DHCP packet was not claimed by any network device
	 * during startup, then free it.
	 */
	if ( cached_dhcpack ) {
		DBGC ( colour, "CACHEDHCP freeing unclaimed cached DHCPACK\n" );
		dhcppkt_put ( cached_dhcpack );
		cached_dhcpack = NULL;
	}
}

/** Cached DHCPACK initialisation function */
struct init_fn cachedhcp_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = cachedhcp_init,
};

/** Cached DHCPACK startup function */
struct startup_fn cachedhcp_startup_fn __startup_fn ( STARTUP_LATE ) = {
	.startup = cachedhcp_startup,
};

/**
 * Apply cached DHCPACK to network device, if applicable
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int cachedhcp_probe ( struct net_device *netdev ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	int rc;

	/* Do nothing unless we have a cached DHCPACK */
	if ( ! cached_dhcpack )
		return 0;

	/* Do nothing unless cached DHCPACK's MAC address matches this
	 * network device.
	 */
	if ( memcmp ( netdev->ll_addr, cached_dhcpack->dhcphdr->chaddr,
		      ll_protocol->ll_addr_len ) != 0 ) {
		DBGC ( colour, "CACHEDHCP cached DHCPACK does not match %s\n",
		       netdev->name );
		return 0;
	}
	DBGC ( colour, "CACHEDHCP cached DHCPACK is for %s\n", netdev->name );

	/* Register as DHCP settings for this network device */
	if ( ( rc = register_settings ( &cached_dhcpack->settings,
					netdev_settings ( netdev ),
					DHCP_SETTINGS_NAME ) ) != 0 ) {
		DBGC ( colour, "CACHEDHCP could not register settings: %s\n",
		       strerror ( rc ) );
		return rc;
	}

	/* Claim cached DHCPACK */
	dhcppkt_put ( cached_dhcpack );
	cached_dhcpack = NULL;

	return 0;
}

/** Cached DHCP packet network device driver */
struct net_driver cachedhcp_driver __net_driver = {
	.name = "cachedhcp",
	.probe = cachedhcp_probe,
};
