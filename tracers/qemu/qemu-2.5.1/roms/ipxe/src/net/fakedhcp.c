/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ipxe/settings.h>
#include <ipxe/netdevice.h>
#include <ipxe/dhcppkt.h>
#include <ipxe/fakedhcp.h>

/** @file
 *
 * Fake DHCP packets
 *
 */

/**
 * Copy settings to DHCP packet
 *
 * @v dest		Destination DHCP packet
 * @v source		Source settings block
 * @v encapsulator	Encapsulating setting tag number, or zero
 * @ret rc		Return status code
 */
static int copy_encap_settings ( struct dhcp_packet *dest,
				 struct settings *source,
				 unsigned int encapsulator ) {
	struct setting setting = { .name = "" };
	unsigned int subtag;
	unsigned int tag;
	void *data;
	int len;
	int rc;

	for ( subtag = DHCP_MIN_OPTION; subtag <= DHCP_MAX_OPTION; subtag++ ) {
		tag = DHCP_ENCAP_OPT ( encapsulator, subtag );
		switch ( tag ) {
		case DHCP_EB_ENCAP:
		case DHCP_VENDOR_ENCAP:
			/* Process encapsulated settings */
			if ( ( rc = copy_encap_settings ( dest, source,
							  tag ) ) != 0 )
				return rc;
			break;
		default:
			/* Copy setting, if present */
			setting.tag = tag;
			len = fetch_raw_setting_copy ( source, &setting, &data);
			if ( len >= 0 ) {
				rc = dhcppkt_store ( dest, tag, data, len );
				free ( data );
				if ( rc != 0 )
					return rc;
			}
			break;
		}
	}

	return 0;
}

/**
 * Copy settings to DHCP packet
 *
 * @v dest		Destination DHCP packet
 * @v source		Source settings block
 * @ret rc		Return status code
 */
static int copy_settings ( struct dhcp_packet *dest,
			   struct settings *source ) {
	return copy_encap_settings ( dest, source, 0 );
}

/**
 * Create fake DHCPDISCOVER packet
 *
 * @v netdev		Network device
 * @v data		Buffer for DHCP packet
 * @v max_len		Size of DHCP packet buffer
 * @ret rc		Return status code
 *
 * Used by external code.
 */
int create_fakedhcpdiscover ( struct net_device *netdev,
			      void *data, size_t max_len ) {
	struct dhcp_packet dhcppkt;
	struct in_addr ciaddr = { 0 };
	int rc;

	if ( ( rc = dhcp_create_request ( &dhcppkt, netdev, DHCPDISCOVER,
					  dhcp_last_xid, ciaddr, data,
					  max_len ) ) != 0 ) {
		DBG ( "Could not create DHCPDISCOVER: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Create fake DHCPACK packet
 *
 * @v netdev		Network device
 * @v data		Buffer for DHCP packet
 * @v max_len		Size of DHCP packet buffer
 * @ret rc		Return status code
 *
 * Used by external code.
 */
int create_fakedhcpack ( struct net_device *netdev,
			 void *data, size_t max_len ) {
	struct dhcp_packet dhcppkt;
	int rc;

	/* Create base DHCPACK packet */
	if ( ( rc = dhcp_create_packet ( &dhcppkt, netdev, DHCPACK,
					 dhcp_last_xid, NULL, 0,
					 data, max_len ) ) != 0 ) {
		DBG ( "Could not create DHCPACK: %s\n", strerror ( rc ) );
		return rc;
	}

	/* Merge in globally-scoped settings, then netdev-specific
	 * settings.  Do it in this order so that netdev-specific
	 * settings take precedence regardless of stated priorities.
	 */
	if ( ( rc = copy_settings ( &dhcppkt, NULL ) ) != 0 ) {
		DBG ( "Could not set DHCPACK global settings: %s\n",
		      strerror ( rc ) );
		return rc;
	}
	if ( ( rc = copy_settings ( &dhcppkt,
				    netdev_settings ( netdev ) ) ) != 0 ) {
		DBG ( "Could not set DHCPACK netdev settings: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Create fake PXE Boot Server ACK packet
 *
 * @v netdev		Network device
 * @v data		Buffer for DHCP packet
 * @v max_len		Size of DHCP packet buffer
 * @ret rc		Return status code
 *
 * Used by external code.
 */
int create_fakepxebsack ( struct net_device *netdev,
			  void *data, size_t max_len ) {
	struct dhcp_packet dhcppkt;
	struct settings *proxy_settings;
	struct settings *pxebs_settings;
	int rc;

	/* Identify available settings */
	proxy_settings = find_settings ( PROXYDHCP_SETTINGS_NAME );
	pxebs_settings = find_settings ( PXEBS_SETTINGS_NAME );
	if ( ( ! proxy_settings ) && ( ! pxebs_settings ) ) {
		/* No PXE boot server; return the regular DHCPACK */
		return create_fakedhcpack ( netdev, data, max_len );
	}

	/* Create base DHCPACK packet */
	if ( ( rc = dhcp_create_packet ( &dhcppkt, netdev, DHCPACK,
					 dhcp_last_xid, NULL, 0,
					 data, max_len ) ) != 0 ) {
		DBG ( "Could not create PXE BS ACK: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	/* Merge in ProxyDHCP options */
	if ( proxy_settings &&
	     ( ( rc = copy_settings ( &dhcppkt, proxy_settings ) ) != 0 ) ) {
		DBG ( "Could not copy ProxyDHCP settings: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	/* Merge in BootServerDHCP options, if present */
	if ( pxebs_settings &&
	     ( ( rc = copy_settings ( &dhcppkt, pxebs_settings ) ) != 0 ) ) {
		DBG ( "Could not copy PXE BS settings: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	return 0;
}
