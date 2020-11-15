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
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/features.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>
#include <ipxe/vlan.h>

/** @file
 *
 * Virtual LANs
 *
 */

FEATURE ( FEATURE_PROTOCOL, "VLAN", DHCP_EB_FEATURE_VLAN, 1 );

struct net_protocol vlan_protocol __net_protocol;

/** VLAN device private data */
struct vlan_device {
	/** Trunk network device */
	struct net_device *trunk;
	/** VLAN tag */
	unsigned int tag;
	/** Default priority */
	unsigned int priority;
};

/**
 * Open VLAN device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int vlan_open ( struct net_device *netdev ) {
	struct vlan_device *vlan = netdev->priv;

	return netdev_open ( vlan->trunk );
}

/**
 * Close VLAN device
 *
 * @v netdev		Network device
 */
static void vlan_close ( struct net_device *netdev ) {
	struct vlan_device *vlan = netdev->priv;

	netdev_close ( vlan->trunk );
}

/**
 * Transmit packet on VLAN device
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int vlan_transmit ( struct net_device *netdev,
			   struct io_buffer *iobuf ) {
	struct vlan_device *vlan = netdev->priv;
	struct net_device *trunk = vlan->trunk;
	struct ll_protocol *ll_protocol;
	struct vlan_header *vlanhdr;
	uint8_t ll_dest_copy[ETH_ALEN];
	uint8_t ll_source_copy[ETH_ALEN];
	const void *ll_dest;
	const void *ll_source;
	uint16_t net_proto;
	unsigned int flags;
	int rc;

	/* Strip link-layer header and preserve link-layer header fields */
	ll_protocol = netdev->ll_protocol;
	if ( ( rc = ll_protocol->pull ( netdev, iobuf, &ll_dest, &ll_source,
					&net_proto, &flags ) ) != 0 ) {
		DBGC ( netdev, "VLAN %s could not parse link-layer header: "
		       "%s\n", netdev->name, strerror ( rc ) );
		return rc;
	}
	memcpy ( ll_dest_copy, ll_dest, ETH_ALEN );
	memcpy ( ll_source_copy, ll_source, ETH_ALEN );

	/* Construct VLAN header */
	vlanhdr = iob_push ( iobuf, sizeof ( *vlanhdr ) );
	vlanhdr->tci = htons ( VLAN_TCI ( vlan->tag, vlan->priority ) );
	vlanhdr->net_proto = net_proto;

	/* Reclaim I/O buffer from VLAN device's TX queue */
	list_del ( &iobuf->list );

	/* Transmit packet on trunk device */
	if ( ( rc = net_tx ( iob_disown ( iobuf ), trunk, &vlan_protocol,
			     ll_dest_copy, ll_source_copy ) ) != 0 ) {
		DBGC ( netdev, "VLAN %s could not transmit: %s\n",
		       netdev->name, strerror ( rc ) );
		/* Cannot return an error status, since that would
		 * cause the I/O buffer to be double-freed.
		 */
		return 0;
	}

	return 0;
}

/**
 * Poll VLAN device
 *
 * @v netdev		Network device
 */
static void vlan_poll ( struct net_device *netdev ) {
	struct vlan_device *vlan = netdev->priv;

	/* Poll trunk device */
	netdev_poll ( vlan->trunk );
}

/**
 * Enable/disable interrupts on VLAN device
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
static void vlan_irq ( struct net_device *netdev, int enable ) {
	struct vlan_device *vlan = netdev->priv;

	/* Enable/disable interrupts on trunk device.  This is not at
	 * all robust, but there is no sensible course of action
	 * available.
	 */
	netdev_irq ( vlan->trunk, enable );
}

/** VLAN device operations */
static struct net_device_operations vlan_operations = {
	.open		= vlan_open,
	.close		= vlan_close,
	.transmit	= vlan_transmit,
	.poll		= vlan_poll,
	.irq		= vlan_irq,
};

/**
 * Synchronise VLAN device
 *
 * @v netdev		Network device
 */
static void vlan_sync ( struct net_device *netdev ) {
	struct vlan_device *vlan = netdev->priv;
	struct net_device *trunk = vlan->trunk;

	/* Synchronise link status */
	if ( netdev->link_rc != trunk->link_rc )
		netdev_link_err ( netdev, trunk->link_rc );

	/* Synchronise open/closed status */
	if ( netdev_is_open ( trunk ) ) {
		if ( ! netdev_is_open ( netdev ) )
			netdev_open ( netdev );
	} else {
		if ( netdev_is_open ( netdev ) )
			netdev_close ( netdev );
	}
}

/**
 * Identify VLAN device
 *
 * @v trunk		Trunk network device
 * @v tag		VLAN tag
 * @ret netdev		VLAN device, if any
 */
struct net_device * vlan_find ( struct net_device *trunk, unsigned int tag ) {
	struct net_device *netdev;
	struct vlan_device *vlan;

	for_each_netdev ( netdev ) {
		if ( netdev->op != &vlan_operations )
			continue;
		vlan = netdev->priv;
		if ( ( vlan->trunk == trunk ) && ( vlan->tag == tag ) )
			return netdev;
	}
	return NULL;
}

/**
 * Process incoming VLAN packet
 *
 * @v iobuf		I/O buffer
 * @v trunk		Trunk network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
static int vlan_rx ( struct io_buffer *iobuf, struct net_device *trunk,
		     const void *ll_dest, const void *ll_source,
		     unsigned int flags __unused ) {
	struct vlan_header *vlanhdr = iobuf->data;
	struct net_device *netdev;
	struct ll_protocol *ll_protocol;
	uint8_t ll_dest_copy[ETH_ALEN];
	uint8_t ll_source_copy[ETH_ALEN];
	uint16_t tag;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *vlanhdr ) ) {
		DBGC ( trunk, "VLAN %s received underlength packet (%zd "
		       "bytes)\n", trunk->name, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto err_sanity;
	}

	/* Identify VLAN device */
	tag = VLAN_TAG ( ntohs ( vlanhdr->tci ) );
	netdev = vlan_find ( trunk, tag );
	if ( ! netdev ) {
		DBGC2 ( trunk, "VLAN %s received packet for unknown VLAN "
			"%d\n", trunk->name, tag );
		rc = -EPIPE;
		goto err_no_vlan;
	}

	/* Strip VLAN header and preserve original link-layer header fields */
	iob_pull ( iobuf, sizeof ( *vlanhdr ) );
	ll_protocol = trunk->ll_protocol;
	memcpy ( ll_dest_copy, ll_dest, ETH_ALEN );
	memcpy ( ll_source_copy, ll_source, ETH_ALEN );

	/* Reconstruct link-layer header for VLAN device */
	ll_protocol = netdev->ll_protocol;
	if ( ( rc = ll_protocol->push ( netdev, iobuf, ll_dest_copy,
					ll_source_copy,
					vlanhdr->net_proto ) ) != 0 ) {
		DBGC ( netdev, "VLAN %s could not reconstruct link-layer "
		       "header: %s\n", netdev->name, strerror ( rc ) );
		goto err_ll_push;
	}

	/* Enqueue packet on VLAN device */
	netdev_rx ( netdev, iob_disown ( iobuf ) );
	return 0;

 err_ll_push:
 err_no_vlan:
 err_sanity:
	free_iob ( iobuf );
	return rc;
}

/** VLAN protocol */
struct net_protocol vlan_protocol __net_protocol = {
	.name = "VLAN",
	.net_proto = htons ( ETH_P_8021Q ),
	.rx = vlan_rx,
};

/**
 * Get the VLAN tag
 *
 * @v netdev		Network device
 * @ret tag		VLAN tag, or 0 if device is not a VLAN device
 */
unsigned int vlan_tag ( struct net_device *netdev ) {
	struct vlan_device *vlan;

	if ( netdev->op == &vlan_operations ) {
		vlan = netdev->priv;
		return vlan->tag;
	} else {
		return 0;
	}
}

/**
 * Check if network device can be used as a VLAN trunk device
 *
 * @v trunk		Trunk network device
 * @ret is_ok		Trunk network device is usable
 *
 * VLAN devices will be created as Ethernet devices.  (We cannot
 * simply clone the link layer of the trunk network device, because
 * this link layer may expect the network device structure to contain
 * some link-layer-private data.)  The trunk network device must
 * therefore have a link layer that is in some sense 'compatible' with
 * Ethernet; specifically, it must have link-layer addresses that are
 * the same length as Ethernet link-layer addresses.
 *
 * As an additional check, and primarily to assist with the sanity of
 * the FCoE code, we refuse to allow nested VLANs.
 */
int vlan_can_be_trunk ( struct net_device *trunk ) {

	return ( ( trunk->ll_protocol->ll_addr_len == ETH_ALEN ) &&
		 ( trunk->op != &vlan_operations ) );
}

/**
 * Create VLAN device
 *
 * @v trunk		Trunk network device
 * @v tag		VLAN tag
 * @v priority		Default VLAN priority
 * @ret rc		Return status code
 */
int vlan_create ( struct net_device *trunk, unsigned int tag,
		  unsigned int priority ) {
	struct net_device *netdev;
	struct vlan_device *vlan;
	int rc;

	/* If VLAN already exists, just update the priority */
	if ( ( netdev = vlan_find ( trunk, tag ) ) != NULL ) {
		vlan = netdev->priv;
		if ( priority != vlan->priority ) {
			DBGC ( netdev, "VLAN %s priority changed from %d to "
			       "%d\n", netdev->name, vlan->priority, priority );
		}
		vlan->priority = priority;
		return 0;
	}

	/* Sanity checks */
	if ( ! vlan_can_be_trunk ( trunk ) ) {
		DBGC ( trunk, "VLAN %s cannot create VLAN on non-trunk "
		       "device\n", trunk->name );
		rc = -ENOTTY;
		goto err_sanity;
	}
	if ( ! VLAN_TAG_IS_VALID ( tag ) ) {
		DBGC ( trunk, "VLAN %s cannot create VLAN with invalid tag "
		       "%d\n", trunk->name, tag );
		rc = -EINVAL;
		goto err_sanity;
	}
	if ( ! VLAN_PRIORITY_IS_VALID ( priority ) ) {
		DBGC ( trunk, "VLAN %s cannot create VLAN with invalid "
		       "priority %d\n", trunk->name, priority );
		rc = -EINVAL;
		goto err_sanity;
	}

	/* Allocate and initialise structure */
	netdev = alloc_etherdev ( sizeof ( *vlan ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc_etherdev;
	}
	netdev_init ( netdev, &vlan_operations );
	netdev->dev = trunk->dev;
	memcpy ( netdev->hw_addr, trunk->ll_addr, ETH_ALEN );
	vlan = netdev->priv;
	vlan->trunk = netdev_get ( trunk );
	vlan->tag = tag;
	vlan->priority = priority;

	/* Construct VLAN device name */
	snprintf ( netdev->name, sizeof ( netdev->name ), "%s-%d",
		   trunk->name, vlan->tag );

	/* Mark device as not supporting interrupts, if applicable */
	if ( ! netdev_irq_supported ( trunk ) )
		netdev->state |= NETDEV_IRQ_UNSUPPORTED;

	/* Register VLAN device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 ) {
		DBGC ( netdev, "VLAN %s could not register: %s\n",
		       netdev->name, strerror ( rc ) );
		goto err_register;
	}

	/* Synchronise with trunk device */
	vlan_sync ( netdev );

	DBGC ( netdev, "VLAN %s created with tag %d and priority %d\n",
	       netdev->name, vlan->tag, vlan->priority );

	return 0;

	unregister_netdev ( netdev );
 err_register:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	netdev_put ( trunk );
 err_alloc_etherdev:
 err_sanity:
	return rc;
}

/**
 * Destroy VLAN device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
int vlan_destroy ( struct net_device *netdev ) {
	struct vlan_device *vlan = netdev->priv;
	struct net_device *trunk;

	/* Sanity check */
	if ( netdev->op != &vlan_operations ) {
		DBGC ( netdev, "VLAN %s cannot destroy non-VLAN device\n",
		       netdev->name );
		return -ENOTTY;
	}

	DBGC ( netdev, "VLAN %s destroyed\n", netdev->name );

	/* Remove VLAN device */
	unregister_netdev ( netdev );
	trunk = vlan->trunk;
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	netdev_put ( trunk );

	return 0;
}

/**
 * Handle trunk network device link state change
 *
 * @v trunk		Trunk network device
 */
static void vlan_notify ( struct net_device *trunk ) {
	struct net_device *netdev;
	struct vlan_device *vlan;

	for_each_netdev ( netdev ) {
		if ( netdev->op != &vlan_operations )
			continue;
		vlan = netdev->priv;
		if ( vlan->trunk == trunk )
			vlan_sync ( netdev );
	}
}

/**
 * Destroy first VLAN device for a given trunk
 *
 * @v trunk		Trunk network device
 * @ret found		A VLAN device was found
 */
static int vlan_remove_first ( struct net_device *trunk ) {
	struct net_device *netdev;
	struct vlan_device *vlan;

	for_each_netdev ( netdev ) {
		if ( netdev->op != &vlan_operations )
			continue;
		vlan = netdev->priv;
		if ( vlan->trunk == trunk ) {
			vlan_destroy ( netdev );
			return 1;
		}
	}
	return 0;
}

/**
 * Destroy all VLAN devices for a given trunk
 *
 * @v trunk		Trunk network device
 */
static void vlan_remove ( struct net_device *trunk ) {

	/* Remove all VLAN devices attached to this trunk, safe
	 * against arbitrary net device removal.
	 */
	while ( vlan_remove_first ( trunk ) ) {}
}

/** VLAN driver */
struct net_driver vlan_driver __net_driver = {
	.name = "VLAN",
	.notify = vlan_notify,
	.remove = vlan_remove,
};
