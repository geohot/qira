/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <byteswap.h>
#include <string.h>
#include <errno.h>
#include <config/general.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/tables.h>
#include <ipxe/process.h>
#include <ipxe/init.h>
#include <ipxe/malloc.h>
#include <ipxe/device.h>
#include <ipxe/errortab.h>
#include <ipxe/profile.h>
#include <ipxe/fault.h>
#include <ipxe/vlan.h>
#include <ipxe/netdevice.h>

/** @file
 *
 * Network device management
 *
 */

/** List of network devices */
struct list_head net_devices = LIST_HEAD_INIT ( net_devices );

/** List of open network devices, in reverse order of opening */
static struct list_head open_net_devices = LIST_HEAD_INIT ( open_net_devices );

/** Network device index */
static unsigned int netdev_index = 0;

/** Network polling profiler */
static struct profiler net_poll_profiler __profiler = { .name = "net.poll" };

/** Network receive profiler */
static struct profiler net_rx_profiler __profiler = { .name = "net.rx" };

/** Network transmit profiler */
static struct profiler net_tx_profiler __profiler = { .name = "net.tx" };

/** Default unknown link status code */
#define EUNKNOWN_LINK_STATUS __einfo_error ( EINFO_EUNKNOWN_LINK_STATUS )
#define EINFO_EUNKNOWN_LINK_STATUS \
	__einfo_uniqify ( EINFO_EINPROGRESS, 0x01, "Unknown" )

/** Default not-yet-attempted-configuration status code */
#define EUNUSED_CONFIG __einfo_error ( EINFO_EUNUSED_CONFIG )
#define EINFO_EUNUSED_CONFIG \
	__einfo_uniqify ( EINFO_EINPROGRESS, 0x02, "Unused" )

/** Default configuration-in-progress status code */
#define EINPROGRESS_CONFIG __einfo_error ( EINFO_EINPROGRESS_CONFIG )
#define EINFO_EINPROGRESS_CONFIG \
	__einfo_uniqify ( EINFO_EINPROGRESS, 0x03, "Incomplete" )

/** Default link-down status code */
#define ENOTCONN_LINK_DOWN __einfo_error ( EINFO_ENOTCONN_LINK_DOWN )
#define EINFO_ENOTCONN_LINK_DOWN \
	__einfo_uniqify ( EINFO_ENOTCONN, 0x01, "Down" )

/** Human-readable message for the default link statuses */
struct errortab netdev_errors[] __errortab = {
	__einfo_errortab ( EINFO_EUNKNOWN_LINK_STATUS ),
	__einfo_errortab ( EINFO_ENOTCONN_LINK_DOWN ),
	__einfo_errortab ( EINFO_EUNUSED_CONFIG ),
	__einfo_errortab ( EINFO_EINPROGRESS_CONFIG ),
};

/**
 * Check whether or not network device has a link-layer address
 *
 * @v netdev		Network device
 * @ret has_ll_addr	Network device has a link-layer address
 */
static int netdev_has_ll_addr ( struct net_device *netdev ) {
	uint8_t *ll_addr = netdev->ll_addr;
	size_t remaining = sizeof ( netdev->ll_addr );

	while ( remaining-- ) {
		if ( *(ll_addr++) != 0 )
			return 1;
	}
	return 0;
}

/**
 * Notify drivers of network device or link state change
 *
 * @v netdev		Network device
 */
static void netdev_notify ( struct net_device *netdev ) {
	struct net_driver *driver;

	for_each_table_entry ( driver, NET_DRIVERS ) {
		if ( driver->notify )
			driver->notify ( netdev );
	}
}

/**
 * Freeze network device receive queue processing
 *
 * @v netdev		Network device
 */
void netdev_rx_freeze ( struct net_device *netdev ) {

	/* Mark receive queue processing as frozen */
	netdev->state |= NETDEV_RX_FROZEN;

	/* Notify drivers of change */
	netdev_notify ( netdev );
}

/**
 * Unfreeze network device receive queue processing
 *
 * @v netdev		Network device
 */
void netdev_rx_unfreeze ( struct net_device *netdev ) {

	/* Mark receive queue processing as not frozen */
	netdev->state &= ~NETDEV_RX_FROZEN;

	/* Notify drivers of change */
	netdev_notify ( netdev );
}

/**
 * Mark network device as having a specific link state
 *
 * @v netdev		Network device
 * @v rc		Link status code
 */
void netdev_link_err ( struct net_device *netdev, int rc ) {

	/* Stop link block timer */
	stop_timer ( &netdev->link_block );

	/* Record link state */
	netdev->link_rc = rc;
	if ( netdev->link_rc == 0 ) {
		DBGC ( netdev, "NETDEV %s link is up\n", netdev->name );
	} else {
		DBGC ( netdev, "NETDEV %s link is down: %s\n",
		       netdev->name, strerror ( netdev->link_rc ) );
	}

	/* Notify drivers of link state change */
	netdev_notify ( netdev );
}

/**
 * Mark network device as having link down
 *
 * @v netdev		Network device
 */
void netdev_link_down ( struct net_device *netdev ) {

	/* Avoid clobbering a more detailed link status code, if one
	 * is already set.
	 */
	if ( ( netdev->link_rc == 0 ) ||
	     ( netdev->link_rc == -EUNKNOWN_LINK_STATUS ) ) {
		netdev_link_err ( netdev, -ENOTCONN_LINK_DOWN );
	}
}

/**
 * Mark network device link as being blocked
 *
 * @v netdev		Network device
 * @v timeout		Timeout (in ticks)
 */
void netdev_link_block ( struct net_device *netdev, unsigned long timeout ) {

	/* Start link block timer */
	if ( ! netdev_link_blocked ( netdev ) ) {
		DBGC ( netdev, "NETDEV %s link blocked for %ld ticks\n",
		       netdev->name, timeout );
	}
	start_timer_fixed ( &netdev->link_block, timeout );
}

/**
 * Mark network device link as being unblocked
 *
 * @v netdev		Network device
 */
void netdev_link_unblock ( struct net_device *netdev ) {

	/* Stop link block timer */
	if ( netdev_link_blocked ( netdev ) )
		DBGC ( netdev, "NETDEV %s link unblocked\n", netdev->name );
	stop_timer ( &netdev->link_block );
}

/**
 * Handle network device link block timer expiry
 *
 * @v timer		Link block timer
 * @v fail		Failure indicator
 */
static void netdev_link_block_expired ( struct retry_timer *timer,
					int fail __unused ) {
	struct net_device *netdev =
		container_of ( timer, struct net_device, link_block );

	/* Assume link is no longer blocked */
	DBGC ( netdev, "NETDEV %s link block expired\n", netdev->name );
}

/**
 * Record network device statistic
 *
 * @v stats		Network device statistics
 * @v rc		Status code
 */
static void netdev_record_stat ( struct net_device_stats *stats, int rc ) {
	struct net_device_error *error;
	struct net_device_error *least_common_error;
	unsigned int i;

	/* If this is not an error, just update the good counter */
	if ( rc == 0 ) {
		stats->good++;
		return;
	}

	/* Update the bad counter */
	stats->bad++;

	/* Locate the appropriate error record */
	least_common_error = &stats->errors[0];
	for ( i = 0 ; i < ( sizeof ( stats->errors ) /
			    sizeof ( stats->errors[0] ) ) ; i++ ) {
		error = &stats->errors[i];
		/* Update matching record, if found */
		if ( error->rc == rc ) {
			error->count++;
			return;
		}
		if ( error->count < least_common_error->count )
			least_common_error = error;
	}

	/* Overwrite the least common error record */
	least_common_error->rc = rc;
	least_common_error->count = 1;
}

/**
 * Transmit raw packet via network device
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 *
 * Transmits the packet via the specified network device.  This
 * function takes ownership of the I/O buffer.
 */
int netdev_tx ( struct net_device *netdev, struct io_buffer *iobuf ) {
	int rc;

	DBGC2 ( netdev, "NETDEV %s transmitting %p (%p+%zx)\n",
		netdev->name, iobuf, iobuf->data, iob_len ( iobuf ) );
	profile_start ( &net_tx_profiler );

	/* Enqueue packet */
	list_add_tail ( &iobuf->list, &netdev->tx_queue );

	/* Avoid calling transmit() on unopened network devices */
	if ( ! netdev_is_open ( netdev ) ) {
		rc = -ENETUNREACH;
		goto err;
	}

	/* Discard packet (for test purposes) if applicable */
	if ( ( rc = inject_fault ( NETDEV_DISCARD_RATE ) ) != 0 )
		goto err;

	/* Transmit packet */
	if ( ( rc = netdev->op->transmit ( netdev, iobuf ) ) != 0 )
		goto err;

	profile_stop ( &net_tx_profiler );
	return 0;

 err:
	netdev_tx_complete_err ( netdev, iobuf, rc );
	return rc;
}

/**
 * Defer transmitted packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 *
 * Drivers may call netdev_tx_defer() if there is insufficient space
 * in the transmit descriptor ring.  Any packets deferred in this way
 * will be automatically retransmitted as soon as space becomes
 * available (i.e. as soon as the driver calls netdev_tx_complete()).
 *
 * The packet must currently be in the network device's TX queue.
 *
 * Drivers utilising netdev_tx_defer() must ensure that space in the
 * transmit descriptor ring is freed up @b before calling
 * netdev_tx_complete().  For example, if the ring is modelled using a
 * producer counter and a consumer counter, then the consumer counter
 * must be incremented before the call to netdev_tx_complete().
 * Failure to do this will cause the retransmitted packet to be
 * immediately redeferred (which will result in out-of-order
 * transmissions and other nastiness).
 */
void netdev_tx_defer ( struct net_device *netdev, struct io_buffer *iobuf ) {

	/* Catch data corruption as early as possible */
	list_check_contains_entry ( iobuf, &netdev->tx_queue, list );

	/* Remove from transmit queue */
	list_del ( &iobuf->list );

	/* Add to deferred transmit queue */
	list_add_tail ( &iobuf->list, &netdev->tx_deferred );

	/* Record "out of space" statistic */
	netdev_tx_err ( netdev, NULL, -ENOBUFS );
}

/**
 * Discard transmitted packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer, or NULL
 * @v rc		Packet status code
 *
 * The packet is discarded and a TX error is recorded.  This function
 * takes ownership of the I/O buffer.
 */
void netdev_tx_err ( struct net_device *netdev,
		     struct io_buffer *iobuf, int rc ) {

	/* Update statistics counter */
	netdev_record_stat ( &netdev->tx_stats, rc );
	if ( rc == 0 ) {
		DBGC2 ( netdev, "NETDEV %s transmission %p complete\n",
			netdev->name, iobuf );
	} else {
		DBGC ( netdev, "NETDEV %s transmission %p failed: %s\n",
		       netdev->name, iobuf, strerror ( rc ) );
	}

	/* Discard packet */
	free_iob ( iobuf );
}

/**
 * Complete network transmission
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @v rc		Packet status code
 *
 * The packet must currently be in the network device's TX queue.
 */
void netdev_tx_complete_err ( struct net_device *netdev,
			      struct io_buffer *iobuf, int rc ) {

	/* Catch data corruption as early as possible */
	list_check_contains_entry ( iobuf, &netdev->tx_queue, list );

	/* Dequeue and free I/O buffer */
	list_del ( &iobuf->list );
	netdev_tx_err ( netdev, iobuf, rc );

	/* Transmit first pending packet, if any */
	if ( ( iobuf = list_first_entry ( &netdev->tx_deferred,
					  struct io_buffer, list ) ) != NULL ) {
		list_del ( &iobuf->list );
		netdev_tx ( netdev, iobuf );
	}
}

/**
 * Complete network transmission
 *
 * @v netdev		Network device
 * @v rc		Packet status code
 *
 * Completes the oldest outstanding packet in the TX queue.
 */
void netdev_tx_complete_next_err ( struct net_device *netdev, int rc ) {
	struct io_buffer *iobuf;

	if ( ( iobuf = list_first_entry ( &netdev->tx_queue, struct io_buffer,
					  list ) ) != NULL ) {
		netdev_tx_complete_err ( netdev, iobuf, rc );
	}
}

/**
 * Flush device's transmit queue
 *
 * @v netdev		Network device
 */
static void netdev_tx_flush ( struct net_device *netdev ) {

	/* Discard any packets in the TX queue.  This will also cause
	 * any packets in the deferred TX queue to be discarded
	 * automatically.
	 */
	while ( ! list_empty ( &netdev->tx_queue ) ) {
		netdev_tx_complete_next_err ( netdev, -ECANCELED );
	}
	assert ( list_empty ( &netdev->tx_queue ) );
	assert ( list_empty ( &netdev->tx_deferred ) );
}

/**
 * Add packet to receive queue
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer, or NULL
 *
 * The packet is added to the network device's RX queue.  This
 * function takes ownership of the I/O buffer.
 */
void netdev_rx ( struct net_device *netdev, struct io_buffer *iobuf ) {
	int rc;

	DBGC2 ( netdev, "NETDEV %s received %p (%p+%zx)\n",
		netdev->name, iobuf, iobuf->data, iob_len ( iobuf ) );

	/* Discard packet (for test purposes) if applicable */
	if ( ( rc = inject_fault ( NETDEV_DISCARD_RATE ) ) != 0 ) {
		netdev_rx_err ( netdev, iobuf, rc );
		return;
	}

	/* Enqueue packet */
	list_add_tail ( &iobuf->list, &netdev->rx_queue );

	/* Update statistics counter */
	netdev_record_stat ( &netdev->rx_stats, 0 );
}

/**
 * Discard received packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer, or NULL
 * @v rc		Packet status code
 *
 * The packet is discarded and an RX error is recorded.  This function
 * takes ownership of the I/O buffer.  @c iobuf may be NULL if, for
 * example, the net device wishes to report an error due to being
 * unable to allocate an I/O buffer.
 */
void netdev_rx_err ( struct net_device *netdev,
		     struct io_buffer *iobuf, int rc ) {

	DBGC ( netdev, "NETDEV %s failed to receive %p: %s\n",
	       netdev->name, iobuf, strerror ( rc ) );

	/* Discard packet */
	free_iob ( iobuf );

	/* Update statistics counter */
	netdev_record_stat ( &netdev->rx_stats, rc );
}

/**
 * Poll for completed and received packets on network device
 *
 * @v netdev		Network device
 *
 * Polls the network device for completed transmissions and received
 * packets.  Any received packets will be added to the RX packet queue
 * via netdev_rx().
 */
void netdev_poll ( struct net_device *netdev ) {

	if ( netdev_is_open ( netdev ) )
		netdev->op->poll ( netdev );
}

/**
 * Remove packet from device's receive queue
 *
 * @v netdev		Network device
 * @ret iobuf		I/O buffer, or NULL
 *
 * Removes the first packet from the device's RX queue and returns it.
 * Ownership of the packet is transferred to the caller.
 */
struct io_buffer * netdev_rx_dequeue ( struct net_device *netdev ) {
	struct io_buffer *iobuf;

	iobuf = list_first_entry ( &netdev->rx_queue, struct io_buffer, list );
	if ( ! iobuf )
		return NULL;

	list_del ( &iobuf->list );
	return iobuf;
}

/**
 * Flush device's receive queue
 *
 * @v netdev		Network device
 */
static void netdev_rx_flush ( struct net_device *netdev ) {
	struct io_buffer *iobuf;

	/* Discard any packets in the RX queue */
	while ( ( iobuf = netdev_rx_dequeue ( netdev ) ) ) {
		netdev_rx_err ( netdev, iobuf, -ECANCELED );
	}
}

/**
 * Finish network device configuration
 *
 * @v config		Network device configuration
 * @v rc		Reason for completion
 */
static void netdev_config_close ( struct net_device_configuration *config,
				  int rc ) {
	struct net_device_configurator *configurator = config->configurator;
	struct net_device *netdev = config->netdev;

	/* Restart interface */
	intf_restart ( &config->job, rc );

	/* Record configuration result */
	config->rc = rc;
	if ( rc == 0 ) {
		DBGC ( netdev, "NETDEV %s configured via %s\n",
		       netdev->name, configurator->name );
	} else {
		DBGC ( netdev, "NETDEV %s configuration via %s failed: %s\n",
		       netdev->name, configurator->name, strerror ( rc ) );
	}
}

/** Network device configuration interface operations */
static struct interface_operation netdev_config_ops[] = {
	INTF_OP ( intf_close, struct net_device_configuration *,
		  netdev_config_close ),
};

/** Network device configuration interface descriptor */
static struct interface_descriptor netdev_config_desc =
	INTF_DESC ( struct net_device_configuration, job, netdev_config_ops );

/**
 * Free network device
 *
 * @v refcnt		Network device reference counter
 */
static void free_netdev ( struct refcnt *refcnt ) {
	struct net_device *netdev =
		container_of ( refcnt, struct net_device, refcnt );

	stop_timer ( &netdev->link_block );
	netdev_tx_flush ( netdev );
	netdev_rx_flush ( netdev );
	clear_settings ( netdev_settings ( netdev ) );
	free ( netdev );
}

/**
 * Allocate network device
 *
 * @v priv_len		Length of private data area (net_device::priv)
 * @ret netdev		Network device, or NULL
 *
 * Allocates space for a network device and its private data area.
 */
struct net_device * alloc_netdev ( size_t priv_len ) {
	struct net_device *netdev;
	struct net_device_configurator *configurator;
	struct net_device_configuration *config;
	unsigned int num_configs;
	size_t confs_len;
	size_t total_len;

	num_configs = table_num_entries ( NET_DEVICE_CONFIGURATORS );
	confs_len = ( num_configs * sizeof ( netdev->configs[0] ) );
	total_len = ( sizeof ( *netdev ) + confs_len + priv_len );
	netdev = zalloc ( total_len );
	if ( netdev ) {
		ref_init ( &netdev->refcnt, free_netdev );
		netdev->link_rc = -EUNKNOWN_LINK_STATUS;
		timer_init ( &netdev->link_block, netdev_link_block_expired,
			     &netdev->refcnt );
		INIT_LIST_HEAD ( &netdev->tx_queue );
		INIT_LIST_HEAD ( &netdev->tx_deferred );
		INIT_LIST_HEAD ( &netdev->rx_queue );
		netdev_settings_init ( netdev );
		config = netdev->configs;
		for_each_table_entry ( configurator, NET_DEVICE_CONFIGURATORS ){
			config->netdev = netdev;
			config->configurator = configurator;
			config->rc = -EUNUSED_CONFIG;
			intf_init ( &config->job, &netdev_config_desc,
				    &netdev->refcnt );
			config++;
		}
		netdev->priv = ( ( ( void * ) netdev ) + sizeof ( *netdev ) +
				 confs_len );
	}
	return netdev;
}

/**
 * Register network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 *
 * Gives the network device a name and adds it to the list of network
 * devices.
 */
int register_netdev ( struct net_device *netdev ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct net_driver *driver;
	struct net_device *duplicate;
	uint32_t seed;
	int rc;

	/* Set initial link-layer address, if not already set */
	if ( ! netdev_has_ll_addr ( netdev ) ) {
		ll_protocol->init_addr ( netdev->hw_addr, netdev->ll_addr );
	}

	/* Reject network devices that are already available via a
	 * different hardware device.
	 */
	duplicate = find_netdev_by_ll_addr ( ll_protocol, netdev->ll_addr );
	if ( duplicate && ( duplicate->dev != netdev->dev ) ) {
		DBGC ( netdev, "NETDEV rejecting duplicate (phys %s) of %s "
		       "(phys %s)\n", netdev->dev->name, duplicate->name,
		       duplicate->dev->name );
		rc = -EEXIST;
		goto err_duplicate;
	}

	/* Record device index and create device name */
	if ( netdev->name[0] == '\0' ) {
		snprintf ( netdev->name, sizeof ( netdev->name ), "net%d",
			   netdev_index );
	}
	netdev->index = ++netdev_index;

	/* Use least significant bits of the link-layer address to
	 * improve the randomness of the (non-cryptographic) random
	 * number generator.
	 */
	memcpy ( &seed, ( netdev->ll_addr + ll_protocol->ll_addr_len
			  - sizeof ( seed ) ), sizeof ( seed ) );
	srand ( rand() ^ seed );

	/* Add to device list */
	netdev_get ( netdev );
	list_add_tail ( &netdev->list, &net_devices );
	DBGC ( netdev, "NETDEV %s registered (phys %s hwaddr %s)\n",
	       netdev->name, netdev->dev->name,
	       netdev_addr ( netdev ) );

	/* Register per-netdev configuration settings */
	if ( ( rc = register_settings ( netdev_settings ( netdev ),
					NULL, netdev->name ) ) != 0 ) {
		DBGC ( netdev, "NETDEV %s could not register settings: %s\n",
		       netdev->name, strerror ( rc ) );
		goto err_register_settings;
	}

	/* Probe device */
	for_each_table_entry ( driver, NET_DRIVERS ) {
		if ( driver->probe && ( rc = driver->probe ( netdev ) ) != 0 ) {
			DBGC ( netdev, "NETDEV %s could not add %s device: "
			       "%s\n", netdev->name, driver->name,
			       strerror ( rc ) );
			goto err_probe;
		}
	}

	return 0;

 err_probe:
	for_each_table_entry_continue_reverse ( driver, NET_DRIVERS ) {
		if ( driver->remove )
			driver->remove ( netdev );
	}
	clear_settings ( netdev_settings ( netdev ) );
	unregister_settings ( netdev_settings ( netdev ) );
 err_register_settings:
 err_duplicate:
	return rc;
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
int netdev_open ( struct net_device *netdev ) {
	int rc;

	/* Do nothing if device is already open */
	if ( netdev->state & NETDEV_OPEN )
		return 0;

	DBGC ( netdev, "NETDEV %s opening\n", netdev->name );

	/* Mark as opened */
	netdev->state |= NETDEV_OPEN;

	/* Open the device */
	if ( ( rc = netdev->op->open ( netdev ) ) != 0 )
		goto err;

	/* Add to head of open devices list */
	list_add ( &netdev->open_list, &open_net_devices );

	/* Notify drivers of device state change */
	netdev_notify ( netdev );

	return 0;

 err:
	netdev->state &= ~NETDEV_OPEN;
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
void netdev_close ( struct net_device *netdev ) {
	unsigned int num_configs;
	unsigned int i;

	/* Do nothing if device is already closed */
	if ( ! ( netdev->state & NETDEV_OPEN ) )
		return;

	DBGC ( netdev, "NETDEV %s closing\n", netdev->name );

	/* Terminate any ongoing configurations.  Use intf_close()
	 * rather than intf_restart() to allow the cancellation to be
	 * reported back to us if a configuration is actually in
	 * progress.
	 */
	num_configs = table_num_entries ( NET_DEVICE_CONFIGURATORS );
	for ( i = 0 ; i < num_configs ; i++ )
		intf_close ( &netdev->configs[i].job, -ECANCELED );

	/* Remove from open devices list */
	list_del ( &netdev->open_list );

	/* Mark as closed */
	netdev->state &= ~NETDEV_OPEN;

	/* Notify drivers of device state change */
	netdev_notify ( netdev );

	/* Close the device */
	netdev->op->close ( netdev );

	/* Flush TX and RX queues */
	netdev_tx_flush ( netdev );
	netdev_rx_flush ( netdev );
}

/**
 * Unregister network device
 *
 * @v netdev		Network device
 *
 * Removes the network device from the list of network devices.
 */
void unregister_netdev ( struct net_device *netdev ) {
	struct net_driver *driver;

	/* Ensure device is closed */
	netdev_close ( netdev );

	/* Remove device */
	for_each_table_entry_reverse ( driver, NET_DRIVERS ) {
		if ( driver->remove )
			driver->remove ( netdev );
	}

	/* Unregister per-netdev configuration settings */
	clear_settings ( netdev_settings ( netdev ) );
	unregister_settings ( netdev_settings ( netdev ) );

	/* Remove from device list */
	DBGC ( netdev, "NETDEV %s unregistered\n", netdev->name );
	list_del ( &netdev->list );
	netdev_put ( netdev );

	/* Reset network device index if no devices remain */
	if ( list_empty ( &net_devices ) )
		netdev_index = 0;
}

/** Enable or disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
void netdev_irq ( struct net_device *netdev, int enable ) {

	/* Do nothing if device does not support interrupts */
	if ( ! netdev_irq_supported ( netdev ) )
		return;

	/* Enable or disable device interrupts */
	netdev->op->irq ( netdev, enable );

	/* Record interrupt enabled state */
	netdev->state &= ~NETDEV_IRQ_ENABLED;
	if ( enable )
		netdev->state |= NETDEV_IRQ_ENABLED;
}

/**
 * Get network device by name
 *
 * @v name		Network device name
 * @ret netdev		Network device, or NULL
 */
struct net_device * find_netdev ( const char *name ) {
	struct net_device *netdev;

	/* Allow "netX" shortcut */
	if ( strcmp ( name, "netX" ) == 0 )
		return last_opened_netdev();

	/* Identify network device by name */
	list_for_each_entry ( netdev, &net_devices, list ) {
		if ( strcmp ( netdev->name, name ) == 0 )
			return netdev;
	}

	return NULL;
}

/**
 * Get network device by index
 *
 * @v index		Network device index
 * @ret netdev		Network device, or NULL
 */
struct net_device * find_netdev_by_index ( unsigned int index ) {
	struct net_device *netdev;

	/* Identify network device by index */
	list_for_each_entry ( netdev, &net_devices, list ) {
		if ( netdev->index == index )
			return netdev;
	}

	return NULL;
}

/**
 * Get network device by PCI bus:dev.fn address
 *
 * @v bus_type		Bus type
 * @v location		Bus location
 * @ret netdev		Network device, or NULL
 */
struct net_device * find_netdev_by_location ( unsigned int bus_type,
					      unsigned int location ) {
	struct net_device *netdev;

	list_for_each_entry ( netdev, &net_devices, list ) {
		if ( ( netdev->dev->desc.bus_type == bus_type ) &&
		     ( netdev->dev->desc.location == location ) )
			return netdev;
	}

	return NULL;	
}

/**
 * Get network device by link-layer address
 *
 * @v ll_protocol	Link-layer protocol
 * @v ll_addr		Link-layer address
 * @ret netdev		Network device, or NULL
 */
struct net_device * find_netdev_by_ll_addr ( struct ll_protocol *ll_protocol,
					     const void *ll_addr ) {
	struct net_device *netdev;

	list_for_each_entry ( netdev, &net_devices, list ) {
		if ( ( netdev->ll_protocol == ll_protocol ) &&
		     ( memcmp ( netdev->ll_addr, ll_addr,
				ll_protocol->ll_addr_len ) == 0 ) )
			return netdev;
	}

	return NULL;
}

/**
 * Get most recently opened network device
 *
 * @ret netdev		Most recently opened network device, or NULL
 */
struct net_device * last_opened_netdev ( void ) {
	struct net_device *netdev;

	netdev = list_first_entry ( &open_net_devices, struct net_device,
				    open_list );
	if ( ! netdev )
		return NULL;

	assert ( netdev_is_open ( netdev ) );
	return netdev;
}

/**
 * Transmit network-layer packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v net_protocol	Network-layer protocol
 * @v ll_dest		Destination link-layer address
 * @v ll_source		Source link-layer address
 * @ret rc		Return status code
 *
 * Prepends link-layer headers to the I/O buffer and transmits the
 * packet via the specified network device.  This function takes
 * ownership of the I/O buffer.
 */
int net_tx ( struct io_buffer *iobuf, struct net_device *netdev,
	     struct net_protocol *net_protocol, const void *ll_dest,
	     const void *ll_source ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	int rc;

	/* Add link-layer header */
	if ( ( rc = ll_protocol->push ( netdev, iobuf, ll_dest, ll_source,
					net_protocol->net_proto ) ) != 0 ) {
		/* Record error for diagnosis */
		netdev_tx_err ( netdev, iobuf, rc );
		return rc;
	}

	/* Transmit packet */
	return netdev_tx ( netdev, iobuf );
}

/**
 * Process received network-layer packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v net_proto		Network-layer protocol, in network-byte order
 * @v ll_dest		Destination link-layer address
 * @v ll_source		Source link-layer address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
int net_rx ( struct io_buffer *iobuf, struct net_device *netdev,
	     uint16_t net_proto, const void *ll_dest, const void *ll_source,
	     unsigned int flags ) {
	struct net_protocol *net_protocol;

	/* Hand off to network-layer protocol, if any */
	for_each_table_entry ( net_protocol, NET_PROTOCOLS ) {
		if ( net_protocol->net_proto == net_proto )
			return net_protocol->rx ( iobuf, netdev, ll_dest,
						  ll_source, flags );
	}

	DBGC ( netdev, "NETDEV %s unknown network protocol %04x\n",
	       netdev->name, ntohs ( net_proto ) );
	free_iob ( iobuf );
	return -ENOTSUP;
}

/**
 * Poll the network stack
 *
 * This polls all interfaces for received packets, and processes
 * packets from the RX queue.
 */
void net_poll ( void ) {
	struct net_device *netdev;
	struct io_buffer *iobuf;
	struct ll_protocol *ll_protocol;
	const void *ll_dest;
	const void *ll_source;
	uint16_t net_proto;
	unsigned int flags;
	int rc;

	/* Poll and process each network device */
	list_for_each_entry ( netdev, &net_devices, list ) {

		/* Poll for new packets */
		profile_start ( &net_poll_profiler );
		netdev_poll ( netdev );
		profile_stop ( &net_poll_profiler );

		/* Leave received packets on the queue if receive
		 * queue processing is currently frozen.  This will
		 * happen when the raw packets are to be manually
		 * dequeued using netdev_rx_dequeue(), rather than
		 * processed via the usual networking stack.
		 */
		if ( netdev_rx_frozen ( netdev ) )
			continue;

		/* Process all received packets */
		while ( ( iobuf = netdev_rx_dequeue ( netdev ) ) ) {

			DBGC2 ( netdev, "NETDEV %s processing %p (%p+%zx)\n",
				netdev->name, iobuf, iobuf->data,
				iob_len ( iobuf ) );
			profile_start ( &net_rx_profiler );

			/* Remove link-layer header */
			ll_protocol = netdev->ll_protocol;
			if ( ( rc = ll_protocol->pull ( netdev, iobuf,
							&ll_dest, &ll_source,
							&net_proto,
							&flags ) ) != 0 ) {
				free_iob ( iobuf );
				continue;
			}

			/* Hand packet to network layer */
			if ( ( rc = net_rx ( iob_disown ( iobuf ), netdev,
					     net_proto, ll_dest,
					     ll_source, flags ) ) != 0 ) {
				/* Record error for diagnosis */
				netdev_rx_err ( netdev, NULL, rc );
			}
			profile_stop ( &net_rx_profiler );
		}
	}
}

/**
 * Single-step the network stack
 *
 * @v process		Network stack process
 */
static void net_step ( struct process *process __unused ) {
	net_poll();
}

/**
 * Get the VLAN tag (when VLAN support is not present)
 *
 * @v netdev		Network device
 * @ret tag		0, indicating that device is not a VLAN device
 */
__weak unsigned int vlan_tag ( struct net_device *netdev __unused ) {
	return 0;
}

/**
 * Identify VLAN device (when VLAN support is not present)
 *
 * @v trunk		Trunk network device
 * @v tag		VLAN tag
 * @ret netdev		VLAN device, if any
 */
__weak struct net_device * vlan_find ( struct net_device *trunk __unused,
				       unsigned int tag __unused ) {
	return NULL;
}

/** Networking stack process */
PERMANENT_PROCESS ( net_process, net_step );

/**
 * Discard some cached network device data
 *
 * @ret discarded	Number of cached items discarded
 */
static unsigned int net_discard ( void ) {
	struct net_device *netdev;
	struct io_buffer *iobuf;
	unsigned int discarded = 0;

	/* Try to drop one deferred TX packet from each network device */
	for_each_netdev ( netdev ) {
		if ( ( iobuf = list_first_entry ( &netdev->tx_deferred,
						  struct io_buffer,
						  list ) ) != NULL ) {

			/* Discard first deferred packet */
			list_del ( &iobuf->list );
			free_iob ( iobuf );

			/* Report discard */
			discarded++;
		}
	}

	return discarded;
}

/** Network device cache discarder */
struct cache_discarder net_discarder __cache_discarder ( CACHE_NORMAL ) = {
	.discard = net_discard,
};

/**
 * Find network device configurator
 *
 * @v name		Name
 * @ret configurator	Network device configurator, or NULL
 */
struct net_device_configurator * find_netdev_configurator ( const char *name ) {
	struct net_device_configurator *configurator;

	for_each_table_entry ( configurator, NET_DEVICE_CONFIGURATORS ) {
		if ( strcmp ( configurator->name, name ) == 0 )
			return configurator;
	}
	return NULL;
}

/**
 * Start network device configuration
 *
 * @v netdev		Network device
 * @v configurator	Network device configurator
 * @ret rc		Return status code
 */
int netdev_configure ( struct net_device *netdev,
		       struct net_device_configurator *configurator ) {
	struct net_device_configuration *config =
		netdev_configuration ( netdev, configurator );
	int rc;

	/* Check applicability of configurator */
	if ( ! netdev_configurator_applies ( netdev, configurator ) ) {
		DBGC ( netdev, "NETDEV %s does not support configuration via "
		       "%s\n", netdev->name, configurator->name );
		return -ENOTSUP;
	}

	/* Terminate any ongoing configuration */
	intf_restart ( &config->job, -ECANCELED );

	/* Mark configuration as being in progress */
	config->rc = -EINPROGRESS_CONFIG;

	DBGC ( netdev, "NETDEV %s starting configuration via %s\n",
	       netdev->name, configurator->name );

	/* Start configuration */
	if ( ( rc = configurator->start ( &config->job, netdev ) ) != 0 ) {
		DBGC ( netdev, "NETDEV %s could not start configuration via "
		       "%s: %s\n", netdev->name, configurator->name,
		       strerror ( rc ) );
		config->rc = rc;
		return rc;
	}

	return 0;
}

/**
 * Start network device configuration via all supported configurators
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
int netdev_configure_all ( struct net_device *netdev ) {
	struct net_device_configurator *configurator;
	int rc;

	/* Start configuration for each configurator */
	for_each_table_entry ( configurator, NET_DEVICE_CONFIGURATORS ) {

		/* Skip any inapplicable configurators */
		if ( ! netdev_configurator_applies ( netdev, configurator ) )
			continue;

		/* Start configuration */
		if ( ( rc = netdev_configure ( netdev, configurator ) ) != 0 )
			return rc;
	}

	return 0;
}

/**
 * Check if network device has a configuration with a specified status code
 *
 * @v netdev		Network device
 * @v rc		Status code
 * @ret has_rc		Network device has a configuration with this status code
 */
static int netdev_has_configuration_rc ( struct net_device *netdev, int rc ) {
	unsigned int num_configs;
	unsigned int i;

	num_configs = table_num_entries ( NET_DEVICE_CONFIGURATORS );
	for ( i = 0 ; i < num_configs ; i++ ) {
		if ( netdev->configs[i].rc == rc )
			return 1;
	}
	return 0;
}

/**
 * Check if network device configuration is in progress
 *
 * @v netdev		Network device
 * @ret is_in_progress	Network device configuration is in progress
 */
int netdev_configuration_in_progress ( struct net_device *netdev ) {

	return netdev_has_configuration_rc ( netdev, -EINPROGRESS_CONFIG );
}

/**
 * Check if network device has at least one successful configuration
 *
 * @v netdev		Network device
 * @v configurator	Configurator
 * @ret rc		Return status code
 */
int netdev_configuration_ok ( struct net_device *netdev ) {

	return netdev_has_configuration_rc ( netdev, 0 );
}
