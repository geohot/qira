#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/if_ether.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <nic.h>

/*
 * Quick and dirty compatibility layer
 *
 * This should allow old-API PCI drivers to at least function until
 * they are updated.  It will not help non-PCI drivers.
 *
 * No drivers should rely on this code.  It will be removed asap.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct nic nic;

static int legacy_registered = 0;

static int legacy_transmit ( struct net_device *netdev, struct io_buffer *iobuf ) {
	struct nic *nic = netdev->priv;
	struct ethhdr *ethhdr;

	DBG ( "Transmitting %zd bytes\n", iob_len ( iobuf ) );
	iob_pad ( iobuf, ETH_ZLEN );
	ethhdr = iobuf->data;
	iob_pull ( iobuf, sizeof ( *ethhdr ) );
	nic->nic_op->transmit ( nic, ( const char * ) ethhdr->h_dest,
				ntohs ( ethhdr->h_protocol ),
				iob_len ( iobuf ), iobuf->data );
	netdev_tx_complete ( netdev, iobuf );
	return 0;
}

static void legacy_poll ( struct net_device *netdev ) {
	struct nic *nic = netdev->priv;
	struct io_buffer *iobuf;

	iobuf = alloc_iob ( ETH_FRAME_LEN );
	if ( ! iobuf )
		return;

	nic->packet = iobuf->data;
	if ( nic->nic_op->poll ( nic, 1 ) ) {
		DBG ( "Received %d bytes\n", nic->packetlen );
		iob_put ( iobuf, nic->packetlen );
		netdev_rx ( netdev, iobuf );
	} else {
		free_iob ( iobuf );
	}
}

static int legacy_open ( struct net_device *netdev __unused ) {
	/* Nothing to do */
	return 0;
}

static void legacy_close ( struct net_device *netdev __unused ) {
	/* Nothing to do */
}

static void legacy_irq ( struct net_device *netdev __unused, int enable ) {
	struct nic *nic = netdev->priv;

	nic->nic_op->irq ( nic, ( enable ? ENABLE : DISABLE ) );
}

static struct net_device_operations legacy_operations = {
	.open		= legacy_open,
	.close		= legacy_close,
	.transmit	= legacy_transmit,
	.poll		= legacy_poll,
	.irq   		= legacy_irq,
};

int legacy_probe ( void *hwdev,
		   void ( * set_drvdata ) ( void *hwdev, void *priv ),
		   struct device *dev,
		   int ( * probe ) ( struct nic *nic, void *hwdev ),
		   void ( * disable ) ( struct nic *nic, void *hwdev ) ) {
	struct net_device *netdev;
	int rc;

	if ( legacy_registered )
		return -EBUSY;
	
	netdev = alloc_etherdev ( 0 );
	if ( ! netdev )
		return -ENOMEM;
	netdev_init ( netdev, &legacy_operations );
	netdev->priv = &nic;
	memset ( &nic, 0, sizeof ( nic ) );
	set_drvdata ( hwdev, netdev );
	netdev->dev = dev;

	nic.node_addr = netdev->hw_addr;
	nic.irqno = dev->desc.irq;

	if ( ! probe ( &nic, hwdev ) ) {
		rc = -ENODEV;
		goto err_probe;
	}

	/* Overwrite the IRQ number.  Some legacy devices set
	 * nic->irqno to 0 in the probe routine to indicate that they
	 * don't support interrupts; doing this allows the timer
	 * interrupt to be used instead.
	 */
	dev->desc.irq = nic.irqno;

	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	/* Mark as link up; legacy devices don't handle link state */
	netdev_link_up ( netdev );

	/* Do not remove this message */
	printf ( "WARNING: Using legacy NIC wrapper on %s\n",
		 netdev->ll_protocol->ntoa ( nic.node_addr ) );

	legacy_registered = 1;
	return 0;

 err_register:
	disable ( &nic, hwdev );
 err_probe:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	return rc;
}

void legacy_remove ( void *hwdev,
		     void * ( * get_drvdata ) ( void *hwdev ),
		     void ( * disable ) ( struct nic *nic, void *hwdev ) ) {
	struct net_device *netdev = get_drvdata ( hwdev );
	struct nic *nic = netdev->priv;

	unregister_netdev ( netdev );
	disable ( nic, hwdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	legacy_registered = 0;
}

int dummy_connect ( struct nic *nic __unused ) {
	return 1;
}

void dummy_irq ( struct nic *nic __unused, irq_action_t irq_action __unused ) {
	return;
}
