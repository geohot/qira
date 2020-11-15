/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ipxe/io.h>
#include <ipxe/pci.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include "intelxvf.h"

/** @file
 *
 * Intel 10 Gigabit Ethernet virtual function network card driver
 *
 */

/******************************************************************************
 *
 * Diagnostics
 *
 ******************************************************************************
 */

/**
 * Dump statistics
 *
 * @v intel		Intel device
 */
static __attribute__ (( unused )) void
intelxvf_stats ( struct intel_nic *intel ) {

	DBGC ( intel, "INTEL %p TX %d (%#x%08x) RX %d (%#x%08x) multi %d\n",
	       intel, readl ( intel->regs + INTELXVF_GPTC ),
	       readl ( intel->regs + INTELXVF_GOTCH ),
	       readl ( intel->regs + INTELXVF_GOTCL ),
	       readl ( intel->regs + INTELXVF_GPRC ),
	       readl ( intel->regs + INTELXVF_GORCH ),
	       readl ( intel->regs + INTELXVF_GORCL ),
	       readl ( intel->regs + INTELXVF_MPRC ) );
}

/******************************************************************************
 *
 * Device reset
 *
 ******************************************************************************
 */

/**
 * Reset hardware
 *
 * @v intel		Intel device
 */
static void intelxvf_reset ( struct intel_nic *intel ) {

	/* Perform a function-level reset */
	writel ( INTELXVF_CTRL_RST, intel->regs + INTELXVF_CTRL );
}

/******************************************************************************
 *
 * Link state
 *
 ******************************************************************************
 */

/**
 * Check link state
 *
 * @v netdev		Network device
 */
static void intelxvf_check_link ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;
	uint32_t links;

	/* Read link status */
	links = readl ( intel->regs + INTELXVF_LINKS );
	DBGC ( intel, "INTEL %p link status is %08x\n", intel, links );

	/* Update network device */
	if ( links & INTELXVF_LINKS_UP ) {
		netdev_link_up ( netdev );
	} else {
		netdev_link_down ( netdev );
	}
}

/******************************************************************************
 *
 * Mailbox messages
 *
 ******************************************************************************
 */

/**
 * Send negotiate API version message
 *
 * @v intel		Intel device
 * @v version		Requested version
 * @ret rc		Return status code
 */
static int intelxvf_mbox_version ( struct intel_nic *intel,
				   unsigned int version ) {
	union intelvf_msg msg;
	int rc;

	/* Send set MTU message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.hdr = INTELXVF_MSG_TYPE_VERSION;
	msg.version.version = version;
	if ( ( rc = intelvf_mbox_msg ( intel, &msg ) ) != 0 ) {
		DBGC ( intel, "INTEL %p negotiate API version failed: %s\n",
		       intel, strerror ( rc ) );
		return rc;
	}

	/* Check response */
	if ( ( msg.hdr & INTELVF_MSG_TYPE_MASK ) != INTELXVF_MSG_TYPE_VERSION ){
		DBGC ( intel, "INTEL %p negotiate API version unexpected "
		       "response:\n", intel );
		DBGC_HDA ( intel, 0, &msg, sizeof ( msg ) );
		return -EPROTO;
	}

	/* Check that this version is supported */
	if ( ! ( msg.hdr & INTELVF_MSG_ACK ) ) {
		DBGC ( intel, "INTEL %p negotiate API version failed\n",
		       intel );
		return -EPERM;
	}

	return 0;
}

/******************************************************************************
 *
 * Network device interface
 *
 ******************************************************************************
 */

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int intelxvf_open ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;
	uint32_t srrctl;
	uint32_t dca_rxctrl;
	int rc;

	/* Reset the function */
	intelxvf_reset ( intel );

	/* Notify PF that reset is complete */
	if ( ( rc = intelvf_mbox_reset ( intel, NULL ) ) != 0 ) {
		DBGC ( intel, "INTEL %p could not reset: %s\n",
		       intel, strerror ( rc ) );
		goto err_mbox_reset;
	}

	/* Negotiate API version 1.1.  If we do not negotiate at least
	 * this version, then the RX datapath will remain disabled if
	 * the PF has jumbo frames enabled.
	 *
	 * Ignore failures, since the host may not actually support
	 * v1.1.
	 */
	intelxvf_mbox_version ( intel, INTELXVF_MSG_VERSION_1_1 );

	/* Set MAC address */
	if ( ( rc = intelvf_mbox_set_mac ( intel, netdev->ll_addr ) ) != 0 ) {
		DBGC ( intel, "INTEL %p could not set MAC address: %s\n",
		       intel, strerror ( rc ) );
		goto err_mbox_set_mac;
	}

	/* Set MTU */
	if ( ( rc = intelvf_mbox_set_mtu ( intel, netdev->max_pkt_len ) ) != 0){
		DBGC ( intel, "INTEL %p could not set MTU %zd: %s\n",
		       intel, netdev->max_pkt_len, strerror ( rc ) );
		goto err_mbox_set_mtu;
	}

	/* Create transmit descriptor ring */
	if ( ( rc = intel_create_ring ( intel, &intel->tx ) ) != 0 )
		goto err_create_tx;

	/* Create receive descriptor ring */
	if ( ( rc = intel_create_ring ( intel, &intel->rx ) ) != 0 )
		goto err_create_rx;

	/* Allocate interrupt vectors */
	writel ( ( INTELXVF_IVAR_RX0_DEFAULT | INTELXVF_IVAR_RX0_VALID |
		   INTELXVF_IVAR_TX0_DEFAULT | INTELXVF_IVAR_TX0_VALID ),
		 intel->regs + INTELXVF_IVAR );
	writel ( ( INTELXVF_IVARM_MBOX_DEFAULT | INTELXVF_IVARM_MBOX_VALID ),
		 intel->regs + INTELXVF_IVARM );

	/* Configure receive buffer sizes and set receive descriptor type */
	srrctl = readl ( intel->regs + INTELXVF_SRRCTL );
	srrctl &= ~( INTELXVF_SRRCTL_BSIZE_MASK |
		     INTELXVF_SRRCTL_DESCTYPE_MASK );
	srrctl |= ( INTELXVF_SRRCTL_BSIZE_DEFAULT |
		    INTELXVF_SRRCTL_DESCTYPE_DEFAULT );
	writel ( srrctl, intel->regs + INTELXVF_SRRCTL );

	/* Clear "must-be-zero" bit for direct cache access (DCA).  We
	 * leave DCA disabled anyway, but if we do not clear this bit
	 * then the received packets contain garbage data.
	 */
	dca_rxctrl = readl ( intel->regs + INTELXVF_DCA_RXCTRL );
	dca_rxctrl &= ~INTELXVF_DCA_RXCTRL_MUST_BE_ZERO;
	writel ( dca_rxctrl, intel->regs + INTELXVF_DCA_RXCTRL );

	/* Fill receive ring */
	intel_refill_rx ( intel );

	/* Update link state */
	intelxvf_check_link ( netdev );

	return 0;

	intel_destroy_ring ( intel, &intel->rx );
 err_create_rx:
	intel_destroy_ring ( intel, &intel->tx );
 err_create_tx:
 err_mbox_set_mtu:
 err_mbox_set_mac:
 err_mbox_reset:
	intelxvf_reset ( intel );
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void intelxvf_close ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;

	/* Destroy receive descriptor ring */
	intel_destroy_ring ( intel, &intel->rx );

	/* Discard any unused receive buffers */
	intel_empty_rx ( intel );

	/* Destroy transmit descriptor ring */
	intel_destroy_ring ( intel, &intel->tx );

	/* Reset the function */
	intelxvf_reset ( intel );
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void intelxvf_poll ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;
	uint32_t eicr;
	int rc;

	/* Check for and acknowledge interrupts */
	eicr = readl ( intel->regs + INTELXVF_EICR );
	if ( ! eicr )
		return;

	/* Poll for TX completions, if applicable */
	if ( eicr & INTELXVF_EIRQ_TX0 )
		intel_poll_tx ( netdev );

	/* Poll for RX completions, if applicable */
	if ( eicr & INTELXVF_EIRQ_RX0 )
		intel_poll_rx ( netdev );

	/* Poll for mailbox messages, if applicable */
	if ( eicr & INTELXVF_EIRQ_MBOX ) {

		/* Poll mailbox */
		if ( ( rc = intelvf_mbox_poll ( intel ) ) != 0 ) {
			DBGC ( intel, "INTEL %p mailbox poll failed!\n",
			       intel );
			netdev_rx_err ( netdev, NULL, rc );
		}

		/* Update link state */
		intelxvf_check_link ( netdev );
	}

	/* Refill RX ring */
	intel_refill_rx ( intel );
}

/**
 * Enable or disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
static void intelxvf_irq ( struct net_device *netdev, int enable ) {
	struct intel_nic *intel = netdev->priv;
	uint32_t mask;

	mask = ( INTELXVF_EIRQ_MBOX | INTELXVF_EIRQ_TX0 | INTELXVF_EIRQ_RX0 );
	if ( enable ) {
		writel ( mask, intel->regs + INTELXVF_EIMS );
	} else {
		writel ( mask, intel->regs + INTELXVF_EIMC );
	}
}

/** Network device operations */
static struct net_device_operations intelxvf_operations = {
	.open		= intelxvf_open,
	.close		= intelxvf_close,
	.transmit	= intel_transmit,
	.poll		= intelxvf_poll,
	.irq		= intelxvf_irq,
};

/******************************************************************************
 *
 * PCI interface
 *
 ******************************************************************************
 */

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
static int intelxvf_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct intel_nic *intel;
	int rc;

	/* Allocate and initialise net device */
	netdev = alloc_etherdev ( sizeof ( *intel ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &intelxvf_operations );
	intel = netdev->priv;
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( intel, 0, sizeof ( *intel ) );
	intel_init_mbox ( &intel->mbox, INTELXVF_MBCTRL, INTELXVF_MBMEM );
	intel_init_ring ( &intel->tx, INTEL_NUM_TX_DESC, INTELXVF_TD,
			  intel_describe_tx_adv );
	intel_init_ring ( &intel->rx, INTEL_NUM_RX_DESC, INTELXVF_RD,
			  intel_describe_rx );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map registers */
	intel->regs = ioremap ( pci->membase, INTELVF_BAR_SIZE );
	if ( ! intel->regs ) {
		rc = -ENODEV;
		goto err_ioremap;
	}

	/* Reset the function */
	intelxvf_reset ( intel );

	/* Send reset message and fetch MAC address */
	if ( ( rc = intelvf_mbox_reset ( intel, netdev->hw_addr ) ) != 0 ) {
		DBGC ( intel, "INTEL %p could not reset and fetch MAC: %s\n",
		       intel, strerror ( rc ) );
		goto err_mbox_reset;
	}

	/* Reset the function (since we will not respond to Control
	 * ("ping") mailbox messages until the network device is opened.
	 */
	intelxvf_reset ( intel );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	/* Set initial link state */
	intelxvf_check_link ( netdev );

	return 0;

	unregister_netdev ( netdev );
 err_register_netdev:
 err_mbox_reset:
	intelxvf_reset ( intel );
	iounmap ( intel->regs );
 err_ioremap:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
 err_alloc:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void intelxvf_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct intel_nic *intel = netdev->priv;

	/* Unregister network device */
	unregister_netdev ( netdev );

	/* Reset the NIC */
	intelxvf_reset ( intel );

	/* Free network device */
	iounmap ( intel->regs );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** PCI device IDs */
static struct pci_device_id intelxvf_nics[] = {
	PCI_ROM ( 0x8086, 0x10ed, "82599-vf", "82599 VF", 0 ),
	PCI_ROM ( 0x8086, 0x1515, "x540-vf", "X540 VF", 0 ),
	PCI_ROM ( 0x8086, 0x1565, "x550-vf", "X550 VF", 0 ),
	PCI_ROM ( 0x8086, 0x15a8, "x552-vf", "X552 VF", 0 ),
};

/** PCI driver */
struct pci_driver intelxvf_driver __pci_driver = {
	.ids = intelxvf_nics,
	.id_count = ( sizeof ( intelxvf_nics ) / sizeof ( intelxvf_nics[0] ) ),
	.probe = intelxvf_probe,
	.remove = intelxvf_remove,
};
