/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/io.h>
#include <ipxe/malloc.h>
#include <ipxe/profile.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include "vmxnet3.h"

/**
 * @file
 *
 * VMware vmxnet3 virtual NIC driver
 *
 */

/** VM command profiler */
static struct profiler vmxnet3_vm_command_profiler __profiler =
	{ .name = "vmxnet3.vm_command" };

/** VM transmit profiler */
static struct profiler vmxnet3_vm_tx_profiler __profiler =
	{ .name = "vmxnet3.vm_tx" };

/** VM receive refill profiler */
static struct profiler vmxnet3_vm_refill_profiler __profiler =
	{ .name = "vmxnet3.vm_refill" };

/** VM event profiler */
static struct profiler vmxnet3_vm_event_profiler __profiler =
	{ .name = "vmxnet3.vm_event" };

/**
 * Issue command
 *
 * @v vmxnet		vmxnet3 NIC
 * @v command		Command to issue
 * @ret result		Command result
 */
static inline uint32_t vmxnet3_command ( struct vmxnet3_nic *vmxnet,
					 uint32_t command ) {
	uint32_t result;

	/* Issue command */
	profile_start ( &vmxnet3_vm_command_profiler );
	writel ( command, ( vmxnet->vd + VMXNET3_VD_CMD ) );
	result = readl ( vmxnet->vd + VMXNET3_VD_CMD );
	profile_stop ( &vmxnet3_vm_command_profiler );
	profile_exclude ( &vmxnet3_vm_command_profiler );

	return result;
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int vmxnet3_transmit ( struct net_device *netdev,
			      struct io_buffer *iobuf ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	struct vmxnet3_tx_desc *tx_desc;
	unsigned int desc_idx;
	unsigned int generation;

	/* Check that we have a free transmit descriptor */
	desc_idx = ( vmxnet->count.tx_prod % VMXNET3_NUM_TX_DESC );
	generation = ( ( vmxnet->count.tx_prod & VMXNET3_NUM_TX_DESC ) ?
		       0 : cpu_to_le32 ( VMXNET3_TXF_GEN ) );
	if ( vmxnet->tx_iobuf[desc_idx] ) {
		DBGC ( vmxnet, "VMXNET3 %p out of transmit descriptors\n",
		       vmxnet );
		return -ENOBUFS;
	}

	/* Increment producer counter */
	vmxnet->count.tx_prod++;

	/* Store I/O buffer for later completion */
	vmxnet->tx_iobuf[desc_idx] = iobuf;

	/* Populate transmit descriptor */
	tx_desc = &vmxnet->dma->tx_desc[desc_idx];
	tx_desc->address = cpu_to_le64 ( virt_to_bus ( iobuf->data ) );
	tx_desc->flags[0] = ( generation | cpu_to_le32 ( iob_len ( iobuf ) ) );
	tx_desc->flags[1] = cpu_to_le32 ( VMXNET3_TXF_CQ | VMXNET3_TXF_EOP );

	/* Hand over descriptor to NIC */
	wmb();
	profile_start ( &vmxnet3_vm_tx_profiler );
	writel ( ( vmxnet->count.tx_prod % VMXNET3_NUM_TX_DESC ),
		 ( vmxnet->pt + VMXNET3_PT_TXPROD ) );
	profile_stop ( &vmxnet3_vm_tx_profiler );
	profile_exclude ( &vmxnet3_vm_tx_profiler );

	return 0;
}

/**
 * Poll for completed transmissions
 *
 * @v netdev		Network device
 */
static void vmxnet3_poll_tx ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	struct vmxnet3_tx_comp *tx_comp;
	struct io_buffer *iobuf;
	unsigned int comp_idx;
	unsigned int desc_idx;
	unsigned int generation;

	while ( 1 ) {

		/* Look for completed descriptors */
		comp_idx = ( vmxnet->count.tx_cons % VMXNET3_NUM_TX_COMP );
		generation = ( ( vmxnet->count.tx_cons & VMXNET3_NUM_TX_COMP ) ?
			       0 : cpu_to_le32 ( VMXNET3_TXCF_GEN ) );
		tx_comp = &vmxnet->dma->tx_comp[comp_idx];
		if ( generation != ( tx_comp->flags &
				     cpu_to_le32 ( VMXNET3_TXCF_GEN ) ) ) {
			break;
		}

		/* Increment consumer counter */
		vmxnet->count.tx_cons++;

		/* Locate corresponding transmit descriptor */
		desc_idx = ( le32_to_cpu ( tx_comp->index ) %
			     VMXNET3_NUM_TX_DESC );
		iobuf = vmxnet->tx_iobuf[desc_idx];
		if ( ! iobuf ) {
			DBGC ( vmxnet, "VMXNET3 %p completed on empty transmit "
			       "buffer %#x/%#x\n", vmxnet, comp_idx, desc_idx );
			netdev_tx_err ( netdev, NULL, -ENOTTY );
			continue;
		}

		/* Remove I/O buffer from transmit queue */
		vmxnet->tx_iobuf[desc_idx] = NULL;

		/* Report transmission completion to network layer */
		DBGC2 ( vmxnet, "VMXNET3 %p completed TX %#x/%#x (len %#zx)\n",
			vmxnet, comp_idx, desc_idx, iob_len ( iobuf ) );
		netdev_tx_complete ( netdev, iobuf );
	}
}

/**
 * Flush any uncompleted transmit buffers
 *
 * @v netdev		Network device
 */
static void vmxnet3_flush_tx ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	unsigned int i;

	for ( i = 0 ; i < VMXNET3_NUM_TX_DESC ; i++ ) {
		if ( vmxnet->tx_iobuf[i] ) {
			netdev_tx_complete_err ( netdev, vmxnet->tx_iobuf[i],
						 -ECANCELED );
			vmxnet->tx_iobuf[i] = NULL;
		}
	}
}

/**
 * Refill receive ring
 *
 * @v netdev		Network device
 */
static void vmxnet3_refill_rx ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	struct vmxnet3_rx_desc *rx_desc;
	struct io_buffer *iobuf;
	unsigned int orig_rx_prod = vmxnet->count.rx_prod;
	unsigned int desc_idx;
	unsigned int generation;

	/* Fill receive ring to specified fill level */
	while ( vmxnet->count.rx_fill < VMXNET3_RX_FILL ) {

		/* Locate receive descriptor */
		desc_idx = ( vmxnet->count.rx_prod % VMXNET3_NUM_RX_DESC );
		generation = ( ( vmxnet->count.rx_prod & VMXNET3_NUM_RX_DESC ) ?
			       0 : cpu_to_le32 ( VMXNET3_RXF_GEN ) );
		assert ( vmxnet->rx_iobuf[desc_idx] == NULL );

		/* Allocate I/O buffer */
		iobuf = alloc_iob ( VMXNET3_MTU + NET_IP_ALIGN );
		if ( ! iobuf ) {
			/* Non-fatal low memory condition */
			break;
		}
		iob_reserve ( iobuf, NET_IP_ALIGN );

		/* Increment producer counter and fill level */
		vmxnet->count.rx_prod++;
		vmxnet->count.rx_fill++;

		/* Store I/O buffer for later completion */
		vmxnet->rx_iobuf[desc_idx] = iobuf;

		/* Populate receive descriptor */
		rx_desc = &vmxnet->dma->rx_desc[desc_idx];
		rx_desc->address = cpu_to_le64 ( virt_to_bus ( iobuf->data ) );
		rx_desc->flags = ( generation | cpu_to_le32 ( VMXNET3_MTU ) );

	}

	/* Hand over any new descriptors to NIC */
	if ( vmxnet->count.rx_prod != orig_rx_prod ) {
		wmb();
		profile_start ( &vmxnet3_vm_refill_profiler );
		writel ( ( vmxnet->count.rx_prod % VMXNET3_NUM_RX_DESC ),
			 ( vmxnet->pt + VMXNET3_PT_RXPROD ) );
		profile_stop ( &vmxnet3_vm_refill_profiler );
		profile_exclude ( &vmxnet3_vm_refill_profiler );
	}
}

/**
 * Poll for received packets
 *
 * @v netdev		Network device
 */
static void vmxnet3_poll_rx ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	struct vmxnet3_rx_comp *rx_comp;
	struct io_buffer *iobuf;
	unsigned int comp_idx;
	unsigned int desc_idx;
	unsigned int generation;
	size_t len;

	while ( 1 ) {

		/* Look for completed descriptors */
		comp_idx = ( vmxnet->count.rx_cons % VMXNET3_NUM_RX_COMP );
		generation = ( ( vmxnet->count.rx_cons & VMXNET3_NUM_RX_COMP ) ?
			       0 : cpu_to_le32 ( VMXNET3_RXCF_GEN ) );
		rx_comp = &vmxnet->dma->rx_comp[comp_idx];
		if ( generation != ( rx_comp->flags &
				     cpu_to_le32 ( VMXNET3_RXCF_GEN ) ) ) {
			break;
		}

		/* Increment consumer counter */
		vmxnet->count.rx_cons++;

		/* Locate corresponding receive descriptor */
		desc_idx = ( le32_to_cpu ( rx_comp->index ) %
			     VMXNET3_NUM_RX_DESC );
		iobuf = vmxnet->rx_iobuf[desc_idx];
		if ( ! iobuf ) {
			DBGC ( vmxnet, "VMXNET3 %p completed on empty receive "
			       "buffer %#x/%#x\n", vmxnet, comp_idx, desc_idx );
			netdev_rx_err ( netdev, NULL, -ENOTTY );
			continue;
		}

		/* Remove I/O buffer from receive queue */
		vmxnet->rx_iobuf[desc_idx] = NULL;
		vmxnet->count.rx_fill--;

		/* Deliver packet to network layer */
		len = ( le32_to_cpu ( rx_comp->len ) &
			( VMXNET3_MAX_PACKET_LEN - 1 ) );
		DBGC2 ( vmxnet, "VMXNET3 %p completed RX %#x/%#x (len %#zx)\n",
			vmxnet, comp_idx, desc_idx, len );
		iob_put ( iobuf, len );
		netdev_rx ( netdev, iobuf );
	}
}

/**
 * Flush any uncompleted receive buffers
 *
 * @v netdev		Network device
 */
static void vmxnet3_flush_rx ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	struct io_buffer *iobuf;
	unsigned int i;

	for ( i = 0 ; i < VMXNET3_NUM_RX_DESC ; i++ ) {
		if ( ( iobuf = vmxnet->rx_iobuf[i] ) != NULL ) {
			netdev_rx_err ( netdev, iobuf, -ECANCELED );
			vmxnet->rx_iobuf[i] = NULL;
		}
	}
}

/**
 * Check link state
 *
 * @v netdev		Network device
 */
static void vmxnet3_check_link ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	uint32_t state;
	int link_up;
	unsigned int link_speed;

	/* Get link state */
	state = vmxnet3_command ( vmxnet, VMXNET3_CMD_GET_LINK );
	link_up = ( state & 1 );
	link_speed = ( state >> 16 );

	/* Report link state to network device */
	if ( link_up ) {
		DBGC ( vmxnet, "VMXNET3 %p link is up at %d Mbps\n",
		       vmxnet, link_speed );
		netdev_link_up ( netdev );
	} else {
		DBGC ( vmxnet, "VMXNET3 %p link is down\n", vmxnet );
		netdev_link_down ( netdev );
	}
}

/**
 * Poll for events
 *
 * @v netdev		Network device
 */
static void vmxnet3_poll_events ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	uint32_t events;

	/* Do nothing unless there are events to process */
	if ( ! vmxnet->dma->shared.ecr )
		return;
	events = le32_to_cpu ( vmxnet->dma->shared.ecr );

	/* Acknowledge these events */
	profile_start ( &vmxnet3_vm_event_profiler );
	writel ( events, ( vmxnet->vd + VMXNET3_VD_ECR ) );
	profile_stop ( &vmxnet3_vm_event_profiler );
	profile_exclude ( &vmxnet3_vm_event_profiler );

	/* Check for link state change */
	if ( events & VMXNET3_ECR_LINK ) {
		vmxnet3_check_link ( netdev );
		events &= ~VMXNET3_ECR_LINK;
	}

	/* Check for queue errors */
	if ( events & ( VMXNET3_ECR_TQERR | VMXNET3_ECR_RQERR ) ) {
		vmxnet3_command ( vmxnet, VMXNET3_CMD_GET_QUEUE_STATUS );
		DBGC ( vmxnet, "VMXNET3 %p queue error status (TX %08x, RX "
		       "%08x)\n", vmxnet,
		       le32_to_cpu ( vmxnet->dma->queues.tx.status.error ),
		       le32_to_cpu ( vmxnet->dma->queues.rx.status.error ) );
		/* Report errors to allow for visibility via "ifstat" */
		if ( events & VMXNET3_ECR_TQERR )
			netdev_tx_err ( netdev, NULL, -EPIPE );
		if ( events & VMXNET3_ECR_RQERR )
			netdev_rx_err ( netdev, NULL, -EPIPE );
		events &= ~( VMXNET3_ECR_TQERR | VMXNET3_ECR_RQERR );
	}

	/* Check for unknown events */
	if ( events ) {
		DBGC ( vmxnet, "VMXNET3 %p unknown events %08x\n",
		       vmxnet, events );
		/* Report error to allow for visibility via "ifstat" */
		netdev_rx_err ( netdev, NULL, -ENODEV );
	}
}

/**
 * Poll network device
 *
 * @v netdev		Network device
 */
static void vmxnet3_poll ( struct net_device *netdev ) {

	vmxnet3_poll_events ( netdev );
	vmxnet3_poll_tx ( netdev );
	vmxnet3_poll_rx ( netdev );
	vmxnet3_refill_rx ( netdev );
}

/**
 * Enable/disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
static void vmxnet3_irq ( struct net_device *netdev, int enable ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );

	DBGC ( vmxnet, "VMXNET3 %p %s IRQ not implemented\n",
	       vmxnet, ( enable ? "enable" : "disable" ) );
}

/**
 * Set MAC address
 *
 * @v vmxnet		vmxnet3 NIC
 * @v ll_addr		Link-layer address to set
 */
static void vmxnet3_set_ll_addr ( struct vmxnet3_nic *vmxnet,
				  const void *ll_addr ) {
	struct {
		uint32_t low;
		uint32_t high;
	} __attribute__ (( packed )) mac;

	memset ( &mac, 0, sizeof ( mac ) );
	memcpy ( &mac, ll_addr, ETH_ALEN );
	writel ( cpu_to_le32 ( mac.low ), ( vmxnet->vd + VMXNET3_VD_MACL ) );
	writel ( cpu_to_le32 ( mac.high ), ( vmxnet->vd + VMXNET3_VD_MACH ) );
}

/**
 * Open NIC
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int vmxnet3_open ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );
	struct vmxnet3_shared *shared;
	struct vmxnet3_queues *queues;
	uint64_t shared_bus;
	uint64_t queues_bus;
	uint32_t status;
	int rc;

	/* Allocate DMA areas */
	vmxnet->dma = malloc_dma ( sizeof ( *vmxnet->dma ), VMXNET3_DMA_ALIGN );
	if ( ! vmxnet->dma ) {
		DBGC ( vmxnet, "VMXNET3 %p could not allocate DMA area\n",
		       vmxnet );
		rc = -ENOMEM;
		goto err_alloc_dma;
	}
	memset ( vmxnet->dma, 0, sizeof ( *vmxnet->dma ) );

	/* Populate queue descriptors */
	queues = &vmxnet->dma->queues;
	queues->tx.cfg.desc_address =
		cpu_to_le64 ( virt_to_bus ( &vmxnet->dma->tx_desc ) );
	queues->tx.cfg.comp_address =
		cpu_to_le64 ( virt_to_bus ( &vmxnet->dma->tx_comp ) );
	queues->tx.cfg.num_desc = cpu_to_le32 ( VMXNET3_NUM_TX_DESC );
	queues->tx.cfg.num_comp = cpu_to_le32 ( VMXNET3_NUM_TX_COMP );
	queues->rx.cfg.desc_address[0] =
		cpu_to_le64 ( virt_to_bus ( &vmxnet->dma->rx_desc ) );
	queues->rx.cfg.comp_address =
		cpu_to_le64 ( virt_to_bus ( &vmxnet->dma->rx_comp ) );
	queues->rx.cfg.num_desc[0] = cpu_to_le32 ( VMXNET3_NUM_RX_DESC );
	queues->rx.cfg.num_comp = cpu_to_le32 ( VMXNET3_NUM_RX_COMP );
	queues_bus = virt_to_bus ( queues );
	DBGC ( vmxnet, "VMXNET3 %p queue descriptors at %08llx+%zx\n",
	       vmxnet, queues_bus, sizeof ( *queues ) );

	/* Populate shared area */
	shared = &vmxnet->dma->shared;
	shared->magic = cpu_to_le32 ( VMXNET3_SHARED_MAGIC );
	shared->misc.version = cpu_to_le32 ( VMXNET3_VERSION_MAGIC );
	shared->misc.version_support = cpu_to_le32 ( VMXNET3_VERSION_SELECT );
	shared->misc.upt_version_support =
		cpu_to_le32 ( VMXNET3_UPT_VERSION_SELECT );
	shared->misc.queue_desc_address = cpu_to_le64 ( queues_bus );
	shared->misc.queue_desc_len = cpu_to_le32 ( sizeof ( *queues ) );
	shared->misc.mtu = cpu_to_le32 ( VMXNET3_MTU );
	shared->misc.num_tx_queues = 1;
	shared->misc.num_rx_queues = 1;
	shared->interrupt.num_intrs = 1;
	shared->interrupt.control = cpu_to_le32 ( VMXNET3_IC_DISABLE_ALL );
	shared->rx_filter.mode = cpu_to_le32 ( VMXNET3_RXM_UCAST |
					       VMXNET3_RXM_BCAST |
					       VMXNET3_RXM_ALL_MULTI );
	shared_bus = virt_to_bus ( shared );
	DBGC ( vmxnet, "VMXNET3 %p shared area at %08llx+%zx\n",
	       vmxnet, shared_bus, sizeof ( *shared ) );

	/* Zero counters */
	memset ( &vmxnet->count, 0, sizeof ( vmxnet->count ) );

	/* Set MAC address */
	vmxnet3_set_ll_addr ( vmxnet, &netdev->ll_addr );

	/* Pass shared area to device */
	writel ( ( shared_bus >> 0 ), ( vmxnet->vd + VMXNET3_VD_DSAL ) );
	writel ( ( shared_bus >> 32 ), ( vmxnet->vd + VMXNET3_VD_DSAH ) );

	/* Activate device */
	if ( ( status = vmxnet3_command ( vmxnet,
					  VMXNET3_CMD_ACTIVATE_DEV ) ) != 0 ) {
		DBGC ( vmxnet, "VMXNET3 %p could not activate (status %#x)\n",
		       vmxnet, status );
		rc = -EIO;
		goto err_activate;
	}

	/* Fill receive ring */
	vmxnet3_refill_rx ( netdev );

	return 0;

	vmxnet3_command ( vmxnet, VMXNET3_CMD_QUIESCE_DEV );
	vmxnet3_command ( vmxnet, VMXNET3_CMD_RESET_DEV );
 err_activate:
	vmxnet3_flush_tx ( netdev );
	vmxnet3_flush_rx ( netdev );
	free_dma ( vmxnet->dma, sizeof ( *vmxnet->dma ) );
 err_alloc_dma:
	return rc;
}

/**
 * Close NIC
 *
 * @v netdev		Network device
 */
static void vmxnet3_close ( struct net_device *netdev ) {
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );

	vmxnet3_command ( vmxnet, VMXNET3_CMD_QUIESCE_DEV );
	vmxnet3_command ( vmxnet, VMXNET3_CMD_RESET_DEV );
	vmxnet3_flush_tx ( netdev );
	vmxnet3_flush_rx ( netdev );
	free_dma ( vmxnet->dma, sizeof ( *vmxnet->dma ) );
}

/** vmxnet3 net device operations */
static struct net_device_operations vmxnet3_operations = {
	.open		= vmxnet3_open,
	.close		= vmxnet3_close,
	.transmit	= vmxnet3_transmit,
	.poll		= vmxnet3_poll,
	.irq		= vmxnet3_irq,
};

/**
 * Check version
 *
 * @v vmxnet		vmxnet3 NIC
 * @ret rc		Return status code
 */
static int vmxnet3_check_version ( struct vmxnet3_nic *vmxnet ) {
	uint32_t version;
	uint32_t upt_version;

	/* Read version */
	version = readl ( vmxnet->vd + VMXNET3_VD_VRRS );
	upt_version = readl ( vmxnet->vd + VMXNET3_VD_UVRS );
	DBGC ( vmxnet, "VMXNET3 %p is version %d (UPT version %d)\n",
	       vmxnet, version, upt_version );

	/* Inform NIC of driver version */
	writel ( VMXNET3_VERSION_SELECT, ( vmxnet->vd + VMXNET3_VD_VRRS ) );
	writel ( VMXNET3_UPT_VERSION_SELECT, ( vmxnet->vd + VMXNET3_VD_UVRS ) );

	return 0;
}

/**
 * Get permanent MAC address
 *
 * @v vmxnet		vmxnet3 NIC
 * @v hw_addr		Hardware address to fill in
 */
static void vmxnet3_get_hw_addr ( struct vmxnet3_nic *vmxnet, void *hw_addr ) {
	struct {
		uint32_t low;
		uint32_t high;
	} __attribute__ (( packed )) mac;

	mac.low = le32_to_cpu ( vmxnet3_command ( vmxnet,
					       VMXNET3_CMD_GET_PERM_MAC_LO ) );
	mac.high = le32_to_cpu ( vmxnet3_command ( vmxnet,
					       VMXNET3_CMD_GET_PERM_MAC_HI ) );
	memcpy ( hw_addr, &mac, ETH_ALEN );
}

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @v id		PCI ID
 * @ret rc		Return status code
 */
static int vmxnet3_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct vmxnet3_nic *vmxnet;
	int rc;

	/* Allocate network device */
	netdev = alloc_etherdev ( sizeof ( *vmxnet ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc_etherdev;
	}
	netdev_init ( netdev, &vmxnet3_operations );
	vmxnet = netdev_priv ( netdev );
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( vmxnet, 0, sizeof ( *vmxnet ) );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map PCI BARs */
	vmxnet->pt = ioremap ( pci_bar_start ( pci, VMXNET3_PT_BAR ),
			       VMXNET3_PT_LEN );
	if ( ! vmxnet->pt ) {
		rc = -ENODEV;
		goto err_ioremap_pt;
	}
	vmxnet->vd = ioremap ( pci_bar_start ( pci, VMXNET3_VD_BAR ),
			       VMXNET3_VD_LEN );
	if ( ! vmxnet->vd ) {
		rc = -ENODEV;
		goto err_ioremap_vd;
	}

	/* Version check */
	if ( ( rc = vmxnet3_check_version ( vmxnet ) ) != 0 )
		goto err_check_version;

	/* Reset device */
	if ( ( rc = vmxnet3_command ( vmxnet, VMXNET3_CMD_RESET_DEV ) ) != 0 )
		goto err_reset;

	/* Read initial MAC address */
	vmxnet3_get_hw_addr ( vmxnet, &netdev->hw_addr );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 ) {
		DBGC ( vmxnet, "VMXNET3 %p could not register net device: "
		       "%s\n", vmxnet, strerror ( rc ) );
		goto err_register_netdev;
	}

	/* Get initial link state */
	vmxnet3_check_link ( netdev );

	return 0;

	unregister_netdev ( netdev );
 err_register_netdev:
 err_reset:
 err_check_version:
	iounmap ( vmxnet->vd );
 err_ioremap_vd:
	iounmap ( vmxnet->pt );
 err_ioremap_pt:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
 err_alloc_etherdev:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void vmxnet3_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct vmxnet3_nic *vmxnet = netdev_priv ( netdev );

	unregister_netdev ( netdev );
	iounmap ( vmxnet->vd );
	iounmap ( vmxnet->pt );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** vmxnet3 PCI IDs */
static struct pci_device_id vmxnet3_nics[] = {
	PCI_ROM ( 0x15ad, 0x07b0, "vmxnet3", "vmxnet3 virtual NIC", 0 ),
};

/** vmxnet3 PCI driver */
struct pci_driver vmxnet3_driver __pci_driver = {
	.ids = vmxnet3_nics,
	.id_count = ( sizeof ( vmxnet3_nics ) / sizeof ( vmxnet3_nics[0] ) ),
	.probe = vmxnet3_probe,
	.remove = vmxnet3_remove,
};
