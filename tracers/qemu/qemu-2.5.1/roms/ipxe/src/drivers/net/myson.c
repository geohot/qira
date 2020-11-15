/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <ipxe/mii.h>
#include "myson.h"

/** @file
 *
 * Myson Technology network card driver
 *
 */

/******************************************************************************
 *
 * Device reset
 *
 ******************************************************************************
 */

/**
 * Reset controller chip
 *
 * @v myson		Myson device
 * @ret rc		Return status code
 */
static int myson_soft_reset ( struct myson_nic *myson ) {
	uint32_t bcr;
	unsigned int i;

	/* Initiate reset */
	bcr = readl ( myson->regs + MYSON_BCR );
	writel ( ( bcr | MYSON_BCR_SWR ), myson->regs + MYSON_BCR );

	/* Wait for reset to complete */
	for ( i = 0 ; i < MYSON_RESET_MAX_WAIT_MS ; i++ ) {

		/* If reset is not complete, delay 1ms and retry */
		if ( readl ( myson->regs + MYSON_BCR ) & MYSON_BCR_SWR ) {
			mdelay ( 1 );
			continue;
		}

		/* Apply a sensible default bus configuration */
		bcr = readl ( myson->regs + MYSON_BCR );
		bcr &= ~MYSON_BCR_PBL_MASK;
		bcr |= ( MYSON_BCR_RLE | MYSON_BCR_RME | MYSON_BCR_WIE |
			 MYSON_BCR_PBL_DEFAULT );
		writel ( bcr, myson->regs + MYSON_BCR );
		DBGC ( myson, "MYSON %p using configuration %08x\n",
		       myson, bcr );

		return 0;
	}

	DBGC ( myson, "MYSON %p timed out waiting for reset\n", myson );
	return -ETIMEDOUT;
}

/**
 * Reload configuration from EEPROM
 *
 * @v myson		Myson device
 * @ret rc		Return status code
 */
static int myson_reload_config ( struct myson_nic *myson ) {
	unsigned int i;

	/* Initiate reload */
	writel ( MYSON_ROM_AUTOLD, myson->regs + MYSON_ROM_MII );

	/* Wait for reload to complete */
	for ( i = 0 ; i < MYSON_AUTOLD_MAX_WAIT_MS ; i++ ) {

		/* If reload is not complete, delay 1ms and retry */
		if ( readl ( myson->regs + MYSON_ROM_MII ) & MYSON_ROM_AUTOLD ){
			mdelay ( 1 );
			continue;
		}

		return 0;
	}

	DBGC ( myson, "MYSON %p timed out waiting for configuration "
	       "reload\n", myson );
	return -ETIMEDOUT;
}

/**
 * Reset hardware
 *
 * @v myson		Myson device
 * @ret rc		Return status code
 */
static int myson_reset ( struct myson_nic *myson ) {
	int rc;

	/* Disable all interrupts */
	writel ( 0, myson->regs + MYSON_IMR );

	/* Perform soft reset */
	if ( ( rc = myson_soft_reset ( myson ) ) != 0 )
		return rc;

	/* Reload configuration from EEPROM */
	if ( ( rc = myson_reload_config ( myson ) ) != 0 )
		return rc;

	return 0;
}

/******************************************************************************
 *
 * Network device interface
 *
 ******************************************************************************
 */

/**
 * Create descriptor ring
 *
 * @v myson		Myson device
 * @v ring		Descriptor ring
 * @ret rc		Return status code
 */
static int myson_create_ring ( struct myson_nic *myson,
			       struct myson_ring *ring ) {
	size_t len = ( ring->count * sizeof ( ring->desc[0] ) );
	struct myson_descriptor *desc;
	struct myson_descriptor *next;
	physaddr_t address;
	unsigned int i;
	int rc;

	/* Allocate descriptor ring */
	ring->desc = malloc_dma ( len, MYSON_RING_ALIGN );
	if ( ! ring->desc ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	address = virt_to_bus ( ring->desc );

	/* Check address is usable by card */
	if ( ! myson_address_ok ( address + len ) ) {
		DBGC ( myson, "MYSON %p cannot support 64-bit ring address\n",
		       myson );
		rc = -ENOTSUP;
		goto err_64bit;
	}

	/* Initialise descriptor ring */
	memset ( ring->desc, 0, len );
	for ( i = 0 ; i < ring->count ; i++ ) {
		desc = &ring->desc[i];
		next = &ring->desc[ ( i + 1 ) % ring->count ];
		desc->next = cpu_to_le32 ( virt_to_bus ( next ) );
	}

	/* Program ring address */
	writel ( address, myson->regs + ring->reg );
	DBGC ( myson, "MYSON %p ring %02x is at [%08llx,%08llx)\n",
	       myson, ring->reg, ( ( unsigned long long ) address ),
	       ( ( unsigned long long ) address + len ) );

	return 0;

 err_64bit:
	free_dma ( ring->desc, len );
	ring->desc = NULL;
 err_alloc:
	return rc;
}

/**
 * Destroy descriptor ring
 *
 * @v myson		Myson device
 * @v ring		Descriptor ring
 */
static void myson_destroy_ring ( struct myson_nic *myson,
				 struct myson_ring *ring ) {
	size_t len = ( ring->count * sizeof ( ring->desc[0] ) );

	/* Clear ring address */
	writel ( 0, myson->regs + ring->reg );

	/* Free descriptor ring */
	free_dma ( ring->desc, len );
	ring->desc = NULL;
	ring->prod = 0;
	ring->cons = 0;
}

/**
 * Refill receive descriptor ring
 *
 * @v netdev		Network device
 */
static void myson_refill_rx ( struct net_device *netdev ) {
	struct myson_nic *myson = netdev->priv;
	struct myson_descriptor *rx;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	physaddr_t address;

	while ( ( myson->rx.prod - myson->rx.cons ) < MYSON_NUM_RX_DESC ) {

		/* Allocate I/O buffer */
		iobuf = alloc_iob ( MYSON_RX_MAX_LEN );
		if ( ! iobuf ) {
			/* Wait for next refill */
			return;
		}

		/* Check address is usable by card */
		address = virt_to_bus ( iobuf->data );
		if ( ! myson_address_ok ( address ) ) {
			DBGC ( myson, "MYSON %p cannot support 64-bit RX "
			       "buffer address\n", myson );
			netdev_rx_err ( netdev, iobuf, -ENOTSUP );
			return;
		}

		/* Get next receive descriptor */
		rx_idx = ( myson->rx.prod++ % MYSON_NUM_RX_DESC );
		rx = &myson->rx.desc[rx_idx];

		/* Populate receive descriptor */
		rx->address = cpu_to_le32 ( address );
		rx->control =
			cpu_to_le32 ( MYSON_RX_CTRL_RBS ( MYSON_RX_MAX_LEN ) );
		wmb();
		rx->status = cpu_to_le32 ( MYSON_RX_STAT_OWN );
		wmb();

		/* Record I/O buffer */
		assert ( myson->rx_iobuf[rx_idx] == NULL );
		myson->rx_iobuf[rx_idx] = iobuf;

		/* Notify card that there are descriptors available */
		writel ( 0, myson->regs + MYSON_RXPDR );

		DBGC2 ( myson, "MYSON %p RX %d is [%llx,%llx)\n", myson,
			rx_idx, ( ( unsigned long long ) address ),
			( ( unsigned long long ) address + MYSON_RX_MAX_LEN ) );
	}
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int myson_open ( struct net_device *netdev ) {
	struct myson_nic *myson = netdev->priv;
	union myson_physical_address mac;
	int rc;

	/* Set MAC address */
	memset ( &mac, 0, sizeof ( mac ) );
	memcpy ( mac.raw, netdev->ll_addr, ETH_ALEN );
	writel ( le32_to_cpu ( mac.reg.low ), myson->regs + MYSON_PAR0 );
	writel ( le32_to_cpu ( mac.reg.high ), myson->regs + MYSON_PAR4 );

	/* Create transmit descriptor ring */
	if ( ( rc = myson_create_ring ( myson, &myson->tx ) ) != 0 )
		goto err_create_tx;

	/* Create receive descriptor ring */
	if ( ( rc = myson_create_ring ( myson, &myson->rx ) ) != 0 )
		goto err_create_rx;

	/* Configure transmitter and receiver */
	writel ( ( MYSON_TCR_TE | MYSON_RCR_PROM | MYSON_RCR_AB | MYSON_RCR_AM |
		   MYSON_RCR_ARP | MYSON_RCR_ALP | MYSON_RCR_RE ),
		 myson->regs + MYSON_TCR_RCR );

	/* Fill receive ring */
	myson_refill_rx ( netdev );

	return 0;

	myson_destroy_ring ( myson, &myson->rx );
 err_create_rx:
	myson_destroy_ring ( myson, &myson->tx );
 err_create_tx:
	return rc;
}

/**
 * Wait for transmit and receive to become idle
 *
 * @v myson		Myson device
 * @ret rc		Return status code
 */
static int myson_wait_idle ( struct myson_nic *myson ) {
	uint32_t tcr_rcr;
	unsigned int i;

	/* Wait for both transmit and receive to be idle */
	for ( i = 0 ; i < MYSON_IDLE_MAX_WAIT_MS ; i++ ) {

		/* If either process is running, delay 1ms and retry */
		tcr_rcr = readl ( myson->regs + MYSON_TCR_RCR );
		if ( tcr_rcr & ( MYSON_TCR_TXS | MYSON_RCR_RXS ) ) {
			mdelay ( 1 );
			continue;
		}

		return 0;
	}

	DBGC ( myson, "MYSON %p timed out waiting for idle state (status "
	       "%08x)\n", myson, tcr_rcr );
	return -ETIMEDOUT;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void myson_close ( struct net_device *netdev ) {
	struct myson_nic *myson = netdev->priv;
	unsigned int i;

	/* Disable receiver and transmitter */
	writel ( 0, myson->regs + MYSON_TCR_RCR );

	/* Allow time for receiver and transmitter to become idle */
	myson_wait_idle ( myson );

	/* Destroy receive descriptor ring */
	myson_destroy_ring ( myson, &myson->rx );

	/* Discard any unused receive buffers */
	for ( i = 0 ; i < MYSON_NUM_RX_DESC ; i++ ) {
		if ( myson->rx_iobuf[i] )
			free_iob ( myson->rx_iobuf[i] );
		myson->rx_iobuf[i] = NULL;
	}

	/* Destroy transmit descriptor ring */
	myson_destroy_ring ( myson, &myson->tx );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int myson_transmit ( struct net_device *netdev,
			    struct io_buffer *iobuf ) {
	struct myson_nic *myson = netdev->priv;
	struct myson_descriptor *tx;
	unsigned int tx_idx;
	physaddr_t address;

	/* Check address is usable by card */
	address = virt_to_bus ( iobuf->data );
	if ( ! myson_address_ok ( address ) ) {
		DBGC ( myson, "MYSON %p cannot support 64-bit TX buffer "
		       "address\n", myson );
		return -ENOTSUP;
	}

	/* Get next transmit descriptor */
	if ( ( myson->tx.prod - myson->tx.cons ) >= MYSON_NUM_TX_DESC ) {
		DBGC ( myson, "MYSON %p out of transmit descriptors\n",
		       myson );
		return -ENOBUFS;
	}
	tx_idx = ( myson->tx.prod++ % MYSON_NUM_TX_DESC );
	tx = &myson->tx.desc[tx_idx];

	/* Populate transmit descriptor */
	tx->address = cpu_to_le32 ( address );
	tx->control = cpu_to_le32 ( MYSON_TX_CTRL_IC | MYSON_TX_CTRL_LD |
				    MYSON_TX_CTRL_FD | MYSON_TX_CTRL_CRC |
				    MYSON_TX_CTRL_PAD | MYSON_TX_CTRL_RTLC |
				    MYSON_TX_CTRL_PKTS ( iob_len ( iobuf ) ) |
				    MYSON_TX_CTRL_TBS ( iob_len ( iobuf ) ) );
	wmb();
	tx->status = cpu_to_le32 ( MYSON_TX_STAT_OWN );
	wmb();

	/* Notify card that there are packets ready to transmit */
	writel ( 0, myson->regs + MYSON_TXPDR );

	DBGC2 ( myson, "MYSON %p TX %d is [%llx,%llx)\n", myson, tx_idx,
		( ( unsigned long long ) address ),
		( ( unsigned long long ) address + iob_len ( iobuf ) ) );

	return 0;
}

/**
 * Poll for completed packets
 *
 * @v netdev		Network device
 */
static void myson_poll_tx ( struct net_device *netdev ) {
	struct myson_nic *myson = netdev->priv;
	struct myson_descriptor *tx;
	unsigned int tx_idx;

	/* Check for completed packets */
	while ( myson->tx.cons != myson->tx.prod ) {

		/* Get next transmit descriptor */
		tx_idx = ( myson->tx.cons % MYSON_NUM_TX_DESC );
		tx = &myson->tx.desc[tx_idx];

		/* Stop if descriptor is still in use */
		if ( tx->status & cpu_to_le32 ( MYSON_TX_STAT_OWN ) )
			return;

		/* Complete TX descriptor */
		if ( tx->status & cpu_to_le32 ( MYSON_TX_STAT_ABORT |
						MYSON_TX_STAT_CSL ) ) {
			DBGC ( myson, "MYSON %p TX %d completion error "
			       "(%08x)\n", myson, tx_idx,
			       le32_to_cpu ( tx->status ) );
			netdev_tx_complete_next_err ( netdev, -EIO );
		} else {
			DBGC2 ( myson, "MYSON %p TX %d complete\n",
				myson, tx_idx );
			netdev_tx_complete_next ( netdev );
		}
		myson->tx.cons++;
	}
}

/**
 * Poll for received packets
 *
 * @v netdev		Network device
 */
static void myson_poll_rx ( struct net_device *netdev ) {
	struct myson_nic *myson = netdev->priv;
	struct myson_descriptor *rx;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	size_t len;

	/* Check for received packets */
	while ( myson->rx.cons != myson->rx.prod ) {

		/* Get next receive descriptor */
		rx_idx = ( myson->rx.cons % MYSON_NUM_RX_DESC );
		rx = &myson->rx.desc[rx_idx];

		/* Stop if descriptor is still in use */
		if ( rx->status & MYSON_RX_STAT_OWN )
			return;

		/* Populate I/O buffer */
		iobuf = myson->rx_iobuf[rx_idx];
		myson->rx_iobuf[rx_idx] = NULL;
		len = MYSON_RX_STAT_FLNG ( le32_to_cpu ( rx->status ) );
		iob_put ( iobuf, len - 4 /* strip CRC */ );

		/* Hand off to network stack */
		if ( rx->status & cpu_to_le32 ( MYSON_RX_STAT_ES ) ) {
			DBGC ( myson, "MYSON %p RX %d error (length %zd, "
			       "status %08x)\n", myson, rx_idx, len,
			       le32_to_cpu ( rx->status ) );
			netdev_rx_err ( netdev, iobuf, -EIO );
		} else {
			DBGC2 ( myson, "MYSON %p RX %d complete (length "
				"%zd)\n", myson, rx_idx, len );
			netdev_rx ( netdev, iobuf );
		}
		myson->rx.cons++;
	}
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void myson_poll ( struct net_device *netdev ) {
	struct myson_nic *myson = netdev->priv;
	uint32_t isr;
	unsigned int i;

	/* Polling the ISR seems to really upset this card; it ends up
	 * getting no useful PCI transfers done and, for some reason,
	 * flooding the network with invalid packets.  Work around
	 * this by introducing deliberate delays between ISR reads.
	 */
	for ( i = 0 ; i < MYSON_ISR_IODELAY_COUNT ; i++ )
		iodelay();

	/* Check for and acknowledge interrupts */
	isr = readl ( myson->regs + MYSON_ISR );
	if ( ! isr )
		return;
	writel ( isr, myson->regs + MYSON_ISR );

	/* Poll for TX completions, if applicable */
	if ( isr & MYSON_IRQ_TI )
		myson_poll_tx ( netdev );

	/* Poll for RX completionsm, if applicable */
	if ( isr & MYSON_IRQ_RI )
		myson_poll_rx ( netdev );

	/* Refill RX ring */
	myson_refill_rx ( netdev );
}

/**
 * Enable or disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
static void myson_irq ( struct net_device *netdev, int enable ) {
	struct myson_nic *myson = netdev->priv;
	uint32_t imr;

	imr = ( enable ? ( MYSON_IRQ_TI | MYSON_IRQ_RI ) : 0 );
	writel ( imr, myson->regs + MYSON_IMR );
}

/** Myson network device operations */
static struct net_device_operations myson_operations = {
	.open		= myson_open,
	.close		= myson_close,
	.transmit	= myson_transmit,
	.poll		= myson_poll,
	.irq		= myson_irq,
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
static int myson_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct myson_nic *myson;
	union myson_physical_address mac;
	int rc;

	/* Allocate and initialise net device */
	netdev = alloc_etherdev ( sizeof ( *myson ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &myson_operations );
	myson = netdev->priv;
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( myson, 0, sizeof ( *myson ) );
	myson_init_ring ( &myson->tx, MYSON_NUM_TX_DESC, MYSON_TXLBA );
	myson_init_ring ( &myson->rx, MYSON_NUM_RX_DESC, MYSON_RXLBA );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map registers */
	myson->regs = ioremap ( pci->membase, MYSON_BAR_SIZE );
	if ( ! myson->regs ) {
		rc = -ENODEV;
		goto err_ioremap;
	}

	/* Reset the NIC */
	if ( ( rc = myson_reset ( myson ) ) != 0 )
		goto err_reset;

	/* Read MAC address */
	mac.reg.low = cpu_to_le32 ( readl ( myson->regs + MYSON_PAR0 ) );
	mac.reg.high = cpu_to_le32 ( readl ( myson->regs + MYSON_PAR4 ) );
	memcpy ( netdev->hw_addr, mac.raw, ETH_ALEN );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	/* Mark as link up; we don't yet handle link state */
	netdev_link_up ( netdev );

	return 0;

	unregister_netdev ( netdev );
 err_register_netdev:
	myson_reset ( myson );
 err_reset:
	iounmap ( myson->regs );
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
static void myson_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct myson_nic *myson = netdev->priv;

	/* Unregister network device */
	unregister_netdev ( netdev );

	/* Reset card */
	myson_reset ( myson );

	/* Free network device */
	iounmap ( myson->regs );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** Myson PCI device IDs */
static struct pci_device_id myson_nics[] = {
        PCI_ROM ( 0x1516, 0x0800, "mtd800", "MTD-8xx", 0 ),
        PCI_ROM ( 0x1516, 0x0803, "mtd803", "Surecom EP-320X-S", 0 ),
        PCI_ROM ( 0x1516, 0x0891, "mtd891", "MTD-8xx", 0 ),
};

/** Myson PCI driver */
struct pci_driver myson_driver __pci_driver = {
	.ids = myson_nics,
	.id_count = ( sizeof ( myson_nics ) / sizeof ( myson_nics[0] ) ),
	.probe = myson_probe,
	.remove = myson_remove,
};
