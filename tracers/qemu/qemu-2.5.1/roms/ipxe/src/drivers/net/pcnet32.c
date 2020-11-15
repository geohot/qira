/*
 * Copyright (c) 2010 Andrei Faur <da3drus@gmail.com>
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/io.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/netdevice.h>
#include <ipxe/pci.h>
#include <ipxe/timer.h>
#include <mii.h>
#include "pcnet32.h"

static u16 pcnet32_wio_read_csr ( unsigned long addr, int index )
{
	outw ( index, addr + PCNET32_WIO_RAP );
	return inw ( addr + PCNET32_WIO_RDP );
}

static void pcnet32_wio_write_csr ( unsigned long addr, int index, u16 val )
{
	outw ( index, addr + PCNET32_WIO_RAP );
	outw ( val, addr + PCNET32_WIO_RDP );
}

static u16 pcnet32_wio_read_bcr ( unsigned long addr, int index )
{
	outw ( index, addr + PCNET32_WIO_RAP );
	return inw ( addr + PCNET32_WIO_BDP );
}

static void pcnet32_wio_write_bcr ( unsigned long addr, int index, u16 val )
{
	outw ( index, addr + PCNET32_WIO_RAP );
	outw ( val, addr + PCNET32_WIO_BDP );
}

static u16 pcnet32_wio_read_rap ( unsigned long addr )
{
	return inw ( addr + PCNET32_WIO_RAP );
}

static void pcnet32_wio_write_rap ( unsigned long addr , u16 val )
{
	outw ( val, addr + PCNET32_WIO_RAP );
}

static void pcnet32_wio_reset ( unsigned long addr )
{
	inw ( addr + PCNET32_WIO_RESET );
}

static int pcnet32_wio_check ( unsigned long addr )
{
	outw ( 88, addr + PCNET32_WIO_RAP );
	return ( inw ( addr + PCNET32_WIO_RAP ) == 88 );
}

static struct pcnet32_access pcnet32_wio = {
	.read_csr	= pcnet32_wio_read_csr,
	.write_csr	= pcnet32_wio_write_csr,
	.read_bcr	= pcnet32_wio_read_bcr,
	.write_bcr	= pcnet32_wio_write_bcr,
	.read_rap	= pcnet32_wio_read_rap,
	.write_rap	= pcnet32_wio_write_rap,
	.reset		= pcnet32_wio_reset,
};

static u16 pcnet32_dwio_read_csr ( unsigned long addr, int index )
{
	outl ( index, addr + PCNET32_DWIO_RAP );
	return ( inl ( addr + PCNET32_DWIO_RDP ) & 0xffff );
}

static void pcnet32_dwio_write_csr ( unsigned long addr, int index, u16 val )
{
	outl ( index, addr + PCNET32_DWIO_RAP );
	outl ( val, addr + PCNET32_DWIO_RDP );
}

static u16 pcnet32_dwio_read_bcr ( unsigned long addr, int index )
{
	outl ( index, addr + PCNET32_DWIO_RAP );
	return ( inl ( addr + PCNET32_DWIO_BDP ) & 0xffff );
}

static void pcnet32_dwio_write_bcr ( unsigned long addr, int index, u16 val )
{
	outl ( index, addr + PCNET32_DWIO_RAP );
	outl ( val, addr + PCNET32_DWIO_BDP );
}

static u16 pcnet32_dwio_read_rap ( unsigned long addr )
{
	return ( inl ( addr + PCNET32_DWIO_RAP ) & 0xffff );
}

static void pcnet32_dwio_write_rap ( unsigned long addr , u16 val )
{
	outl ( val, addr + PCNET32_DWIO_RAP );
}

static void pcnet32_dwio_reset ( unsigned long addr )
{
	inl ( addr + PCNET32_DWIO_RESET );
}

static int pcnet32_dwio_check ( unsigned long addr )
{
	outl ( 88, addr + PCNET32_DWIO_RAP );
	return ( ( inl ( addr + PCNET32_DWIO_RAP ) & 0xffff ) == 88 );
}


static struct pcnet32_access pcnet32_dwio = {
	.read_csr	= pcnet32_dwio_read_csr,
	.write_csr	= pcnet32_dwio_write_csr,
	.read_bcr	= pcnet32_dwio_read_bcr,
	.write_bcr	= pcnet32_dwio_write_bcr,
	.read_rap	= pcnet32_dwio_read_rap,
	.write_rap	= pcnet32_dwio_write_rap,
	.reset		= pcnet32_dwio_reset,
};

static int
pcnet32_mdio_read ( struct net_device *netdev, int phy, int reg )
{
	struct pcnet32_private *priv = netdev->priv;
	unsigned long ioaddr = priv->pci_dev->ioaddr;
	u16 val_out;

	if ( ! priv->mii )
		return 0;

	/* First, select PHY chip and the register we want to read */
	priv->a->write_bcr ( ioaddr, 33,
		( ( phy & 0x1f ) << 5 ) | ( reg & 0x1f ) );

	/* Read the selected register's value */
	val_out = priv->a->read_bcr ( ioaddr, 34 );

	return val_out;
}

static void
__unused pcnet32_mdio_write ( struct net_device *netdev, int phy, int reg, int val )
{
	struct pcnet32_private *priv = netdev->priv;
	unsigned long ioaddr = priv->pci_dev->ioaddr;

	if ( ! priv->mii )
		return;

	/* First, select PHY chip and the register we want to write to */
	priv->a->write_bcr ( ioaddr, 33,
		( ( phy & 0x1f ) << 5 ) | ( reg & 0x1f ) );

	/* Write val to the selected register */
	priv->a->write_bcr ( ioaddr, 34, val );
}


/**
 * pcnet32_refill_rx_ring - Allocates iobufs for every Rx descriptor
 * that doesn't have one and isn't in use by the hardware
 *
 * @v priv	Driver private structure
 */
static void
pcnet32_refill_rx_ring ( struct pcnet32_private *priv )
{
	struct pcnet32_rx_desc *rx_curr_desc;
	u16 status;
	int i;

	DBGP ( "pcnet32_refill_rx_ring\n" );

	for ( i = 0; i < RX_RING_SIZE; i++ ) {
		rx_curr_desc = priv->rx_base + i;

		status = le16_to_cpu ( rx_curr_desc->status );

		/* Don't touch descriptors owned by the hardware */
		if ( status & DescOwn )
			continue;

		/* Descriptors with iobufs still need to be processed */
		if ( priv->rx_iobuf[i] != NULL )
			continue;

		/* If alloc_iob fails, try again later (next poll) */
		if ( ! ( priv->rx_iobuf[i] = alloc_iob ( PKT_BUF_SIZE ) ) ) {
			DBG ( "Refill rx ring failed\n" );
			break;
		}

		rx_curr_desc->base =
			cpu_to_le32 ( virt_to_bus ( priv->rx_iobuf[i]->data ) );
		rx_curr_desc->buf_length = cpu_to_le16 ( -PKT_BUF_SIZE );
		rx_curr_desc->msg_length = rx_curr_desc->reserved = 0;

		/* Owner changes after the other status fields are set */
		wmb();
		rx_curr_desc->status = cpu_to_le16 ( DescOwn );
	}

}

/**
 * pcnet32_setup_rx_resources - allocate Rx resources (Descriptors)
 *
 * @v priv	Driver private structure
 *
 * @ret rc	Returns 0 on success, negative on failure
 */
static int
pcnet32_setup_rx_resources ( struct pcnet32_private *priv )
{
	DBGP ( "pcnet32_setup_rx_resources\n" );

	priv->rx_base = malloc_dma ( RX_RING_BYTES, RX_RING_ALIGN );

	DBG ( "priv->rx_base = %#08lx\n", virt_to_bus ( priv->rx_base ) );

	if ( ! priv->rx_base ) {
		return -ENOMEM;
	}

	memset ( priv->rx_base, 0, RX_RING_BYTES );

	pcnet32_refill_rx_ring ( priv );

	priv->rx_curr = 0;

	return 0;
}

static void
pcnet32_free_rx_resources ( struct pcnet32_private *priv )
{
	int i;

	DBGP ( "pcnet32_free_rx_resources\n" );

	free_dma ( priv->rx_base, RX_RING_BYTES );

	for ( i = 0; i < RX_RING_SIZE; i++ ) {
		free_iob ( priv->rx_iobuf[i] );
		priv->rx_iobuf[i] = NULL;
	}
}

/**
 * pcnet32_setup_tx_resources - allocate Tx resources (Descriptors)
 *
 * @v priv	Driver private structure
 *
 * @ret rc	Returns 0 on success, negative on failure
 */
static int
pcnet32_setup_tx_resources ( struct pcnet32_private *priv )
{
	DBGP ( "pcnet32_setup_tx_resources\n" );

	priv->tx_base = malloc_dma ( TX_RING_BYTES, TX_RING_ALIGN );

	if ( ! priv->tx_base ) {
		return -ENOMEM;
	}

	memset ( priv->tx_base, 0, TX_RING_BYTES );

	DBG ( "priv->tx_base = %#08lx\n", virt_to_bus ( priv->tx_base ) );

	priv->tx_curr = 0;
	priv->tx_fill_ctr = 0;
	priv->tx_tail = 0;

	return 0;
}

static void
pcnet32_free_tx_resources ( struct pcnet32_private *priv )
{
	DBGP ( "pcnet32_free_tx_resources\n" );

	free_dma ( priv->tx_base, TX_RING_BYTES );
}

static int
pcnet32_chip_detect ( struct pcnet32_private *priv )
{
	int fdx, mii, fset;
	int media;
	int rc;
	unsigned long ioaddr;
	struct pcnet32_access *a;
	int chip_version;
	char *chipname;

	ioaddr = priv->pci_dev->ioaddr;
	a = priv->a;

	chip_version = a->read_csr ( ioaddr, 88 )
		| ( a->read_csr ( ioaddr, 89 ) << 16 );

	rc = -ENODEV;

	DBG ( "PCnet chip version is 0x%X\n", chip_version );
	if ( ( chip_version & 0xfff ) != 0x003 )
		goto err_unsupported;

	fdx = mii = fset = 0;
	chip_version = ( chip_version >> 12 ) & 0xffff;

	switch (chip_version) {
	case 0x2420:
		chipname = "PCnet/PCI 79C970";
		break;
	case 0x2430:
		/* 970 gives the wrong chip id back */
		chipname = "PCnet/PCI 79C970";
		break;
	case 0x2621:
		chipname = "PCnet/PCI II 79C970A";
		fdx = 1;
		break;
	case 0x2623:
		chipname = "PCnet/FAST 79C971";
		fdx = 1;
		mii = 1;
		fset = 1;
		break;
	case 0x2624:
		chipname = "PCnet/FAST+ 79C972";
		fdx = 1;
		mii = 1;
		fset = 1;
		break;
	case 0x2625:
		chipname = "PCnet/FAST III 79C973";
		fdx = 1;
		mii = 1;
		break;
	case 0x2626:
		chipname = "PCnet/Home 79C978";
		fdx = 1;
		/*
		 * This is based on specs published at www.amd.com. This section
		 * assumes that a NIC with a 79C978 wants to go into 1Mb HomePNA
		 * mode. The 79C978 can also go into standard ethernet, and
		 * there probably should be some sort of module option to select
		 * the mode by which the card should operate
		 */
		/* switch to home wiring mode */
		media = a->read_bcr(ioaddr, 49);

		DBG ( "media reset to %#x.\n", media );
		a->write_bcr(ioaddr, 49, media);
		break;
	case 0x2627:
		chipname = "PCnet/FAST III 79C975";
		fdx = 1;
		mii = 1;
		break;
	case 0x2628:
		chipname = "PCnet/PRO 79C976";
		fdx = 1;
		mii = 1;
		break;
	default:
		chipname = "UNKNOWN";
		DBG ( "PCnet version %#x, no PCnet32 chip.\n", chip_version );
		goto err_unsupported;
	}

	DBG ( "PCnet chipname %s\n", chipname );

	/*
	 * On selected chips turn on the BCR18:NOUFLO bit. This stops transmit
	 * starting until the packet is loaded. Strike one for reliability, lose
	 * one for latency - although on PCI this isn't a big loss. Older chips
	 * have FIFO's smaller than a packet, so you can't do this.
	 * Turn on BCR18:BurstRdEn and BCR18:BurstWrEn.
	 */
	if (fset) {
		a->write_bcr ( ioaddr, 18,
			( a->read_bcr ( ioaddr, 18 ) | 0x0860 ) );
		a->write_csr ( ioaddr, 80,
			( a->read_csr ( ioaddr, 80 ) & 0x0C00) | 0x0C00 );
	}

	priv->full_duplex = fdx;
	priv->mii = mii;

	return 0;

err_unsupported:
	return rc;
}

/**
 * pcnet32_set_ops - Determines the ops used to access the registers
 *
 * @v priv	Driver private structure
 *
 * @ret rc	Returns 0 on success, negative on failure
 */
static int
pcnet32_set_ops ( struct pcnet32_private *priv )
{
	int rc;
	unsigned long ioaddr;

	ioaddr = priv->pci_dev->ioaddr;

	/* Check if CSR0 has its default value and perform a write / read
	   in the RAP register to see if it works. Based on these results
	   determine what mode the NIC is in (WIO / DWIO)
	 */
	rc = -ENODEV;

	if ( pcnet32_wio_read_csr ( ioaddr, 0 ) == 4 &&
	     pcnet32_wio_check ( ioaddr ) ) {
		priv->a = &pcnet32_wio;
	} else {
		pcnet32_dwio_reset ( ioaddr );
		if ( pcnet32_dwio_read_csr ( ioaddr, 0 ) == 4 &&
		     pcnet32_dwio_check ( ioaddr ) ) {
			priv->a = &pcnet32_dwio;
		} else {
			goto err_unsupported;
		}
	}

	return 0;

err_unsupported:
	return rc;
}

/**
 * pcnet32_setup_init_block - setup the NICs initialization block
 *
 * @v priv	Driver private structure
 *
 * @ret rc	Returns 0 on success, negative on failure
 */
static void
pcnet32_setup_init_block ( struct pcnet32_private *priv )
{
	int i;

	/* Configure the network port based on what we've established so far */
	priv->init_block.mode =
		cpu_to_le16 ( ( priv->options & PCNET32_PORT_PORTSEL ) << 7 );

	/* Setup RLEN and TLEN fields */
	priv->init_block.tlen_rlen =
		cpu_to_le16 ( ( PCNET32_LOG_RX_BUFFERS << 4 ) |
			      ( PCNET32_LOG_TX_BUFFERS << 12 ) );

	/* Fill in physical address */
	for ( i = 0; i < ETH_ALEN; i++)
		priv->init_block.phys_addr[i] = priv->netdev->hw_addr[i];

	/* No multicasting scheme, accept everything */
	priv->init_block.filter[0] = 0xffffffff;
	priv->init_block.filter[1] = 0xffffffff;

	priv->init_block.rx_ring =
		cpu_to_le32 ( virt_to_bus ( priv->rx_base ) );
	priv->init_block.tx_ring =
		cpu_to_le32 ( virt_to_bus ( priv->tx_base ) );

	/* Make sure all changes are visible */
	wmb();
}

/**
 * pcnet32_setup_probe_phy - go through all PHYs and see which one is present
 *
 * @v priv	Driver private structure
 */
static void
pcnet32_setup_probe_phy ( struct pcnet32_private *priv )
{
	unsigned long ioaddr = priv->pci_dev->ioaddr;
	unsigned int phycount = 0;
	int phy_id;
	int i;

	if ( priv->mii ) {
		phy_id = ( ( priv->a->read_bcr ( ioaddr, 33 ) ) >> 5 ) & 0x1f;
		for ( i = 0; i < PCNET32_MAX_PHYS; i++ ) {
			unsigned short id1, id2;
			id1 = pcnet32_mdio_read ( priv->netdev, i, MII_PHYSID1 );
			if ( id1 == 0xffff )
				continue;
			id2 = pcnet32_mdio_read ( priv->netdev, i, MII_PHYSID2 );
			if ( id2 == 0xffff )
				continue;
			if ( i == 31 && ( ( priv->chip_version + 1 ) & 0xfffe ) == 0x2624 )
				continue;

			phycount++;
			phy_id = i;
		}
		priv->a->write_bcr ( ioaddr, 33, phy_id << 5 );
		if ( phycount > 1 )
			priv->options |= PCNET32_PORT_MII;
	}
}

/**
 * pcnet32_setup_mac_addr - check for inconsistency between CSR12-14
 * and PROM addresses
 *
 * @v priv	Driver private structure
 */
static int
pcnet32_setup_mac_addr ( struct pcnet32_private *priv )
{
	int i;
	u8 promaddr[ETH_ALEN];
	unsigned long ioaddr = priv->pci_dev->ioaddr;

	/* In most chips, after a chip reset, the ethernet address is read from
	 * the station address PROM at the base address and programmed into the
	 * "Physical Address Registers" CSR12-14.
	 * As a precautionary measure, we read the PROM values and complain if
	 * they disagree with the CSRs.  If they miscompare, and the PROM addr
	 * is valid, then the PROM addr is used.
	 */
	for ( i = 0; i < 3; i++ ) {
		unsigned int val;
		val = priv->a->read_csr ( ioaddr, i + 12 ) & 0x0ffff;
		/* There may be endianness issues here. */
		priv->netdev->hw_addr[2 * i] = val & 0x0ff;
		priv->netdev->hw_addr[2 * i + 1] = ( val >> 8 ) & 0x0ff;
	}

	for ( i = 0; i < ETH_ALEN; i++ )
		promaddr[i] = inb ( ioaddr + i );

	if ( memcmp ( promaddr, priv->netdev->hw_addr, ETH_ALEN ) ||
	     ! is_valid_ether_addr ( priv->netdev->hw_addr ) ) {
		if ( is_valid_ether_addr ( promaddr ) ) {
			DBG ( "CSR address is invalid, using PROM addr\n" );
			memcpy ( priv->netdev->hw_addr, promaddr, ETH_ALEN );
		}
	}

	/* If ethernet address is not valid, return error */
	if ( ! is_valid_ether_addr ( priv->netdev->hw_addr ) )
		return -EADDRNOTAVAIL;

	return 0;
}

/**
 * pcnet32_setup_if_duplex - Sets the NICs used interface and duplex mode
 *
 * @v priv	Driver private structure
 */
static void
pcnet32_setup_if_duplex ( struct pcnet32_private *priv )
{
	unsigned long ioaddr = priv->pci_dev->ioaddr;
	u16 val;

	/* Set/Reset autoselect bit */
	val = priv->a->read_bcr ( ioaddr, 2 ) & ~2;
	if ( priv->options & PCNET32_PORT_ASEL )
		val |= 2;
	priv->a->write_bcr ( ioaddr, 2, val );

	/* Handle full duplex setting */
	if ( priv->full_duplex ) {
		val = priv->a->read_bcr ( ioaddr, 9 ) & ~3;
		if ( priv->options & PCNET32_PORT_FD ) {
			val |= 1;
			if ( priv->options == ( PCNET32_PORT_FD | PCNET32_PORT_AUI ) )
				val |= 2;
		} else if ( priv->options & PCNET32_PORT_ASEL ) {
			/* Workaround of xSeries 250, on for 79C975 only */
			if ( priv->chip_version == 0x2627 )
				val |= 3;
		}
		priv->a->write_bcr ( ioaddr, 9, val );
	}

	/* Set/Reset GPSI bit in test register */
	val = priv->a->read_csr ( ioaddr, 124 ) & ~0x10;
	if ( ( priv->options & PCNET32_PORT_PORTSEL ) == PCNET32_PORT_GPSI )
		val |= 0x10;
	priv->a->write_bcr ( ioaddr, 124, val );

	/* Allied Telesyn AT are 100Mbit only and do not negotiate */
	u16 subsys_vend_id, subsys_dev_id;
	pci_read_config_word ( priv->pci_dev,
			       PCI_SUBSYSTEM_VENDOR_ID,
			       &subsys_vend_id );
	pci_read_config_word ( priv->pci_dev,
			       PCI_SUBSYSTEM_ID,
			       &subsys_dev_id );
	if ( subsys_vend_id == PCI_VENDOR_ID_AT &&
	     ( ( subsys_dev_id == PCI_SUBDEVICE_ID_AT_2700FX ) ||
	       ( subsys_dev_id == PCI_SUBDEVICE_ID_AT_2701FX ) ) ) {
		priv->options = PCNET32_PORT_FD | PCNET32_PORT_100;
	}

	if ( priv->mii && ! ( priv->options & PCNET32_PORT_ASEL ) ) {
		/* Disable Auto Negotiation, set 10Mbps, HD */
		val = priv->a->read_bcr ( ioaddr, 32 ) & ~0x38;
		if ( priv->options & PCNET32_PORT_FD )
			val |= 0x10;
		if ( priv->options & PCNET32_PORT_100 )
			val |= 0x08;
		priv->a->write_bcr ( ioaddr, 32, val );
	} else if ( priv->options & PCNET32_PORT_ASEL ) {
		/* 79C970 chips do not have the BCR32 register */
		if ( ( priv->chip_version != 0x2420 ) &&
		     ( priv->chip_version != 0x2621 ) ) {
			/* Enable Auto Negotiation, setup, disable FD */
			val = priv->a->read_bcr ( ioaddr, 32 ) & ~0x98;
			val |= 0x20;
			priv->a->write_bcr ( ioaddr, 32, val );
		}
	}
}

/**
 * pcnet32_hw_start - Starts up the NIC
 *
 * @v priv	Driver private structure
 */
static void
pcnet32_hw_start ( struct pcnet32_private *priv )
{
	unsigned long ioaddr = priv->pci_dev->ioaddr;
	int i;

	/* Begin initialization procedure */
	priv->a->write_csr ( ioaddr, 0, Init );

	/* Wait for the initialization to be done */
	i = 0;
	while ( i++ < 100 )
		if ( priv->a->read_csr ( ioaddr, 0 ) & InitDone )
			break;

	/* Start the chip */
	priv->a->write_csr ( ioaddr, 0, Strt );
}

/**
 * open - Called when a network interface is made active
 *
 * @v netdev	Network device
 * @ret rc	Return status code, 0 on success, negative value on failure
 **/
static int
pcnet32_open ( struct net_device *netdev )
{
	struct pcnet32_private *priv = netdev_priv ( netdev );
	unsigned long ioaddr = priv->pci_dev->ioaddr;
	int rc;
	u16 val;

	/* Setup TX and RX descriptors */
	if ( ( rc = pcnet32_setup_tx_resources ( priv ) ) != 0 ) {
		DBG ( "Error setting up TX resources\n" );
		goto err_setup_tx;
	}

	if ( ( rc = pcnet32_setup_rx_resources ( priv ) ) != 0 ) {
		DBG ( "Error setting up RX resources\n" );
		goto err_setup_rx;
	}

	/* Reset the chip */
	priv->a->reset ( ioaddr );

	/* Switch pcnet32 to 32bit mode */
	priv->a->write_bcr ( ioaddr, 20, PCNET32_SWSTYLE_PCNET32 );

	/* Setup the interface and duplex mode */
	pcnet32_setup_if_duplex ( priv );

	/* Disable interrupts */
	val = priv->a->read_csr ( ioaddr, 3 );
	val |= BablMask | MissFrameMask | RxIntMask | TxIntMask | InitDoneMask;
	priv->a->write_csr ( ioaddr, 3, val );

	/* Setup initialization block */
	pcnet32_setup_init_block ( priv );

	/* Fill in the address of the initialization block */
	priv->a->write_csr ( ioaddr, 1,
		( virt_to_bus ( &priv->init_block ) ) & 0xffff );
	priv->a->write_csr ( ioaddr, 2,
		( virt_to_bus ( &priv->init_block ) ) >> 16 );

	/* Enable Auto-Pad, disable interrupts */
	priv->a->write_csr ( ioaddr, 4, 0x0915 );

	pcnet32_hw_start ( priv );

	return 0;

err_setup_rx:
	pcnet32_free_tx_resources ( priv );
err_setup_tx:
	priv->a->reset( priv->pci_dev->ioaddr );
	return rc;
}

/**
 * transmit - Transmit a packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 *
 * @ret rc	Returns 0 on success, negative on failure
 */
static int
pcnet32_transmit ( struct net_device *netdev, struct io_buffer *iobuf )
{
	struct pcnet32_private *priv = netdev_priv ( netdev );
	unsigned long ioaddr = priv->pci_dev->ioaddr;
	uint32_t tx_len = iob_len ( iobuf );
	struct pcnet32_tx_desc *tx_curr_desc;

	DBGP ( "pcnet32_transmit\n" );

	if ( priv->tx_fill_ctr == TX_RING_SIZE ) {
		DBG ( "Tx overflow\n" );
		return -ENOTSUP;
	}

	priv->tx_iobuf[priv->tx_curr] = iobuf;

	tx_curr_desc = priv->tx_base + priv->tx_curr;

	/* Configure current descriptor to transmit packet */
	tx_curr_desc->length = cpu_to_le16 ( -tx_len );
	tx_curr_desc->misc = 0x00000000;
	tx_curr_desc->base = cpu_to_le32 ( virt_to_bus ( iobuf->data ) );

	/* Owner changes after the other status fields are set */
	wmb();
	tx_curr_desc->status =
		cpu_to_le16 ( DescOwn | StartOfPacket | EndOfPacket );

	/* Trigger an immediate send poll */
	priv->a->write_csr ( ioaddr, 0,
		( priv->irq_enabled ? IntEnable : 0 ) | TxDemand );

	/* Point to the next free descriptor */
	priv->tx_curr = ( priv->tx_curr + 1 ) % TX_RING_SIZE;

	/* Increment number of tx descriptors in use */
	priv->tx_fill_ctr++;

	return 0;
}

/**
 * pcnet32_process_tx_packets - Checks for successfully sent packets,
 * reports them to iPXE with netdev_tx_complete()
 *
 * @v netdev	Network device
 */
static void
pcnet32_process_tx_packets ( struct net_device *netdev )
{
	struct pcnet32_private *priv = netdev_priv ( netdev );
	struct pcnet32_tx_desc *tx_curr_desc;

	DBGP ( "pcnet32_process_tx_packets\n" );

	while ( priv->tx_tail != priv->tx_curr ) {
		tx_curr_desc = priv->tx_base + priv->tx_tail;

		u16 status = le16_to_cpu ( tx_curr_desc->status );

		DBG ( "Before OWN bit check, status: %#08x\n", status );

		/* Skip this descriptor if hardware still owns it */
		if ( status & DescOwn )
			break;

		DBG ( "Transmitted packet.\n" );
		DBG ( "priv->tx_fill_ctr= %d\n", priv->tx_fill_ctr );
		DBG ( "priv->tx_tail	= %d\n", priv->tx_tail );
		DBG ( "priv->tx_curr	= %d\n", priv->tx_curr );
		DBG ( "tx_curr_desc	= %#08lx\n", virt_to_bus ( tx_curr_desc ) );

		/* This packet is ready for completion */
		netdev_tx_complete ( netdev, priv->tx_iobuf[priv->tx_tail]);

		/* Clear the descriptor */
		memset ( tx_curr_desc, 0, sizeof(*tx_curr_desc) );

		/* Reduce the number of tx descriptors in use */
		priv->tx_fill_ctr--;

		/* Go to next available descriptor */
		priv->tx_tail = ( priv->tx_tail + 1 ) % TX_RING_SIZE;
	}
}

/**
 * pcnet32_process_rx_packets - Checks for received packets, reports them
 * to iPXE with netdev_rx() or netdev_rx_err() if there was an error receiving
 * the packet
 *
 * @v netdev	Network device
 */
static void
pcnet32_process_rx_packets ( struct net_device *netdev )
{
	struct pcnet32_private *priv = netdev_priv ( netdev );
	struct pcnet32_rx_desc *rx_curr_desc;
	u16 status;
	u32 len;
	int i;

	DBGP ( "pcnet32_process_rx_packets\n" );

	for ( i = 0; i < RX_RING_SIZE; i++ ) {
		rx_curr_desc = priv->rx_base + priv->rx_curr;

		status = le16_to_cpu ( rx_curr_desc->status );
		rmb();

		DBG ( "Before OWN bit check, status: %#08x\n", status );

		/* Skip this descriptor if hardware still owns it */
		if ( status & DescOwn )
			break;

		/* We own the descriptor, but it has not been refilled yet */
		if ( priv->rx_iobuf[priv->rx_curr] == NULL )
			break;

		DBG ( "Received packet.\n" );
		DBG ( "priv->rx_curr	= %d\n", priv->rx_curr );
		DBG ( "rx_len		= %d\n",
		      ( le32_to_cpu ( rx_curr_desc->msg_length ) & 0xfff ) - 4 );
		DBG ( "rx_curr_desc	= %#08lx\n",
		      virt_to_bus ( rx_curr_desc ) );

		/* Check ERR bit */
		if ( status & 0x4000 ) {
			netdev_rx_err ( netdev, priv->rx_iobuf[priv->rx_curr],
					-EINVAL );
			DBG ( "Corrupted packet received!\n");
		} else {
			/* Adjust size of the iobuf to reflect received data */
			len = ( le32_to_cpu ( rx_curr_desc->msg_length ) & 0xfff ) - 4;
			iob_put ( priv->rx_iobuf[priv->rx_curr], len );

			/* Add this packet to the receive queue */
			netdev_rx ( netdev, priv->rx_iobuf[priv->rx_curr] );
		}

		/* Invalidate iobuf and descriptor */
		priv->rx_iobuf[priv->rx_curr] = NULL;
		memset ( rx_curr_desc, 0, sizeof(*rx_curr_desc) );

		/* Point to the next free descriptor */
		priv->rx_curr = ( priv->rx_curr + 1 ) % RX_RING_SIZE;
	}

	/* Allocate new iobufs where needed */
	pcnet32_refill_rx_ring ( priv );
}

/**
 * poll - Poll for received packets
 *
 * @v netdev	Network device
 */
static void
pcnet32_poll ( struct net_device *netdev )
{
	struct pcnet32_private *priv = netdev_priv ( netdev );
	unsigned long ioaddr = priv->pci_dev->ioaddr;
	u16 status;

	DBGP ( "pcnet32_poll\n" );

	status = priv->a->read_csr ( ioaddr, 0 );

	/* Clear interrupts */
	priv->a->write_csr ( ioaddr, 0, status );

	DBG ( "pcnet32_poll: mask = %#04x, status = %#04x\n",
		priv->a->read_csr ( ioaddr, 3 ), status );

	/* Return when RINT or TINT are not set */
	if ( ( status & 0x0500 ) == 0x0000 )
		return;

	/* Process transmitted packets */
	pcnet32_process_tx_packets ( netdev );

	/* Process received packets */
	pcnet32_process_rx_packets ( netdev );
}

/**
 * close - Disable network interface
 *
 * @v netdev	network interface device structure
 **/
static void
pcnet32_close ( struct net_device *netdev )
{
	struct pcnet32_private *priv = netdev_priv ( netdev );
	unsigned long ioaddr = priv->pci_dev->ioaddr;

	DBGP ( "pcnet32_close\n" );

	/* Reset the chip */
	pcnet32_wio_reset ( ioaddr );

	/* Stop the PCNET32 - it occasionally polls memory if we don't */
	priv->a->write_csr ( ioaddr, 0, Stop );

	/* Switch back to 16bit mode to avoid problems with dumb
	 * DOS packet driver after a warm reboot */
	priv->a->write_bcr ( ioaddr, 20, PCNET32_SWSTYLE_LANCE );

	pcnet32_free_rx_resources ( priv );
	pcnet32_free_tx_resources ( priv );
}

static void pcnet32_irq_enable ( struct pcnet32_private *priv )
{
	unsigned long ioaddr = priv->pci_dev->ioaddr;
	u16 val;

	DBGP ( "pcnet32_irq_enable\n" );

	/* Enable TINT and RINT masks */
	val = priv->a->read_csr ( ioaddr, 3 );
	val &= ~( RxIntMask | TxIntMask );
	priv->a->write_csr ( ioaddr, 3, val );

	/* Enable interrupts */
	priv->a->write_csr ( ioaddr, 0, IntEnable );

	priv->irq_enabled = 1;
}

static void pcnet32_irq_disable ( struct pcnet32_private *priv )
{
	unsigned long ioaddr = priv->pci_dev->ioaddr;

	DBGP ( "pcnet32_irq_disable\n" );

	priv->a->write_csr ( ioaddr, 0, 0x0000 );

	priv->irq_enabled = 0;
}

/**
 * irq - enable or disable interrupts
 *
 * @v netdev    network adapter
 * @v action    requested interrupt action
 **/
static void
pcnet32_irq ( struct net_device *netdev, int action )
{
	struct pcnet32_private *priv = netdev_priv ( netdev );

	DBGP ( "pcnet32_irq\n" );

	switch ( action ) {
	case 0:
		pcnet32_irq_disable ( priv );
		break;
	default:
		pcnet32_irq_enable ( priv );
		break;
	}
}

static struct net_device_operations pcnet32_operations = {
	.open		= pcnet32_open,
	.transmit	= pcnet32_transmit,
	.poll		= pcnet32_poll,
	.close		= pcnet32_close,
	.irq		= pcnet32_irq,
};

/**
 * probe - Initial configuration of NIC
 *
 * @v pdev	PCI device
 * @v ent	PCI IDs
 *
 * @ret rc	Return status code
 **/
static int
pcnet32_probe ( struct pci_device *pdev )
{
	struct net_device *netdev;
	struct pcnet32_private *priv;
	unsigned long ioaddr;
	int rc;

	DBGP ( "pcnet32_probe\n" );

	DBG ( "Found %s, vendor = %#04x, device = %#04x\n",
		pdev->id->name, pdev->id->vendor, pdev->id->device );

	/* Allocate our private data */
	netdev = alloc_etherdev ( sizeof ( *priv ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc_etherdev;
	}

	/* Link our operations to the netdev struct */
	netdev_init ( netdev, &pcnet32_operations );

	/* Link the PCI device to the netdev struct */
	pci_set_drvdata ( pdev, netdev );
	netdev->dev = &pdev->dev;

	/* Get a reference to our private data */
	priv = netdev_priv ( netdev );

	/* We'll need these set up for the rest of the routines */
	priv->pci_dev = pdev;
	priv->netdev = netdev;

	ioaddr = pdev->ioaddr;

	/* Only use irqs under UNDI */
	priv->irq_enabled = 0;

	/* Reset the chip */
	pcnet32_wio_reset ( ioaddr );

	if ( ( rc = pcnet32_set_ops ( priv ) ) != 0 ) {
		DBG ( "Setting driver operations failed\n");
		goto err_set_ops;
	}

	if ( ( rc = pcnet32_chip_detect ( priv ) ) != 0 ) {
		DBG ( "pcnet32_chip_detect failed\n" );
		goto err_chip_detect;
	}

	/* Enter bus mastering mode */
	adjust_pci_device ( pdev );

	/* Verify and get MAC address */
	if ( ( rc = pcnet32_setup_mac_addr ( priv ) ) != 0 ) {
		DBG ( "Setting MAC address failed\n" );
		goto err_mac_addr;
	}

	DBG ( "IO Addr 0x%lX, MAC Addr %s\n", ioaddr,
		eth_ntoa ( netdev->hw_addr ) );

	priv->options = PCNET32_PORT_ASEL;

	/* Detect special T1/E1 WAN card by checking for MAC address */
	if ( netdev->hw_addr[0] == 0x00 &&
	     netdev->hw_addr[1] == 0xE0 &&
	     netdev->hw_addr[2] == 0x75 )
		priv->options = PCNET32_PORT_FD | PCNET32_PORT_GPSI;

	/* Probe the PHY so we can check link state and speed */
	pcnet32_setup_probe_phy ( priv );

	if ( ( rc = register_netdev ( netdev ) ) != 0 ) {
		DBG ( "Error registering netdev\n" );
		goto err_register;
	}

	netdev_link_up ( netdev );

	return 0;

err_register:
	netdev_put ( netdev );
err_chip_detect:
err_set_ops:
err_alloc_etherdev:
err_mac_addr:
	return rc;
}

/**
 * remove - Device Removal Routine
 *
 * @v pdev PCI device information struct
 **/
static void
pcnet32_remove ( struct pci_device *pdev )
{
	struct net_device *netdev = pci_get_drvdata ( pdev );
	unsigned long ioaddr = pdev->ioaddr;

	DBGP ( "pcnet32_remove\n" );

	/* Reset the chip */
	pcnet32_wio_reset ( ioaddr );

	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

static struct pci_device_id pcnet32_nics[] = {
	PCI_ROM(0x1022, 0x2000, "pcnet32", "AMD PCnet/PCI", 0),
	PCI_ROM(0x1022, 0x2625, "pcnetfastiii", "AMD PCNet FAST III", 0),
	PCI_ROM(0x1022, 0x2001, "amdhomepna", "AMD PCnet/HomePNA", 0),
};

struct pci_driver pcnet32_driver __pci_driver = {
	.ids		= pcnet32_nics,
	.id_count	= ARRAY_SIZE ( pcnet32_nics ),
	.probe		= pcnet32_probe,
	.remove		= pcnet32_remove,
};
