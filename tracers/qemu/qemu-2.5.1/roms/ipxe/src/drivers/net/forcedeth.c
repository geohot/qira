/*
 *    forcedeth.c -- Driver for NVIDIA nForce media access controllers for iPXE
 *    Copyright (c) 2010 Andrei Faur <da3drus@gmail.com>
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License as
 *    published by the Free Software Foundation; either version 2 of the
 *    License, or any later version.
 *
 *    This program is distributed in the hope that it will be useful, but
 *    WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *    02110-1301, USA.
 *
 * Portions of this code are taken from the Linux forcedeth driver that was
 * based on a cleanroom reimplementation which was based on reverse engineered
 * documentation written by Carl-Daniel Hailfinger and Andrew de Quincey:
 * Copyright (C) 2003,4,5 Manfred Spraul
 * Copyright (C) 2004 Andrew de Quincey (wol support)
 * Copyright (C) 2004 Carl-Daniel Hailfinger (invalid MAC handling, insane
 *		IRQ rate fixes, bigendian fixes, cleanups, verification)
 * Copyright (c) 2004,2005,2006,2007,2008,2009 NVIDIA Corporation
 *
 * The probe, remove, open and close functions, along with the functions they
 * call, are direct copies of the above mentioned driver, modified where
 * necessary to make them work for iPXE.
 *
 * The poll and transmit functions were completely rewritten to make use of
 * the iPXE API. This process was aided by constant referencing of the above
 * mentioned Linux driver. This driver would not have been possible without this
 * prior work.
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
#include <ipxe/crypto.h>
#include <ipxe/pci.h>
#include <ipxe/timer.h>
#include <mii.h>
#include "forcedeth.h"

static inline void pci_push ( void *ioaddr )
{
	/* force out pending posted writes */
	wmb();
	readl ( ioaddr );
}

static int
reg_delay ( struct forcedeth_private *priv, int offset, u32 mask,
	    u32 target, int delay, int delaymax, const char *msg )
{
	void *ioaddr = priv->mmio_addr;

	pci_push ( ioaddr );
	do {
		udelay ( delay );
		delaymax -= delay;
		if ( delaymax < 0 ) {
			if ( msg )
				DBG ( "%s\n", msg );
			return 1;
		}
	} while ( ( readl ( ioaddr + offset ) & mask ) != target );

	return 0;
}

/* read/write a register on the PHY */
static int
mii_rw ( struct forcedeth_private *priv, int addr, int miireg, int value )
{
	void *ioaddr = priv->mmio_addr;
	u32 reg;
	int retval;

	writel ( NVREG_MIISTAT_MASK_RW, ioaddr + NvRegMIIStatus );

	reg = readl ( ioaddr + NvRegMIIControl );
	if ( reg & NVREG_MIICTL_INUSE ) {
		writel ( NVREG_MIICTL_INUSE, ioaddr + NvRegMIIControl );
		udelay ( NV_MIIBUSY_DELAY );
	}

	reg = ( addr << NVREG_MIICTL_ADDRSHIFT ) | miireg;
	if ( value != MII_READ ) {
		writel ( value, ioaddr + NvRegMIIData );
		reg |= NVREG_MIICTL_WRITE;
	}
	writel ( reg, ioaddr + NvRegMIIControl );

	if ( reg_delay ( priv, NvRegMIIControl, NVREG_MIICTL_INUSE, 0,
			NV_MIIPHY_DELAY, NV_MIIPHY_DELAYMAX, NULL ) ) {
		DBG ( "mii_rw of reg %d at PHY %d timed out.\n",
			miireg, addr );
		retval = -1;
	} else if ( value != MII_READ ) {
		/* it was a write operation - fewer failures are detectable */
		DBG ( "mii_rw wrote 0x%x to reg %d at PHY %d\n",
			value, miireg, addr );
		retval = 0;
	} else if ( readl ( ioaddr + NvRegMIIStatus ) & NVREG_MIISTAT_ERROR ) {
		DBG ( "mii_rw of reg %d at PHY %d failed.\n",
			miireg, addr );
		retval = -1;
	} else {
		retval = readl ( ioaddr + NvRegMIIData );
		DBG ( "mii_rw read from reg %d at PHY %d: 0x%x.\n",
			miireg, addr, retval );
	}

	return retval;
}

static void
nv_txrx_gate ( struct forcedeth_private *priv, int gate )
{
	void *ioaddr = priv->mmio_addr;
	u32 powerstate;

	if ( ! priv->mac_in_use &&
	     ( priv->driver_data & DEV_HAS_POWER_CNTRL ) ) {
		powerstate = readl ( ioaddr + NvRegPowerState2 );
		if ( gate )
			powerstate |= NVREG_POWERSTATE2_GATE_CLOCKS;
		else
			powerstate &= ~NVREG_POWERSTATE2_GATE_CLOCKS;
		writel ( powerstate, ioaddr + NvRegPowerState2 );
	}
}

static void
nv_mac_reset ( struct forcedeth_private * priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 temp1, temp2, temp3;

	writel ( NVREG_TXRXCTL_BIT2 | NVREG_TXRXCTL_RESET | NVREG_TXRXCTL_DESC_1,
		 ioaddr + NvRegTxRxControl );
	pci_push ( ioaddr );

	/* save registers since they will be cleared on reset */
	temp1 = readl ( ioaddr + NvRegMacAddrA );
	temp2 = readl ( ioaddr + NvRegMacAddrB );
	temp3 = readl ( ioaddr + NvRegTransmitPoll );

	writel ( NVREG_MAC_RESET_ASSERT, ioaddr + NvRegMacReset );
	pci_push ( ioaddr );
	udelay ( NV_MAC_RESET_DELAY );
	writel ( 0, ioaddr + NvRegMacReset );
	pci_push ( ioaddr );
	udelay ( NV_MAC_RESET_DELAY );

	/* restore saved registers */
	writel ( temp1, ioaddr + NvRegMacAddrA );
	writel ( temp2, ioaddr + NvRegMacAddrB );
	writel ( temp3, ioaddr + NvRegTransmitPoll );

	writel ( NVREG_TXRXCTL_BIT2 | NVREG_TXRXCTL_DESC_1,
		 ioaddr + NvRegTxRxControl );
	pci_push ( ioaddr );
}

static void
nv_init_tx_ring ( struct forcedeth_private *priv )
{
	int i;

	for ( i = 0; i < TX_RING_SIZE; i++ ) {
		priv->tx_ring[i].flaglen = 0;
		priv->tx_ring[i].buf = 0;
		priv->tx_iobuf[i] = NULL;
	}

	priv->tx_fill_ctr = 0;
	priv->tx_curr = 0;
	priv->tx_tail = 0;
}

/**
 * nv_alloc_rx - Allocates iobufs for every Rx descriptor
 * that doesn't have one and isn't in use by the hardware
 *
 * @v priv	Driver private structure
 */
static void
nv_alloc_rx ( struct forcedeth_private *priv )
{
	struct ring_desc *rx_curr_desc;
	int i;
	u32 status;

	DBGP ( "nv_alloc_rx\n" );

	for ( i = 0; i < RX_RING_SIZE; i++ ) {
		rx_curr_desc = priv->rx_ring + i;
		status = le32_to_cpu ( rx_curr_desc->flaglen );

		/* Don't touch the descriptors owned by the hardware */
		if ( status & NV_RX_AVAIL )
			continue;

		/* Descriptors with iobufs still need to be processed */
		if ( priv->rx_iobuf[i] != NULL )
			continue;

		/* If alloc_iob fails, try again later (next poll) */
		if ( ! ( priv->rx_iobuf[i] = alloc_iob ( RX_BUF_SZ ) ) ) {
			DBG ( "Refill rx_ring failed, size %d\n", RX_BUF_SZ );
			break;
		}

		rx_curr_desc->buf =
			cpu_to_le32 ( virt_to_bus ( priv->rx_iobuf[i]->data ) );
		wmb();
		rx_curr_desc->flaglen =
			cpu_to_le32 ( RX_BUF_SZ | NV_RX_AVAIL );
	}
}

static void
nv_init_rx_ring ( struct forcedeth_private *priv )
{
	int i;

	for ( i = 0; i < RX_RING_SIZE; i++ ) {
		priv->rx_ring[i].flaglen = 0;
		priv->rx_ring[i].buf = 0;
		priv->rx_iobuf[i] = NULL;
	}

	priv->rx_curr = 0;
}

/**
 * nv_init_rings - Allocate and intialize descriptor rings
 *
 * @v priv	Driver private structure
 *
 * @ret rc	Return status code
 **/
static int
nv_init_rings ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	int rc = -ENOMEM;

	/* Allocate ring for both TX and RX */
	priv->rx_ring =
		malloc_dma ( sizeof(struct ring_desc) * RXTX_RING_SIZE, 32 );
	if ( ! priv->rx_ring )
		goto err_malloc;
	priv->tx_ring = &priv->rx_ring[RX_RING_SIZE];

	/* Initialize rings */
	nv_init_tx_ring ( priv );
	nv_init_rx_ring ( priv );

	/* Allocate iobufs for RX */
	nv_alloc_rx ( priv );

	/* Give hw rings */
	writel ( cpu_to_le32 ( virt_to_bus ( priv->rx_ring ) ),
		 ioaddr + NvRegRxRingPhysAddr );
	writel ( cpu_to_le32 ( virt_to_bus ( priv->tx_ring ) ),
		 ioaddr + NvRegTxRingPhysAddr );

	DBG ( "RX ring at phys addr: %#08lx\n",
		virt_to_bus ( priv->rx_ring ) );
	DBG ( "TX ring at phys addr: %#08lx\n",
		virt_to_bus ( priv->tx_ring ) );

	writel ( ( ( RX_RING_SIZE - 1 ) << NVREG_RINGSZ_RXSHIFT ) +
		 ( ( TX_RING_SIZE - 1 ) << NVREG_RINGSZ_TXSHIFT ),
		 ioaddr + NvRegRingSizes );

	return 0;

err_malloc:
	DBG ( "Could not allocate descriptor rings\n");
	return rc;
}

static void
nv_free_rxtx_resources ( struct forcedeth_private *priv )
{
	int i;

	DBGP ( "nv_free_rxtx_resources\n" );

	free_dma ( priv->rx_ring, sizeof(struct ring_desc) * RXTX_RING_SIZE );

	for ( i = 0; i < RX_RING_SIZE; i++ ) {
		free_iob ( priv->rx_iobuf[i] );
		priv->rx_iobuf[i] = NULL;
	}
}

static void
nv_txrx_reset ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;

	writel ( NVREG_TXRXCTL_BIT2 | NVREG_TXRXCTL_RESET | NVREG_TXRXCTL_DESC_1,
		 ioaddr + NvRegTxRxControl );
	pci_push ( ioaddr );
	udelay ( NV_TXRX_RESET_DELAY );
	writel ( NVREG_TXRXCTL_BIT2 | NVREG_TXRXCTL_DESC_1,
		 ioaddr + NvRegTxRxControl );
	pci_push ( ioaddr );
}

static void
nv_disable_hw_interrupts ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;

	writel ( 0, ioaddr + NvRegIrqMask );
	pci_push ( ioaddr );
}

static void
nv_enable_hw_interrupts ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;

	writel ( NVREG_IRQMASK_THROUGHPUT, ioaddr + NvRegIrqMask );
}

static void
nv_start_rx ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 rx_ctrl = readl ( ioaddr + NvRegReceiverControl );

	DBGP ( "nv_start_rx\n" );
	/* Already running? Stop it. */
	if ( ( readl ( ioaddr + NvRegReceiverControl ) & NVREG_RCVCTL_START ) && !priv->mac_in_use ) {
		rx_ctrl &= ~NVREG_RCVCTL_START;
		writel ( rx_ctrl, ioaddr + NvRegReceiverControl );
		pci_push ( ioaddr );
	}
	writel ( priv->linkspeed, ioaddr + NvRegLinkSpeed );
	pci_push ( ioaddr );
        rx_ctrl |= NVREG_RCVCTL_START;
        if ( priv->mac_in_use )
		rx_ctrl &= ~NVREG_RCVCTL_RX_PATH_EN;
	writel ( rx_ctrl, ioaddr + NvRegReceiverControl );
	DBG ( "nv_start_rx to duplex %d, speed 0x%08x.\n",
		priv->duplex, priv->linkspeed);
	pci_push ( ioaddr );
}

static void
nv_stop_rx ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 rx_ctrl = readl ( ioaddr + NvRegReceiverControl );

	DBGP ( "nv_stop_rx\n" );
	if ( ! priv->mac_in_use )
		rx_ctrl &= ~NVREG_RCVCTL_START;
	else
		rx_ctrl |= NVREG_RCVCTL_RX_PATH_EN;
	writel ( rx_ctrl, ioaddr + NvRegReceiverControl );
	reg_delay ( priv, NvRegReceiverStatus, NVREG_RCVSTAT_BUSY, 0,
			NV_RXSTOP_DELAY1, NV_RXSTOP_DELAY1MAX,
			"nv_stop_rx: ReceiverStatus remained busy");

	udelay ( NV_RXSTOP_DELAY2 );
	if ( ! priv->mac_in_use )
		writel ( 0, priv + NvRegLinkSpeed );
}

static void
nv_start_tx ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 tx_ctrl = readl ( ioaddr + NvRegTransmitterControl );

	DBGP ( "nv_start_tx\n" );
	tx_ctrl |= NVREG_XMITCTL_START;
	if ( priv->mac_in_use )
		tx_ctrl &= ~NVREG_XMITCTL_TX_PATH_EN;
	writel ( tx_ctrl, ioaddr + NvRegTransmitterControl );
	pci_push ( ioaddr );
}

static void
nv_stop_tx ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 tx_ctrl = readl ( ioaddr + NvRegTransmitterControl );

	DBGP ( "nv_stop_tx");

	if ( ! priv->mac_in_use )
		tx_ctrl &= ~NVREG_XMITCTL_START;
	else
		tx_ctrl |= NVREG_XMITCTL_TX_PATH_EN;
	writel ( tx_ctrl, ioaddr + NvRegTransmitterControl );
	reg_delay ( priv, NvRegTransmitterStatus, NVREG_XMITSTAT_BUSY, 0,
			NV_TXSTOP_DELAY1, NV_TXSTOP_DELAY1MAX,
			"nv_stop_tx: TransmitterStatus remained busy");

	udelay ( NV_TXSTOP_DELAY2 );
	if ( ! priv->mac_in_use )
		writel( readl ( ioaddr + NvRegTransmitPoll) &
				NVREG_TRANSMITPOLL_MAC_ADDR_REV,
			ioaddr + NvRegTransmitPoll);
}


static void
nv_update_pause ( struct forcedeth_private *priv, u32 pause_flags )
{
	void *ioaddr = priv->mmio_addr;

	priv->pause_flags &= ~ ( NV_PAUSEFRAME_TX_ENABLE |
				 NV_PAUSEFRAME_RX_ENABLE );

	if ( priv->pause_flags & NV_PAUSEFRAME_RX_CAPABLE ) {
		u32 pff = readl ( ioaddr + NvRegPacketFilterFlags ) & ~NVREG_PFF_PAUSE_RX;
		if ( pause_flags & NV_PAUSEFRAME_RX_ENABLE ) {
			writel ( pff | NVREG_PFF_PAUSE_RX, ioaddr + NvRegPacketFilterFlags );
			priv->pause_flags |= NV_PAUSEFRAME_RX_ENABLE;
		} else {
			writel ( pff, ioaddr + NvRegPacketFilterFlags );
		}
	}
	if ( priv->pause_flags & NV_PAUSEFRAME_TX_CAPABLE ) {
		u32 regmisc = readl ( ioaddr + NvRegMisc1 ) & ~NVREG_MISC1_PAUSE_TX;
		if ( pause_flags & NV_PAUSEFRAME_TX_ENABLE ) {
			u32 pause_enable = NVREG_TX_PAUSEFRAME_ENABLE_V1;
			if ( priv->driver_data & DEV_HAS_PAUSEFRAME_TX_V2 )
				pause_enable = NVREG_TX_PAUSEFRAME_ENABLE_V2;
			if ( priv->driver_data & DEV_HAS_PAUSEFRAME_TX_V3 ) {
				pause_enable = NVREG_TX_PAUSEFRAME_ENABLE_V3;
				/* limit the number of tx pause frames to a default of 8 */
				writel ( readl ( ioaddr + NvRegTxPauseFrameLimit ) |
						NVREG_TX_PAUSEFRAMELIMIT_ENABLE,
					 ioaddr + NvRegTxPauseFrameLimit );
			}
			writel ( pause_enable, ioaddr + NvRegTxPauseFrame );
			writel ( regmisc | NVREG_MISC1_PAUSE_TX, ioaddr + NvRegMisc1 );
			priv->pause_flags |= NV_PAUSEFRAME_TX_ENABLE;
		} else {
			writel ( NVREG_TX_PAUSEFRAME_DISABLE, ioaddr + NvRegTxPauseFrame );
			writel ( regmisc, ioaddr + NvRegMisc1 );
		}
	}
}

static int
nv_update_linkspeed ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	int adv = 0;
	int lpa = 0;
	int adv_lpa, adv_pause, lpa_pause;
	u32 newls = priv->linkspeed;
	int newdup = priv->duplex;
	int mii_status;
	int retval = 0;
	u32 control_1000, status_1000, phyreg, pause_flags, txreg;
	u32 txrxFlags = 0;
	u32 phy_exp;

	/* BMSR_LSTATUS is latched, read it twice:
	 * we want the current value.
	 */
	mii_rw ( priv, priv->phyaddr, MII_BMSR, MII_READ );
	mii_status = mii_rw ( priv, priv->phyaddr, MII_BMSR, MII_READ );

	if ( ! ( mii_status & BMSR_LSTATUS ) ) {
		DBG ( "No link detected by phy - falling back to 10HD.\n" );
		newls = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_10;
		newdup = 0;
		retval = 0;
		goto set_speed;
	}

	/* check auto negotiation is complete */
	if ( ! ( mii_status & BMSR_ANEGCOMPLETE ) ) {
		/* still in autonegotiation - configure nic for 10 MBit HD and wait. */
		newls = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_10;
		newdup = 0;
		retval = 0;
		DBG ( "autoneg not completed - falling back to 10HD.\n" );
		goto set_speed;
	}

	adv = mii_rw ( priv, priv->phyaddr, MII_ADVERTISE, MII_READ );
	lpa = mii_rw ( priv, priv->phyaddr, MII_LPA, MII_READ );
	DBG ( "nv_update_linkspeed: PHY advertises 0x%04x, lpa 0x%04x.\n", adv, lpa );

	retval = 1;
	if ( priv->gigabit == PHY_GIGABIT ) {
		control_1000 = mii_rw ( priv, priv->phyaddr, MII_CTRL1000, MII_READ);
		status_1000 = mii_rw ( priv, priv->phyaddr, MII_STAT1000, MII_READ);

		if ( ( control_1000 & ADVERTISE_1000FULL ) &&
			( status_1000 & LPA_1000FULL ) ) {
			DBG ( "nv_update_linkspeed: GBit ethernet detected.\n" );
			newls = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_1000;
			newdup = 1;
			goto set_speed;
		}
	}

	/* FIXME: handle parallel detection properly */
	adv_lpa = lpa & adv;
	if ( adv_lpa & LPA_100FULL ) {
		newls = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_100;
		newdup = 1;
	} else if ( adv_lpa & LPA_100HALF ) {
		newls = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_100;
		newdup = 0;
	} else if ( adv_lpa & LPA_10FULL ) {
		newls = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_10;
		newdup = 1;
	} else if ( adv_lpa & LPA_10HALF ) {
		newls = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_10;
		newdup = 0;
	} else {
		DBG ( "bad ability %04x - falling back to 10HD.\n", adv_lpa);
		newls = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_10;
		newdup = 0;
	}

set_speed:
	if ( priv->duplex == newdup && priv->linkspeed == newls )
		return retval;

	DBG ( "changing link setting from %d/%d to %d/%d.\n",
		priv->linkspeed, priv->duplex, newls, newdup);

	priv->duplex = newdup;
	priv->linkspeed = newls;

	/* The transmitter and receiver must be restarted for safe update */
	if ( readl ( ioaddr + NvRegTransmitterControl ) & NVREG_XMITCTL_START ) {
		txrxFlags |= NV_RESTART_TX;
		nv_stop_tx ( priv );
	}
	if ( readl ( ioaddr + NvRegReceiverControl ) & NVREG_RCVCTL_START) {
		txrxFlags |= NV_RESTART_RX;
		nv_stop_rx ( priv );
	}

	if ( priv->gigabit == PHY_GIGABIT ) {
		phyreg = readl ( ioaddr + NvRegSlotTime );
		phyreg &= ~(0x3FF00);
		if ( ( ( priv->linkspeed & 0xFFF ) == NVREG_LINKSPEED_10 ) ||
		     ( ( priv->linkspeed & 0xFFF ) == NVREG_LINKSPEED_100) )
			phyreg |= NVREG_SLOTTIME_10_100_FULL;
		else if ( ( priv->linkspeed & 0xFFF ) == NVREG_LINKSPEED_1000 )
			phyreg |= NVREG_SLOTTIME_1000_FULL;
		writel( phyreg, priv + NvRegSlotTime );
	}

	phyreg = readl ( ioaddr + NvRegPhyInterface );
	phyreg &= ~( PHY_HALF | PHY_100 | PHY_1000 );
	if ( priv->duplex == 0 )
		phyreg |= PHY_HALF;
	if ( ( priv->linkspeed & NVREG_LINKSPEED_MASK ) == NVREG_LINKSPEED_100 )
		phyreg |= PHY_100;
	else if ( ( priv->linkspeed & NVREG_LINKSPEED_MASK ) == NVREG_LINKSPEED_1000 )
		phyreg |= PHY_1000;
	writel ( phyreg, ioaddr + NvRegPhyInterface );

	phy_exp = mii_rw ( priv, priv->phyaddr, MII_EXPANSION, MII_READ ) & EXPANSION_NWAY; /* autoneg capable */
	if ( phyreg & PHY_RGMII ) {
		if ( ( priv->linkspeed & NVREG_LINKSPEED_MASK ) == NVREG_LINKSPEED_1000 ) {
			txreg = NVREG_TX_DEFERRAL_RGMII_1000;
		} else {
			if ( !phy_exp && !priv->duplex && ( priv->driver_data & DEV_HAS_COLLISION_FIX ) ) {
				if ( ( priv->linkspeed & NVREG_LINKSPEED_MASK ) == NVREG_LINKSPEED_10 )
					txreg = NVREG_TX_DEFERRAL_RGMII_STRETCH_10;
				else
					txreg = NVREG_TX_DEFERRAL_RGMII_STRETCH_100;
			} else {
				txreg = NVREG_TX_DEFERRAL_RGMII_10_100;
			}
		}
	} else {
		if ( !phy_exp && !priv->duplex && ( priv->driver_data & DEV_HAS_COLLISION_FIX ) )
			txreg = NVREG_TX_DEFERRAL_MII_STRETCH;
		else
			txreg = NVREG_TX_DEFERRAL_DEFAULT;
	}
	writel ( txreg, ioaddr + NvRegTxDeferral );

	txreg = NVREG_TX_WM_DESC1_DEFAULT;
	writel ( txreg, ioaddr + NvRegTxWatermark );

	writel ( NVREG_MISC1_FORCE | ( priv->duplex ? 0 : NVREG_MISC1_HD ), ioaddr + NvRegMisc1 );
	pci_push ( ioaddr );
	writel ( priv->linkspeed, priv + NvRegLinkSpeed);
	pci_push ( ioaddr );

	pause_flags = 0;
	/* setup pause frame */
	if ( priv->duplex != 0 ) {
		if ( priv->pause_flags & NV_PAUSEFRAME_AUTONEG ) {
			adv_pause = adv & ( ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM );
			lpa_pause = lpa & ( LPA_PAUSE_CAP | LPA_PAUSE_ASYM );

			switch ( adv_pause ) {
			case ADVERTISE_PAUSE_CAP:
				if ( lpa_pause & LPA_PAUSE_CAP ) {
					pause_flags |= NV_PAUSEFRAME_RX_ENABLE;
					if ( priv->pause_flags & NV_PAUSEFRAME_TX_REQ )
						pause_flags |= NV_PAUSEFRAME_TX_ENABLE;
				}
				break;
			case ADVERTISE_PAUSE_ASYM:
				if ( lpa_pause == ( LPA_PAUSE_CAP | LPA_PAUSE_ASYM ) )
				{
					pause_flags |= NV_PAUSEFRAME_TX_ENABLE;
				}
				break;
			case ADVERTISE_PAUSE_CAP| ADVERTISE_PAUSE_ASYM:
				if ( lpa_pause & LPA_PAUSE_CAP )
				{
					pause_flags |=  NV_PAUSEFRAME_RX_ENABLE;
					if ( priv->pause_flags & NV_PAUSEFRAME_TX_REQ )
						pause_flags |= NV_PAUSEFRAME_TX_ENABLE;
				}
				if ( lpa_pause == LPA_PAUSE_ASYM )
				{
					pause_flags |= NV_PAUSEFRAME_RX_ENABLE;
				}
				break;
			}
		} else {
			pause_flags = priv->pause_flags;
		}
	}
	nv_update_pause ( priv, pause_flags );

	if ( txrxFlags & NV_RESTART_TX )
		nv_start_tx ( priv );
	if ( txrxFlags & NV_RESTART_RX )
		nv_start_rx ( priv );

	return retval;
}


/**
 * open - Called when a network interface is made active
 *
 * @v netdev	Network device
 * @ret rc	Return status code, 0 on success, negative value on failure
 **/
static int
forcedeth_open ( struct net_device *netdev )
{
	struct forcedeth_private *priv = netdev_priv ( netdev );
	void *ioaddr = priv->mmio_addr;
	int i;
	int rc;
	u32 low;

	DBGP ( "forcedeth_open\n" );

	/* Power up phy */
	mii_rw ( priv, priv->phyaddr, MII_BMCR,
		 mii_rw ( priv, priv->phyaddr, MII_BMCR, MII_READ ) & ~BMCR_PDOWN );

	nv_txrx_gate ( priv, 0 );

	/* Erase previous misconfiguration */
	if ( priv->driver_data & DEV_HAS_POWER_CNTRL )
		nv_mac_reset ( priv );

	/* Clear multicast masks and addresses, enter promiscuous mode */
	writel ( 0, ioaddr + NvRegMulticastAddrA );
	writel ( 0, ioaddr + NvRegMulticastAddrB );
	writel ( NVREG_MCASTMASKA_NONE, ioaddr + NvRegMulticastMaskA );
	writel ( NVREG_MCASTMASKB_NONE, ioaddr + NvRegMulticastMaskB );
	writel ( NVREG_PFF_PROMISC, ioaddr + NvRegPacketFilterFlags );

	writel ( 0, ioaddr + NvRegTransmitterControl );
	writel ( 0, ioaddr + NvRegReceiverControl );

	writel ( 0, ioaddr + NvRegAdapterControl );

	writel ( 0, ioaddr + NvRegLinkSpeed );
	writel ( readl ( ioaddr + NvRegTransmitPoll ) & NVREG_TRANSMITPOLL_MAC_ADDR_REV,
		 ioaddr + NvRegTransmitPoll );
	nv_txrx_reset ( priv );
	writel ( 0, ioaddr + NvRegUnknownSetupReg6 );

	/* Initialize descriptor rings */
	if ( ( rc = nv_init_rings ( priv ) ) != 0 )
		goto err_init_rings;

	writel ( priv->linkspeed, ioaddr + NvRegLinkSpeed );
	writel ( NVREG_TX_WM_DESC1_DEFAULT, ioaddr + NvRegTxWatermark );
	writel ( NVREG_TXRXCTL_DESC_1, ioaddr + NvRegTxRxControl );
	writel ( 0 , ioaddr + NvRegVlanControl );
	pci_push ( ioaddr );
	writel ( NVREG_TXRXCTL_BIT1 | NVREG_TXRXCTL_DESC_1,
		 ioaddr + NvRegTxRxControl );
	reg_delay ( priv, NvRegUnknownSetupReg5, NVREG_UNKSETUP5_BIT31,
		    NVREG_UNKSETUP5_BIT31, NV_SETUP5_DELAY, NV_SETUP5_DELAYMAX,
		    "open: SetupReg5, Bit 31 remained off\n" );

	writel ( 0, ioaddr + NvRegMIIMask );
	writel ( NVREG_IRQSTAT_MASK, ioaddr + NvRegIrqStatus );
	writel ( NVREG_MIISTAT_MASK_ALL, ioaddr + NvRegMIIStatus );

	writel ( NVREG_MISC1_FORCE | NVREG_MISC1_HD, ioaddr + NvRegMisc1 );
	writel ( readl ( ioaddr + NvRegTransmitterStatus ),
		 ioaddr + NvRegTransmitterStatus );
	writel ( RX_BUF_SZ, ioaddr + NvRegOffloadConfig );

	writel ( readl ( ioaddr + NvRegReceiverStatus),
		 ioaddr + NvRegReceiverStatus );

	/* Set up slot time */
	low = ( random() & NVREG_SLOTTIME_MASK );
	writel ( low | NVREG_SLOTTIME_DEFAULT, ioaddr + NvRegSlotTime );

	writel ( NVREG_TX_DEFERRAL_DEFAULT , ioaddr + NvRegTxDeferral );
	writel ( NVREG_RX_DEFERRAL_DEFAULT , ioaddr + NvRegRxDeferral );

	writel ( NVREG_POLL_DEFAULT_THROUGHPUT, ioaddr + NvRegPollingInterval );

	writel ( NVREG_UNKSETUP6_VAL, ioaddr + NvRegUnknownSetupReg6 );
	writel ( ( priv->phyaddr << NVREG_ADAPTCTL_PHYSHIFT ) |
		 NVREG_ADAPTCTL_PHYVALID | NVREG_ADAPTCTL_RUNNING,
		 ioaddr + NvRegAdapterControl );
	writel ( NVREG_MIISPEED_BIT8 | NVREG_MIIDELAY, ioaddr + NvRegMIISpeed );
	writel ( NVREG_MII_LINKCHANGE, ioaddr + NvRegMIIMask );

	i = readl ( ioaddr + NvRegPowerState );
	if ( ( i & NVREG_POWERSTATE_POWEREDUP ) == 0 )
		writel ( NVREG_POWERSTATE_POWEREDUP | i, ioaddr + NvRegPowerState );

	pci_push ( ioaddr );
	udelay ( 10 );
	writel ( readl ( ioaddr + NvRegPowerState ) | NVREG_POWERSTATE_VALID,
		 ioaddr + NvRegPowerState );

	nv_disable_hw_interrupts ( priv );
	writel ( NVREG_MIISTAT_MASK_ALL, ioaddr + NvRegMIIStatus );
	writel ( NVREG_IRQSTAT_MASK, ioaddr + NvRegIrqStatus );
	pci_push ( ioaddr );

	readl ( ioaddr + NvRegMIIStatus );
	writel ( NVREG_MIISTAT_MASK_ALL, ioaddr + NvRegMIIStatus );
	priv->linkspeed = 0;
	nv_update_linkspeed ( priv );
	nv_start_rx ( priv );
	nv_start_tx ( priv );

	return 0;

err_init_rings:
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
forcedeth_transmit ( struct net_device *netdev, struct io_buffer *iobuf )
{
	struct forcedeth_private *priv = netdev_priv ( netdev );
	void *ioaddr = priv->mmio_addr;
	struct ring_desc *tx_curr_desc;
	u32 size = iob_len ( iobuf );

	DBGP ( "forcedeth_transmit\n" );

	/* NOTE: Some NICs have a hw bug that causes them to malfunction
	 * when there are more than 16 outstanding TXs. Increasing the TX
	 * ring size might trigger this bug */
	if ( priv->tx_fill_ctr == TX_RING_SIZE ) {
		DBG ( "Tx overflow\n" );
		return -ENOBUFS;
	}

	/* Pad small packets to minimum length */
	iob_pad ( iobuf, ETH_ZLEN );

	priv->tx_iobuf[priv->tx_curr] = iobuf;

	tx_curr_desc = priv->tx_ring + priv->tx_curr;

	/* Configure current descriptor to transmit packet
	 * ( NV_TX_VALID sets the ownership bit ) */
	tx_curr_desc->buf =
		cpu_to_le32 ( virt_to_bus ( iobuf->data ) );
	wmb();
	/* Since we don't do fragmentation offloading, we always have
	 * the last packet bit set */
	tx_curr_desc->flaglen =
		cpu_to_le32 ( ( size - 1 ) | NV_TX_VALID | NV_TX_LASTPACKET );

	DBG ( "forcedeth_transmit: flaglen = %#04x\n",
		( size - 1 ) | NV_TX_VALID | NV_TX_LASTPACKET );
	DBG ( "forcedeth_transmit: tx_fill_ctr = %d\n",
		priv->tx_fill_ctr );

	writel ( NVREG_TXRXCTL_KICK | NVREG_TXRXCTL_DESC_1,
		 ioaddr + NvRegTxRxControl );
	pci_push ( ioaddr );

	/* Point to the next free descriptor */
	priv->tx_curr = ( priv->tx_curr + 1 ) % TX_RING_SIZE;

	/* Increment number of descriptors in use */
	priv->tx_fill_ctr++;

	return 0;
}

/**
 * nv_process_tx_packets - Checks for successfully sent packets,
 * reports them to iPXE with netdev_tx_complete()
 *
 * @v netdev    Network device
 */
static void
nv_process_tx_packets ( struct net_device *netdev )
{
	struct forcedeth_private *priv = netdev_priv ( netdev );
	struct ring_desc *tx_curr_desc;
	u32 flaglen;

	DBGP ( "nv_process_tx_packets\n" );

	while ( priv->tx_tail != priv->tx_curr ) {

		tx_curr_desc = priv->tx_ring + priv->tx_tail;
		flaglen = le32_to_cpu ( tx_curr_desc->flaglen );
		rmb();

		/* Skip this descriptor if hardware still owns it */
		if ( flaglen & NV_TX_VALID )
			break;

		DBG ( "Transmitted packet.\n" );
		DBG ( "priv->tx_fill_ctr= %d\n", priv->tx_fill_ctr );
		DBG ( "priv->tx_tail	= %d\n", priv->tx_tail );
		DBG ( "priv->tx_curr	= %d\n", priv->tx_curr );
		DBG ( "flaglen		= %#04x\n", flaglen );

		/* This packet is ready for completion */
		netdev_tx_complete ( netdev, priv->tx_iobuf[priv->tx_tail] );

		/* Clear the descriptor */
		memset ( tx_curr_desc, 0, sizeof(*tx_curr_desc) );

		/* Reduce the number of tx descriptors in use */
		priv->tx_fill_ctr--;

		/* Go to next available descriptor */
		priv->tx_tail = ( priv->tx_tail + 1 ) % TX_RING_SIZE;
	}
}

/**
 * nv_process_rx_packets - Checks for received packets, reports them
 * to iPXE with netdev_rx() or netdev_rx_err() if there was an error receiving
 * the packet
 *
 * @v netdev    Network device
 */
static void
nv_process_rx_packets ( struct net_device *netdev )
{
	struct forcedeth_private *priv = netdev_priv ( netdev );
	struct io_buffer *curr_iob;
	struct ring_desc *rx_curr_desc;
	u32 flags, len;
	int i;

	DBGP ( "nv_process_rx_packets\n" );

	for ( i = 0; i < RX_RING_SIZE; i++ ) {

		rx_curr_desc = priv->rx_ring + priv->rx_curr;
		flags = le32_to_cpu ( rx_curr_desc->flaglen );
		rmb();

		/* Skip this descriptor if hardware still owns it */
		if ( flags & NV_RX_AVAIL )
			break;

		/* We own the descriptor, but it has not been refilled yet */
		curr_iob = priv->rx_iobuf[priv->rx_curr];
		DBG ( "%p %p\n", curr_iob, priv->rx_iobuf[priv->rx_curr] );
		if ( curr_iob == NULL )
			break;

		DBG ( "Received packet.\n" );
		DBG ( "priv->rx_curr	= %d\n", priv->rx_curr );
		DBG ( "flags		= %#04x\n", flags );

		/* Check for errors */
		if ( ( flags & NV_RX_DESCRIPTORVALID ) &&
		     ( flags & NV_RX_ERROR ) ) {
				netdev_rx_err ( netdev, curr_iob, -EINVAL );
				DBG ( " Corrupted packet received!\n" );
		} else {
			len = flags & LEN_MASK_V1;

			iob_put ( curr_iob, len );
			netdev_rx ( netdev, curr_iob );
		}

		/* Invalidate iobuf */
		priv->rx_iobuf[priv->rx_curr] = NULL;

		/* Invalidate descriptor */
		memset ( rx_curr_desc, 0, sizeof(*rx_curr_desc) );

		/* Point to the next free descriptor */
		priv->rx_curr = ( priv->rx_curr + 1 ) % RX_RING_SIZE;
	}

	nv_alloc_rx ( priv );
}

/**
 * check_link - Check for link status change
 *
 * @v netdev	Network device
 */
static void
forcedeth_link_status ( struct net_device *netdev )
{
	struct forcedeth_private *priv = netdev_priv ( netdev );
	void *ioaddr = priv->mmio_addr;

	/* Clear the MII link change status by reading the MIIStatus register */
	readl ( ioaddr + NvRegMIIStatus );
	writel ( NVREG_MIISTAT_LINKCHANGE, ioaddr + NvRegMIIStatus );

	if ( nv_update_linkspeed ( priv ) == 1 )
		netdev_link_up ( netdev );
	else
		netdev_link_down ( netdev );
}

/**
 * poll - Poll for received packets
 *
 * @v netdev	Network device
 */
static void
forcedeth_poll ( struct net_device *netdev )
{
	struct forcedeth_private *priv = netdev_priv ( netdev );
	void *ioaddr = priv->mmio_addr;
	u32 status;

	DBGP ( "forcedeth_poll\n" );

	status = readl ( ioaddr + NvRegIrqStatus ) & NVREG_IRQSTAT_MASK;

	/* Return when no interrupts have been triggered */
	if ( ! status )
		return;

	/* Clear interrupts */
	writel ( NVREG_IRQSTAT_MASK, ioaddr + NvRegIrqStatus );

	DBG ( "forcedeth_poll: status = %#04x\n", status );

	/* Link change interrupt occurred. Call always if link is down,
	 * to give auto-neg a chance to finish */
	if ( ( status & NVREG_IRQ_LINK ) || ! ( netdev_link_ok ( netdev ) ) )
		forcedeth_link_status ( netdev );

	/* Process transmitted packets */
	nv_process_tx_packets ( netdev );

	/* Process received packets */
	nv_process_rx_packets ( netdev );
}

/**
 * close - Disable network interface
 *
 * @v netdev	network interface device structure
 **/
static void
forcedeth_close ( struct net_device *netdev )
{
	struct forcedeth_private *priv = netdev_priv ( netdev );

	DBGP ( "forcedeth_close\n" );

	nv_stop_rx ( priv );
	nv_stop_tx ( priv );
	nv_txrx_reset ( priv );

	/* Disable interrupts on the nic or we will lock up */
	nv_disable_hw_interrupts ( priv );

	nv_free_rxtx_resources ( priv );

	nv_txrx_gate ( priv, 0 );

	/* FIXME: power down nic */
}

/**
 * irq - enable or disable interrupts
 *
 * @v netdev    network adapter
 * @v action    requested interrupt action
 **/
static void
forcedeth_irq ( struct net_device *netdev, int action )
{
	struct forcedeth_private *priv = netdev_priv ( netdev );

	DBGP ( "forcedeth_irq\n" );

	switch ( action ) {
	case 0:
		nv_disable_hw_interrupts ( priv );
		break;
	default:
		nv_enable_hw_interrupts ( priv );
		break;
	}
}

static struct net_device_operations forcedeth_operations  = {
	.open		= forcedeth_open,
	.transmit	= forcedeth_transmit,
	.poll		= forcedeth_poll,
	.close		= forcedeth_close,
	.irq		= forcedeth_irq,
};

static int
nv_setup_mac_addr ( struct forcedeth_private *priv )
{
	struct net_device *dev = priv->netdev;
	void *ioaddr = priv->mmio_addr;
	u32 orig_mac[2];
	u32 txreg;

	orig_mac[0] = readl ( ioaddr + NvRegMacAddrA );
	orig_mac[1] = readl ( ioaddr + NvRegMacAddrB );

	txreg = readl ( ioaddr + NvRegTransmitPoll );

	if ( ( priv->driver_data & DEV_HAS_CORRECT_MACADDR ) ||
	     ( txreg & NVREG_TRANSMITPOLL_MAC_ADDR_REV ) ) {
		/* mac address is already in correct order */
		dev->hw_addr[0] = ( orig_mac[0] >> 0 ) & 0xff;
		dev->hw_addr[1] = ( orig_mac[0] >> 8 ) & 0xff;
		dev->hw_addr[2] = ( orig_mac[0] >> 16 ) & 0xff;
		dev->hw_addr[3] = ( orig_mac[0] >> 24 ) & 0xff;
		dev->hw_addr[4] = ( orig_mac[1] >> 0 ) & 0xff;
		dev->hw_addr[5] = ( orig_mac[1] >> 8 ) & 0xff;
	} else {
		/* need to reverse mac address to correct order */
		dev->hw_addr[0] = ( orig_mac[1] >> 8 ) & 0xff;
		dev->hw_addr[1] = ( orig_mac[1] >> 0 ) & 0xff;
		dev->hw_addr[2] = ( orig_mac[0] >> 24 ) & 0xff;
		dev->hw_addr[3] = ( orig_mac[0] >> 16 ) & 0xff;
		dev->hw_addr[4] = ( orig_mac[0] >> 8 ) & 0xff;
		dev->hw_addr[5] = ( orig_mac[0] >> 0 ) & 0xff;
	}

	if ( ! is_valid_ether_addr ( dev->hw_addr ) )
		return -EADDRNOTAVAIL;

	DBG ( "MAC address is: %s\n", eth_ntoa ( dev->hw_addr ) );

	return 0;
}

static int
nv_mgmt_acquire_sema ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	int i;
	u32 tx_ctrl, mgmt_sema;

	for ( i = 0; i < 10; i++ ) {
		mgmt_sema = readl ( ioaddr + NvRegTransmitterControl ) &
			NVREG_XMITCTL_MGMT_SEMA_MASK;
		if ( mgmt_sema == NVREG_XMITCTL_MGMT_SEMA_FREE )
			break;
		mdelay ( 500 );
	}

	if ( mgmt_sema != NVREG_XMITCTL_MGMT_SEMA_FREE )
		return 0;

	for ( i = 0; i < 2; i++ ) {
		tx_ctrl = readl ( ioaddr + NvRegTransmitterControl );
		tx_ctrl |= NVREG_XMITCTL_HOST_SEMA_ACQ;
		writel ( tx_ctrl, ioaddr + NvRegTransmitterControl );

		/* verify that the semaphore was acquired */
		tx_ctrl = readl ( ioaddr + NvRegTransmitterControl );
		if ( ( ( tx_ctrl & NVREG_XMITCTL_HOST_SEMA_MASK ) ==
		       NVREG_XMITCTL_HOST_SEMA_ACQ ) &&
		     ( ( tx_ctrl & NVREG_XMITCTL_MGMT_SEMA_MASK ) ==
		       NVREG_XMITCTL_MGMT_SEMA_FREE ) ) {
			priv->mgmt_sema = 1;
			return 1;
		} else {
			udelay ( 50 );
		}
	}

	return 0;
}

static void
nv_mgmt_release_sema ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 tx_ctrl;

	if ( priv->driver_data & DEV_HAS_MGMT_UNIT ) {
		if ( priv->mgmt_sema ) {
			tx_ctrl = readl (ioaddr + NvRegTransmitterControl );
			tx_ctrl &= ~NVREG_XMITCTL_HOST_SEMA_ACQ;
			writel ( tx_ctrl, ioaddr + NvRegTransmitterControl );
		}
	}
}

static int
nv_mgmt_get_version ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 data_ready = readl ( ioaddr + NvRegTransmitterControl );
	u32 data_ready2 = 0;
	unsigned long start;
	int ready = 0;

	writel ( NVREG_MGMTUNITGETVERSION,
		ioaddr + NvRegMgmtUnitGetVersion );
	writel ( data_ready ^ NVREG_XMITCTL_DATA_START,
		ioaddr + NvRegTransmitterControl );
	start = currticks();

	while ( currticks() > start + 5 * ticks_per_sec() ) {
		data_ready2 = readl ( ioaddr + NvRegTransmitterControl );
		if ( ( data_ready & NVREG_XMITCTL_DATA_READY ) !=
		     ( data_ready2 & NVREG_XMITCTL_DATA_READY ) ) {
			ready = 1;
			break;
		}
		mdelay ( 1000 );
	}

	if ( ! ready || ( data_ready2 & NVREG_XMITCTL_DATA_ERROR ) )
		return 0;

	priv->mgmt_version =
		readl ( ioaddr + NvRegMgmtUnitVersion ) & NVREG_MGMTUNITVERSION;

	return 1;
}



static int
phy_reset ( struct forcedeth_private *priv, u32 bmcr_setup )
{
	u32 miicontrol;
	unsigned int tries = 0;

	miicontrol = BMCR_RESET | bmcr_setup;
	if ( mii_rw ( priv, priv->phyaddr, MII_BMCR, miicontrol ) ) {
		return -1;
	}

	mdelay ( 500 );

	/* must wait till reset is deasserted */
	while ( miicontrol & BMCR_RESET ) {
		mdelay ( 10 );
		miicontrol = mii_rw ( priv, priv->phyaddr, MII_BMCR, MII_READ );
		if ( tries++ > 100 )
			return -1;
	}
	return 0;
}

static int
phy_init ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 phyinterface, phy_reserved, mii_status;
	u32 mii_control, mii_control_1000, reg;

	/* phy errata for E3016 phy */
	if ( priv->phy_model == PHY_MODEL_MARVELL_E3016 ) {
		reg = mii_rw ( priv, priv->phyaddr, MII_NCONFIG, MII_READ );
		reg &= ~PHY_MARVELL_E3016_INITMASK;
		if ( mii_rw ( priv, priv->phyaddr, MII_NCONFIG, reg ) ) {
			DBG ( "PHY write to errata reg failed.\n" );
			return PHY_ERROR;
		}
	}

	if ( priv->phy_oui == PHY_OUI_REALTEK ) {
		if ( priv->phy_model == PHY_MODEL_REALTEK_8211 &&
		     priv->phy_rev == PHY_REV_REALTEK_8211B ) {
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG1, PHY_REALTEK_INIT1 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG2, PHY_REALTEK_INIT2 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG1, PHY_REALTEK_INIT3 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG3, PHY_REALTEK_INIT4 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG4, PHY_REALTEK_INIT5 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG5, PHY_REALTEK_INIT6 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG1, PHY_REALTEK_INIT1 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
		}

		if ( priv->phy_model == PHY_MODEL_REALTEK_8211 &&
		     priv->phy_rev == PHY_REV_REALTEK_8211C ) {
			u32 powerstate = readl ( ioaddr + NvRegPowerState2 );

			/* need to perform hw phy reset */
			powerstate |= NVREG_POWERSTATE2_PHY_RESET;
			writel ( powerstate , ioaddr + NvRegPowerState2 );
			mdelay ( 25 );

			powerstate &= ~NVREG_POWERSTATE2_PHY_RESET;
			writel ( powerstate , ioaddr + NvRegPowerState2 );
			mdelay ( 25 );

			reg = mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG6, MII_READ );
			reg |= PHY_REALTEK_INIT9;
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG6, reg ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG1, PHY_REALTEK_INIT10 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}

			reg = mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG7, MII_READ );
			if ( ! ( reg & PHY_REALTEK_INIT11 ) ) {
				reg |= PHY_REALTEK_INIT11;
				if ( mii_rw ( priv, priv->phyaddr,
					PHY_REALTEK_INIT_REG7, reg ) ) {
					DBG ( "PHY init failed.\n" );
					return PHY_ERROR;
				}
			}
			if ( mii_rw ( priv, priv->phyaddr,
				PHY_REALTEK_INIT_REG1, PHY_REALTEK_INIT1 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
		}
		if ( priv->phy_model == PHY_MODEL_REALTEK_8201 ) {
			if ( priv->driver_data & DEV_NEED_PHY_INIT_FIX ) {
				phy_reserved = mii_rw ( priv, priv->phyaddr,
							PHY_REALTEK_INIT_REG6,
							MII_READ );
				phy_reserved |= PHY_REALTEK_INIT7;
				if ( mii_rw ( priv, priv->phyaddr,
					      PHY_REALTEK_INIT_REG6,
					      phy_reserved ) ) {
					DBG ( "PHY init failed.\n" );
					return PHY_ERROR;
				}
			}
		}
	}

	/* set advertise register */
	reg = mii_rw ( priv, priv->phyaddr, MII_ADVERTISE, MII_READ );
	reg |= ( ADVERTISE_10HALF | ADVERTISE_10FULL | ADVERTISE_100HALF |
		 ADVERTISE_100FULL | ADVERTISE_PAUSE_ASYM | ADVERTISE_PAUSE_CAP );
	if ( mii_rw ( priv, priv->phyaddr, MII_ADVERTISE, reg ) ) {
		DBG ( "PHY init failed.\n" );
		return PHY_ERROR;
	}

	/* get phy interface type */
	phyinterface = readl ( ioaddr + NvRegPhyInterface );

	/* see if gigabit phy */
	mii_status = mii_rw ( priv, priv->phyaddr, MII_BMSR, MII_READ );
	if ( mii_status & PHY_GIGABIT ) {
		priv->gigabit = PHY_GIGABIT;
		mii_control_1000 =
			mii_rw ( priv, priv->phyaddr, MII_CTRL1000, MII_READ );
		mii_control_1000 &= ~ADVERTISE_1000HALF;
		if ( phyinterface & PHY_RGMII )
			mii_control_1000 |= ADVERTISE_1000FULL;
		else
			mii_control_1000 &= ~ADVERTISE_1000FULL;

		if ( mii_rw ( priv, priv->phyaddr, MII_CTRL1000, mii_control_1000)) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
	} else {
		priv->gigabit = 0;
	}

	mii_control = mii_rw ( priv, priv->phyaddr, MII_BMCR, MII_READ );
	mii_control |= BMCR_ANENABLE;

	if ( priv->phy_oui == PHY_OUI_REALTEK &&
	     priv->phy_model == PHY_MODEL_REALTEK_8211 &&
	     priv->phy_rev == PHY_REV_REALTEK_8211C ) {
		/* start autoneg since we already performed hw reset above */
		mii_control |= BMCR_ANRESTART;
		if ( mii_rw ( priv, priv->phyaddr, MII_BMCR, mii_control ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
	} else {
		/* reset the phy
		 * (certain phys need bmcr to be setup with reset )
		 */
		if ( phy_reset ( priv, mii_control ) ) {
			DBG ( "PHY reset failed\n" );
			return PHY_ERROR;
		}
	}

	/* phy vendor specific configuration */
	if ( ( priv->phy_oui == PHY_OUI_CICADA ) && ( phyinterface & PHY_RGMII ) ) {
		phy_reserved = mii_rw ( priv, priv->phyaddr, MII_RESV1, MII_READ );
		phy_reserved &= ~( PHY_CICADA_INIT1 | PHY_CICADA_INIT2 );
		phy_reserved |= ( PHY_CICADA_INIT3 | PHY_CICADA_INIT4 );
		if ( mii_rw ( priv, priv->phyaddr, MII_RESV1, phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		phy_reserved = mii_rw ( priv, priv->phyaddr, MII_NCONFIG, MII_READ );
		phy_reserved |= PHY_CICADA_INIT5;
		if ( mii_rw ( priv, priv->phyaddr, MII_NCONFIG, phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
	}
	if ( priv->phy_oui == PHY_OUI_CICADA ) {
		phy_reserved = mii_rw ( priv, priv->phyaddr, MII_SREVISION, MII_READ );
		phy_reserved |= PHY_CICADA_INIT6;
		if ( mii_rw ( priv, priv->phyaddr, MII_SREVISION, phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
	}
	if ( priv->phy_oui == PHY_OUI_VITESSE ) {
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG1,
						   PHY_VITESSE_INIT1)) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG2,
						   PHY_VITESSE_INIT2)) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		phy_reserved = mii_rw ( priv, priv->phyaddr,
					PHY_VITESSE_INIT_REG4, MII_READ);
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG4,
						   phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		phy_reserved = mii_rw ( priv, priv->phyaddr,
					PHY_VITESSE_INIT_REG3, MII_READ);
		phy_reserved &= ~PHY_VITESSE_INIT_MSK1;
		phy_reserved |= PHY_VITESSE_INIT3;
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG3,
						   phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG2,
						   PHY_VITESSE_INIT4 ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG2,
						   PHY_VITESSE_INIT5 ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		phy_reserved = mii_rw ( priv, priv->phyaddr,
					PHY_VITESSE_INIT_REG4, MII_READ);
		phy_reserved &= ~PHY_VITESSE_INIT_MSK1;
		phy_reserved |= PHY_VITESSE_INIT3;
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG4,
						   phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		phy_reserved = mii_rw ( priv, priv->phyaddr,
					PHY_VITESSE_INIT_REG3, MII_READ);
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG3,
						   phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG2,
						   PHY_VITESSE_INIT6 ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG2,
						   PHY_VITESSE_INIT7 ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		phy_reserved = mii_rw ( priv, priv->phyaddr,
					PHY_VITESSE_INIT_REG4, MII_READ);
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG4,
						   phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		phy_reserved = mii_rw ( priv, priv->phyaddr,
					PHY_VITESSE_INIT_REG3, MII_READ);
		phy_reserved &= ~PHY_VITESSE_INIT_MSK2;
		phy_reserved |= PHY_VITESSE_INIT8;
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG3,
						   phy_reserved ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG2,
						   PHY_VITESSE_INIT9 ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
		if ( mii_rw ( priv, priv->phyaddr, PHY_VITESSE_INIT_REG1,
						   PHY_VITESSE_INIT10 ) ) {
			DBG ( "PHY init failed.\n" );
			return PHY_ERROR;
		}
	}

	if ( priv->phy_oui == PHY_OUI_REALTEK ) {
		if ( priv->phy_model == PHY_MODEL_REALTEK_8211 &&
		     priv->phy_rev == PHY_REV_REALTEK_8211B ) {
			/* reset could have cleared these out, set them back */
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG1, PHY_REALTEK_INIT1 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG2, PHY_REALTEK_INIT2 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG1, PHY_REALTEK_INIT3 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG3, PHY_REALTEK_INIT4 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG4, PHY_REALTEK_INIT5 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG5, PHY_REALTEK_INIT6 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG1, PHY_REALTEK_INIT1 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
		}
		if ( priv->phy_model == PHY_MODEL_REALTEK_8201 ) {
			if ( priv->driver_data & DEV_NEED_PHY_INIT_FIX ) {
				phy_reserved = mii_rw ( priv, priv->phyaddr,
							PHY_REALTEK_INIT_REG6,
							MII_READ );
				phy_reserved |= PHY_REALTEK_INIT7;
				if ( mii_rw ( priv, priv->phyaddr,
					      PHY_REALTEK_INIT_REG6,
					      phy_reserved ) ) {
					DBG ( "PHY init failed.\n" );
					return PHY_ERROR;
				}
			}

			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG1,
				      PHY_REALTEK_INIT3 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			phy_reserved = mii_rw ( priv, priv->phyaddr,
						PHY_REALTEK_INIT_REG2,
						MII_READ );
			phy_reserved &= ~PHY_REALTEK_INIT_MSK1;
			phy_reserved |= PHY_REALTEK_INIT3;
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG2,
				      phy_reserved ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
			if ( mii_rw ( priv, priv->phyaddr,
				      PHY_REALTEK_INIT_REG1,
				      PHY_REALTEK_INIT1 ) ) {
				DBG ( "PHY init failed.\n" );
				return PHY_ERROR;
			}
		}
	}

	/* some phys clear out pause advertisement on reset, set it back */
	mii_rw ( priv, priv->phyaddr, MII_ADVERTISE, reg );

	/* restart auto negotiation, power down phy */
	mii_control = mii_rw ( priv, priv->phyaddr, MII_BMCR, MII_READ );
	mii_control |= ( BMCR_ANRESTART | BMCR_ANENABLE );
	if ( mii_rw ( priv, priv->phyaddr, MII_BMCR, mii_control ) ) {
		return PHY_ERROR;
	}

	return 0;
}

/**
 * nv_setup_phy - Find PHY and initialize it
 *
 * @v priv	Driver private structure
 *
 * @ret rc	Return status code
 **/
static int
nv_setup_phy ( struct forcedeth_private *priv )
{
	void *ioaddr = priv->mmio_addr;
	u32 phystate_orig = 0, phystate;
	int phyinitialised = 0;
	u32 powerstate;
	int rc = 0;
	int i;

	if ( priv->driver_data & DEV_HAS_POWER_CNTRL ) {
		/* take phy and nic out of low power mode */
		powerstate = readl ( ioaddr + NvRegPowerState2 );
		powerstate &= ~NVREG_POWERSTATE2_POWERUP_MASK;
		if ( ( priv->driver_data & DEV_NEED_LOW_POWER_FIX ) &&
		     ( ( priv->pci_dev->class & 0xff ) >= 0xA3 ) )
			powerstate |= NVREG_POWERSTATE2_POWERUP_REV_A3;
		writel ( powerstate, ioaddr + NvRegPowerState2 );
	}


	/* clear phy state and temporarily halt phy interrupts */
	writel ( 0, ioaddr + NvRegMIIMask );
	phystate = readl ( ioaddr + NvRegAdapterControl );
	if ( phystate & NVREG_ADAPTCTL_RUNNING ) {
		phystate_orig = 1;
		phystate &= ~NVREG_ADAPTCTL_RUNNING;
		writel ( phystate, ioaddr + NvRegAdapterControl );
	}
	writel ( NVREG_MIISTAT_MASK_ALL, ioaddr + NvRegMIIStatus );

	if ( priv->driver_data & DEV_HAS_MGMT_UNIT ) {
		/* management unit running on the mac? */
		if ( ( readl ( ioaddr + NvRegTransmitterControl ) & NVREG_XMITCTL_MGMT_ST ) &&
		     ( readl ( ioaddr + NvRegTransmitterControl ) & NVREG_XMITCTL_SYNC_PHY_INIT ) &&
		     nv_mgmt_acquire_sema ( priv ) &&
		     nv_mgmt_get_version ( priv ) ) {
			priv->mac_in_use = 1;
			if ( priv->mgmt_version > 0 ) {
				priv->mac_in_use = readl ( ioaddr + NvRegMgmtUnitControl ) & NVREG_MGMTUNITCONTROL_INUSE;
			}

			DBG ( "mgmt unit is running. mac in use\n" );

			/* management unit setup the phy already? */
			if ( priv->mac_in_use &&
			   ( ( readl ( ioaddr + NvRegTransmitterControl ) & NVREG_XMITCTL_SYNC_MASK ) ==
			     NVREG_XMITCTL_SYNC_PHY_INIT ) ) {
				/* phy is inited by mgmt unit */
				phyinitialised = 1;
				DBG ( "Phy already initialized by mgmt unit" );
			}
		}
	}

	/* find a suitable phy */
	for ( i = 1; i <= 32; i++ ) {
		int id1, id2;
		int phyaddr = i & 0x1f;

		id1 = mii_rw ( priv, phyaddr, MII_PHYSID1, MII_READ );
		if ( id1 < 0 || id1 == 0xffff )
			continue;
		id2 = mii_rw ( priv, phyaddr, MII_PHYSID2, MII_READ );
		if ( id2 < 0 || id2 == 0xffff )
			continue;

		priv->phy_model = id2 & PHYID2_MODEL_MASK;
		id1 = ( id1 & PHYID1_OUI_MASK ) << PHYID1_OUI_SHFT;
		id2 = ( id2 & PHYID2_OUI_MASK ) >> PHYID2_OUI_SHFT;
		DBG ( "Found PHY: %04x:%04x at address %d\n", id1, id2, phyaddr );
		priv->phyaddr = phyaddr;
		priv->phy_oui = id1 | id2;

		/* Realtek hardcoded phy id1 to all zeros on certain phys */
		if ( priv->phy_oui == PHY_OUI_REALTEK2 )
			priv->phy_oui = PHY_OUI_REALTEK;
		/* Setup phy revision for Realtek */
		if ( priv->phy_oui == PHY_OUI_REALTEK &&
		     priv->phy_model == PHY_MODEL_REALTEK_8211 )
			priv->phy_rev = mii_rw ( priv, phyaddr, MII_RESV1,
						 MII_READ ) & PHY_REV_MASK;
		break;
	}
	if ( i == 33 ) {
		DBG ( "Could not find a valid PHY.\n" );
		rc = -ENODEV;
		goto err_phy;
	}

	if ( ! phyinitialised ) {
		/* reset it */
		phy_init ( priv );
	} else {
		u32 mii_status = mii_rw ( priv, priv->phyaddr, MII_BMSR, MII_READ );
		if ( mii_status & PHY_GIGABIT ) {
			priv->gigabit = PHY_GIGABIT;
		}
	}

	return 0;

err_phy:
	if ( phystate_orig )
		writel ( phystate | NVREG_ADAPTCTL_RUNNING,
			 ioaddr + NvRegAdapterControl );
	return rc;
}

/**
 * forcedeth_map_regs - Find a suitable BAR for the NIC and
 * map the registers in memory
 *
 * @v priv	Driver private structure
 *
 * @ret rc	Return status code
 **/
static int
forcedeth_map_regs ( struct forcedeth_private *priv )
{
	void *ioaddr;
	uint32_t bar;
	unsigned long addr;
	u32 register_size;
	int reg;
	int rc;

	/* Set register size based on NIC */
	if ( priv->driver_data & ( DEV_HAS_VLAN | DEV_HAS_MSI_X |
		DEV_HAS_POWER_CNTRL | DEV_HAS_STATISTICS_V2 |
		DEV_HAS_STATISTICS_V3 ) ) {
		register_size = NV_PCI_REGSZ_VER3;
	} else if ( priv->driver_data & DEV_HAS_STATISTICS_V1 ) {
		register_size = NV_PCI_REGSZ_VER2;
	} else {
		register_size = NV_PCI_REGSZ_VER1;
	}

	/* Find an appropriate region for all the registers */
	rc = -EINVAL;
	addr = 0;
	for ( reg = PCI_BASE_ADDRESS_0; reg <= PCI_BASE_ADDRESS_5; reg += 4 ) {
		pci_read_config_dword ( priv->pci_dev, reg, &bar );

		if ( ( ! ( bar & PCI_BASE_ADDRESS_SPACE_IO ) ) &&
		     ( pci_bar_size ( priv->pci_dev, reg ) >= register_size ) ){
			addr = pci_bar_start ( priv->pci_dev, reg );
			break;
		}
	}

	if ( reg > PCI_BASE_ADDRESS_5 ) {
		DBG ( "Couldn't find register window\n" );
		goto err_bar_sz;
	}

	rc = -ENOMEM;
	ioaddr = ioremap ( addr, register_size );
	if ( ! ioaddr ) {
		DBG ( "Cannot remap MMIO\n" );
		goto err_ioremap;
	}

	priv->mmio_addr = ioaddr;

	return 0;

err_bar_sz:
err_ioremap:
	return rc;
}

/**
 * probe - Initial configuration of NIC
 *
 * @v pdev	PCI device
 * @v ent	PCI IDs
 *
 * @ret rc	Return status code
 **/
static int
forcedeth_probe ( struct pci_device *pdev )
{
	struct net_device *netdev;
	struct forcedeth_private *priv;
	void *ioaddr;
	int rc;

	DBGP ( "forcedeth_probe\n" );

	DBG ( "Found %s, vendor = %#04x, device = %#04x\n",
	      pdev->id->name, pdev->id->vendor, pdev->id->device );

	/* Allocate our private data */
	netdev = alloc_etherdev ( sizeof ( *priv ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		DBG ( "Failed to allocate net device\n" );
		goto err_alloc_etherdev;
	}

	/* Link our operations to the netdev struct */
	netdev_init ( netdev, &forcedeth_operations );

	/* Link the PCI device to the netdev struct */
	pci_set_drvdata ( pdev, netdev );
	netdev->dev = &pdev->dev;

	/* Get a reference to our private data */
	priv = netdev_priv ( netdev );

	/* We'll need these set up for the rest of the routines */
	priv->pci_dev = pdev;
	priv->netdev = netdev;
	priv->driver_data = pdev->id->driver_data;

	adjust_pci_device ( pdev );

	/* Use memory mapped I/O */
	if ( ( rc = forcedeth_map_regs ( priv ) ) != 0 )
		goto err_map_regs;
	ioaddr = priv->mmio_addr;

	/* Verify and get MAC address */
	if ( ( rc = nv_setup_mac_addr ( priv ) ) != 0 ) {
		DBG ( "Invalid MAC address detected\n" );
		goto err_mac_addr;
	}

	/* Disable WOL */
	writel ( 0, ioaddr + NvRegWakeUpFlags );

	if ( ( rc = nv_setup_phy ( priv ) ) != 0 )
		goto err_setup_phy;

	/* Set Pause Frame parameters */
	priv->pause_flags = NV_PAUSEFRAME_RX_CAPABLE |
			    NV_PAUSEFRAME_RX_REQ |
			    NV_PAUSEFRAME_AUTONEG;
	if ( ( priv->driver_data & DEV_HAS_PAUSEFRAME_TX_V1 ) ||
	     ( priv->driver_data & DEV_HAS_PAUSEFRAME_TX_V2 ) ||
	     ( priv->driver_data & DEV_HAS_PAUSEFRAME_TX_V3 ) ) {
		priv->pause_flags |= NV_PAUSEFRAME_TX_CAPABLE | NV_PAUSEFRAME_TX_REQ;
	}

	if ( priv->pause_flags & NV_PAUSEFRAME_TX_CAPABLE )
		writel ( NVREG_TX_PAUSEFRAME_DISABLE, ioaddr + NvRegTxPauseFrame );

	/* Set default link speed settings */
	priv->linkspeed = NVREG_LINKSPEED_FORCE | NVREG_LINKSPEED_10;
	priv->duplex = 0;

	if ( ( rc = register_netdev ( netdev ) ) != 0 ) {
		DBG ( "Error registering netdev\n" );
		goto err_register_netdev;
	}

	forcedeth_link_status ( netdev );

	return 0;

err_register_netdev:
err_setup_phy:
err_mac_addr:
	iounmap ( priv->mmio_addr );
err_map_regs:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
err_alloc_etherdev:
	return rc;
}

static void
nv_restore_phy ( struct forcedeth_private *priv )
{
	u16 phy_reserved, mii_control;

	if ( priv->phy_oui == PHY_OUI_REALTEK &&
	     priv->phy_model == PHY_MODEL_REALTEK_8201 ) {
		mii_rw ( priv, priv->phyaddr, PHY_REALTEK_INIT_REG1,
					      PHY_REALTEK_INIT3 );
		phy_reserved = mii_rw ( priv, priv->phyaddr,
					PHY_REALTEK_INIT_REG2, MII_READ );
		phy_reserved &= ~PHY_REALTEK_INIT_MSK1;
		phy_reserved |= PHY_REALTEK_INIT8;
		mii_rw ( priv, priv->phyaddr, PHY_REALTEK_INIT_REG2,
					      phy_reserved );
		mii_rw ( priv, priv->phyaddr, PHY_REALTEK_INIT_REG1,
					      PHY_REALTEK_INIT1 );

		/* restart auto negotiation */
		mii_control = mii_rw ( priv, priv->phyaddr, MII_BMCR, MII_READ );
		mii_control |= ( BMCR_ANRESTART | BMCR_ANENABLE );
		mii_rw ( priv, priv->phyaddr, MII_BMCR, mii_control );
	}
}

/**
 * remove - Device Removal Routine
 *
 * @v pdev PCI device information struct
 **/
static void
forcedeth_remove ( struct pci_device *pdev )
{
	struct net_device *netdev = pci_get_drvdata ( pdev );
	struct forcedeth_private *priv = netdev->priv;

	DBGP ( "forcedeth_remove\n" );

	unregister_netdev ( netdev );

	nv_restore_phy ( priv );

	nv_mgmt_release_sema ( priv );

	iounmap ( priv->mmio_addr );

	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

static struct pci_device_id forcedeth_nics[] = {
	PCI_ROM(0x10DE, 0x01C3, "nForce", "nForce Ethernet Controller", DEV_NEED_TIMERIRQ|DEV_NEED_LINKTIMER),
	PCI_ROM(0x10DE, 0x0066, "nForce2", "nForce2 Ethernet Controller", DEV_NEED_TIMERIRQ|DEV_NEED_LINKTIMER),
	PCI_ROM(0x10DE, 0x00D6, "nForce3", "nForce3 Ethernet Controller", DEV_NEED_TIMERIRQ|DEV_NEED_LINKTIMER),
	PCI_ROM(0x10DE, 0x0086, "nForce3", "nForce3 Ethernet Controller", DEV_NEED_TIMERIRQ|DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC| DEV_HAS_CHECKSUM),
	PCI_ROM(0x10DE, 0x008C, "nForce3", "nForce3 Ethernet Controller", DEV_NEED_TIMERIRQ|DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC| DEV_HAS_CHECKSUM),
	PCI_ROM(0x10DE, 0x00E6, "nForce3", "nForce3 Ethernet Controller", DEV_NEED_TIMERIRQ|DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC| DEV_HAS_CHECKSUM),
	PCI_ROM(0x10DE, 0x00DF, "nForce3", "nForce3 Ethernet Controller", DEV_NEED_TIMERIRQ|DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC| DEV_HAS_CHECKSUM),
	PCI_ROM(0x10DE, 0x0056, "CK804", "CK804 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_STATISTICS_V1|DEV_NEED_TX_LIMIT),
	PCI_ROM(0x10DE, 0x0057, "CK804", "CK804 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_STATISTICS_V1|DEV_NEED_TX_LIMIT),
	PCI_ROM(0x10DE, 0x0037, "MCP04", "MCP04 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_STATISTICS_V1|DEV_NEED_TX_LIMIT),
	PCI_ROM(0x10DE, 0x0038, "MCP04", "MCP04 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_STATISTICS_V1|DEV_NEED_TX_LIMIT),
	PCI_ROM(0x10DE, 0x0268, "MCP51", "MCP51 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_STATISTICS_V1|DEV_NEED_LOW_POWER_FIX),
	PCI_ROM(0x10DE, 0x0269, "MCP51", "MCP51 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_STATISTICS_V1|DEV_NEED_LOW_POWER_FIX),
	PCI_ROM(0x10DE, 0x0372, "MCP55", "MCP55 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_VLAN|DEV_HAS_MSI|DEV_HAS_MSI_X| DEV_HAS_POWER_CNTRL|DEV_HAS_PAUSEFRAME_TX_V1| DEV_HAS_STATISTICS_V2|DEV_HAS_TEST_EXTENDED| DEV_HAS_MGMT_UNIT|DEV_NEED_TX_LIMIT|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0373, "MCP55", "MCP55 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_VLAN|DEV_HAS_MSI|DEV_HAS_MSI_X| DEV_HAS_POWER_CNTRL|DEV_HAS_PAUSEFRAME_TX_V1| DEV_HAS_STATISTICS_V2|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_NEED_TX_LIMIT|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x03E5, "MCP61", "MCP61 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x03E6, "MCP61", "MCP61 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x03EE, "MCP61", "MCP61 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x03EF, "MCP61", "MCP61 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0450, "MCP65", "MCP65 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_HIGH_DMA| DEV_HAS_POWER_CNTRL|DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1| DEV_HAS_STATISTICS_V2|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_HAS_CORRECT_MACADDR|DEV_NEED_TX_LIMIT|DEV_HAS_GEAR_MODE| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0451, "MCP65", "MCP65 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_HIGH_DMA| DEV_HAS_POWER_CNTRL|DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1| DEV_HAS_STATISTICS_V2|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_HAS_CORRECT_MACADDR|DEV_NEED_TX_LIMIT|DEV_HAS_GEAR_MODE| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0452, "MCP65", "MCP65 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_HIGH_DMA| DEV_HAS_POWER_CNTRL|DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1| DEV_HAS_STATISTICS_V2|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_HAS_CORRECT_MACADDR|DEV_NEED_TX_LIMIT|DEV_HAS_GEAR_MODE| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0453, "MCP65", "MCP65 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_HIGH_DMA| DEV_HAS_POWER_CNTRL|DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1| DEV_HAS_STATISTICS_V2|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_HAS_CORRECT_MACADDR|DEV_NEED_TX_LIMIT|DEV_HAS_GEAR_MODE| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x054C, "MCP67", "MCP67 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_HAS_GEAR_MODE|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x054D, "MCP67", "MCP67 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_HAS_GEAR_MODE|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x054E, "MCP67", "MCP67 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_HAS_GEAR_MODE|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x054F, "MCP67", "MCP67 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_HAS_GEAR_MODE|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x07DC, "MCP73", "MCP73 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_HAS_GEAR_MODE|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x07DD, "MCP73", "MCP73 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_HAS_GEAR_MODE|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x07DE, "MCP73", "MCP73 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_HAS_GEAR_MODE|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x07DF, "MCP73", "MCP73 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_HIGH_DMA|DEV_HAS_POWER_CNTRL| DEV_HAS_MSI|DEV_HAS_PAUSEFRAME_TX_V1|DEV_HAS_STATISTICS_V2| DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_HAS_GEAR_MODE|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0760, "MCP77", "MCP77 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_CHECKSUM|DEV_HAS_HIGH_DMA| DEV_HAS_MSI|DEV_HAS_POWER_CNTRL|DEV_HAS_PAUSEFRAME_TX_V2| DEV_HAS_STATISTICS_V3|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_HAS_CORRECT_MACADDR|DEV_HAS_COLLISION_FIX| DEV_NEED_TX_LIMIT2|DEV_HAS_GEAR_MODE|DEV_NEED_PHY_INIT_FIX| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0761, "MCP77", "MCP77 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_CHECKSUM|DEV_HAS_HIGH_DMA| DEV_HAS_MSI|DEV_HAS_POWER_CNTRL|DEV_HAS_PAUSEFRAME_TX_V2| DEV_HAS_STATISTICS_V3|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_HAS_CORRECT_MACADDR|DEV_HAS_COLLISION_FIX| DEV_NEED_TX_LIMIT2|DEV_HAS_GEAR_MODE|DEV_NEED_PHY_INIT_FIX| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0762, "MCP77", "MCP77 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_CHECKSUM|DEV_HAS_HIGH_DMA| DEV_HAS_MSI|DEV_HAS_POWER_CNTRL|DEV_HAS_PAUSEFRAME_TX_V2| DEV_HAS_STATISTICS_V3|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_HAS_CORRECT_MACADDR|DEV_HAS_COLLISION_FIX| DEV_NEED_TX_LIMIT2|DEV_HAS_GEAR_MODE|DEV_NEED_PHY_INIT_FIX| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0763, "MCP77", "MCP77 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_CHECKSUM|DEV_HAS_HIGH_DMA| DEV_HAS_MSI|DEV_HAS_POWER_CNTRL|DEV_HAS_PAUSEFRAME_TX_V2| DEV_HAS_STATISTICS_V3|DEV_HAS_TEST_EXTENDED|DEV_HAS_MGMT_UNIT| DEV_HAS_CORRECT_MACADDR|DEV_HAS_COLLISION_FIX| DEV_NEED_TX_LIMIT2|DEV_HAS_GEAR_MODE|DEV_NEED_PHY_INIT_FIX| DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0AB0, "MCP79", "MCP79 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_MSI|DEV_HAS_POWER_CNTRL| DEV_HAS_PAUSEFRAME_TX_V3|DEV_HAS_STATISTICS_V3| DEV_HAS_TEST_EXTENDED|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_NEED_TX_LIMIT2|DEV_HAS_GEAR_MODE| DEV_NEED_PHY_INIT_FIX|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0AB1, "MCP79", "MCP79 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_MSI|DEV_HAS_POWER_CNTRL| DEV_HAS_PAUSEFRAME_TX_V3|DEV_HAS_STATISTICS_V3| DEV_HAS_TEST_EXTENDED|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_NEED_TX_LIMIT2|DEV_HAS_GEAR_MODE| DEV_NEED_PHY_INIT_FIX|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0AB2, "MCP79", "MCP79 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_MSI|DEV_HAS_POWER_CNTRL| DEV_HAS_PAUSEFRAME_TX_V3|DEV_HAS_STATISTICS_V3| DEV_HAS_TEST_EXTENDED|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_NEED_TX_LIMIT2|DEV_HAS_GEAR_MODE| DEV_NEED_PHY_INIT_FIX|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0AB3, "MCP79", "MCP79 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_MSI|DEV_HAS_POWER_CNTRL| DEV_HAS_PAUSEFRAME_TX_V3|DEV_HAS_STATISTICS_V3| DEV_HAS_TEST_EXTENDED|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_NEED_TX_LIMIT2|DEV_HAS_GEAR_MODE| DEV_NEED_PHY_INIT_FIX|DEV_NEED_MSI_FIX),
	PCI_ROM(0x10DE, 0x0D7D, "MCP89", "MCP89 Ethernet Controller", DEV_NEED_LINKTIMER|DEV_HAS_LARGEDESC|DEV_HAS_CHECKSUM| DEV_HAS_HIGH_DMA|DEV_HAS_MSI|DEV_HAS_POWER_CNTRL| DEV_HAS_PAUSEFRAME_TX_V3|DEV_HAS_STATISTICS_V3| DEV_HAS_TEST_EXTENDED|DEV_HAS_CORRECT_MACADDR| DEV_HAS_COLLISION_FIX|DEV_HAS_GEAR_MODE|DEV_NEED_PHY_INIT_FIX),
};

struct pci_driver forcedeth_driver __pci_driver = {
	.ids		= forcedeth_nics,
	.id_count	= ARRAY_SIZE(forcedeth_nics),
	.probe		= forcedeth_probe,
	.remove		= forcedeth_remove,
};
