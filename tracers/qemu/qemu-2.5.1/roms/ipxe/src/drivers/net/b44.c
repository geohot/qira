/*
 * Copyright (c) 2008 Stefan Hajnoczi <stefanha@gmail.com>
 * Copyright (c) 2008 Pantelis Koukousoulas <pktoss@gmail.com>
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
 * This driver is a port of the b44 linux driver version 1.01
 *
 * Copyright (c) 2002 David S. Miller <davem@redhat.com>
 * Copyright (c) Pekka Pietikainen <pp@ee.oulu.fi>
 * Copyright (C) 2006 Broadcom Corporation.
 *
 * Some ssb bits copied from version 2.0 of the b44 driver
 * Copyright (c) Michael Buesch
 *
 * Copyright (c) a lot of people too. Please respect their work.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/io.h>
#include <mii.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include "b44.h"


static inline int ring_next(int index)
{
	/* B44_RING_SIZE is a power of 2 :) */
	return (index + 1) & (B44_RING_SIZE - 1);
}


/* Memory-mapped I/O wrappers */

static inline u32 br32(const struct b44_private *bp, u32 reg)
{
	return readl(bp->regs + reg);
}


static inline void bw32(const struct b44_private *bp, u32 reg, u32 val)
{
	writel(val, bp->regs + reg);
}


static inline void bflush(const struct b44_private *bp, u32 reg, u32 timeout)
{
	readl(bp->regs + reg);
	udelay(timeout);
}


#define VIRT_TO_B44(addr)	( virt_to_bus(addr) + SB_PCI_DMA )


/**
 * Check if card can access address
 *
 * @v address		Virtual address
 * @v address_ok	Card can access address
 */
static inline __attribute__ (( always_inline )) int
b44_address_ok ( void *address ) {

	/* Card can address anything with a 30-bit address */
	if ( ( virt_to_bus ( address ) & ~B44_30BIT_DMA_MASK ) == 0 )
		return 1;

	return 0;
}

/**
 * Ring cells waiting to be processed are between 'tx_cur' and 'pending'
 * indexes in the ring.
 */
static u32 pending_tx_index(struct b44_private *bp)
{
	u32 pending = br32(bp, B44_DMATX_STAT);
	pending &= DMATX_STAT_CDMASK;

	pending /= sizeof(struct dma_desc);
	return pending & (B44_RING_SIZE - 1);
}


/**
 * Ring cells waiting to be processed are between 'rx_cur' and 'pending'
 * indexes in the ring.
 */
static u32 pending_rx_index(struct b44_private *bp)
{
	u32 pending = br32(bp, B44_DMARX_STAT);
	pending &= DMARX_STAT_CDMASK;

	pending /= sizeof(struct dma_desc);
	return pending & (B44_RING_SIZE - 1);
}


/**
 * Wait until the given bit is set/cleared.
 */
static int b44_wait_bit(struct b44_private *bp, unsigned long reg, u32 bit,
			            unsigned long timeout, const int clear)
{
	unsigned long i;

	for (i = 0; i < timeout; i++) {
		u32 val = br32(bp, reg);

		if (clear && !(val & bit))
			break;

		if (!clear && (val & bit))
			break;

		udelay(10);
	}
	if (i == timeout) {
		return -ENODEV;
	}
	return 0;
}


/*
 * Sonics Silicon Backplane support. SSB is a mini-bus interconnecting
 * so-called IP Cores. One of those cores implements the Fast Ethernet
 * functionality and another one the PCI engine.
 *
 * You need to switch to the core you want to talk to before actually
 * sending commands.
 *
 * See: http://bcm-v4.sipsolutions.net/Backplane for (reverse-engineered)
 * specs.
 */

static inline u32 ssb_get_core_rev(struct b44_private *bp)
{
	return (br32(bp, B44_SBIDHIGH) & SBIDHIGH_RC_MASK);
}


static inline int ssb_is_core_up(struct b44_private *bp)
{
	return ((br32(bp, B44_SBTMSLOW) & (SSB_CORE_DOWN | SBTMSLOW_CLOCK))
	                                                == SBTMSLOW_CLOCK);
}


static u32 ssb_pci_setup(struct b44_private *bp, u32 cores)
{
	u32 bar_orig, pci_rev, val;

	pci_read_config_dword(bp->pci, SSB_BAR0_WIN, &bar_orig);
	pci_write_config_dword(bp->pci, SSB_BAR0_WIN,
	                       BCM4400_PCI_CORE_ADDR);
	pci_rev = ssb_get_core_rev(bp);

	val = br32(bp, B44_SBINTVEC);
	val |= cores;
	bw32(bp, B44_SBINTVEC, val);

	val = br32(bp, SSB_PCI_TRANS_2);
	val |= SSB_PCI_PREF | SSB_PCI_BURST;
	bw32(bp, SSB_PCI_TRANS_2, val);

	pci_write_config_dword(bp->pci, SSB_BAR0_WIN, bar_orig);

	return pci_rev;
}


static void ssb_core_disable(struct b44_private *bp)
{
	if (br32(bp, B44_SBTMSLOW) & SBTMSLOW_RESET)
		return;

	bw32(bp, B44_SBTMSLOW, (SBTMSLOW_REJECT | SBTMSLOW_CLOCK));
	b44_wait_bit(bp, B44_SBTMSLOW, SBTMSLOW_REJECT, 100000, 0);
	b44_wait_bit(bp, B44_SBTMSHIGH, SBTMSHIGH_BUSY, 100000, 1);

	bw32(bp, B44_SBTMSLOW, (SBTMSLOW_FGC | SBTMSLOW_CLOCK |
	                                        SSB_CORE_DOWN));
	bflush(bp, B44_SBTMSLOW, 1);

	bw32(bp, B44_SBTMSLOW, SSB_CORE_DOWN);
	bflush(bp, B44_SBTMSLOW, 1);
}


static void ssb_core_reset(struct b44_private *bp)
{
	u32 val;
	const u32 mask = (SBTMSLOW_CLOCK | SBTMSLOW_FGC | SBTMSLOW_RESET);

	ssb_core_disable(bp);

	bw32(bp, B44_SBTMSLOW, mask);
	bflush(bp, B44_SBTMSLOW, 1);

	/* Clear SERR if set, this is a hw bug workaround.  */
	if (br32(bp, B44_SBTMSHIGH) & SBTMSHIGH_SERR)
		bw32(bp, B44_SBTMSHIGH, 0);

	val = br32(bp, B44_SBIMSTATE);
	if (val & (SBIMSTATE_BAD)) {
		bw32(bp, B44_SBIMSTATE, val & ~SBIMSTATE_BAD);
	}

	bw32(bp, B44_SBTMSLOW, (SBTMSLOW_CLOCK | SBTMSLOW_FGC));
	bflush(bp, B44_SBTMSLOW, 1);

	bw32(bp, B44_SBTMSLOW, (SBTMSLOW_CLOCK));
	bflush(bp, B44_SBTMSLOW, 1);
}


/*
 * Driver helper functions
 */

/*
 * Chip reset provides power to the b44 MAC & PCI cores, which
 * is necessary for MAC register access. We only do a partial
 * reset in case of transmit/receive errors (ISTAT_ERRORS) to
 * avoid the chip being hung for an unnecessary long time in
 * this case.
 *
 * Called-by: b44_close, b44_halt, b44_inithw(b44_open), b44_probe
 */
static void b44_chip_reset(struct b44_private *bp, int reset_kind)
{
	if (ssb_is_core_up(bp)) {
		bw32(bp, B44_RCV_LAZY, 0);

		bw32(bp, B44_ENET_CTRL, ENET_CTRL_DISABLE);

		b44_wait_bit(bp, B44_ENET_CTRL, ENET_CTRL_DISABLE, 200, 1);

		bw32(bp, B44_DMATX_CTRL, 0);

		bp->tx_dirty = bp->tx_cur = 0;

		if (br32(bp, B44_DMARX_STAT) & DMARX_STAT_EMASK)
			b44_wait_bit(bp, B44_DMARX_STAT, DMARX_STAT_SIDLE,
			                                          100, 0);

		bw32(bp, B44_DMARX_CTRL, 0);

		bp->rx_cur = 0;
	} else {
		ssb_pci_setup(bp, SBINTVEC_ENET0);
	}

	ssb_core_reset(bp);

	/* Don't enable PHY if we are only doing a partial reset. */
	if (reset_kind == B44_CHIP_RESET_PARTIAL)
		return;

	/* Make PHY accessible. */
	bw32(bp, B44_MDIO_CTRL,
	     (MDIO_CTRL_PREAMBLE | (0x0d & MDIO_CTRL_MAXF_MASK)));
	bflush(bp, B44_MDIO_CTRL, 1);

	/* Enable internal or external PHY */
	if (!(br32(bp, B44_DEVCTRL) & DEVCTRL_IPP)) {
		bw32(bp, B44_ENET_CTRL, ENET_CTRL_EPSEL);
		bflush(bp, B44_ENET_CTRL, 1);
	} else {
		u32 val = br32(bp, B44_DEVCTRL);
		if (val & DEVCTRL_EPR) {
			bw32(bp, B44_DEVCTRL, (val & ~DEVCTRL_EPR));
			bflush(bp, B44_DEVCTRL, 100);
		}
	}
}


/**
 * called by b44_poll in the error path
 */
static void b44_halt(struct b44_private *bp)
{
	/* disable ints */
	bw32(bp, B44_IMASK, 0);
	bflush(bp, B44_IMASK, 1);

	DBG("b44: powering down PHY\n");
	bw32(bp, B44_MAC_CTRL, MAC_CTRL_PHY_PDOWN);

	/*
	 * Now reset the chip, but without enabling
	 * the MAC&PHY part of it.
	 * This has to be done _after_ we shut down the PHY
	 */
	b44_chip_reset(bp, B44_CHIP_RESET_PARTIAL);
}



/*
 * Called at device open time to get the chip ready for
 * packet processing.
 *
 * Called-by: b44_open
 */
static void b44_init_hw(struct b44_private *bp, int reset_kind)
{
	u32 val;
#define CTRL_MASK (DMARX_CTRL_ENABLE | (RX_PKT_OFFSET << DMARX_CTRL_ROSHIFT))

	b44_chip_reset(bp, B44_CHIP_RESET_FULL);
	if (reset_kind == B44_FULL_RESET) {
		b44_phy_reset(bp);
	}

	/* Enable CRC32, set proper LED modes and power on PHY */
	bw32(bp, B44_MAC_CTRL, MAC_CTRL_CRC32_ENAB | MAC_CTRL_PHY_LEDCTRL);
	bw32(bp, B44_RCV_LAZY, (1 << RCV_LAZY_FC_SHIFT));

	/* This sets the MAC address too.  */
	b44_set_rx_mode(bp->netdev);

	/* MTU + eth header + possible VLAN tag + struct rx_header */
	bw32(bp, B44_RXMAXLEN, B44_MAX_MTU + ETH_HLEN + 8 + RX_HEADER_LEN);
	bw32(bp, B44_TXMAXLEN, B44_MAX_MTU + ETH_HLEN + 8 + RX_HEADER_LEN);

	bw32(bp, B44_TX_HIWMARK, TX_HIWMARK_DEFLT);
	if (reset_kind == B44_PARTIAL_RESET) {
		bw32(bp, B44_DMARX_CTRL, CTRL_MASK);
	} else {
		bw32(bp, B44_DMATX_CTRL, DMATX_CTRL_ENABLE);
		bw32(bp, B44_DMATX_ADDR, VIRT_TO_B44(bp->tx));

		bw32(bp, B44_DMARX_CTRL, CTRL_MASK);
		bw32(bp, B44_DMARX_ADDR, VIRT_TO_B44(bp->rx));
		bw32(bp, B44_DMARX_PTR, B44_RX_RING_LEN_BYTES);

		bw32(bp, B44_MIB_CTRL, MIB_CTRL_CLR_ON_READ);
	}

	val = br32(bp, B44_ENET_CTRL);
	bw32(bp, B44_ENET_CTRL, (val | ENET_CTRL_ENABLE));
#undef CTRL_MASK
}


/***  Management of ring descriptors  ***/


static void b44_populate_rx_descriptor(struct b44_private *bp, u32 idx)
{
	struct rx_header *rh;
	u32 ctrl, addr;

	rh = bp->rx_iobuf[idx]->data;
	rh->len = 0;
	rh->flags = 0;
	ctrl = DESC_CTRL_LEN & (RX_PKT_BUF_SZ - RX_PKT_OFFSET);
	if (idx == B44_RING_LAST) {
		ctrl |= DESC_CTRL_EOT;
	}
	addr = VIRT_TO_B44(bp->rx_iobuf[idx]->data);

	bp->rx[idx].ctrl = cpu_to_le32(ctrl);
	bp->rx[idx].addr = cpu_to_le32(addr);
	bw32(bp, B44_DMARX_PTR, idx * sizeof(struct dma_desc));
}


/*
 * Refill RX ring descriptors with buffers. This is needed
 * because during rx we are passing ownership of descriptor
 * buffers to the network stack.
 */
static void b44_rx_refill(struct b44_private *bp, u32 pending)
{
	struct io_buffer *iobuf;
	u32 i;

	// skip pending
	for (i = pending + 1; i != bp->rx_cur; i = ring_next(i)) {
		if (bp->rx_iobuf[i] != NULL)
			continue;

		iobuf = alloc_iob(RX_PKT_BUF_SZ);
		if (!iobuf) {
			DBG("Refill rx ring failed!!\n");
			break;
		}
		if (!b44_address_ok(iobuf->data)) {
			DBG("Refill rx ring bad address!!\n");
			free_iob(iobuf);
			break;
		}
		bp->rx_iobuf[i] = iobuf;

		b44_populate_rx_descriptor(bp, i);
	}
}


static void b44_free_rx_ring(struct b44_private *bp)
{
	u32 i;

	if (bp->rx) {
		for (i = 0; i < B44_RING_SIZE; i++) {
			free_iob(bp->rx_iobuf[i]);
			bp->rx_iobuf[i] = NULL;
		}
		free_dma(bp->rx, B44_RX_RING_LEN_BYTES);
		bp->rx = NULL;
	}
}


static int b44_init_rx_ring(struct b44_private *bp)
{
	b44_free_rx_ring(bp);

	bp->rx = malloc_dma(B44_RX_RING_LEN_BYTES, B44_DMA_ALIGNMENT);
	if (!bp->rx)
		return -ENOMEM;
	if (!b44_address_ok(bp->rx)) {
		free_dma(bp->rx, B44_RX_RING_LEN_BYTES);
		return -ENOTSUP;
	}

	memset(bp->rx_iobuf, 0, sizeof(bp->rx_iobuf));

	bp->rx_iobuf[0] = alloc_iob(RX_PKT_BUF_SZ);
	b44_populate_rx_descriptor(bp, 0);
	b44_rx_refill(bp, 0);

	DBG("Init RX rings: rx=0x%08lx\n", VIRT_TO_B44(bp->rx));
	return 0;
}


static void b44_free_tx_ring(struct b44_private *bp)
{
	if (bp->tx) {
		free_dma(bp->tx, B44_TX_RING_LEN_BYTES);
		bp->tx = NULL;
	}
}


static int b44_init_tx_ring(struct b44_private *bp)
{
	b44_free_tx_ring(bp);

	bp->tx = malloc_dma(B44_TX_RING_LEN_BYTES, B44_DMA_ALIGNMENT);
	if (!bp->tx)
		return -ENOMEM;
	if (!b44_address_ok(bp->tx)) {
		free_dma(bp->tx, B44_TX_RING_LEN_BYTES);
		return -ENOTSUP;
	}

	memset(bp->tx, 0, B44_TX_RING_LEN_BYTES);
	memset(bp->tx_iobuf, 0, sizeof(bp->tx_iobuf));

	DBG("Init TX rings: tx=0x%08lx\n", VIRT_TO_B44(bp->tx));
	return 0;
}


/*** Interaction with the PHY ***/


static int b44_phy_read(struct b44_private *bp, int reg, u32 * val)
{
	int err;

	u32 arg1 = (MDIO_OP_READ << MDIO_DATA_OP_SHIFT);
	u32 arg2 = (bp->phy_addr << MDIO_DATA_PMD_SHIFT);
	u32 arg3 = (reg << MDIO_DATA_RA_SHIFT);
	u32 arg4 = (MDIO_TA_VALID << MDIO_DATA_TA_SHIFT);
	u32 argv = arg1 | arg2 | arg3 | arg4;

	bw32(bp, B44_EMAC_ISTAT, EMAC_INT_MII);
	bw32(bp, B44_MDIO_DATA, (MDIO_DATA_SB_START | argv));
	err = b44_wait_bit(bp, B44_EMAC_ISTAT, EMAC_INT_MII, 100, 0);
	*val = br32(bp, B44_MDIO_DATA) & MDIO_DATA_DATA;

	return err;
}


static int b44_phy_write(struct b44_private *bp, int reg, u32 val)
{
	u32 arg1 = (MDIO_OP_WRITE << MDIO_DATA_OP_SHIFT);
	u32 arg2 = (bp->phy_addr << MDIO_DATA_PMD_SHIFT);
	u32 arg3 = (reg << MDIO_DATA_RA_SHIFT);
	u32 arg4 = (MDIO_TA_VALID << MDIO_DATA_TA_SHIFT);
	u32 arg5 = (val & MDIO_DATA_DATA);
	u32 argv = arg1 | arg2 | arg3 | arg4 | arg5;


	bw32(bp, B44_EMAC_ISTAT, EMAC_INT_MII);
	bw32(bp, B44_MDIO_DATA, (MDIO_DATA_SB_START | argv));
	return b44_wait_bit(bp, B44_EMAC_ISTAT, EMAC_INT_MII, 100, 0);
}


static int b44_phy_reset(struct b44_private *bp)
{
	u32 val;
	int err;

	err = b44_phy_write(bp, MII_BMCR, BMCR_RESET);
	if (err)
		return err;

	udelay(100);
	err = b44_phy_read(bp, MII_BMCR, &val);
	if (!err) {
		if (val & BMCR_RESET) {
			return -ENODEV;
		}
	}

	return 0;
}


/*
 * The BCM44xx CAM (Content Addressable Memory) stores the MAC
 * and PHY address.
 */
static void b44_cam_write(struct b44_private *bp, unsigned char *data,
			                                    int index)
{
	u32 val;

	val  = ((u32) data[2]) << 24;
	val |= ((u32) data[3]) << 16;
	val |= ((u32) data[4]) << 8;
	val |= ((u32) data[5]) << 0;
	bw32(bp, B44_CAM_DATA_LO, val);


	val = (CAM_DATA_HI_VALID |
	       (((u32) data[0]) << 8) | (((u32) data[1]) << 0));

	bw32(bp, B44_CAM_DATA_HI, val);

	val = CAM_CTRL_WRITE | (index << CAM_CTRL_INDEX_SHIFT);
	bw32(bp, B44_CAM_CTRL, val);

	b44_wait_bit(bp, B44_CAM_CTRL, CAM_CTRL_BUSY, 100, 1);
}


static void b44_set_mac_addr(struct b44_private *bp)
{
	u32 val;
	bw32(bp, B44_CAM_CTRL, 0);
	b44_cam_write(bp, bp->netdev->ll_addr, 0);
	val = br32(bp, B44_CAM_CTRL);
	bw32(bp, B44_CAM_CTRL, val | CAM_CTRL_ENABLE);
}


/* Read 128-bytes of EEPROM. */
static void b44_read_eeprom(struct b44_private *bp, u8 * data)
{
	long i;
	u16 *ptr = (u16 *) data;

	for (i = 0; i < 128; i += 2)
		ptr[i / 2] = cpu_to_le16(readw(bp->regs + 4096 + i));
}


static void b44_load_mac_and_phy_addr(struct b44_private *bp)
{
	u8 eeprom[128];

	/* Load MAC address, note byteswapping */
	b44_read_eeprom(bp, &eeprom[0]);
	bp->netdev->hw_addr[0] = eeprom[79];
	bp->netdev->hw_addr[1] = eeprom[78];
	bp->netdev->hw_addr[2] = eeprom[81];
	bp->netdev->hw_addr[3] = eeprom[80];
	bp->netdev->hw_addr[4] = eeprom[83];
	bp->netdev->hw_addr[5] = eeprom[82];

	/* Load PHY address */
	bp->phy_addr = eeprom[90] & 0x1f;
}


static void b44_set_rx_mode(struct net_device *netdev)
{
	struct b44_private *bp = netdev_priv(netdev);
	unsigned char zero[6] = { 0, 0, 0, 0, 0, 0 };
	u32 val;
	int i;

	val = br32(bp, B44_RXCONFIG);
	val &= ~RXCONFIG_PROMISC;
	val |= RXCONFIG_ALLMULTI;

	b44_set_mac_addr(bp);

	for (i = 1; i < 64; i++)
		b44_cam_write(bp, zero, i);

	bw32(bp, B44_RXCONFIG, val);
	val = br32(bp, B44_CAM_CTRL);
	bw32(bp, B44_CAM_CTRL, val | CAM_CTRL_ENABLE);
}


/*** Implementation of iPXE driver callbacks ***/

/**
 * Probe device
 *
 * @v pci	PCI device
 * @v id	Matching entry in ID table
 * @ret rc	Return status code
 */
static int b44_probe(struct pci_device *pci)
{
	struct net_device *netdev;
	struct b44_private *bp;
	int rc;

	/* Set up netdev */
	netdev = alloc_etherdev(sizeof(*bp));
	if (!netdev)
		return -ENOMEM;

	netdev_init(netdev, &b44_operations);
	pci_set_drvdata(pci, netdev);
	netdev->dev = &pci->dev;

	/* Set up private data */
	bp = netdev_priv(netdev);
	memset(bp, 0, sizeof(*bp));
	bp->netdev = netdev;
	bp->pci = pci;

	/* Map device registers */
	bp->regs = ioremap(pci->membase, B44_REGS_SIZE);
	if (!bp->regs) {
		netdev_put(netdev);
		return -ENOMEM;
	}

	/* Enable PCI bus mastering */
	adjust_pci_device(pci);

	b44_load_mac_and_phy_addr(bp);

	rc = register_netdev(netdev);
	if (rc != 0) {
		iounmap(bp->regs);
		netdev_put(netdev);
		return rc;
	}

	/* Link management currently not implemented */
	netdev_link_up(netdev);

	b44_chip_reset(bp, B44_CHIP_RESET_FULL);

	DBG("b44 %s (%04x:%04x) regs=%p MAC=%s\n", pci->id->name,
	    pci->id->vendor, pci->id->device, bp->regs,
	    eth_ntoa(netdev->ll_addr));

	return 0;
}


/**
 * Remove device
 *
 * @v pci	PCI device
 */
static void b44_remove(struct pci_device *pci)
{
	struct net_device *netdev = pci_get_drvdata(pci);
	struct b44_private *bp = netdev_priv(netdev);

	ssb_core_disable(bp);
	unregister_netdev(netdev);
	iounmap(bp->regs);
	netdev_nullify(netdev);
	netdev_put(netdev);
}


/** Enable or disable interrupts
 *
 * @v netdev	Network device
 * @v enable	Interrupts should be enabled
 */
static void b44_irq(struct net_device *netdev, int enable)
{
	struct b44_private *bp = netdev_priv(netdev);

	/* Interrupt mask specifies which events generate interrupts */
	bw32(bp, B44_IMASK, enable ? IMASK_DEF : IMASK_DISABLE);
}


/** Open network device
 *
 * @v netdev	Network device
 * @ret rc	Return status code
 */
static int b44_open(struct net_device *netdev)
{
	struct b44_private *bp = netdev_priv(netdev);
	int rc;

	rc = b44_init_tx_ring(bp);
	if (rc != 0)
		return rc;

	rc = b44_init_rx_ring(bp);
	if (rc != 0)
		return rc;

	b44_init_hw(bp, B44_FULL_RESET);

	/* Disable interrupts */
	b44_irq(netdev, 0);

	return 0;
}


/** Close network device
 *
 * @v netdev	Network device
 */
static void b44_close(struct net_device *netdev)
{
	struct b44_private *bp = netdev_priv(netdev);

	b44_chip_reset(bp, B44_FULL_RESET);
	b44_free_tx_ring(bp);
	b44_free_rx_ring(bp);
}


/** Transmit packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 * @ret rc	Return status code
 */
static int b44_transmit(struct net_device *netdev, struct io_buffer *iobuf)
{
	struct b44_private *bp = netdev_priv(netdev);
	u32 cur = bp->tx_cur;
	u32 ctrl;

	/* Check for TX ring overflow */
	if (bp->tx[cur].ctrl) {
		DBG("tx overflow\n");
		return -ENOBUFS;
	}

	/* Check for addressability */
	if (!b44_address_ok(iobuf->data))
		return -ENOTSUP;

	/* Will call netdev_tx_complete() on the iobuf later */
	bp->tx_iobuf[cur] = iobuf;

	/* Set up TX descriptor */
	ctrl = (iob_len(iobuf) & DESC_CTRL_LEN) |
	    DESC_CTRL_IOC | DESC_CTRL_SOF | DESC_CTRL_EOF;

	if (cur == B44_RING_LAST)
		ctrl |= DESC_CTRL_EOT;

	bp->tx[cur].ctrl = cpu_to_le32(ctrl);
	bp->tx[cur].addr = cpu_to_le32(VIRT_TO_B44(iobuf->data));

	/* Update next available descriptor index */
	cur = ring_next(cur);
	bp->tx_cur = cur;
	wmb();

	/* Tell card that a new TX descriptor is ready */
	bw32(bp, B44_DMATX_PTR, cur * sizeof(struct dma_desc));
	return 0;
}


/** Recycles sent TX descriptors and notifies network stack
 *
 * @v bp Driver state
 */
static void b44_tx_complete(struct b44_private *bp)
{
	u32 cur, i;

	cur = pending_tx_index(bp);

	for (i = bp->tx_dirty; i != cur; i = ring_next(i)) {
		/* Free finished frame */
		netdev_tx_complete(bp->netdev, bp->tx_iobuf[i]);
		bp->tx_iobuf[i] = NULL;

		/* Clear TX descriptor */
		bp->tx[i].ctrl = 0;
		bp->tx[i].addr = 0;
	}
	bp->tx_dirty = cur;
}


static void b44_process_rx_packets(struct b44_private *bp)
{
	struct io_buffer *iob;	/* received data */
	struct rx_header *rh;
	u32 pending, i;
	u16 len;

	pending = pending_rx_index(bp);

	for (i = bp->rx_cur; i != pending; i = ring_next(i)) {
		iob = bp->rx_iobuf[i];
		if (iob == NULL)
			break;

		rh = iob->data;
		len = le16_to_cpu(rh->len);

		/*
		 * Guard against incompletely written RX descriptors.
		 * Without this, things can get really slow!
		 */
		if (len == 0)
			break;

		/* Discard CRC that is generated by the card */
		len -= 4;

		/* Check for invalid packets and errors */
		if (len > RX_PKT_BUF_SZ - RX_PKT_OFFSET ||
		    (rh->flags & cpu_to_le16(RX_FLAG_ERRORS))) {
			DBG("rx error len=%d flags=%04x\n", len,
			                 cpu_to_le16(rh->flags));
			rh->len = 0;
			rh->flags = 0;
			netdev_rx_err(bp->netdev, iob, -EINVAL);
			continue;
		}

		/* Clear RX descriptor */
		rh->len = 0;
		rh->flags = 0;
		bp->rx_iobuf[i] = NULL;

		/* Hand off the IO buffer to the network stack */
		iob_reserve(iob, RX_PKT_OFFSET);
		iob_put(iob, len);
		netdev_rx(bp->netdev, iob);
	}
	bp->rx_cur = i;
	b44_rx_refill(bp, pending_rx_index(bp));
}


/** Poll for completed and received packets
 *
 * @v netdev	Network device
 */
static void b44_poll(struct net_device *netdev)
{
	struct b44_private *bp = netdev_priv(netdev);
	u32 istat;

	/* Interrupt status */
	istat = br32(bp, B44_ISTAT);
	istat &= IMASK_DEF;	/* only the events we care about */

	if (!istat)
		return;
	if (istat & ISTAT_TX)
		b44_tx_complete(bp);
	if (istat & ISTAT_RX)
		b44_process_rx_packets(bp);
	if (istat & ISTAT_ERRORS) {
		DBG("b44 error istat=0x%08x\n", istat);

		/* Reset B44 core partially to avoid long waits */
		b44_irq(bp->netdev, 0);
		b44_halt(bp);
		b44_init_tx_ring(bp);
		b44_init_rx_ring(bp);
		b44_init_hw(bp, B44_FULL_RESET_SKIP_PHY);
	}

	/* Acknowledge interrupt */
	bw32(bp, B44_ISTAT, 0);
	bflush(bp, B44_ISTAT, 1);
}


static struct net_device_operations b44_operations = {
	.open = b44_open,
	.close = b44_close,
	.transmit = b44_transmit,
	.poll = b44_poll,
	.irq = b44_irq,
};


static struct pci_device_id b44_nics[] = {
	PCI_ROM(0x14e4, 0x4401, "BCM4401", "BCM4401", 0),
	PCI_ROM(0x14e4, 0x170c, "BCM4401-B0", "BCM4401-B0", 0),
	PCI_ROM(0x14e4, 0x4402, "BCM4401-B1", "BCM4401-B1", 0),
};


struct pci_driver b44_driver __pci_driver = {
	.ids = b44_nics,
	.id_count = sizeof b44_nics / sizeof b44_nics[0],
	.probe = b44_probe,
	.remove = b44_remove,
};
