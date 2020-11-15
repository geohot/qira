/*
 * iPXE driver for Marvell Yukon chipset and SysKonnect Gigabit
 * Ethernet adapters. Derived from Linux skge driver (v1.13), which was
 * based on earlier sk98lin, e100 and FreeBSD if_sk drivers.
 *
 * This driver intentionally does not support all the features of the
 * original driver such as link fail-over and link management because
 * those should be done at higher levels.
 *
 * Copyright (C) 2004, 2005 Stephen Hemminger <shemminger@osdl.org>
 *
 * Modified for iPXE, July 2008 by Michael Decker <mrd999@gmail.com>
 * Tested and Modified in December 2009 by
 *    Thomas Miletich <thomas.miletich@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_ONLY );

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>

#include "skge.h"

static struct pci_device_id skge_id_table[] = {
	PCI_ROM(0x10b7, 0x1700,     "3C940",     "3COM 3C940", 0),
	PCI_ROM(0x10b7, 0x80eb,     "3C940B",    "3COM 3C940", 0),
	PCI_ROM(0x1148, 0x4300,     "GE",        "Syskonnect GE", 0),
	PCI_ROM(0x1148, 0x4320,     "YU",        "Syskonnect YU", 0),
	PCI_ROM(0x1186, 0x4C00,     "DGE510T",   "DLink DGE-510T", 0),
	PCI_ROM(0x1186, 0x4b01,     "DGE530T",   "DLink DGE-530T", 0),
	PCI_ROM(0x11ab, 0x4320,     "id4320",    "Marvell id4320", 0),
	PCI_ROM(0x11ab, 0x5005,     "id5005",    "Marvell id5005", 0), /* Belkin */
	PCI_ROM(0x1371, 0x434e,     "Gigacard",  "CNET Gigacard", 0),
	PCI_ROM(0x1737, 0x1064,     "EG1064",    "Linksys EG1064", 0),
	PCI_ROM(0x1737, 0xffff,     "id_any",    "Linksys [any]", 0)
};

static int skge_up(struct net_device *dev);
static void skge_down(struct net_device *dev);
static void skge_tx_clean(struct net_device *dev);
static int xm_phy_write(struct skge_hw *hw, int port, u16 reg, u16 val);
static int gm_phy_write(struct skge_hw *hw, int port, u16 reg, u16 val);
static void yukon_init(struct skge_hw *hw, int port);
static void genesis_mac_init(struct skge_hw *hw, int port);
static void genesis_link_up(struct skge_port *skge);

static void skge_phyirq(struct skge_hw *hw);
static void skge_poll(struct net_device *dev);
static int skge_xmit_frame(struct net_device *dev, struct io_buffer *iob);
static void skge_net_irq ( struct net_device *dev, int enable );

static void skge_rx_refill(struct net_device *dev);

static struct net_device_operations skge_operations = {
	.open     = skge_up,
	.close    = skge_down,
	.transmit = skge_xmit_frame,
	.poll     = skge_poll,
	.irq      = skge_net_irq
};

/* Avoid conditionals by using array */
static const int txqaddr[] = { Q_XA1, Q_XA2 };
static const int rxqaddr[] = { Q_R1, Q_R2 };
static const u32 rxirqmask[] = { IS_R1_F, IS_R2_F };
static const u32 txirqmask[] = { IS_XA1_F, IS_XA2_F };
static const u32 napimask[] = { IS_R1_F|IS_XA1_F, IS_R2_F|IS_XA2_F };
static const u32 portmask[] = { IS_PORT_1, IS_PORT_2 };

/* Determine supported/advertised modes based on hardware.
 * Note: ethtool ADVERTISED_xxx == SUPPORTED_xxx
 */
static u32 skge_supported_modes(const struct skge_hw *hw)
{
	u32 supported;

	if (hw->copper) {
		supported = SUPPORTED_10baseT_Half
			| SUPPORTED_10baseT_Full
			| SUPPORTED_100baseT_Half
			| SUPPORTED_100baseT_Full
			| SUPPORTED_1000baseT_Half
			| SUPPORTED_1000baseT_Full
			| SUPPORTED_Autoneg| SUPPORTED_TP;

		if (hw->chip_id == CHIP_ID_GENESIS)
			supported &= ~(SUPPORTED_10baseT_Half
					     | SUPPORTED_10baseT_Full
					     | SUPPORTED_100baseT_Half
					     | SUPPORTED_100baseT_Full);

		else if (hw->chip_id == CHIP_ID_YUKON)
			supported &= ~SUPPORTED_1000baseT_Half;
	} else
		supported = SUPPORTED_1000baseT_Full | SUPPORTED_1000baseT_Half
			| SUPPORTED_FIBRE | SUPPORTED_Autoneg;

	return supported;
}

/* Chip internal frequency for clock calculations */
static inline u32 hwkhz(const struct skge_hw *hw)
{
	return (hw->chip_id == CHIP_ID_GENESIS) ? 53125 : 78125;
}

/* Microseconds to chip HZ */
static inline u32 skge_usecs2clk(const struct skge_hw *hw, u32 usec)
{
	return hwkhz(hw) * usec / 1000;
}

enum led_mode { LED_MODE_OFF, LED_MODE_ON, LED_MODE_TST };
static void skge_led(struct skge_port *skge, enum led_mode mode)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;

	if (hw->chip_id == CHIP_ID_GENESIS) {
		switch (mode) {
		case LED_MODE_OFF:
			if (hw->phy_type == SK_PHY_BCOM)
				xm_phy_write(hw, port, PHY_BCOM_P_EXT_CTRL, PHY_B_PEC_LED_OFF);
			else {
				skge_write32(hw, SK_REG(port, TX_LED_VAL), 0);
				skge_write8(hw, SK_REG(port, TX_LED_CTRL), LED_T_OFF);
			}
			skge_write8(hw, SK_REG(port, LNK_LED_REG), LINKLED_OFF);
			skge_write32(hw, SK_REG(port, RX_LED_VAL), 0);
			skge_write8(hw, SK_REG(port, RX_LED_CTRL), LED_T_OFF);
			break;

		case LED_MODE_ON:
			skge_write8(hw, SK_REG(port, LNK_LED_REG), LINKLED_ON);
			skge_write8(hw, SK_REG(port, LNK_LED_REG), LINKLED_LINKSYNC_ON);

			skge_write8(hw, SK_REG(port, RX_LED_CTRL), LED_START);
			skge_write8(hw, SK_REG(port, TX_LED_CTRL), LED_START);

			break;

		case LED_MODE_TST:
			skge_write8(hw, SK_REG(port, RX_LED_TST), LED_T_ON);
			skge_write32(hw, SK_REG(port, RX_LED_VAL), 100);
			skge_write8(hw, SK_REG(port, RX_LED_CTRL), LED_START);

			if (hw->phy_type == SK_PHY_BCOM)
				xm_phy_write(hw, port, PHY_BCOM_P_EXT_CTRL, PHY_B_PEC_LED_ON);
			else {
				skge_write8(hw, SK_REG(port, TX_LED_TST), LED_T_ON);
				skge_write32(hw, SK_REG(port, TX_LED_VAL), 100);
				skge_write8(hw, SK_REG(port, TX_LED_CTRL), LED_START);
			}

		}
	} else {
		switch (mode) {
		case LED_MODE_OFF:
			gm_phy_write(hw, port, PHY_MARV_LED_CTRL, 0);
			gm_phy_write(hw, port, PHY_MARV_LED_OVER,
				     PHY_M_LED_MO_DUP(MO_LED_OFF)  |
				     PHY_M_LED_MO_10(MO_LED_OFF)   |
				     PHY_M_LED_MO_100(MO_LED_OFF)  |
				     PHY_M_LED_MO_1000(MO_LED_OFF) |
				     PHY_M_LED_MO_RX(MO_LED_OFF));
			break;
		case LED_MODE_ON:
			gm_phy_write(hw, port, PHY_MARV_LED_CTRL,
				     PHY_M_LED_PULS_DUR(PULS_170MS) |
				     PHY_M_LED_BLINK_RT(BLINK_84MS) |
				     PHY_M_LEDC_TX_CTRL |
				     PHY_M_LEDC_DP_CTRL);

			gm_phy_write(hw, port, PHY_MARV_LED_OVER,
				     PHY_M_LED_MO_RX(MO_LED_OFF) |
				     (skge->speed == SPEED_100 ?
				      PHY_M_LED_MO_100(MO_LED_ON) : 0));
			break;
		case LED_MODE_TST:
			gm_phy_write(hw, port, PHY_MARV_LED_CTRL, 0);
			gm_phy_write(hw, port, PHY_MARV_LED_OVER,
				     PHY_M_LED_MO_DUP(MO_LED_ON)  |
				     PHY_M_LED_MO_10(MO_LED_ON)   |
				     PHY_M_LED_MO_100(MO_LED_ON)  |
				     PHY_M_LED_MO_1000(MO_LED_ON) |
				     PHY_M_LED_MO_RX(MO_LED_ON));
		}
	}
}

/*
 * I've left in these EEPROM and VPD functions, as someone may desire to
 * integrate them in the future. -mdeck
 *
 * static int skge_get_eeprom_len(struct net_device *dev)
 * {
 * 	struct skge_port *skge = netdev_priv(dev);
 * 	u32 reg2;
 *
 * 	pci_read_config_dword(skge->hw->pdev, PCI_DEV_REG2, &reg2);
 * 	return 1 << ( ((reg2 & PCI_VPD_ROM_SZ) >> 14) + 8);
 * }
 *
 * static u32 skge_vpd_read(struct pci_dev *pdev, int cap, u16 offset)
 * {
 * 	u32 val;
 *
 * 	pci_write_config_word(pdev, cap + PCI_VPD_ADDR, offset);
 *
 * 	do {
 * 		pci_read_config_word(pdev, cap + PCI_VPD_ADDR, &offset);
 * 	} while (!(offset & PCI_VPD_ADDR_F));
 *
 * 	pci_read_config_dword(pdev, cap + PCI_VPD_DATA, &val);
 * 	return val;
 * }
 *
 * static void skge_vpd_write(struct pci_dev *pdev, int cap, u16 offset, u32 val)
 * {
 * 	pci_write_config_dword(pdev, cap + PCI_VPD_DATA, val);
 * 	pci_write_config_word(pdev, cap + PCI_VPD_ADDR,
 * 			      offset | PCI_VPD_ADDR_F);
 *
 * 	do {
 * 		pci_read_config_word(pdev, cap + PCI_VPD_ADDR, &offset);
 * 	} while (offset & PCI_VPD_ADDR_F);
 * }
 *
 * static int skge_get_eeprom(struct net_device *dev, struct ethtool_eeprom *eeprom,
 * 			   u8 *data)
 * {
 * 	struct skge_port *skge = netdev_priv(dev);
 * 	struct pci_dev *pdev = skge->hw->pdev;
 * 	int cap = pci_find_capability(pdev, PCI_CAP_ID_VPD);
 * 	int length = eeprom->len;
 * 	u16 offset = eeprom->offset;
 *
 * 	if (!cap)
 * 		return -EINVAL;
 *
 * 	eeprom->magic = SKGE_EEPROM_MAGIC;
 *
 * 	while (length > 0) {
 * 		u32 val = skge_vpd_read(pdev, cap, offset);
 * 		int n = min_t(int, length, sizeof(val));
 *
 * 		memcpy(data, &val, n);
 * 		length -= n;
 * 		data += n;
 * 		offset += n;
 * 	}
 * 	return 0;
 * }
 *
 * static int skge_set_eeprom(struct net_device *dev, struct ethtool_eeprom *eeprom,
 * 			   u8 *data)
 * {
 * 	struct skge_port *skge = netdev_priv(dev);
 * 	struct pci_dev *pdev = skge->hw->pdev;
 * 	int cap = pci_find_capability(pdev, PCI_CAP_ID_VPD);
 * 	int length = eeprom->len;
 * 	u16 offset = eeprom->offset;
 *
 * 	if (!cap)
 * 		return -EINVAL;
 *
 * 	if (eeprom->magic != SKGE_EEPROM_MAGIC)
 * 		return -EINVAL;
 *
 * 	while (length > 0) {
 * 		u32 val;
 * 		int n = min_t(int, length, sizeof(val));
 *
 * 		if (n < sizeof(val))
 * 			val = skge_vpd_read(pdev, cap, offset);
 * 		memcpy(&val, data, n);
 *
 * 		skge_vpd_write(pdev, cap, offset, val);
 *
 * 		length -= n;
 * 		data += n;
 * 		offset += n;
 * 	}
 * 	return 0;
 * }
 */

/*
 * Allocate ring elements and chain them together
 * One-to-one association of board descriptors with ring elements
 */
static int skge_ring_alloc(struct skge_ring *ring, void *vaddr, u32 base,
                           size_t num)
{
	struct skge_tx_desc *d;
	struct skge_element *e;
	unsigned int i;

	ring->start = zalloc(num*sizeof(*e));
	if (!ring->start)
		return -ENOMEM;

	for (i = 0, e = ring->start, d = vaddr; i < num; i++, e++, d++) {
		e->desc = d;
		if (i == num - 1) {
			e->next = ring->start;
			d->next_offset = base;
		} else {
			e->next = e + 1;
			d->next_offset = base + (i+1) * sizeof(*d);
		}
	}
	ring->to_use = ring->to_clean = ring->start;

	return 0;
}

/* Allocate and setup a new buffer for receiving */
static void skge_rx_setup(struct skge_port *skge __unused,
			  struct skge_element *e,
			  struct io_buffer *iob, unsigned int bufsize)
{
	struct skge_rx_desc *rd = e->desc;
	u64 map;

	map = ( iob != NULL ) ? virt_to_bus(iob->data) : 0;

	rd->dma_lo = map;
	rd->dma_hi = map >> 32;
	e->iob = iob;
	rd->csum1_start = ETH_HLEN;
	rd->csum2_start = ETH_HLEN;
	rd->csum1 = 0;
	rd->csum2 = 0;

	wmb();

	rd->control = BMU_OWN | BMU_STF | BMU_IRQ_EOF | BMU_TCP_CHECK | bufsize;
}

/* Resume receiving using existing skb,
 * Note: DMA address is not changed by chip.
 * 	 MTU not changed while receiver active.
 */
static inline void skge_rx_reuse(struct skge_element *e, unsigned int size)
{
	struct skge_rx_desc *rd = e->desc;

	rd->csum2 = 0;
	rd->csum2_start = ETH_HLEN;

	wmb();

	rd->control = BMU_OWN | BMU_STF | BMU_IRQ_EOF | BMU_TCP_CHECK | size;
}


/* Free all  buffers in receive ring, assumes receiver stopped */
static void skge_rx_clean(struct skge_port *skge)
{
	struct skge_ring *ring = &skge->rx_ring;
	struct skge_element *e;

	e = ring->start;
	do {
		struct skge_rx_desc *rd = e->desc;
		rd->control = 0;
		if (e->iob) {
			free_iob(e->iob);
			e->iob = NULL;
		}
	} while ((e = e->next) != ring->start);
}

static void skge_link_up(struct skge_port *skge)
{
	skge_write8(skge->hw, SK_REG(skge->port, LNK_LED_REG),
		    LED_BLK_OFF|LED_SYNC_OFF|LED_ON);

	netdev_link_up(skge->netdev);

	DBG2(PFX "%s: Link is up at %d Mbps, %s duplex\n",
	     skge->netdev->name, skge->speed,
	     skge->duplex == DUPLEX_FULL ? "full" : "half");
}

static void skge_link_down(struct skge_port *skge)
{
	skge_write8(skge->hw, SK_REG(skge->port, LNK_LED_REG), LED_OFF);
	netdev_link_down(skge->netdev);

	DBG2(PFX "%s: Link is down.\n", skge->netdev->name);
}


static void xm_link_down(struct skge_hw *hw, int port)
{
	struct net_device *dev = hw->dev[port];
	struct skge_port *skge = netdev_priv(dev);

	xm_write16(hw, port, XM_IMSK, XM_IMSK_DISABLE);

	if (netdev_link_ok(dev))
		skge_link_down(skge);
}

static int __xm_phy_read(struct skge_hw *hw, int port, u16 reg, u16 *val)
{
	int i;

	xm_write16(hw, port, XM_PHY_ADDR, reg | hw->phy_addr);
	*val = xm_read16(hw, port, XM_PHY_DATA);

	if (hw->phy_type == SK_PHY_XMAC)
		goto ready;

	for (i = 0; i < PHY_RETRIES; i++) {
		if (xm_read16(hw, port, XM_MMU_CMD) & XM_MMU_PHY_RDY)
			goto ready;
		udelay(1);
	}

	return -ETIMEDOUT;
 ready:
	*val = xm_read16(hw, port, XM_PHY_DATA);

	return 0;
}

static u16 xm_phy_read(struct skge_hw *hw, int port, u16 reg)
{
	u16 v = 0;
	if (__xm_phy_read(hw, port, reg, &v))
		DBG(PFX "%s: phy read timed out\n",
		       hw->dev[port]->name);
	return v;
}

static int xm_phy_write(struct skge_hw *hw, int port, u16 reg, u16 val)
{
	int i;

	xm_write16(hw, port, XM_PHY_ADDR, reg | hw->phy_addr);
	for (i = 0; i < PHY_RETRIES; i++) {
		if (!(xm_read16(hw, port, XM_MMU_CMD) & XM_MMU_PHY_BUSY))
			goto ready;
		udelay(1);
	}
	return -EIO;

 ready:
	xm_write16(hw, port, XM_PHY_DATA, val);
	for (i = 0; i < PHY_RETRIES; i++) {
		if (!(xm_read16(hw, port, XM_MMU_CMD) & XM_MMU_PHY_BUSY))
			return 0;
		udelay(1);
	}
	return -ETIMEDOUT;
}

static void genesis_init(struct skge_hw *hw)
{
	/* set blink source counter */
	skge_write32(hw, B2_BSC_INI, (SK_BLK_DUR * SK_FACT_53) / 100);
	skge_write8(hw, B2_BSC_CTRL, BSC_START);

	/* configure mac arbiter */
	skge_write16(hw, B3_MA_TO_CTRL, MA_RST_CLR);

	/* configure mac arbiter timeout values */
	skge_write8(hw, B3_MA_TOINI_RX1, SK_MAC_TO_53);
	skge_write8(hw, B3_MA_TOINI_RX2, SK_MAC_TO_53);
	skge_write8(hw, B3_MA_TOINI_TX1, SK_MAC_TO_53);
	skge_write8(hw, B3_MA_TOINI_TX2, SK_MAC_TO_53);

	skge_write8(hw, B3_MA_RCINI_RX1, 0);
	skge_write8(hw, B3_MA_RCINI_RX2, 0);
	skge_write8(hw, B3_MA_RCINI_TX1, 0);
	skge_write8(hw, B3_MA_RCINI_TX2, 0);

	/* configure packet arbiter timeout */
	skge_write16(hw, B3_PA_CTRL, PA_RST_CLR);
	skge_write16(hw, B3_PA_TOINI_RX1, SK_PKT_TO_MAX);
	skge_write16(hw, B3_PA_TOINI_TX1, SK_PKT_TO_MAX);
	skge_write16(hw, B3_PA_TOINI_RX2, SK_PKT_TO_MAX);
	skge_write16(hw, B3_PA_TOINI_TX2, SK_PKT_TO_MAX);
}

static void genesis_reset(struct skge_hw *hw, int port)
{
	const u8 zero[8]  = { 0 };
	u32 reg;

	skge_write8(hw, SK_REG(port, GMAC_IRQ_MSK), 0);

	/* reset the statistics module */
	xm_write32(hw, port, XM_GP_PORT, XM_GP_RES_STAT);
	xm_write16(hw, port, XM_IMSK, XM_IMSK_DISABLE);
	xm_write32(hw, port, XM_MODE, 0);		/* clear Mode Reg */
	xm_write16(hw, port, XM_TX_CMD, 0);	/* reset TX CMD Reg */
	xm_write16(hw, port, XM_RX_CMD, 0);	/* reset RX CMD Reg */

	/* disable Broadcom PHY IRQ */
	if (hw->phy_type == SK_PHY_BCOM)
		xm_write16(hw, port, PHY_BCOM_INT_MASK, 0xffff);

	xm_outhash(hw, port, XM_HSM, zero);

	/* Flush TX and RX fifo */
	reg = xm_read32(hw, port, XM_MODE);
	xm_write32(hw, port, XM_MODE, reg | XM_MD_FTF);
	xm_write32(hw, port, XM_MODE, reg | XM_MD_FRF);
}


/* Convert mode to MII values  */
static const u16 phy_pause_map[] = {
	[FLOW_MODE_NONE] =	0,
	[FLOW_MODE_LOC_SEND] =	PHY_AN_PAUSE_ASYM,
	[FLOW_MODE_SYMMETRIC] = PHY_AN_PAUSE_CAP,
	[FLOW_MODE_SYM_OR_REM]  = PHY_AN_PAUSE_CAP | PHY_AN_PAUSE_ASYM,
};

/* special defines for FIBER (88E1011S only) */
static const u16 fiber_pause_map[] = {
	[FLOW_MODE_NONE]	= PHY_X_P_NO_PAUSE,
	[FLOW_MODE_LOC_SEND]	= PHY_X_P_ASYM_MD,
	[FLOW_MODE_SYMMETRIC]	= PHY_X_P_SYM_MD,
	[FLOW_MODE_SYM_OR_REM]	= PHY_X_P_BOTH_MD,
};


/* Check status of Broadcom phy link */
static void bcom_check_link(struct skge_hw *hw, int port)
{
	struct net_device *dev = hw->dev[port];
	struct skge_port *skge = netdev_priv(dev);
	u16 status;

	/* read twice because of latch */
	xm_phy_read(hw, port, PHY_BCOM_STAT);
	status = xm_phy_read(hw, port, PHY_BCOM_STAT);

	if ((status & PHY_ST_LSYNC) == 0) {
		xm_link_down(hw, port);
		return;
	}

	if (skge->autoneg == AUTONEG_ENABLE) {
		u16 lpa, aux;

		if (!(status & PHY_ST_AN_OVER))
			return;

		lpa = xm_phy_read(hw, port, PHY_XMAC_AUNE_LP);
		if (lpa & PHY_B_AN_RF) {
			DBG(PFX "%s: remote fault\n",
			       dev->name);
			return;
		}

		aux = xm_phy_read(hw, port, PHY_BCOM_AUX_STAT);

		/* Check Duplex mismatch */
		switch (aux & PHY_B_AS_AN_RES_MSK) {
		case PHY_B_RES_1000FD:
			skge->duplex = DUPLEX_FULL;
			break;
		case PHY_B_RES_1000HD:
			skge->duplex = DUPLEX_HALF;
			break;
		default:
			DBG(PFX "%s: duplex mismatch\n",
			       dev->name);
			return;
		}

		/* We are using IEEE 802.3z/D5.0 Table 37-4 */
		switch (aux & PHY_B_AS_PAUSE_MSK) {
		case PHY_B_AS_PAUSE_MSK:
			skge->flow_status = FLOW_STAT_SYMMETRIC;
			break;
		case PHY_B_AS_PRR:
			skge->flow_status = FLOW_STAT_REM_SEND;
			break;
		case PHY_B_AS_PRT:
			skge->flow_status = FLOW_STAT_LOC_SEND;
			break;
		default:
			skge->flow_status = FLOW_STAT_NONE;
		}
		skge->speed = SPEED_1000;
	}

	if (!netdev_link_ok(dev))
		genesis_link_up(skge);
}

/* Broadcom 5400 only supports giagabit! SysKonnect did not put an additional
 * Phy on for 100 or 10Mbit operation
 */
static void bcom_phy_init(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	unsigned int i;
	u16 id1, r, ext, ctl;

	/* magic workaround patterns for Broadcom */
	static const struct {
		u16 reg;
		u16 val;
	} A1hack[] = {
		{ 0x18, 0x0c20 }, { 0x17, 0x0012 }, { 0x15, 0x1104 },
		{ 0x17, 0x0013 }, { 0x15, 0x0404 }, { 0x17, 0x8006 },
		{ 0x15, 0x0132 }, { 0x17, 0x8006 }, { 0x15, 0x0232 },
		{ 0x17, 0x800D }, { 0x15, 0x000F }, { 0x18, 0x0420 },
	}, C0hack[] = {
		{ 0x18, 0x0c20 }, { 0x17, 0x0012 }, { 0x15, 0x1204 },
		{ 0x17, 0x0013 }, { 0x15, 0x0A04 }, { 0x18, 0x0420 },
	};

	/* read Id from external PHY (all have the same address) */
	id1 = xm_phy_read(hw, port, PHY_XMAC_ID1);

	/* Optimize MDIO transfer by suppressing preamble. */
	r = xm_read16(hw, port, XM_MMU_CMD);
	r |=  XM_MMU_NO_PRE;
	xm_write16(hw, port, XM_MMU_CMD,r);

	switch (id1) {
	case PHY_BCOM_ID1_C0:
		/*
		 * Workaround BCOM Errata for the C0 type.
		 * Write magic patterns to reserved registers.
		 */
		for (i = 0; i < ARRAY_SIZE(C0hack); i++)
			xm_phy_write(hw, port,
				     C0hack[i].reg, C0hack[i].val);

		break;
	case PHY_BCOM_ID1_A1:
		/*
		 * Workaround BCOM Errata for the A1 type.
		 * Write magic patterns to reserved registers.
		 */
		for (i = 0; i < ARRAY_SIZE(A1hack); i++)
			xm_phy_write(hw, port,
				     A1hack[i].reg, A1hack[i].val);
		break;
	}

	/*
	 * Workaround BCOM Errata (#10523) for all BCom PHYs.
	 * Disable Power Management after reset.
	 */
	r = xm_phy_read(hw, port, PHY_BCOM_AUX_CTRL);
	r |= PHY_B_AC_DIS_PM;
	xm_phy_write(hw, port, PHY_BCOM_AUX_CTRL, r);

	/* Dummy read */
	xm_read16(hw, port, XM_ISRC);

	ext = PHY_B_PEC_EN_LTR; /* enable tx led */
	ctl = PHY_CT_SP1000;	/* always 1000mbit */

	if (skge->autoneg == AUTONEG_ENABLE) {
		/*
		 * Workaround BCOM Errata #1 for the C5 type.
		 * 1000Base-T Link Acquisition Failure in Slave Mode
		 * Set Repeater/DTE bit 10 of the 1000Base-T Control Register
		 */
		u16 adv = PHY_B_1000C_RD;
		if (skge->advertising & ADVERTISED_1000baseT_Half)
			adv |= PHY_B_1000C_AHD;
		if (skge->advertising & ADVERTISED_1000baseT_Full)
			adv |= PHY_B_1000C_AFD;
		xm_phy_write(hw, port, PHY_BCOM_1000T_CTRL, adv);

		ctl |= PHY_CT_ANE | PHY_CT_RE_CFG;
	} else {
		if (skge->duplex == DUPLEX_FULL)
			ctl |= PHY_CT_DUP_MD;
		/* Force to slave */
		xm_phy_write(hw, port, PHY_BCOM_1000T_CTRL, PHY_B_1000C_MSE);
	}

	/* Set autonegotiation pause parameters */
	xm_phy_write(hw, port, PHY_BCOM_AUNE_ADV,
		     phy_pause_map[skge->flow_control] | PHY_AN_CSMA);

	xm_phy_write(hw, port, PHY_BCOM_P_EXT_CTRL, ext);
	xm_phy_write(hw, port, PHY_BCOM_CTRL, ctl);

	/* Use link status change interrupt */
	xm_phy_write(hw, port, PHY_BCOM_INT_MASK, PHY_B_DEF_MSK);
}

static void xm_phy_init(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	u16 ctrl = 0;

	if (skge->autoneg == AUTONEG_ENABLE) {
		if (skge->advertising & ADVERTISED_1000baseT_Half)
			ctrl |= PHY_X_AN_HD;
		if (skge->advertising & ADVERTISED_1000baseT_Full)
			ctrl |= PHY_X_AN_FD;

		ctrl |= fiber_pause_map[skge->flow_control];

		xm_phy_write(hw, port, PHY_XMAC_AUNE_ADV, ctrl);

		/* Restart Auto-negotiation */
		ctrl = PHY_CT_ANE | PHY_CT_RE_CFG;
	} else {
		/* Set DuplexMode in Config register */
		if (skge->duplex == DUPLEX_FULL)
			ctrl |= PHY_CT_DUP_MD;
		/*
		 * Do NOT enable Auto-negotiation here. This would hold
		 * the link down because no IDLEs are transmitted
		 */
	}

	xm_phy_write(hw, port, PHY_XMAC_CTRL, ctrl);

	/* Poll PHY for status changes */
	skge->use_xm_link_timer = 1;
}

static int xm_check_link(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	u16 status;

	/* read twice because of latch */
	xm_phy_read(hw, port, PHY_XMAC_STAT);
	status = xm_phy_read(hw, port, PHY_XMAC_STAT);

	if ((status & PHY_ST_LSYNC) == 0) {
		xm_link_down(hw, port);
		return 0;
	}

	if (skge->autoneg == AUTONEG_ENABLE) {
		u16 lpa, res;

		if (!(status & PHY_ST_AN_OVER))
			return 0;

		lpa = xm_phy_read(hw, port, PHY_XMAC_AUNE_LP);
		if (lpa & PHY_B_AN_RF) {
			DBG(PFX "%s: remote fault\n",
			       dev->name);
			return 0;
		}

		res = xm_phy_read(hw, port, PHY_XMAC_RES_ABI);

		/* Check Duplex mismatch */
		switch (res & (PHY_X_RS_HD | PHY_X_RS_FD)) {
		case PHY_X_RS_FD:
			skge->duplex = DUPLEX_FULL;
			break;
		case PHY_X_RS_HD:
			skge->duplex = DUPLEX_HALF;
			break;
		default:
			DBG(PFX "%s: duplex mismatch\n",
			       dev->name);
			return 0;
		}

		/* We are using IEEE 802.3z/D5.0 Table 37-4 */
		if ((skge->flow_control == FLOW_MODE_SYMMETRIC ||
		     skge->flow_control == FLOW_MODE_SYM_OR_REM) &&
		    (lpa & PHY_X_P_SYM_MD))
			skge->flow_status = FLOW_STAT_SYMMETRIC;
		else if (skge->flow_control == FLOW_MODE_SYM_OR_REM &&
			 (lpa & PHY_X_RS_PAUSE) == PHY_X_P_ASYM_MD)
			/* Enable PAUSE receive, disable PAUSE transmit */
			skge->flow_status  = FLOW_STAT_REM_SEND;
		else if (skge->flow_control == FLOW_MODE_LOC_SEND &&
			 (lpa & PHY_X_RS_PAUSE) == PHY_X_P_BOTH_MD)
			/* Disable PAUSE receive, enable PAUSE transmit */
			skge->flow_status = FLOW_STAT_LOC_SEND;
		else
			skge->flow_status = FLOW_STAT_NONE;

		skge->speed = SPEED_1000;
	}

	if (!netdev_link_ok(dev))
		genesis_link_up(skge);
	return 1;
}

/* Poll to check for link coming up.
 *
 * Since internal PHY is wired to a level triggered pin, can't
 * get an interrupt when carrier is detected, need to poll for
 * link coming up.
 */
static void xm_link_timer(struct skge_port *skge)
{
	struct net_device *dev = skge->netdev;
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	int i;

	/*
	 * Verify that the link by checking GPIO register three times.
	 * This pin has the signal from the link_sync pin connected to it.
	 */
	for (i = 0; i < 3; i++) {
		if (xm_read16(hw, port, XM_GP_PORT) & XM_GP_INP_ASS)
			return;
	}

        /* Re-enable interrupt to detect link down */
	if (xm_check_link(dev)) {
		u16 msk = xm_read16(hw, port, XM_IMSK);
		msk &= ~XM_IS_INP_ASS;
		xm_write16(hw, port, XM_IMSK, msk);
		xm_read16(hw, port, XM_ISRC);
	}
}

static void genesis_mac_init(struct skge_hw *hw, int port)
{
	struct net_device *dev = hw->dev[port];
	struct skge_port *skge = netdev_priv(dev);
	int i;
	u32 r;
	const u8 zero[6]  = { 0 };

	for (i = 0; i < 10; i++) {
		skge_write16(hw, SK_REG(port, TX_MFF_CTRL1),
			     MFF_SET_MAC_RST);
		if (skge_read16(hw, SK_REG(port, TX_MFF_CTRL1)) & MFF_SET_MAC_RST)
			goto reset_ok;
		udelay(1);
	}

	DBG(PFX "%s: genesis reset failed\n", dev->name);

 reset_ok:
	/* Unreset the XMAC. */
	skge_write16(hw, SK_REG(port, TX_MFF_CTRL1), MFF_CLR_MAC_RST);

	/*
	 * Perform additional initialization for external PHYs,
	 * namely for the 1000baseTX cards that use the XMAC's
	 * GMII mode.
	 */
	if (hw->phy_type != SK_PHY_XMAC) {
		/* Take external Phy out of reset */
		r = skge_read32(hw, B2_GP_IO);
		if (port == 0)
			r |= GP_DIR_0|GP_IO_0;
		else
			r |= GP_DIR_2|GP_IO_2;

		skge_write32(hw, B2_GP_IO, r);

		/* Enable GMII interface */
		xm_write16(hw, port, XM_HW_CFG, XM_HW_GMII_MD);
	}


	switch(hw->phy_type) {
	case SK_PHY_XMAC:
		xm_phy_init(skge);
		break;
	case SK_PHY_BCOM:
		bcom_phy_init(skge);
		bcom_check_link(hw, port);
	}

	/* Set Station Address */
	xm_outaddr(hw, port, XM_SA, dev->ll_addr);

	/* We don't use match addresses so clear */
	for (i = 1; i < 16; i++)
		xm_outaddr(hw, port, XM_EXM(i), zero);

	/* Clear MIB counters */
	xm_write16(hw, port, XM_STAT_CMD,
			XM_SC_CLR_RXC | XM_SC_CLR_TXC);
	/* Clear two times according to Errata #3 */
	xm_write16(hw, port, XM_STAT_CMD,
			XM_SC_CLR_RXC | XM_SC_CLR_TXC);

	/* configure Rx High Water Mark (XM_RX_HI_WM) */
	xm_write16(hw, port, XM_RX_HI_WM, 1450);

	/* We don't need the FCS appended to the packet. */
	r = XM_RX_LENERR_OK | XM_RX_STRIP_FCS;

	if (skge->duplex == DUPLEX_HALF) {
		/*
		 * If in manual half duplex mode the other side might be in
		 * full duplex mode, so ignore if a carrier extension is not seen
		 * on frames received
		 */
		r |= XM_RX_DIS_CEXT;
	}
	xm_write16(hw, port, XM_RX_CMD, r);

	/* We want short frames padded to 60 bytes. */
	xm_write16(hw, port, XM_TX_CMD, XM_TX_AUTO_PAD);

	xm_write16(hw, port, XM_TX_THR, 512);

	/*
	 * Enable the reception of all error frames. This is is
	 * a necessary evil due to the design of the XMAC. The
	 * XMAC's receive FIFO is only 8K in size, however jumbo
	 * frames can be up to 9000 bytes in length. When bad
	 * frame filtering is enabled, the XMAC's RX FIFO operates
	 * in 'store and forward' mode. For this to work, the
	 * entire frame has to fit into the FIFO, but that means
	 * that jumbo frames larger than 8192 bytes will be
	 * truncated. Disabling all bad frame filtering causes
	 * the RX FIFO to operate in streaming mode, in which
	 * case the XMAC will start transferring frames out of the
	 * RX FIFO as soon as the FIFO threshold is reached.
	 */
	xm_write32(hw, port, XM_MODE, XM_DEF_MODE);


	/*
	 * Initialize the Receive Counter Event Mask (XM_RX_EV_MSK)
	 *	- Enable all bits excepting 'Octets Rx OK Low CntOv'
	 *	  and 'Octets Rx OK Hi Cnt Ov'.
	 */
	xm_write32(hw, port, XM_RX_EV_MSK, XMR_DEF_MSK);

	/*
	 * Initialize the Transmit Counter Event Mask (XM_TX_EV_MSK)
	 *	- Enable all bits excepting 'Octets Tx OK Low CntOv'
	 *	  and 'Octets Tx OK Hi Cnt Ov'.
	 */
	xm_write32(hw, port, XM_TX_EV_MSK, XMT_DEF_MSK);

	/* Configure MAC arbiter */
	skge_write16(hw, B3_MA_TO_CTRL, MA_RST_CLR);

	/* configure timeout values */
	skge_write8(hw, B3_MA_TOINI_RX1, 72);
	skge_write8(hw, B3_MA_TOINI_RX2, 72);
	skge_write8(hw, B3_MA_TOINI_TX1, 72);
	skge_write8(hw, B3_MA_TOINI_TX2, 72);

	skge_write8(hw, B3_MA_RCINI_RX1, 0);
	skge_write8(hw, B3_MA_RCINI_RX2, 0);
	skge_write8(hw, B3_MA_RCINI_TX1, 0);
	skge_write8(hw, B3_MA_RCINI_TX2, 0);

	/* Configure Rx MAC FIFO */
	skge_write8(hw, SK_REG(port, RX_MFF_CTRL2), MFF_RST_CLR);
	skge_write16(hw, SK_REG(port, RX_MFF_CTRL1), MFF_ENA_TIM_PAT);
	skge_write8(hw, SK_REG(port, RX_MFF_CTRL2), MFF_ENA_OP_MD);

	/* Configure Tx MAC FIFO */
	skge_write8(hw, SK_REG(port, TX_MFF_CTRL2), MFF_RST_CLR);
	skge_write16(hw, SK_REG(port, TX_MFF_CTRL1), MFF_TX_CTRL_DEF);
	skge_write8(hw, SK_REG(port, TX_MFF_CTRL2), MFF_ENA_OP_MD);

	/* enable timeout timers */
	skge_write16(hw, B3_PA_CTRL,
		     (port == 0) ? PA_ENA_TO_TX1 : PA_ENA_TO_TX2);
}

static void genesis_stop(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	unsigned retries = 1000;
	u16 cmd;

	/* Disable Tx and Rx */
	cmd = xm_read16(hw, port, XM_MMU_CMD);
	cmd &= ~(XM_MMU_ENA_RX | XM_MMU_ENA_TX);
	xm_write16(hw, port, XM_MMU_CMD, cmd);

	genesis_reset(hw, port);

	/* Clear Tx packet arbiter timeout IRQ */
	skge_write16(hw, B3_PA_CTRL,
		     port == 0 ? PA_CLR_TO_TX1 : PA_CLR_TO_TX2);

	/* Reset the MAC */
	skge_write16(hw, SK_REG(port, TX_MFF_CTRL1), MFF_CLR_MAC_RST);
	do {
		skge_write16(hw, SK_REG(port, TX_MFF_CTRL1), MFF_SET_MAC_RST);
		if (!(skge_read16(hw, SK_REG(port, TX_MFF_CTRL1)) & MFF_SET_MAC_RST))
			break;
	} while (--retries > 0);

	/* For external PHYs there must be special handling */
	if (hw->phy_type != SK_PHY_XMAC) {
		u32 reg = skge_read32(hw, B2_GP_IO);
		if (port == 0) {
			reg |= GP_DIR_0;
			reg &= ~GP_IO_0;
		} else {
			reg |= GP_DIR_2;
			reg &= ~GP_IO_2;
		}
		skge_write32(hw, B2_GP_IO, reg);
		skge_read32(hw, B2_GP_IO);
	}

	xm_write16(hw, port, XM_MMU_CMD,
			xm_read16(hw, port, XM_MMU_CMD)
			& ~(XM_MMU_ENA_RX | XM_MMU_ENA_TX));

	xm_read16(hw, port, XM_MMU_CMD);
}

static void genesis_link_up(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	u16 cmd, msk;
	u32 mode;

	cmd = xm_read16(hw, port, XM_MMU_CMD);

	/*
	 * enabling pause frame reception is required for 1000BT
	 * because the XMAC is not reset if the link is going down
	 */
	if (skge->flow_status == FLOW_STAT_NONE ||
	    skge->flow_status == FLOW_STAT_LOC_SEND)
		/* Disable Pause Frame Reception */
		cmd |= XM_MMU_IGN_PF;
	else
		/* Enable Pause Frame Reception */
		cmd &= ~XM_MMU_IGN_PF;

	xm_write16(hw, port, XM_MMU_CMD, cmd);

	mode = xm_read32(hw, port, XM_MODE);
	if (skge->flow_status== FLOW_STAT_SYMMETRIC ||
	    skge->flow_status == FLOW_STAT_LOC_SEND) {
		/*
		 * Configure Pause Frame Generation
		 * Use internal and external Pause Frame Generation.
		 * Sending pause frames is edge triggered.
		 * Send a Pause frame with the maximum pause time if
		 * internal oder external FIFO full condition occurs.
		 * Send a zero pause time frame to re-start transmission.
		 */
		/* XM_PAUSE_DA = '010000C28001' (default) */
		/* XM_MAC_PTIME = 0xffff (maximum) */
		/* remember this value is defined in big endian (!) */
		xm_write16(hw, port, XM_MAC_PTIME, 0xffff);

		mode |= XM_PAUSE_MODE;
		skge_write16(hw, SK_REG(port, RX_MFF_CTRL1), MFF_ENA_PAUSE);
	} else {
		/*
		 * disable pause frame generation is required for 1000BT
		 * because the XMAC is not reset if the link is going down
		 */
		/* Disable Pause Mode in Mode Register */
		mode &= ~XM_PAUSE_MODE;

		skge_write16(hw, SK_REG(port, RX_MFF_CTRL1), MFF_DIS_PAUSE);
	}

	xm_write32(hw, port, XM_MODE, mode);

	/* Turn on detection of Tx underrun */
	msk = xm_read16(hw, port, XM_IMSK);
	msk &= ~XM_IS_TXF_UR;
	xm_write16(hw, port, XM_IMSK, msk);

	xm_read16(hw, port, XM_ISRC);

	/* get MMU Command Reg. */
	cmd = xm_read16(hw, port, XM_MMU_CMD);
	if (hw->phy_type != SK_PHY_XMAC && skge->duplex == DUPLEX_FULL)
		cmd |= XM_MMU_GMII_FD;

	/*
	 * Workaround BCOM Errata (#10523) for all BCom Phys
	 * Enable Power Management after link up
	 */
	if (hw->phy_type == SK_PHY_BCOM) {
		xm_phy_write(hw, port, PHY_BCOM_AUX_CTRL,
			     xm_phy_read(hw, port, PHY_BCOM_AUX_CTRL)
			     & ~PHY_B_AC_DIS_PM);
		xm_phy_write(hw, port, PHY_BCOM_INT_MASK, PHY_B_DEF_MSK);
	}

	/* enable Rx/Tx */
	xm_write16(hw, port, XM_MMU_CMD,
			cmd | XM_MMU_ENA_RX | XM_MMU_ENA_TX);
	skge_link_up(skge);
}


static inline void bcom_phy_intr(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	u16 isrc;

	isrc = xm_phy_read(hw, port, PHY_BCOM_INT_STAT);
	DBGIO(PFX "%s: phy interrupt status 0x%x\n",
	     skge->netdev->name, isrc);

	if (isrc & PHY_B_IS_PSE)
		DBG(PFX "%s: uncorrectable pair swap error\n",
		    hw->dev[port]->name);

	/* Workaround BCom Errata:
	 *	enable and disable loopback mode if "NO HCD" occurs.
	 */
	if (isrc & PHY_B_IS_NO_HDCL) {
		u16 ctrl = xm_phy_read(hw, port, PHY_BCOM_CTRL);
		xm_phy_write(hw, port, PHY_BCOM_CTRL,
				  ctrl | PHY_CT_LOOP);
		xm_phy_write(hw, port, PHY_BCOM_CTRL,
				  ctrl & ~PHY_CT_LOOP);
	}

	if (isrc & (PHY_B_IS_AN_PR | PHY_B_IS_LST_CHANGE))
		bcom_check_link(hw, port);

}

static int gm_phy_write(struct skge_hw *hw, int port, u16 reg, u16 val)
{
	int i;

	gma_write16(hw, port, GM_SMI_DATA, val);
	gma_write16(hw, port, GM_SMI_CTRL,
			 GM_SMI_CT_PHY_AD(hw->phy_addr) | GM_SMI_CT_REG_AD(reg));
	for (i = 0; i < PHY_RETRIES; i++) {
		udelay(1);

		if (!(gma_read16(hw, port, GM_SMI_CTRL) & GM_SMI_CT_BUSY))
			return 0;
	}

	DBG(PFX "%s: phy write timeout port %x reg %x val %x\n",
	    hw->dev[port]->name,
	    port, reg, val);
	return -EIO;
}

static int __gm_phy_read(struct skge_hw *hw, int port, u16 reg, u16 *val)
{
	int i;

	gma_write16(hw, port, GM_SMI_CTRL,
			 GM_SMI_CT_PHY_AD(hw->phy_addr)
			 | GM_SMI_CT_REG_AD(reg) | GM_SMI_CT_OP_RD);

	for (i = 0; i < PHY_RETRIES; i++) {
		udelay(1);
		if (gma_read16(hw, port, GM_SMI_CTRL) & GM_SMI_CT_RD_VAL)
			goto ready;
	}

	return -ETIMEDOUT;
 ready:
	*val = gma_read16(hw, port, GM_SMI_DATA);
	return 0;
}

static u16 gm_phy_read(struct skge_hw *hw, int port, u16 reg)
{
	u16 v = 0;
	if (__gm_phy_read(hw, port, reg, &v))
		DBG(PFX "%s: phy read timeout port %x reg %x val %x\n",
	       hw->dev[port]->name,
	       port, reg, v);
	return v;
}

/* Marvell Phy Initialization */
static void yukon_init(struct skge_hw *hw, int port)
{
	struct skge_port *skge = netdev_priv(hw->dev[port]);
	u16 ctrl, ct1000, adv;

	if (skge->autoneg == AUTONEG_ENABLE) {
		u16 ectrl = gm_phy_read(hw, port, PHY_MARV_EXT_CTRL);

		ectrl &= ~(PHY_M_EC_M_DSC_MSK | PHY_M_EC_S_DSC_MSK |
			  PHY_M_EC_MAC_S_MSK);
		ectrl |= PHY_M_EC_MAC_S(MAC_TX_CLK_25_MHZ);

		ectrl |= PHY_M_EC_M_DSC(0) | PHY_M_EC_S_DSC(1);

		gm_phy_write(hw, port, PHY_MARV_EXT_CTRL, ectrl);
	}

	ctrl = gm_phy_read(hw, port, PHY_MARV_CTRL);
	if (skge->autoneg == AUTONEG_DISABLE)
		ctrl &= ~PHY_CT_ANE;

	ctrl |= PHY_CT_RESET;
	gm_phy_write(hw, port, PHY_MARV_CTRL, ctrl);

	ctrl = 0;
	ct1000 = 0;
	adv = PHY_AN_CSMA;

	if (skge->autoneg == AUTONEG_ENABLE) {
		if (hw->copper) {
			if (skge->advertising & ADVERTISED_1000baseT_Full)
				ct1000 |= PHY_M_1000C_AFD;
			if (skge->advertising & ADVERTISED_1000baseT_Half)
				ct1000 |= PHY_M_1000C_AHD;
			if (skge->advertising & ADVERTISED_100baseT_Full)
				adv |= PHY_M_AN_100_FD;
			if (skge->advertising & ADVERTISED_100baseT_Half)
				adv |= PHY_M_AN_100_HD;
			if (skge->advertising & ADVERTISED_10baseT_Full)
				adv |= PHY_M_AN_10_FD;
			if (skge->advertising & ADVERTISED_10baseT_Half)
				adv |= PHY_M_AN_10_HD;

			/* Set Flow-control capabilities */
			adv |= phy_pause_map[skge->flow_control];
		} else {
			if (skge->advertising & ADVERTISED_1000baseT_Full)
				adv |= PHY_M_AN_1000X_AFD;
			if (skge->advertising & ADVERTISED_1000baseT_Half)
				adv |= PHY_M_AN_1000X_AHD;

			adv |= fiber_pause_map[skge->flow_control];
		}

		/* Restart Auto-negotiation */
		ctrl |= PHY_CT_ANE | PHY_CT_RE_CFG;
	} else {
		/* forced speed/duplex settings */
		ct1000 = PHY_M_1000C_MSE;

		if (skge->duplex == DUPLEX_FULL)
			ctrl |= PHY_CT_DUP_MD;

		switch (skge->speed) {
		case SPEED_1000:
			ctrl |= PHY_CT_SP1000;
			break;
		case SPEED_100:
			ctrl |= PHY_CT_SP100;
			break;
		}

		ctrl |= PHY_CT_RESET;
	}

	gm_phy_write(hw, port, PHY_MARV_1000T_CTRL, ct1000);

	gm_phy_write(hw, port, PHY_MARV_AUNE_ADV, adv);
	gm_phy_write(hw, port, PHY_MARV_CTRL, ctrl);

	/* Enable phy interrupt on autonegotiation complete (or link up) */
	if (skge->autoneg == AUTONEG_ENABLE)
		gm_phy_write(hw, port, PHY_MARV_INT_MASK, PHY_M_IS_AN_MSK);
	else
		gm_phy_write(hw, port, PHY_MARV_INT_MASK, PHY_M_IS_DEF_MSK);
}

static void yukon_reset(struct skge_hw *hw, int port)
{
	gm_phy_write(hw, port, PHY_MARV_INT_MASK, 0);/* disable PHY IRQs */
	gma_write16(hw, port, GM_MC_ADDR_H1, 0);	/* clear MC hash */
	gma_write16(hw, port, GM_MC_ADDR_H2, 0);
	gma_write16(hw, port, GM_MC_ADDR_H3, 0);
	gma_write16(hw, port, GM_MC_ADDR_H4, 0);

	gma_write16(hw, port, GM_RX_CTRL,
			 gma_read16(hw, port, GM_RX_CTRL)
			 | GM_RXCR_UCF_ENA | GM_RXCR_MCF_ENA);
}

/* Apparently, early versions of Yukon-Lite had wrong chip_id? */
static int is_yukon_lite_a0(struct skge_hw *hw)
{
	u32 reg;
	int ret;

	if (hw->chip_id != CHIP_ID_YUKON)
		return 0;

	reg = skge_read32(hw, B2_FAR);
	skge_write8(hw, B2_FAR + 3, 0xff);
	ret = (skge_read8(hw, B2_FAR + 3) != 0);
	skge_write32(hw, B2_FAR, reg);
	return ret;
}

static void yukon_mac_init(struct skge_hw *hw, int port)
{
	struct skge_port *skge = netdev_priv(hw->dev[port]);
	int i;
	u32 reg;
	const u8 *addr = hw->dev[port]->ll_addr;

	/* WA code for COMA mode -- set PHY reset */
	if (hw->chip_id == CHIP_ID_YUKON_LITE &&
	    hw->chip_rev >= CHIP_REV_YU_LITE_A3) {
		reg = skge_read32(hw, B2_GP_IO);
		reg |= GP_DIR_9 | GP_IO_9;
		skge_write32(hw, B2_GP_IO, reg);
	}

	/* hard reset */
	skge_write32(hw, SK_REG(port, GPHY_CTRL), GPC_RST_SET);
	skge_write32(hw, SK_REG(port, GMAC_CTRL), GMC_RST_SET);

	/* WA code for COMA mode -- clear PHY reset */
	if (hw->chip_id == CHIP_ID_YUKON_LITE &&
	    hw->chip_rev >= CHIP_REV_YU_LITE_A3) {
		reg = skge_read32(hw, B2_GP_IO);
		reg |= GP_DIR_9;
		reg &= ~GP_IO_9;
		skge_write32(hw, B2_GP_IO, reg);
	}

	/* Set hardware config mode */
	reg = GPC_INT_POL_HI | GPC_DIS_FC | GPC_DIS_SLEEP |
		GPC_ENA_XC | GPC_ANEG_ADV_ALL_M | GPC_ENA_PAUSE;
	reg |= hw->copper ? GPC_HWCFG_GMII_COP : GPC_HWCFG_GMII_FIB;

	/* Clear GMC reset */
	skge_write32(hw, SK_REG(port, GPHY_CTRL), reg | GPC_RST_SET);
	skge_write32(hw, SK_REG(port, GPHY_CTRL), reg | GPC_RST_CLR);
	skge_write32(hw, SK_REG(port, GMAC_CTRL), GMC_PAUSE_ON | GMC_RST_CLR);

	if (skge->autoneg == AUTONEG_DISABLE) {
		reg = GM_GPCR_AU_ALL_DIS;
		gma_write16(hw, port, GM_GP_CTRL,
				 gma_read16(hw, port, GM_GP_CTRL) | reg);

		switch (skge->speed) {
		case SPEED_1000:
			reg &= ~GM_GPCR_SPEED_100;
			reg |= GM_GPCR_SPEED_1000;
			break;
		case SPEED_100:
			reg &= ~GM_GPCR_SPEED_1000;
			reg |= GM_GPCR_SPEED_100;
			break;
		case SPEED_10:
			reg &= ~(GM_GPCR_SPEED_1000 | GM_GPCR_SPEED_100);
			break;
		}

		if (skge->duplex == DUPLEX_FULL)
			reg |= GM_GPCR_DUP_FULL;
	} else
		reg = GM_GPCR_SPEED_1000 | GM_GPCR_SPEED_100 | GM_GPCR_DUP_FULL;

	switch (skge->flow_control) {
	case FLOW_MODE_NONE:
		skge_write32(hw, SK_REG(port, GMAC_CTRL), GMC_PAUSE_OFF);
		reg |= GM_GPCR_FC_TX_DIS | GM_GPCR_FC_RX_DIS | GM_GPCR_AU_FCT_DIS;
		break;
	case FLOW_MODE_LOC_SEND:
		/* disable Rx flow-control */
		reg |= GM_GPCR_FC_RX_DIS | GM_GPCR_AU_FCT_DIS;
		break;
	case FLOW_MODE_SYMMETRIC:
	case FLOW_MODE_SYM_OR_REM:
		/* enable Tx & Rx flow-control */
		break;
	}

	gma_write16(hw, port, GM_GP_CTRL, reg);
	skge_read16(hw, SK_REG(port, GMAC_IRQ_SRC));

	yukon_init(hw, port);

	/* MIB clear */
	reg = gma_read16(hw, port, GM_PHY_ADDR);
	gma_write16(hw, port, GM_PHY_ADDR, reg | GM_PAR_MIB_CLR);

	for (i = 0; i < GM_MIB_CNT_SIZE; i++)
		gma_read16(hw, port, GM_MIB_CNT_BASE + 8*i);
	gma_write16(hw, port, GM_PHY_ADDR, reg);

	/* transmit control */
	gma_write16(hw, port, GM_TX_CTRL, TX_COL_THR(TX_COL_DEF));

	/* receive control reg: unicast + multicast + no FCS  */
	gma_write16(hw, port, GM_RX_CTRL,
			 GM_RXCR_UCF_ENA | GM_RXCR_CRC_DIS | GM_RXCR_MCF_ENA);

	/* transmit flow control */
	gma_write16(hw, port, GM_TX_FLOW_CTRL, 0xffff);

	/* transmit parameter */
	gma_write16(hw, port, GM_TX_PARAM,
			 TX_JAM_LEN_VAL(TX_JAM_LEN_DEF) |
			 TX_JAM_IPG_VAL(TX_JAM_IPG_DEF) |
			 TX_IPG_JAM_DATA(TX_IPG_JAM_DEF));

	/* configure the Serial Mode Register */
	reg = DATA_BLIND_VAL(DATA_BLIND_DEF)
		| GM_SMOD_VLAN_ENA
		| IPG_DATA_VAL(IPG_DATA_DEF);

	gma_write16(hw, port, GM_SERIAL_MODE, reg);

	/* physical address: used for pause frames */
	gma_set_addr(hw, port, GM_SRC_ADDR_1L, addr);
	/* virtual address for data */
	gma_set_addr(hw, port, GM_SRC_ADDR_2L, addr);

	/* enable interrupt mask for counter overflows */
	gma_write16(hw, port, GM_TX_IRQ_MSK, 0);
	gma_write16(hw, port, GM_RX_IRQ_MSK, 0);
	gma_write16(hw, port, GM_TR_IRQ_MSK, 0);

	/* Initialize Mac Fifo */

	/* Configure Rx MAC FIFO */
	skge_write16(hw, SK_REG(port, RX_GMF_FL_MSK), RX_FF_FL_DEF_MSK);
	reg = GMF_OPER_ON | GMF_RX_F_FL_ON;

	/* disable Rx GMAC FIFO Flush for YUKON-Lite Rev. A0 only */
	if (is_yukon_lite_a0(hw))
		reg &= ~GMF_RX_F_FL_ON;

	skge_write8(hw, SK_REG(port, RX_GMF_CTRL_T), GMF_RST_CLR);
	skge_write16(hw, SK_REG(port, RX_GMF_CTRL_T), reg);
	/*
	 * because Pause Packet Truncation in GMAC is not working
	 * we have to increase the Flush Threshold to 64 bytes
	 * in order to flush pause packets in Rx FIFO on Yukon-1
	 */
	skge_write16(hw, SK_REG(port, RX_GMF_FL_THR), RX_GMF_FL_THR_DEF+1);

	/* Configure Tx MAC FIFO */
	skge_write8(hw, SK_REG(port, TX_GMF_CTRL_T), GMF_RST_CLR);
	skge_write16(hw, SK_REG(port, TX_GMF_CTRL_T), GMF_OPER_ON);
}

/* Go into power down mode */
static void yukon_suspend(struct skge_hw *hw, int port)
{
	u16 ctrl;

	ctrl = gm_phy_read(hw, port, PHY_MARV_PHY_CTRL);
	ctrl |= PHY_M_PC_POL_R_DIS;
	gm_phy_write(hw, port, PHY_MARV_PHY_CTRL, ctrl);

	ctrl = gm_phy_read(hw, port, PHY_MARV_CTRL);
	ctrl |= PHY_CT_RESET;
	gm_phy_write(hw, port, PHY_MARV_CTRL, ctrl);

	/* switch IEEE compatible power down mode on */
	ctrl = gm_phy_read(hw, port, PHY_MARV_CTRL);
	ctrl |= PHY_CT_PDOWN;
	gm_phy_write(hw, port, PHY_MARV_CTRL, ctrl);
}

static void yukon_stop(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;

	skge_write8(hw, SK_REG(port, GMAC_IRQ_MSK), 0);
	yukon_reset(hw, port);

	gma_write16(hw, port, GM_GP_CTRL,
			 gma_read16(hw, port, GM_GP_CTRL)
			 & ~(GM_GPCR_TX_ENA|GM_GPCR_RX_ENA));
	gma_read16(hw, port, GM_GP_CTRL);

	yukon_suspend(hw, port);

	/* set GPHY Control reset */
	skge_write8(hw, SK_REG(port, GPHY_CTRL), GPC_RST_SET);
	skge_write8(hw, SK_REG(port, GMAC_CTRL), GMC_RST_SET);
}

static u16 yukon_speed(const struct skge_hw *hw __unused, u16 aux)
{
	switch (aux & PHY_M_PS_SPEED_MSK) {
	case PHY_M_PS_SPEED_1000:
		return SPEED_1000;
	case PHY_M_PS_SPEED_100:
		return SPEED_100;
	default:
		return SPEED_10;
	}
}

static void yukon_link_up(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	u16 reg;

	/* Enable Transmit FIFO Underrun */
	skge_write8(hw, SK_REG(port, GMAC_IRQ_MSK), GMAC_DEF_MSK);

	reg = gma_read16(hw, port, GM_GP_CTRL);
	if (skge->duplex == DUPLEX_FULL || skge->autoneg == AUTONEG_ENABLE)
		reg |= GM_GPCR_DUP_FULL;

	/* enable Rx/Tx */
	reg |= GM_GPCR_RX_ENA | GM_GPCR_TX_ENA;
	gma_write16(hw, port, GM_GP_CTRL, reg);

	gm_phy_write(hw, port, PHY_MARV_INT_MASK, PHY_M_IS_DEF_MSK);
	skge_link_up(skge);
}

static void yukon_link_down(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	u16 ctrl;

	ctrl = gma_read16(hw, port, GM_GP_CTRL);
	ctrl &= ~(GM_GPCR_RX_ENA | GM_GPCR_TX_ENA);
	gma_write16(hw, port, GM_GP_CTRL, ctrl);

	if (skge->flow_status == FLOW_STAT_REM_SEND) {
		ctrl = gm_phy_read(hw, port, PHY_MARV_AUNE_ADV);
		ctrl |= PHY_M_AN_ASP;
		/* restore Asymmetric Pause bit */
		gm_phy_write(hw, port, PHY_MARV_AUNE_ADV, ctrl);
	}

	skge_link_down(skge);

	yukon_init(hw, port);
}

static void yukon_phy_intr(struct skge_port *skge)
{
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	const char *reason = NULL;
	u16 istatus, phystat;

	istatus = gm_phy_read(hw, port, PHY_MARV_INT_STAT);
	phystat = gm_phy_read(hw, port, PHY_MARV_PHY_STAT);

	DBGIO(PFX "%s: phy interrupt status 0x%x 0x%x\n",
	     skge->netdev->name, istatus, phystat);

	if (istatus & PHY_M_IS_AN_COMPL) {
		if (gm_phy_read(hw, port, PHY_MARV_AUNE_LP)
		    & PHY_M_AN_RF) {
			reason = "remote fault";
			goto failed;
		}

		if (gm_phy_read(hw, port, PHY_MARV_1000T_STAT) & PHY_B_1000S_MSF) {
			reason = "master/slave fault";
			goto failed;
		}

		if (!(phystat & PHY_M_PS_SPDUP_RES)) {
			reason = "speed/duplex";
			goto failed;
		}

		skge->duplex = (phystat & PHY_M_PS_FULL_DUP)
			? DUPLEX_FULL : DUPLEX_HALF;
		skge->speed = yukon_speed(hw, phystat);

		/* We are using IEEE 802.3z/D5.0 Table 37-4 */
		switch (phystat & PHY_M_PS_PAUSE_MSK) {
		case PHY_M_PS_PAUSE_MSK:
			skge->flow_status = FLOW_STAT_SYMMETRIC;
			break;
		case PHY_M_PS_RX_P_EN:
			skge->flow_status = FLOW_STAT_REM_SEND;
			break;
		case PHY_M_PS_TX_P_EN:
			skge->flow_status = FLOW_STAT_LOC_SEND;
			break;
		default:
			skge->flow_status = FLOW_STAT_NONE;
		}

		if (skge->flow_status == FLOW_STAT_NONE ||
		    (skge->speed < SPEED_1000 && skge->duplex == DUPLEX_HALF))
			skge_write8(hw, SK_REG(port, GMAC_CTRL), GMC_PAUSE_OFF);
		else
			skge_write8(hw, SK_REG(port, GMAC_CTRL), GMC_PAUSE_ON);
		yukon_link_up(skge);
		return;
	}

	if (istatus & PHY_M_IS_LSP_CHANGE)
		skge->speed = yukon_speed(hw, phystat);

	if (istatus & PHY_M_IS_DUP_CHANGE)
		skge->duplex = (phystat & PHY_M_PS_FULL_DUP) ? DUPLEX_FULL : DUPLEX_HALF;
	if (istatus & PHY_M_IS_LST_CHANGE) {
		if (phystat & PHY_M_PS_LINK_UP)
			yukon_link_up(skge);
		else
			yukon_link_down(skge);
	}
	return;
 failed:
	DBG(PFX "%s: autonegotiation failed (%s)\n",
	       skge->netdev->name, reason);

	/* XXX restart autonegotiation? */
}

static void skge_ramset(struct skge_hw *hw, u16 q, u32 start, size_t len)
{
	u32 end;

	start /= 8;
	len /= 8;
	end = start + len - 1;

	skge_write8(hw, RB_ADDR(q, RB_CTRL), RB_RST_CLR);
	skge_write32(hw, RB_ADDR(q, RB_START), start);
	skge_write32(hw, RB_ADDR(q, RB_WP), start);
	skge_write32(hw, RB_ADDR(q, RB_RP), start);
	skge_write32(hw, RB_ADDR(q, RB_END), end);

	if (q == Q_R1 || q == Q_R2) {
		/* Set thresholds on receive queue's */
		skge_write32(hw, RB_ADDR(q, RB_RX_UTPP),
			     start + (2*len)/3);
		skge_write32(hw, RB_ADDR(q, RB_RX_LTPP),
			     start + (len/3));
	} else {
		/* Enable store & forward on Tx queue's because
		 * Tx FIFO is only 4K on Genesis and 1K on Yukon
		 */
		skge_write8(hw, RB_ADDR(q, RB_CTRL), RB_ENA_STFWD);
	}

	skge_write8(hw, RB_ADDR(q, RB_CTRL), RB_ENA_OP_MD);
}

/* Setup Bus Memory Interface */
static void skge_qset(struct skge_port *skge, u16 q,
		      const struct skge_element *e)
{
	struct skge_hw *hw = skge->hw;
	u32 watermark = 0x600;
	u64 base = skge->dma + (e->desc - skge->mem);

	/* optimization to reduce window on 32bit/33mhz */
	if ((skge_read16(hw, B0_CTST) & (CS_BUS_CLOCK | CS_BUS_SLOT_SZ)) == 0)
		watermark /= 2;

	skge_write32(hw, Q_ADDR(q, Q_CSR), CSR_CLR_RESET);
	skge_write32(hw, Q_ADDR(q, Q_F), watermark);
	skge_write32(hw, Q_ADDR(q, Q_DA_H), (u32)(base >> 32));
	skge_write32(hw, Q_ADDR(q, Q_DA_L), (u32)base);
}

void skge_free(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);

	free(skge->rx_ring.start);
	skge->rx_ring.start = NULL;

	free(skge->tx_ring.start);
	skge->tx_ring.start = NULL;

	free_dma(skge->mem, RING_SIZE);
	skge->mem = NULL;
	skge->dma = 0;
}

static int skge_up(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_hw *hw = skge->hw;
	int port = skge->port;
	u32 chunk, ram_addr;
	int err;

	DBG2(PFX "%s: enabling interface\n", dev->name);

	skge->mem = malloc_dma(RING_SIZE, SKGE_RING_ALIGN);
	skge->dma = virt_to_bus(skge->mem);
	if (!skge->mem)
		return -ENOMEM;
	memset(skge->mem, 0, RING_SIZE);

	assert(!(skge->dma & 7));

	/* FIXME: find out whether 64 bit iPXE will be loaded > 4GB */
	if ((u64)skge->dma >> 32 != ((u64) skge->dma + RING_SIZE) >> 32) {
		DBG(PFX "pci_alloc_consistent region crosses 4G boundary\n");
		err = -EINVAL;
		goto err;
	}

	err = skge_ring_alloc(&skge->rx_ring, skge->mem, skge->dma, NUM_RX_DESC);
	if (err)
		goto err;

	/* this call relies on e->iob and d->control to be 0
	 * This is assured by calling memset() on skge->mem and using zalloc()
	 * for the skge_element structures.
	 */
	skge_rx_refill(dev);

	err = skge_ring_alloc(&skge->tx_ring, skge->mem + RX_RING_SIZE,
			      skge->dma + RX_RING_SIZE, NUM_TX_DESC);
	if (err)
		goto err;

	/* Initialize MAC */
	if (hw->chip_id == CHIP_ID_GENESIS)
		genesis_mac_init(hw, port);
	else
		yukon_mac_init(hw, port);

	/* Configure RAMbuffers - equally between ports and tx/rx */
	chunk = (hw->ram_size  - hw->ram_offset) / (hw->ports * 2);
	ram_addr = hw->ram_offset + 2 * chunk * port;

	skge_ramset(hw, rxqaddr[port], ram_addr, chunk);
	skge_qset(skge, rxqaddr[port], skge->rx_ring.to_clean);

	assert(!(skge->tx_ring.to_use != skge->tx_ring.to_clean));
	skge_ramset(hw, txqaddr[port], ram_addr+chunk, chunk);
	skge_qset(skge, txqaddr[port], skge->tx_ring.to_use);

	/* Start receiver BMU */
	wmb();
	skge_write8(hw, Q_ADDR(rxqaddr[port], Q_CSR), CSR_START | CSR_IRQ_CL_F);
	skge_led(skge, LED_MODE_ON);

	hw->intr_mask |= portmask[port];
	skge_write32(hw, B0_IMSK, hw->intr_mask);

	return 0;

 err:
	skge_rx_clean(skge);
	skge_free(dev);

	return err;
}

/* stop receiver */
static void skge_rx_stop(struct skge_hw *hw, int port)
{
	skge_write8(hw, Q_ADDR(rxqaddr[port], Q_CSR), CSR_STOP);
	skge_write32(hw, RB_ADDR(port ? Q_R2 : Q_R1, RB_CTRL),
		     RB_RST_SET|RB_DIS_OP_MD);
	skge_write32(hw, Q_ADDR(rxqaddr[port], Q_CSR), CSR_SET_RESET);
}

static void skge_down(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_hw *hw = skge->hw;
	int port = skge->port;

	if (skge->mem == NULL)
		return;

	DBG2(PFX "%s: disabling interface\n", dev->name);

	if (hw->chip_id == CHIP_ID_GENESIS && hw->phy_type == SK_PHY_XMAC)
		skge->use_xm_link_timer = 0;

	netdev_link_down(dev);

	hw->intr_mask &= ~portmask[port];
	skge_write32(hw, B0_IMSK, hw->intr_mask);

	skge_write8(skge->hw, SK_REG(skge->port, LNK_LED_REG), LED_OFF);
	if (hw->chip_id == CHIP_ID_GENESIS)
		genesis_stop(skge);
	else
		yukon_stop(skge);

	/* Stop transmitter */
	skge_write8(hw, Q_ADDR(txqaddr[port], Q_CSR), CSR_STOP);
	skge_write32(hw, RB_ADDR(txqaddr[port], RB_CTRL),
		     RB_RST_SET|RB_DIS_OP_MD);


	/* Disable Force Sync bit and Enable Alloc bit */
	skge_write8(hw, SK_REG(port, TXA_CTRL),
		    TXA_DIS_FSYNC | TXA_DIS_ALLOC | TXA_STOP_RC);

	/* Stop Interval Timer and Limit Counter of Tx Arbiter */
	skge_write32(hw, SK_REG(port, TXA_ITI_INI), 0L);
	skge_write32(hw, SK_REG(port, TXA_LIM_INI), 0L);

	/* Reset PCI FIFO */
	skge_write32(hw, Q_ADDR(txqaddr[port], Q_CSR), CSR_SET_RESET);
	skge_write32(hw, RB_ADDR(txqaddr[port], RB_CTRL), RB_RST_SET);

	/* Reset the RAM Buffer async Tx queue */
	skge_write8(hw, RB_ADDR(port == 0 ? Q_XA1 : Q_XA2, RB_CTRL), RB_RST_SET);

	skge_rx_stop(hw, port);

	if (hw->chip_id == CHIP_ID_GENESIS) {
		skge_write8(hw, SK_REG(port, TX_MFF_CTRL2), MFF_RST_SET);
		skge_write8(hw, SK_REG(port, RX_MFF_CTRL2), MFF_RST_SET);
	} else {
		skge_write8(hw, SK_REG(port, RX_GMF_CTRL_T), GMF_RST_SET);
		skge_write8(hw, SK_REG(port, TX_GMF_CTRL_T), GMF_RST_SET);
	}

	skge_led(skge, LED_MODE_OFF);

	skge_tx_clean(dev);

	skge_rx_clean(skge);

	skge_free(dev);
	return;
}

static inline int skge_tx_avail(const struct skge_ring *ring)
{
	mb();
	return ((ring->to_clean > ring->to_use) ? 0 : NUM_TX_DESC)
		+ (ring->to_clean - ring->to_use) - 1;
}

static int skge_xmit_frame(struct net_device *dev, struct io_buffer *iob)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_hw *hw = skge->hw;
	struct skge_element *e;
	struct skge_tx_desc *td;
	u32 control, len;
	u64 map;

	if (skge_tx_avail(&skge->tx_ring) < 1)
		return -EBUSY;

	e = skge->tx_ring.to_use;
	td = e->desc;
	assert(!(td->control & BMU_OWN));
	e->iob = iob;
	len = iob_len(iob);
	map = virt_to_bus(iob->data);

	td->dma_lo = map;
	td->dma_hi = map >> 32;

	control = BMU_CHECK;

	control |= BMU_EOF| BMU_IRQ_EOF;
	/* Make sure all the descriptors written */
	wmb();
	td->control = BMU_OWN | BMU_SW | BMU_STF | control | len;
	wmb();

	skge_write8(hw, Q_ADDR(txqaddr[skge->port], Q_CSR), CSR_START);

	DBGIO(PFX "%s: tx queued, slot %td, len %d\n",
	     dev->name, e - skge->tx_ring.start, (unsigned int)len);

	skge->tx_ring.to_use = e->next;
	wmb();

	if (skge_tx_avail(&skge->tx_ring) <= 1) {
		DBG(PFX "%s: transmit queue full\n", dev->name);
	}

	return 0;
}

/* Free all buffers in transmit ring */
static void skge_tx_clean(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_element *e;

	for (e = skge->tx_ring.to_clean; e != skge->tx_ring.to_use; e = e->next) {
		struct skge_tx_desc *td = e->desc;
		td->control = 0;
	}

	skge->tx_ring.to_clean = e;
}

static const u8 pause_mc_addr[ETH_ALEN] = { 0x1, 0x80, 0xc2, 0x0, 0x0, 0x1 };

static inline u16 phy_length(const struct skge_hw *hw, u32 status)
{
	if (hw->chip_id == CHIP_ID_GENESIS)
		return status >> XMR_FS_LEN_SHIFT;
	else
		return status >> GMR_FS_LEN_SHIFT;
}

static inline int bad_phy_status(const struct skge_hw *hw, u32 status)
{
	if (hw->chip_id == CHIP_ID_GENESIS)
		return (status & (XMR_FS_ERR | XMR_FS_2L_VLAN)) != 0;
	else
		return (status & GMR_FS_ANY_ERR) ||
			(status & GMR_FS_RX_OK) == 0;
}

/* Free all buffers in Tx ring which are no longer owned by device */
static void skge_tx_done(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_ring *ring = &skge->tx_ring;
	struct skge_element *e;

	skge_write8(skge->hw, Q_ADDR(txqaddr[skge->port], Q_CSR), CSR_IRQ_CL_F);

	for (e = ring->to_clean; e != ring->to_use; e = e->next) {
		u32 control = ((const struct skge_tx_desc *) e->desc)->control;

		if (control & BMU_OWN)
			break;

		netdev_tx_complete(dev, e->iob);
	}
	skge->tx_ring.to_clean = e;

	/* Can run lockless until we need to synchronize to restart queue. */
	mb();
}

static void skge_rx_refill(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_ring *ring = &skge->rx_ring;
	struct skge_element *e;
	struct io_buffer *iob;
	struct skge_rx_desc *rd;
	u32 control;
	int i;

	for (i = 0; i < NUM_RX_DESC; i++) {
		e = ring->to_clean;
		rd = e->desc;
		iob = e->iob;
		control = rd->control;

		/* nothing to do here */
		if (iob || (control & BMU_OWN))
			continue;

		DBG2("refilling rx desc %zd: ", (ring->to_clean - ring->start));

		iob = alloc_iob(RX_BUF_SIZE);
		if (iob) {
			skge_rx_setup(skge, e, iob, RX_BUF_SIZE);
		} else {
			DBG("descr %zd: alloc_iob() failed\n",
			     (ring->to_clean - ring->start));
			/* We pass the descriptor to the NIC even if the
			 * allocation failed. The card will stop as soon as it
			 * encounters a descriptor with the OWN bit set to 0,
			 * thus never getting to the next descriptor that might
			 * contain a valid io_buffer. This would effectively
			 * stall the receive.
			 */
			skge_rx_setup(skge, e, NULL, 0);
		}

		ring->to_clean = e->next;
	}
}

static void skge_rx_done(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_ring *ring = &skge->rx_ring;
	struct skge_rx_desc *rd;
	struct skge_element *e;
	struct io_buffer *iob;
	u32 control;
	u16 len;
	int i;

	e = ring->to_clean;
	for (i = 0; i < NUM_RX_DESC; i++) {
		iob = e->iob;
		rd = e->desc;

		rmb();
		control = rd->control;

		if ((control & BMU_OWN))
			break;

		if (!iob)
			continue;

		len = control & BMU_BBC;

		/* catch RX errors */
		if ((bad_phy_status(skge->hw, rd->status)) ||
		   (phy_length(skge->hw, rd->status) != len)) {
			/* report receive errors */
			DBG("rx error\n");
			netdev_rx_err(dev, iob, -EIO);
		} else {
			DBG2("received packet, len %d\n", len);
			iob_put(iob, len);
			netdev_rx(dev, iob);
		}

		/* io_buffer passed to core, make sure we don't reuse it */
		e->iob = NULL;

		e = e->next;
	}
	skge_rx_refill(dev);
}

static void skge_poll(struct net_device *dev)
{
	struct skge_port *skge = netdev_priv(dev);
	struct skge_hw *hw = skge->hw;
	u32 status;

	/* reading this register ACKs interrupts */
	status = skge_read32(hw, B0_SP_ISRC);

	/* Link event? */
	if (status & IS_EXT_REG) {
		skge_phyirq(hw);
		if (skge->use_xm_link_timer)
			xm_link_timer(skge);
	}

	skge_tx_done(dev);

	skge_write8(hw, Q_ADDR(rxqaddr[skge->port], Q_CSR), CSR_IRQ_CL_F);

	skge_rx_done(dev);

	/* restart receiver */
	wmb();
	skge_write8(hw, Q_ADDR(rxqaddr[skge->port], Q_CSR), CSR_START);

	skge_read32(hw, B0_IMSK);

	return;
}

static void skge_phyirq(struct skge_hw *hw)
{
	int port;

	for (port = 0; port < hw->ports; port++) {
		struct net_device *dev = hw->dev[port];
		struct skge_port *skge = netdev_priv(dev);

		if (hw->chip_id != CHIP_ID_GENESIS)
			yukon_phy_intr(skge);
		else if (hw->phy_type == SK_PHY_BCOM)
			bcom_phy_intr(skge);
	}

	hw->intr_mask |= IS_EXT_REG;
	skge_write32(hw, B0_IMSK, hw->intr_mask);
	skge_read32(hw, B0_IMSK);
}

static const struct {
	u8 id;
	const char *name;
} skge_chips[] = {
	{ CHIP_ID_GENESIS,	"Genesis" },
	{ CHIP_ID_YUKON,	 "Yukon" },
	{ CHIP_ID_YUKON_LITE,	 "Yukon-Lite"},
	{ CHIP_ID_YUKON_LP,	 "Yukon-LP"},
};

static const char *skge_board_name(const struct skge_hw *hw)
{
	unsigned int i;
	static char buf[16];

	for (i = 0; i < ARRAY_SIZE(skge_chips); i++)
		if (skge_chips[i].id == hw->chip_id)
			return skge_chips[i].name;

	snprintf(buf, sizeof buf, "chipid 0x%x", hw->chip_id);
	return buf;
}


/*
 * Setup the board data structure, but don't bring up
 * the port(s)
 */
static int skge_reset(struct skge_hw *hw)
{
	u32 reg;
	u16 ctst, pci_status;
	u8 t8, mac_cfg, pmd_type;
	int i;

	ctst = skge_read16(hw, B0_CTST);

	/* do a SW reset */
	skge_write8(hw, B0_CTST, CS_RST_SET);
	skge_write8(hw, B0_CTST, CS_RST_CLR);

	/* clear PCI errors, if any */
	skge_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_ON);
	skge_write8(hw, B2_TST_CTRL2, 0);

	pci_read_config_word(hw->pdev, PCI_STATUS, &pci_status);
	pci_write_config_word(hw->pdev, PCI_STATUS,
			      pci_status | PCI_STATUS_ERROR_BITS);
	skge_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
	skge_write8(hw, B0_CTST, CS_MRST_CLR);

	/* restore CLK_RUN bits (for Yukon-Lite) */
	skge_write16(hw, B0_CTST,
		     ctst & (CS_CLK_RUN_HOT|CS_CLK_RUN_RST|CS_CLK_RUN_ENA));

	hw->chip_id = skge_read8(hw, B2_CHIP_ID);
	hw->phy_type = skge_read8(hw, B2_E_1) & 0xf;
	pmd_type = skge_read8(hw, B2_PMD_TYP);
	hw->copper = (pmd_type == 'T' || pmd_type == '1');

	switch (hw->chip_id) {
	case CHIP_ID_GENESIS:
		switch (hw->phy_type) {
		case SK_PHY_XMAC:
			hw->phy_addr = PHY_ADDR_XMAC;
			break;
		case SK_PHY_BCOM:
			hw->phy_addr = PHY_ADDR_BCOM;
			break;
		default:
			DBG(PFX "unsupported phy type 0x%x\n",
			       hw->phy_type);
			return -EOPNOTSUPP;
		}
		break;

	case CHIP_ID_YUKON:
	case CHIP_ID_YUKON_LITE:
	case CHIP_ID_YUKON_LP:
		if (hw->phy_type < SK_PHY_MARV_COPPER && pmd_type != 'S')
			hw->copper = 1;

		hw->phy_addr = PHY_ADDR_MARV;
		break;

	default:
		DBG(PFX "unsupported chip type 0x%x\n",
		       hw->chip_id);
		return -EOPNOTSUPP;
	}

	mac_cfg = skge_read8(hw, B2_MAC_CFG);
	hw->ports = (mac_cfg & CFG_SNG_MAC) ? 1 : 2;
	hw->chip_rev = (mac_cfg & CFG_CHIP_R_MSK) >> 4;

	/* read the adapters RAM size */
	t8 = skge_read8(hw, B2_E_0);
	if (hw->chip_id == CHIP_ID_GENESIS) {
		if (t8 == 3) {
			/* special case: 4 x 64k x 36, offset = 0x80000 */
			hw->ram_size = 0x100000;
			hw->ram_offset = 0x80000;
		} else
			hw->ram_size = t8 * 512;
	}
	else if (t8 == 0)
		hw->ram_size = 0x20000;
	else
		hw->ram_size = t8 * 4096;

	hw->intr_mask = IS_HW_ERR;

	/* Use PHY IRQ for all but fiber based Genesis board */
	if (!(hw->chip_id == CHIP_ID_GENESIS && hw->phy_type == SK_PHY_XMAC))
		hw->intr_mask |= IS_EXT_REG;

	if (hw->chip_id == CHIP_ID_GENESIS)
		genesis_init(hw);
	else {
		/* switch power to VCC (WA for VAUX problem) */
		skge_write8(hw, B0_POWER_CTRL,
			    PC_VAUX_ENA | PC_VCC_ENA | PC_VAUX_OFF | PC_VCC_ON);

		/* avoid boards with stuck Hardware error bits */
		if ((skge_read32(hw, B0_ISRC) & IS_HW_ERR) &&
		    (skge_read32(hw, B0_HWE_ISRC) & IS_IRQ_SENSOR)) {
			DBG(PFX "stuck hardware sensor bit\n");
			hw->intr_mask &= ~IS_HW_ERR;
		}

		/* Clear PHY COMA */
		skge_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_ON);
		pci_read_config_dword(hw->pdev, PCI_DEV_REG1, &reg);
		reg &= ~PCI_PHY_COMA;
		pci_write_config_dword(hw->pdev, PCI_DEV_REG1, reg);
		skge_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_OFF);


		for (i = 0; i < hw->ports; i++) {
			skge_write16(hw, SK_REG(i, GMAC_LINK_CTRL), GMLC_RST_SET);
			skge_write16(hw, SK_REG(i, GMAC_LINK_CTRL), GMLC_RST_CLR);
		}
	}

	/* turn off hardware timer (unused) */
	skge_write8(hw, B2_TI_CTRL, TIM_STOP);
	skge_write8(hw, B2_TI_CTRL, TIM_CLR_IRQ);
	skge_write8(hw, B0_LED, LED_STAT_ON);

	/* enable the Tx Arbiters */
	for (i = 0; i < hw->ports; i++)
		skge_write8(hw, SK_REG(i, TXA_CTRL), TXA_ENA_ARB);

	/* Initialize ram interface */
	skge_write16(hw, B3_RI_CTRL, RI_RST_CLR);

	skge_write8(hw, B3_RI_WTO_R1, SK_RI_TO_53);
	skge_write8(hw, B3_RI_WTO_XA1, SK_RI_TO_53);
	skge_write8(hw, B3_RI_WTO_XS1, SK_RI_TO_53);
	skge_write8(hw, B3_RI_RTO_R1, SK_RI_TO_53);
	skge_write8(hw, B3_RI_RTO_XA1, SK_RI_TO_53);
	skge_write8(hw, B3_RI_RTO_XS1, SK_RI_TO_53);
	skge_write8(hw, B3_RI_WTO_R2, SK_RI_TO_53);
	skge_write8(hw, B3_RI_WTO_XA2, SK_RI_TO_53);
	skge_write8(hw, B3_RI_WTO_XS2, SK_RI_TO_53);
	skge_write8(hw, B3_RI_RTO_R2, SK_RI_TO_53);
	skge_write8(hw, B3_RI_RTO_XA2, SK_RI_TO_53);
	skge_write8(hw, B3_RI_RTO_XS2, SK_RI_TO_53);

	skge_write32(hw, B0_HWE_IMSK, IS_ERR_MSK);

	/* Set interrupt moderation for Transmit only
	 * Receive interrupts avoided by NAPI
	 */
	skge_write32(hw, B2_IRQM_MSK, IS_XA1_F|IS_XA2_F);
	skge_write32(hw, B2_IRQM_INI, skge_usecs2clk(hw, 100));
	skge_write32(hw, B2_IRQM_CTRL, TIM_START);

	skge_write32(hw, B0_IMSK, hw->intr_mask);

	for (i = 0; i < hw->ports; i++) {
		if (hw->chip_id == CHIP_ID_GENESIS)
			genesis_reset(hw, i);
		else
			yukon_reset(hw, i);
	}

	return 0;
}

/* Initialize network device */
static struct net_device *skge_devinit(struct skge_hw *hw, int port,
				       int highmem __unused)
{
	struct skge_port *skge;
	struct net_device *dev = alloc_etherdev(sizeof(*skge));

	if (!dev) {
		DBG(PFX "etherdev alloc failed\n");
		return NULL;
	}

	dev->dev = &hw->pdev->dev;

	skge = netdev_priv(dev);
	skge->netdev = dev;
	skge->hw = hw;

	/* Auto speed and flow control */
	skge->autoneg = AUTONEG_ENABLE;
	skge->flow_control = FLOW_MODE_SYM_OR_REM;
	skge->duplex = -1;
	skge->speed = -1;
	skge->advertising = skge_supported_modes(hw);

	hw->dev[port] = dev;

	skge->port = port;

	/* read the mac address */
	memcpy(dev->hw_addr, (void *) (hw->regs + B2_MAC_1 + port*8), ETH_ALEN);

	return dev;
}

static void skge_show_addr(struct net_device *dev)
{
	DBG2(PFX "%s: addr %s\n",
	     dev->name, netdev_addr(dev));
}

static int skge_probe(struct pci_device *pdev)
{
	struct net_device *dev, *dev1;
	struct skge_hw *hw;
	int err, using_dac = 0;

	adjust_pci_device(pdev);

	err = -ENOMEM;
	hw = zalloc(sizeof(*hw));
	if (!hw) {
		DBG(PFX "cannot allocate hardware struct\n");
		goto err_out_free_regions;
	}

	hw->pdev = pdev;

	hw->regs = (unsigned long)ioremap(pci_bar_start(pdev, PCI_BASE_ADDRESS_0),
				SKGE_REG_SIZE);
	if (!hw->regs) {
		DBG(PFX "cannot map device registers\n");
		goto err_out_free_hw;
	}

	err = skge_reset(hw);
	if (err)
		goto err_out_iounmap;

	DBG(PFX " addr 0x%llx irq %d chip %s rev %d\n",
	    (unsigned long long)pdev->ioaddr, pdev->irq,
	    skge_board_name(hw), hw->chip_rev);

	dev = skge_devinit(hw, 0, using_dac);
	if (!dev)
		goto err_out_led_off;

	netdev_init ( dev, &skge_operations );

	err = register_netdev(dev);
	if (err) {
		DBG(PFX "cannot register net device\n");
		goto err_out_free_netdev;
	}

	skge_show_addr(dev);

	if (hw->ports > 1 && (dev1 = skge_devinit(hw, 1, using_dac))) {
		if (register_netdev(dev1) == 0)
			skge_show_addr(dev1);
		else {
			/* Failure to register second port need not be fatal */
			DBG(PFX "register of second port failed\n");
			hw->dev[1] = NULL;
			netdev_nullify(dev1);
			netdev_put(dev1);
		}
	}
	pci_set_drvdata(pdev, hw);

	return 0;

err_out_free_netdev:
	netdev_nullify(dev);
	netdev_put(dev);
err_out_led_off:
	skge_write16(hw, B0_LED, LED_STAT_OFF);
err_out_iounmap:
	iounmap((void*)hw->regs);
err_out_free_hw:
	free(hw);
err_out_free_regions:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void skge_remove(struct pci_device *pdev)
{
	struct skge_hw *hw  = pci_get_drvdata(pdev);
	struct net_device *dev0, *dev1;

	if (!hw)
		return;

	if ((dev1 = hw->dev[1]))
		unregister_netdev(dev1);
	dev0 = hw->dev[0];
	unregister_netdev(dev0);

	hw->intr_mask = 0;
	skge_write32(hw, B0_IMSK, 0);
	skge_read32(hw, B0_IMSK);

	skge_write16(hw, B0_LED, LED_STAT_OFF);
	skge_write8(hw, B0_CTST, CS_RST_SET);

	if (dev1) {
		netdev_nullify(dev1);
		netdev_put(dev1);
	}
	netdev_nullify(dev0);
	netdev_put(dev0);

	iounmap((void*)hw->regs);
	free(hw);
	pci_set_drvdata(pdev, NULL);
}

/*
 * Enable or disable IRQ masking.
 *
 * @v netdev		Device to control.
 * @v enable		Zero to mask off IRQ, non-zero to enable IRQ.
 *
 * This is a iPXE Network Driver API function.
 */
static void skge_net_irq ( struct net_device *dev, int enable ) {
	struct skge_port *skge = netdev_priv(dev);
	struct skge_hw *hw = skge->hw;

	if (enable)
		hw->intr_mask |= portmask[skge->port];
	else
		hw->intr_mask &= ~portmask[skge->port];
	skge_write32(hw, B0_IMSK, hw->intr_mask);
}

struct pci_driver skge_driver __pci_driver = {
	.ids      = skge_id_table,
	.id_count = ( sizeof (skge_id_table) / sizeof (skge_id_table[0]) ),
	.probe    = skge_probe,
	.remove   = skge_remove
};

