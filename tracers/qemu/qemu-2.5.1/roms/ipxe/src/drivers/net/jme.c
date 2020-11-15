/*
 * JMicron JMC2x0 series PCIe Ethernet gPXE Device Driver
 *
 * Copyright 2010 Guo-Fu Tseng <cooldavid@cooldavid.org>
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
 *
 */
FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ipxe/io.h>
#include <errno.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/malloc.h>
#include <mii.h>
#include "jme.h"

static int
jme_mdio_read(struct net_device *netdev, int phy, int reg)
{
	struct jme_adapter *jme = netdev->priv;
	int i, val, again = (reg == MII_BMSR) ? 1 : 0;

read_again:
	jwrite32(jme, JME_SMI, SMI_OP_REQ |
				smi_phy_addr(phy) |
				smi_reg_addr(reg));

	for (i = JME_PHY_TIMEOUT * 50 ; i > 0 ; --i) {
		udelay(20);
		val = jread32(jme, JME_SMI);
		if ((val & SMI_OP_REQ) == 0)
			break;
	}

	if (i == 0) {
		DBG("phy(%d) read timeout : %d\n", phy, reg);
		return 0;
	}

	if (again--)
		goto read_again;

	return (val & SMI_DATA_MASK) >> SMI_DATA_SHIFT;
}

static void
jme_mdio_write(struct net_device *netdev,
				int phy, int reg, int val)
{
	struct jme_adapter *jme = netdev->priv;
	int i;

	jwrite32(jme, JME_SMI, SMI_OP_WRITE | SMI_OP_REQ |
		((val << SMI_DATA_SHIFT) & SMI_DATA_MASK) |
		smi_phy_addr(phy) | smi_reg_addr(reg));

	wmb();
	for (i = JME_PHY_TIMEOUT * 50 ; i > 0 ; --i) {
		udelay(20);
		if ((jread32(jme, JME_SMI) & SMI_OP_REQ) == 0)
			break;
	}

	if (i == 0)
		DBG("phy(%d) write timeout : %d\n", phy, reg);

	return;
}

static void
jme_reset_phy_processor(struct jme_adapter *jme)
{
	u32 val;

	jme_mdio_write(jme->mii_if.dev,
			jme->mii_if.phy_id,
			MII_ADVERTISE, ADVERTISE_ALL |
			ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);

	if (jme->pdev->device == PCI_DEVICE_ID_JMICRON_JMC250)
		jme_mdio_write(jme->mii_if.dev,
				jme->mii_if.phy_id,
				MII_CTRL1000,
				ADVERTISE_1000FULL | ADVERTISE_1000HALF);

	val = jme_mdio_read(jme->mii_if.dev,
				jme->mii_if.phy_id,
				MII_BMCR);

	jme_mdio_write(jme->mii_if.dev,
			jme->mii_if.phy_id,
			MII_BMCR, val | BMCR_RESET);

	return;
}

static void
jme_phy_init(struct jme_adapter *jme)
{
	u16 reg26;

	reg26 = jme_mdio_read(jme->mii_if.dev, jme->mii_if.phy_id, 26);
	jme_mdio_write(jme->mii_if.dev, jme->mii_if.phy_id, 26, reg26 | 0x1000);
}

static void
jme_set_phyfifoa(struct jme_adapter *jme)
{
	jme_mdio_write(jme->mii_if.dev, jme->mii_if.phy_id, 27, 0x0004);
}

static void
jme_set_phyfifob(struct jme_adapter *jme)
{
	jme_mdio_write(jme->mii_if.dev, jme->mii_if.phy_id, 27, 0x0000);
}

static void
jme_phy_off(struct jme_adapter *jme)
{
	jme_mdio_write(jme->mii_if.dev, jme->mii_if.phy_id, MII_BMCR, BMCR_PDOWN);
}

static void
jme_restart_an(struct jme_adapter *jme)
{
	uint32_t bmcr;

	bmcr = jme_mdio_read(jme->mii_if.dev, jme->mii_if.phy_id, MII_BMCR);
	bmcr |= (BMCR_ANENABLE | BMCR_ANRESTART);
	jme_mdio_write(jme->mii_if.dev, jme->mii_if.phy_id, MII_BMCR, bmcr);
}

static void
jme_reset_ghc_speed(struct jme_adapter *jme)
{
	jme->reg_ghc &= ~(GHC_SPEED_1000M | GHC_DPX);
	jwrite32(jme, JME_GHC, jme->reg_ghc);
}

static void
jme_start_irq(struct jme_adapter *jme)
{
	/*
	 * Enable Interrupts
	 */
	jwrite32(jme, JME_IENS, INTR_ENABLE);
}

static void
jme_stop_irq(struct jme_adapter *jme)
{
	/*
	 * Disable Interrupts
	 */
	jwrite32f(jme, JME_IENC, INTR_ENABLE);
}

static void
jme_setup_wakeup_frame(struct jme_adapter *jme,
		u32 *mask, u32 crc, int fnr)
{
	int i;

	/*
	 * Setup CRC pattern
	 */
	jwrite32(jme, JME_WFOI, WFOI_CRC_SEL | (fnr & WFOI_FRAME_SEL));
	wmb();
	jwrite32(jme, JME_WFODP, crc);
	wmb();

	/*
	 * Setup Mask
	 */
	for (i = 0 ; i < WAKEUP_FRAME_MASK_DWNR ; ++i) {
		jwrite32(jme, JME_WFOI,
				((i << WFOI_MASK_SHIFT) & WFOI_MASK_SEL) |
				(fnr & WFOI_FRAME_SEL));
		wmb();
		jwrite32(jme, JME_WFODP, mask[i]);
		wmb();
	}
}

static void
jme_reset_mac_processor(struct jme_adapter *jme)
{
	u32 mask[WAKEUP_FRAME_MASK_DWNR] = {0, 0, 0, 0};
	u32 crc = 0xCDCDCDCD;
	int i;

	jwrite32(jme, JME_GHC, jme->reg_ghc | GHC_SWRST);
	udelay(2);
	jwrite32(jme, JME_GHC, jme->reg_ghc);

	jwrite32(jme, JME_RXDBA_LO, 0x00000000);
	jwrite32(jme, JME_RXDBA_HI, 0x00000000);
	jwrite32(jme, JME_RXQDC, 0x00000000);
	jwrite32(jme, JME_RXNDA, 0x00000000);
	jwrite32(jme, JME_TXDBA_LO, 0x00000000);
	jwrite32(jme, JME_TXDBA_HI, 0x00000000);
	jwrite32(jme, JME_TXQDC, 0x00000000);
	jwrite32(jme, JME_TXNDA, 0x00000000);

	jwrite32(jme, JME_RXMCHT_LO, 0x00000000);
	jwrite32(jme, JME_RXMCHT_HI, 0x00000000);
	for (i = 0 ; i < WAKEUP_FRAME_NR ; ++i)
		jme_setup_wakeup_frame(jme, mask, crc, i);
	jwrite32(jme, JME_GPREG0, GPREG0_DEFAULT);
	jwrite32(jme, JME_GPREG1, GPREG1_DEFAULT);
}

static void
jme_free_tx_buffers(struct jme_adapter *jme)
{
	struct jme_ring *txring = &jme->txring;
	struct io_buffer *txbi;
	unsigned int i;

	for (i = 0; i < jme->tx_ring_size; ++i) {
		txbi = txring->bufinf[i];
		if (txbi) {
			netdev_tx_complete_err(jme->mii_if.dev,
					txbi, -ENOLINK);
			txring->bufinf[i] = NULL;
		}
	}
}

static void
jme_free_tx_resources(struct jme_adapter *jme)
{
	struct jme_ring *txring = &jme->txring;

	if (txring->desc) {
		if (txring->bufinf) {
			memset(txring->bufinf, 0,
				sizeof(struct io_buffer *) * jme->tx_ring_size);
			free(txring->bufinf);
		}
		free_dma(txring->desc, jme->tx_ring_size * TX_DESC_SIZE);
		txring->desc		= NULL;
		txring->dma		= 0;
		txring->bufinf		= NULL;
	}
	txring->next_to_use	= 0;
	txring->next_to_clean	= 0;
	txring->nr_free		= 0;
}

static int
jme_alloc_tx_resources(struct jme_adapter *jme)
{
	struct jme_ring *txring = &jme->txring;

	txring->desc = malloc_dma(jme->tx_ring_size * TX_DESC_SIZE,
					RING_DESC_ALIGN);
	if (!txring->desc) {
		DBG("Can not allocate transmit ring descriptors.\n");
		goto err_out;
	}

	/*
	 * 16 Bytes align
	 */
	txring->dma		= virt_to_bus(txring->desc);
	txring->bufinf		= malloc(sizeof(struct io_buffer *) *
					jme->tx_ring_size);
	if (!(txring->bufinf)) {
		DBG("Can not allocate transmit buffer info.\n");
		goto err_out;
	}

	/*
	 * Initialize Transmit Buffer Pointers
	 */
	memset(txring->bufinf, 0,
		sizeof(struct io_buffer *) * jme->tx_ring_size);

	return 0;

err_out:
	jme_free_tx_resources(jme);
	return -ENOMEM;
}

static void
jme_init_tx_ring(struct jme_adapter *jme)
{
	struct jme_ring *txring = &jme->txring;

	txring->next_to_clean	= 0;
	txring->next_to_use	= 0;
	txring->nr_free		= jme->tx_ring_size;

	/*
	 * Initialize Transmit Descriptors
	 */
	memset(txring->desc, 0, jme->tx_ring_size * TX_DESC_SIZE);
	jme_free_tx_buffers(jme);
}

static void
jme_enable_tx_engine(struct jme_adapter *jme)
{
	/*
	 * Select Queue 0
	 */
	jwrite32(jme, JME_TXCS, TXCS_DEFAULT | TXCS_SELECT_QUEUE0);
	wmb();

	/*
	 * Setup TX Queue 0 DMA Bass Address
	 */
	jwrite32(jme, JME_TXDBA_LO, (uint64_t)jme->txring.dma & 0xFFFFFFFFUL);
	jwrite32(jme, JME_TXDBA_HI, (uint64_t)(jme->txring.dma) >> 32);
	jwrite32(jme, JME_TXNDA, (uint64_t)jme->txring.dma & 0xFFFFFFFFUL);

	/*
	 * Setup TX Descptor Count
	 */
	jwrite32(jme, JME_TXQDC, jme->tx_ring_size);

	/*
	 * Enable TX Engine
	 */
	wmb();
	jwrite32(jme, JME_TXCS, jme->reg_txcs |
				TXCS_SELECT_QUEUE0 |
				TXCS_ENABLE);

}

static void
jme_disable_tx_engine(struct jme_adapter *jme)
{
	int i;
	u32 val;

	/*
	 * Disable TX Engine
	 */
	jwrite32(jme, JME_TXCS, jme->reg_txcs | TXCS_SELECT_QUEUE0);
	wmb();

	val = jread32(jme, JME_TXCS);
	for (i = JME_TX_DISABLE_TIMEOUT ; (val & TXCS_ENABLE) && i > 0 ; --i) {
		mdelay(1);
		val = jread32(jme, JME_TXCS);
		rmb();
	}

	if (!i)
		DBG("Disable TX engine timeout.\n");
}


static void
jme_set_clean_rxdesc(struct jme_adapter *jme, int i)
{
	struct jme_ring *rxring = &jme->rxring;
	register struct rxdesc *rxdesc = rxring->desc;
	struct io_buffer *rxbi = rxring->bufinf[i];
	uint64_t mapping;

	rxdesc += i;
	mapping = virt_to_bus(rxbi->data);

	rxdesc->dw[0] = 0;
	rxdesc->dw[1] = 0;
	rxdesc->desc1.bufaddrh	= cpu_to_le32(mapping >> 32);
	rxdesc->desc1.bufaddrl	= cpu_to_le32(mapping & 0xFFFFFFFFUL);
	rxdesc->desc1.datalen	= cpu_to_le16(RX_ALLOC_LEN);
	wmb();
	rxdesc->desc1.flags	|= RXFLAG_OWN | RXFLAG_INT;
}

static int
jme_make_new_rx_buf(struct io_buffer **rxbip)
{
	struct io_buffer *inbuf;

	/*
	 * IOB_ALIGN == 2048
	 */
	inbuf = alloc_iob(RX_ALLOC_LEN);
	if (!inbuf) {
		DBG("Allocate receive iob error.\n");
		return -ENOMEM;
	}
	*rxbip = inbuf;

	return 0;
}

static void
jme_free_rx_buf(struct jme_adapter *jme, int i)
{
	struct jme_ring *rxring = &jme->rxring;
	struct io_buffer *rxbi = rxring->bufinf[i];

	if (rxbi) {
		free_iob(rxbi);
		rxring->bufinf[i] = NULL;
	}
}

static void
jme_free_rx_resources(struct jme_adapter *jme)
{
	unsigned int i;
	struct jme_ring *rxring = &jme->rxring;

	if (rxring->desc) {
		if (rxring->bufinf) {
			for (i = 0 ; i < jme->rx_ring_size ; ++i)
				jme_free_rx_buf(jme, i);
			free(rxring->bufinf);
		}

		free_dma(rxring->desc, jme->rx_ring_size * RX_DESC_SIZE);
		rxring->desc     = NULL;
		rxring->dma      = 0;
		rxring->bufinf   = NULL;
	}
	rxring->next_to_fill = 0;
	rxring->next_to_clean = 0;
}

static int
jme_alloc_rx_resources(struct jme_adapter *jme)
{
	unsigned int i;
	struct jme_ring *rxring = &jme->rxring;
	struct io_buffer **bufinf;

	rxring->desc = malloc_dma(jme->rx_ring_size * RX_DESC_SIZE,
			RING_DESC_ALIGN);
	if (!rxring->desc) {
		DBG("Can not allocate receive ring descriptors.\n");
		goto err_out;
	}

	/*
	 * 16 Bytes align
	 */
	rxring->dma		= virt_to_bus(rxring->desc);
	rxring->bufinf		= malloc(sizeof(struct io_buffer *) *
					jme->rx_ring_size);
	if (!(rxring->bufinf)) {
		DBG("Can not allocate receive buffer info.\n");
		goto err_out;
	}

	/*
	 * Initiallize Receive Buffer Pointers
	 */
	bufinf = rxring->bufinf;
	memset(bufinf, 0, sizeof(struct io_buffer *) * jme->rx_ring_size);
	for (i = 0 ; i < jme->rx_ring_size ; ++i) {
		if (jme_make_new_rx_buf(bufinf))
			goto err_out;
		++bufinf;
	}

	return 0;

err_out:
	jme_free_rx_resources(jme);
	return -ENOMEM;
}

static void
jme_init_rx_ring(struct jme_adapter *jme)
{
	unsigned int i;
	struct jme_ring *rxring = &jme->rxring;

	for (i = 0 ; i < jme->rx_ring_size ; ++i)
		jme_set_clean_rxdesc(jme, i);

	rxring->next_to_fill = 0;
	rxring->next_to_clean = 0;
}

static void
jme_set_multi(struct jme_adapter *jme)
{
	/*
	 * Just receive all kind of packet for new.
	 */
	jme->reg_rxmcs |= RXMCS_ALLFRAME | RXMCS_BRDFRAME | RXMCS_UNIFRAME;
	jwrite32(jme, JME_RXMCS, jme->reg_rxmcs);
}

static void
jme_enable_rx_engine(struct jme_adapter *jme)
{
	/*
	 * Select Queue 0
	 */
	jwrite32(jme, JME_RXCS, jme->reg_rxcs |
				RXCS_QUEUESEL_Q0);
	wmb();

	/*
	 * Setup RX DMA Bass Address
	 */
	jwrite32(jme, JME_RXDBA_LO, (uint64_t)(jme->rxring.dma) & 0xFFFFFFFFUL);
	jwrite32(jme, JME_RXDBA_HI, (uint64_t)(jme->rxring.dma) >> 32);
	jwrite32(jme, JME_RXNDA, (uint64_t)(jme->rxring.dma) & 0xFFFFFFFFUL);

	/*
	 * Setup RX Descriptor Count
	 */
	jwrite32(jme, JME_RXQDC, jme->rx_ring_size);

	/*
	 * Setup Unicast Filter
	 */
	jme_set_multi(jme);

	/*
	 * Enable RX Engine
	 */
	wmb();
	jwrite32(jme, JME_RXCS, jme->reg_rxcs |
				RXCS_QUEUESEL_Q0 |
				RXCS_ENABLE |
				RXCS_QST);
}

static void
jme_restart_rx_engine(struct jme_adapter *jme)
{
	/*
	 * Start RX Engine
	 */
	jwrite32(jme, JME_RXCS, jme->reg_rxcs |
				RXCS_QUEUESEL_Q0 |
				RXCS_ENABLE |
				RXCS_QST);
}

static void
jme_disable_rx_engine(struct jme_adapter *jme)
{
	int i;
	u32 val;

	/*
	 * Disable RX Engine
	 */
	jwrite32(jme, JME_RXCS, jme->reg_rxcs);
	wmb();

	val = jread32(jme, JME_RXCS);
	for (i = JME_RX_DISABLE_TIMEOUT ; (val & RXCS_ENABLE) && i > 0 ; --i) {
		mdelay(1);
		val = jread32(jme, JME_RXCS);
		rmb();
	}

	if (!i)
		DBG("Disable RX engine timeout.\n");

}

static void
jme_refill_rx_ring(struct jme_adapter *jme, int curhole)
{
	struct jme_ring *rxring = &jme->rxring;
	int i = rxring->next_to_fill;
	struct io_buffer **bufinf = rxring->bufinf;
	int mask = jme->rx_ring_mask;
	int limit = jme->rx_ring_size;

	while (limit--) {
		if (!bufinf[i]) {
			if (jme_make_new_rx_buf(bufinf + i))
				break;
			jme_set_clean_rxdesc(jme, i);
		}
		if (i == curhole)
			limit = 0;
		i = (i + 1) & mask;
	}
	rxring->next_to_fill = i;
}

static void
jme_alloc_and_feed_iob(struct jme_adapter *jme, int idx)
{
	struct jme_ring *rxring = &jme->rxring;
	struct rxdesc *rxdesc = rxring->desc;
	struct io_buffer *rxbi = rxring->bufinf[idx];
	struct net_device *netdev = jme->mii_if.dev;
	int framesize;

	rxdesc += idx;

	framesize = le16_to_cpu(rxdesc->descwb.framesize);
	iob_put(rxbi, framesize);
	netdev_rx(netdev, rxbi);

	rxring->bufinf[idx] = NULL;
	jme_refill_rx_ring(jme, idx);
}

static void
jme_process_receive(struct jme_adapter *jme)
{
	struct jme_ring *rxring = &jme->rxring;
	struct rxdesc *rxdesc = rxring->desc;
	struct net_device *netdev = jme->mii_if.dev;
	int i, j, ccnt, desccnt, mask = jme->rx_ring_mask;
	unsigned int limit = jme->rx_ring_size;

	i = rxring->next_to_clean;
	rxdesc += i;
	while (rxring->bufinf[i] &&
		!(rxdesc->descwb.flags & cpu_to_le16(RXWBFLAG_OWN)) &&
		(rxdesc->descwb.desccnt & RXWBDCNT_WBCPL) &&
		limit--) {

		rmb();
		desccnt = rxdesc->descwb.desccnt & RXWBDCNT_DCNT;
		DBG2("Cleaning rx desc=%d, cnt=%d\n", i, desccnt);

		if (desccnt > 1 || rxdesc->descwb.errstat & RXWBERR_ALLERR) {
			for (j = i, ccnt = desccnt ; ccnt-- ; ) {
				jme_set_clean_rxdesc(jme, j);
				j = (j + 1) & (mask);
			}
			DBG("Dropped packet due to ");
			if (desccnt > 1)
				DBG("long packet.(%d descriptors)\n", desccnt);
			else
				DBG("Packet error.\n");
			netdev_rx_err(netdev, NULL, -EINVAL);
		} else {
			jme_alloc_and_feed_iob(jme, i);
		}

		i = (i + desccnt) & (mask);
		rxdesc = rxring->desc;
		rxdesc += i;
	}
	rxring->next_to_clean = i;

	return;
}

static void
jme_set_custom_macaddr(struct net_device *netdev)
{
	struct jme_adapter *jme = netdev->priv;
	uint8_t *addr = netdev->ll_addr;
	u32 val;

	val = (addr[3] & 0xff) << 24 |
	      (addr[2] & 0xff) << 16 |
	      (addr[1] & 0xff) <<  8 |
	      (addr[0] & 0xff);
	jwrite32(jme, JME_RXUMA_LO, val);
	val = (addr[5] & 0xff) << 8 |
	      (addr[4] & 0xff);
	jwrite32(jme, JME_RXUMA_HI, val);
}

/**
 * Open NIC
 *
 * @v netdev		Net device
 * @ret rc		Return status code
 */
static int
jme_open(struct net_device *netdev)
{
	struct jme_adapter *jme = netdev->priv;
	int rc;

	/*
	 * Allocate receive resources
	 */
	rc = jme_alloc_rx_resources(jme);
	if (rc) {
		DBG("Allocate receive resources error.\n");
		goto nomem_out;
	}

	/*
	 * Allocate transmit resources
	 */
	rc = jme_alloc_tx_resources(jme);
	if (rc) {
		DBG("Allocate transmit resources error.\n");
		goto free_rx_resources_out;
	}

	jme_set_custom_macaddr(netdev);
	jme_reset_phy_processor(jme);
	jme_restart_an(jme);

	return 0;

free_rx_resources_out:
	jme_free_rx_resources(jme);
nomem_out:
	return rc;
}

/**
 * Close NIC
 *
 * @v netdev		Net device
 */
static void
jme_close(struct net_device *netdev)
{
	struct jme_adapter *jme = netdev->priv;

	jme_free_tx_resources(jme);
	jme_free_rx_resources(jme);
	jme_reset_mac_processor(jme);
	jme->phylink = 0;
	jme_phy_off(jme);
	netdev_link_down(netdev);
}

static int
jme_alloc_txdesc(struct jme_adapter *jme)
{
	struct jme_ring *txring = &jme->txring;
	int idx;

	idx = txring->next_to_use;
	if (txring->nr_free < 1)
		return -1;
	--(txring->nr_free);
	txring->next_to_use = (txring->next_to_use + 1) & jme->tx_ring_mask;

	return idx;
}

static void
jme_fill_tx_desc(struct jme_adapter *jme, struct io_buffer *iob, int idx)
{
	struct jme_ring *txring = &jme->txring;
	struct txdesc *txdesc = txring->desc;
	uint16_t len = iob_len(iob);
	unsigned long int mapping;

	txdesc += idx;
	mapping = virt_to_bus(iob->data);
	DBG2("TX buffer address: %p(%08lx+%x)\n",
			iob->data, mapping, len);
	txdesc->dw[0] = 0;
	txdesc->dw[1] = 0;
	txdesc->dw[2] = 0;
	txdesc->dw[3] = 0;
	txdesc->desc1.datalen	= cpu_to_le16(len);
	txdesc->desc1.pktsize	= cpu_to_le16(len);
	txdesc->desc1.bufaddr	= cpu_to_le32(mapping);
	/*
	 * Set OWN bit at final.
	 * When kernel transmit faster than NIC.
	 * And NIC trying to send this descriptor before we tell
	 * it to start sending this TX queue.
	 * Other fields are already filled correctly.
	 */
	wmb();
	txdesc->desc1.flags = TXFLAG_OWN | TXFLAG_INT;
	/*
	 * Set tx buffer info after telling NIC to send
	 * For better tx_clean timing
	 */
	wmb();
	txring->bufinf[idx] = iob;
}

/**
 * Transmit packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 * @ret rc	Return status code
 */
static int
jme_transmit(struct net_device *netdev, struct io_buffer *iobuf)
{
	struct jme_adapter *jme = netdev->priv;
	int idx;

	idx = jme_alloc_txdesc(jme);
	if (idx < 0) {
		/*
		 * Pause transmit queue somehow if possible.
		 */
		DBG("TX ring full!\n");
		return -EOVERFLOW;
	}

	jme_fill_tx_desc(jme, iobuf, idx);

	jwrite32(jme, JME_TXCS, jme->reg_txcs |
				TXCS_SELECT_QUEUE0 |
				TXCS_QUEUE0S |
				TXCS_ENABLE);
	DBG2("xmit: idx=%d\n", idx);

	return 0;
}

static int
jme_check_link(struct net_device *netdev, int testonly)
{
	struct jme_adapter *jme = netdev->priv;
	u32 phylink, ghc, cnt = JME_SPDRSV_TIMEOUT, gpreg1;
	int rc = 0;

	phylink = jread32(jme, JME_PHY_LINK);

	if (phylink & PHY_LINK_UP) {
		/*
		 * Keep polling for speed/duplex resolve complete
		 */
		while (!(phylink & PHY_LINK_SPEEDDPU_RESOLVED) &&
			--cnt) {

			udelay(1);
			phylink = jread32(jme, JME_PHY_LINK);
		}
		if (!cnt)
			DBG("Waiting speed resolve timeout.\n");

		if (jme->phylink == phylink) {
			rc = 1;
			goto out;
		}
		if (testonly)
			goto out;

		jme->phylink = phylink;

		ghc = jme->reg_ghc & ~(GHC_SPEED | GHC_DPX |
				GHC_TO_CLK_PCIE | GHC_TXMAC_CLK_PCIE |
				GHC_TO_CLK_GPHY | GHC_TXMAC_CLK_GPHY);
		switch (phylink & PHY_LINK_SPEED_MASK) {
		case PHY_LINK_SPEED_10M:
			ghc |= GHC_SPEED_10M |
				GHC_TO_CLK_PCIE | GHC_TXMAC_CLK_PCIE;
			break;
		case PHY_LINK_SPEED_100M:
			ghc |= GHC_SPEED_100M |
				GHC_TO_CLK_PCIE | GHC_TXMAC_CLK_PCIE;
			break;
		case PHY_LINK_SPEED_1000M:
			ghc |= GHC_SPEED_1000M |
				GHC_TO_CLK_GPHY | GHC_TXMAC_CLK_GPHY;
			break;
		default:
			break;
		}

		if (phylink & PHY_LINK_DUPLEX) {
			jwrite32(jme, JME_TXMCS, TXMCS_DEFAULT);
			ghc |= GHC_DPX;
		} else {
			jwrite32(jme, JME_TXMCS, TXMCS_DEFAULT |
						TXMCS_BACKOFF |
						TXMCS_CARRIERSENSE |
						TXMCS_COLLISION);
			jwrite32(jme, JME_TXTRHD, TXTRHD_TXPEN |
				((0x2000 << TXTRHD_TXP_SHIFT) & TXTRHD_TXP) |
				TXTRHD_TXREN |
				((8 << TXTRHD_TXRL_SHIFT) & TXTRHD_TXRL));
		}

		gpreg1 = GPREG1_DEFAULT;
		if (is_buggy250(jme->pdev->device, jme->chiprev)) {
			if (!(phylink & PHY_LINK_DUPLEX))
				gpreg1 |= GPREG1_HALFMODEPATCH;
			switch (phylink & PHY_LINK_SPEED_MASK) {
			case PHY_LINK_SPEED_10M:
				jme_set_phyfifoa(jme);
				gpreg1 |= GPREG1_RSSPATCH;
				break;
			case PHY_LINK_SPEED_100M:
				jme_set_phyfifob(jme);
				gpreg1 |= GPREG1_RSSPATCH;
				break;
			case PHY_LINK_SPEED_1000M:
				jme_set_phyfifoa(jme);
				break;
			default:
				break;
			}
		}

		jwrite32(jme, JME_GPREG1, gpreg1);
		jwrite32(jme, JME_GHC, ghc);
		jme->reg_ghc = ghc;

		DBG("Link is up at %d Mbps, %s-Duplex, MDI%s.\n",
		    ((phylink & PHY_LINK_SPEED_MASK)
			     == PHY_LINK_SPEED_1000M) ? 1000 :
		    ((phylink & PHY_LINK_SPEED_MASK)
			     == PHY_LINK_SPEED_100M)  ? 100  : 10,
		    (phylink & PHY_LINK_DUPLEX) ? "Full" : "Half",
		    (phylink & PHY_LINK_MDI_STAT) ? "-X" : "");
		netdev_link_up(netdev);
	} else {
		if (testonly)
			goto out;

		DBG("Link is down.\n");
		jme->phylink = 0;
		netdev_link_down(netdev);
	}

out:
	return rc;
}

static void
jme_link_change(struct net_device *netdev)
{
	struct jme_adapter *jme = netdev->priv;

	/*
	 * Do nothing if the link status did not change.
	 */
	if (jme_check_link(netdev, 1))
		return;

	if (netdev_link_ok(netdev)) {
		netdev_link_down(netdev);
		jme_disable_rx_engine(jme);
		jme_disable_tx_engine(jme);
		jme_reset_ghc_speed(jme);
		jme_reset_mac_processor(jme);
	}

	jme_check_link(netdev, 0);
	if (netdev_link_ok(netdev)) {
		jme_init_rx_ring(jme);
		jme_enable_rx_engine(jme);
		jme_init_tx_ring(jme);
		jme_enable_tx_engine(jme);
	}

	return;
}

static void
jme_tx_clean(struct jme_adapter *jme)
{
	struct jme_ring *txring = &jme->txring;
	struct txdesc *txdesc = txring->desc;
	struct io_buffer *txbi;
	struct net_device *netdev = jme->mii_if.dev;
	int i, cnt = 0, max, err, mask;

	max = jme->tx_ring_size - txring->nr_free;
	mask = jme->tx_ring_mask;

	for (i = txring->next_to_clean ; cnt < max ; ++cnt) {

		txbi = txring->bufinf[i];

		if (txbi && !(txdesc[i].descwb.flags & TXWBFLAG_OWN)) {
			DBG2("TX clean address: %08lx(%08lx+%zx)\n",
					(unsigned long)txbi->data,
					virt_to_bus(txbi->data),
					iob_len(txbi));
			err = txdesc[i].descwb.flags & TXWBFLAG_ALLERR;
			if (err)
				netdev_tx_complete_err(netdev, txbi, -EIO);
			else
				netdev_tx_complete(netdev, txbi);
			txring->bufinf[i] = NULL;
		} else {
			break;
		}

		i = (i + 1) & mask;
	}

	DBG2("txclean: next %d\n", i);
	txring->next_to_clean = i;
	txring->nr_free += cnt;
}
/**
 * Poll for received packets
 *
 * @v netdev	Network device
 */
static void
jme_poll(struct net_device *netdev)
{
	struct jme_adapter *jme = netdev->priv;
	u32 intrstat;

	intrstat = jread32(jme, JME_IEVE);

	/*
	 * Check if any actions needs to perform.
	 */
	if ((intrstat & INTR_ENABLE) == 0)
		return;

	/*
	 * Check if the device still exist
	 */
	if (intrstat == ~((typeof(intrstat))0))
		return;

	DBG2("intrstat 0x%08x\n", intrstat);
	if (intrstat & (INTR_LINKCH | INTR_SWINTR)) {
		DBG2("Link changed\n");
		jme_link_change(netdev);

		/*
		 * Clear all interrupt status
		 */
		jwrite32(jme, JME_IEVE, intrstat);

		/*
		 * Link change event is critical
		 * all other events are ignored
		 */
		return;
	}

	/*
	 * Process transmission complete first to free more memory.
	 */
	if (intrstat & INTR_TX0) {
		DBG2("Packet transmit complete\n");
		jme_tx_clean(jme);
		jwrite32(jme, JME_IEVE, intrstat & INTR_TX0);
	}

	if (intrstat & (INTR_RX0 | INTR_RX0EMP)) {
		DBG2("Packet received\n");
		jme_process_receive(jme);
		jwrite32(jme, JME_IEVE,
			intrstat & (INTR_RX0 | INTR_RX0EMP));
		if (intrstat & INTR_RX0EMP)
			jme_restart_rx_engine(jme);
	}

	/*
	 * Clean all other interrupt status
	 */
	jwrite32(jme, JME_IEVE,
		intrstat & ~(INTR_RX0 | INTR_RX0EMP | INTR_TX0));
}

/**
 * Enable/disable interrupts
 *
 * @v netdev	Network device
 * @v enable	Interrupts should be enabled
 */
static void
jme_irq(struct net_device *netdev, int enable)
{
	struct jme_adapter *jme = netdev->priv;

	DBG("jme interrupts %s\n", (enable ? "enabled" : "disabled"));
	if (enable)
		jme_start_irq(jme);
	else
		jme_stop_irq(jme);
}

/** JME net device operations */
static struct net_device_operations jme_operations = {
	.open		= jme_open,
	.close		= jme_close,
	.transmit	= jme_transmit,
	.poll		= jme_poll,
	.irq		= jme_irq,
};

static void
jme_check_hw_ver(struct jme_adapter *jme)
{
	u32 chipmode;

	chipmode = jread32(jme, JME_CHIPMODE);

	jme->fpgaver = (chipmode & CM_FPGAVER_MASK) >> CM_FPGAVER_SHIFT;
	jme->chiprev = (chipmode & CM_CHIPREV_MASK) >> CM_CHIPREV_SHIFT;
}

static int
jme_reload_eeprom(struct jme_adapter *jme)
{
	u32 val;
	int i;

	val = jread32(jme, JME_SMBCSR);

	if (val & SMBCSR_EEPROMD) {
		val |= SMBCSR_CNACK;
		jwrite32(jme, JME_SMBCSR, val);
		val |= SMBCSR_RELOAD;
		jwrite32(jme, JME_SMBCSR, val);
		mdelay(12);

		for (i = JME_EEPROM_RELOAD_TIMEOUT; i > 0; --i) {
			mdelay(1);
			if ((jread32(jme, JME_SMBCSR) & SMBCSR_RELOAD) == 0)
				break;
		}

		if (i == 0) {
			DBG("eeprom reload timeout\n");
			return -EIO;
		}
	}

	return 0;
}

static void
jme_load_macaddr(struct net_device *netdev)
{
	struct jme_adapter *jme = netdev_priv(netdev);
	unsigned char macaddr[6];
	u32 val;

	val = jread32(jme, JME_RXUMA_LO);
	macaddr[0] = (val >>  0) & 0xFF;
	macaddr[1] = (val >>  8) & 0xFF;
	macaddr[2] = (val >> 16) & 0xFF;
	macaddr[3] = (val >> 24) & 0xFF;
	val = jread32(jme, JME_RXUMA_HI);
	macaddr[4] = (val >>  0) & 0xFF;
	macaddr[5] = (val >>  8) & 0xFF;
	memcpy(netdev->hw_addr, macaddr, 6);
}

/**
 * Probe PCI device
 *
 * @v pci	PCI device
 * @v id	PCI ID
 * @ret rc	Return status code
 */
static int
jme_probe(struct pci_device *pci)
{
	struct net_device *netdev;
	struct jme_adapter *jme;
	int rc;
	uint8_t mrrs;

	/* Allocate net device */
	netdev = alloc_etherdev(sizeof(*jme));
	if (!netdev)
		return -ENOMEM;
	netdev_init(netdev, &jme_operations);
	jme = netdev->priv;
	pci_set_drvdata(pci, netdev);
	netdev->dev = &pci->dev;
	jme->regs = ioremap(pci->membase, JME_REGS_SIZE);
	if (!(jme->regs)) {
		DBG("Mapping PCI resource region error.\n");
		rc = -ENOMEM;
		goto err_out;
	}
	jme->reg_ghc = 0;
	jme->reg_rxcs = RXCS_DEFAULT;
	jme->reg_rxmcs = RXMCS_DEFAULT;
	jme->phylink = 0;
	jme->pdev = pci;
	jme->mii_if.dev = netdev;
	jme->mii_if.phy_id = 1;
	jme->mii_if.mdio_read = jme_mdio_read;
	jme->mii_if.mdio_write = jme_mdio_write;
	jme->rx_ring_size = 1 << 4;
	jme->rx_ring_mask = jme->rx_ring_size - 1;
	jme->tx_ring_size = 1 << 4;
	jme->tx_ring_mask = jme->tx_ring_size - 1;

	/* Fix up PCI device */
	adjust_pci_device(pci);

	/*
	 * Get Max Read Req Size from PCI Config Space
	 */
	pci_read_config_byte(pci, PCI_DCSR_MRRS, &mrrs);
	mrrs &= PCI_DCSR_MRRS_MASK;
	switch (mrrs) {
	case MRRS_128B:
		jme->reg_txcs = TXCS_DEFAULT | TXCS_DMASIZE_128B;
		break;
	case MRRS_256B:
		jme->reg_txcs = TXCS_DEFAULT | TXCS_DMASIZE_256B;
		break;
	default:
		jme->reg_txcs = TXCS_DEFAULT | TXCS_DMASIZE_512B;
		break;
	};

	/*
	 * Get basic hardware info.
	 */
	jme_check_hw_ver(jme);
	if (pci->device == PCI_DEVICE_ID_JMICRON_JMC250)
		jme->mii_if.supports_gmii = 1;
	else
		jme->mii_if.supports_gmii = 0;

	/*
	 * Initialize PHY
	 */
	jme_set_phyfifoa(jme);
	jme_phy_init(jme);

	/*
	 * Bring down phy before interface is opened.
	 */
	jme_phy_off(jme);

	/*
	 * Reset MAC processor and reload EEPROM for MAC Address
	 */
	jme_reset_mac_processor(jme);
	rc = jme_reload_eeprom(jme);
	if (rc) {
		DBG("Reload eeprom for reading MAC Address error.\n");
		goto err_unmap;
	}
	jme_load_macaddr(netdev);

	/* Register network device */
	if ((rc = register_netdev(netdev)) != 0) {
		DBG("Register net_device error.\n");
		goto err_unmap;
	}

	return 0;

err_unmap:
	iounmap(jme->regs);
err_out:
	netdev_nullify(netdev);
	netdev_put(netdev);
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci	PCI device
 */
static void
jme_remove(struct pci_device *pci)
{
	struct net_device *netdev = pci_get_drvdata(pci);
	struct jme_adapter *jme = netdev->priv;

	iounmap(jme->regs);
	unregister_netdev(netdev);
	netdev_nullify(netdev);
	netdev_put(netdev);
}

static struct pci_device_id jm_nics[] = {
PCI_ROM(0x197b, 0x0250, "jme",  "JMicron Gigabit Ethernet", 0),
PCI_ROM(0x197b, 0x0260, "jmfe", "JMicron Fast Ethernet",    0),
};

struct pci_driver jme_driver __pci_driver = {
        .ids = jm_nics,
        .id_count = ( sizeof ( jm_nics ) / sizeof ( jm_nics[0] ) ),
        .probe = jme_probe,
        .remove = jme_remove,
};

