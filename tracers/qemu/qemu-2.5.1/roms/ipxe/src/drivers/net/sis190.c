/*
   sis190.c: Silicon Integrated Systems SiS190 ethernet driver

   Copyright (c) 2003 K.M. Liu <kmliu@sis.com>
   Copyright (c) 2003, 2004 Jeff Garzik <jgarzik@pobox.com>
   Copyright (c) 2003, 2004, 2005 Francois Romieu <romieu@fr.zoreil.com>

   Modified for iPXE 2009 by Thomas Miletich <thomas.miletich@gmail.com>

   Based on r8169.c, tg3.c, 8139cp.c, skge.c, epic100.c and SiS 190/191
   genuine driver.

   This software may be used and distributed according to the terms of
   the GNU General Public License (GPL), incorporated herein by reference.
   Drivers based on or derived from this code fall under the GPL and must
   retain the authorship, copyright and license notice.  This file is not
   a complete program and may only be used when the entire operating
   system is licensed under the GPL.

   See the file COPYING in this distribution for more information.

 */

FILE_LICENCE ( GPL_ANY );

#include "sis190.h"

static struct pci_device_id sis190_pci_tbl[] = {
	PCI_ROM (0x1039, 0x0190, "sis190", "sis190", 0),
	PCI_ROM (0x1039, 0x0191, "sis191", "sis191", 0),
};

/******************************************************************************
 *************** HACK to keep ISA bridge in the PCI device list ***************
 ******************************************************************************/

/* Some sis190 variants store the MAC address in the BIOS CMOS. To read it, we
 * have to use a PCI to ISA bridge. To access the bridge we need a few things
 * from it's struct pci_device. We fake the successful probe of a driver to
 * keep the bridge's struct pci_device in the list of pci_devices.
 * See details in sis190_get_mac_addr_from_apc().
 */

static struct pci_device_id sis190_isa_bridge_tbl[] = {
	PCI_ID (0x1039, 0x0965, "", "", 0),
	PCI_ID (0x1039, 0x0966, "", "", 0),
	PCI_ID (0x1039, 0x0968, "", "", 0),
};

static int sis190_isa_bridge_probe(struct pci_device *pdev __unused)
{
	return 0;
}

static void sis190_isa_bridge_remove(struct pci_device *pdev __unused)
{
	return;
}

struct pci_driver sis190_isa_bridge_driver __pci_driver = {
	.ids		= sis190_isa_bridge_tbl,
	.id_count	= (sizeof(sis190_isa_bridge_tbl) /
	                   sizeof(sis190_isa_bridge_tbl[0])),
	.probe		= sis190_isa_bridge_probe,
	.remove		= sis190_isa_bridge_remove,
};

/******************************************************************************
 *********************************** </HACK> **********************************
 ******************************************************************************/

static const u32 sis190_intr_mask =
	RxQEmpty | RxQInt | TxQ1Int | TxQ0Int | RxHalt | TxHalt | LinkChange;

/*
 * Maximum number of multicast addresses to filter (vs. Rx-all-multicast).
 * The chips use a 64 element hash table based on the Ethernet CRC.
 */
static const int multicast_filter_limit = 32;

static void __mdio_cmd(void *ioaddr, u32 ctl)
{
	unsigned int i;

	SIS_W32(GMIIControl, ctl);

	mdelay(1);

	for (i = 0; i < 100; i++) {
		if (!(SIS_R32(GMIIControl) & EhnMIInotDone))
			break;
		mdelay(1);
	}

	if (i > 99)
		DBG("sis190: PHY command timed out !\n");
}

static void mdio_write(void *ioaddr, int phy_id, int reg, int val)
{
	__mdio_cmd(ioaddr, EhnMIIreq | EhnMIIwrite |
		(((u32) reg) << EhnMIIregShift) | (phy_id << EhnMIIpmdShift) |
		(((u32) val) << EhnMIIdataShift));
}

static int mdio_read(void *ioaddr, int phy_id, int reg)
{
	__mdio_cmd(ioaddr, EhnMIIreq | EhnMIIread |
		(((u32) reg) << EhnMIIregShift) | (phy_id << EhnMIIpmdShift));

	return (u16) (SIS_R32(GMIIControl) >> EhnMIIdataShift);
}

static void __mdio_write(struct net_device *dev, int phy_id, int reg, int val)
{
	struct sis190_private *tp = netdev_priv(dev);

	mdio_write(tp->mmio_addr, phy_id, reg, val);
}

static int __mdio_read(struct net_device *dev, int phy_id, int reg)
{
	struct sis190_private *tp = netdev_priv(dev);

	return mdio_read(tp->mmio_addr, phy_id, reg);
}

static u16 mdio_read_latched(void *ioaddr, int phy_id, int reg)
{
	mdio_read(ioaddr, phy_id, reg);
	return mdio_read(ioaddr, phy_id, reg);
}

static u16 sis190_read_eeprom(void *ioaddr, u32 reg)
{
	u16 data = 0xffff;
	unsigned int i;

	if (!(SIS_R32(ROMControl) & 0x0002))
		return 0;

	SIS_W32(ROMInterface, EEREQ | EEROP | (reg << 10));

	for (i = 0; i < 200; i++) {
		if (!(SIS_R32(ROMInterface) & EEREQ)) {
			data = (SIS_R32(ROMInterface) & 0xffff0000) >> 16;
			break;
		}
		mdelay(1);
	}

	return data;
}

static void sis190_irq_mask_and_ack(void *ioaddr)
{
	SIS_W32(IntrMask, 0x00);
	SIS_W32(IntrStatus, 0xffffffff);
	SIS_PCI_COMMIT();
}

static void sis190_asic_down(void *ioaddr)
{
	/* Stop the chip's Tx and Rx DMA processes. */

	SIS_W32(TxControl, 0x1a00);
	SIS_W32(RxControl, 0x1a00);

	sis190_irq_mask_and_ack(ioaddr);
}

static inline void sis190_mark_as_last_descriptor(struct RxDesc *desc)
{
	desc->size |= cpu_to_le32(RingEnd);
}

static inline void sis190_give_to_asic(struct RxDesc *desc)
{
	u32 eor = le32_to_cpu(desc->size) & RingEnd;

	desc->PSize = 0x0;
	desc->size = cpu_to_le32((RX_BUF_SIZE & RX_BUF_MASK) | eor);
	wmb();
	desc->status = cpu_to_le32(OWNbit | INTbit);
}

static inline void sis190_map_to_asic(struct RxDesc *desc, u32 mapping)
{
	desc->addr = cpu_to_le32(mapping);
	sis190_give_to_asic(desc);
}

static inline void sis190_make_unusable_by_asic(struct RxDesc *desc)
{
	desc->PSize = 0x0;
	desc->addr = cpu_to_le32(0xdeadbeef);
	desc->size &= cpu_to_le32(RingEnd);
	wmb();
	desc->status = 0x0;
}

static struct io_buffer *sis190_alloc_rx_iob(struct RxDesc *desc)
{
	struct io_buffer *iob;

	iob = alloc_iob(RX_BUF_SIZE);
	if (iob) {
		u32 mapping;

		mapping = virt_to_bus(iob->data);
		sis190_map_to_asic(desc, mapping);
	} else {
		DBG("sis190: alloc_iob failed\n");
		sis190_make_unusable_by_asic(desc);
	}

	return iob;
}

static u32 sis190_rx_fill(struct sis190_private *tp, u32 start, u32 end)
{
	u32 cur;

	for (cur = start; cur < end; cur++) {
		unsigned int i = cur % NUM_RX_DESC;

		if (tp->Rx_iobuf[i])
			continue;

		tp->Rx_iobuf[i] = sis190_alloc_rx_iob(tp->RxDescRing + i);

		if (!tp->Rx_iobuf[i])
			break;
	}
	return cur - start;
}

static inline int sis190_rx_pkt_err(u32 status)
{
#define ErrMask	(OVRUN | SHORT | LIMIT | MIIER | NIBON | COLON | ABORT)

	if ((status & CRCOK) && !(status & ErrMask))
		return 0;

	return -1;
}

static int sis190_process_rx(struct sis190_private *tp)
{
	u32 rx_left, cur_rx = tp->cur_rx;
	u32 delta, count;

	rx_left = NUM_RX_DESC + tp->dirty_rx - cur_rx;

	for (; rx_left > 0; rx_left--, cur_rx++) {
		unsigned int entry = cur_rx % NUM_RX_DESC;
		struct RxDesc *desc = tp->RxDescRing + entry;
		u32 status;

		if (le32_to_cpu(desc->status) & OWNbit)
			break;

		status = le32_to_cpu(desc->PSize);

		if (sis190_rx_pkt_err(status) < 0) {
			sis190_give_to_asic(desc);
		} else {
			struct io_buffer *iob = tp->Rx_iobuf[entry];
			unsigned int pkt_size = (status & RxSizeMask) - 4;

			if (pkt_size > RX_BUF_SIZE) {
				DBG("sis190: (frag) status = %08x.\n", status);
				sis190_give_to_asic(desc);
				continue;
			}

			sis190_make_unusable_by_asic(desc);

			iob_put(iob, pkt_size);

			DBG2("sis190: received packet. len: %d\n", pkt_size);
			netdev_rx(tp->dev, iob);
			DBGIO_HD(iob->data, 60);
			tp->Rx_iobuf[entry] = NULL;
		}
	}
	count = cur_rx - tp->cur_rx;
	tp->cur_rx = cur_rx;

	delta = sis190_rx_fill(tp, tp->dirty_rx, tp->cur_rx);
	if (!delta && count)
		DBG("sis190: no Rx buffer allocated.\n");
	tp->dirty_rx += delta;

	if (((tp->dirty_rx + NUM_RX_DESC) == tp->cur_rx))
		DBG("sis190: Rx buffers exhausted.\n");

	return count;
}

static inline int sis190_tx_pkt_err(u32 status)
{
#define TxErrMask (WND | TABRT | FIFO | LINK)

	if (!(status & TxErrMask))
		return 0;

	return -1;
}

static void sis190_process_tx(struct sis190_private *tp)
{
	u32 pending, dirty_tx = tp->dirty_tx;

	pending = tp->cur_tx - dirty_tx;

	for (; pending; pending--, dirty_tx++) {
		unsigned int entry = dirty_tx % NUM_TX_DESC;
		struct TxDesc *txd = tp->TxDescRing + entry;
		u32 status = le32_to_cpu(txd->status);
		struct io_buffer *iob;

		if (status & OWNbit)
			break;

		iob = tp->Tx_iobuf[entry];

		if (!iob)
			break;

		if (sis190_tx_pkt_err(status) == 0) {
			DBG2("sis190: Transmitted packet: %#08x\n", status);
			netdev_tx_complete(tp->dev, iob);
		} else {
			DBG("sis190: Transmit error: %#08x\n", status);
			netdev_tx_complete_err(tp->dev, iob, -EINVAL);
		}

		tp->Tx_iobuf[entry] = NULL;
	}

	if (tp->dirty_tx != dirty_tx)
		tp->dirty_tx = dirty_tx;
}

/*
 * The interrupt handler does all of the Rx thread work and cleans up after
 * the Tx thread.
 */
static void sis190_poll(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	void  *ioaddr = tp->mmio_addr;
	u32 status;

	status = SIS_R32(IntrStatus);

	if ((status == 0xffffffff) || !status)
		return;

	SIS_W32(IntrStatus, status);

	/* sis190_phy_task() needs to be called in event of a LinkChange and
	 * after auto-negotiation is finished. Finishing auto-neg won't generate
	 * any indication, hence we call it every time if the link is bad. */
	if ((status & LinkChange) || !netdev_link_ok(dev))
		sis190_phy_task(tp);

	if (status & RxQInt)
		sis190_process_rx(tp);

	if (status & TxQ0Int)
		sis190_process_tx(tp);
}

static inline void sis190_init_ring_indexes(struct sis190_private *tp)
{
	tp->dirty_tx = tp->dirty_rx = tp->cur_tx = tp->cur_rx = 0;
}

static int sis190_init_ring(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);

	sis190_init_ring_indexes(tp);

	memset(tp->Tx_iobuf, 0, NUM_TX_DESC * sizeof(struct io_buffer *));
	memset(tp->Rx_iobuf, 0, NUM_RX_DESC * sizeof(struct io_buffer *));

	if (sis190_rx_fill(tp, 0, NUM_RX_DESC) != NUM_RX_DESC)
		goto err;

	sis190_mark_as_last_descriptor(tp->RxDescRing + NUM_RX_DESC - 1);

	return 0;

err:
	sis190_free(dev);
	return -ENOMEM;
}

static void sis190_set_rx_mode(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	u32 mc_filter[2];	/* Multicast hash filter */
	u16 rx_mode;

	rx_mode = AcceptBroadcast | AcceptMyPhys | AcceptMulticast;
	mc_filter[1] = mc_filter[0] = 0xffffffff;

	SIS_W16(RxMacControl, rx_mode | 0x2);
	SIS_W32(RxHashTable, mc_filter[0]);
	SIS_W32(RxHashTable + 4, mc_filter[1]);

}

static void sis190_soft_reset(void  *ioaddr)
{
	SIS_W32(IntrControl, 0x8000);
	SIS_PCI_COMMIT();
	SIS_W32(IntrControl, 0x0);
	sis190_asic_down(ioaddr);
}

static void sis190_hw_start(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;

	sis190_soft_reset(ioaddr);

	SIS_W32(TxDescStartAddr, tp->tx_dma);
	SIS_W32(RxDescStartAddr, tp->rx_dma);

	SIS_W32(IntrStatus, 0xffffffff);
	SIS_W32(IntrMask, 0x0);
	SIS_W32(GMIIControl, 0x0);
	SIS_W32(TxMacControl, 0x60);
	SIS_W16(RxMacControl, 0x02);
	SIS_W32(RxHashTable, 0x0);
	SIS_W32(0x6c, 0x0);
	SIS_W32(RxWolCtrl, 0x0);
	SIS_W32(RxWolData, 0x0);

	SIS_PCI_COMMIT();

	sis190_set_rx_mode(dev);

	SIS_W32(TxControl, 0x1a00 | CmdTxEnb);
	SIS_W32(RxControl, 0x1a1d);
}

static void sis190_phy_task(struct sis190_private *tp)
{
	struct net_device *dev = tp->dev;
	void *ioaddr = tp->mmio_addr;
	int phy_id = tp->mii_if.phy_id;
	int cnt = 0;
	u16 val;

	val = mdio_read(ioaddr, phy_id, MII_BMCR);

	/* 100ms timeout is completely arbitrary. I have no datasheet to
	 * check whether that's a sensible value or not.
	 */
	while ((val & BMCR_RESET) && (cnt < 100)) {
		val = mdio_read(ioaddr, phy_id, MII_BMCR);
		mdelay(1);
		cnt++;
	}

	if (cnt > 99) {
		DBG("sis190: BMCR_RESET timeout\n");
		return;
	}

	if (!(mdio_read_latched(ioaddr, phy_id, MII_BMSR) &
		     BMSR_ANEGCOMPLETE)) {
		DBG("sis190: auto-negotiating...\n");
		netdev_link_down(dev);
	} else {
		/* Rejoice ! */
		struct {
			int val;
			u32 ctl;
			const char *msg;
		} reg31[] = {
			{ LPA_1000FULL, 0x07000c00 | 0x00001000,
				"1000 Mbps Full Duplex" },
			{ LPA_1000HALF, 0x07000c00,
				"1000 Mbps Half Duplex" },
			{ LPA_100FULL, 0x04000800 | 0x00001000,
				"100 Mbps Full Duplex" },
			{ LPA_100HALF, 0x04000800,
				"100 Mbps Half Duplex" },
			{ LPA_10FULL, 0x04000400 | 0x00001000,
				"10 Mbps Full Duplex" },
			{ LPA_10HALF, 0x04000400,
				"10 Mbps Half Duplex" },
			{ 0, 0x04000400, "unknown" }
		}, *p = NULL;
		u16 adv, autoexp, gigadv, gigrec;

		val = mdio_read(ioaddr, phy_id, 0x1f);

		val = mdio_read(ioaddr, phy_id, MII_LPA);
		adv = mdio_read(ioaddr, phy_id, MII_ADVERTISE);

		autoexp = mdio_read(ioaddr, phy_id, MII_EXPANSION);

		if (val & LPA_NPAGE && autoexp & EXPANSION_NWAY) {
			/* check for gigabit speed */
			gigadv = mdio_read(ioaddr, phy_id, MII_CTRL1000);
			gigrec = mdio_read(ioaddr, phy_id, MII_STAT1000);
			val = (gigadv & (gigrec >> 2));
			if (val & ADVERTISE_1000FULL)
				p = reg31;
			else if (val & ADVERTISE_1000HALF)
				p = reg31 + 1;
		}

		if (!p) {
			val &= adv;

			for (p = reg31; p->val; p++) {
				if ((val & p->val) == p->val)
					break;
			}
		}

		p->ctl |= SIS_R32(StationControl) & ~0x0f001c00;

		if ((tp->features & F_HAS_RGMII) &&
		    (tp->features & F_PHY_BCM5461)) {
			// Set Tx Delay in RGMII mode.
			mdio_write(ioaddr, phy_id, 0x18, 0xf1c7);
			udelay(200);
			mdio_write(ioaddr, phy_id, 0x1c, 0x8c00);
			p->ctl |= 0x03000000;
		}

		SIS_W32(StationControl, p->ctl);

		if (tp->features & F_HAS_RGMII) {
			SIS_W32(RGDelay, 0x0441);
			SIS_W32(RGDelay, 0x0440);
		}

		DBG("sis190: link on %s mode.\n", p->msg);
		netdev_link_up(dev);
	}
}

static int sis190_open(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	int rc;

	/* Allocate TX ring */
	tp->TxDescRing = malloc_dma(TX_RING_BYTES, RING_ALIGNMENT);
	if (!tp->TxDescRing) {
		DBG("sis190: TX ring allocation failed\n");
		rc = -ENOMEM;
		goto out;
	}
	tp->tx_dma = cpu_to_le32(virt_to_bus(tp->TxDescRing));

	/* Allocate RX ring */
	tp->RxDescRing = malloc_dma(RX_RING_BYTES, RING_ALIGNMENT);
	if (!tp->RxDescRing) {
		DBG("sis190: RX ring allocation failed\n");
		rc = -ENOMEM;
		goto error;
	}
	tp->rx_dma = cpu_to_le32(virt_to_bus(tp->RxDescRing));

	rc = sis190_init_ring(dev);
	if (rc < 0)
		goto error;

	/* init rx filter, also program MAC address to card */
	sis190_init_rxfilter(dev);

	sis190_hw_start(dev);
out:
	return rc;

error:
	sis190_free(dev);
	goto out;
}

static void sis190_down(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	void  *ioaddr = tp->mmio_addr;

	do {
		sis190_asic_down(ioaddr);
	} while (SIS_R32(IntrMask));
}

static void sis190_free(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	int i;

	free_dma(tp->TxDescRing, TX_RING_BYTES);
	free_dma(tp->RxDescRing, RX_RING_BYTES);

	tp->TxDescRing = NULL;
	tp->RxDescRing = NULL;

	tp->tx_dma = 0;
	tp->rx_dma = 0;

	tp->cur_tx = tp->dirty_tx = 0;
	tp->cur_rx = tp->dirty_rx = 0;

	for (i = 0; i < NUM_RX_DESC; i++) {
		free_iob(tp->Rx_iobuf[i]);
		tp->Rx_iobuf[i] = NULL;
	}

	/* tx io_buffers aren't owned by the driver, so don't free them */
	for(i = 0; i < NUM_TX_DESC; i++)
		tp->Tx_iobuf[i] = NULL;
}

static void sis190_close(struct net_device *dev)
{
	sis190_down(dev);
	sis190_free(dev);
}

static int sis190_transmit(struct net_device *dev, struct io_buffer *iob)
{
	struct sis190_private *tp = netdev_priv(dev);
	void  *ioaddr = tp->mmio_addr;
	u32 len, entry;
	struct TxDesc *desc;

	len = iob_len(iob);
	if (len < ETH_ZLEN) {
		iob_pad(iob, ETH_ZLEN);
		len = ETH_ZLEN;
	}

	entry = tp->cur_tx % NUM_TX_DESC;
	desc = tp->TxDescRing + entry;

	if (le32_to_cpu(desc->status) & OWNbit) {
		DBG("sis190: Tx Ring full\n");
		return -EINVAL;
	}

	tp->Tx_iobuf[entry] = iob;

	desc->PSize = cpu_to_le32(len);
	desc->addr = cpu_to_le32(virt_to_bus(iob->data));

	desc->size = cpu_to_le32(len);
	if (entry == (NUM_TX_DESC - 1))
		desc->size |= cpu_to_le32(RingEnd);

	wmb();

	desc->status = cpu_to_le32(OWNbit | INTbit | DEFbit | CRCbit | PADbit);

	tp->cur_tx++;

	SIS_W32(TxControl, 0x1a00 | CmdReset | CmdTxEnb);

	return 0;
}

static void sis190_free_phy(struct list_head *first_phy)
{
	struct sis190_phy *cur, *next;

	list_for_each_entry_safe(cur, next, first_phy, list) {
		free(cur);
	}
}

/**
 *	sis190_default_phy - Select default PHY for sis190 mac.
 *	@dev: the net device to probe for
 *
 *	Select first detected PHY with link as default.
 *	If no one is link on, select PHY whose types is HOME as default.
 *	If HOME doesn't exist, select LAN.
 */
static u16 sis190_default_phy(struct sis190_private *tp)
{
	struct sis190_phy *phy, *phy_home, *phy_default, *phy_lan;
	struct mii_if_info *mii_if = &tp->mii_if;
	void  *ioaddr = tp->mmio_addr;
	u16 status;

	phy_home = phy_default = phy_lan = NULL;

	list_for_each_entry(phy, &tp->first_phy, list) {
		status = mdio_read_latched(ioaddr, phy->phy_id, MII_BMSR);

		// Link ON & Not select default PHY & not ghost PHY.
		if ((status & BMSR_LSTATUS) &&
		    !phy_default &&
		    (phy->type != UNKNOWN)) {
			phy_default = phy;
		} else {
			status = mdio_read(ioaddr, phy->phy_id, MII_BMCR);
			mdio_write(ioaddr, phy->phy_id, MII_BMCR,
				   status | BMCR_ANENABLE | BMCR_ISOLATE);
			if (phy->type == HOME)
				phy_home = phy;
			else if (phy->type == LAN)
				phy_lan = phy;
		}
	}

	if (!phy_default) {
		if (phy_home)
			phy_default = phy_home;
		else if (phy_lan)
			phy_default = phy_lan;
		else
			phy_default = list_entry(&tp->first_phy,
						 struct sis190_phy, list);
	}

	if (mii_if->phy_id != phy_default->phy_id) {
		mii_if->phy_id = phy_default->phy_id;
		DBG("sis190: Using transceiver at address %d as default.\n",
		     mii_if->phy_id);
	}

	status = mdio_read(ioaddr, mii_if->phy_id, MII_BMCR);
	status &= (~BMCR_ISOLATE);

	mdio_write(ioaddr, mii_if->phy_id, MII_BMCR, status);
	status = mdio_read_latched(ioaddr, mii_if->phy_id, MII_BMSR);

	return status;
}

static void sis190_init_phy(struct sis190_private *tp,
			    struct sis190_phy *phy, unsigned int phy_id,
			    u16 mii_status)
{
	void *ioaddr = tp->mmio_addr;
	struct mii_chip_info *p;

	INIT_LIST_HEAD(&phy->list);
	phy->status = mii_status;
	phy->phy_id = phy_id;

	phy->id[0] = mdio_read(ioaddr, phy_id, MII_PHYSID1);
	phy->id[1] = mdio_read(ioaddr, phy_id, MII_PHYSID2);

	for (p = mii_chip_table; p->type; p++) {
		if ((p->id[0] == phy->id[0]) &&
		    (p->id[1] == (phy->id[1] & 0xfff0))) {
			break;
		}
	}

	if (p->id[1]) {
		phy->type = (p->type == MIX) ?
			((mii_status & (BMSR_100FULL | BMSR_100HALF)) ?
				LAN : HOME) : p->type;
		tp->features |= p->feature;

		DBG("sis190: %s transceiver at address %d.\n", p->name, phy_id);
	} else {
		phy->type = UNKNOWN;

		DBG("sis190: unknown PHY 0x%x:0x%x transceiver at address %d\n",
		    phy->id[0], (phy->id[1] & 0xfff0), phy_id);
	}
}

static void sis190_mii_probe_88e1111_fixup(struct sis190_private *tp)
{
	if (tp->features & F_PHY_88E1111) {
		void *ioaddr = tp->mmio_addr;
		int phy_id = tp->mii_if.phy_id;
		u16 reg[2][2] = {
			{ 0x808b, 0x0ce1 },
			{ 0x808f, 0x0c60 }
		}, *p;

		p = (tp->features & F_HAS_RGMII) ? reg[0] : reg[1];

		mdio_write(ioaddr, phy_id, 0x1b, p[0]);
		udelay(200);
		mdio_write(ioaddr, phy_id, 0x14, p[1]);
		udelay(200);
	}
}

/**
 *	sis190_mii_probe - Probe MII PHY for sis190
 *	@dev: the net device to probe for
 *
 *	Search for total of 32 possible mii phy addresses.
 *	Identify and set current phy if found one,
 *	return error if it failed to found.
 */
static int sis190_mii_probe(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	struct mii_if_info *mii_if = &tp->mii_if;
	void *ioaddr = tp->mmio_addr;
	int phy_id;
	int rc = 0;

	INIT_LIST_HEAD(&tp->first_phy);

	for (phy_id = 0; phy_id < PHY_MAX_ADDR; phy_id++) {
		struct sis190_phy *phy;
		u16 status;

		status = mdio_read_latched(ioaddr, phy_id, MII_BMSR);

		// Try next mii if the current one is not accessible.
		if (status == 0xffff || status == 0x0000)
			continue;

		phy = zalloc(sizeof(*phy));
		if (!phy) {
			sis190_free_phy(&tp->first_phy);
			rc = -ENOMEM;
			goto out;
		}

		DBG("sis190: found PHY\n");

		sis190_init_phy(tp, phy, phy_id, status);

		list_add(&tp->first_phy, &phy->list);
	}

	if (list_empty(&tp->first_phy)) {
		DBG("sis190: No MII transceivers found!\n");
		rc = -EIO;
		goto out;
	}

	/* Select default PHY for mac */
	sis190_default_phy(tp);

	sis190_mii_probe_88e1111_fixup(tp);

	mii_if->dev = dev;
	mii_if->mdio_read = __mdio_read;
	mii_if->mdio_write = __mdio_write;
	mii_if->phy_id_mask = PHY_ID_ANY;
	mii_if->reg_num_mask = MII_REG_ANY;
out:
	return rc;
}

static void sis190_mii_remove(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);

	sis190_free_phy(&tp->first_phy);
}

static int sis190_init_board(struct pci_device *pdev, struct net_device **netdev)
{
	struct sis190_private *tp;
	struct net_device *dev;
	void *ioaddr;
	int rc;

	dev = alloc_etherdev(sizeof(*tp));
	if (!dev) {
		DBG("sis190: unable to alloc new etherdev\n");
		rc = -ENOMEM;
		goto err;
	}

	dev->dev = &pdev->dev;

	tp = netdev_priv(dev);
	memset(tp, 0, sizeof(*tp));

	tp->dev = dev;

	adjust_pci_device(pdev);

	ioaddr = ioremap(pdev->membase, SIS190_REGS_SIZE);
	if (!ioaddr) {
		DBG("sis190: cannot remap MMIO, aborting\n");
		rc = -EIO;
		goto err;
	}

	tp->pci_device = pdev;
	tp->mmio_addr = ioaddr;

	sis190_irq_mask_and_ack(ioaddr);

	sis190_soft_reset(ioaddr);

	*netdev = dev;

	return 0;

err:
	return rc;
}

static void sis190_set_rgmii(struct sis190_private *tp, u8 reg)
{
	tp->features |= (reg & 0x80) ? F_HAS_RGMII : 0;
}

static int sis190_get_mac_addr_from_eeprom(struct pci_device *pdev __unused,
						     struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	u16 sig;
	int i;

	DBG("sis190: Read MAC address from EEPROM\n");

	/* Check to see if there is a sane EEPROM */
	sig = (u16) sis190_read_eeprom(ioaddr, EEPROMSignature);

	if ((sig == 0xffff) || (sig == 0x0000)) {
		DBG("sis190: Error EEPROM read.\n");
		return -EIO;
	}

	/* Get MAC address from EEPROM */
	for (i = 0; i < ETH_ALEN / 2; i++) {
		u16 w = sis190_read_eeprom(ioaddr, EEPROMMACAddr + i);

		((u16 *)dev->hw_addr)[i] = cpu_to_le16(w);
	}

	sis190_set_rgmii(tp, sis190_read_eeprom(ioaddr, EEPROMInfo));

	return 0;
}

/**
 *	sis190_get_mac_addr_from_apc - Get MAC address for SiS96x model
 *	@pdev: PCI device
 *	@dev:  network device to get address for
 *
 *	SiS96x model, use APC CMOS RAM to store MAC address.
 *	APC CMOS RAM is accessed through ISA bridge.
 *	MAC address is read into @net_dev->dev_addr.
 */
static int sis190_get_mac_addr_from_apc(struct pci_device *pdev,
					struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	struct pci_device *isa_bridge = NULL;
	struct device *d;
	u8 reg, tmp8;
	unsigned int i;

	DBG("sis190: Read MAC address from APC.\n");

	list_for_each_entry(d, &(pdev->dev.siblings), siblings) {
		unsigned int i;
		isa_bridge = container_of(d, struct pci_device, dev);
		for(i = 0; i < sis190_isa_bridge_driver.id_count; i++) {
			if(isa_bridge->vendor ==
			     sis190_isa_bridge_driver.ids[i].vendor
			     && isa_bridge->device ==
			     sis190_isa_bridge_driver.ids[i].device) {
				DBG("sis190: ISA bridge found\n");
				break;
			} else {
				isa_bridge = NULL;
			}
		}
		if(isa_bridge)
			break;
	}

	if (!isa_bridge) {
		DBG("sis190: Can not find ISA bridge.\n");
		return -EIO;
	}

	/* Enable port 78h & 79h to access APC Registers. */
	pci_read_config_byte(isa_bridge, 0x48, &tmp8);
	reg = (tmp8 & ~0x02);
	pci_write_config_byte(isa_bridge, 0x48, reg);
	udelay(50);
	pci_read_config_byte(isa_bridge, 0x48, &reg);

        for (i = 0; i < ETH_ALEN; i++) {
                outb(0x9 + i, 0x78);
                dev->hw_addr[i] = inb(0x79);
        }

	outb(0x12, 0x78);
	reg = inb(0x79);

	sis190_set_rgmii(tp, reg);

	/* Restore the value to ISA Bridge */
	pci_write_config_byte(isa_bridge, 0x48, tmp8);

	return 0;
}

/**
 *      sis190_init_rxfilter - Initialize the Rx filter
 *      @dev: network device to initialize
 *
 *      Set receive filter address to our MAC address
 *      and enable packet filtering.
 */
static inline void sis190_init_rxfilter(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	u16 ctl;
	int i;

	ctl = SIS_R16(RxMacControl);
	/*
	 * Disable packet filtering before setting filter.
	 * Note: SiS's driver writes 32 bits but RxMacControl is 16 bits
	 * only and followed by RxMacAddr (6 bytes). Strange. -- FR
	 */
	SIS_W16(RxMacControl, ctl & ~0x0f00);

	for (i = 0; i < ETH_ALEN; i++)
		SIS_W8(RxMacAddr + i, dev->ll_addr[i]);

	SIS_W16(RxMacControl, ctl);
	SIS_PCI_COMMIT();
}

static int sis190_get_mac_addr(struct pci_device *pdev,
					 struct net_device *dev)
{
	int rc;

	rc = sis190_get_mac_addr_from_eeprom(pdev, dev);
	if (rc < 0) {
		u8 reg;

		pci_read_config_byte(pdev, 0x73, &reg);

		if (reg & 0x00000001)
			rc = sis190_get_mac_addr_from_apc(pdev, dev);
	}
	return rc;
}

static void sis190_set_speed_auto(struct net_device *dev)
{
	struct sis190_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;
	int phy_id = tp->mii_if.phy_id;
	int val;

	DBG("sis190: Enabling Auto-negotiation.\n");

	val = mdio_read(ioaddr, phy_id, MII_ADVERTISE);

	// Enable 10/100 Full/Half Mode, leave MII_ADVERTISE bit4:0
	// unchanged.
	mdio_write(ioaddr, phy_id, MII_ADVERTISE, (val & ADVERTISE_SLCT) |
		   ADVERTISE_100FULL | ADVERTISE_10FULL |
		   ADVERTISE_100HALF | ADVERTISE_10HALF);

	// Enable 1000 Full Mode.
	mdio_write(ioaddr, phy_id, MII_CTRL1000, ADVERTISE_1000FULL);

	// Enable auto-negotiation and restart auto-negotiation.
	mdio_write(ioaddr, phy_id, MII_BMCR,
		   BMCR_ANENABLE | BMCR_ANRESTART | BMCR_RESET);
}

static void sis190_irq(struct net_device *dev, int enable)
{
	struct sis190_private *tp = netdev_priv(dev);
	void *ioaddr = tp->mmio_addr;

	SIS_W32(IntrStatus, 0xffffffff);

	if (enable == 0)
		SIS_W32(IntrMask, 0x00);
	else
		SIS_W32(IntrMask, sis190_intr_mask);

	SIS_PCI_COMMIT();
}

static struct net_device_operations sis190_netdev_ops = {
	.open = sis190_open,
	.close = sis190_close,
	.poll = sis190_poll,
	.transmit = sis190_transmit,
	.irq = sis190_irq,
};

static int sis190_probe(struct pci_device *pdev)
{
	struct sis190_private *tp;
	struct net_device *dev;
	int rc;

	rc = sis190_init_board(pdev, &dev);
	if (rc < 0)
		goto out;
	netdev_init(dev, &sis190_netdev_ops);

	pci_set_drvdata(pdev, dev);

	tp = netdev_priv(dev);

	rc = sis190_get_mac_addr(pdev, dev);
	if (rc < 0)
		goto err;

	rc = sis190_mii_probe(dev);
	if (rc < 0)
		goto err;

	rc = register_netdev(dev);
	if (rc < 0)
		goto err;

	sis190_set_speed_auto(dev);
	sis190_phy_task(tp);

out:
	return rc;

err:
	sis190_mii_remove(dev);
	iounmap(tp->mmio_addr);
	goto out;
}

static void sis190_remove(struct pci_device *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct sis190_private *tp = dev->priv;
	void *ioaddr = tp->mmio_addr;

	sis190_mii_remove(dev);

	/* shutdown chip, disable interrupts, etc */
	sis190_soft_reset(ioaddr);

	iounmap(tp->mmio_addr);

	unregister_netdev(dev);
	netdev_nullify(dev);
	netdev_put(dev);
}

struct pci_driver sis190_pci_driver __pci_driver = {
	.ids		= sis190_pci_tbl,
	.id_count	= (sizeof(sis190_pci_tbl) / sizeof(sis190_pci_tbl[0])),
	.probe		= sis190_probe,
	.remove		= sis190_remove,
};
