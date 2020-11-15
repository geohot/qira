
/*
 * Linux device driver for RTL8180 / RTL8185
 *
 * Copyright 2007 Michael Wu <flamingice@sourmilk.net>
 * Copyright 2007 Andrea Merello <andreamrl@tiscali.it>
 *
 * Modified for iPXE, June 2009, by Joshua Oreman <oremanj@rwcr.net>
 *
 * Based on the r8180 driver, which is:
 * Copyright 2004-2005 Andrea Merello <andreamrl@tiscali.it>, et al.
 *
 * Thanks to Realtek for their support!
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

FILE_LICENCE(GPL2_ONLY);

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <ipxe/net80211.h>
#include <ipxe/netdevice.h>
#include <ipxe/threewire.h>

#include "rtl818x.h"

/* rtl818x_rates[hw rate number] = rate in 100kbps units */
static const u16 rtl818x_rates[] = {
	10, 20, 55, 110, /* 802.11b */
	60, 90, 120, 180, 240, 360, 480, 540, /* 802.11g */
	0, 0, 0, 0,		/* index safely using a value masked with 0xF */
};
#define RTL818X_NR_B_RATES  4
#define RTL818X_NR_RATES    12

/* used by RF drivers */
void rtl818x_write_phy(struct net80211_device *dev, u8 addr, u32 data)
{
	struct rtl818x_priv *priv = dev->priv;
	int i = 10;
	u32 buf;

	buf = (data << 8) | addr;

	rtl818x_iowrite32(priv, (u32 *)&priv->map->PHY[0], buf | 0x80);
	while (i--) {
		rtl818x_iowrite32(priv, (u32 *)&priv->map->PHY[0], buf);
		if (rtl818x_ioread8(priv, &priv->map->PHY[2]) == (data & 0xFF))
			return;
	}
}

static void rtl818x_handle_rx(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	unsigned int count = RTL818X_RX_RING_SIZE;

	while (count--) {
		struct rtl818x_rx_desc *entry = &priv->rx_ring[priv->rx_idx];
		struct io_buffer *iob = priv->rx_buf[priv->rx_idx];
		u32 flags = le32_to_cpu(entry->flags);

		if (flags & RTL818X_RX_DESC_FLAG_OWN)
			return;

		if (flags & (RTL818X_RX_DESC_FLAG_DMA_FAIL |
			     RTL818X_RX_DESC_FLAG_FOF |
			     RTL818X_RX_DESC_FLAG_RX_ERR)) {
			/* This is crappy hardware. The Linux driver
			   doesn't even log these. */
			goto done;
		} else if (flags & RTL818X_RX_DESC_FLAG_CRC32_ERR) {
			/* This is actually a corrupt packet. */
			DBG2("rtl818x RX:%d CRC fail: flags %08x\n",
			     priv->rx_idx, flags);
			net80211_rx_err(dev, NULL, EIO);
		} else {
			u32 flags2 = le32_to_cpu(entry->flags2);
			struct io_buffer *new_iob = alloc_iob(MAX_RX_SIZE);
			if (!new_iob) {
				net80211_rx_err(dev, NULL, ENOMEM);
				goto done;
			}

			DBGP("rtl818x RX:%d success: flags %08x %08x\n",
			     priv->rx_idx, flags, flags2);

			iob_put(iob, flags & 0xFFF);

			net80211_rx(dev, iob, (flags2 >> 8) & 0x7f,
				    rtl818x_rates[(flags >> 20) & 0xf]);

			iob = new_iob;
			priv->rx_buf[priv->rx_idx] = iob;
		}

	done:
		entry->rx_buf = cpu_to_le32(virt_to_bus(iob->data));
		entry->flags = cpu_to_le32(RTL818X_RX_DESC_FLAG_OWN | MAX_RX_SIZE);

		if (priv->rx_idx == RTL818X_RX_RING_SIZE - 1)
			entry->flags |= cpu_to_le32(RTL818X_RX_DESC_FLAG_EOR);

		priv->rx_idx = (priv->rx_idx + 1) % RTL818X_RX_RING_SIZE;
	}
}

static void rtl818x_handle_tx(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	unsigned int count = RTL818X_TX_RING_SIZE;

	while (count--) {
		struct rtl818x_tx_desc *entry = &priv->tx_ring[priv->tx_cons];
		struct io_buffer *iob = priv->tx_buf[priv->tx_cons];
		u32 flags = le32_to_cpu(entry->flags);
		int rc;

		if ((flags & RTL818X_TX_DESC_FLAG_OWN) || !iob)
			return;

		rc = 0;
		if (!(flags & RTL818X_TX_DESC_FLAG_TX_OK)) {
			/* our packet was not ACKed properly */
			rc = EIO;
		}

		net80211_tx_complete(dev, iob, flags & 0xFF, rc);

		priv->tx_buf[priv->tx_cons] = NULL;
		priv->tx_cons = (priv->tx_cons + 1) % RTL818X_TX_RING_SIZE;
	}
}

static void rtl818x_poll(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	u16 reg = rtl818x_ioread16(priv, &priv->map->INT_STATUS);

	if (reg == 0xFFFF)
		return;

	rtl818x_iowrite16(priv, &priv->map->INT_STATUS, reg);

	if (reg & (RTL818X_INT_TXN_OK | RTL818X_INT_TXN_ERR))
		rtl818x_handle_tx(dev);

	if (reg & (RTL818X_INT_RX_OK | RTL818X_INT_RX_ERR))
		rtl818x_handle_rx(dev);
}

#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))

static int rtl818x_tx(struct net80211_device *dev, struct io_buffer *iob)
{
	struct rtl818x_priv *priv = dev->priv;
	struct rtl818x_tx_desc *entry;
	u32 tx_flags;
	u16 plcp_len = 0;
	int len = iob_len(iob);

	tx_flags = RTL818X_TX_DESC_FLAG_OWN | RTL818X_TX_DESC_FLAG_FS |
		RTL818X_TX_DESC_FLAG_LS | (priv->hw_rate << 24) | len;

	if (priv->r8185) {
		tx_flags |= RTL818X_TX_DESC_FLAG_DMA |
			    RTL818X_TX_DESC_FLAG_NO_ENC;
	} else {
		unsigned int remainder;

		plcp_len = DIV_ROUND_UP(16 * (len + 4),
					(dev->rates[dev->rate] * 2) / 10);
		remainder = (16 * (len + 4)) %
			    ((dev->rates[dev->rate] * 2) / 10);

		if (remainder > 0 && remainder <= 6)
			plcp_len |= 1 << 15;
	}

	entry = &priv->tx_ring[priv->tx_prod];

	if (dev->phy_flags & NET80211_PHY_USE_PROTECTION) {
		tx_flags |= RTL818X_TX_DESC_FLAG_CTS;
		tx_flags |= priv->hw_rtscts_rate << 19;
		entry->rts_duration = net80211_cts_duration(dev, len);
	} else {
		entry->rts_duration = 0;
	}

	if (entry->flags & RTL818X_TX_DESC_FLAG_OWN) {
		/* card hasn't processed the old packet yet! */
		return -EBUSY;
	}

	priv->tx_buf[priv->tx_prod] = iob;
	priv->tx_prod = (priv->tx_prod + 1) % RTL818X_TX_RING_SIZE;

	entry->plcp_len = cpu_to_le16(plcp_len);
	entry->tx_buf = cpu_to_le32(virt_to_bus(iob->data));
	entry->frame_len = cpu_to_le32(len);
	entry->flags2 = /* alternate retry rate in 100kbps << 4 */ 0;
	entry->retry_limit = RTL818X_MAX_RETRIES;
	entry->flags = cpu_to_le32(tx_flags);

	rtl818x_iowrite8(priv, &priv->map->TX_DMA_POLLING, (1 << 5));

	return 0;
}

void rtl818x_set_anaparam(struct rtl818x_priv *priv, u32 anaparam)
{
	u8 reg;

	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, &priv->map->CONFIG3);
	rtl818x_iowrite8(priv, &priv->map->CONFIG3,
		 reg | RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite32(priv, &priv->map->ANAPARAM, anaparam);
	rtl818x_iowrite8(priv, &priv->map->CONFIG3,
		 reg & ~RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
}

static int rtl818x_init_hw(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	u16 reg;

	rtl818x_iowrite8(priv, &priv->map->CMD, 0);
	rtl818x_ioread8(priv, &priv->map->CMD);
	mdelay(10);

	/* reset */
	rtl818x_iowrite16(priv, &priv->map->INT_MASK, 0);
	rtl818x_ioread8(priv, &priv->map->CMD);

	reg = rtl818x_ioread8(priv, &priv->map->CMD);
	reg &= (1 << 1);
	reg |= RTL818X_CMD_RESET;
	rtl818x_iowrite8(priv, &priv->map->CMD, RTL818X_CMD_RESET);
	rtl818x_ioread8(priv, &priv->map->CMD);
	mdelay(200);

	/* check success of reset */
	if (rtl818x_ioread8(priv, &priv->map->CMD) & RTL818X_CMD_RESET) {
		DBG("rtl818x %s: reset timeout!\n", dev->netdev->name);
		return -ETIMEDOUT;
	}

	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_LOAD);
	rtl818x_ioread8(priv, &priv->map->CMD);
	mdelay(200);

	if (rtl818x_ioread8(priv, &priv->map->CONFIG3) & (1 << 3)) {
		/* For cardbus */
		reg = rtl818x_ioread8(priv, &priv->map->CONFIG3);
		reg |= 1 << 1;
		rtl818x_iowrite8(priv, &priv->map->CONFIG3, reg);
		reg = rtl818x_ioread16(priv, &priv->map->FEMR);
		reg |= (1 << 15) | (1 << 14) | (1 << 4);
		rtl818x_iowrite16(priv, &priv->map->FEMR, reg);
	}

	rtl818x_iowrite8(priv, &priv->map->MSR, 0);

	if (!priv->r8185)
		rtl818x_set_anaparam(priv, priv->anaparam);

	rtl818x_iowrite32(priv, &priv->map->RDSAR, priv->rx_ring_dma);
	rtl818x_iowrite32(priv, &priv->map->TNPDA, priv->tx_ring_dma);

	/* TODO: necessary? specs indicate not */
	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, &priv->map->CONFIG2);
	rtl818x_iowrite8(priv, &priv->map->CONFIG2, reg & ~(1 << 3));
	if (priv->r8185) {
		reg = rtl818x_ioread8(priv, &priv->map->CONFIG2);
		rtl818x_iowrite8(priv, &priv->map->CONFIG2, reg | (1 << 4));
	}
	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);

	/* TODO: set CONFIG5 for calibrating AGC on rtl8180 + philips radio? */

	/* TODO: turn off hw wep on rtl8180 */

	rtl818x_iowrite32(priv, &priv->map->INT_TIMEOUT, 0);

	if (priv->r8185) {
		rtl818x_iowrite8(priv, &priv->map->WPA_CONF, 0);
		rtl818x_iowrite8(priv, &priv->map->RATE_FALLBACK, 0x81);
		rtl818x_iowrite8(priv, &priv->map->RESP_RATE, (8 << 4) | 0);

		rtl818x_iowrite16(priv, &priv->map->BRSR, 0x01F3);

		/* TODO: set ClkRun enable? necessary? */
		reg = rtl818x_ioread8(priv, &priv->map->GP_ENABLE);
		rtl818x_iowrite8(priv, &priv->map->GP_ENABLE, reg & ~(1 << 6));
		rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
		reg = rtl818x_ioread8(priv, &priv->map->CONFIG3);
		rtl818x_iowrite8(priv, &priv->map->CONFIG3, reg | (1 << 2));
		rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
	} else {
		rtl818x_iowrite16(priv, &priv->map->BRSR, 0x1);
		rtl818x_iowrite8(priv, &priv->map->SECURITY, 0);

		rtl818x_iowrite8(priv, &priv->map->PHY_DELAY, 0x6);
		rtl818x_iowrite8(priv, &priv->map->CARRIER_SENSE_COUNTER, 0x4C);
	}

	priv->rf->init(dev);
	if (priv->r8185)
		rtl818x_iowrite16(priv, &priv->map->BRSR, 0x01F3);
	return 0;
}

static int rtl818x_init_rx_ring(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	struct rtl818x_rx_desc *entry;
	int i;

	priv->rx_ring = malloc_dma(sizeof(*priv->rx_ring) * RTL818X_RX_RING_SIZE,
				   RTL818X_RING_ALIGN);
	priv->rx_ring_dma = virt_to_bus(priv->rx_ring);
	if (!priv->rx_ring) {
		DBG("rtl818x %s: cannot allocate RX ring\n", dev->netdev->name);
		return -ENOMEM;
	}

	memset(priv->rx_ring, 0, sizeof(*priv->rx_ring) * RTL818X_RX_RING_SIZE);
	priv->rx_idx = 0;

	for (i = 0; i < RTL818X_RX_RING_SIZE; i++) {
		struct io_buffer *iob = alloc_iob(MAX_RX_SIZE);
		entry = &priv->rx_ring[i];
		if (!iob)
			return -ENOMEM;

		priv->rx_buf[i] = iob;
		entry->rx_buf = cpu_to_le32(virt_to_bus(iob->data));
		entry->flags = cpu_to_le32(RTL818X_RX_DESC_FLAG_OWN |
					   MAX_RX_SIZE);
	}
	entry->flags |= cpu_to_le32(RTL818X_RX_DESC_FLAG_EOR);
	return 0;
}

static void rtl818x_free_rx_ring(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	int i;

	for (i = 0; i < RTL818X_RX_RING_SIZE; i++) {
		free_iob(priv->rx_buf[i]);
		priv->rx_buf[i] = NULL;
	}

	free_dma(priv->rx_ring, sizeof(*priv->rx_ring) * RTL818X_RX_RING_SIZE);
	priv->rx_ring = NULL;
}

static int rtl818x_init_tx_ring(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	int i;

	priv->tx_ring = malloc_dma(sizeof(*priv->tx_ring) * RTL818X_TX_RING_SIZE,
				   RTL818X_RING_ALIGN);
	priv->tx_ring_dma = virt_to_bus(priv->tx_ring);
	if (!priv->tx_ring) {
		DBG("rtl818x %s: cannot allocate TX ring\n", dev->netdev->name);
		return -ENOMEM;
	}

	memset(priv->tx_ring, 0, sizeof(*priv->tx_ring) * RTL818X_TX_RING_SIZE);
	priv->tx_prod = priv->tx_cons = 0;

	for (i = 0; i < RTL818X_TX_RING_SIZE; i++)
		priv->tx_ring[i].next_tx_desc = cpu_to_le32(priv->tx_ring_dma +
				((i + 1) % RTL818X_TX_RING_SIZE) * sizeof(*priv->tx_ring));

	return 0;
}

static void rtl818x_free_tx_ring(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	int i;

	for (i = 0; i < RTL818X_TX_RING_SIZE; i++) {
		if (priv->tx_buf[i])
			net80211_tx_complete(dev, priv->tx_buf[i], 0, ECANCELED);
		priv->tx_buf[i] = NULL;
	}

	free_dma(priv->tx_ring, sizeof(*priv->tx_ring) * RTL818X_TX_RING_SIZE);
	priv->tx_ring = NULL;
}

static void rtl818x_irq(struct net80211_device *dev, int enable)
{
	struct rtl818x_priv *priv = dev->priv;
	rtl818x_iowrite16(priv, &priv->map->INT_MASK, enable? 0xFFFF : 0);
}

/* Sets the MAC address of the card. */
static void rtl818x_set_hwaddr(struct net80211_device *dev, u8 *hwaddr)
{
	struct rtl818x_priv *priv = dev->priv;
	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	rtl818x_iowrite32(priv, (u32 *)&priv->map->MAC[0],
			  le32_to_cpu(*(u32 *)hwaddr));
	rtl818x_iowrite16(priv, (u16 *)&priv->map->MAC[4],
			  le16_to_cpu(*(u16 *)(hwaddr + 4)));
	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
}

static int rtl818x_start(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	int ret;
	u32 reg;

	ret = rtl818x_init_rx_ring(dev);
	if (ret)
		return ret;

	ret = rtl818x_init_tx_ring(dev);
	if (ret)
		goto err_free_rings;

	ret = rtl818x_init_hw(dev);
	if (ret)
		goto err_free_rings;

	rtl818x_set_hwaddr(dev, dev->netdev->ll_addr);

	rtl818x_iowrite32(priv, &priv->map->RDSAR, priv->rx_ring_dma);
	rtl818x_iowrite32(priv, &priv->map->TNPDA, priv->tx_ring_dma);

	rtl818x_iowrite16(priv, &priv->map->INT_MASK, 0);

	rtl818x_iowrite32(priv, &priv->map->MAR[0], ~0);
	rtl818x_iowrite32(priv, &priv->map->MAR[1], ~0);

	reg = RTL818X_RX_CONF_ONLYERLPKT |
	      RTL818X_RX_CONF_RX_AUTORESETPHY |
	      RTL818X_RX_CONF_MGMT |
	      RTL818X_RX_CONF_DATA |
	      (7 << 8 /* MAX RX DMA */) |
	      RTL818X_RX_CONF_BROADCAST |
	      RTL818X_RX_CONF_NICMAC;

	if (priv->r8185)
		reg |= RTL818X_RX_CONF_CSDM1 | RTL818X_RX_CONF_CSDM2;
	else {
		reg |= (priv->rfparam & RF_PARAM_CARRIERSENSE1)
			? RTL818X_RX_CONF_CSDM1 : 0;
		reg |= (priv->rfparam & RF_PARAM_CARRIERSENSE2)
			? RTL818X_RX_CONF_CSDM2 : 0;
	}

	priv->rx_conf = reg;
	rtl818x_iowrite32(priv, &priv->map->RX_CONF, reg);

	if (priv->r8185) {
		reg = rtl818x_ioread8(priv, &priv->map->CW_CONF);
		reg &= ~RTL818X_CW_CONF_PERPACKET_CW_SHIFT;
		reg |= RTL818X_CW_CONF_PERPACKET_RETRY_SHIFT;
		rtl818x_iowrite8(priv, &priv->map->CW_CONF, reg);

		reg = rtl818x_ioread8(priv, &priv->map->TX_AGC_CTL);
		reg &= ~RTL818X_TX_AGC_CTL_PERPACKET_GAIN_SHIFT;
		reg &= ~RTL818X_TX_AGC_CTL_PERPACKET_ANTSEL_SHIFT;
		reg |=  RTL818X_TX_AGC_CTL_FEEDBACK_ANT;
		rtl818x_iowrite8(priv, &priv->map->TX_AGC_CTL, reg);

		/* disable early TX */
		rtl818x_iowrite8(priv, (u8 *)priv->map + 0xec, 0x3f);
	}

	reg = rtl818x_ioread32(priv, &priv->map->TX_CONF);
	reg |= (6 << 21 /* MAX TX DMA */) |
	       RTL818X_TX_CONF_NO_ICV;

	if (priv->r8185)
		reg &= ~RTL818X_TX_CONF_PROBE_DTS;
	else
		reg &= ~RTL818X_TX_CONF_HW_SEQNUM;

	/* different meaning, same value on both rtl8185 and rtl8180 */
	reg &= ~RTL818X_TX_CONF_SAT_HWPLCP;

	rtl818x_iowrite32(priv, &priv->map->TX_CONF, reg);

	reg = rtl818x_ioread8(priv, &priv->map->CMD);
	reg |= RTL818X_CMD_RX_ENABLE;
	reg |= RTL818X_CMD_TX_ENABLE;
	rtl818x_iowrite8(priv, &priv->map->CMD, reg);

	DBG("%s rtl818x: started\n", dev->netdev->name);

	return 0;

 err_free_rings:
	rtl818x_free_rx_ring(dev);
	if (priv->tx_ring)
		rtl818x_free_tx_ring(dev);

	DBG("%s rtl818x: failed to start\n", dev->netdev->name);

	return ret;
}

static void rtl818x_stop(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	u8 reg;

	rtl818x_irq(dev, 0);

	reg = rtl818x_ioread8(priv, &priv->map->CMD);
	reg &= ~RTL818X_CMD_TX_ENABLE;
	reg &= ~RTL818X_CMD_RX_ENABLE;
	rtl818x_iowrite8(priv, &priv->map->CMD, reg);

	priv->rf->stop(dev);

	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, &priv->map->CONFIG4);
	rtl818x_iowrite8(priv, &priv->map->CONFIG4, reg | RTL818X_CONFIG4_VCOOFF);
	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);

	rtl818x_free_rx_ring(dev);
	rtl818x_free_tx_ring(dev);
}

static int rtl818x_config(struct net80211_device *dev, int changed)
{
	struct rtl818x_priv *priv = dev->priv;
	int i;

	if (changed & NET80211_CFG_CHANNEL)
		priv->rf->set_chan(dev, &dev->channels[dev->channel]);

	if (changed & NET80211_CFG_ASSOC) {
		for (i = 0; i < ETH_ALEN; i++)
			rtl818x_iowrite8(priv, &priv->map->BSSID[i], dev->bssid[i]);
		rtl818x_iowrite8(priv, &priv->map->MSR,
				 dev->state & NET80211_ASSOCIATED?
					RTL818X_MSR_INFRA : RTL818X_MSR_NO_LINK);
	}

	if (changed & NET80211_CFG_PHY_PARAMS)
		priv->rf->conf_erp(dev);

	if (changed & NET80211_CFG_RATE) {
		/* figure out the hardware rate number for the new
		   logical rate */
		int hw_rate;
		for (hw_rate = 0; hw_rate < RTL818X_NR_RATES &&
			     rtl818x_rates[hw_rate] != dev->rates[dev->rate];
		     hw_rate++)
			;
		if (hw_rate >= RTL818X_NR_RATES)
			return -EINVAL;

		priv->hw_rate = hw_rate;

		/* and the RTS/CTS rate */
		for (hw_rate = 0; hw_rate < RTL818X_NR_RATES &&
			     rtl818x_rates[hw_rate] !=
				dev->rates[dev->rtscts_rate];
		     hw_rate++)
			;
		if (hw_rate >= RTL818X_NR_RATES)
			hw_rate = priv->hw_rate;

		priv->hw_rtscts_rate = hw_rate;
	}

	return 0;
}

static const u8 rtl818x_eeprom_bits[] = {
	[SPI_BIT_SCLK] = RTL818X_EEPROM_CMD_CK,
	[SPI_BIT_MISO] = RTL818X_EEPROM_CMD_READ,
	[SPI_BIT_MOSI] = RTL818X_EEPROM_CMD_WRITE,
	[SPI_BIT_SS(0)] = RTL818X_EEPROM_CMD_CS,
};

static int rtl818x_spi_read_bit(struct bit_basher *basher, unsigned int bit_id)
{
	struct rtl818x_priv *priv = container_of(basher, struct rtl818x_priv,
						 spibit.basher);

	u8 reg = rtl818x_ioread8(priv, &priv->map->EEPROM_CMD);
	return reg & rtl818x_eeprom_bits[bit_id];
}

static void rtl818x_spi_write_bit(struct bit_basher *basher,
				  unsigned int bit_id, unsigned long data)
{
	struct rtl818x_priv *priv = container_of(basher, struct rtl818x_priv,
						 spibit.basher);

	u8 reg = rtl818x_ioread8(priv, &priv->map->EEPROM_CMD);
	u8 mask = rtl818x_eeprom_bits[bit_id];
	reg = (reg & ~mask) | (data & mask);

	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, reg);

	rtl818x_ioread8(priv, &priv->map->EEPROM_CMD);
	udelay(10);
}

static struct bit_basher_operations rtl818x_basher_ops = {
	.read = rtl818x_spi_read_bit,
	.write = rtl818x_spi_write_bit,
};

#if DBGLVL_MAX
static const char *rtl818x_rf_names[] = {
	NULL,			/* no 0 */
	"Intersil", "RFMD",	/* unsupported 1-2 */
	"SA2400", "max2820", "GRF5101",	/* supported 3-5 */
	NULL, NULL, NULL,	/* no 6-8 */
	"RTL8225",		/* supported 9 */
	"RTL8255",		/* unsupported 10 */
};
#define RTL818X_NR_RF_NAMES 11
#endif

struct net80211_device_operations rtl818x_operations = {
	.open = rtl818x_start,
	.close = rtl818x_stop,
	.transmit = rtl818x_tx,
	.poll = rtl818x_poll,
	.irq = rtl818x_irq,
	.config = rtl818x_config,
};

int rtl818x_probe(struct pci_device *pdev )
{
	struct net80211_device *dev;
	struct rtl818x_priv *priv;
	struct rtl818x_rf_ops *rf;
	int err, i;
	const char *chip_name;
	u32 reg;
	u16 eeprom_val;
	struct net80211_hw_info *hwinfo;

	hwinfo = zalloc(sizeof(*hwinfo));
	if (!hwinfo) {
		DBG("rtl818x: hwinfo alloc failed\n");
		return -ENOMEM;
	}

	adjust_pci_device(pdev);

	dev = net80211_alloc(sizeof(*priv));
	if (!dev) {
		DBG("rtl818x: net80211 alloc failed\n");
		return -ENOMEM;
	}

	priv = dev->priv;
	priv->pdev = pdev;
	dev->netdev->dev = &pdev->dev;

	priv->map = (struct rtl818x_csr *)pdev->ioaddr;
	if (!priv->map) {
		DBG("rtl818x: cannot find device memory\n");
		err = -ENXIO;
		goto err_free_dev;
	}

	reg = rtl818x_ioread32(priv, &priv->map->TX_CONF);
	reg &= RTL818X_TX_CONF_HWVER_MASK;
	switch (reg) {
	case RTL818X_TX_CONF_R8180_ABCD:
		chip_name = "0";
		break;
	case RTL818X_TX_CONF_R8180_F:
		chip_name = "0vF";
		break;
	case RTL818X_TX_CONF_R8185_ABC:
		chip_name = "5";
		break;
	case RTL818X_TX_CONF_R8185_D:
		chip_name = "5vD";
		break;
	default:
		DBG("rtl818x: Unknown chip! (0x%x)\n", reg >> 25);
		err = -ENOSYS;
		goto err_free_dev;
	}

	priv->r8185 = reg & RTL818X_TX_CONF_R8185_ABC;

	hwinfo->bands = NET80211_BAND_BIT_2GHZ;
	hwinfo->flags = NET80211_HW_RX_HAS_FCS;
	hwinfo->signal_type = NET80211_SIGNAL_ARBITRARY;
	hwinfo->signal_max = 65;
	hwinfo->channel_change_time = 1000;

	memcpy(hwinfo->rates[NET80211_BAND_2GHZ], rtl818x_rates,
	       sizeof(*rtl818x_rates) * RTL818X_NR_RATES);

	if (priv->r8185) {
		hwinfo->modes = NET80211_MODE_B | NET80211_MODE_G;
		hwinfo->nr_rates[NET80211_BAND_2GHZ] = RTL818X_NR_RATES;
	} else {
		hwinfo->modes = NET80211_MODE_B;
		hwinfo->nr_rates[NET80211_BAND_2GHZ] = RTL818X_NR_B_RATES;
	}

	priv->spibit.basher.op = &rtl818x_basher_ops;
	priv->spibit.bus.mode = SPI_MODE_THREEWIRE;
	init_spi_bit_basher(&priv->spibit);

	DBG2("rtl818x RX_CONF: %08x\n", rtl818x_ioread32(priv, &priv->map->RX_CONF));

	if (rtl818x_ioread32(priv, &priv->map->RX_CONF) & (1 << 6))
		init_at93c66(&priv->eeprom, 16);
	else
		init_at93c46(&priv->eeprom, 16);
	priv->eeprom.bus = &priv->spibit.bus;

	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_PROGRAM);
	rtl818x_ioread8(priv, &priv->map->EEPROM_CMD);
	udelay(10);

	nvs_read(&priv->eeprom.nvs, 0x06, &eeprom_val, 2);
	DBG2("rtl818x eeprom val = %04x\n", eeprom_val);
	eeprom_val &= 0xFF;

	priv->rf = NULL;
	for_each_table_entry(rf, RTL818X_RF_DRIVERS) {
		if (rf->id == eeprom_val) {
			priv->rf = rf;
			break;
		}
	}

	if (!priv->rf) {
#if DBGLVL_MAX
		if (eeprom_val < RTL818X_NR_RF_NAMES &&
		    rtl818x_rf_names[eeprom_val] != NULL)
			DBG("rtl818x: %s RF frontend not supported!\n",
			    rtl818x_rf_names[eeprom_val]);
		else
			DBG("rtl818x: RF frontend #%d not recognized!\n",
			    eeprom_val);
#endif

		err = -ENOSYS;
		goto err_free_dev;
	}

	nvs_read(&priv->eeprom.nvs, 0x17, &eeprom_val, 2);
	priv->csthreshold = eeprom_val >> 8;
	if (!priv->r8185) {
		nvs_read(&priv->eeprom.nvs, 0xD, &priv->anaparam, 4);
		nvs_read(&priv->eeprom.nvs, 0x19, &priv->rfparam, 2);
		priv->anaparam = le32_to_cpu(priv->anaparam);
		priv->rfparam = le16_to_cpu(priv->rfparam);
	}

	/* read the MAC address */
	nvs_read(&priv->eeprom.nvs, 0x7, hwinfo->hwaddr, 6);

	/* CCK TX power */
	for (i = 0; i < 14; i += 2) {
		u16 txpwr;
		nvs_read(&priv->eeprom.nvs, 0x10 + (i >> 1), &txpwr, 2);
		priv->txpower[i] = txpwr & 0xFF;
		priv->txpower[i + 1] = txpwr >> 8;
	}

	/* OFDM TX power */
	if (priv->r8185) {
		for (i = 0; i < 14; i += 2) {
			u16 txpwr;
			nvs_read(&priv->eeprom.nvs, 0x20 + (i >> 1), &txpwr, 2);
			priv->txpower[i] |= (txpwr & 0xFF) << 8;
			priv->txpower[i + 1] |= txpwr & 0xFF00;
		}
	}

	rtl818x_iowrite8(priv, &priv->map->EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);

	err = net80211_register(dev, &rtl818x_operations, hwinfo);
	if (err) {
		DBG("rtl818x: cannot register device\n");
		goto err_free_dev;
	}

	free(hwinfo);

	DBG("rtl818x: Realtek RTL818%s (RF chip %s) with address %s\n",
	    chip_name, priv->rf->name, netdev_addr(dev->netdev));

	return 0;

 err_free_dev:
	pci_set_drvdata(pdev, NULL);
	net80211_free(dev);
	free(hwinfo);
	return err;
}

void rtl818x_remove(struct pci_device *pdev)
{
	struct net80211_device *dev = pci_get_drvdata(pdev);

	if (!dev)
		return;

	net80211_unregister(dev);
	net80211_free(dev);
}
