/*
 * Radio tuning for Maxim max2820 on RTL8180
 *
 * Copyright 2007 Andrea Merello <andreamrl@tiscali.it>
 *
 * Modified slightly for iPXE, June 2009 by Joshua Oreman.
 *
 * Code from the BSD driver and the rtl8181 project have been
 * very useful to understand certain things
 *
 * I want to thanks the Authors of such projects and the Ndiswrapper
 * project Authors.
 *
 * A special Big Thanks also is for all people who donated me cards,
 * making possible the creation of the original rtl8180 driver
 * from which this code is derived!
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <unistd.h>
#include <ipxe/pci.h>
#include <ipxe/net80211.h>

#include "rtl818x.h"

FILE_LICENCE(GPL2_ONLY);

#define MAXIM_ANTENNA 0xb3

static const u32 max2820_chan[] = {
	12, /* CH 1 */
	17,
	22,
	27,
	32,
	37,
	42,
	47,
	52,
	57,
	62,
	67,
	72,
	84, /* CH 14 */
};

static void write_max2820(struct net80211_device *dev, u8 addr, u32 data)
{
	struct rtl818x_priv *priv = dev->priv;
	u32 phy_config;

	phy_config = 0x90 + (data & 0xf);
	phy_config <<= 16;
	phy_config += addr;
	phy_config <<= 8;
	phy_config += (data >> 4) & 0xff;

	/* This was originally a 32-bit write to a typecast
	   RFPinsOutput, but gcc complained about aliasing rules. -JBO */
	rtl818x_iowrite16(priv, &priv->map->RFPinsOutput, phy_config & 0xffff);
	rtl818x_iowrite16(priv, &priv->map->RFPinsEnable, phy_config >> 16);

	mdelay(1);
}

static void max2820_write_phy_antenna(struct net80211_device *dev, short chan)
{
	struct rtl818x_priv *priv = dev->priv;
	u8 ant;

	ant = MAXIM_ANTENNA;
	if (priv->rfparam & RF_PARAM_ANTBDEFAULT)
		ant |= BB_ANTENNA_B;
	if (chan == 14)
		ant |= BB_ANTATTEN_CHAN14;

	rtl818x_write_phy(dev, 0x10, ant);
}

static void max2820_rf_set_channel(struct net80211_device *dev,
				   struct net80211_channel *channelp)
{
	struct rtl818x_priv *priv = dev->priv;
	int channel = channelp->channel_nr;
	unsigned int chan_idx = channel - 1;
	u32 txpw = priv->txpower[chan_idx] & 0xFF;
	u32 chan = max2820_chan[chan_idx];

	/* While philips SA2400 drive the PA bias from
	 * sa2400, for MAXIM we do this directly from BB */
	rtl818x_write_phy(dev, 3, txpw);

	max2820_write_phy_antenna(dev, channel);
	write_max2820(dev, 3, chan);
}

static void max2820_rf_stop(struct net80211_device *dev)
{
	rtl818x_write_phy(dev, 3, 0x8);
	write_max2820(dev, 1, 0);
}


static void max2820_rf_init(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;

	/* MAXIM from netbsd driver */
	write_max2820(dev, 0, 0x007); /* test mode as indicated in datasheet */
	write_max2820(dev, 1, 0x01e); /* enable register */
	write_max2820(dev, 2, 0x001); /* synt register */

	max2820_rf_set_channel(dev, NULL);

	write_max2820(dev, 4, 0x313); /* rx register */

	/* PA is driven directly by the BB, we keep the MAXIM bias
	 * at the highest value in case that setting it to lower
	 * values may introduce some further attenuation somewhere..
	 */
	write_max2820(dev, 5, 0x00f);

	/* baseband configuration */
	rtl818x_write_phy(dev, 0, 0x88); /* sys1       */
	rtl818x_write_phy(dev, 3, 0x08); /* txagc      */
	rtl818x_write_phy(dev, 4, 0xf8); /* lnadet     */
	rtl818x_write_phy(dev, 5, 0x90); /* ifagcinit  */
	rtl818x_write_phy(dev, 6, 0x1a); /* ifagclimit */
	rtl818x_write_phy(dev, 7, 0x64); /* ifagcdet   */

	max2820_write_phy_antenna(dev, 1);

	rtl818x_write_phy(dev, 0x11, 0x88); /* trl */

	if (rtl818x_ioread8(priv, &priv->map->CONFIG2) &
	    RTL818X_CONFIG2_ANTENNA_DIV)
		rtl818x_write_phy(dev, 0x12, 0xc7);
	else
		rtl818x_write_phy(dev, 0x12, 0x47);

	rtl818x_write_phy(dev, 0x13, 0x9b);

	rtl818x_write_phy(dev, 0x19, 0x0);  /* CHESTLIM */
	rtl818x_write_phy(dev, 0x1a, 0x9f); /* CHSQLIM  */

	max2820_rf_set_channel(dev, NULL);
}

struct rtl818x_rf_ops max2820_rf_ops __rtl818x_rf_driver = {
	.name		= "Maxim max2820",
	.id		= 4,
	.init		= max2820_rf_init,
	.stop		= max2820_rf_stop,
	.set_chan	= max2820_rf_set_channel
};
