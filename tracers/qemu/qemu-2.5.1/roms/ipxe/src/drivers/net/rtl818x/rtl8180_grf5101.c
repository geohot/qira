/*
 * Radio tuning for GCT GRF5101 on RTL8180
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

#define GRF5101_ANTENNA 0xA3

static const int grf5101_encode[] = {
	0x0, 0x8, 0x4, 0xC,
	0x2, 0xA, 0x6, 0xE,
	0x1, 0x9, 0x5, 0xD,
	0x3, 0xB, 0x7, 0xF
};

static void write_grf5101(struct net80211_device *dev, u8 addr, u32 data)
{
	struct rtl818x_priv *priv = dev->priv;
	u32 phy_config;

	phy_config =  grf5101_encode[(data >> 8) & 0xF];
	phy_config |= grf5101_encode[(data >> 4) & 0xF] << 4;
	phy_config |= grf5101_encode[data & 0xF] << 8;
	phy_config |= grf5101_encode[(addr >> 1) & 0xF] << 12;
	phy_config |= (addr & 1) << 16;
	phy_config |= grf5101_encode[(data & 0xf000) >> 12] << 24;

	/* MAC will bang bits to the chip */
	phy_config |= 0x90000000;

	/* This was originally a 32-bit write to a typecast
	   RFPinsOutput, but gcc complained about aliasing rules. -JBO */
	rtl818x_iowrite16(priv, &priv->map->RFPinsOutput, phy_config & 0xffff);
	rtl818x_iowrite16(priv, &priv->map->RFPinsEnable, phy_config >> 16);

	mdelay(3);
}

static void grf5101_write_phy_antenna(struct net80211_device *dev, short chan)
{
	struct rtl818x_priv *priv = dev->priv;
	u8 ant = GRF5101_ANTENNA;

	if (priv->rfparam & RF_PARAM_ANTBDEFAULT)
		ant |= BB_ANTENNA_B;

	if (chan == 14)
		ant |= BB_ANTATTEN_CHAN14;

	rtl818x_write_phy(dev, 0x10, ant);
}

static void grf5101_rf_set_channel(struct net80211_device *dev,
				   struct net80211_channel *channelp)
{
	struct rtl818x_priv *priv = dev->priv;
	int channel = channelp->channel_nr;
	u32 txpw = priv->txpower[channel - 1] & 0xFF;
	u32 chan = channel - 1;

	/* set TX power */
	write_grf5101(dev, 0x15, 0x0);
	write_grf5101(dev, 0x06, txpw);
	write_grf5101(dev, 0x15, 0x10);
	write_grf5101(dev, 0x15, 0x0);

	/* set frequency */
	write_grf5101(dev, 0x07, 0x0);
	write_grf5101(dev, 0x0B, chan);
	write_grf5101(dev, 0x07, 0x1000);

	grf5101_write_phy_antenna(dev, channel);
}

static void grf5101_rf_stop(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;
	u32 anaparam;

	anaparam = priv->anaparam;
	anaparam &= 0x000fffff;
	anaparam |= 0x3f900000;
	rtl818x_set_anaparam(priv, anaparam);

	write_grf5101(dev, 0x07, 0x0);
	write_grf5101(dev, 0x1f, 0x45);
	write_grf5101(dev, 0x1f, 0x5);
	write_grf5101(dev, 0x00, 0x8e4);
}

static void grf5101_rf_init(struct net80211_device *dev)
{
	struct rtl818x_priv *priv = dev->priv;

	rtl818x_set_anaparam(priv, priv->anaparam);

	write_grf5101(dev, 0x1f, 0x0);
	write_grf5101(dev, 0x1f, 0x0);
	write_grf5101(dev, 0x1f, 0x40);
	write_grf5101(dev, 0x1f, 0x60);
	write_grf5101(dev, 0x1f, 0x61);
	write_grf5101(dev, 0x1f, 0x61);
	write_grf5101(dev, 0x00, 0xae4);
	write_grf5101(dev, 0x1f, 0x1);
	write_grf5101(dev, 0x1f, 0x41);
	write_grf5101(dev, 0x1f, 0x61);

	write_grf5101(dev, 0x01, 0x1a23);
	write_grf5101(dev, 0x02, 0x4971);
	write_grf5101(dev, 0x03, 0x41de);
	write_grf5101(dev, 0x04, 0x2d80);
	write_grf5101(dev, 0x05, 0x68ff);	/* 0x61ff original value */
	write_grf5101(dev, 0x06, 0x0);
	write_grf5101(dev, 0x07, 0x0);
	write_grf5101(dev, 0x08, 0x7533);
	write_grf5101(dev, 0x09, 0xc401);
	write_grf5101(dev, 0x0a, 0x0);
	write_grf5101(dev, 0x0c, 0x1c7);
	write_grf5101(dev, 0x0d, 0x29d3);
	write_grf5101(dev, 0x0e, 0x2e8);
	write_grf5101(dev, 0x10, 0x192);
	write_grf5101(dev, 0x11, 0x248);
	write_grf5101(dev, 0x12, 0x0);
	write_grf5101(dev, 0x13, 0x20c4);
	write_grf5101(dev, 0x14, 0xf4fc);
	write_grf5101(dev, 0x15, 0x0);
	write_grf5101(dev, 0x16, 0x1500);

	write_grf5101(dev, 0x07, 0x1000);

	/* baseband configuration */
	rtl818x_write_phy(dev, 0, 0xa8);
	rtl818x_write_phy(dev, 3, 0x0);
	rtl818x_write_phy(dev, 4, 0xc0);
	rtl818x_write_phy(dev, 5, 0x90);
	rtl818x_write_phy(dev, 6, 0x1e);
	rtl818x_write_phy(dev, 7, 0x64);

	grf5101_write_phy_antenna(dev, 1);

	rtl818x_write_phy(dev, 0x11, 0x88);

	if (rtl818x_ioread8(priv, &priv->map->CONFIG2) &
	    RTL818X_CONFIG2_ANTENNA_DIV)
		rtl818x_write_phy(dev, 0x12, 0xc0); /* enable ant diversity */
	else
		rtl818x_write_phy(dev, 0x12, 0x40); /* disable ant diversity */

	rtl818x_write_phy(dev, 0x13, 0x90 | priv->csthreshold);

	rtl818x_write_phy(dev, 0x19, 0x0);
	rtl818x_write_phy(dev, 0x1a, 0xa0);
	rtl818x_write_phy(dev, 0x1b, 0x44);
}

struct rtl818x_rf_ops grf5101_rf_ops __rtl818x_rf_driver = {
	.name		= "GCT GRF5101",
	.id             = 5,
	.init		= grf5101_rf_init,
	.stop		= grf5101_rf_stop,
	.set_chan	= grf5101_rf_set_channel
};
