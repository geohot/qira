/*
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2004-2005 Atheros Communications, Inc.
 * Copyright (c) 2006 Devicescape Software, Inc.
 * Copyright (c) 2007 Jiri Slaby <jirislaby@gmail.com>
 * Copyright (c) 2007 Luis R. Rodriguez <mcgrof@winlab.rutgers.edu>
 *
 * Modified for iPXE, July 2009, by Joshua Oreman <oremanj@rwcr.net>
 * Original from Linux kernel 2.6.30.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 */

FILE_LICENCE ( BSD3 );

#include <stdlib.h>
#include <ipxe/malloc.h>
#include <ipxe/timer.h>
#include <ipxe/netdevice.h>
#include <ipxe/pci.h>
#include <ipxe/pci_io.h>

#include "base.h"
#include "reg.h"

#define ATH5K_CALIB_INTERVAL	10 /* Calibrate PHY every 10 seconds */
#define ATH5K_RETRIES		4  /* Number of times to retry packet sends */
#define ATH5K_DESC_ALIGN	16 /* Alignment for TX/RX descriptors */

/******************\
* Internal defines *
\******************/

/* Known PCI ids */
static struct pci_device_id ath5k_nics[] = {
	PCI_ROM(0x168c, 0x0207, "ath5210e", "Atheros 5210 early", AR5K_AR5210),
	PCI_ROM(0x168c, 0x0007, "ath5210", "Atheros 5210", AR5K_AR5210),
	PCI_ROM(0x168c, 0x0011, "ath5311", "Atheros 5311 (AHB)", AR5K_AR5211),
	PCI_ROM(0x168c, 0x0012, "ath5211", "Atheros 5211", AR5K_AR5211),
	PCI_ROM(0x168c, 0x0013, "ath5212", "Atheros 5212", AR5K_AR5212),
	PCI_ROM(0xa727, 0x0013, "ath5212c","3com Ath 5212", AR5K_AR5212),
	PCI_ROM(0x10b7, 0x0013, "rdag675", "3com 3CRDAG675", AR5K_AR5212),
	PCI_ROM(0x168c, 0x1014, "ath5212m", "Ath 5212 miniPCI", AR5K_AR5212),
	PCI_ROM(0x168c, 0x0014, "ath5212x14", "Atheros 5212 x14", AR5K_AR5212),
	PCI_ROM(0x168c, 0x0015, "ath5212x15", "Atheros 5212 x15", AR5K_AR5212),
	PCI_ROM(0x168c, 0x0016, "ath5212x16", "Atheros 5212 x16", AR5K_AR5212),
	PCI_ROM(0x168c, 0x0017, "ath5212x17", "Atheros 5212 x17", AR5K_AR5212),
	PCI_ROM(0x168c, 0x0018, "ath5212x18", "Atheros 5212 x18", AR5K_AR5212),
	PCI_ROM(0x168c, 0x0019, "ath5212x19", "Atheros 5212 x19", AR5K_AR5212),
	PCI_ROM(0x168c, 0x001a, "ath2413", "Atheros 2413 Griffin", AR5K_AR5212),
	PCI_ROM(0x168c, 0x001b, "ath5413", "Atheros 5413 Eagle", AR5K_AR5212),
	PCI_ROM(0x168c, 0x001c, "ath5212e", "Atheros 5212 PCI-E", AR5K_AR5212),
	PCI_ROM(0x168c, 0x001d, "ath2417", "Atheros 2417 Nala", AR5K_AR5212),
};

/* Known SREVs */
static const struct ath5k_srev_name srev_names[] = {
	{ "5210",	AR5K_VERSION_MAC,	AR5K_SREV_AR5210 },
	{ "5311",	AR5K_VERSION_MAC,	AR5K_SREV_AR5311 },
	{ "5311A",	AR5K_VERSION_MAC,	AR5K_SREV_AR5311A },
	{ "5311B",	AR5K_VERSION_MAC,	AR5K_SREV_AR5311B },
	{ "5211",	AR5K_VERSION_MAC,	AR5K_SREV_AR5211 },
	{ "5212",	AR5K_VERSION_MAC,	AR5K_SREV_AR5212 },
	{ "5213",	AR5K_VERSION_MAC,	AR5K_SREV_AR5213 },
	{ "5213A",	AR5K_VERSION_MAC,	AR5K_SREV_AR5213A },
	{ "2413",	AR5K_VERSION_MAC,	AR5K_SREV_AR2413 },
	{ "2414",	AR5K_VERSION_MAC,	AR5K_SREV_AR2414 },
	{ "5424",	AR5K_VERSION_MAC,	AR5K_SREV_AR5424 },
	{ "5413",	AR5K_VERSION_MAC,	AR5K_SREV_AR5413 },
	{ "5414",	AR5K_VERSION_MAC,	AR5K_SREV_AR5414 },
	{ "2415",	AR5K_VERSION_MAC,	AR5K_SREV_AR2415 },
	{ "5416",	AR5K_VERSION_MAC,	AR5K_SREV_AR5416 },
	{ "5418",	AR5K_VERSION_MAC,	AR5K_SREV_AR5418 },
	{ "2425",	AR5K_VERSION_MAC,	AR5K_SREV_AR2425 },
	{ "2417",	AR5K_VERSION_MAC,	AR5K_SREV_AR2417 },
	{ "xxxxx",	AR5K_VERSION_MAC,	AR5K_SREV_UNKNOWN },
	{ "5110",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5110 },
	{ "5111",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5111 },
	{ "5111A",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5111A },
	{ "2111",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_2111 },
	{ "5112",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5112 },
	{ "5112A",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5112A },
	{ "5112B",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5112B },
	{ "2112",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_2112 },
	{ "2112A",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_2112A },
	{ "2112B",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_2112B },
	{ "2413",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_2413 },
	{ "5413",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5413 },
	{ "2316",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_2316 },
	{ "2317",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_2317 },
	{ "5424",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5424 },
	{ "5133",	AR5K_VERSION_RAD,	AR5K_SREV_RAD_5133 },
	{ "xxxxx",	AR5K_VERSION_RAD,	AR5K_SREV_UNKNOWN },
};

#define ATH5K_SPMBL_NO   1
#define ATH5K_SPMBL_YES  2
#define ATH5K_SPMBL_BOTH 3

static const struct {
	u16 bitrate;
	u8 short_pmbl;
	u8 hw_code;
} ath5k_rates[] = {
	{ 10, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_1M },
	{ 20, ATH5K_SPMBL_NO, ATH5K_RATE_CODE_2M },
	{ 55, ATH5K_SPMBL_NO, ATH5K_RATE_CODE_5_5M },
	{ 110, ATH5K_SPMBL_NO, ATH5K_RATE_CODE_11M },
	{ 60, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_6M },
	{ 90, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_9M },
	{ 120, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_12M },
	{ 180, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_18M },
	{ 240, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_24M },
	{ 360, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_36M },
	{ 480, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_48M },
	{ 540, ATH5K_SPMBL_BOTH, ATH5K_RATE_CODE_54M },
	{ 20, ATH5K_SPMBL_YES, ATH5K_RATE_CODE_2M | AR5K_SET_SHORT_PREAMBLE },
	{ 55, ATH5K_SPMBL_YES, ATH5K_RATE_CODE_5_5M | AR5K_SET_SHORT_PREAMBLE },
	{ 110, ATH5K_SPMBL_YES, ATH5K_RATE_CODE_11M | AR5K_SET_SHORT_PREAMBLE },
	{ 0, 0, 0 },
};

#define ATH5K_NR_RATES 15

/*
 * Prototypes - PCI stack related functions
 */
static int 		ath5k_probe(struct pci_device *pdev);
static void		ath5k_remove(struct pci_device *pdev);

struct pci_driver ath5k_pci_driver __pci_driver = {
	.ids		= ath5k_nics,
	.id_count	= sizeof(ath5k_nics) / sizeof(ath5k_nics[0]),
	.probe		= ath5k_probe,
	.remove		= ath5k_remove,
};



/*
 * Prototypes - MAC 802.11 stack related functions
 */
static int ath5k_tx(struct net80211_device *dev, struct io_buffer *skb);
static int ath5k_reset(struct ath5k_softc *sc, struct net80211_channel *chan);
static int ath5k_reset_wake(struct ath5k_softc *sc);
static int ath5k_start(struct net80211_device *dev);
static void ath5k_stop(struct net80211_device *dev);
static int ath5k_config(struct net80211_device *dev, int changed);
static void ath5k_poll(struct net80211_device *dev);
static void ath5k_irq(struct net80211_device *dev, int enable);

static struct net80211_device_operations ath5k_ops = {
	.open		= ath5k_start,
	.close		= ath5k_stop,
	.transmit	= ath5k_tx,
	.poll		= ath5k_poll,
	.irq		= ath5k_irq,
	.config		= ath5k_config,
};

/*
 * Prototypes - Internal functions
 */
/* Attach detach */
static int 	ath5k_attach(struct net80211_device *dev);
static void 	ath5k_detach(struct net80211_device *dev);
/* Channel/mode setup */
static unsigned int ath5k_copy_channels(struct ath5k_hw *ah,
				struct net80211_channel *channels,
				unsigned int mode,
				unsigned int max);
static int 	ath5k_setup_bands(struct net80211_device *dev);
static int 	ath5k_chan_set(struct ath5k_softc *sc,
				struct net80211_channel *chan);
static void	ath5k_setcurmode(struct ath5k_softc *sc,
				unsigned int mode);
static void	ath5k_mode_setup(struct ath5k_softc *sc);

/* Descriptor setup */
static int	ath5k_desc_alloc(struct ath5k_softc *sc);
static void	ath5k_desc_free(struct ath5k_softc *sc);
/* Buffers setup */
static int 	ath5k_rxbuf_setup(struct ath5k_softc *sc, struct ath5k_buf *bf);
static int 	ath5k_txbuf_setup(struct ath5k_softc *sc, struct ath5k_buf *bf);

static inline void ath5k_txbuf_free(struct ath5k_softc *sc,
				    struct ath5k_buf *bf)
{
	if (!bf->iob)
		return;

	net80211_tx_complete(sc->dev, bf->iob, 0, ECANCELED);
	bf->iob = NULL;
}

static inline void ath5k_rxbuf_free(struct ath5k_softc *sc __unused,
				    struct ath5k_buf *bf)
{
	free_iob(bf->iob);
	bf->iob = NULL;
}

/* Queues setup */
static int 	ath5k_txq_setup(struct ath5k_softc *sc,
					   int qtype, int subtype);
static void 	ath5k_txq_drainq(struct ath5k_softc *sc,
				 struct ath5k_txq *txq);
static void 	ath5k_txq_cleanup(struct ath5k_softc *sc);
static void 	ath5k_txq_release(struct ath5k_softc *sc);
/* Rx handling */
static int 	ath5k_rx_start(struct ath5k_softc *sc);
static void 	ath5k_rx_stop(struct ath5k_softc *sc);
/* Tx handling */
static void 	ath5k_tx_processq(struct ath5k_softc *sc,
				  struct ath5k_txq *txq);

/* Interrupt handling */
static int 	ath5k_init(struct ath5k_softc *sc);
static int 	ath5k_stop_hw(struct ath5k_softc *sc);

static void 	ath5k_calibrate(struct ath5k_softc *sc);

/* Filter */
static void	ath5k_configure_filter(struct ath5k_softc *sc);

/********************\
* PCI Initialization *
\********************/

#if DBGLVL_MAX
static const char *
ath5k_chip_name(enum ath5k_srev_type type, u16 val)
{
	const char *name = "xxxxx";
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(srev_names); i++) {
		if (srev_names[i].sr_type != type)
			continue;

		if ((val & 0xf0) == srev_names[i].sr_val)
			name = srev_names[i].sr_name;

		if ((val & 0xff) == srev_names[i].sr_val) {
			name = srev_names[i].sr_name;
			break;
		}
	}

	return name;
}
#endif

static int ath5k_probe(struct pci_device *pdev)
{
	void *mem;
	struct ath5k_softc *sc;
	struct net80211_device *dev;
	int ret;
	u8 csz;

	adjust_pci_device(pdev);

	/*
	 * Cache line size is used to size and align various
	 * structures used to communicate with the hardware.
	 */
	pci_read_config_byte(pdev, PCI_CACHE_LINE_SIZE, &csz);
	if (csz == 0) {
		/*
		 * We must have this setup properly for rx buffer
		 * DMA to work so force a reasonable value here if it
		 * comes up zero.
		 */
		csz = 16;
		pci_write_config_byte(pdev, PCI_CACHE_LINE_SIZE, csz);
	}
	/*
	 * The default setting of latency timer yields poor results,
	 * set it to the value used by other systems.  It may be worth
	 * tweaking this setting more.
	 */
	pci_write_config_byte(pdev, PCI_LATENCY_TIMER, 0xa8);

	/*
	 * Disable the RETRY_TIMEOUT register (0x41) to keep
	 * PCI Tx retries from interfering with C3 CPU state.
	 */
	pci_write_config_byte(pdev, 0x41, 0);

	mem = ioremap(pdev->membase, 0x10000);
	if (!mem) {
		DBG("ath5k: cannot remap PCI memory region\n");
		ret = -EIO;
		goto err;
	}

	/*
	 * Allocate dev (net80211 main struct)
	 * and dev->priv (driver private data)
	 */
	dev = net80211_alloc(sizeof(*sc));
	if (!dev) {
		DBG("ath5k: cannot allocate 802.11 device\n");
		ret = -ENOMEM;
		goto err_map;
	}

	/* Initialize driver private data */
	sc = dev->priv;
	sc->dev = dev;
	sc->pdev = pdev;

	sc->hwinfo = zalloc(sizeof(*sc->hwinfo));
	if (!sc->hwinfo) {
		DBG("ath5k: cannot allocate 802.11 hardware info structure\n");
		ret = -ENOMEM;
		goto err_free;
	}

	sc->hwinfo->flags = NET80211_HW_RX_HAS_FCS;
	sc->hwinfo->signal_type = NET80211_SIGNAL_DB;
	sc->hwinfo->signal_max = 40; /* 35dB should give perfect 54Mbps */
	sc->hwinfo->channel_change_time = 5000;

	/* Avoid working with the device until setup is complete */
	sc->status |= ATH_STAT_INVALID;

	sc->iobase = mem;
	sc->cachelsz = csz * 4; /* convert to bytes */

	DBG("ath5k: register base at %p (%08lx)\n", sc->iobase, pdev->membase);
	DBG("ath5k: cache line size %d\n", sc->cachelsz);

	/* Set private data */
	pci_set_drvdata(pdev, dev);
	dev->netdev->dev = (struct device *)pdev;

	/* Initialize device */
	ret = ath5k_hw_attach(sc, pdev->id->driver_data, &sc->ah);
	if (ret)
		goto err_free_hwinfo;

	/* Finish private driver data initialization */
	ret = ath5k_attach(dev);
	if (ret)
		goto err_ah;

#if DBGLVL_MAX
	DBG("Atheros AR%s chip found (MAC: 0x%x, PHY: 0x%x)\n",
	    ath5k_chip_name(AR5K_VERSION_MAC, sc->ah->ah_mac_srev),
	    sc->ah->ah_mac_srev, sc->ah->ah_phy_revision);

	if (!sc->ah->ah_single_chip) {
		/* Single chip radio (!RF5111) */
		if (sc->ah->ah_radio_5ghz_revision &&
		    !sc->ah->ah_radio_2ghz_revision) {
			/* No 5GHz support -> report 2GHz radio */
			if (!(sc->ah->ah_capabilities.cap_mode & AR5K_MODE_BIT_11A)) {
				DBG("RF%s 2GHz radio found (0x%x)\n",
				    ath5k_chip_name(AR5K_VERSION_RAD,
						    sc->ah->ah_radio_5ghz_revision),
				    sc->ah->ah_radio_5ghz_revision);
			/* No 2GHz support (5110 and some
			 * 5Ghz only cards) -> report 5Ghz radio */
			} else if (!(sc->ah->ah_capabilities.cap_mode & AR5K_MODE_BIT_11B)) {
				DBG("RF%s 5GHz radio found (0x%x)\n",
				    ath5k_chip_name(AR5K_VERSION_RAD,
						    sc->ah->ah_radio_5ghz_revision),
				    sc->ah->ah_radio_5ghz_revision);
			/* Multiband radio */
			} else {
				DBG("RF%s multiband radio found (0x%x)\n",
				    ath5k_chip_name(AR5K_VERSION_RAD,
						    sc->ah->ah_radio_5ghz_revision),
				    sc->ah->ah_radio_5ghz_revision);
			}
		}
		/* Multi chip radio (RF5111 - RF2111) ->
		 * report both 2GHz/5GHz radios */
		else if (sc->ah->ah_radio_5ghz_revision &&
			 sc->ah->ah_radio_2ghz_revision) {
			DBG("RF%s 5GHz radio found (0x%x)\n",
			    ath5k_chip_name(AR5K_VERSION_RAD,
					    sc->ah->ah_radio_5ghz_revision),
			    sc->ah->ah_radio_5ghz_revision);
			DBG("RF%s 2GHz radio found (0x%x)\n",
			    ath5k_chip_name(AR5K_VERSION_RAD,
					    sc->ah->ah_radio_2ghz_revision),
			    sc->ah->ah_radio_2ghz_revision);
		}
	}
#endif

	/* Ready to go */
	sc->status &= ~ATH_STAT_INVALID;

	return 0;
err_ah:
	ath5k_hw_detach(sc->ah);
err_free_hwinfo:
	free(sc->hwinfo);
err_free:
	net80211_free(dev);
err_map:
	iounmap(mem);
err:
	return ret;
}

static void ath5k_remove(struct pci_device *pdev)
{
	struct net80211_device *dev = pci_get_drvdata(pdev);
	struct ath5k_softc *sc = dev->priv;

	ath5k_detach(dev);
	ath5k_hw_detach(sc->ah);
	iounmap(sc->iobase);
	free(sc->hwinfo);
	net80211_free(dev);
}


/***********************\
* Driver Initialization *
\***********************/

static int
ath5k_attach(struct net80211_device *dev)
{
	struct ath5k_softc *sc = dev->priv;
	struct ath5k_hw *ah = sc->ah;
	int ret;

	/*
	 * Collect the channel list.  The 802.11 layer
	 * is resposible for filtering this list based
	 * on settings like the phy mode and regulatory
	 * domain restrictions.
	 */
	ret = ath5k_setup_bands(dev);
	if (ret) {
		DBG("ath5k: can't get channels\n");
		goto err;
	}

	/* NB: setup here so ath5k_rate_update is happy */
	if (ah->ah_modes & AR5K_MODE_BIT_11A)
		ath5k_setcurmode(sc, AR5K_MODE_11A);
	else
		ath5k_setcurmode(sc, AR5K_MODE_11B);

	/*
	 * Allocate tx+rx descriptors and populate the lists.
	 */
	ret = ath5k_desc_alloc(sc);
	if (ret) {
		DBG("ath5k: can't allocate descriptors\n");
		goto err;
	}

	/*
	 * Allocate hardware transmit queues. Note that hw functions
	 * handle reseting these queues at the needed time.
	 */
	ret = ath5k_txq_setup(sc, AR5K_TX_QUEUE_DATA, AR5K_WME_AC_BE);
	if (ret) {
		DBG("ath5k: can't setup xmit queue\n");
		goto err_desc;
	}

	sc->last_calib_ticks = currticks();

	ret = ath5k_eeprom_read_mac(ah, sc->hwinfo->hwaddr);
	if (ret) {
		DBG("ath5k: unable to read address from EEPROM: 0x%04x\n",
		    sc->pdev->device);
		goto err_queues;
	}

	memset(sc->bssidmask, 0xff, ETH_ALEN);
	ath5k_hw_set_bssid_mask(sc->ah, sc->bssidmask);

	ret = net80211_register(sc->dev, &ath5k_ops, sc->hwinfo);
	if (ret) {
		DBG("ath5k: can't register ieee80211 hw\n");
		goto err_queues;
	}

	return 0;
err_queues:
	ath5k_txq_release(sc);
err_desc:
	ath5k_desc_free(sc);
err:
	return ret;
}

static void
ath5k_detach(struct net80211_device *dev)
{
	struct ath5k_softc *sc = dev->priv;

	net80211_unregister(dev);
	ath5k_desc_free(sc);
	ath5k_txq_release(sc);
}




/********************\
* Channel/mode setup *
\********************/

/*
 * Convert IEEE channel number to MHz frequency.
 */
static inline short
ath5k_ieee2mhz(short chan)
{
	if (chan < 14)
		return 2407 + 5 * chan;
	if (chan == 14)
		return 2484;
	if (chan < 27)
		return 2212 + 20 * chan;
	return 5000 + 5 * chan;
}

static unsigned int
ath5k_copy_channels(struct ath5k_hw *ah,
		    struct net80211_channel *channels,
		    unsigned int mode, unsigned int max)
{
	unsigned int i, count, size, chfreq, freq, ch;

	if (!(ah->ah_modes & (1 << mode)))
		return 0;

	switch (mode) {
	case AR5K_MODE_11A:
	case AR5K_MODE_11A_TURBO:
		/* 1..220, but 2GHz frequencies are filtered by check_channel */
		size = 220;
		chfreq = CHANNEL_5GHZ;
		break;
	case AR5K_MODE_11B:
	case AR5K_MODE_11G:
	case AR5K_MODE_11G_TURBO:
		size = 26;
		chfreq = CHANNEL_2GHZ;
		break;
	default:
		return 0;
	}

	for (i = 0, count = 0; i < size && max > 0; i++) {
		ch = i + 1 ;
		freq = ath5k_ieee2mhz(ch);

		/* Check if channel is supported by the chipset */
		if (!ath5k_channel_ok(ah, freq, chfreq))
			continue;

		/* Write channel info and increment counter */
		channels[count].center_freq = freq;
		channels[count].maxpower = 0; /* use regulatory */
		channels[count].band = (chfreq == CHANNEL_2GHZ) ?
			NET80211_BAND_2GHZ : NET80211_BAND_5GHZ;
		switch (mode) {
		case AR5K_MODE_11A:
		case AR5K_MODE_11G:
			channels[count].hw_value = chfreq | CHANNEL_OFDM;
			break;
		case AR5K_MODE_11A_TURBO:
		case AR5K_MODE_11G_TURBO:
			channels[count].hw_value = chfreq |
				CHANNEL_OFDM | CHANNEL_TURBO;
			break;
		case AR5K_MODE_11B:
			channels[count].hw_value = CHANNEL_B;
		}

		count++;
		max--;
	}

	return count;
}

static int
ath5k_setup_bands(struct net80211_device *dev)
{
	struct ath5k_softc *sc = dev->priv;
	struct ath5k_hw *ah = sc->ah;
	int max_c, count_c = 0;
	int i;
	int band;

	max_c = sizeof(sc->hwinfo->channels) / sizeof(sc->hwinfo->channels[0]);

	/* 2GHz band */
	if (sc->ah->ah_capabilities.cap_mode & AR5K_MODE_BIT_11G) {
		/* G mode */
		band = NET80211_BAND_2GHZ;
		sc->hwinfo->bands = NET80211_BAND_BIT_2GHZ;
		sc->hwinfo->modes = (NET80211_MODE_G | NET80211_MODE_B);

		for (i = 0; i < 12; i++)
			sc->hwinfo->rates[band][i] = ath5k_rates[i].bitrate;
		sc->hwinfo->nr_rates[band] = 12;

		sc->hwinfo->nr_channels =
			ath5k_copy_channels(ah, sc->hwinfo->channels,
					    AR5K_MODE_11G, max_c);
		count_c = sc->hwinfo->nr_channels;
		max_c -= count_c;
	} else if (sc->ah->ah_capabilities.cap_mode & AR5K_MODE_BIT_11B) {
		/* B mode */
		band = NET80211_BAND_2GHZ;
		sc->hwinfo->bands = NET80211_BAND_BIT_2GHZ;
		sc->hwinfo->modes = NET80211_MODE_B;

		for (i = 0; i < 4; i++)
			sc->hwinfo->rates[band][i] = ath5k_rates[i].bitrate;
		sc->hwinfo->nr_rates[band] = 4;

		sc->hwinfo->nr_channels =
			ath5k_copy_channels(ah, sc->hwinfo->channels,
					    AR5K_MODE_11B, max_c);
		count_c = sc->hwinfo->nr_channels;
		max_c -= count_c;
	}

	/* 5GHz band, A mode */
	if (sc->ah->ah_capabilities.cap_mode & AR5K_MODE_BIT_11A) {
		band = NET80211_BAND_5GHZ;
		sc->hwinfo->bands |= NET80211_BAND_BIT_5GHZ;
		sc->hwinfo->modes |= NET80211_MODE_A;

		for (i = 0; i < 8; i++)
			sc->hwinfo->rates[band][i] = ath5k_rates[i+4].bitrate;
		sc->hwinfo->nr_rates[band] = 8;

		sc->hwinfo->nr_channels =
			ath5k_copy_channels(ah, sc->hwinfo->channels,
					    AR5K_MODE_11B, max_c);
		count_c = sc->hwinfo->nr_channels;
		max_c -= count_c;
	}

	return 0;
}

/*
 * Set/change channels.  If the channel is really being changed,
 * it's done by reseting the chip.  To accomplish this we must
 * first cleanup any pending DMA, then restart stuff after a la
 * ath5k_init.
 */
static int
ath5k_chan_set(struct ath5k_softc *sc, struct net80211_channel *chan)
{
	if (chan->center_freq != sc->curchan->center_freq ||
	    chan->hw_value != sc->curchan->hw_value) {
		/*
		 * To switch channels clear any pending DMA operations;
		 * wait long enough for the RX fifo to drain, reset the
		 * hardware at the new frequency, and then re-enable
		 * the relevant bits of the h/w.
		 */
		DBG2("ath5k: resetting for channel change (%d -> %d MHz)\n",
		     sc->curchan->center_freq, chan->center_freq);
		return ath5k_reset(sc, chan);
	}

	return 0;
}

static void
ath5k_setcurmode(struct ath5k_softc *sc, unsigned int mode)
{
	sc->curmode = mode;

	if (mode == AR5K_MODE_11A) {
		sc->curband = NET80211_BAND_5GHZ;
	} else {
		sc->curband = NET80211_BAND_2GHZ;
	}
}

static void
ath5k_mode_setup(struct ath5k_softc *sc)
{
	struct ath5k_hw *ah = sc->ah;
	u32 rfilt;

	/* configure rx filter */
	rfilt = sc->filter_flags;
	ath5k_hw_set_rx_filter(ah, rfilt);

	if (ath5k_hw_hasbssidmask(ah))
		ath5k_hw_set_bssid_mask(ah, sc->bssidmask);

	/* configure operational mode */
	ath5k_hw_set_opmode(ah);

	ath5k_hw_set_mcast_filter(ah, 0, 0);
}

static inline int
ath5k_hw_rix_to_bitrate(int hw_rix)
{
	int i;

	for (i = 0; i < ATH5K_NR_RATES; i++) {
		if (ath5k_rates[i].hw_code == hw_rix)
			return ath5k_rates[i].bitrate;
	}

	DBG("ath5k: invalid rix %02x\n", hw_rix);
	return 10;		/* use lowest rate */
}

int ath5k_bitrate_to_hw_rix(int bitrate)
{
	int i;

	for (i = 0; i < ATH5K_NR_RATES; i++) {
		if (ath5k_rates[i].bitrate == bitrate)
			return ath5k_rates[i].hw_code;
	}

	DBG("ath5k: invalid bitrate %d\n", bitrate);
	return ATH5K_RATE_CODE_1M; /* use lowest rate */
}

/***************\
* Buffers setup *
\***************/

static struct io_buffer *
ath5k_rx_iob_alloc(struct ath5k_softc *sc, u32 *iob_addr)
{
	struct io_buffer *iob;
	unsigned int off;

	/*
	 * Allocate buffer with headroom_needed space for the
	 * fake physical layer header at the start.
	 */
	iob = alloc_iob(sc->rxbufsize + sc->cachelsz - 1);

	if (!iob) {
		DBG("ath5k: can't alloc iobuf of size %d\n",
		    sc->rxbufsize + sc->cachelsz - 1);
		return NULL;
	}

	*iob_addr = virt_to_bus(iob->data);

	/*
	 * Cache-line-align.  This is important (for the
	 * 5210 at least) as not doing so causes bogus data
	 * in rx'd frames.
	 */
	off = *iob_addr % sc->cachelsz;
	if (off != 0) {
		iob_reserve(iob, sc->cachelsz - off);
		*iob_addr += sc->cachelsz - off;
	}

	return iob;
}

static int
ath5k_rxbuf_setup(struct ath5k_softc *sc, struct ath5k_buf *bf)
{
	struct ath5k_hw *ah = sc->ah;
	struct io_buffer *iob = bf->iob;
	struct ath5k_desc *ds;

	if (!iob) {
		iob = ath5k_rx_iob_alloc(sc, &bf->iobaddr);
		if (!iob)
			return -ENOMEM;
		bf->iob = iob;
	}

	/*
	 * Setup descriptors.  For receive we always terminate
	 * the descriptor list with a self-linked entry so we'll
	 * not get overrun under high load (as can happen with a
	 * 5212 when ANI processing enables PHY error frames).
	 *
	 * To insure the last descriptor is self-linked we create
	 * each descriptor as self-linked and add it to the end.  As
	 * each additional descriptor is added the previous self-linked
	 * entry is ``fixed'' naturally.  This should be safe even
	 * if DMA is happening.  When processing RX interrupts we
	 * never remove/process the last, self-linked, entry on the
	 * descriptor list.  This insures the hardware always has
	 * someplace to write a new frame.
	 */
	ds = bf->desc;
	ds->ds_link = bf->daddr;	/* link to self */
	ds->ds_data = bf->iobaddr;
	if (ah->ah_setup_rx_desc(ah, ds,
				 iob_tailroom(iob),	/* buffer size */
				 0) != 0) {
		DBG("ath5k: error setting up RX descriptor for %zd bytes\n", iob_tailroom(iob));
		return -EINVAL;
	}

	if (sc->rxlink != NULL)
		*sc->rxlink = bf->daddr;
	sc->rxlink = &ds->ds_link;
	return 0;
}

static int
ath5k_txbuf_setup(struct ath5k_softc *sc, struct ath5k_buf *bf)
{
	struct ath5k_hw *ah = sc->ah;
	struct ath5k_txq *txq = &sc->txq;
	struct ath5k_desc *ds = bf->desc;
	struct io_buffer *iob = bf->iob;
	unsigned int pktlen, flags;
	int ret;
	u16 duration = 0;
	u16 cts_rate = 0;

	flags = AR5K_TXDESC_INTREQ | AR5K_TXDESC_CLRDMASK;
	bf->iobaddr = virt_to_bus(iob->data);
	pktlen = iob_len(iob);

	/* FIXME: If we are in g mode and rate is a CCK rate
	 * subtract ah->ah_txpower.txp_cck_ofdm_pwr_delta
	 * from tx power (value is in dB units already) */
	if (sc->dev->phy_flags & NET80211_PHY_USE_PROTECTION) {
		struct net80211_device *dev = sc->dev;

		flags |= AR5K_TXDESC_CTSENA;
		cts_rate = sc->hw_rtscts_rate;
		duration = net80211_cts_duration(dev, pktlen);
	}
	ret = ah->ah_setup_tx_desc(ah, ds, pktlen,
				   IEEE80211_TYP_FRAME_HEADER_LEN,
				   AR5K_PKT_TYPE_NORMAL, sc->power_level * 2,
				   sc->hw_rate, ATH5K_RETRIES,
				   AR5K_TXKEYIX_INVALID, 0, flags,
				   cts_rate, duration);
	if (ret)
		return ret;

	ds->ds_link = 0;
	ds->ds_data = bf->iobaddr;

	list_add_tail(&bf->list, &txq->q);
	if (txq->link == NULL) /* is this first packet? */
		ath5k_hw_set_txdp(ah, txq->qnum, bf->daddr);
	else /* no, so only link it */
		*txq->link = bf->daddr;

	txq->link = &ds->ds_link;
	ath5k_hw_start_tx_dma(ah, txq->qnum);
	mb();

	return 0;
}

/*******************\
* Descriptors setup *
\*******************/

static int
ath5k_desc_alloc(struct ath5k_softc *sc)
{
	struct ath5k_desc *ds;
	struct ath5k_buf *bf;
	u32 da;
	unsigned int i;
	int ret;

	/* allocate descriptors */
	sc->desc_len = sizeof(struct ath5k_desc) * (ATH_TXBUF + ATH_RXBUF + 1);
	sc->desc = malloc_dma(sc->desc_len, ATH5K_DESC_ALIGN);
	if (sc->desc == NULL) {
		DBG("ath5k: can't allocate descriptors\n");
		ret = -ENOMEM;
		goto err;
	}
	memset(sc->desc, 0, sc->desc_len);
	sc->desc_daddr = virt_to_bus(sc->desc);

	ds = sc->desc;
	da = sc->desc_daddr;

	bf = calloc(ATH_TXBUF + ATH_RXBUF + 1, sizeof(struct ath5k_buf));
	if (bf == NULL) {
		DBG("ath5k: can't allocate buffer pointers\n");
		ret = -ENOMEM;
		goto err_free;
	}
	sc->bufptr = bf;

	INIT_LIST_HEAD(&sc->rxbuf);
	for (i = 0; i < ATH_RXBUF; i++, bf++, ds++, da += sizeof(*ds)) {
		bf->desc = ds;
		bf->daddr = da;
		list_add_tail(&bf->list, &sc->rxbuf);
	}

	INIT_LIST_HEAD(&sc->txbuf);
	sc->txbuf_len = ATH_TXBUF;
	for (i = 0; i < ATH_TXBUF; i++, bf++, ds++, da += sizeof(*ds)) {
		bf->desc = ds;
		bf->daddr = da;
		list_add_tail(&bf->list, &sc->txbuf);
	}

	return 0;

err_free:
	free_dma(sc->desc, sc->desc_len);
err:
	sc->desc = NULL;
	return ret;
}

static void
ath5k_desc_free(struct ath5k_softc *sc)
{
	struct ath5k_buf *bf;

	list_for_each_entry(bf, &sc->txbuf, list)
		ath5k_txbuf_free(sc, bf);
	list_for_each_entry(bf, &sc->rxbuf, list)
		ath5k_rxbuf_free(sc, bf);

	/* Free memory associated with all descriptors */
	free_dma(sc->desc, sc->desc_len);

	free(sc->bufptr);
	sc->bufptr = NULL;
}





/**************\
* Queues setup *
\**************/

static int
ath5k_txq_setup(struct ath5k_softc *sc, int qtype, int subtype)
{
	struct ath5k_hw *ah = sc->ah;
	struct ath5k_txq *txq;
	struct ath5k_txq_info qi = {
		.tqi_subtype = subtype,
		.tqi_aifs = AR5K_TXQ_USEDEFAULT,
		.tqi_cw_min = AR5K_TXQ_USEDEFAULT,
		.tqi_cw_max = AR5K_TXQ_USEDEFAULT
	};
	int qnum;

	/*
	 * Enable interrupts only for EOL and DESC conditions.
	 * We mark tx descriptors to receive a DESC interrupt
	 * when a tx queue gets deep; otherwise waiting for the
	 * EOL to reap descriptors.  Note that this is done to
	 * reduce interrupt load and this only defers reaping
	 * descriptors, never transmitting frames.  Aside from
	 * reducing interrupts this also permits more concurrency.
	 * The only potential downside is if the tx queue backs
	 * up in which case the top half of the kernel may backup
	 * due to a lack of tx descriptors.
	 */
	qi.tqi_flags = AR5K_TXQ_FLAG_TXEOLINT_ENABLE |
				AR5K_TXQ_FLAG_TXDESCINT_ENABLE;
	qnum = ath5k_hw_setup_tx_queue(ah, qtype, &qi);
	if (qnum < 0) {
		DBG("ath5k: can't set up a TX queue\n");
		return -EIO;
	}

	txq = &sc->txq;
	if (!txq->setup) {
		txq->qnum = qnum;
		txq->link = NULL;
		INIT_LIST_HEAD(&txq->q);
		txq->setup = 1;
	}
	return 0;
}

static void
ath5k_txq_drainq(struct ath5k_softc *sc, struct ath5k_txq *txq)
{
	struct ath5k_buf *bf, *bf0;

	list_for_each_entry_safe(bf, bf0, &txq->q, list) {
		ath5k_txbuf_free(sc, bf);

		list_del(&bf->list);
		list_add_tail(&bf->list, &sc->txbuf);
		sc->txbuf_len++;
	}
	txq->link = NULL;
}

/*
 * Drain the transmit queues and reclaim resources.
 */
static void
ath5k_txq_cleanup(struct ath5k_softc *sc)
{
	struct ath5k_hw *ah = sc->ah;

	if (!(sc->status & ATH_STAT_INVALID)) {
		/* don't touch the hardware if marked invalid */
		if (sc->txq.setup) {
			ath5k_hw_stop_tx_dma(ah, sc->txq.qnum);
			DBG("ath5k: txq [%d] %x, link %p\n",
			    sc->txq.qnum,
			    ath5k_hw_get_txdp(ah, sc->txq.qnum),
			    sc->txq.link);
		}
	}

	if (sc->txq.setup)
		ath5k_txq_drainq(sc, &sc->txq);
}

static void
ath5k_txq_release(struct ath5k_softc *sc)
{
	if (sc->txq.setup) {
		ath5k_hw_release_tx_queue(sc->ah);
		sc->txq.setup = 0;
	}
}




/*************\
* RX Handling *
\*************/

/*
 * Enable the receive h/w following a reset.
 */
static int
ath5k_rx_start(struct ath5k_softc *sc)
{
	struct ath5k_hw *ah = sc->ah;
	struct ath5k_buf *bf;
	int ret;

	sc->rxbufsize = IEEE80211_MAX_LEN;
	if (sc->rxbufsize % sc->cachelsz != 0)
		sc->rxbufsize += sc->cachelsz - (sc->rxbufsize % sc->cachelsz);

	sc->rxlink = NULL;

	list_for_each_entry(bf, &sc->rxbuf, list) {
		ret = ath5k_rxbuf_setup(sc, bf);
		if (ret != 0)
			return ret;
	}

	bf = list_entry(sc->rxbuf.next, struct ath5k_buf, list);

	ath5k_hw_set_rxdp(ah, bf->daddr);
	ath5k_hw_start_rx_dma(ah);	/* enable recv descriptors */
	ath5k_mode_setup(sc);		/* set filters, etc. */
	ath5k_hw_start_rx_pcu(ah);	/* re-enable PCU/DMA engine */

	return 0;
}

/*
 * Disable the receive h/w in preparation for a reset.
 */
static void
ath5k_rx_stop(struct ath5k_softc *sc)
{
	struct ath5k_hw *ah = sc->ah;

	ath5k_hw_stop_rx_pcu(ah);	/* disable PCU */
	ath5k_hw_set_rx_filter(ah, 0);	/* clear recv filter */
	ath5k_hw_stop_rx_dma(ah);	/* disable DMA engine */

	sc->rxlink = NULL;		/* just in case */
}

static void
ath5k_handle_rx(struct ath5k_softc *sc)
{
	struct ath5k_rx_status rs;
	struct io_buffer *iob, *next_iob;
	u32 next_iob_addr;
	struct ath5k_buf *bf, *bf_last;
	struct ath5k_desc *ds;
	int ret;

	memset(&rs, 0, sizeof(rs));

	if (list_empty(&sc->rxbuf)) {
		DBG("ath5k: empty rx buf pool\n");
		return;
	}

	bf_last = list_entry(sc->rxbuf.prev, struct ath5k_buf, list);

	do {
		bf = list_entry(sc->rxbuf.next, struct ath5k_buf, list);
		assert(bf->iob != NULL);
		iob = bf->iob;
		ds = bf->desc;

		/*
		 * last buffer must not be freed to ensure proper hardware
		 * function. When the hardware finishes also a packet next to
		 * it, we are sure, it doesn't use it anymore and we can go on.
		 */
		if (bf_last == bf)
			bf->flags |= 1;
		if (bf->flags) {
			struct ath5k_buf *bf_next = list_entry(bf->list.next,
					struct ath5k_buf, list);
			ret = sc->ah->ah_proc_rx_desc(sc->ah, bf_next->desc,
					&rs);
			if (ret)
				break;
			bf->flags &= ~1;
			/* skip the overwritten one (even status is martian) */
			goto next;
		}

		ret = sc->ah->ah_proc_rx_desc(sc->ah, ds, &rs);
		if (ret) {
			if (ret != -EINPROGRESS) {
				DBG("ath5k: error in processing rx desc: %s\n",
				    strerror(ret));
				net80211_rx_err(sc->dev, NULL, -ret);
			} else {
				/* normal return, reached end of
				   available descriptors */
			}
			return;
		}

		if (rs.rs_more) {
			DBG("ath5k: unsupported fragmented rx\n");
			goto next;
		}

		if (rs.rs_status) {
			if (rs.rs_status & AR5K_RXERR_PHY) {
				/* These are uncommon, and may indicate a real problem. */
				net80211_rx_err(sc->dev, NULL, EIO);
				goto next;
			}
			if (rs.rs_status & AR5K_RXERR_CRC) {
				/* These occur *all the time*. */
				goto next;
			}
			if (rs.rs_status & AR5K_RXERR_DECRYPT) {
				/*
				 * Decrypt error.  If the error occurred
				 * because there was no hardware key, then
				 * let the frame through so the upper layers
				 * can process it.  This is necessary for 5210
				 * parts which have no way to setup a ``clear''
				 * key cache entry.
				 *
				 * XXX do key cache faulting
				 */
				if (rs.rs_keyix == AR5K_RXKEYIX_INVALID &&
				    !(rs.rs_status & AR5K_RXERR_CRC))
					goto accept;
			}

			/* any other error, unhandled */
			DBG("ath5k: packet rx status %x\n", rs.rs_status);
			goto next;
		}
accept:
		next_iob = ath5k_rx_iob_alloc(sc, &next_iob_addr);

		/*
		 * If we can't replace bf->iob with a new iob under memory
		 * pressure, just skip this packet
		 */
		if (!next_iob) {
			DBG("ath5k: dropping packet under memory pressure\n");
			goto next;
		}

		iob_put(iob, rs.rs_datalen);

		/* The MAC header is padded to have 32-bit boundary if the
		 * packet payload is non-zero. However, iPXE only
		 * supports standard 802.11 packets with 24-byte
		 * header, so no padding correction should be needed.
		 */

		DBG2("ath5k: rx %d bytes, signal %d\n", rs.rs_datalen,
		     rs.rs_rssi);

		net80211_rx(sc->dev, iob, rs.rs_rssi,
			    ath5k_hw_rix_to_bitrate(rs.rs_rate));

		bf->iob = next_iob;
		bf->iobaddr = next_iob_addr;
next:
		list_del(&bf->list);
		list_add_tail(&bf->list, &sc->rxbuf);
	} while (ath5k_rxbuf_setup(sc, bf) == 0);
}




/*************\
* TX Handling *
\*************/

static void
ath5k_tx_processq(struct ath5k_softc *sc, struct ath5k_txq *txq)
{
	struct ath5k_tx_status ts;
	struct ath5k_buf *bf, *bf0;
	struct ath5k_desc *ds;
	struct io_buffer *iob;
	int ret;

	memset(&ts, 0, sizeof(ts));

	list_for_each_entry_safe(bf, bf0, &txq->q, list) {
		ds = bf->desc;

		ret = sc->ah->ah_proc_tx_desc(sc->ah, ds, &ts);
		if (ret) {
			if (ret != -EINPROGRESS) {
				DBG("ath5k: error in processing tx desc: %s\n",
				    strerror(ret));
			} else {
				/* normal return, reached end of tx completions */
			}
			break;
		}

		iob = bf->iob;
		bf->iob = NULL;

		DBG2("ath5k: tx %zd bytes complete, %d retries\n",
		     iob_len(iob), ts.ts_retry[0]);

		net80211_tx_complete(sc->dev, iob, ts.ts_retry[0],
				     ts.ts_status ? EIO : 0);

		list_del(&bf->list);
		list_add_tail(&bf->list, &sc->txbuf);
		sc->txbuf_len++;
	}

	if (list_empty(&txq->q))
		txq->link = NULL;
}

static void
ath5k_handle_tx(struct ath5k_softc *sc)
{
	ath5k_tx_processq(sc, &sc->txq);
}


/********************\
* Interrupt handling *
\********************/

static void
ath5k_irq(struct net80211_device *dev, int enable)
{
	struct ath5k_softc *sc = dev->priv;
	struct ath5k_hw *ah = sc->ah;

	sc->irq_ena = enable;
	ah->ah_ier = enable ? AR5K_IER_ENABLE : AR5K_IER_DISABLE;

	ath5k_hw_reg_write(ah, ah->ah_ier, AR5K_IER);
	ath5k_hw_set_imr(ah, sc->imask);
}

static int
ath5k_init(struct ath5k_softc *sc)
{
	struct ath5k_hw *ah = sc->ah;
	int ret, i;

	/*
	 * Stop anything previously setup.  This is safe
	 * no matter this is the first time through or not.
	 */
	ath5k_stop_hw(sc);

	/*
	 * The basic interface to setting the hardware in a good
	 * state is ``reset''.  On return the hardware is known to
	 * be powered up and with interrupts disabled.  This must
	 * be followed by initialization of the appropriate bits
	 * and then setup of the interrupt mask.
	 */
	sc->curchan = sc->dev->channels + sc->dev->channel;
	sc->curband = sc->curchan->band;
	sc->imask = AR5K_INT_RXOK | AR5K_INT_RXERR | AR5K_INT_RXEOL |
		AR5K_INT_RXORN | AR5K_INT_TXDESC | AR5K_INT_TXEOL |
		AR5K_INT_FATAL | AR5K_INT_GLOBAL;
	ret = ath5k_reset(sc, NULL);
	if (ret)
		goto done;

	ath5k_rfkill_hw_start(ah);

	/*
	 * Reset the key cache since some parts do not reset the
	 * contents on initial power up or resume from suspend.
	 */
	for (i = 0; i < AR5K_KEYTABLE_SIZE; i++)
		ath5k_hw_reset_key(ah, i);

	/* Set ack to be sent at low bit-rates */
	ath5k_hw_set_ack_bitrate_high(ah, 0);

	ret = 0;
done:
	mb();
	return ret;
}

static int
ath5k_stop_hw(struct ath5k_softc *sc)
{
	struct ath5k_hw *ah = sc->ah;

	/*
	 * Shutdown the hardware and driver:
	 *    stop output from above
	 *    disable interrupts
	 *    turn off timers
	 *    turn off the radio
	 *    clear transmit machinery
	 *    clear receive machinery
	 *    drain and release tx queues
	 *    reclaim beacon resources
	 *    power down hardware
	 *
	 * Note that some of this work is not possible if the
	 * hardware is gone (invalid).
	 */

	if (!(sc->status & ATH_STAT_INVALID)) {
		ath5k_hw_set_imr(ah, 0);
	}
	ath5k_txq_cleanup(sc);
	if (!(sc->status & ATH_STAT_INVALID)) {
		ath5k_rx_stop(sc);
		ath5k_hw_phy_disable(ah);
	} else
		sc->rxlink = NULL;

	ath5k_rfkill_hw_stop(sc->ah);

	return 0;
}

static void
ath5k_poll(struct net80211_device *dev)
{
	struct ath5k_softc *sc = dev->priv;
	struct ath5k_hw *ah = sc->ah;
	enum ath5k_int status;
	unsigned int counter = 1000;

	if (currticks() - sc->last_calib_ticks >
	    ATH5K_CALIB_INTERVAL * ticks_per_sec()) {
		ath5k_calibrate(sc);
		sc->last_calib_ticks = currticks();
	}

	if ((sc->status & ATH_STAT_INVALID) ||
	    (sc->irq_ena && !ath5k_hw_is_intr_pending(ah)))
		return;

	do {
		ath5k_hw_get_isr(ah, &status);		/* NB: clears IRQ too */
		DBGP("ath5k: status %#x/%#x\n", status, sc->imask);
		if (status & AR5K_INT_FATAL) {
			/*
			 * Fatal errors are unrecoverable.
			 * Typically these are caused by DMA errors.
			 */
			DBG("ath5k: fatal error, resetting\n");
			ath5k_reset_wake(sc);
		} else if (status & AR5K_INT_RXORN) {
			DBG("ath5k: rx overrun, resetting\n");
			ath5k_reset_wake(sc);
		} else {
			if (status & AR5K_INT_RXEOL) {
				/*
				 * NB: the hardware should re-read the link when
				 *     RXE bit is written, but it doesn't work at
				 *     least on older hardware revs.
				 */
				DBG("ath5k: rx EOL\n");
				sc->rxlink = NULL;
			}
			if (status & AR5K_INT_TXURN) {
				/* bump tx trigger level */
				DBG("ath5k: tx underrun\n");
				ath5k_hw_update_tx_triglevel(ah, 1);
			}
			if (status & (AR5K_INT_RXOK | AR5K_INT_RXERR))
				ath5k_handle_rx(sc);
			if (status & (AR5K_INT_TXOK | AR5K_INT_TXDESC
				      | AR5K_INT_TXERR | AR5K_INT_TXEOL))
				ath5k_handle_tx(sc);
		}
	} while (ath5k_hw_is_intr_pending(ah) && counter-- > 0);

	if (!counter)
		DBG("ath5k: too many interrupts, giving up for now\n");
}

/*
 * Periodically recalibrate the PHY to account
 * for temperature/environment changes.
 */
static void
ath5k_calibrate(struct ath5k_softc *sc)
{
	struct ath5k_hw *ah = sc->ah;

	if (ath5k_hw_gainf_calibrate(ah) == AR5K_RFGAIN_NEED_CHANGE) {
		/*
		 * Rfgain is out of bounds, reset the chip
		 * to load new gain values.
		 */
		DBG("ath5k: resetting for calibration\n");
		ath5k_reset_wake(sc);
	}
	if (ath5k_hw_phy_calibrate(ah, sc->curchan))
		DBG("ath5k: calibration of channel %d failed\n",
		    sc->curchan->channel_nr);
}


/********************\
* Net80211 functions *
\********************/

static int
ath5k_tx(struct net80211_device *dev, struct io_buffer *iob)
{
	struct ath5k_softc *sc = dev->priv;
	struct ath5k_buf *bf;
	int rc;

	/*
	 * The hardware expects the header padded to 4 byte boundaries.
	 * iPXE only ever sends 24-byte headers, so no action necessary.
	 */

	if (list_empty(&sc->txbuf)) {
		DBG("ath5k: dropping packet because no tx bufs available\n");
		return -ENOBUFS;
	}

	bf = list_entry(sc->txbuf.next, struct ath5k_buf, list);
	list_del(&bf->list);
	sc->txbuf_len--;

	bf->iob = iob;

	if ((rc = ath5k_txbuf_setup(sc, bf)) != 0) {
		bf->iob = NULL;
		list_add_tail(&bf->list, &sc->txbuf);
		sc->txbuf_len++;
		return rc;
	}
	return 0;
}

/*
 * Reset the hardware.  If chan is not NULL, then also pause rx/tx
 * and change to the given channel.
 */
static int
ath5k_reset(struct ath5k_softc *sc, struct net80211_channel *chan)
{
	struct ath5k_hw *ah = sc->ah;
	int ret;

	if (chan) {
		ath5k_hw_set_imr(ah, 0);
		ath5k_txq_cleanup(sc);
		ath5k_rx_stop(sc);

		sc->curchan = chan;
		sc->curband = chan->band;
	}

	ret = ath5k_hw_reset(ah, sc->curchan, 1);
	if (ret) {
		DBG("ath5k: can't reset hardware: %s\n", strerror(ret));
		return ret;
	}

	ret = ath5k_rx_start(sc);
	if (ret) {
		DBG("ath5k: can't start rx logic: %s\n", strerror(ret));
		return ret;
	}

	/*
	 * Change channels and update the h/w rate map if we're switching;
	 * e.g. 11a to 11b/g.
	 *
	 * We may be doing a reset in response to an ioctl that changes the
	 * channel so update any state that might change as a result.
	 *
	 * XXX needed?
	 */
/*	ath5k_chan_change(sc, c); */

	/* Reenable interrupts if necessary */
	ath5k_irq(sc->dev, sc->irq_ena);

	return 0;
}

static int ath5k_reset_wake(struct ath5k_softc *sc)
{
	return ath5k_reset(sc, sc->curchan);
}

static int ath5k_start(struct net80211_device *dev)
{
	struct ath5k_softc *sc = dev->priv;
	int ret;

	if ((ret = ath5k_init(sc)) != 0)
		return ret;

	sc->assoc = 0;
	ath5k_configure_filter(sc);
	ath5k_hw_set_lladdr(sc->ah, dev->netdev->ll_addr);

	return 0;
}

static void ath5k_stop(struct net80211_device *dev)
{
	struct ath5k_softc *sc = dev->priv;
	u8 mac[ETH_ALEN] = {};

	ath5k_hw_set_lladdr(sc->ah, mac);

	ath5k_stop_hw(sc);
}

static int
ath5k_config(struct net80211_device *dev, int changed)
{
	struct ath5k_softc *sc = dev->priv;
	struct ath5k_hw *ah = sc->ah;
	struct net80211_channel *chan = &dev->channels[dev->channel];
	int ret;

	if (changed & NET80211_CFG_CHANNEL) {
		sc->power_level = chan->maxpower;
		if ((ret = ath5k_chan_set(sc, chan)) != 0)
			return ret;
	}

	if ((changed & NET80211_CFG_RATE) ||
	    (changed & NET80211_CFG_PHY_PARAMS)) {
		int spmbl = ATH5K_SPMBL_NO;
		u16 rate = dev->rates[dev->rate];
		u16 slowrate = dev->rates[dev->rtscts_rate];
		int i;

		if (dev->phy_flags & NET80211_PHY_USE_SHORT_PREAMBLE)
			spmbl = ATH5K_SPMBL_YES;

		for (i = 0; i < ATH5K_NR_RATES; i++) {
			if (ath5k_rates[i].bitrate == rate &&
			    (ath5k_rates[i].short_pmbl & spmbl))
				sc->hw_rate = ath5k_rates[i].hw_code;

			if (ath5k_rates[i].bitrate == slowrate &&
			    (ath5k_rates[i].short_pmbl & spmbl))
				sc->hw_rtscts_rate = ath5k_rates[i].hw_code;
		}
	}

	if (changed & NET80211_CFG_ASSOC) {
		sc->assoc = !!(dev->state & NET80211_ASSOCIATED);
		if (sc->assoc) {
			memcpy(ah->ah_bssid, dev->bssid, ETH_ALEN);
		} else {
			memset(ah->ah_bssid, 0xff, ETH_ALEN);
		}
		ath5k_hw_set_associd(ah, ah->ah_bssid, 0);
	}

	return 0;
}

/*
 * o always accept unicast, broadcast, and multicast traffic
 * o multicast traffic for all BSSIDs will be enabled if mac80211
 *   says it should be
 * o maintain current state of phy ofdm or phy cck error reception.
 *   If the hardware detects any of these type of errors then
 *   ath5k_hw_get_rx_filter() will pass to us the respective
 *   hardware filters to be able to receive these type of frames.
 * o probe request frames are accepted only when operating in
 *   hostap, adhoc, or monitor modes
 * o enable promiscuous mode according to the interface state
 * o accept beacons:
 *   - when operating in adhoc mode so the 802.11 layer creates
 *     node table entries for peers,
 *   - when operating in station mode for collecting rssi data when
 *     the station is otherwise quiet, or
 *   - when scanning
 */
static void ath5k_configure_filter(struct ath5k_softc *sc)
{
	struct ath5k_hw *ah = sc->ah;
	u32 mfilt[2], rfilt;

	/* Enable all multicast */
	mfilt[0] = ~0;
	mfilt[1] = ~0;

	/* Enable data frames and beacons */
	rfilt = (AR5K_RX_FILTER_UCAST | AR5K_RX_FILTER_BCAST |
		 AR5K_RX_FILTER_MCAST | AR5K_RX_FILTER_BEACON);

	/* Set filters */
	ath5k_hw_set_rx_filter(ah, rfilt);

	/* Set multicast bits */
	ath5k_hw_set_mcast_filter(ah, mfilt[0], mfilt[1]);

	/* Set the cached hw filter flags, this will alter actually
	 * be set in HW */
	sc->filter_flags = rfilt;
}
