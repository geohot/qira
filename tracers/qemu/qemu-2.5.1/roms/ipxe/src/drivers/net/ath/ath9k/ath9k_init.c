/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Modified for iPXE by Scott K Logan <logans@cottsay.net> July 2011
 * Original from Linux kernel 3.0.1
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

FILE_LICENCE ( BSD2 );

#include <ipxe/malloc.h>
#include <ipxe/pci_io.h>
#include <ipxe/pci.h>

#include "ath9k.h"

int is_ath9k_unloaded;
/* We use the hw_value as an index into our private channel structure */

#define CHAN2G(_freq, _idx)  { \
	.band = NET80211_BAND_2GHZ, \
	.center_freq = (_freq), \
	.hw_value = (_idx), \
	.maxpower = 20, \
}

#define CHAN5G(_freq, _idx) { \
	.band = NET80211_BAND_5GHZ, \
	.center_freq = (_freq), \
	.hw_value = (_idx), \
	.maxpower = 20, \
}

/* Some 2 GHz radios are actually tunable on 2312-2732
 * on 5 MHz steps, we support the channels which we know
 * we have calibration data for all cards though to make
 * this static */
static const struct net80211_channel ath9k_2ghz_chantable[] = {
	CHAN2G(2412, 0), /* Channel 1 */
	CHAN2G(2417, 1), /* Channel 2 */
	CHAN2G(2422, 2), /* Channel 3 */
	CHAN2G(2427, 3), /* Channel 4 */
	CHAN2G(2432, 4), /* Channel 5 */
	CHAN2G(2437, 5), /* Channel 6 */
	CHAN2G(2442, 6), /* Channel 7 */
	CHAN2G(2447, 7), /* Channel 8 */
	CHAN2G(2452, 8), /* Channel 9 */
	CHAN2G(2457, 9), /* Channel 10 */
	CHAN2G(2462, 10), /* Channel 11 */
	CHAN2G(2467, 11), /* Channel 12 */
	CHAN2G(2472, 12), /* Channel 13 */
	CHAN2G(2484, 13), /* Channel 14 */
};

/* Some 5 GHz radios are actually tunable on XXXX-YYYY
 * on 5 MHz steps, we support the channels which we know
 * we have calibration data for all cards though to make
 * this static */
static const struct net80211_channel ath9k_5ghz_chantable[] = {
	/* _We_ call this UNII 1 */
	CHAN5G(5180, 14), /* Channel 36 */
	CHAN5G(5200, 15), /* Channel 40 */
	CHAN5G(5220, 16), /* Channel 44 */
	CHAN5G(5240, 17), /* Channel 48 */
	/* _We_ call this UNII 2 */
	CHAN5G(5260, 18), /* Channel 52 */
	CHAN5G(5280, 19), /* Channel 56 */
	CHAN5G(5300, 20), /* Channel 60 */
	CHAN5G(5320, 21), /* Channel 64 */
	/* _We_ call this "Middle band" */
	CHAN5G(5500, 22), /* Channel 100 */
	CHAN5G(5520, 23), /* Channel 104 */
	CHAN5G(5540, 24), /* Channel 108 */
	CHAN5G(5560, 25), /* Channel 112 */
	CHAN5G(5580, 26), /* Channel 116 */
	CHAN5G(5600, 27), /* Channel 120 */
	CHAN5G(5620, 28), /* Channel 124 */
	CHAN5G(5640, 29), /* Channel 128 */
	CHAN5G(5660, 30), /* Channel 132 */
	CHAN5G(5680, 31), /* Channel 136 */
	CHAN5G(5700, 32), /* Channel 140 */
	/* _We_ call this UNII 3 */
	CHAN5G(5745, 33), /* Channel 149 */
	CHAN5G(5765, 34), /* Channel 153 */
	CHAN5G(5785, 35), /* Channel 157 */
	CHAN5G(5805, 36), /* Channel 161 */
	CHAN5G(5825, 37), /* Channel 165 */
};

/* Atheros hardware rate code addition for short premble */
#define SHPCHECK(__hw_rate, __flags) \
	((__flags & IEEE80211_TX_RC_USE_SHORT_PREAMBLE) ? (__hw_rate | 0x04 ) : 0)

#define RATE(_bitrate, _hw_rate, _flags) {              \
	.bitrate        = (_bitrate),                   \
	.flags          = (_flags),                     \
	.hw_value       = (_hw_rate),                   \
	.hw_value_short = (SHPCHECK(_hw_rate, _flags))  \
}

static struct ath9k_legacy_rate ath9k_legacy_rates[] = {
	RATE(10, 0x1b, 0),
	RATE(20, 0x1a, IEEE80211_TX_RC_USE_SHORT_PREAMBLE),
	RATE(55, 0x19, IEEE80211_TX_RC_USE_SHORT_PREAMBLE),
	RATE(110, 0x18, IEEE80211_TX_RC_USE_SHORT_PREAMBLE),
	RATE(60, 0x0b, 0),
	RATE(90, 0x0f, 0),
	RATE(120, 0x0a, 0),
	RATE(180, 0x0e, 0),
	RATE(240, 0x09, 0),
	RATE(360, 0x0d, 0),
	RATE(480, 0x08, 0),
	RATE(540, 0x0c, 0),
};

static void ath9k_deinit_softc(struct ath_softc *sc);

/*
 * Read and write, they both share the same lock. We do this to serialize
 * reads and writes on Atheros 802.11n PCI devices only. This is required
 * as the FIFO on these devices can only accept sanely 2 requests.
 */

static void ath9k_iowrite32(void *hw_priv, u32 val, u32 reg_offset)
{
	struct ath_hw *ah = (struct ath_hw *) hw_priv;
	struct ath_common *common = ath9k_hw_common(ah);
	struct ath_softc *sc = (struct ath_softc *) common->priv;

	writel(val, sc->mem + reg_offset);
}

static unsigned int ath9k_ioread32(void *hw_priv, u32 reg_offset)
{
	struct ath_hw *ah = (struct ath_hw *) hw_priv;
	struct ath_common *common = ath9k_hw_common(ah);
	struct ath_softc *sc = (struct ath_softc *) common->priv;
	u32 val;

	val = readl(sc->mem + reg_offset);
	return val;
}

static unsigned int ath9k_reg_rmw(void *hw_priv, u32 reg_offset, u32 set, u32 clr)
{
	struct ath_hw *ah = (struct ath_hw *) hw_priv;
	struct ath_common *common = ath9k_hw_common(ah);
	struct ath_softc *sc = (struct ath_softc *) common->priv;
	u32 val;

	val = readl(sc->mem + reg_offset);
	val &= ~clr;
	val |= set;
	writel(val, sc->mem + reg_offset);

	return val;
}

/**************************/
/*     Initialization     */
/**************************/

/*
 *  This function will allocate both the DMA descriptor structure, and the
 *  buffers it contains.  These are used to contain the descriptors used
 *  by the system.
*/
int ath_descdma_setup(struct ath_softc *sc, struct ath_descdma *dd,
		      struct list_head *head, const char *name,
		      int nbuf, int ndesc, int is_tx)
{
#define	DS2PHYS(_dd, _ds)						\
	((_dd)->dd_desc_paddr + ((char *)(_ds) - (char *)(_dd)->dd_desc))
#define ATH_DESC_4KB_BOUND_CHECK(_daddr) ((((_daddr) & 0xFFF) > 0xF9F) ? 1 : 0)
	u8 *ds;
	struct ath_buf *bf;
	int i, bsize, error, desc_len;

	DBG2("ath9k: %s DMA: %d buffers %d desc/buf\n",
		name, nbuf, ndesc);

	INIT_LIST_HEAD(head);

	if (is_tx)
		desc_len = sc->sc_ah->caps.tx_desc_len;
	else
		desc_len = sizeof(struct ath_desc);

	/* ath_desc must be a multiple of DWORDs */
	if ((desc_len % 4) != 0) {
		DBG("ath9k: ath_desc not DWORD aligned\n");
		error = -ENOMEM;
		goto fail;
	}

	dd->dd_desc_len = desc_len * nbuf * ndesc;

	/*
	 * Need additional DMA memory because we can't use
	 * descriptors that cross the 4K page boundary.
	 * However, iPXE only utilizes 16 buffers, which
	 * will never make up more than half of one page,
	 * so we will only ever skip 1 descriptor, if that.
	 */
	if (!(sc->sc_ah->caps.hw_caps & ATH9K_HW_CAP_4KB_SPLITTRANS)) {
		u32 ndesc_skipped = 1;
		u32 dma_len;

		dma_len = ndesc_skipped * desc_len;
		dd->dd_desc_len += dma_len;
	}

	/* allocate descriptors */
	dd->dd_desc = malloc_dma(dd->dd_desc_len, 16);
	if (dd->dd_desc == NULL) {
		error = -ENOMEM;
		goto fail;
	}
	dd->dd_desc_paddr = virt_to_bus(dd->dd_desc);
	ds = (u8 *) dd->dd_desc;
	DBG2("ath9k: %s DMA map: %p (%d) -> %llx (%d)\n",
		name, ds, (u32) dd->dd_desc_len,
		ito64(dd->dd_desc_paddr), /*XXX*/(u32) dd->dd_desc_len);

	/* allocate buffers */
	bsize = sizeof(struct ath_buf) * nbuf;
	bf = zalloc(bsize);
	if (bf == NULL) {
		error = -ENOMEM;
		goto fail2;
	}
	dd->dd_bufptr = bf;

	for (i = 0; i < nbuf; i++, bf++, ds += (desc_len * ndesc)) {
		bf->bf_desc = ds;
		bf->bf_daddr = DS2PHYS(dd, ds);

		if (!(sc->sc_ah->caps.hw_caps &
		      ATH9K_HW_CAP_4KB_SPLITTRANS)) {
			/*
			 * Skip descriptor addresses which can cause 4KB
			 * boundary crossing (addr + length) with a 32 dword
			 * descriptor fetch.
			 */
			while (ATH_DESC_4KB_BOUND_CHECK(bf->bf_daddr)) {
				ds += (desc_len * ndesc);
				bf->bf_desc = ds;
				bf->bf_daddr = DS2PHYS(dd, ds);
			}
		}
		list_add_tail(&bf->list, head);
	}
	return 0;
fail2:
	free_dma(dd->dd_desc, dd->dd_desc_len);
fail:
	memset(dd, 0, sizeof(*dd));
	return error;
#undef ATH_DESC_4KB_BOUND_CHECK
#undef DS2PHYS
}

void ath9k_init_crypto(struct ath_softc *sc)
{
	struct ath_common *common = ath9k_hw_common(sc->sc_ah);
	unsigned int i = 0;

	/* Get the hardware key cache size. */
	common->keymax = AR_KEYTABLE_SIZE;

	/*
	 * Reset the key cache since some parts do not
	 * reset the contents on initial power up.
	 */
	for (i = 0; i < common->keymax; i++)
		ath_hw_keyreset(common, (u16) i);

	/*
	 * Check whether the separate key cache entries
	 * are required to handle both tx+rx MIC keys.
	 * With split mic keys the number of stations is limited
	 * to 27 otherwise 59.
	 */
	if (sc->sc_ah->misc_mode & AR_PCU_MIC_NEW_LOC_ENA)
		common->crypt_caps |= ATH_CRYPT_CAP_MIC_COMBINED;
}

static int ath9k_init_queues(struct ath_softc *sc)
{
	int i = 0;

	for (i = 0; i < WME_NUM_AC; i++) {
		sc->tx.txq_map[i] = ath_txq_setup(sc, ATH9K_TX_QUEUE_DATA, i);
		sc->tx.txq_map[i]->mac80211_qnum = i;
	}
	return 0;
}

static int ath9k_init_channels_rates(struct ath_softc *sc)
{
	unsigned int i;

	memcpy(&sc->rates, ath9k_legacy_rates, sizeof(ath9k_legacy_rates));

	if (sc->sc_ah->caps.hw_caps & ATH9K_HW_CAP_2GHZ) {
		memcpy(&sc->hwinfo->channels[sc->hwinfo->nr_channels], ath9k_2ghz_chantable, sizeof(ath9k_2ghz_chantable));

		sc->hwinfo->nr_channels += ARRAY_SIZE(ath9k_2ghz_chantable);

		for (i = 0; i < ARRAY_SIZE(ath9k_legacy_rates); i++)
			sc->hwinfo->rates[NET80211_BAND_2GHZ][i] = ath9k_legacy_rates[i].bitrate;
		sc->hwinfo->nr_rates[NET80211_BAND_2GHZ] = ARRAY_SIZE(ath9k_legacy_rates);
	}

	if (sc->sc_ah->caps.hw_caps & ATH9K_HW_CAP_5GHZ) {
		memcpy(&sc->hwinfo->channels[sc->hwinfo->nr_channels], ath9k_5ghz_chantable, sizeof(ath9k_5ghz_chantable));

		sc->hwinfo->nr_channels += ARRAY_SIZE(ath9k_5ghz_chantable);

		for (i = 4; i < ARRAY_SIZE(ath9k_legacy_rates); i++)
			sc->hwinfo->rates[NET80211_BAND_5GHZ][i - 4] = ath9k_legacy_rates[i].bitrate;
		sc->hwinfo->nr_rates[NET80211_BAND_5GHZ] = ARRAY_SIZE(ath9k_legacy_rates) - 4;
	}
	return 0;
}

static void ath9k_init_misc(struct ath_softc *sc)
{
	struct ath_common *common = ath9k_hw_common(sc->sc_ah);

	common->ani.timer = 0;

	sc->config.txpowlimit = ATH_TXPOWER_MAX;

	common->tx_chainmask = sc->sc_ah->caps.tx_chainmask;
	common->rx_chainmask = sc->sc_ah->caps.rx_chainmask;

	ath9k_hw_set_diversity(sc->sc_ah, 1);
	sc->rx.defant = ath9k_hw_getdefantenna(sc->sc_ah);

	memcpy(common->bssidmask, ath_bcast_mac, ETH_ALEN);
}

static int ath9k_init_softc(u16 devid, struct ath_softc *sc, u16 subsysid,
			    const struct ath_bus_ops *bus_ops)
{
	struct ath_hw *ah = NULL;
	struct ath_common *common;
	int ret = 0, i;
	int csz = 0;

	ah = zalloc(sizeof(struct ath_hw));
	if (!ah)
		return -ENOMEM;

	ah->dev = sc->dev;
	ah->hw_version.devid = devid;
	ah->hw_version.subsysid = subsysid;
	ah->reg_ops.read = ath9k_ioread32;
	ah->reg_ops.write = ath9k_iowrite32;
	ah->reg_ops.rmw = ath9k_reg_rmw;
	sc->sc_ah = ah;

	sc->hwinfo = zalloc(sizeof(*sc->hwinfo));
	if (!sc->hwinfo) {
		DBG("ath9k: cannot allocate 802.11 hardware info structure\n");
		return -ENOMEM;
	}

	ah->ah_flags |= AH_USE_EEPROM;
	sc->sc_ah->led_pin = -1;

	common = ath9k_hw_common(ah);
	common->ops = &ah->reg_ops;
	common->bus_ops = bus_ops;
	common->ah = ah;
	common->dev = sc->dev;
	common->priv = sc;

	sc->intr_tq = ath9k_tasklet;

	/*
	 * Cache line size is used to size and align various
	 * structures used to communicate with the hardware.
	 */
	ath_read_cachesize(common, &csz);
	common->cachelsz = csz << 2; /* convert to bytes */

	/* Initializes the hardware for all supported chipsets */
	ret = ath9k_hw_init(ah);
	if (ret)
		goto err_hw;

	memcpy(sc->hwinfo->hwaddr, common->macaddr, ETH_ALEN);

	ret = ath9k_init_queues(sc);
	if (ret)
		goto err_queues;

	ret = ath9k_init_channels_rates(sc);
	if (ret)
		goto err_btcoex;

	ath9k_init_crypto(sc);
	ath9k_init_misc(sc);

	return 0;

err_btcoex:
	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++)
		if (ATH_TXQ_SETUP(sc, i))
			ath_tx_cleanupq(sc, &sc->tx.txq[i]);
err_queues:
	ath9k_hw_deinit(ah);
err_hw:
	free(sc->hwinfo);
	sc->hwinfo = NULL;

	free(ah);
	sc->sc_ah = NULL;

	return ret;
}

static void ath9k_init_band_txpower(struct ath_softc *sc, int band)
{
	struct net80211_channel *chan;
	struct ath_hw *ah = sc->sc_ah;
	struct ath_regulatory *reg = ath9k_hw_regulatory(ah);
	int i;

	for (i = 0; i < sc->hwinfo->nr_channels; i++) {
		chan = &sc->hwinfo->channels[i];
		if(chan->band != band)
			continue;
		ah->curchan = &ah->channels[chan->hw_value];
		ath9k_hw_set_txpowerlimit(ah, MAX_RATE_POWER, 1);
		chan->maxpower = reg->max_power_level / 2;
	}
}

static void ath9k_init_txpower_limits(struct ath_softc *sc)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath9k_channel *curchan = ah->curchan;

	if (ah->caps.hw_caps & ATH9K_HW_CAP_2GHZ)
		ath9k_init_band_txpower(sc, NET80211_BAND_2GHZ);
	if (ah->caps.hw_caps & ATH9K_HW_CAP_5GHZ)
		ath9k_init_band_txpower(sc, NET80211_BAND_5GHZ);

	ah->curchan = curchan;
}

void ath9k_set_hw_capab(struct ath_softc *sc, struct net80211_device *dev __unused)
{
	sc->hwinfo->flags = NET80211_HW_RX_HAS_FCS;
	sc->hwinfo->signal_type = NET80211_SIGNAL_DB;
	sc->hwinfo->signal_max = 40; /* 35dB should give perfect 54Mbps */
	sc->hwinfo->channel_change_time = 5000;

	if (sc->sc_ah->caps.hw_caps & ATH9K_HW_CAP_2GHZ)
	{
		sc->hwinfo->bands |= NET80211_BAND_BIT_2GHZ;
		sc->hwinfo->modes |= NET80211_MODE_B | NET80211_MODE_G;
	}
	if (sc->sc_ah->caps.hw_caps & ATH9K_HW_CAP_5GHZ)
	{
		sc->hwinfo->bands |= NET80211_BAND_BIT_5GHZ;
		sc->hwinfo->modes |= NET80211_MODE_A;
	}
}

int ath9k_init_device(u16 devid, struct ath_softc *sc, u16 subsysid,
		    const struct ath_bus_ops *bus_ops)
{
	struct net80211_device *dev = sc->dev;
	/*struct ath_common *common;
	struct ath_hw *ah;*/
	int error = 0;
	/*struct ath_regulatory *reg;*/

	/* Bring up device */
	error = ath9k_init_softc(devid, sc, subsysid, bus_ops);
	if (error != 0)
		goto error_init;

	/*ah = sc->sc_ah;
	common = ath9k_hw_common(ah);*/
	ath9k_set_hw_capab(sc, dev);
	/* TODO Cottsay: reg */
	/* Initialize regulatory */
	/*error = ath_regd_init(&common->regulatory, sc->dev->wiphy,
			      ath9k_reg_notifier);
	if (error)
		goto error_regd;

	reg = &common->regulatory;*/

	/* Setup TX DMA */
	error = ath_tx_init(sc, ATH_TXBUF);
	if (error != 0)
		goto error_tx;

	/* Setup RX DMA */
	error = ath_rx_init(sc, ATH_RXBUF);
	if (error != 0)
		goto error_rx;

	ath9k_init_txpower_limits(sc);

	/* Register with mac80211 */
	error = net80211_register(dev, &ath9k_ops, sc->hwinfo);
	if (error)
		goto error_register;

	/* TODO Cottsay: reg */
	/* Handle world regulatory */
	/*if (!ath_is_world_regd(reg)) {
		error = regulatory_hint(hw->wiphy, reg->alpha2);
		if (error)
			goto error_world;
	}*/

	sc->hw_pll_work = ath_hw_pll_work;
	sc->last_rssi = ATH_RSSI_DUMMY_MARKER;

	/* TODO Cottsay: rfkill */
	/*ath_start_rfkill_poll(sc);*/

	return 0;

//error_world:
//	net80211_unregister(dev);
error_register:
	ath_rx_cleanup(sc);
error_rx:
	ath_tx_cleanup(sc);
error_tx:
	ath9k_deinit_softc(sc);
error_init:
	return error;
}

/*****************************/
/*     De-Initialization     */
/*****************************/

static void ath9k_deinit_softc(struct ath_softc *sc)
{
	int i = 0;

	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++)
		if (ATH_TXQ_SETUP(sc, i))
			ath_tx_cleanupq(sc, &sc->tx.txq[i]);

	ath9k_hw_deinit(sc->sc_ah);

	free(sc->hwinfo);
	sc->hwinfo = NULL;
	free(sc->sc_ah);
	sc->sc_ah = NULL;
}

void ath9k_deinit_device(struct ath_softc *sc)
{
	struct net80211_device *dev = sc->dev;

	net80211_unregister(dev);
	ath_rx_cleanup(sc);
	ath_tx_cleanup(sc);
	ath9k_deinit_softc(sc);
}

void ath_descdma_cleanup(struct ath_softc *sc __unused,
			 struct ath_descdma *dd,
			 struct list_head *head)
{
	free_dma(dd->dd_desc, dd->dd_desc_len);

	INIT_LIST_HEAD(head);
	free(dd->dd_bufptr);
	memset(dd, 0, sizeof(*dd));
}
