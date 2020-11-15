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

#include <ipxe/io.h>

#include "ath9k.h"
#include "ar9003_mac.h"

/*
 * Setup and link descriptors.
 *
 * 11N: we can no longer afford to self link the last descriptor.
 * MAC acknowledges BA status as long as it copies frames to host
 * buffer (or rx fifo). This can incorrectly acknowledge packets
 * to a sender if last desc is self-linked.
 */
static void ath_rx_buf_link(struct ath_softc *sc, struct ath_buf *bf)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	struct ath_desc *ds;
//	struct io_buffer *iob;

	ATH_RXBUF_RESET(bf);

	ds = bf->bf_desc;
	ds->ds_link = 0; /* link to null */
	ds->ds_data = bf->bf_buf_addr;

//	/* virtual addr of the beginning of the buffer. */
//	iob = bf->bf_mpdu;
//	ds->ds_vdata = iob->data;

	/*
	 * setup rx descriptors. The rx_bufsize here tells the hardware
	 * how much data it can DMA to us and that we are prepared
	 * to process
	 */
	ath9k_hw_setuprxdesc(ah, ds,
			     common->rx_bufsize,
			     0);

	if (sc->rx.rxlink == NULL)
		ath9k_hw_putrxbuf(ah, bf->bf_daddr);
	else
		*sc->rx.rxlink = bf->bf_daddr;

	sc->rx.rxlink = &ds->ds_link;
}

static void ath_setdefantenna(struct ath_softc *sc, u32 antenna)
{
	/* XXX block beacon interrupts */
	ath9k_hw_setantenna(sc->sc_ah, antenna);
	sc->rx.defant = antenna;
	sc->rx.rxotherant = 0;
}

static void ath_opmode_init(struct ath_softc *sc)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);

	u32 rfilt, mfilt[2];

	/* configure rx filter */
	rfilt = ath_calcrxfilter(sc);
	ath9k_hw_setrxfilter(ah, rfilt);

	/* configure bssid mask */
	ath_hw_setbssidmask(common);

	/* configure operational mode */
	ath9k_hw_setopmode(ah);

	/* calculate and install multicast filter */
	mfilt[0] = mfilt[1] = ~0;
	ath9k_hw_setmcastfilter(ah, mfilt[0], mfilt[1]);
}

int ath_rx_init(struct ath_softc *sc, int nbufs)
{
	struct ath_common *common = ath9k_hw_common(sc->sc_ah);
	struct io_buffer *iob;
	u32 *iob_addr = NULL;
	struct ath_buf *bf;
	int error = 0;

	sc->sc_flags &= ~SC_OP_RXFLUSH;

	common->rx_bufsize = IEEE80211_MAX_MPDU_LEN / 2 +
			     sc->sc_ah->caps.rx_status_len;

	DBG2("ath9k: cachelsz %d rxbufsize %d\n",
		common->cachelsz, common->rx_bufsize);

	/* Initialize rx descriptors */

	error = ath_descdma_setup(sc, &sc->rx.rxdma, &sc->rx.rxbuf,
			"rx", nbufs, 1, 0);
	if (error != 0) {
		DBG("ath9k: "
			"failed to allocate rx descriptors: %d\n",
			error);
		goto err;
	}

	list_for_each_entry(bf, &sc->rx.rxbuf, list) {
		iob = ath_rxbuf_alloc(common, common->rx_bufsize,
				      iob_addr);
		if (iob == NULL) {
			error = -ENOMEM;
			goto err;
		}

		bf->bf_mpdu = iob;
		bf->bf_buf_addr = *iob_addr;
	}
	sc->rx.rxlink = NULL;

err:
	if (error)
		ath_rx_cleanup(sc);

	return error;
}

void ath_rx_cleanup(struct ath_softc *sc)
{
	struct io_buffer *iob;
	struct ath_buf *bf;

	list_for_each_entry(bf, &sc->rx.rxbuf, list) {
		iob = bf->bf_mpdu;
		if (iob) {
			free_iob(iob);
			bf->bf_buf_addr = 0;
			bf->bf_mpdu = NULL;
		}
	}

	if (sc->rx.rxdma.dd_desc_len != 0)
		ath_descdma_cleanup(sc, &sc->rx.rxdma, &sc->rx.rxbuf);
}

/*
 * Calculate the receive filter according to the
 * operating mode and state:
 *
 * o always accept unicast, broadcast, and multicast traffic
 * o maintain current state of phy error reception (the hal
 *   may enable phy error frames for noise immunity work)
 * o probe request frames are accepted only when operating in
 *   hostap, adhoc, or monitor modes
 * o enable promiscuous mode according to the interface state
 * o accept beacons:
 *   - when operating in adhoc mode so the 802.11 layer creates
 *     node table entries for peers,
 *   - when operating in station mode for collecting rssi data when
 *     the station is otherwise quiet, or
 *   - when operating as a repeater so we see repeater-sta beacons
 *   - when scanning
 */

u32 ath_calcrxfilter(struct ath_softc *sc)
{
#define	RX_FILTER_PRESERVE (ATH9K_RX_FILTER_PHYERR | ATH9K_RX_FILTER_PHYRADAR)

	u32 rfilt;

	rfilt = (ath9k_hw_getrxfilter(sc->sc_ah) & RX_FILTER_PRESERVE)
		| ATH9K_RX_FILTER_UCAST | ATH9K_RX_FILTER_BCAST
		| ATH9K_RX_FILTER_MCAST | ATH9K_RX_FILTER_BEACON;

	return rfilt;

#undef RX_FILTER_PRESERVE
}

int ath_startrecv(struct ath_softc *sc)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_buf *bf, *tbf;

	if (list_empty(&sc->rx.rxbuf))
		goto start_recv;

	sc->rx.rxlink = NULL;
	list_for_each_entry_safe(bf, tbf, &sc->rx.rxbuf, list) {
		ath_rx_buf_link(sc, bf);
	}

	/* We could have deleted elements so the list may be empty now */
	if (list_empty(&sc->rx.rxbuf))
		goto start_recv;

	bf = list_first_entry(&sc->rx.rxbuf, struct ath_buf, list);
	ath9k_hw_putrxbuf(ah, bf->bf_daddr);
	ath9k_hw_rxena(ah);

start_recv:
	ath_opmode_init(sc);
	ath9k_hw_startpcureceive(ah, (sc->sc_flags & SC_OP_OFFCHANNEL));

	return 0;
}

int ath_stoprecv(struct ath_softc *sc)
{
	struct ath_hw *ah = sc->sc_ah;
	int stopped, reset = 0;

	ath9k_hw_abortpcurecv(ah);
	ath9k_hw_setrxfilter(ah, 0);
	stopped = ath9k_hw_stopdmarecv(ah, &reset);

	sc->rx.rxlink = NULL;

	if (!(ah->ah_flags & AH_UNPLUGGED) &&
	    !stopped) {
		DBG("ath9k: "
			"Could not stop RX, we could be "
			"confusing the DMA engine when we start RX up\n");
	}
	return stopped && !reset;
}

void ath_flushrecv(struct ath_softc *sc)
{
	sc->sc_flags |= SC_OP_RXFLUSH;
	ath_rx_tasklet(sc, 1, 0);
	sc->sc_flags &= ~SC_OP_RXFLUSH;
}

static struct ath_buf *ath_get_next_rx_buf(struct ath_softc *sc,
					   struct ath_rx_status *rs)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_desc *ds;
	struct ath_buf *bf;
	int ret;

	if (list_empty(&sc->rx.rxbuf)) {
		sc->rx.rxlink = NULL;
		return NULL;
	}

	bf = list_first_entry(&sc->rx.rxbuf, struct ath_buf, list);
	ds = bf->bf_desc;

	/*
	 * Must provide the virtual address of the current
	 * descriptor, the physical address, and the virtual
	 * address of the next descriptor in the h/w chain.
	 * This allows the HAL to look ahead to see if the
	 * hardware is done with a descriptor by checking the
	 * done bit in the following descriptor and the address
	 * of the current descriptor the DMA engine is working
	 * on.  All this is necessary because of our use of
	 * a self-linked list to avoid rx overruns.
	 */
	ret = ath9k_hw_rxprocdesc(ah, ds, rs, 0);
	if (ret == -EINPROGRESS) {
		struct ath_rx_status trs;
		struct ath_buf *tbf;
		struct ath_desc *tds;

		memset(&trs, 0, sizeof(trs));
		if ((&bf->list)->next == &sc->rx.rxbuf) {
			sc->rx.rxlink = NULL;
			return NULL;
		}

		tbf = list_entry(bf->list.next, struct ath_buf, list);

		/*
		 * On some hardware the descriptor status words could
		 * get corrupted, including the done bit. Because of
		 * this, check if the next descriptor's done bit is
		 * set or not.
		 *
		 * If the next descriptor's done bit is set, the current
		 * descriptor has been corrupted. Force s/w to discard
		 * this descriptor and continue...
		 */

		tds = tbf->bf_desc;
		ret = ath9k_hw_rxprocdesc(ah, tds, &trs, 0);
		if (ret == -EINPROGRESS)
			return NULL;
	}

	if (!bf->bf_mpdu)
		return bf;

	return bf;
}

/* Assumes you've already done the endian to CPU conversion */
static int ath9k_rx_accept(struct ath_common *common,
			    struct ath_rx_status *rx_stats,
			    int *decrypt_error)
{
	struct ath_hw *ah = common->ah;
	u8 rx_status_len = ah->caps.rx_status_len;


	if (!rx_stats->rs_datalen)
		return 0;
        /*
         * rs_status follows rs_datalen so if rs_datalen is too large
         * we can take a hint that hardware corrupted it, so ignore
         * those frames.
         */
	if (rx_stats->rs_datalen > (common->rx_bufsize - rx_status_len))
		return 0;

	/* Only use error bits from the last fragment */
	if (rx_stats->rs_more)
		return 1;

	/*
	 * The rx_stats->rs_status will not be set until the end of the
	 * chained descriptors so it can be ignored if rs_more is set. The
	 * rs_more will be false at the last element of the chained
	 * descriptors.
	 */
	if (rx_stats->rs_status != 0) {
		if (rx_stats->rs_status & ATH9K_RXERR_PHY)
			return 0;

		if (rx_stats->rs_status & ATH9K_RXERR_DECRYPT) {
			*decrypt_error = 1;
		}
		/*
		 * Reject error frames with the exception of
		 * decryption and MIC failures. For monitor mode,
		 * we also ignore the CRC error.
		 */
		if (ah->is_monitoring) {
			if (rx_stats->rs_status &
			    ~(ATH9K_RXERR_DECRYPT | ATH9K_RXERR_MIC |
			      ATH9K_RXERR_CRC))
				return 0;
		} else {
			if (rx_stats->rs_status &
			    ~(ATH9K_RXERR_DECRYPT | ATH9K_RXERR_MIC)) {
				return 0;
			}
		}
	}
	return 1;
}

static int ath9k_process_rate(struct ath_common *common __unused,
			      struct net80211_device *dev,
			      struct ath_rx_status *rx_stats,
			      int *rix)
{
	struct ath_softc *sc = (struct ath_softc *)dev->priv;
	int band;
	int i = 0;

	band = (dev->channels + sc->dev->channel)->band;

	for (i = 0; i < sc->hwinfo->nr_rates[band]; i++) {
		if (sc->rates[i].hw_value == rx_stats->rs_rate) {
			*rix = i;
			return 0;
		}
		if (sc->rates[i].hw_value_short == rx_stats->rs_rate) {
			*rix = i;
			return 0;
		}
	}

	/*
	 * No valid hardware bitrate found -- we should not get here
	 * because hardware has already validated this frame as OK.
	 */
	DBG("ath9k: "
		"unsupported hw bitrate detected 0x%02x using 1 Mbit\n",
		rx_stats->rs_rate);

	return -EINVAL;
}

/*
 * For Decrypt or Demic errors, we only mark packet status here and always push
 * up the frame up to let mac80211 handle the actual error case, be it no
 * decryption key or real decryption error. This let us keep statistics there.
 */
static int ath9k_rx_iob_preprocess(struct ath_common *common,
				   struct net80211_device *dev,
				   struct ath_rx_status *rx_stats,
				   int *rix,
				   int *decrypt_error)
{
	/*
	 * everything but the rate is checked here, the rate check is done
	 * separately to avoid doing two lookups for a rate for each frame.
	 */
	if (!ath9k_rx_accept(common, rx_stats, decrypt_error))
		return -EINVAL;

	/* Only use status info from the last fragment */
	if (rx_stats->rs_more)
		return 0;

	if (ath9k_process_rate(common, dev, rx_stats, rix))
		return -EINVAL;

	return 0;
}

int ath_rx_tasklet(struct ath_softc *sc, int flush, int hp __unused)
{
	struct ath_buf *bf;
	struct io_buffer *iob = NULL, *requeue_iob;
	u32 *requeue_iob_addr = NULL;
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	/*
	 * The hw can technically differ from common->hw when using ath9k
	 * virtual wiphy so to account for that we iterate over the active
	 * wiphys and find the appropriate wiphy and therefore hw.
	 */
	struct net80211_device *dev = sc->dev;
	int retval;
	int decrypt_error = 0;
	struct ath_rx_status rs;
	int rix = 0;

	do {
		/* If handling rx interrupt and flush is in progress => exit */
		if ((sc->sc_flags & SC_OP_RXFLUSH) && (flush == 0))
			break;

		memset(&rs, 0, sizeof(rs));
		bf = ath_get_next_rx_buf(sc, &rs);

		if (!bf)
			break;

		iob = bf->bf_mpdu;
		if (!iob)
			continue;

		/*
		 * If we're asked to flush receive queue, directly
		 * chain it back at the queue without processing it.
		 */
		if (flush)
			goto requeue_drop_frag;

		retval = ath9k_rx_iob_preprocess(common, dev, &rs,
						 &rix, &decrypt_error);
		if (retval)
			goto requeue_drop_frag;

		/* Ensure we always have an iob to requeue once we are done
		 * processing the current buffer's iob */
		requeue_iob = ath_rxbuf_alloc(common, common->rx_bufsize, requeue_iob_addr);

		/* If there is no memory we ignore the current RX'd frame,
		 * tell hardware it can give us a new frame using the old
		 * iob and put it at the tail of the sc->rx.rxbuf list for
		 * processing. */
		if (!requeue_iob)
			goto requeue_drop_frag;

		iob_put(iob, rs.rs_datalen + ah->caps.rx_status_len);
		if (ah->caps.rx_status_len)
			iob_pull(iob, ah->caps.rx_status_len);

		/* We will now give hardware our shiny new allocated iob */
		bf->bf_mpdu = requeue_iob;
		bf->bf_buf_addr = *requeue_iob_addr;

		/*
		 * change the default rx antenna if rx diversity chooses the
		 * other antenna 3 times in a row.
		 */
		if (sc->rx.defant != rs.rs_antenna) {
			if (++sc->rx.rxotherant >= 3)
				ath_setdefantenna(sc, rs.rs_antenna);
		} else {
			sc->rx.rxotherant = 0;
		}

		DBGIO("ath9k: rx %d bytes, signal %d, bitrate %d, hw_value %d\n", rs.rs_datalen,
		                                rs.rs_rssi, sc->rates[rix].bitrate, rs.rs_rate);

		net80211_rx(dev, iob, rs.rs_rssi,
				sc->rates[rix].bitrate);

requeue_drop_frag:
		list_del(&bf->list);
		list_add_tail(&bf->list, &sc->rx.rxbuf);
		ath_rx_buf_link(sc, bf);
		ath9k_hw_rxena(ah);
	} while (1);

	return 0;
}
