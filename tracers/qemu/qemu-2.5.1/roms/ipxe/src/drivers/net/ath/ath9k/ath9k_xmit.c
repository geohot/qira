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

#define BITS_PER_BYTE           8
#define OFDM_PLCP_BITS          22
#define HT_RC_2_STREAMS(_rc)    ((((_rc) & 0x78) >> 3) + 1)
#define L_STF                   8
#define L_LTF                   8
#define L_SIG                   4
#define HT_SIG                  8
#define HT_STF                  4
#define HT_LTF(_ns)             (4 * (_ns))
#define SYMBOL_TIME(_ns)        ((_ns) << 2) /* ns * 4 us */
#define SYMBOL_TIME_HALFGI(_ns) (((_ns) * 18 + 4) / 5)  /* ns * 3.6 us */
#define NUM_SYMBOLS_PER_USEC(_usec) (_usec >> 2)
#define NUM_SYMBOLS_PER_USEC_HALFGI(_usec) (((_usec*5)-4)/18)


#define IS_HT_RATE(_rate)     ((_rate) & 0x80)

static void ath_tx_send_normal(struct ath_softc *sc, struct ath_txq *txq,
			       struct ath_atx_tid *tid,
			       struct list_head *bf_head);
static void ath_tx_complete_buf(struct ath_softc *sc, struct ath_buf *bf,
				struct ath_txq *txq, struct list_head *bf_q,
				struct ath_tx_status *ts, int txok, int sendbar);
static void ath_tx_txqaddbuf(struct ath_softc *sc, struct ath_txq *txq,
			     struct list_head *head);
static void ath_buf_set_rate(struct ath_softc *sc, struct ath_buf *bf, int len);

enum {
	MCS_HT20,
	MCS_HT20_SGI,
	MCS_HT40,
	MCS_HT40_SGI,
};

/*********************/
/* Aggregation logic */
/*********************/

static void ath_tx_queue_tid(struct ath_txq *txq, struct ath_atx_tid *tid)
{
	struct ath_atx_ac *ac = tid->ac;

	if (tid->paused)
		return;

	if (tid->sched)
		return;

	tid->sched = 1;
	list_add_tail(&tid->list, &ac->tid_q);

	if (ac->sched)
		return;

	ac->sched = 1;
	list_add_tail(&ac->list, &txq->axq_acq);
}

static struct ath_buf *ath_tx_get_buffer(struct ath_softc *sc)
{
	struct ath_buf *bf = NULL;

	if (list_empty(&sc->tx.txbuf)) {
		return NULL;
	}

	bf = list_first_entry(&sc->tx.txbuf, struct ath_buf, list);
	list_del(&bf->list);

	return bf;
}

static void ath_tx_return_buffer(struct ath_softc *sc, struct ath_buf *bf)
{
	list_add_tail(&bf->list, &sc->tx.txbuf);
}

/********************/
/* Queue Management */
/********************/

struct ath_txq *ath_txq_setup(struct ath_softc *sc, int qtype, int subtype)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath9k_tx_queue_info qi;
	static const int subtype_txq_to_hwq[] = {
		[WME_AC_BE] = ATH_TXQ_AC_BE,
	};
	int axq_qnum, i;

	memset(&qi, 0, sizeof(qi));
	qi.tqi_subtype = subtype_txq_to_hwq[subtype];
	qi.tqi_aifs = ATH9K_TXQ_USEDEFAULT;
	qi.tqi_cwmin = ATH9K_TXQ_USEDEFAULT;
	qi.tqi_cwmax = ATH9K_TXQ_USEDEFAULT;
	qi.tqi_physCompBuf = 0;

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
	 *
	 * The UAPSD queue is an exception, since we take a desc-
	 * based intr on the EOSP frames.
	 */
	qi.tqi_qflags = TXQ_FLAG_TXEOLINT_ENABLE |
			TXQ_FLAG_TXDESCINT_ENABLE;

	axq_qnum = ath9k_hw_setuptxqueue(ah, qtype, &qi);
	if (axq_qnum == -1) {
		/*
		 * NB: don't print a message, this happens
		 * normally on parts with too few tx queues
		 */
		return NULL;
	}
	if ((unsigned int)axq_qnum >= ARRAY_SIZE(sc->tx.txq)) {
		DBG("ath9k: qnum %d out of range, max %zd!\n",
			axq_qnum, ARRAY_SIZE(sc->tx.txq));
		ath9k_hw_releasetxqueue(ah, axq_qnum);
		return NULL;
	}
	if (!ATH_TXQ_SETUP(sc, axq_qnum)) {
		struct ath_txq *txq = &sc->tx.txq[axq_qnum];

		txq->axq_qnum = axq_qnum;
		txq->mac80211_qnum = -1;
		txq->axq_link = NULL;
		INIT_LIST_HEAD(&txq->axq_q);
		INIT_LIST_HEAD(&txq->axq_acq);
		txq->axq_depth = 0;
		txq->axq_ampdu_depth = 0;
		txq->axq_tx_inprogress = 0;
		sc->tx.txqsetup |= 1<<axq_qnum;

		txq->txq_headidx = txq->txq_tailidx = 0;
		for (i = 0; i < ATH_TXFIFO_DEPTH; i++)
			INIT_LIST_HEAD(&txq->txq_fifo[i]);
		INIT_LIST_HEAD(&txq->txq_fifo_pending);
	}
	return &sc->tx.txq[axq_qnum];
}

/*
 * Drain a given TX queue (could be Beacon or Data)
 *
 * This assumes output has been stopped and
 * we do not need to block ath_tx_tasklet.
 */
void ath_draintxq(struct ath_softc *sc, struct ath_txq *txq, int retry_tx __unused)
{
	struct ath_buf *bf, *lastbf __unused;
	struct list_head bf_head;
	struct ath_tx_status ts;

	memset(&ts, 0, sizeof(ts));
	INIT_LIST_HEAD(&bf_head);

	for (;;) {
		if (list_empty(&txq->axq_q)) {
			txq->axq_link = NULL;
			break;
		}
		bf = list_first_entry(&txq->axq_q, struct ath_buf,
				      list);

		if (bf->bf_stale) {
			list_del(&bf->list);

			ath_tx_return_buffer(sc, bf);
			continue;
		}

		lastbf = bf->bf_lastbf;

		list_cut_position(&bf_head, &txq->axq_q, &lastbf->list);

		txq->axq_depth--;
		ath_tx_complete_buf(sc, bf, txq, &bf_head, &ts, 0, 0);
	}

	txq->axq_tx_inprogress = 0;
}

int ath_drain_all_txq(struct ath_softc *sc, int retry_tx)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_txq *txq;
	int i, npend = 0;

	if (sc->sc_flags & SC_OP_INVALID)
		return 1;

	ath9k_hw_abort_tx_dma(ah);

	/* Check if any queue remains active */
	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (!ATH_TXQ_SETUP(sc, i))
			continue;

		npend += ath9k_hw_numtxpending(ah, sc->tx.txq[i].axq_qnum);
	}

	if (npend)
		DBG("ath9k: Failed to stop TX DMA!\n");

	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (!ATH_TXQ_SETUP(sc, i))
			continue;

		/*
		 * The caller will resume queues with ieee80211_wake_queues.
		 * Mark the queue as not stopped to prevent ath_tx_complete
		 * from waking the queue too early.
		 */
		txq = &sc->tx.txq[i];
		txq->stopped = 0;
		ath_draintxq(sc, txq, retry_tx);
	}

	return !npend;
}

void ath_tx_cleanupq(struct ath_softc *sc, struct ath_txq *txq)
{
	ath9k_hw_releasetxqueue(sc->sc_ah, txq->axq_qnum);
	sc->tx.txqsetup &= ~(1<<txq->axq_qnum);
}

/* For each axq_acq entry, for each tid, try to schedule packets
 * for transmit until ampdu_depth has reached min Q depth.
 */
void ath_txq_schedule(struct ath_softc *sc __unused, struct ath_txq *txq)
{
	struct ath_atx_ac *ac, *ac_tmp, *last_ac;
	struct ath_atx_tid *tid, *last_tid;

	if (list_empty(&txq->axq_acq) ||
	    txq->axq_ampdu_depth >= ATH_AGGR_MIN_QDEPTH)
		return;

	ac = list_first_entry(&txq->axq_acq, struct ath_atx_ac, list);
	last_ac = list_entry(txq->axq_acq.prev, struct ath_atx_ac, list);

	list_for_each_entry_safe(ac, ac_tmp, &txq->axq_acq, list) {
		last_tid = list_entry(ac->tid_q.prev, struct ath_atx_tid, list);
		list_del(&ac->list);
		ac->sched = 0;

		while (!list_empty(&ac->tid_q)) {
			tid = list_first_entry(&ac->tid_q, struct ath_atx_tid,
					       list);
			list_del(&tid->list);
			tid->sched = 0;

			if (tid->paused)
				continue;

			/*
			 * add tid to round-robin queue if more frames
			 * are pending for the tid
			 */
			if (!list_empty(&tid->buf_q))
				ath_tx_queue_tid(txq, tid);

			if (tid == last_tid ||
			    txq->axq_ampdu_depth >= ATH_AGGR_MIN_QDEPTH)
				break;
		}

		if (!list_empty(&ac->tid_q)) {
			if (!ac->sched) {
				ac->sched = 1;
				list_add_tail(&ac->list, &txq->axq_acq);
			}
		}

		if (ac == last_ac ||
		    txq->axq_ampdu_depth >= ATH_AGGR_MIN_QDEPTH)
			return;
	}
}

/***********/
/* TX, DMA */
/***********/

/*
 * Insert a chain of ath_buf (descriptors) on a txq and
 * assume the descriptors are already chained together by caller.
 */
static void ath_tx_txqaddbuf(struct ath_softc *sc, struct ath_txq *txq,
			     struct list_head *head)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_buf *bf;

	/*
	 * Insert the frame on the outbound list and
	 * pass it on to the hardware.
	 */

	if (list_empty(head))
		return;

	bf = list_first_entry(head, struct ath_buf, list);

	DBGIO("ath9k: "
		"qnum: %d, txq depth: %d\n", txq->axq_qnum, txq->axq_depth);

	list_splice_tail_init(head, &txq->axq_q);

	if (txq->axq_link == NULL) {
		ath9k_hw_puttxbuf(ah, txq->axq_qnum, bf->bf_daddr);
		DBGIO("ath9k: TXDP[%d] = %llx (%p)\n",
			txq->axq_qnum, ito64(bf->bf_daddr),
			bf->bf_desc);
	} else {
		*txq->axq_link = bf->bf_daddr;
		DBGIO("ath9k: "
			"link[%d] (%p)=%llx (%p)\n",
			txq->axq_qnum, txq->axq_link,
			ito64(bf->bf_daddr), bf->bf_desc);
	}
	ath9k_hw_get_desc_link(ah, bf->bf_lastbf->bf_desc,
			       &txq->axq_link);
	ath9k_hw_txstart(ah, txq->axq_qnum);

	txq->axq_depth++;
}

static void ath_tx_send_normal(struct ath_softc *sc, struct ath_txq *txq,
			       struct ath_atx_tid *tid,
			       struct list_head *bf_head)
{
	struct ath_buf *bf;

	bf = list_first_entry(bf_head, struct ath_buf, list);
	bf->bf_state.bf_type &= ~BUF_AMPDU;

	/* update starting sequence number for subsequent ADDBA request */
	if (tid)
		INCR(tid->seq_start, IEEE80211_SEQ_MAX);

	bf->bf_lastbf = bf;
	ath_buf_set_rate(sc, bf, iob_len(bf->bf_mpdu) + FCS_LEN);
	ath_tx_txqaddbuf(sc, txq, bf_head);
}

static enum ath9k_pkt_type get_hw_packet_type(struct io_buffer *iob)
{
	struct ieee80211_frame *hdr;
	enum ath9k_pkt_type htype;
	u16 fc;

	hdr = (struct ieee80211_frame *)iob->data;
	fc = hdr->fc;

	if ((fc & (IEEE80211_FC_TYPE | IEEE80211_FC_SUBTYPE)) == (IEEE80211_TYPE_MGMT | IEEE80211_STYPE_BEACON))
		htype = ATH9K_PKT_TYPE_BEACON;
	else if ((fc & (IEEE80211_FC_TYPE | IEEE80211_FC_SUBTYPE)) == (IEEE80211_TYPE_MGMT | IEEE80211_STYPE_PROBE_RESP))
		htype = ATH9K_PKT_TYPE_PROBE_RESP;
	else
		htype = ATH9K_PKT_TYPE_NORMAL;

	return htype;
}

static int setup_tx_flags(struct io_buffer *iob __unused)
{
	int flags = 0;

	flags |= ATH9K_TXDESC_INTREQ;

	return flags;
}

u8 ath_txchainmask_reduction(struct ath_softc *sc, u8 chainmask, u32 rate)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath9k_channel *curchan = ah->curchan;
	if ((sc->sc_flags & SC_OP_ENABLE_APM) &&
			(curchan->channelFlags & CHANNEL_5GHZ) &&
			(chainmask == 0x7) && (rate < 0x90))
		return 0x3;
	else
		return chainmask;
}

static void ath_buf_set_rate(struct ath_softc *sc, struct ath_buf *bf, int len)
{
	struct ath_common *common = ath9k_hw_common(sc->sc_ah);
	struct ath9k_11n_rate_series series[4];
	const struct ath9k_legacy_rate *rate;
	int i, flags = 0;
	u8 rix = 0, ctsrate = 0;
	int is_pspoll;

	memset(series, 0, sizeof(struct ath9k_11n_rate_series) * 4);

	is_pspoll = 0;

	/*
	 * We check if Short Preamble is needed for the CTS rate by
	 * checking the BSS's global flag.
	 * But for the rate series, IEEE80211_TX_RC_USE_SHORT_PREAMBLE is used.
	 */
	rate = &sc->rates[sc->hw_rix];
	ctsrate = rate->hw_value;
	if (sc->sc_flags & SC_OP_PREAMBLE_SHORT)
		ctsrate |= rate->hw_value_short;

	for (i = 0; i < 4; i++) {
		int is_40 __unused, is_sgi __unused, is_sp;
		int phy;

		rix = sc->hw_rix;
		series[i].Tries = ATH_TXMAXTRY;

		if (sc->sc_flags & SC_OP_PROTECT_ENABLE) {
			series[i].RateFlags |= ATH9K_RATESERIES_RTS_CTS;
			flags |= ATH9K_TXDESC_CTSENA;
		}

		is_sp = !!(rate->flags & IEEE80211_TX_RC_USE_SHORT_PREAMBLE);

		/* legacy rates */
		if ((sc->dev->channels + sc->dev->channel)->band == NET80211_BAND_2GHZ)
			phy = CHANNEL_CCK;
		else
			phy = CHANNEL_OFDM;

		series[i].Rate = rate->hw_value;
		if (rate->hw_value_short && (sc->sc_flags & SC_OP_PREAMBLE_SHORT)) {
			if (rate->flags & IEEE80211_TX_RC_USE_SHORT_PREAMBLE)
				series[i].Rate |= rate->hw_value_short;
		} else {
			is_sp = 0;
		}

		if (bf->bf_state.bfs_paprd)
			series[i].ChSel = common->tx_chainmask;
		else
			series[i].ChSel = ath_txchainmask_reduction(sc,
					common->tx_chainmask, series[i].Rate);

		series[i].PktDuration = ath9k_hw_computetxtime(sc->sc_ah,
			phy, rate->bitrate * 100, len, rix, is_sp);
	}

	/* For AR5416 - RTS cannot be followed by a frame larger than 8K */
	if (bf_isaggr(bf) && (len > sc->sc_ah->caps.rts_aggr_limit))
		flags &= ~ATH9K_TXDESC_RTSENA;

	/* ATH9K_TXDESC_RTSENA and ATH9K_TXDESC_CTSENA are mutually exclusive. */
	if (flags & ATH9K_TXDESC_RTSENA)
		flags &= ~ATH9K_TXDESC_CTSENA;

	/* set dur_update_en for l-sig computation except for PS-Poll frames */
	ath9k_hw_set11n_ratescenario(sc->sc_ah, bf->bf_desc,
				     bf->bf_lastbf->bf_desc,
				     !is_pspoll, ctsrate,
				     0, series, 4, flags);

}

static struct ath_buf *ath_tx_setup_buffer(struct net80211_device *dev,
					   struct ath_txq *txq,
					   struct io_buffer *iob)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hw *ah = sc->sc_ah;
	struct ath_buf *bf;
	struct ath_desc *ds;
	int frm_type;
	static const enum ath9k_key_type net80211_keytype_to_ath[] = {
			[NET80211_CRYPT_NONE] = ATH9K_KEY_TYPE_CLEAR,
			[NET80211_CRYPT_WEP] = ATH9K_KEY_TYPE_WEP,
			[NET80211_CRYPT_TKIP] = ATH9K_KEY_TYPE_TKIP,
			[NET80211_CRYPT_CCMP] = ATH9K_KEY_TYPE_AES,
			[NET80211_CRYPT_UNKNOWN] = ATH9K_KEY_TYPE_CLEAR,
	};

	bf = ath_tx_get_buffer(sc);
	if (!bf) {
		DBG("ath9k: TX buffers are full\n");
		return NULL;
	}

	ATH_TXBUF_RESET(bf);

	bf->bf_flags = setup_tx_flags(iob);
	bf->bf_mpdu = iob;

	bf->bf_buf_addr = virt_to_bus(iob->data);

	frm_type = get_hw_packet_type(iob);

	ds = bf->bf_desc;
	ath9k_hw_set_desc_link(ah, ds, 0);

	ath9k_hw_set11n_txdesc(ah, ds, iob_len(iob) + FCS_LEN, frm_type, MAX_RATE_POWER,
			       ATH9K_TXKEYIX_INVALID, net80211_keytype_to_ath[dev->crypto->algorithm], bf->bf_flags);

	ath9k_hw_filltxdesc(ah, ds,
			    iob_len(iob),	/* segment length */
			    1,		/* first segment */
			    1,		/* last segment */
			    ds,		/* first descriptor */
			    bf->bf_buf_addr,
			    txq->axq_qnum);


	return bf;
}

/* FIXME: tx power */
static void ath_tx_start_dma(struct ath_softc *sc, struct ath_buf *bf,
			     struct ath_tx_control *txctl)
{
	struct list_head bf_head;
	struct ath_atx_tid *tid = NULL;

	INIT_LIST_HEAD(&bf_head);
	list_add_tail(&bf->list, &bf_head);

	bf->bf_state.bfs_paprd = txctl->paprd;

	if (txctl->paprd)
		bf->bf_state.bfs_paprd_timestamp = ( currticks() * 1000 ) / TICKS_PER_SEC;

	ath9k_hw_set_clrdmask(sc->sc_ah, bf->bf_desc, 1);

	ath_tx_send_normal(sc, txctl->txq, tid, &bf_head);
}

/* Upon failure caller should free iob */
int ath_tx_start(struct net80211_device *dev, struct io_buffer *iob,
		 struct ath_tx_control *txctl)
{
	struct ath_softc *sc = dev->priv;
	struct ath_txq *txq = txctl->txq;
	struct ath_buf *bf;
	int q;

	/*
	 * At this point, the vif, hw_key and sta pointers in the tx control
	 * info are no longer valid (overwritten by the ath_frame_info data.
	 */

	bf = ath_tx_setup_buffer(dev, txctl->txq, iob);
	if (!bf)
		return -ENOMEM;

	q = 0;
	if (txq == sc->tx.txq_map[q] &&
	    ++txq->pending_frames > ATH_MAX_QDEPTH && !txq->stopped) {
		txq->stopped = 1;
	}

	ath_tx_start_dma(sc, bf, txctl);

	return 0;
}

/*****************/
/* TX Completion */
/*****************/

static void ath_tx_complete(struct ath_softc *sc, struct io_buffer *iob,
			    int tx_flags __unused, struct ath_tx_status *ts, struct ath_txq *txq)
{
	struct net80211_device *dev = sc->dev;
	int q, padpos __unused, padsize __unused;

	DBGIO("ath9k: TX complete: iob: %p\n", iob);

	q = 0;
	if (txq == sc->tx.txq_map[q]) {
		if (--txq->pending_frames < 0)
			txq->pending_frames = 0;

		if (txq->stopped && txq->pending_frames < ATH_MAX_QDEPTH) {
			txq->stopped = 0;
		}
	}

	net80211_tx_complete(dev, iob, ts->ts_longretry,
			(ts->ts_status & ATH9K_TXERR_MASK) ? EIO : 0);
}

static void ath_tx_complete_buf(struct ath_softc *sc, struct ath_buf *bf,
				struct ath_txq *txq, struct list_head *bf_q,
				struct ath_tx_status *ts, int txok, int sendbar)
{
	struct io_buffer *iob = bf->bf_mpdu;
	int tx_flags = 0;

	if (sendbar)
		tx_flags = ATH_TX_BAR;

	if (!txok) {
		tx_flags |= ATH_TX_ERROR;

		if (bf_isxretried(bf))
			tx_flags |= ATH_TX_XRETRY;
	}

	bf->bf_buf_addr = 0;

	ath_tx_complete(sc, iob, tx_flags,
			ts, txq);

	/* At this point, iob (bf->bf_mpdu) is consumed...make sure we don't
	 * accidentally reference it later.
	 */
	bf->bf_mpdu = NULL;

	/*
	 * Return the list of ath_buf of this mpdu to free queue
	 */
	list_splice_tail_init(bf_q, &sc->tx.txbuf);
}

static void ath_tx_processq(struct ath_softc *sc, struct ath_txq *txq)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_buf *bf, *lastbf, *bf_held = NULL;
	struct list_head bf_head;
	struct ath_desc *ds;
	struct ath_tx_status ts;
	int txok;
	int status;

	DBGIO("ath9k: tx queue %d (%x), link %p\n",
		txq->axq_qnum, ath9k_hw_gettxbuf(sc->sc_ah, txq->axq_qnum),
		txq->axq_link);

	for (;;) {
		if (list_empty(&txq->axq_q)) {
			txq->axq_link = NULL;
			if (sc->sc_flags & SC_OP_TXAGGR)
				ath_txq_schedule(sc, txq);
			break;
		}
		bf = list_first_entry(&txq->axq_q, struct ath_buf, list);

		/*
		 * There is a race condition that a BH gets scheduled
		 * after sw writes TxE and before hw re-load the last
		 * descriptor to get the newly chained one.
		 * Software must keep the last DONE descriptor as a
		 * holding descriptor - software does so by marking
		 * it with the STALE flag.
		 */
		bf_held = NULL;
		if (bf->bf_stale) {
			bf_held = bf;
			if (list_is_last(&bf_held->list, &txq->axq_q)) {
				break;
			} else {
				bf = list_entry(bf_held->list.next,
						struct ath_buf, list);
			}
		}

		lastbf = bf->bf_lastbf;
		ds = lastbf->bf_desc;

		memset(&ts, 0, sizeof(ts));
		status = ath9k_hw_txprocdesc(ah, ds, &ts);
		if (status == -EINPROGRESS) {
			break;
		}

		/*
		 * Remove ath_buf's of the same transmit unit from txq,
		 * however leave the last descriptor back as the holding
		 * descriptor for hw.
		 */
		lastbf->bf_stale = 1;
		INIT_LIST_HEAD(&bf_head);
		if (!list_is_singular(&lastbf->list))
			list_cut_position(&bf_head,
				&txq->axq_q, lastbf->list.prev);

		txq->axq_depth--;
		txok = !(ts.ts_status & ATH9K_TXERR_MASK);
		txq->axq_tx_inprogress = 0;
		if (bf_held)
			list_del(&bf_held->list);

		if (bf_held)
			ath_tx_return_buffer(sc, bf_held);

		/*
		 * This frame is sent out as a single frame.
		 * Use hardware retry status for this frame.
		 */
		if (ts.ts_status & ATH9K_TXERR_XRETRY)
			bf->bf_state.bf_type |= BUF_XRETRY;

		ath_tx_complete_buf(sc, bf, txq, &bf_head, &ts, txok, 0);

		if (sc->sc_flags & SC_OP_TXAGGR)
			ath_txq_schedule(sc, txq);
	}
}

static void ath_tx_complete_poll_work(struct ath_softc *sc)
{
	struct ath_txq *txq;
	int i;
	int needreset = 0;

	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++)
		if (ATH_TXQ_SETUP(sc, i)) {
			txq = &sc->tx.txq[i];
			if (txq->axq_depth) {
				if (txq->axq_tx_inprogress) {
					needreset = 1;
					break;
				} else {
					txq->axq_tx_inprogress = 1;
				}
			}
		}

	if (needreset) {
		DBG("ath9k: "
			"tx hung, resetting the chip\n");
		ath_reset(sc, 1);
	}

	sc->tx_complete_work_timer = ( currticks() * 1000 ) / TICKS_PER_SEC + ATH_TX_COMPLETE_POLL_INT;
}



void ath_tx_tasklet(struct ath_softc *sc)
{
	int i;
	u32 qcumask = ((1 << ATH9K_NUM_TX_QUEUES) - 1);

	ath9k_hw_gettxintrtxqs(sc->sc_ah, &qcumask);

	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(sc, i) && (qcumask & (1 << i)))
			ath_tx_processq(sc, &sc->tx.txq[i]);
	}
}

/*****************/
/* Init, Cleanup */
/*****************/

int ath_tx_init(struct ath_softc *sc, int nbufs)
{
	int error = 0;

	error = ath_descdma_setup(sc, &sc->tx.txdma, &sc->tx.txbuf,
				  "tx", nbufs, 1, 1);
	if (error != 0) {
		DBG("ath9k: "
			"Failed to allocate tx descriptors: %d\n", error);
		goto err;
	}

	sc->tx_complete_work = ath_tx_complete_poll_work;

err:
	if (error != 0)
		ath_tx_cleanup(sc);

	return error;
}

void ath_tx_cleanup(struct ath_softc *sc)
{
	if (sc->tx.txdma.dd_desc_len != 0)
		ath_descdma_cleanup(sc, &sc->tx.txdma, &sc->tx.txbuf);
}
