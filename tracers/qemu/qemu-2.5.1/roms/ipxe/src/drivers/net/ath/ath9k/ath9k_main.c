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

static void ath9k_bss_info_changed(struct net80211_device *dev, u32 changed);

int ath9k_setpower(struct ath_softc *sc, enum ath9k_power_mode mode)
{
	int ret;

	ret = ath9k_hw_setpower(sc->sc_ah, mode);

	return ret;
}

static void ath_start_ani(struct ath_common *common)
{
	struct ath_hw *ah = common->ah;
	unsigned long timestamp = ( currticks() * 1000 ) / TICKS_PER_SEC;
	struct ath_softc *sc = (struct ath_softc *) common->priv;

	if (!(sc->sc_flags & SC_OP_ANI_RUN))
		return;

	if (sc->sc_flags & SC_OP_OFFCHANNEL)
		return;

	common->ani.longcal_timer = timestamp;
	common->ani.shortcal_timer = timestamp;
	common->ani.checkani_timer = timestamp;

	common->ani.timer = timestamp + ah->config.ani_poll_interval;
}

static void ath_update_survey_nf(struct ath_softc *sc, int channel)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath9k_channel *chan = &ah->channels[channel];
	struct survey_info *survey = &sc->survey[channel];

	if (chan->noisefloor) {
		survey->filled |= SURVEY_INFO_NOISE_DBM;
		survey->noise = chan->noisefloor;
	}
}

/*
 * Updates the survey statistics and returns the busy time since last
 * update in %, if the measurement duration was long enough for the
 * result to be useful, -1 otherwise.
 */
static int ath_update_survey_stats(struct ath_softc *sc)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	int pos = ah->curchan - &ah->channels[0];
	struct survey_info *survey = &sc->survey[pos];
	struct ath_cycle_counters *cc = &common->cc_survey;
	unsigned int div = common->clockrate * 1000;
	int ret = 0;

	if (!ah->curchan)
		return -1;

	if (ah->power_mode == ATH9K_PM_AWAKE)
		ath_hw_cycle_counters_update(common);

	if (cc->cycles > 0) {
		survey->filled |= SURVEY_INFO_CHANNEL_TIME |
			SURVEY_INFO_CHANNEL_TIME_BUSY |
			SURVEY_INFO_CHANNEL_TIME_RX |
			SURVEY_INFO_CHANNEL_TIME_TX;
		survey->channel_time += cc->cycles / div;
		survey->channel_time_busy += cc->rx_busy / div;
		survey->channel_time_rx += cc->rx_frame / div;
		survey->channel_time_tx += cc->tx_frame / div;
	}

	if (cc->cycles < div)
		return -1;

	if (cc->cycles > 0)
		ret = cc->rx_busy * 100 / cc->cycles;

	memset(cc, 0, sizeof(*cc));

	ath_update_survey_nf(sc, pos);

	return ret;
}

/*
 * Set/change channels.  If the channel is really being changed, it's done
 * by reseting the chip.  To accomplish this we must first cleanup any pending
 * DMA, then restart stuff.
*/
int ath_set_channel(struct ath_softc *sc, struct net80211_device *dev,
		    struct ath9k_channel *hchan)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	int fastcc __unused = 1, stopped __unused;
	struct net80211_channel *channel = dev->channels + dev->channel;
	struct ath9k_hw_cal_data *caldata = NULL;
	int r;

	if (sc->sc_flags & SC_OP_INVALID)
		return -EIO;

	sc->hw_busy_count = 0;

	common->ani.timer = 0;
	sc->tx_complete_work_timer = 0;
	sc->hw_pll_work_timer = 0;

	/*
	 * This is only performed if the channel settings have
	 * actually changed.
	 *
	 * To switch channels clear any pending DMA operations;
	 * wait long enough for the RX fifo to drain, reset the
	 * hardware at the new frequency, and then re-enable
	 * the relevant bits of the h/w.
	 */
	ath9k_hw_disable_interrupts(ah);
	stopped = ath_drain_all_txq(sc, 0);

	if (!ath_stoprecv(sc))
		stopped = 0;

	if (!ath9k_hw_check_alive(ah))
		stopped = 0;

	/* XXX: do not flush receive queue here. We don't want
	 * to flush data frames already in queue because of
	 * changing channel. */

	if (!(sc->sc_flags & SC_OP_OFFCHANNEL))
		caldata = &sc->caldata;

	DBG2("ath9k: "
		"(%d MHz) -> (%d MHz)\n",
		sc->sc_ah->curchan->channel,
		channel->center_freq);

	r = ath9k_hw_reset(ah, hchan, caldata, fastcc);
	if (r) {
		DBG("ath9k: "
			"Unable to reset channel (%d MHz), reset status %d\n",
			channel->center_freq, r);
		goto ps_restore;
	}

	if (ath_startrecv(sc) != 0) {
		DBG("ath9k: Unable to restart recv logic\n");
		r = -EIO;
		goto ps_restore;
	}

	ath9k_cmn_update_txpow(ah, sc->curtxpow,
			       sc->config.txpowlimit, &sc->curtxpow);
	ath9k_hw_set_interrupts(ah, ah->imask);

	if (!(sc->sc_flags & (SC_OP_OFFCHANNEL))) {
		sc->tx_complete_work(sc);
		sc->hw_pll_work_timer = (currticks() * 1000 ) / TICKS_PER_SEC + 500;
		ath_start_ani(common);
	}

 ps_restore:
	return r;
}

/*
 *  This routine performs the periodic noise floor calibration function
 *  that is used to adjust and optimize the chip performance.  This
 *  takes environmental changes (location, temperature) into account.
 *  When the task is complete, it reschedules itself depending on the
 *  appropriate interval that was calculated.
 */
void ath_ani_calibrate(struct ath_softc *sc)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	int longcal = 0;
	int shortcal = 0;
	int aniflag = 0;
	unsigned int timestamp = (currticks() * 1000 ) / TICKS_PER_SEC;
	u32 cal_interval, short_cal_interval, long_cal_interval;

	if (ah->caldata && ah->caldata->nfcal_interference)
		long_cal_interval = ATH_LONG_CALINTERVAL_INT;
	else
		long_cal_interval = ATH_LONG_CALINTERVAL;

	short_cal_interval = ATH_STA_SHORT_CALINTERVAL;

	/* Only calibrate if awake */
	if (sc->sc_ah->power_mode != ATH9K_PM_AWAKE)
		goto set_timer;

	/* Long calibration runs independently of short calibration. */
	if ((timestamp - common->ani.longcal_timer) >= long_cal_interval) {
		longcal = 1;
		DBG2("ath9k: longcal @%d\n", timestamp);
		common->ani.longcal_timer = timestamp;
	}

	/* Short calibration applies only while caldone is false */
	if (!common->ani.caldone) {
		if ((timestamp - common->ani.shortcal_timer) >= short_cal_interval) {
			shortcal = 1;
			DBG2("ath9k: "
				"shortcal @%d\n", timestamp);
			common->ani.shortcal_timer = timestamp;
			common->ani.resetcal_timer = timestamp;
		}
	} else {
		if ((timestamp - common->ani.resetcal_timer) >=
		    ATH_RESTART_CALINTERVAL) {
			common->ani.caldone = ath9k_hw_reset_calvalid(ah);
			if (common->ani.caldone)
				common->ani.resetcal_timer = timestamp;
		}
	}

	/* Verify whether we must check ANI */
	if ((timestamp - common->ani.checkani_timer) >=
	     ah->config.ani_poll_interval) {
		aniflag = 1;
		common->ani.checkani_timer = timestamp;
	}

	/* Skip all processing if there's nothing to do. */
	if (longcal || shortcal || aniflag) {
		/* Call ANI routine if necessary */
		if (aniflag) {
			ath9k_hw_ani_monitor(ah, ah->curchan);
			ath_update_survey_stats(sc);
		}

		/* Perform calibration if necessary */
		if (longcal || shortcal) {
			common->ani.caldone =
				ath9k_hw_calibrate(ah,
						   ah->curchan,
						   common->rx_chainmask,
						   longcal);
		}
	}

set_timer:
	/*
	* Set timer interval based on previous results.
	* The interval must be the shortest necessary to satisfy ANI,
	* short calibration and long calibration.
	*/
	cal_interval = ATH_LONG_CALINTERVAL;
	if (sc->sc_ah->config.enable_ani)
		cal_interval = min(cal_interval,
				   (u32)ah->config.ani_poll_interval);
	if (!common->ani.caldone)
		cal_interval = min(cal_interval, (u32)short_cal_interval);

	common->ani.timer = timestamp + cal_interval;
}

void ath_hw_check(struct ath_softc *sc)
{
	int busy;

	if (ath9k_hw_check_alive(sc->sc_ah))
		goto out;

	busy = ath_update_survey_stats(sc);

	DBG("ath9k: Possible baseband hang, "
		"busy=%d (try %d)\n", busy, sc->hw_busy_count + 1);
	if (busy >= 99) {
		if (++sc->hw_busy_count >= 3)
			ath_reset(sc, 1);
	} else if (busy >= 0)
		sc->hw_busy_count = 0;

out:
	return;
}

static void ath_hw_pll_rx_hang_check(struct ath_softc *sc, u32 pll_sqsum)
{
	static int count;

	if (pll_sqsum >= 0x40000) {
		count++;
		if (count == 3) {
			/* Rx is hung for more than 500ms. Reset it */
			DBG("ath9k: "
				"Possible RX hang, resetting");
			ath_reset(sc, 1);
			count = 0;
		}
	} else
		count = 0;
}

void ath_hw_pll_work(struct ath_softc *sc)
{
	u32 pll_sqsum;

	if (AR_SREV_9485(sc->sc_ah)) {
		pll_sqsum = ar9003_get_pll_sqsum_dvc(sc->sc_ah);

		ath_hw_pll_rx_hang_check(sc, pll_sqsum);

		sc->hw_pll_work_timer = (currticks() * 1000 ) / TICKS_PER_SEC + 200;
	}
}


void ath9k_tasklet(struct ath_softc *sc)
{
	struct ath_hw *ah = sc->sc_ah;

	u32 status = sc->intrstatus;
	u32 rxmask;

	if ((status & ATH9K_INT_FATAL) ||
	    (status & ATH9K_INT_BB_WATCHDOG)) {
		ath_reset(sc, 1);
		return;
	}

	rxmask = (ATH9K_INT_RX | ATH9K_INT_RXEOL | ATH9K_INT_RXORN);

	if (status & rxmask) {
		ath_rx_tasklet(sc, 0, 0);
	}

	if (status & ATH9K_INT_TX) {
		ath_tx_tasklet(sc);
	}

	/* re-enable hardware interrupt */
	ath9k_hw_enable_interrupts(ah);
}

void ath_isr(struct net80211_device *dev)
{
#define SCHED_INTR (				\
		ATH9K_INT_FATAL |		\
		ATH9K_INT_BB_WATCHDOG |		\
		ATH9K_INT_RXORN |		\
		ATH9K_INT_RXEOL |		\
		ATH9K_INT_RX |			\
		ATH9K_INT_RXLP |		\
		ATH9K_INT_RXHP |		\
		ATH9K_INT_TX |			\
		ATH9K_INT_BMISS |		\
		ATH9K_INT_CST |			\
		ATH9K_INT_TSFOOR |		\
		ATH9K_INT_GENTIMER)

	struct ath_softc *sc = dev->priv;
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	enum ath9k_int status;
	unsigned long timestamp = (currticks() * 1000 ) / TICKS_PER_SEC;
	int sched = 0;

	/*
	 * The hardware is not ready/present, don't
	 * touch anything. Note this can happen early
	 * on if the IRQ is shared.
	 */
	if (sc->sc_flags & SC_OP_INVALID)
		return;


	/* Check calibration */
	if(timestamp >= (unsigned int)common->ani.timer && common->ani.timer)
		ath_ani_calibrate(sc);

	/* Check tx_complete_work */
	if(timestamp >= (unsigned int)sc->tx_complete_work_timer && sc->tx_complete_work_timer)
		sc->tx_complete_work(sc);

	/* Check hw_pll_work */
	if(timestamp >= (unsigned int)sc->hw_pll_work_timer && sc->hw_pll_work_timer)
		sc->hw_pll_work(sc);

	/* shared irq, not for us */

	if (!ath9k_hw_intrpend(ah))
		return;

	/*
	 * Figure out the reason(s) for the interrupt.  Note
	 * that the hal returns a pseudo-ISR that may include
	 * bits we haven't explicitly enabled so we mask the
	 * value to insure we only process bits we requested.
	 */
	ath9k_hw_getisr(ah, &status);	/* NB: clears ISR too */
	status &= ah->imask;	/* discard unasked-for bits */

	/*
	 * If there are no status bits set, then this interrupt was not
	 * for me (should have been caught above).
	 */
	if (!status)
		return;

	/* Cache the status */
	sc->intrstatus = status;

	if (status & SCHED_INTR)
		sched = 1;

	/*
	 * If a FATAL or RXORN interrupt is received, we have to reset the
	 * chip immediately.
	 */
	if ((status & ATH9K_INT_FATAL) || (status & ATH9K_INT_RXORN))
		goto chip_reset;

	if (status & ATH9K_INT_TXURN)
		ath9k_hw_updatetxtriglevel(ah, 1);

	if (!(ah->caps.hw_caps & ATH9K_HW_CAP_AUTOSLEEP))
		if (status & ATH9K_INT_TIM_TIMER) {
			if (sc->ps_idle)
				goto chip_reset;
			/* Clear RxAbort bit so that we can
			 * receive frames */
			ath9k_setpower(sc, ATH9K_PM_AWAKE);
			ath9k_hw_setrxabort(sc->sc_ah, 0);
			sc->ps_flags |= PS_WAIT_FOR_BEACON;
		}

chip_reset:

	if (sched) {
		/* turn off every interrupt */
		ath9k_hw_disable_interrupts(ah);
		sc->intr_tq(sc);
	}

	return;

#undef SCHED_INTR
}

void ath_radio_disable(struct ath_softc *sc, struct net80211_device *dev)
{
	struct ath_hw *ah = sc->sc_ah;
	struct net80211_channel *channel = dev->channels + dev->channel;
	int r;

	sc->hw_pll_work_timer = 0;

	/*
	 * Keep the LED on when the radio is disabled
	 * during idle unassociated state.
	 */
	if (!sc->ps_idle) {
		ath9k_hw_set_gpio(ah, ah->led_pin, 1);
		ath9k_hw_cfg_gpio_input(ah, ah->led_pin);
	}

	/* Disable interrupts */
	ath9k_hw_disable_interrupts(ah);

	ath_drain_all_txq(sc, 0);	/* clear pending tx frames */

	ath_stoprecv(sc);		/* turn off frame recv */
	ath_flushrecv(sc);		/* flush recv queue */

	if (!ah->curchan)
		ah->curchan = ath9k_cmn_get_curchannel(dev, ah);

	r = ath9k_hw_reset(ah, ah->curchan, ah->caldata, 0);
	if (r) {
		DBG("ath9k: "
			"Unable to reset channel (%d MHz), reset status %d\n",
			channel->center_freq, r);
	}

	ath9k_hw_phy_disable(ah);

	ath9k_hw_configpcipowersave(ah, 1, 1);
}

int ath_reset(struct ath_softc *sc, int retry_tx)
{
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	int r;

	sc->hw_busy_count = 0;

	/* Stop ANI */
	common->ani.timer = 0;

	ath9k_hw_disable_interrupts(ah);
	ath_drain_all_txq(sc, retry_tx);

	ath_stoprecv(sc);
	ath_flushrecv(sc);

	r = ath9k_hw_reset(ah, sc->sc_ah->curchan, ah->caldata, 0);
	if (r)
		DBG("ath9k: "
			"Unable to reset hardware; reset status %d\n", r);

	if (ath_startrecv(sc) != 0)
		DBG("ath9k: Unable to start recv logic\n");

	/*
	 * We may be doing a reset in response to a request
	 * that changes the channel so update any state that
	 * might change as a result.
	 */
	ath9k_cmn_update_txpow(ah, sc->curtxpow,
			       sc->config.txpowlimit, &sc->curtxpow);

	ath9k_hw_set_interrupts(ah, ah->imask);

	if (retry_tx) {
		int i;
		for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
			if (ATH_TXQ_SETUP(sc, i)) {
				ath_txq_schedule(sc, &sc->tx.txq[i]);
			}
		}
	}

	/* Start ANI */
	ath_start_ani(common);

	return r;
}

/**********************/
/* mac80211 callbacks */
/**********************/

static int ath9k_start(struct net80211_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	struct net80211_channel *curchan = dev->channels + dev->channel;
	struct ath9k_channel *init_channel;
	int r;

	DBG("ath9k: "
		"Starting driver with initial channel: %d MHz\n",
		curchan->center_freq);

	/* setup initial channel */
	sc->chan_idx = curchan->hw_value;

	init_channel = ath9k_cmn_get_curchannel(dev, ah);

	/* Reset SERDES registers */
	ath9k_hw_configpcipowersave(ah, 0, 0);

	/*
	 * The basic interface to setting the hardware in a good
	 * state is ``reset''.  On return the hardware is known to
	 * be powered up and with interrupts disabled.  This must
	 * be followed by initialization of the appropriate bits
	 * and then setup of the interrupt mask.
	 */
	r = ath9k_hw_reset(ah, init_channel, ah->caldata, 0);
	if (r) {
		DBG("ath9k: "
			"Unable to reset hardware; reset status %d (freq %d MHz)\n",
			r, curchan->center_freq);
		goto mutex_unlock;
	}

	/*
	 * This is needed only to setup initial state
	 * but it's best done after a reset.
	 */
	ath9k_cmn_update_txpow(ah, sc->curtxpow,
			sc->config.txpowlimit, &sc->curtxpow);

	/*
	 * Setup the hardware after reset:
	 * The receive engine is set going.
	 * Frame transmit is handled entirely
	 * in the frame output path; there's nothing to do
	 * here except setup the interrupt mask.
	 */
	if (ath_startrecv(sc) != 0) {
		DBG("ath9k: Unable to start recv logic\n");
		r = -EIO;
		goto mutex_unlock;
	}

	/* Setup our intr mask. */
	ah->imask = ATH9K_INT_TX | ATH9K_INT_RXEOL |
		    ATH9K_INT_RXORN | ATH9K_INT_FATAL |
		    ATH9K_INT_GLOBAL;

	ah->imask |= ATH9K_INT_RX;

	sc->sc_flags &= ~SC_OP_INVALID;
	sc->sc_ah->is_monitoring = 0;

	ath9k_hw_set_interrupts(ah, ah->imask);

	sc->tx_complete_work(sc);

	if (ah->caps.pcie_lcr_extsync_en && common->bus_ops->extn_synch_en)
		common->bus_ops->extn_synch_en(common);

mutex_unlock:
	return r;
}

static int ath9k_tx(struct net80211_device *dev, struct io_buffer *iob)
{
	struct ath_softc *sc = dev->priv;
	struct ath_tx_control txctl;
	int ret = 0;

	memset(&txctl, 0, sizeof(struct ath_tx_control));
	txctl.txq = sc->tx.txq_map[0];

	DBGIO("ath9k: transmitting packet, iob: %p\n", iob);

	ret = ath_tx_start(dev, iob, &txctl);
	if (ret) {
		DBG("ath9k: TX failed\n");
		goto exit;
	}

	return ret;
exit:
	free_iob(iob);
	return ret;
}

static void ath9k_stop(struct net80211_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hw *ah = sc->sc_ah;

	sc->tx_complete_work_timer = 0;
	sc->hw_pll_work_timer = 0;

	if (sc->sc_flags & SC_OP_INVALID) {
		DBG("ath9k: Device not present\n");
		return;
	}

	/* prevent tasklets to enable interrupts once we disable them */
	ah->imask &= ~ATH9K_INT_GLOBAL;

	/* make sure h/w will not generate any interrupt
	 * before setting the invalid flag. */
	ath9k_hw_disable_interrupts(ah);

	if (!(sc->sc_flags & SC_OP_INVALID)) {
		ath_drain_all_txq(sc, 0);
		ath_stoprecv(sc);
		ath9k_hw_phy_disable(ah);
	} else
		sc->rx.rxlink = NULL;

	if (sc->rx.frag) {
		free_iob(sc->rx.frag);
		sc->rx.frag = NULL;
	}

	/* disable HAL and put h/w to sleep */
	ath9k_hw_disable(ah);
	ath9k_hw_configpcipowersave(ah, 1, 1);

	ath_radio_disable(sc, dev);

	sc->sc_flags |= SC_OP_INVALID;

	DBG("ath9k: Driver halt\n");
}

static int ath9k_config(struct net80211_device *dev, int changed)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hw *ah = sc->sc_ah;

	if ((changed & NET80211_CFG_RATE) ||
			(changed & NET80211_CFG_PHY_PARAMS)) {
		int spmbl = (sc->sc_flags & SC_OP_PREAMBLE_SHORT) ? IEEE80211_TX_RC_USE_SHORT_PREAMBLE : 0;
		u16 rate = dev->rates[dev->rate];
		u16 slowrate = dev->rates[dev->rtscts_rate];
		int i;

		for (i = 0; i < NET80211_MAX_RATES; i++) {
			if (sc->rates[i].bitrate == rate &&
			    (sc->rates[i].flags & spmbl))
				sc->hw_rix = i;

			if (sc->rates[i].bitrate == slowrate &&
			    (sc->rates[i].flags & spmbl))
				sc->hw_rix = i;
		}
	}

	ath9k_bss_info_changed(dev, changed);

	if (changed & NET80211_CFG_CHANNEL) {
		struct net80211_channel *curchan = dev->channels + dev->channel;
		int pos = curchan->hw_value;
		int old_pos = -1;

		if (ah->curchan)
			old_pos = ah->curchan - &ah->channels[0];

		sc->sc_flags &= ~SC_OP_OFFCHANNEL;

		DBG2("ath9k: "
			"Set channel: %d MHz\n",
			curchan->center_freq);

		ath9k_cmn_update_ichannel(&sc->sc_ah->channels[pos],
					  curchan);

		/* update survey stats for the old channel before switching */
		ath_update_survey_stats(sc);

		/*
		 * If the operating channel changes, change the survey in-use flags
		 * along with it.
		 * Reset the survey data for the new channel, unless we're switching
		 * back to the operating channel from an off-channel operation.
		 */
		if (sc->cur_survey != &sc->survey[pos]) {

			if (sc->cur_survey)
				sc->cur_survey->filled &= ~SURVEY_INFO_IN_USE;

			sc->cur_survey = &sc->survey[pos];

			memset(sc->cur_survey, 0, sizeof(struct survey_info));
			sc->cur_survey->filled |= SURVEY_INFO_IN_USE;
		} else if (!(sc->survey[pos].filled & SURVEY_INFO_IN_USE)) {
			memset(&sc->survey[pos], 0, sizeof(struct survey_info));
		}

		if (ath_set_channel(sc, dev, &sc->sc_ah->channels[pos]) < 0) {
			DBG("ath9k: Unable to set channel\n");
			return -EINVAL;
		}

		/*
		 * The most recent snapshot of channel->noisefloor for the old
		 * channel is only available after the hardware reset. Copy it to
		 * the survey stats now.
		 */
		if (old_pos >= 0)
			ath_update_survey_nf(sc, old_pos);
	}

	if (changed & NET80211_CFG_CHANNEL) {
		DBG2("ath9k: "
			"Set power: %d\n", (dev->channels + dev->channel)->maxpower);
		sc->config.txpowlimit = 2 * (dev->channels + dev->channel)->maxpower;
		ath9k_cmn_update_txpow(ah, sc->curtxpow,
				       sc->config.txpowlimit, &sc->curtxpow);
	}

	return 0;
}

static void ath9k_bss_iter(struct ath_softc *sc)
{
	struct ath_common *common = ath9k_hw_common(sc->sc_ah);

	if (common->dev->state & NET80211_ASSOCIATED) {
		sc->sc_flags |= SC_OP_PRIM_STA_VIF;
		memcpy(common->curbssid, common->dev->bssid, ETH_ALEN);
		common->curaid = common->dev->aid;
		ath9k_hw_write_associd(sc->sc_ah);
		DBG("ath9k: "
			"Bss Info ASSOC %d, bssid: %pM\n",
			common->dev->aid, common->curbssid);

		/*
		 * Request a re-configuration of Beacon related timers
		 * on the receipt of the first Beacon frame (i.e.,
		 * after time sync with the AP).
		 */
		sc->ps_flags |= PS_BEACON_SYNC | PS_WAIT_FOR_BEACON;
		/* Reset rssi stats */
		sc->last_rssi = ATH_RSSI_DUMMY_MARKER;
		sc->sc_ah->stats.avgbrssi = ATH_RSSI_DUMMY_MARKER;

		sc->sc_flags |= SC_OP_ANI_RUN;
		ath_start_ani(common);
	}
}

static void ath9k_config_bss(struct ath_softc *sc)
{
	struct ath_common *common = ath9k_hw_common(sc->sc_ah);
	struct net80211_device *dev = common->dev;

	/* Reconfigure bss info */
	if (!(dev->state & NET80211_ASSOCIATED)) {
		DBG2("ath9k: "
			"ath9k: Bss Info DISASSOC %d, bssid %pM\n",
			common->curaid, common->curbssid);
		sc->sc_flags &= ~(SC_OP_PRIM_STA_VIF | SC_OP_BEACONS);
		memset(common->curbssid, 0, ETH_ALEN);
		common->curaid = 0;
	}

	ath9k_bss_iter(sc);

	/*
	 * None of station vifs are associated.
	 * Clear bssid & aid
	 */
	if (!(sc->sc_flags & SC_OP_PRIM_STA_VIF)) {
		ath9k_hw_write_associd(sc->sc_ah);
		/* Stop ANI */
		sc->sc_flags &= ~SC_OP_ANI_RUN;
		common->ani.timer = 0;
	}
}

static void ath9k_bss_info_changed(struct net80211_device *dev,
				   u32 changed)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hw *ah = sc->sc_ah;
	struct ath_common *common = ath9k_hw_common(ah);
	int slottime;

	if (changed & NET80211_CFG_ASSOC) {
		ath9k_config_bss(sc);

		DBG2("ath9k: BSSID: %pM aid: 0x%x\n",
			common->curbssid, common->curaid);
	}

	if (changed & NET80211_CFG_PHY_PARAMS) {
		if (dev->phy_flags & NET80211_PHY_USE_PROTECTION)
			slottime = 9;
		else
			slottime = 20;
		ah->slottime = slottime;
		ath9k_hw_init_global_settings(ah);

		DBG2("ath9k: BSS Changed PREAMBLE %d\n",
				!!(dev->phy_flags & NET80211_PHY_USE_SHORT_PREAMBLE));
		if (dev->phy_flags & NET80211_PHY_USE_SHORT_PREAMBLE)
			sc->sc_flags |= SC_OP_PREAMBLE_SHORT;
		else
			sc->sc_flags &= ~SC_OP_PREAMBLE_SHORT;

		DBG2("ath9k: BSS Changed CTS PROT %d\n",
			!!(dev->phy_flags & NET80211_PHY_USE_PROTECTION));
		if ((dev->phy_flags & NET80211_PHY_USE_PROTECTION) &&
		    (dev->channels + dev->channel)->band != NET80211_BAND_5GHZ)
			sc->sc_flags |= SC_OP_PROTECT_ENABLE;
		else
			sc->sc_flags &= ~SC_OP_PROTECT_ENABLE;
	}
}

static void ath9k_poll(struct net80211_device *dev)
{
	ath_isr(dev);
}

static void ath9k_irq(struct net80211_device *dev, int enable)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hw *ah = sc->sc_ah;

	ah->ah_ier = enable ? AR_IER_ENABLE : AR_IER_DISABLE;

	ath9k_hw_set_interrupts(ah, ah->imask);
}

struct net80211_device_operations ath9k_ops = {
	.transmit	= ath9k_tx,
	.open		= ath9k_start,
	.close		= ath9k_stop,
	.config		= ath9k_config,
	.poll		= ath9k_poll,
	.irq		= ath9k_irq,
};
