/*
 * Copyright (c) 2009-2011 Atheros Communications Inc.
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

/*
 * Module for common driver code between ath9k and ath9k_htc
 */

#include "common.h"

/*
 * Update internal channel flags.
 */
void ath9k_cmn_update_ichannel(struct ath9k_channel *ichan,
			       struct net80211_channel *chan)
{
	ichan->channel = chan->center_freq;
	ichan->chan = chan;

	if (chan->band == NET80211_BAND_2GHZ) {
		ichan->chanmode = CHANNEL_G;
		ichan->channelFlags = CHANNEL_2GHZ | CHANNEL_OFDM;
	} else {
		ichan->chanmode = CHANNEL_A;
		ichan->channelFlags = CHANNEL_5GHZ | CHANNEL_OFDM;
	}
}

/*
 * Get the internal channel reference.
 */
struct ath9k_channel *ath9k_cmn_get_curchannel(struct net80211_device *dev,
					       struct ath_hw *ah)
{
	struct net80211_channel *curchan = dev->channels + dev->channel;
	struct ath9k_channel *channel;
	u8 chan_idx;

	chan_idx = curchan->hw_value;
	channel = &ah->channels[chan_idx];
	ath9k_cmn_update_ichannel(channel, curchan);

	return channel;
}

void ath9k_cmn_update_txpow(struct ath_hw *ah, u16 cur_txpow,
			    u16 new_txpow, u16 *txpower)
{
	if (cur_txpow != new_txpow) {
		ath9k_hw_set_txpowerlimit(ah, new_txpow, 0);
		/* read back in case value is clamped */
		*txpower = ath9k_hw_regulatory(ah)->power_limit;
	}
}
