/*
 * Copyright (c) 2004-2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006-2008 Nick Kossifidis <mickflemm@gmail.com>
 * Copyright (c) 2007-2008 Matthew W. S. Bell  <mentor@madwifi.org>
 * Copyright (c) 2007-2008 Luis Rodriguez <mcgrof@winlab.rutgers.edu>
 * Copyright (c) 2007-2008 Pavel Roskin <proski@gnu.org>
 * Copyright (c) 2007-2008 Jiri Slaby <jirislaby@gmail.com>
 *
 * Lightly modified for iPXE, July 2009, by Joshua Oreman <oremanj@rwcr.net>.
 *
 * Permission to use, copy, modify, and distribute this software for any
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
 *
 */

FILE_LICENCE ( MIT );

/*********************************\
* Protocol Control Unit Functions *
\*********************************/

#include "ath5k.h"
#include "reg.h"
#include "base.h"

/*******************\
* Generic functions *
\*******************/

/**
 * ath5k_hw_set_opmode - Set PCU operating mode
 *
 * @ah: The &struct ath5k_hw
 *
 * Initialize PCU for the various operating modes (AP/STA etc)
 *
 * For iPXE we always assume STA mode.
 */
int ath5k_hw_set_opmode(struct ath5k_hw *ah)
{
	u32 pcu_reg, beacon_reg, low_id, high_id;


	/* Preserve rest settings */
	pcu_reg = ath5k_hw_reg_read(ah, AR5K_STA_ID1) & 0xffff0000;
	pcu_reg &= ~(AR5K_STA_ID1_ADHOC | AR5K_STA_ID1_AP
			| AR5K_STA_ID1_KEYSRCH_MODE
			| (ah->ah_version == AR5K_AR5210 ?
			(AR5K_STA_ID1_PWR_SV | AR5K_STA_ID1_NO_PSPOLL) : 0));

	beacon_reg = 0;

	pcu_reg |= AR5K_STA_ID1_KEYSRCH_MODE
		| (ah->ah_version == AR5K_AR5210 ?
		   AR5K_STA_ID1_PWR_SV : 0);

	/*
	 * Set PCU registers
	 */
	low_id = AR5K_LOW_ID(ah->ah_sta_id);
	high_id = AR5K_HIGH_ID(ah->ah_sta_id);
	ath5k_hw_reg_write(ah, low_id, AR5K_STA_ID0);
	ath5k_hw_reg_write(ah, pcu_reg | high_id, AR5K_STA_ID1);

	/*
	 * Set Beacon Control Register on 5210
	 */
	if (ah->ah_version == AR5K_AR5210)
		ath5k_hw_reg_write(ah, beacon_reg, AR5K_BCR);

	return 0;
}

/**
 * ath5k_hw_set_ack_bitrate - set bitrate for ACKs
 *
 * @ah: The &struct ath5k_hw
 * @high: Flag to determine if we want to use high transmition rate
 * for ACKs or not
 *
 * If high flag is set, we tell hw to use a set of control rates based on
 * the current transmition rate (check out control_rates array inside reset.c).
 * If not hw just uses the lowest rate available for the current modulation
 * scheme being used (1Mbit for CCK and 6Mbits for OFDM).
 */
void ath5k_hw_set_ack_bitrate_high(struct ath5k_hw *ah, int high)
{
	if (ah->ah_version != AR5K_AR5212)
		return;
	else {
		u32 val = AR5K_STA_ID1_BASE_RATE_11B | AR5K_STA_ID1_ACKCTS_6MB;
		if (high)
			AR5K_REG_ENABLE_BITS(ah, AR5K_STA_ID1, val);
		else
			AR5K_REG_DISABLE_BITS(ah, AR5K_STA_ID1, val);
	}
}


/******************\
* ACK/CTS Timeouts *
\******************/

/**
 * ath5k_hw_het_ack_timeout - Get ACK timeout from PCU in usec
 *
 * @ah: The &struct ath5k_hw
 */
unsigned int ath5k_hw_get_ack_timeout(struct ath5k_hw *ah)
{
	return ath5k_hw_clocktoh(AR5K_REG_MS(ath5k_hw_reg_read(ah,
			AR5K_TIME_OUT), AR5K_TIME_OUT_ACK), ah->ah_turbo);
}

/**
 * ath5k_hw_set_ack_timeout - Set ACK timeout on PCU
 *
 * @ah: The &struct ath5k_hw
 * @timeout: Timeout in usec
 */
int ath5k_hw_set_ack_timeout(struct ath5k_hw *ah, unsigned int timeout)
{
	if (ath5k_hw_clocktoh(AR5K_REG_MS(0xffffffff, AR5K_TIME_OUT_ACK),
			ah->ah_turbo) <= timeout)
		return -EINVAL;

	AR5K_REG_WRITE_BITS(ah, AR5K_TIME_OUT, AR5K_TIME_OUT_ACK,
		ath5k_hw_htoclock(timeout, ah->ah_turbo));

	return 0;
}

/**
 * ath5k_hw_get_cts_timeout - Get CTS timeout from PCU in usec
 *
 * @ah: The &struct ath5k_hw
 */
unsigned int ath5k_hw_get_cts_timeout(struct ath5k_hw *ah)
{
	return ath5k_hw_clocktoh(AR5K_REG_MS(ath5k_hw_reg_read(ah,
			AR5K_TIME_OUT), AR5K_TIME_OUT_CTS), ah->ah_turbo);
}

/**
 * ath5k_hw_set_cts_timeout - Set CTS timeout on PCU
 *
 * @ah: The &struct ath5k_hw
 * @timeout: Timeout in usec
 */
int ath5k_hw_set_cts_timeout(struct ath5k_hw *ah, unsigned int timeout)
{
	if (ath5k_hw_clocktoh(AR5K_REG_MS(0xffffffff, AR5K_TIME_OUT_CTS),
			ah->ah_turbo) <= timeout)
		return -EINVAL;

	AR5K_REG_WRITE_BITS(ah, AR5K_TIME_OUT, AR5K_TIME_OUT_CTS,
			ath5k_hw_htoclock(timeout, ah->ah_turbo));

	return 0;
}


/****************\
* BSSID handling *
\****************/

/**
 * ath5k_hw_get_lladdr - Get station id
 *
 * @ah: The &struct ath5k_hw
 * @mac: The card's mac address
 *
 * Initialize ah->ah_sta_id using the mac address provided
 * (just a memcpy).
 *
 * TODO: Remove it once we merge ath5k_softc and ath5k_hw
 */
void ath5k_hw_get_lladdr(struct ath5k_hw *ah, u8 *mac)
{
	memcpy(mac, ah->ah_sta_id, ETH_ALEN);
}

/**
 * ath5k_hw_set_lladdr - Set station id
 *
 * @ah: The &struct ath5k_hw
 * @mac: The card's mac address
 *
 * Set station id on hw using the provided mac address
 */
int ath5k_hw_set_lladdr(struct ath5k_hw *ah, const u8 *mac)
{
	u32 low_id, high_id;
	u32 pcu_reg;

	/* Set new station ID */
	memcpy(ah->ah_sta_id, mac, ETH_ALEN);

	pcu_reg = ath5k_hw_reg_read(ah, AR5K_STA_ID1) & 0xffff0000;

	low_id = AR5K_LOW_ID(mac);
	high_id = AR5K_HIGH_ID(mac);

	ath5k_hw_reg_write(ah, low_id, AR5K_STA_ID0);
	ath5k_hw_reg_write(ah, pcu_reg | high_id, AR5K_STA_ID1);

	return 0;
}

/**
 * ath5k_hw_set_associd - Set BSSID for association
 *
 * @ah: The &struct ath5k_hw
 * @bssid: BSSID
 * @assoc_id: Assoc id
 *
 * Sets the BSSID which trigers the "SME Join" operation
 */
void ath5k_hw_set_associd(struct ath5k_hw *ah, const u8 *bssid, u16 assoc_id)
{
	u32 low_id, high_id;

	/*
	 * Set simple BSSID mask on 5212
	 */
	if (ah->ah_version == AR5K_AR5212) {
		ath5k_hw_reg_write(ah, AR5K_LOW_ID(ah->ah_bssid_mask),
							AR5K_BSS_IDM0);
		ath5k_hw_reg_write(ah, AR5K_HIGH_ID(ah->ah_bssid_mask),
							AR5K_BSS_IDM1);
	}

	/*
	 * Set BSSID which triggers the "SME Join" operation
	 */
	low_id = AR5K_LOW_ID(bssid);
	high_id = AR5K_HIGH_ID(bssid);
	ath5k_hw_reg_write(ah, low_id, AR5K_BSS_ID0);
	ath5k_hw_reg_write(ah, high_id | ((assoc_id & 0x3fff) <<
				AR5K_BSS_ID1_AID_S), AR5K_BSS_ID1);
}

/**
 * ath5k_hw_set_bssid_mask - filter out bssids we listen
 *
 * @ah: the &struct ath5k_hw
 * @mask: the bssid_mask, a u8 array of size ETH_ALEN
 *
 * BSSID masking is a method used by AR5212 and newer hardware to inform PCU
 * which bits of the interface's MAC address should be looked at when trying
 * to decide which packets to ACK. In station mode and AP mode with a single
 * BSS every bit matters since we lock to only one BSS. In AP mode with
 * multiple BSSes (virtual interfaces) not every bit matters because hw must
 * accept frames for all BSSes and so we tweak some bits of our mac address
 * in order to have multiple BSSes.
 *
 * NOTE: This is a simple filter and does *not* filter out all
 * relevant frames. Some frames that are not for us might get ACKed from us
 * by PCU because they just match the mask.
 *
 * When handling multiple BSSes you can get the BSSID mask by computing the
 * set of  ~ ( MAC XOR BSSID ) for all bssids we handle.
 *
 * When you do this you are essentially computing the common bits of all your
 * BSSes. Later it is assumed the harware will "and" (&) the BSSID mask with
 * the MAC address to obtain the relevant bits and compare the result with
 * (frame's BSSID & mask) to see if they match.
 */
/*
 * Simple example: on your card you have have two BSSes you have created with
 * BSSID-01 and BSSID-02. Lets assume BSSID-01 will not use the MAC address.
 * There is another BSSID-03 but you are not part of it. For simplicity's sake,
 * assuming only 4 bits for a mac address and for BSSIDs you can then have:
 *
 *                  \
 * MAC:                0001 |
 * BSSID-01:   0100 | --> Belongs to us
 * BSSID-02:   1001 |
 *                  /
 * -------------------
 * BSSID-03:   0110  | --> External
 * -------------------
 *
 * Our bssid_mask would then be:
 *
 *             On loop iteration for BSSID-01:
 *             ~(0001 ^ 0100)  -> ~(0101)
 *                             ->   1010
 *             bssid_mask      =    1010
 *
 *             On loop iteration for BSSID-02:
 *             bssid_mask &= ~(0001   ^   1001)
 *             bssid_mask =   (1010)  & ~(0001 ^ 1001)
 *             bssid_mask =   (1010)  & ~(1001)
 *             bssid_mask =   (1010)  &  (0110)
 *             bssid_mask =   0010
 *
 * A bssid_mask of 0010 means "only pay attention to the second least
 * significant bit". This is because its the only bit common
 * amongst the MAC and all BSSIDs we support. To findout what the real
 * common bit is we can simply "&" the bssid_mask now with any BSSID we have
 * or our MAC address (we assume the hardware uses the MAC address).
 *
 * Now, suppose there's an incoming frame for BSSID-03:
 *
 * IFRAME-01:  0110
 *
 * An easy eye-inspeciton of this already should tell you that this frame
 * will not pass our check. This is beacuse the bssid_mask tells the
 * hardware to only look at the second least significant bit and the
 * common bit amongst the MAC and BSSIDs is 0, this frame has the 2nd LSB
 * as 1, which does not match 0.
 *
 * So with IFRAME-01 we *assume* the hardware will do:
 *
 *     allow = (IFRAME-01 & bssid_mask) == (bssid_mask & MAC) ? 1 : 0;
 *  --> allow = (0110 & 0010) == (0010 & 0001) ? 1 : 0;
 *  --> allow = (0010) == 0000 ? 1 : 0;
 *  --> allow = 0
 *
 *  Lets now test a frame that should work:
 *
 * IFRAME-02:  0001 (we should allow)
 *
 *     allow = (0001 & 1010) == 1010
 *
 *     allow = (IFRAME-02 & bssid_mask) == (bssid_mask & MAC) ? 1 : 0;
 *  --> allow = (0001 & 0010) ==  (0010 & 0001) ? 1 :0;
 *  --> allow = (0010) == (0010)
 *  --> allow = 1
 *
 * Other examples:
 *
 * IFRAME-03:  0100 --> allowed
 * IFRAME-04:  1001 --> allowed
 * IFRAME-05:  1101 --> allowed but its not for us!!!
 *
 */
int ath5k_hw_set_bssid_mask(struct ath5k_hw *ah, const u8 *mask)
{
	u32 low_id, high_id;

	/* Cache bssid mask so that we can restore it
	 * on reset */
	memcpy(ah->ah_bssid_mask, mask, ETH_ALEN);
	if (ah->ah_version == AR5K_AR5212) {
		low_id = AR5K_LOW_ID(mask);
		high_id = AR5K_HIGH_ID(mask);

		ath5k_hw_reg_write(ah, low_id, AR5K_BSS_IDM0);
		ath5k_hw_reg_write(ah, high_id, AR5K_BSS_IDM1);

		return 0;
	}

	return -EIO;
}


/************\
* RX Control *
\************/

/**
 * ath5k_hw_start_rx_pcu - Start RX engine
 *
 * @ah: The &struct ath5k_hw
 *
 * Starts RX engine on PCU so that hw can process RXed frames
 * (ACK etc).
 *
 * NOTE: RX DMA should be already enabled using ath5k_hw_start_rx_dma
 * TODO: Init ANI here
 */
void ath5k_hw_start_rx_pcu(struct ath5k_hw *ah)
{
	AR5K_REG_DISABLE_BITS(ah, AR5K_DIAG_SW, AR5K_DIAG_SW_DIS_RX);
}

/**
 * at5k_hw_stop_rx_pcu - Stop RX engine
 *
 * @ah: The &struct ath5k_hw
 *
 * Stops RX engine on PCU
 *
 * TODO: Detach ANI here
 */
void ath5k_hw_stop_rx_pcu(struct ath5k_hw *ah)
{
	AR5K_REG_ENABLE_BITS(ah, AR5K_DIAG_SW, AR5K_DIAG_SW_DIS_RX);
}

/*
 * Set multicast filter
 */
void ath5k_hw_set_mcast_filter(struct ath5k_hw *ah, u32 filter0, u32 filter1)
{
	/* Set the multicat filter */
	ath5k_hw_reg_write(ah, filter0, AR5K_MCAST_FILTER0);
	ath5k_hw_reg_write(ah, filter1, AR5K_MCAST_FILTER1);
}

/**
 * ath5k_hw_get_rx_filter - Get current rx filter
 *
 * @ah: The &struct ath5k_hw
 *
 * Returns the RX filter by reading rx filter and
 * phy error filter registers. RX filter is used
 * to set the allowed frame types that PCU will accept
 * and pass to the driver. For a list of frame types
 * check out reg.h.
 */
u32 ath5k_hw_get_rx_filter(struct ath5k_hw *ah)
{
	u32 data, filter = 0;

	filter = ath5k_hw_reg_read(ah, AR5K_RX_FILTER);

	/*Radar detection for 5212*/
	if (ah->ah_version == AR5K_AR5212) {
		data = ath5k_hw_reg_read(ah, AR5K_PHY_ERR_FIL);

		if (data & AR5K_PHY_ERR_FIL_RADAR)
			filter |= AR5K_RX_FILTER_RADARERR;
		if (data & (AR5K_PHY_ERR_FIL_OFDM | AR5K_PHY_ERR_FIL_CCK))
			filter |= AR5K_RX_FILTER_PHYERR;
	}

	return filter;
}

/**
 * ath5k_hw_set_rx_filter - Set rx filter
 *
 * @ah: The &struct ath5k_hw
 * @filter: RX filter mask (see reg.h)
 *
 * Sets RX filter register and also handles PHY error filter
 * register on 5212 and newer chips so that we have proper PHY
 * error reporting.
 */
void ath5k_hw_set_rx_filter(struct ath5k_hw *ah, u32 filter)
{
	u32 data = 0;

	/* Set PHY error filter register on 5212*/
	if (ah->ah_version == AR5K_AR5212) {
		if (filter & AR5K_RX_FILTER_RADARERR)
			data |= AR5K_PHY_ERR_FIL_RADAR;
		if (filter & AR5K_RX_FILTER_PHYERR)
			data |= AR5K_PHY_ERR_FIL_OFDM | AR5K_PHY_ERR_FIL_CCK;
	}

	/*
	 * The AR5210 uses promiscous mode to detect radar activity
	 */
	if (ah->ah_version == AR5K_AR5210 &&
			(filter & AR5K_RX_FILTER_RADARERR)) {
		filter &= ~AR5K_RX_FILTER_RADARERR;
		filter |= AR5K_RX_FILTER_PROM;
	}

	/*Zero length DMA (phy error reporting) */
	if (data)
		AR5K_REG_ENABLE_BITS(ah, AR5K_RXCFG, AR5K_RXCFG_ZLFDMA);
	else
		AR5K_REG_DISABLE_BITS(ah, AR5K_RXCFG, AR5K_RXCFG_ZLFDMA);

	/*Write RX Filter register*/
	ath5k_hw_reg_write(ah, filter & 0xff, AR5K_RX_FILTER);

	/*Write PHY error filter register on 5212*/
	if (ah->ah_version == AR5K_AR5212)
		ath5k_hw_reg_write(ah, data, AR5K_PHY_ERR_FIL);

}

/*********************\
* Key table functions *
\*********************/

/*
 * Reset a key entry on the table
 */
int ath5k_hw_reset_key(struct ath5k_hw *ah, u16 entry)
{
	unsigned int i, type;
	u16 micentry = entry + AR5K_KEYTABLE_MIC_OFFSET;

	type = ath5k_hw_reg_read(ah, AR5K_KEYTABLE_TYPE(entry));

	for (i = 0; i < AR5K_KEYCACHE_SIZE; i++)
		ath5k_hw_reg_write(ah, 0, AR5K_KEYTABLE_OFF(entry, i));

	/* Reset associated MIC entry if TKIP
	 * is enabled located at offset (entry + 64) */
	if (type == AR5K_KEYTABLE_TYPE_TKIP) {
		for (i = 0; i < AR5K_KEYCACHE_SIZE / 2 ; i++)
			ath5k_hw_reg_write(ah, 0,
				AR5K_KEYTABLE_OFF(micentry, i));
	}

	/*
	 * Set NULL encryption on AR5212+
	 *
	 * Note: AR5K_KEYTABLE_TYPE -> AR5K_KEYTABLE_OFF(entry, 5)
	 *       AR5K_KEYTABLE_TYPE_NULL -> 0x00000007
	 *
	 * Note2: Windows driver (ndiswrapper) sets this to
	 *        0x00000714 instead of 0x00000007
	 */
	if (ah->ah_version >= AR5K_AR5211) {
		ath5k_hw_reg_write(ah, AR5K_KEYTABLE_TYPE_NULL,
				AR5K_KEYTABLE_TYPE(entry));

		if (type == AR5K_KEYTABLE_TYPE_TKIP) {
			ath5k_hw_reg_write(ah, AR5K_KEYTABLE_TYPE_NULL,
				AR5K_KEYTABLE_TYPE(micentry));
		}
	}

	return 0;
}
