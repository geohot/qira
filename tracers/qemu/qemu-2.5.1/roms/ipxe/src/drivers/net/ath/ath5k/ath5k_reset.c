/*
 * Copyright (c) 2004-2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006-2008 Nick Kossifidis <mickflemm@gmail.com>
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

#define _ATH5K_RESET

/*****************************\
  Reset functions and helpers
\*****************************/

#include <ipxe/pci.h> 		/* To determine if a card is pci-e */
#include <unistd.h>

#include "ath5k.h"
#include "reg.h"
#include "base.h"

/* Find last set bit; fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32 */
static int fls(int x)
{
        int r = 32;

        if (!x)
                return 0;
        if (!(x & 0xffff0000u)) {
                x <<= 16;
                r -= 16;
        }
        if (!(x & 0xff000000u)) {
                x <<= 8;
                r -= 8;
        }
        if (!(x & 0xf0000000u)) {
                x <<= 4;
                r -= 4;
        }
        if (!(x & 0xc0000000u)) {
                x <<= 2;
                r -= 2;
        }
        if (!(x & 0x80000000u)) {
                x <<= 1;
                r -= 1;
        }
        return r;
}


/**
 * ath5k_hw_write_ofdm_timings - set OFDM timings on AR5212
 *
 * @ah: the &struct ath5k_hw
 * @channel: the currently set channel upon reset
 *
 * Write the delta slope coefficient (used on pilot tracking ?) for OFDM
 * operation on the AR5212 upon reset. This is a helper for ath5k_hw_reset().
 *
 * Since delta slope is floating point we split it on its exponent and
 * mantissa and provide these values on hw.
 *
 * For more infos i think this patent is related
 * http://www.freepatentsonline.com/7184495.html
 */
static int ath5k_hw_write_ofdm_timings(struct ath5k_hw *ah,
	struct net80211_channel *channel)
{
	/* Get exponent and mantissa and set it */
	u32 coef_scaled, coef_exp, coef_man,
		ds_coef_exp, ds_coef_man, clock;

	if (!(ah->ah_version == AR5K_AR5212) ||
	    !(channel->hw_value & CHANNEL_OFDM)) {
		DBG("ath5k: attempt to set OFDM timings on non-OFDM channel\n");
		return -EFAULT;
	}

	/* Get coefficient
	 * ALGO: coef = (5 * clock * carrier_freq) / 2)
	 * we scale coef by shifting clock value by 24 for
	 * better precision since we use integers */
	/* TODO: Half/quarter rate */
	clock =  ath5k_hw_htoclock(1, channel->hw_value & CHANNEL_TURBO);

	coef_scaled = ((5 * (clock << 24)) / 2) / channel->center_freq;

	/* Get exponent
	 * ALGO: coef_exp = 14 - highest set bit position */
	coef_exp = fls(coef_scaled) - 1;

	/* Doesn't make sense if it's zero*/
	if (!coef_scaled || !coef_exp)
		return -EINVAL;

	/* Note: we've shifted coef_scaled by 24 */
	coef_exp = 14 - (coef_exp - 24);


	/* Get mantissa (significant digits)
	 * ALGO: coef_mant = floor(coef_scaled* 2^coef_exp+0.5) */
	coef_man = coef_scaled +
		(1 << (24 - coef_exp - 1));

	/* Calculate delta slope coefficient exponent
	 * and mantissa (remove scaling) and set them on hw */
	ds_coef_man = coef_man >> (24 - coef_exp);
	ds_coef_exp = coef_exp - 16;

	AR5K_REG_WRITE_BITS(ah, AR5K_PHY_TIMING_3,
		AR5K_PHY_TIMING_3_DSC_MAN, ds_coef_man);
	AR5K_REG_WRITE_BITS(ah, AR5K_PHY_TIMING_3,
		AR5K_PHY_TIMING_3_DSC_EXP, ds_coef_exp);

	return 0;
}


/*
 * index into rates for control rates, we can set it up like this because
 * this is only used for AR5212 and we know it supports G mode
 */
static const unsigned int control_rates[] =
	{ 0, 1, 1, 1, 4, 4, 6, 6, 8, 8, 8, 8 };

/**
 * ath5k_hw_write_rate_duration - fill rate code to duration table
 *
 * @ah: the &struct ath5k_hw
 * @mode: one of enum ath5k_driver_mode
 *
 * Write the rate code to duration table upon hw reset. This is a helper for
 * ath5k_hw_reset(). It seems all this is doing is setting an ACK timeout on
 * the hardware, based on current mode, for each rate. The rates which are
 * capable of short preamble (802.11b rates 2Mbps, 5.5Mbps, and 11Mbps) have
 * different rate code so we write their value twice (one for long preample
 * and one for short).
 *
 * Note: Band doesn't matter here, if we set the values for OFDM it works
 * on both a and g modes. So all we have to do is set values for all g rates
 * that include all OFDM and CCK rates. If we operate in turbo or xr/half/
 * quarter rate mode, we need to use another set of bitrates (that's why we
 * need the mode parameter) but we don't handle these proprietary modes yet.
 */
static inline void ath5k_hw_write_rate_duration(struct ath5k_hw *ah,
       unsigned int mode __unused)
{
	struct ath5k_softc *sc = ah->ah_sc;
	u16 rate;
	int i;

	/* Write rate duration table */
	for (i = 0; i < sc->hwinfo->nr_rates[NET80211_BAND_2GHZ]; i++) {
		u32 reg;
		u16 tx_time;

		rate = sc->hwinfo->rates[NET80211_BAND_2GHZ][i];

		/* Set ACK timeout */
		reg = AR5K_RATE_DUR(ath5k_bitrate_to_hw_rix(rate));

		/* An ACK frame consists of 10 bytes. If you add the FCS,
		 * it's 14 bytes. Note we use the control rate and not the
		 * actual rate for this rate. See mac80211 tx.c
		 * ieee80211_duration() for a brief description of
		 * what rate we should choose to TX ACKs. */
		tx_time = net80211_duration(sc->dev, 14, rate);

		ath5k_hw_reg_write(ah, tx_time, reg);

		if (rate != 20 && rate != 55 && rate != 110)
			continue;

		/*
		 * We're not distinguishing short preamble here,
		 * This is true, all we'll get is a longer value here
		 * which is not necessarilly bad.
		 */
		ath5k_hw_reg_write(ah, tx_time,
			reg + (AR5K_SET_SHORT_PREAMBLE << 2));
	}
}

/*
 * Reset chipset
 */
static int ath5k_hw_nic_reset(struct ath5k_hw *ah, u32 val)
{
	int ret;
	u32 mask = val ? val : ~0U;

	/* Read-and-clear RX Descriptor Pointer*/
	ath5k_hw_reg_read(ah, AR5K_RXDP);

	/*
	 * Reset the device and wait until success
	 */
	ath5k_hw_reg_write(ah, val, AR5K_RESET_CTL);

	/* Wait at least 128 PCI clocks */
	udelay(15);

	if (ah->ah_version == AR5K_AR5210) {
		val &= AR5K_RESET_CTL_PCU | AR5K_RESET_CTL_DMA
			| AR5K_RESET_CTL_MAC | AR5K_RESET_CTL_PHY;
		mask &= AR5K_RESET_CTL_PCU | AR5K_RESET_CTL_DMA
			| AR5K_RESET_CTL_MAC | AR5K_RESET_CTL_PHY;
	} else {
		val &= AR5K_RESET_CTL_PCU | AR5K_RESET_CTL_BASEBAND;
		mask &= AR5K_RESET_CTL_PCU | AR5K_RESET_CTL_BASEBAND;
	}

	ret = ath5k_hw_register_timeout(ah, AR5K_RESET_CTL, mask, val, 0);

	/*
	 * Reset configuration register (for hw byte-swap). Note that this
	 * is only set for big endian. We do the necessary magic in
	 * AR5K_INIT_CFG.
	 */
	if ((val & AR5K_RESET_CTL_PCU) == 0)
		ath5k_hw_reg_write(ah, AR5K_INIT_CFG, AR5K_CFG);

	return ret;
}

/*
 * Sleep control
 */
int ath5k_hw_wake(struct ath5k_hw *ah)
{
	unsigned int i;
	u32 staid, data;

	staid = ath5k_hw_reg_read(ah, AR5K_STA_ID1);
	staid &= ~AR5K_STA_ID1_PWR_SV;

	/* Preserve sleep duration */
	data = ath5k_hw_reg_read(ah, AR5K_SLEEP_CTL);
	if (data & 0xffc00000)
		data = 0;
	else
		data = data & 0xfffcffff;

	ath5k_hw_reg_write(ah, data, AR5K_SLEEP_CTL);
	udelay(15);

	for (i = 50; i > 0; i--) {
		/* Check if the chip did wake up */
		if ((ath5k_hw_reg_read(ah, AR5K_PCICFG) &
		     AR5K_PCICFG_SPWR_DN) == 0)
			break;

		/* Wait a bit and retry */
		udelay(200);
		ath5k_hw_reg_write(ah, data, AR5K_SLEEP_CTL);
	}

	/* Fail if the chip didn't wake up */
	if (i <= 0)
		return -EIO;

	ath5k_hw_reg_write(ah, staid, AR5K_STA_ID1);

	return 0;
}

/*
 * Bring up MAC + PHY Chips and program PLL
 * TODO: Half/Quarter rate support
 */
int ath5k_hw_nic_wakeup(struct ath5k_hw *ah, int flags, int initial __unused)
{
	struct pci_device *pdev = ah->ah_sc->pdev;
	u32 turbo, mode, clock, bus_flags;
	int ret;

	turbo = 0;
	mode = 0;
	clock = 0;

	/* Wakeup the device */
	ret = ath5k_hw_wake(ah);
	if (ret) {
		DBG("ath5k: failed to wake up the MAC chip\n");
		return ret;
	}

	if (ah->ah_version != AR5K_AR5210) {
		/*
		 * Get channel mode flags
		 */

		if (ah->ah_radio >= AR5K_RF5112) {
			mode = AR5K_PHY_MODE_RAD_RF5112;
			clock = AR5K_PHY_PLL_RF5112;
		} else {
			mode = AR5K_PHY_MODE_RAD_RF5111;	/*Zero*/
			clock = AR5K_PHY_PLL_RF5111;		/*Zero*/
		}

		if (flags & CHANNEL_2GHZ) {
			mode |= AR5K_PHY_MODE_FREQ_2GHZ;
			clock |= AR5K_PHY_PLL_44MHZ;

			if (flags & CHANNEL_CCK) {
				mode |= AR5K_PHY_MODE_MOD_CCK;
			} else if (flags & CHANNEL_OFDM) {
				/* XXX Dynamic OFDM/CCK is not supported by the
				 * AR5211 so we set MOD_OFDM for plain g (no
				 * CCK headers) operation. We need to test
				 * this, 5211 might support ofdm-only g after
				 * all, there are also initial register values
				 * in the code for g mode (see initvals.c). */
				if (ah->ah_version == AR5K_AR5211)
					mode |= AR5K_PHY_MODE_MOD_OFDM;
				else
					mode |= AR5K_PHY_MODE_MOD_DYN;
			} else {
				DBG("ath5k: invalid radio modulation mode\n");
				return -EINVAL;
			}
		} else if (flags & CHANNEL_5GHZ) {
			mode |= AR5K_PHY_MODE_FREQ_5GHZ;

			if (ah->ah_radio == AR5K_RF5413)
				clock = AR5K_PHY_PLL_40MHZ_5413;
			else
				clock |= AR5K_PHY_PLL_40MHZ;

			if (flags & CHANNEL_OFDM)
				mode |= AR5K_PHY_MODE_MOD_OFDM;
			else {
				DBG("ath5k: invalid radio modulation mode\n");
				return -EINVAL;
			}
		} else {
			DBG("ath5k: invalid radio frequency mode\n");
			return -EINVAL;
		}

		if (flags & CHANNEL_TURBO)
			turbo = AR5K_PHY_TURBO_MODE | AR5K_PHY_TURBO_SHORT;
	} else { /* Reset the device */

		/* ...enable Atheros turbo mode if requested */
		if (flags & CHANNEL_TURBO)
			ath5k_hw_reg_write(ah, AR5K_PHY_TURBO_MODE,
					AR5K_PHY_TURBO);
	}

	/* reseting PCI on PCI-E cards results card to hang
	 * and always return 0xffff... so we ingore that flag
	 * for PCI-E cards */
	if (pci_find_capability(pdev, PCI_CAP_ID_EXP))
		bus_flags = 0;
	else
		bus_flags = AR5K_RESET_CTL_PCI;

	/* Reset chipset */
	if (ah->ah_version == AR5K_AR5210) {
		ret = ath5k_hw_nic_reset(ah, AR5K_RESET_CTL_PCU |
			AR5K_RESET_CTL_MAC | AR5K_RESET_CTL_DMA |
			AR5K_RESET_CTL_PHY | AR5K_RESET_CTL_PCI);
		mdelay(2);
	} else {
		ret = ath5k_hw_nic_reset(ah, AR5K_RESET_CTL_PCU |
			AR5K_RESET_CTL_BASEBAND | bus_flags);
	}
	if (ret) {
		DBG("ath5k: failed to reset the MAC chip\n");
		return -EIO;
	}

	/* ...wakeup again!*/
	ret = ath5k_hw_wake(ah);
	if (ret) {
		DBG("ath5k: failed to resume the MAC chip\n");
		return ret;
	}

	/* ...final warm reset */
	if (ath5k_hw_nic_reset(ah, 0)) {
		DBG("ath5k: failed to warm reset the MAC chip\n");
		return -EIO;
	}

	if (ah->ah_version != AR5K_AR5210) {

		/* ...update PLL if needed */
		if (ath5k_hw_reg_read(ah, AR5K_PHY_PLL) != clock) {
			ath5k_hw_reg_write(ah, clock, AR5K_PHY_PLL);
			udelay(300);
		}

		/* ...set the PHY operating mode */
		ath5k_hw_reg_write(ah, mode, AR5K_PHY_MODE);
		ath5k_hw_reg_write(ah, turbo, AR5K_PHY_TURBO);
	}

	return 0;
}

static int ath5k_hw_chan_has_spur_noise(struct ath5k_hw *ah,
				struct net80211_channel *channel)
{
	u8 refclk_freq;

	if ((ah->ah_radio == AR5K_RF5112) ||
	(ah->ah_radio == AR5K_RF5413) ||
	(ah->ah_mac_version == (AR5K_SREV_AR2417 >> 4)))
		refclk_freq = 40;
	else
		refclk_freq = 32;

	if ((channel->center_freq % refclk_freq != 0) &&
	((channel->center_freq % refclk_freq < 10) ||
	(channel->center_freq % refclk_freq > 22)))
		return 1;
	else
		return 0;
}

/* TODO: Half/Quarter rate */
static void ath5k_hw_tweak_initval_settings(struct ath5k_hw *ah,
				struct net80211_channel *channel)
{
	if (ah->ah_version == AR5K_AR5212 &&
	    ah->ah_phy_revision >= AR5K_SREV_PHY_5212A) {

		/* Setup ADC control */
		ath5k_hw_reg_write(ah,
				(AR5K_REG_SM(2,
				AR5K_PHY_ADC_CTL_INBUFGAIN_OFF) |
				AR5K_REG_SM(2,
				AR5K_PHY_ADC_CTL_INBUFGAIN_ON) |
				AR5K_PHY_ADC_CTL_PWD_DAC_OFF |
				AR5K_PHY_ADC_CTL_PWD_ADC_OFF),
				AR5K_PHY_ADC_CTL);



		/* Disable barker RSSI threshold */
		AR5K_REG_DISABLE_BITS(ah, AR5K_PHY_DAG_CCK_CTL,
				AR5K_PHY_DAG_CCK_CTL_EN_RSSI_THR);

		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_DAG_CCK_CTL,
			AR5K_PHY_DAG_CCK_CTL_RSSI_THR, 2);

		/* Set the mute mask */
		ath5k_hw_reg_write(ah, 0x0000000f, AR5K_SEQ_MASK);
	}

	/* Clear PHY_BLUETOOTH to allow RX_CLEAR line debug */
	if (ah->ah_phy_revision >= AR5K_SREV_PHY_5212B)
		ath5k_hw_reg_write(ah, 0, AR5K_PHY_BLUETOOTH);

	/* Enable DCU double buffering */
	if (ah->ah_phy_revision > AR5K_SREV_PHY_5212B)
		AR5K_REG_DISABLE_BITS(ah, AR5K_TXCFG,
				AR5K_TXCFG_DCU_DBL_BUF_DIS);

	/* Set DAC/ADC delays */
	if (ah->ah_version == AR5K_AR5212) {
		u32 scal;
		if (ah->ah_mac_version == (AR5K_SREV_AR2417 >> 4))
			scal = AR5K_PHY_SCAL_32MHZ_2417;
		else if (ath5k_eeprom_is_hb63(ah))
			scal = AR5K_PHY_SCAL_32MHZ_HB63;
		else
			scal = AR5K_PHY_SCAL_32MHZ;
		ath5k_hw_reg_write(ah, scal, AR5K_PHY_SCAL);
	}

	/* Set fast ADC */
	if ((ah->ah_radio == AR5K_RF5413) ||
	(ah->ah_mac_version == (AR5K_SREV_AR2417 >> 4))) {
		u32 fast_adc = 1;

		if (channel->center_freq == 2462 ||
		channel->center_freq == 2467)
			fast_adc = 0;

		/* Only update if needed */
		if (ath5k_hw_reg_read(ah, AR5K_PHY_FAST_ADC) != fast_adc)
				ath5k_hw_reg_write(ah, fast_adc,
						AR5K_PHY_FAST_ADC);
	}

	/* Fix for first revision of the RF5112 RF chipset */
	if (ah->ah_radio == AR5K_RF5112 &&
			ah->ah_radio_5ghz_revision <
			AR5K_SREV_RAD_5112A) {
		u32 data;
		ath5k_hw_reg_write(ah, AR5K_PHY_CCKTXCTL_WORLD,
				AR5K_PHY_CCKTXCTL);
		if (channel->hw_value & CHANNEL_5GHZ)
			data = 0xffb81020;
		else
			data = 0xffb80d20;
		ath5k_hw_reg_write(ah, data, AR5K_PHY_FRAME_CTL);
	}

	if (ah->ah_mac_srev < AR5K_SREV_AR5211) {
		u32 usec_reg;
		/* 5311 has different tx/rx latency masks
		 * from 5211, since we deal 5311 the same
		 * as 5211 when setting initvals, shift
		 * values here to their proper locations */
		usec_reg = ath5k_hw_reg_read(ah, AR5K_USEC_5211);
		ath5k_hw_reg_write(ah, usec_reg & (AR5K_USEC_1 |
				AR5K_USEC_32 |
				AR5K_USEC_TX_LATENCY_5211 |
				AR5K_REG_SM(29,
				AR5K_USEC_RX_LATENCY_5210)),
				AR5K_USEC_5211);
		/* Clear QCU/DCU clock gating register */
		ath5k_hw_reg_write(ah, 0, AR5K_QCUDCU_CLKGT);
		/* Set DAC/ADC delays */
		ath5k_hw_reg_write(ah, 0x08, AR5K_PHY_SCAL);
		/* Enable PCU FIFO corruption ECO */
		AR5K_REG_ENABLE_BITS(ah, AR5K_DIAG_SW_5211,
					AR5K_DIAG_SW_ECO_ENABLE);
	}
}

static void ath5k_hw_commit_eeprom_settings(struct ath5k_hw *ah,
		struct net80211_channel *channel, u8 *ant, u8 ee_mode)
{
	struct ath5k_eeprom_info *ee = &ah->ah_capabilities.cap_eeprom;
	s16 cck_ofdm_pwr_delta;

	/* Adjust power delta for channel 14 */
	if (channel->center_freq == 2484)
		cck_ofdm_pwr_delta =
			((ee->ee_cck_ofdm_power_delta -
			ee->ee_scaled_cck_delta) * 2) / 10;
	else
		cck_ofdm_pwr_delta =
			(ee->ee_cck_ofdm_power_delta * 2) / 10;

	/* Set CCK to OFDM power delta on tx power
	 * adjustment register */
	if (ah->ah_phy_revision >= AR5K_SREV_PHY_5212A) {
		if (channel->hw_value == CHANNEL_G)
			ath5k_hw_reg_write(ah,
			AR5K_REG_SM((ee->ee_cck_ofdm_gain_delta * -1),
				AR5K_PHY_TX_PWR_ADJ_CCK_GAIN_DELTA) |
			AR5K_REG_SM((cck_ofdm_pwr_delta * -1),
				AR5K_PHY_TX_PWR_ADJ_CCK_PCDAC_INDEX),
				AR5K_PHY_TX_PWR_ADJ);
		else
			ath5k_hw_reg_write(ah, 0, AR5K_PHY_TX_PWR_ADJ);
	} else {
		/* For older revs we scale power on sw during tx power
		 * setup */
		ah->ah_txpower.txp_cck_ofdm_pwr_delta = cck_ofdm_pwr_delta;
		ah->ah_txpower.txp_cck_ofdm_gainf_delta =
						ee->ee_cck_ofdm_gain_delta;
	}

	/* Set antenna idle switch table */
	AR5K_REG_WRITE_BITS(ah, AR5K_PHY_ANT_CTL,
			AR5K_PHY_ANT_CTL_SWTABLE_IDLE,
			(ah->ah_antenna[ee_mode][0] |
			AR5K_PHY_ANT_CTL_TXRX_EN));

	/* Set antenna switch table */
	ath5k_hw_reg_write(ah, ah->ah_antenna[ee_mode][ant[0]],
		AR5K_PHY_ANT_SWITCH_TABLE_0);
	ath5k_hw_reg_write(ah, ah->ah_antenna[ee_mode][ant[1]],
		AR5K_PHY_ANT_SWITCH_TABLE_1);

	/* Noise floor threshold */
	ath5k_hw_reg_write(ah,
		AR5K_PHY_NF_SVAL(ee->ee_noise_floor_thr[ee_mode]),
		AR5K_PHY_NFTHRES);

	if ((channel->hw_value & CHANNEL_TURBO) &&
	(ah->ah_ee_version >= AR5K_EEPROM_VERSION_5_0)) {
		/* Switch settling time (Turbo) */
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_SETTLING,
				AR5K_PHY_SETTLING_SWITCH,
				ee->ee_switch_settling_turbo[ee_mode]);

		/* Tx/Rx attenuation (Turbo) */
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_GAIN,
				AR5K_PHY_GAIN_TXRX_ATTEN,
				ee->ee_atn_tx_rx_turbo[ee_mode]);

		/* ADC/PGA desired size (Turbo) */
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_DESIRED_SIZE,
				AR5K_PHY_DESIRED_SIZE_ADC,
				ee->ee_adc_desired_size_turbo[ee_mode]);

		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_DESIRED_SIZE,
				AR5K_PHY_DESIRED_SIZE_PGA,
				ee->ee_pga_desired_size_turbo[ee_mode]);

		/* Tx/Rx margin (Turbo) */
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_GAIN_2GHZ,
				AR5K_PHY_GAIN_2GHZ_MARGIN_TXRX,
				ee->ee_margin_tx_rx_turbo[ee_mode]);

	} else {
		/* Switch settling time */
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_SETTLING,
				AR5K_PHY_SETTLING_SWITCH,
				ee->ee_switch_settling[ee_mode]);

		/* Tx/Rx attenuation */
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_GAIN,
				AR5K_PHY_GAIN_TXRX_ATTEN,
				ee->ee_atn_tx_rx[ee_mode]);

		/* ADC/PGA desired size */
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_DESIRED_SIZE,
				AR5K_PHY_DESIRED_SIZE_ADC,
				ee->ee_adc_desired_size[ee_mode]);

		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_DESIRED_SIZE,
				AR5K_PHY_DESIRED_SIZE_PGA,
				ee->ee_pga_desired_size[ee_mode]);

		/* Tx/Rx margin */
		if (ah->ah_ee_version >= AR5K_EEPROM_VERSION_4_1)
			AR5K_REG_WRITE_BITS(ah, AR5K_PHY_GAIN_2GHZ,
				AR5K_PHY_GAIN_2GHZ_MARGIN_TXRX,
				ee->ee_margin_tx_rx[ee_mode]);
	}

	/* XPA delays */
	ath5k_hw_reg_write(ah,
		(ee->ee_tx_end2xpa_disable[ee_mode] << 24) |
		(ee->ee_tx_end2xpa_disable[ee_mode] << 16) |
		(ee->ee_tx_frm2xpa_enable[ee_mode] << 8) |
		(ee->ee_tx_frm2xpa_enable[ee_mode]), AR5K_PHY_RF_CTL4);

	/* XLNA delay */
	AR5K_REG_WRITE_BITS(ah, AR5K_PHY_RF_CTL3,
			AR5K_PHY_RF_CTL3_TXE2XLNA_ON,
			ee->ee_tx_end2xlna_enable[ee_mode]);

	/* Thresh64 (ANI) */
	AR5K_REG_WRITE_BITS(ah, AR5K_PHY_NF,
			AR5K_PHY_NF_THRESH62,
			ee->ee_thr_62[ee_mode]);


	/* False detect backoff for channels
	 * that have spur noise. Write the new
	 * cyclic power RSSI threshold. */
	if (ath5k_hw_chan_has_spur_noise(ah, channel))
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_OFDM_SELFCORR,
				AR5K_PHY_OFDM_SELFCORR_CYPWR_THR1,
				AR5K_INIT_CYCRSSI_THR1 +
				ee->ee_false_detect[ee_mode]);
	else
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_OFDM_SELFCORR,
				AR5K_PHY_OFDM_SELFCORR_CYPWR_THR1,
				AR5K_INIT_CYCRSSI_THR1);

	/* I/Q correction
	 * TODO: Per channel i/q infos ? */
	AR5K_REG_ENABLE_BITS(ah, AR5K_PHY_IQ,
		AR5K_PHY_IQ_CORR_ENABLE |
		(ee->ee_i_cal[ee_mode] << AR5K_PHY_IQ_CORR_Q_I_COFF_S) |
		ee->ee_q_cal[ee_mode]);

	/* Heavy clipping -disable for now */
	if (ah->ah_ee_version >= AR5K_EEPROM_VERSION_5_1)
		ath5k_hw_reg_write(ah, 0, AR5K_PHY_HEAVY_CLIP_ENABLE);

	return;
}

/*
 * Main reset function
 */
int ath5k_hw_reset(struct ath5k_hw *ah,
	struct net80211_channel *channel, int change_channel)
{
	u32 s_seq[10], s_ant, s_led[3], staid1_flags;
	u32 phy_tst1;
	u8 mode, freq, ee_mode, ant[2];
	int i, ret;

	s_ant = 0;
	ee_mode = 0;
	staid1_flags = 0;
	freq = 0;
	mode = 0;

	/*
	 * Save some registers before a reset
	 */
	/*DCU/Antenna selection not available on 5210*/
	if (ah->ah_version != AR5K_AR5210) {

		switch (channel->hw_value & CHANNEL_MODES) {
		case CHANNEL_A:
			mode = AR5K_MODE_11A;
			freq = AR5K_INI_RFGAIN_5GHZ;
			ee_mode = AR5K_EEPROM_MODE_11A;
			break;
		case CHANNEL_G:
			mode = AR5K_MODE_11G;
			freq = AR5K_INI_RFGAIN_2GHZ;
			ee_mode = AR5K_EEPROM_MODE_11G;
			break;
		case CHANNEL_B:
			mode = AR5K_MODE_11B;
			freq = AR5K_INI_RFGAIN_2GHZ;
			ee_mode = AR5K_EEPROM_MODE_11B;
			break;
		case CHANNEL_T:
			mode = AR5K_MODE_11A_TURBO;
			freq = AR5K_INI_RFGAIN_5GHZ;
			ee_mode = AR5K_EEPROM_MODE_11A;
			break;
		case CHANNEL_TG:
			if (ah->ah_version == AR5K_AR5211) {
				DBG("ath5k: TurboG not available on 5211\n");
				return -EINVAL;
			}
			mode = AR5K_MODE_11G_TURBO;
			freq = AR5K_INI_RFGAIN_2GHZ;
			ee_mode = AR5K_EEPROM_MODE_11G;
			break;
		case CHANNEL_XR:
			if (ah->ah_version == AR5K_AR5211) {
				DBG("ath5k: XR mode not available on 5211\n");
				return -EINVAL;
			}
			mode = AR5K_MODE_XR;
			freq = AR5K_INI_RFGAIN_5GHZ;
			ee_mode = AR5K_EEPROM_MODE_11A;
			break;
		default:
			DBG("ath5k: invalid channel (%d MHz)\n",
			    channel->center_freq);
			return -EINVAL;
		}

		if (change_channel) {
			/*
			 * Save frame sequence count
			 * For revs. after Oahu, only save
			 * seq num for DCU 0 (Global seq num)
			 */
			if (ah->ah_mac_srev < AR5K_SREV_AR5211) {

				for (i = 0; i < 10; i++)
					s_seq[i] = ath5k_hw_reg_read(ah,
						AR5K_QUEUE_DCU_SEQNUM(i));

			} else {
				s_seq[0] = ath5k_hw_reg_read(ah,
						AR5K_QUEUE_DCU_SEQNUM(0));
			}
		}

		/* Save default antenna */
		s_ant = ath5k_hw_reg_read(ah, AR5K_DEFAULT_ANTENNA);

		if (ah->ah_version == AR5K_AR5212) {
			/* Since we are going to write rf buffer
			 * check if we have any pending gain_F
			 * optimization settings */
			if (change_channel && ah->ah_rf_banks != NULL)
				ath5k_hw_gainf_calibrate(ah);
		}
	}

	/*GPIOs*/
	s_led[0] = ath5k_hw_reg_read(ah, AR5K_PCICFG) &
					AR5K_PCICFG_LEDSTATE;
	s_led[1] = ath5k_hw_reg_read(ah, AR5K_GPIOCR);
	s_led[2] = ath5k_hw_reg_read(ah, AR5K_GPIODO);

	/* AR5K_STA_ID1 flags, only preserve antenna
	 * settings and ack/cts rate mode */
	staid1_flags = ath5k_hw_reg_read(ah, AR5K_STA_ID1) &
			(AR5K_STA_ID1_DEFAULT_ANTENNA |
			AR5K_STA_ID1_DESC_ANTENNA |
			AR5K_STA_ID1_RTS_DEF_ANTENNA |
			AR5K_STA_ID1_ACKCTS_6MB |
			AR5K_STA_ID1_BASE_RATE_11B |
			AR5K_STA_ID1_SELFGEN_DEF_ANT);

	/* Wakeup the device */
	ret = ath5k_hw_nic_wakeup(ah, channel->hw_value, 0);
	if (ret)
		return ret;

	/* PHY access enable */
	if (ah->ah_mac_srev >= AR5K_SREV_AR5211)
		ath5k_hw_reg_write(ah, AR5K_PHY_SHIFT_5GHZ, AR5K_PHY(0));
	else
		ath5k_hw_reg_write(ah, AR5K_PHY_SHIFT_5GHZ | 0x40,
							AR5K_PHY(0));

	/* Write initial settings */
	ret = ath5k_hw_write_initvals(ah, mode, change_channel);
	if (ret)
		return ret;

	/*
	 * 5211/5212 Specific
	 */
	if (ah->ah_version != AR5K_AR5210) {

		/*
		 * Write initial RF gain settings
		 * This should work for both 5111/5112
		 */
		ret = ath5k_hw_rfgain_init(ah, freq);
		if (ret)
			return ret;

		mdelay(1);

		/*
		 * Tweak initval settings for revised
		 * chipsets and add some more config
		 * bits
		 */
		ath5k_hw_tweak_initval_settings(ah, channel);

		/*
		 * Set TX power (FIXME)
		 */
		ret = ath5k_hw_txpower(ah, channel, ee_mode,
					AR5K_TUNE_DEFAULT_TXPOWER);
		if (ret)
			return ret;

		/* Write rate duration table only on AR5212 */
		if (ah->ah_version == AR5K_AR5212)
			ath5k_hw_write_rate_duration(ah, mode);

		/*
		 * Write RF buffer
		 */
		ret = ath5k_hw_rfregs_init(ah, channel, mode);
		if (ret)
			return ret;


		/* Write OFDM timings on 5212*/
		if (ah->ah_version == AR5K_AR5212 &&
			channel->hw_value & CHANNEL_OFDM) {
			ret = ath5k_hw_write_ofdm_timings(ah, channel);
			if (ret)
				return ret;
		}

		/*Enable/disable 802.11b mode on 5111
		(enable 2111 frequency converter + CCK)*/
		if (ah->ah_radio == AR5K_RF5111) {
			if (mode == AR5K_MODE_11B)
				AR5K_REG_ENABLE_BITS(ah, AR5K_TXCFG,
				    AR5K_TXCFG_B_MODE);
			else
				AR5K_REG_DISABLE_BITS(ah, AR5K_TXCFG,
				    AR5K_TXCFG_B_MODE);
		}

		/*
		 * In case a fixed antenna was set as default
		 * write the same settings on both AR5K_PHY_ANT_SWITCH_TABLE
		 * registers.
		 */
		if (s_ant != 0) {
			if (s_ant == AR5K_ANT_FIXED_A) /* 1 - Main */
				ant[0] = ant[1] = AR5K_ANT_FIXED_A;
			else	/* 2 - Aux */
				ant[0] = ant[1] = AR5K_ANT_FIXED_B;
		} else {
			ant[0] = AR5K_ANT_FIXED_A;
			ant[1] = AR5K_ANT_FIXED_B;
		}

		/* Commit values from EEPROM */
		ath5k_hw_commit_eeprom_settings(ah, channel, ant, ee_mode);

	} else {
		/*
		 * For 5210 we do all initialization using
		 * initvals, so we don't have to modify
		 * any settings (5210 also only supports
		 * a/aturbo modes)
		 */
		mdelay(1);
		/* Disable phy and wait */
		ath5k_hw_reg_write(ah, AR5K_PHY_ACT_DISABLE, AR5K_PHY_ACT);
		mdelay(1);
	}

	/*
	 * Restore saved values
	 */

	/*DCU/Antenna selection not available on 5210*/
	if (ah->ah_version != AR5K_AR5210) {

		if (change_channel) {
			if (ah->ah_mac_srev < AR5K_SREV_AR5211) {
				for (i = 0; i < 10; i++)
					ath5k_hw_reg_write(ah, s_seq[i],
						AR5K_QUEUE_DCU_SEQNUM(i));
			} else {
				ath5k_hw_reg_write(ah, s_seq[0],
					AR5K_QUEUE_DCU_SEQNUM(0));
			}
		}

		ath5k_hw_reg_write(ah, s_ant, AR5K_DEFAULT_ANTENNA);
	}

	/* Ledstate */
	AR5K_REG_ENABLE_BITS(ah, AR5K_PCICFG, s_led[0]);

	/* Gpio settings */
	ath5k_hw_reg_write(ah, s_led[1], AR5K_GPIOCR);
	ath5k_hw_reg_write(ah, s_led[2], AR5K_GPIODO);

	/* Restore sta_id flags and preserve our mac address*/
	ath5k_hw_reg_write(ah, AR5K_LOW_ID(ah->ah_sta_id),
						AR5K_STA_ID0);
	ath5k_hw_reg_write(ah, staid1_flags | AR5K_HIGH_ID(ah->ah_sta_id),
						AR5K_STA_ID1);


	/*
	 * Configure PCU
	 */

	/* Restore bssid and bssid mask */
	/* XXX: add ah->aid once mac80211 gives this to us */
	ath5k_hw_set_associd(ah, ah->ah_bssid, 0);

	/* Set PCU config */
	ath5k_hw_set_opmode(ah);

	/* Clear any pending interrupts
	 * PISR/SISR Not available on 5210 */
	if (ah->ah_version != AR5K_AR5210)
		ath5k_hw_reg_write(ah, 0xffffffff, AR5K_PISR);

	/* Set RSSI/BRSSI thresholds
	 *
	 * Note: If we decide to set this value
	 * dynamicaly, have in mind that when AR5K_RSSI_THR
	 * register is read it might return 0x40 if we haven't
	 * wrote anything to it plus BMISS RSSI threshold is zeroed.
	 * So doing a save/restore procedure here isn't the right
	 * choice. Instead store it on ath5k_hw */
	ath5k_hw_reg_write(ah, (AR5K_TUNE_RSSI_THRES |
				AR5K_TUNE_BMISS_THRES <<
				AR5K_RSSI_THR_BMISS_S),
				AR5K_RSSI_THR);

	/* MIC QoS support */
	if (ah->ah_mac_srev >= AR5K_SREV_AR2413) {
		ath5k_hw_reg_write(ah, 0x000100aa, AR5K_MIC_QOS_CTL);
		ath5k_hw_reg_write(ah, 0x00003210, AR5K_MIC_QOS_SEL);
	}

	/* QoS NOACK Policy */
	if (ah->ah_version == AR5K_AR5212) {
		ath5k_hw_reg_write(ah,
			AR5K_REG_SM(2, AR5K_QOS_NOACK_2BIT_VALUES) |
			AR5K_REG_SM(5, AR5K_QOS_NOACK_BIT_OFFSET)  |
			AR5K_REG_SM(0, AR5K_QOS_NOACK_BYTE_OFFSET),
			AR5K_QOS_NOACK);
	}


	/*
	 * Configure PHY
	 */

	/* Set channel on PHY */
	ret = ath5k_hw_channel(ah, channel);
	if (ret)
		return ret;

	/*
	 * Enable the PHY and wait until completion
	 * This includes BaseBand and Synthesizer
	 * activation.
	 */
	ath5k_hw_reg_write(ah, AR5K_PHY_ACT_ENABLE, AR5K_PHY_ACT);

	/*
	 * On 5211+ read activation -> rx delay
	 * and use it.
	 *
	 * TODO: Half/quarter rate support
	 */
	if (ah->ah_version != AR5K_AR5210) {
		u32 delay;
		delay = ath5k_hw_reg_read(ah, AR5K_PHY_RX_DELAY) &
			AR5K_PHY_RX_DELAY_M;
		delay = (channel->hw_value & CHANNEL_CCK) ?
			((delay << 2) / 22) : (delay / 10);

		udelay(100 + (2 * delay));
	} else {
		mdelay(1);
	}

	/*
	 * Perform ADC test to see if baseband is ready
	 * Set tx hold and check adc test register
	 */
	phy_tst1 = ath5k_hw_reg_read(ah, AR5K_PHY_TST1);
	ath5k_hw_reg_write(ah, AR5K_PHY_TST1_TXHOLD, AR5K_PHY_TST1);
	for (i = 0; i <= 20; i++) {
		if (!(ath5k_hw_reg_read(ah, AR5K_PHY_ADC_TEST) & 0x10))
			break;
		udelay(200);
	}
	ath5k_hw_reg_write(ah, phy_tst1, AR5K_PHY_TST1);

	/*
	 * Start automatic gain control calibration
	 *
	 * During AGC calibration RX path is re-routed to
	 * a power detector so we don't receive anything.
	 *
	 * This method is used to calibrate some static offsets
	 * used together with on-the fly I/Q calibration (the
	 * one performed via ath5k_hw_phy_calibrate), that doesn't
	 * interrupt rx path.
	 *
	 * While rx path is re-routed to the power detector we also
	 * start a noise floor calibration, to measure the
	 * card's noise floor (the noise we measure when we are not
	 * transmiting or receiving anything).
	 *
	 * If we are in a noisy environment AGC calibration may time
	 * out and/or noise floor calibration might timeout.
	 */
	AR5K_REG_ENABLE_BITS(ah, AR5K_PHY_AGCCTL,
				AR5K_PHY_AGCCTL_CAL);

	/* At the same time start I/Q calibration for QAM constellation
	 * -no need for CCK- */
	ah->ah_calibration = 0;
	if (!(mode == AR5K_MODE_11B)) {
		ah->ah_calibration = 1;
		AR5K_REG_WRITE_BITS(ah, AR5K_PHY_IQ,
				AR5K_PHY_IQ_CAL_NUM_LOG_MAX, 15);
		AR5K_REG_ENABLE_BITS(ah, AR5K_PHY_IQ,
				AR5K_PHY_IQ_RUN);
	}

	/* Wait for gain calibration to finish (we check for I/Q calibration
	 * during ath5k_phy_calibrate) */
	if (ath5k_hw_register_timeout(ah, AR5K_PHY_AGCCTL,
			AR5K_PHY_AGCCTL_CAL, 0, 0)) {
		DBG("ath5k: gain calibration timeout (%d MHz)\n",
		    channel->center_freq);
	}

	/*
	 * If we run NF calibration before AGC, it always times out.
	 * Binary HAL starts NF and AGC calibration at the same time
	 * and only waits for AGC to finish. Also if AGC or NF cal.
	 * times out, reset doesn't fail on binary HAL. I believe
	 * that's wrong because since rx path is routed to a detector,
	 * if cal. doesn't finish we won't have RX. Sam's HAL for AR5210/5211
	 * enables noise floor calibration after offset calibration and if noise
	 * floor calibration fails, reset fails. I believe that's
	 * a better approach, we just need to find a polling interval
	 * that suits best, even if reset continues we need to make
	 * sure that rx path is ready.
	 */
	ath5k_hw_noise_floor_calibration(ah, channel->center_freq);


	/*
	 * Configure QCUs/DCUs
	 */

	/* TODO: HW Compression support for data queues */
	/* TODO: Burst prefetch for data queues */

	/*
	 * Reset queues and start beacon timers at the end of the reset routine
	 * This also sets QCU mask on each DCU for 1:1 qcu to dcu mapping
	 * Note: If we want we can assign multiple qcus on one dcu.
	 */
	ret = ath5k_hw_reset_tx_queue(ah);
	if (ret) {
		DBG("ath5k: failed to reset TX queue\n");
		return ret;
	}

	/*
	 * Configure DMA/Interrupts
	 */

	/*
	 * Set Rx/Tx DMA Configuration
	 *
	 * Set standard DMA size (128). Note that
	 * a DMA size of 512 causes rx overruns and tx errors
	 * on pci-e cards (tested on 5424 but since rx overruns
	 * also occur on 5416/5418 with madwifi we set 128
	 * for all PCI-E cards to be safe).
	 *
	 * XXX: need to check 5210 for this
	 * TODO: Check out tx triger level, it's always 64 on dumps but I
	 * guess we can tweak it and see how it goes ;-)
	 */
	if (ah->ah_version != AR5K_AR5210) {
		AR5K_REG_WRITE_BITS(ah, AR5K_TXCFG,
			AR5K_TXCFG_SDMAMR, AR5K_DMASIZE_128B);
		AR5K_REG_WRITE_BITS(ah, AR5K_RXCFG,
			AR5K_RXCFG_SDMAMW, AR5K_DMASIZE_128B);
	}

	/* Pre-enable interrupts on 5211/5212*/
	if (ah->ah_version != AR5K_AR5210)
		ath5k_hw_set_imr(ah, ah->ah_imr);

	/*
	 * Setup RFKill interrupt if rfkill flag is set on eeprom.
	 * TODO: Use gpio pin and polarity infos from eeprom
	 * TODO: Handle this in ath5k_intr because it'll result
	 * 	 a nasty interrupt storm.
	 */
#if 0
	if (AR5K_EEPROM_HDR_RFKILL(ah->ah_capabilities.cap_eeprom.ee_header)) {
		ath5k_hw_set_gpio_input(ah, 0);
		ah->ah_gpio[0] = ath5k_hw_get_gpio(ah, 0);
		if (ah->ah_gpio[0] == 0)
			ath5k_hw_set_gpio_intr(ah, 0, 1);
		else
			ath5k_hw_set_gpio_intr(ah, 0, 0);
	}
#endif

	/*
	 * Disable beacons and reset the register
	 */
	AR5K_REG_DISABLE_BITS(ah, AR5K_BEACON, AR5K_BEACON_ENABLE |
			AR5K_BEACON_RESET_TSF);

	return 0;
}

#undef _ATH5K_RESET
