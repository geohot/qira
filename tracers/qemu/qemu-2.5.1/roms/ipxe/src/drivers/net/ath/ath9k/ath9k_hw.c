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

#include <ipxe/vsprintf.h>
#include <ipxe/io.h>

#include "hw.h"
#include "hw-ops.h"
#include "ar9003_mac.h"

static int ath9k_hw_set_reset_reg(struct ath_hw *ah, u32 type);

/* Private hardware callbacks */

static void ath9k_hw_init_cal_settings(struct ath_hw *ah)
{
	ath9k_hw_private_ops(ah)->init_cal_settings(ah);
}

static void ath9k_hw_init_mode_regs(struct ath_hw *ah)
{
	ath9k_hw_private_ops(ah)->init_mode_regs(ah);
}

static u32 ath9k_hw_compute_pll_control(struct ath_hw *ah,
					struct ath9k_channel *chan)
{
	return ath9k_hw_private_ops(ah)->compute_pll_control(ah, chan);
}

static void ath9k_hw_init_mode_gain_regs(struct ath_hw *ah)
{
	if (!ath9k_hw_private_ops(ah)->init_mode_gain_regs)
		return;

	ath9k_hw_private_ops(ah)->init_mode_gain_regs(ah);
}

static void ath9k_hw_ani_cache_ini_regs(struct ath_hw *ah)
{
	/* You will not have this callback if using the old ANI */
	if (!ath9k_hw_private_ops(ah)->ani_cache_ini_regs)
		return;

	ath9k_hw_private_ops(ah)->ani_cache_ini_regs(ah);
}

/********************/
/* Helper Functions */
/********************/

static void ath9k_hw_set_clockrate(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	struct net80211_device *dev = common->dev;
	unsigned int clockrate;

	if (!ah->curchan) /* should really check for CCK instead */
		clockrate = ATH9K_CLOCK_RATE_CCK;
	else if ((dev->channels + dev->channel)->band == NET80211_BAND_2GHZ)
		clockrate = ATH9K_CLOCK_RATE_2GHZ_OFDM;
	else if (ah->caps.hw_caps & ATH9K_HW_CAP_FASTCLOCK)
		clockrate = ATH9K_CLOCK_FAST_RATE_5GHZ_OFDM;
	else
		clockrate = ATH9K_CLOCK_RATE_5GHZ_OFDM;

	common->clockrate = clockrate;
}

static u32 ath9k_hw_mac_to_clks(struct ath_hw *ah, u32 usecs)
{
	struct ath_common *common = ath9k_hw_common(ah);

	return usecs * common->clockrate;
}

int ath9k_hw_wait(struct ath_hw *ah, u32 reg, u32 mask, u32 val, u32 timeout)
{
	unsigned int i;

	for (i = 0; i < (timeout / AH_TIME_QUANTUM); i++) {
		if ((REG_READ(ah, reg) & mask) == val)
			return 1;

		udelay(AH_TIME_QUANTUM);
	}

	DBG("ath9k: "
		"timeout (%d us) on reg 0x%x: 0x%08x & 0x%08x != 0x%08x\n",
		timeout, reg, REG_READ(ah, reg), mask, val);

	return 0;
}

void ath9k_hw_write_array(struct ath_hw *ah, struct ar5416IniArray *array,
			  int column, unsigned int *writecnt)
{
	unsigned int r;

	ENABLE_REGWRITE_BUFFER(ah);
	for (r = 0; r < array->ia_rows; r++) {
		REG_WRITE(ah, INI_RA(array, r, 0),
			  INI_RA(array, r, column));
		DO_DELAY(*writecnt);
	}
	REGWRITE_BUFFER_FLUSH(ah);
}

u32 ath9k_hw_reverse_bits(u32 val, u32 n)
{
	u32 retval;
	unsigned int i;

	for (i = 0, retval = 0; i < n; i++) {
		retval = (retval << 1) | (val & 1);
		val >>= 1;
	}
	return retval;
}

u16 ath9k_hw_computetxtime(struct ath_hw *ah,
			   u8 phy, int kbps,
			   u32 frameLen, u16 rateix,
			   int shortPreamble)
{
	u32 bitsPerSymbol, numBits, numSymbols, phyTime, txTime;

	if (kbps == 0)
		return 0;

	switch (phy) {
	case CHANNEL_CCK:
		phyTime = CCK_PREAMBLE_BITS + CCK_PLCP_BITS;
		if (shortPreamble)
			phyTime >>= 1;
		numBits = frameLen << 3;
		txTime = CCK_SIFS_TIME + phyTime + ((numBits * 1000) / kbps);
		break;
	case CHANNEL_OFDM:
		if (ah->curchan && IS_CHAN_QUARTER_RATE(ah->curchan)) {
			bitsPerSymbol =	(kbps * OFDM_SYMBOL_TIME_QUARTER) / 1000;
			numBits = OFDM_PLCP_BITS + (frameLen << 3);
			numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol);
			txTime = OFDM_SIFS_TIME_QUARTER
				+ OFDM_PREAMBLE_TIME_QUARTER
				+ (numSymbols * OFDM_SYMBOL_TIME_QUARTER);
		} else if (ah->curchan &&
			   IS_CHAN_HALF_RATE(ah->curchan)) {
			bitsPerSymbol =	(kbps * OFDM_SYMBOL_TIME_HALF) / 1000;
			numBits = OFDM_PLCP_BITS + (frameLen << 3);
			numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol);
			txTime = OFDM_SIFS_TIME_HALF +
				OFDM_PREAMBLE_TIME_HALF
				+ (numSymbols * OFDM_SYMBOL_TIME_HALF);
		} else {
			bitsPerSymbol = (kbps * OFDM_SYMBOL_TIME) / 1000;
			numBits = OFDM_PLCP_BITS + (frameLen << 3);
			numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol);
			txTime = OFDM_SIFS_TIME + OFDM_PREAMBLE_TIME
				+ (numSymbols * OFDM_SYMBOL_TIME);
		}
		break;
	default:
		DBG("ath9k: "
			"Unknown phy %d (rate ix %d)\n", phy, rateix);
		txTime = 0;
		break;
	}

	return txTime;
}

void ath9k_hw_get_channel_centers(struct ath_hw *ah __unused,
				  struct ath9k_channel *chan,
				  struct chan_centers *centers)
{
	int8_t extoff;

	if (!IS_CHAN_HT40(chan)) {
		centers->ctl_center = centers->ext_center =
			centers->synth_center = chan->channel;
		return;
	}

	if ((chan->chanmode == CHANNEL_A_HT40PLUS) ||
	    (chan->chanmode == CHANNEL_G_HT40PLUS)) {
		centers->synth_center =
			chan->channel + HT40_CHANNEL_CENTER_SHIFT;
		extoff = 1;
	} else {
		centers->synth_center =
			chan->channel - HT40_CHANNEL_CENTER_SHIFT;
		extoff = -1;
	}

	centers->ctl_center =
		centers->synth_center - (extoff * HT40_CHANNEL_CENTER_SHIFT);
	/* 25 MHz spacing is supported by hw but not on upper layers */
	centers->ext_center =
		centers->synth_center + (extoff * HT40_CHANNEL_CENTER_SHIFT);
}

/******************/
/* Chip Revisions */
/******************/

static void ath9k_hw_read_revisions(struct ath_hw *ah)
{
	u32 val;

	switch (ah->hw_version.devid) {
	case AR5416_AR9100_DEVID:
		ah->hw_version.macVersion = AR_SREV_VERSION_9100;
		break;
	case AR9300_DEVID_AR9340:
		ah->hw_version.macVersion = AR_SREV_VERSION_9340;
		val = REG_READ(ah, AR_SREV);
		ah->hw_version.macRev = MS(val, AR_SREV_REVISION2);
		return;
	}

	val = REG_READ(ah, AR_SREV) & AR_SREV_ID;

	if (val == 0xFF) {
		val = REG_READ(ah, AR_SREV);
		ah->hw_version.macVersion =
			(val & AR_SREV_VERSION2) >> AR_SREV_TYPE2_S;
		ah->hw_version.macRev = MS(val, AR_SREV_REVISION2);
		ah->is_pciexpress = (val & AR_SREV_TYPE2_HOST_MODE) ? 0 : 1;
	} else {
		if (!AR_SREV_9100(ah))
			ah->hw_version.macVersion = MS(val, AR_SREV_VERSION);

		ah->hw_version.macRev = val & AR_SREV_REVISION;

		if (ah->hw_version.macVersion == AR_SREV_VERSION_5416_PCIE)
			ah->is_pciexpress = 1;
	}
}

/************************************/
/* HW Attach, Detach, Init Routines */
/************************************/

static void ath9k_hw_disablepcie(struct ath_hw *ah)
{
	if (!AR_SREV_5416(ah))
		return;

	REG_WRITE(ah, AR_PCIE_SERDES, 0x9248fc00);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x24924924);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x28000029);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x57160824);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x25980579);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x00000000);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x1aaabe40);
	REG_WRITE(ah, AR_PCIE_SERDES, 0xbe105554);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x000e1007);

	REG_WRITE(ah, AR_PCIE_SERDES2, 0x00000000);
}

/* This should work for all families including legacy */
static int ath9k_hw_chip_test(struct ath_hw *ah)
{
	u32 regAddr[2] = { AR_STA_ID0 };
	u32 regHold[2];
	static const u32 patternData[4] = {
		0x55555555, 0xaaaaaaaa, 0x66666666, 0x99999999
	};
	int i, j, loop_max;

	if (!AR_SREV_9300_20_OR_LATER(ah)) {
		loop_max = 2;
		regAddr[1] = AR_PHY_BASE + (8 << 2);
	} else
		loop_max = 1;

	for (i = 0; i < loop_max; i++) {
		u32 addr = regAddr[i];
		u32 wrData, rdData;

		regHold[i] = REG_READ(ah, addr);
		for (j = 0; j < 0x100; j++) {
			wrData = (j << 16) | j;
			REG_WRITE(ah, addr, wrData);
			rdData = REG_READ(ah, addr);
			if (rdData != wrData) {
				DBG("ath9k: "
					"address test failed addr: 0x%08x - wr:0x%08x != rd:0x%08x\n",
					addr, wrData, rdData);
				return 0;
			}
		}
		for (j = 0; j < 4; j++) {
			wrData = patternData[j];
			REG_WRITE(ah, addr, wrData);
			rdData = REG_READ(ah, addr);
			if (wrData != rdData) {
				DBG("ath9k: "
					"address test failed addr: 0x%08x - wr:0x%08x != rd:0x%08x\n",
					addr, wrData, rdData);
				return 0;
			}
		}
		REG_WRITE(ah, regAddr[i], regHold[i]);
	}
	udelay(100);

	return 1;
}

static void ath9k_hw_init_config(struct ath_hw *ah)
{
	int i;

	ah->config.dma_beacon_response_time = 2;
	ah->config.sw_beacon_response_time = 10;
	ah->config.additional_swba_backoff = 0;
	ah->config.ack_6mb = 0x0;
	ah->config.cwm_ignore_extcca = 0;
	ah->config.pcie_powersave_enable = 0;
	ah->config.pcie_clock_req = 0;
	ah->config.pcie_waen = 0;
	ah->config.analog_shiftreg = 1;
	ah->config.enable_ani = 1;

	for (i = 0; i < AR_EEPROM_MODAL_SPURS; i++) {
		ah->config.spurchans[i][0] = AR_NO_SPUR;
		ah->config.spurchans[i][1] = AR_NO_SPUR;
	}

	/* PAPRD needs some more work to be enabled */
	ah->config.paprd_disable = 1;

	ah->config.rx_intr_mitigation = 1;
	ah->config.pcieSerDesWrite = 1;
}

static void ath9k_hw_init_defaults(struct ath_hw *ah)
{
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);

	regulatory->country_code = CTRY_DEFAULT;
	regulatory->power_limit = MAX_RATE_POWER;
	regulatory->tp_scale = ATH9K_TP_SCALE_MAX;

	ah->hw_version.magic = AR5416_MAGIC;
	ah->hw_version.subvendorid = 0;

	ah->atim_window = 0;
	ah->sta_id1_defaults =
		AR_STA_ID1_CRPT_MIC_ENABLE |
		AR_STA_ID1_MCAST_KSRCH;
	if (AR_SREV_9100(ah))
		ah->sta_id1_defaults |= AR_STA_ID1_AR9100_BA_FIX;
	ah->enable_32kHz_clock = DONT_USE_32KHZ;
	ah->slottime = 20;
	ah->globaltxtimeout = (u32) -1;
	ah->power_mode = ATH9K_PM_UNDEFINED;
}

static int ath9k_hw_init_macaddr(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	u32 sum;
	int i;
	u16 eeval;
	static const u32 EEP_MAC[] = { EEP_MAC_LSW, EEP_MAC_MID, EEP_MAC_MSW };

	sum = 0;
	for (i = 0; i < 3; i++) {
		eeval = ah->eep_ops->get_eeprom(ah, EEP_MAC[i]);
		sum += eeval;
		common->macaddr[2 * i] = eeval >> 8;
		common->macaddr[2 * i + 1] = eeval & 0xff;
	}
	if (sum == 0 || sum == 0xffff * 3)
		return -EADDRNOTAVAIL;

	return 0;
}

static int ath9k_hw_post_init(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	int ecode;

	if (common->bus_ops->ath_bus_type != ATH_USB) {
		if (!ath9k_hw_chip_test(ah))
			return -ENODEV;
	}

	if (!AR_SREV_9300_20_OR_LATER(ah)) {
		ecode = ar9002_hw_rf_claim(ah);
		if (ecode != 0)
			return ecode;
	}

	ecode = ath9k_hw_eeprom_init(ah);
	if (ecode != 0)
		return ecode;

	DBG("ath9k: "
		"Eeprom VER: %d, REV: %d\n",
		ah->eep_ops->get_eeprom_ver(ah),
		ah->eep_ops->get_eeprom_rev(ah));

	ecode = ath9k_hw_rf_alloc_ext_banks(ah);
	if (ecode) {
		DBG("ath9k: "
			"Failed allocating banks for external radio\n");
		ath9k_hw_rf_free_ext_banks(ah);
		return ecode;
	}

	if (!AR_SREV_9100(ah) && !AR_SREV_9340(ah)) {
		ath9k_hw_ani_setup(ah);
		ath9k_hw_ani_init(ah);
	}

	return 0;
}

static void ath9k_hw_attach_ops(struct ath_hw *ah)
{
	if (AR_SREV_9300_20_OR_LATER(ah))
		ar9003_hw_attach_ops(ah);
	else
		ar9002_hw_attach_ops(ah);
}

/* Called for all hardware families */
static int __ath9k_hw_init(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	int r = 0;

	ath9k_hw_read_revisions(ah);

	/*
	 * Read back AR_WA into a permanent copy and set bits 14 and 17.
	 * We need to do this to avoid RMW of this register. We cannot
	 * read the reg when chip is asleep.
	 */
	ah->WARegVal = REG_READ(ah, AR_WA);
	ah->WARegVal |= (AR_WA_D3_L1_DISABLE |
			 AR_WA_ASPM_TIMER_BASED_DISABLE);

	if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_POWER_ON)) {
		DBG("ath9k: Couldn't reset chip\n");
		return -EIO;
	}

	ath9k_hw_init_defaults(ah);
	ath9k_hw_init_config(ah);

	ath9k_hw_attach_ops(ah);

	if (!ath9k_hw_setpower(ah, ATH9K_PM_AWAKE)) {
		DBG("ath9k: Couldn't wakeup chip\n");
		return -EIO;
	}

	if (ah->config.serialize_regmode == SER_REG_MODE_AUTO) {
		if (ah->hw_version.macVersion == AR_SREV_VERSION_5416_PCI ||
		    ((AR_SREV_9160(ah) || AR_SREV_9280(ah)) &&
		     !ah->is_pciexpress)) {
			ah->config.serialize_regmode =
				SER_REG_MODE_ON;
		} else {
			ah->config.serialize_regmode =
				SER_REG_MODE_OFF;
		}
	}

	DBG2("ath9k: serialize_regmode is %d\n",
		ah->config.serialize_regmode);

	if (AR_SREV_9285(ah) || AR_SREV_9271(ah))
		ah->config.max_txtrig_level = MAX_TX_FIFO_THRESHOLD >> 1;
	else
		ah->config.max_txtrig_level = MAX_TX_FIFO_THRESHOLD;

	switch (ah->hw_version.macVersion) {
	case AR_SREV_VERSION_5416_PCI:
	case AR_SREV_VERSION_5416_PCIE:
	case AR_SREV_VERSION_9160:
	case AR_SREV_VERSION_9100:
	case AR_SREV_VERSION_9280:
	case AR_SREV_VERSION_9285:
	case AR_SREV_VERSION_9287:
	case AR_SREV_VERSION_9271:
	case AR_SREV_VERSION_9300:
	case AR_SREV_VERSION_9485:
	case AR_SREV_VERSION_9340:
		break;
	default:
		DBG("ath9k: "
			"Mac Chip Rev 0x%02x.%x is not supported by this driver\n",
			ah->hw_version.macVersion, ah->hw_version.macRev);
		return -EOPNOTSUPP;
	}

	if (AR_SREV_9271(ah) || AR_SREV_9100(ah) || AR_SREV_9340(ah))
		ah->is_pciexpress = 0;

	ah->hw_version.phyRev = REG_READ(ah, AR_PHY_CHIP_ID);
	ath9k_hw_init_cal_settings(ah);

	ah->ani_function = ATH9K_ANI_ALL;
	if (AR_SREV_9280_20_OR_LATER(ah) && !AR_SREV_9300_20_OR_LATER(ah))
		ah->ani_function &= ~ATH9K_ANI_NOISE_IMMUNITY_LEVEL;
	if (!AR_SREV_9300_20_OR_LATER(ah))
		ah->ani_function &= ~ATH9K_ANI_MRC_CCK;

	ath9k_hw_init_mode_regs(ah);


	if (ah->is_pciexpress)
		ath9k_hw_configpcipowersave(ah, 0, 0);
	else
		ath9k_hw_disablepcie(ah);

	if (!AR_SREV_9300_20_OR_LATER(ah))
		ar9002_hw_cck_chan14_spread(ah);

	r = ath9k_hw_post_init(ah);
	if (r)
		return r;

	ath9k_hw_init_mode_gain_regs(ah);
	r = ath9k_hw_fill_cap_info(ah);
	if (r)
		return r;

	r = ath9k_hw_init_macaddr(ah);
	if (r) {
		DBG("ath9k: Failed to initialize MAC address\n");
		return r;
	}

	if (AR_SREV_9285(ah) || AR_SREV_9271(ah))
		ah->tx_trig_level = (AR_FTRIG_256B >> AR_FTRIG_S);
	else
		ah->tx_trig_level = (AR_FTRIG_512B >> AR_FTRIG_S);

	common->state = ATH_HW_INITIALIZED;

	return 0;
}

int ath9k_hw_init(struct ath_hw *ah)
{
	int ret;
	struct ath_common *common = ath9k_hw_common(ah);

	/* These are all the AR5008/AR9001/AR9002 hardware family of chipsets */
	switch (ah->hw_version.devid) {
	case AR5416_DEVID_PCI:
	case AR5416_DEVID_PCIE:
	case AR5416_AR9100_DEVID:
	case AR9160_DEVID_PCI:
	case AR9280_DEVID_PCI:
	case AR9280_DEVID_PCIE:
	case AR9285_DEVID_PCIE:
	case AR9287_DEVID_PCI:
	case AR9287_DEVID_PCIE:
	case AR2427_DEVID_PCIE:
	case AR9300_DEVID_PCIE:
	case AR9300_DEVID_AR9485_PCIE:
	case AR9300_DEVID_AR9340:
		break;
	default:
		if (common->bus_ops->ath_bus_type == ATH_USB)
			break;
		DBG("ath9k: Hardware device ID 0x%04x not supported\n",
			ah->hw_version.devid);
		return -EOPNOTSUPP;
	}

	ret = __ath9k_hw_init(ah);
	if (ret) {
		DBG("ath9k: "
			"Unable to initialize hardware; initialization status: %d\n",
			ret);
		return ret;
	}

	return 0;
}

u32 ar9003_get_pll_sqsum_dvc(struct ath_hw *ah)
{
	REG_CLR_BIT(ah, PLL3, PLL3_DO_MEAS_MASK);
	udelay(100);
	REG_SET_BIT(ah, PLL3, PLL3_DO_MEAS_MASK);

	while ((REG_READ(ah, PLL4) & PLL4_MEAS_DONE) == 0)
		udelay(100);

	return (REG_READ(ah, PLL3) & SQSUM_DVC_MASK) >> 3;
}

static void ath9k_hw_init_pll(struct ath_hw *ah,
			      struct ath9k_channel *chan)
{
	u32 pll;

	if (AR_SREV_9485(ah)) {

		/* program BB PLL ki and kd value, ki=0x4, kd=0x40 */
		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL2,
			      AR_CH0_BB_DPLL2_PLL_PWD, 0x1);
		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL2,
			      AR_CH0_DPLL2_KD, 0x40);
		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL2,
			      AR_CH0_DPLL2_KI, 0x4);

		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL1,
			      AR_CH0_BB_DPLL1_REFDIV, 0x5);
		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL1,
			      AR_CH0_BB_DPLL1_NINI, 0x58);
		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL1,
			      AR_CH0_BB_DPLL1_NFRAC, 0x0);

		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL2,
			      AR_CH0_BB_DPLL2_OUTDIV, 0x1);
		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL2,
			      AR_CH0_BB_DPLL2_LOCAL_PLL, 0x1);
		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL2,
			      AR_CH0_BB_DPLL2_EN_NEGTRIG, 0x1);

		/* program BB PLL phase_shift to 0x6 */
		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL3,
			      AR_CH0_BB_DPLL3_PHASE_SHIFT, 0x6);

		REG_RMW_FIELD(ah, AR_CH0_BB_DPLL2,
			      AR_CH0_BB_DPLL2_PLL_PWD, 0x0);
		udelay(1000);
	} else if (AR_SREV_9340(ah)) {
		u32 regval, pll2_divint, pll2_divfrac, refdiv;

		REG_WRITE(ah, AR_RTC_PLL_CONTROL, 0x1142c);
		udelay(1000);

		REG_SET_BIT(ah, AR_PHY_PLL_MODE, 0x1 << 16);
		udelay(100);

		if (ah->is_clk_25mhz) {
			pll2_divint = 0x54;
			pll2_divfrac = 0x1eb85;
			refdiv = 3;
		} else {
			pll2_divint = 88;
			pll2_divfrac = 0;
			refdiv = 5;
		}

		regval = REG_READ(ah, AR_PHY_PLL_MODE);
		regval |= (0x1 << 16);
		REG_WRITE(ah, AR_PHY_PLL_MODE, regval);
		udelay(100);

		REG_WRITE(ah, AR_PHY_PLL_CONTROL, (refdiv << 27) |
			  (pll2_divint << 18) | pll2_divfrac);
		udelay(100);

		regval = REG_READ(ah, AR_PHY_PLL_MODE);
		regval = (regval & 0x80071fff) | (0x1 << 30) | (0x1 << 13) |
			 (0x4 << 26) | (0x18 << 19);
		REG_WRITE(ah, AR_PHY_PLL_MODE, regval);
		REG_WRITE(ah, AR_PHY_PLL_MODE,
			  REG_READ(ah, AR_PHY_PLL_MODE) & 0xfffeffff);
		udelay(1000);
	}

	pll = ath9k_hw_compute_pll_control(ah, chan);

	REG_WRITE(ah, AR_RTC_PLL_CONTROL, pll);

	if (AR_SREV_9485(ah) || AR_SREV_9340(ah))
		udelay(1000);

	/* Switch the core clock for ar9271 to 117Mhz */
	if (AR_SREV_9271(ah)) {
		udelay(500);
		REG_WRITE(ah, 0x50040, 0x304);
	}

	udelay(RTC_PLL_SETTLE_DELAY);

	REG_WRITE(ah, AR_RTC_SLEEP_CLK, AR_RTC_FORCE_DERIVED_CLK);

	if (AR_SREV_9340(ah)) {
		if (ah->is_clk_25mhz) {
			REG_WRITE(ah, AR_RTC_DERIVED_CLK, 0x17c << 1);
			REG_WRITE(ah, AR_SLP32_MODE, 0x0010f3d7);
			REG_WRITE(ah,  AR_SLP32_INC, 0x0001e7ae);
		} else {
			REG_WRITE(ah, AR_RTC_DERIVED_CLK, 0x261 << 1);
			REG_WRITE(ah, AR_SLP32_MODE, 0x0010f400);
			REG_WRITE(ah,  AR_SLP32_INC, 0x0001e800);
		}
		udelay(100);
	}
}

static void ath9k_hw_init_interrupt_masks(struct ath_hw *ah)
{
	u32 sync_default = AR_INTR_SYNC_DEFAULT;
	u32 imr_reg = AR_IMR_TXERR |
		AR_IMR_TXURN |
		AR_IMR_RXERR |
		AR_IMR_RXORN;;

	if (AR_SREV_9340(ah))
		sync_default &= ~AR_INTR_SYNC_HOST1_FATAL;

	if (AR_SREV_9300_20_OR_LATER(ah)) {
		imr_reg |= AR_IMR_RXOK_HP;
		if (ah->config.rx_intr_mitigation)
			imr_reg |= AR_IMR_RXINTM | AR_IMR_RXMINTR;
		else
			imr_reg |= AR_IMR_RXOK_LP;

	} else {
		if (ah->config.rx_intr_mitigation)
			imr_reg |= AR_IMR_RXINTM | AR_IMR_RXMINTR;
		else
			imr_reg |= AR_IMR_RXOK;
	}

	if (ah->config.tx_intr_mitigation)
		imr_reg |= AR_IMR_TXINTM | AR_IMR_TXMINTR;
	else
		imr_reg |= AR_IMR_TXOK;

	ENABLE_REGWRITE_BUFFER(ah);

	REG_WRITE(ah, AR_IMR, imr_reg);
//	ah->imrs2_reg |= AR_IMR_S2_GTT;
	REG_WRITE(ah, AR_IMR_S2, ah->imrs2_reg);

	if (!AR_SREV_9100(ah)) {
		REG_WRITE(ah, AR_INTR_SYNC_CAUSE, 0xFFFFFFFF);
		REG_WRITE(ah, AR_INTR_SYNC_ENABLE, sync_default);
		REG_WRITE(ah, AR_INTR_SYNC_MASK, 0);
	}

	REGWRITE_BUFFER_FLUSH(ah);

	if (AR_SREV_9300_20_OR_LATER(ah)) {
		REG_WRITE(ah, AR_INTR_PRIO_ASYNC_ENABLE, 0);
		REG_WRITE(ah, AR_INTR_PRIO_ASYNC_MASK, 0);
		REG_WRITE(ah, AR_INTR_PRIO_SYNC_ENABLE, 0);
		REG_WRITE(ah, AR_INTR_PRIO_SYNC_MASK, 0);
	}
}

static void ath9k_hw_setslottime(struct ath_hw *ah, u32 us)
{
	u32 val = ath9k_hw_mac_to_clks(ah, us);
	val = min(val, (u32) 0xFFFF);
	REG_WRITE(ah, AR_D_GBL_IFS_SLOT, val);
}

static void ath9k_hw_set_ack_timeout(struct ath_hw *ah, u32 us)
{
	u32 val = ath9k_hw_mac_to_clks(ah, us);
	val = min(val, (u32) MS(0xFFFFFFFF, AR_TIME_OUT_ACK));
	REG_RMW_FIELD(ah, AR_TIME_OUT, AR_TIME_OUT_ACK, val);
}

static void ath9k_hw_set_cts_timeout(struct ath_hw *ah, u32 us)
{
	u32 val = ath9k_hw_mac_to_clks(ah, us);
	val = min(val, (u32) MS(0xFFFFFFFF, AR_TIME_OUT_CTS));
	REG_RMW_FIELD(ah, AR_TIME_OUT, AR_TIME_OUT_CTS, val);
}

static int ath9k_hw_set_global_txtimeout(struct ath_hw *ah, u32 tu)
{
	if (tu > 0xFFFF) {
		DBG("ath9k: "
			"bad global tx timeout %d\n", tu);
		ah->globaltxtimeout = (u32) -1;
		return 0;
	} else {
		REG_RMW_FIELD(ah, AR_GTXTO, AR_GTXTO_TIMEOUT_LIMIT, tu);
		ah->globaltxtimeout = tu;
		return 1;
	}
}

void ath9k_hw_init_global_settings(struct ath_hw *ah)
{
	int acktimeout;
	int slottime;
	int sifstime;

	DBG2("ath9k: ah->misc_mode 0x%x\n",
		ah->misc_mode);

	if (ah->misc_mode != 0)
		REG_SET_BIT(ah, AR_PCU_MISC, ah->misc_mode);

	if ((ah->dev->channels + ah->dev->channel)->band == NET80211_BAND_5GHZ)
		sifstime = 16;
	else
		sifstime = 10;

	/* As defined by IEEE 802.11-2007 17.3.8.6 */
	slottime = ah->slottime + 3 * ah->coverage_class;
	acktimeout = slottime + sifstime;

	/*
	 * Workaround for early ACK timeouts, add an offset to match the
	 * initval's 64us ack timeout value.
	 * This was initially only meant to work around an issue with delayed
	 * BA frames in some implementations, but it has been found to fix ACK
	 * timeout issues in other cases as well.
	 */
	if ((ah->dev->channels + ah->dev->channel)->band == NET80211_BAND_2GHZ)
		acktimeout += 64 - sifstime - ah->slottime;

	ath9k_hw_setslottime(ah, ah->slottime);
	ath9k_hw_set_ack_timeout(ah, acktimeout);
	ath9k_hw_set_cts_timeout(ah, acktimeout);
	if (ah->globaltxtimeout != (u32) -1)
		ath9k_hw_set_global_txtimeout(ah, ah->globaltxtimeout);
}

void ath9k_hw_deinit(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);

	if (common->state < ATH_HW_INITIALIZED)
		goto free_hw;

	ath9k_hw_setpower(ah, ATH9K_PM_FULL_SLEEP);

free_hw:
	ath9k_hw_rf_free_ext_banks(ah);
}

/*******/
/* INI */
/*******/

u32 ath9k_regd_get_ctl(struct ath_regulatory *reg, struct ath9k_channel *chan)
{
	u32 ctl = ath_regd_get_band_ctl(reg, chan->chan->band);

	if (IS_CHAN_B(chan))
		ctl |= CTL_11B;
	else if (IS_CHAN_G(chan))
		ctl |= CTL_11G;
	else
		ctl |= CTL_11A;

	return ctl;
}

/****************************************/
/* Reset and Channel Switching Routines */
/****************************************/

static inline void ath9k_hw_set_dma(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);

	ENABLE_REGWRITE_BUFFER(ah);

	/*
	 * set AHB_MODE not to do cacheline prefetches
	*/
	if (!AR_SREV_9300_20_OR_LATER(ah))
		REG_SET_BIT(ah, AR_AHB_MODE, AR_AHB_PREFETCH_RD_EN);

	/*
	 * let mac dma reads be in 128 byte chunks
	 */
	REG_RMW(ah, AR_TXCFG, AR_TXCFG_DMASZ_128B, AR_TXCFG_DMASZ_MASK);

	REGWRITE_BUFFER_FLUSH(ah);

	/*
	 * Restore TX Trigger Level to its pre-reset value.
	 * The initial value depends on whether aggregation is enabled, and is
	 * adjusted whenever underruns are detected.
	 */
	if (!AR_SREV_9300_20_OR_LATER(ah))
		REG_RMW_FIELD(ah, AR_TXCFG, AR_FTRIG, ah->tx_trig_level);

	ENABLE_REGWRITE_BUFFER(ah);

	/*
	 * let mac dma writes be in 128 byte chunks
	 */
	REG_RMW(ah, AR_RXCFG, AR_RXCFG_DMASZ_128B, AR_RXCFG_DMASZ_MASK);

	/*
	 * Setup receive FIFO threshold to hold off TX activities
	 */
	REG_WRITE(ah, AR_RXFIFO_CFG, 0x200);

	if (AR_SREV_9300_20_OR_LATER(ah)) {
		REG_RMW_FIELD(ah, AR_RXBP_THRESH, AR_RXBP_THRESH_HP, 0x1);
		REG_RMW_FIELD(ah, AR_RXBP_THRESH, AR_RXBP_THRESH_LP, 0x1);

		ath9k_hw_set_rx_bufsize(ah, common->rx_bufsize -
			ah->caps.rx_status_len);
	}

	/*
	 * reduce the number of usable entries in PCU TXBUF to avoid
	 * wrap around issues.
	 */
	if (AR_SREV_9285(ah)) {
		/* For AR9285 the number of Fifos are reduced to half.
		 * So set the usable tx buf size also to half to
		 * avoid data/delimiter underruns
		 */
		REG_WRITE(ah, AR_PCU_TXBUF_CTRL,
			  AR_9285_PCU_TXBUF_CTRL_USABLE_SIZE);
	} else if (!AR_SREV_9271(ah)) {
		REG_WRITE(ah, AR_PCU_TXBUF_CTRL,
			  AR_PCU_TXBUF_CTRL_USABLE_SIZE);
	}

	REGWRITE_BUFFER_FLUSH(ah);

	if (AR_SREV_9300_20_OR_LATER(ah))
		ath9k_hw_reset_txstatus_ring(ah);
}

static void ath9k_hw_set_operating_mode(struct ath_hw *ah)
{
	u32 mask = AR_STA_ID1_STA_AP | AR_STA_ID1_ADHOC;
	u32 set = AR_STA_ID1_KSRCH_MODE;

	REG_CLR_BIT(ah, AR_CFG, AR_CFG_AP_ADHOC_INDICATION);

	REG_RMW(ah, AR_STA_ID1, set, mask);
}

void ath9k_hw_get_delta_slope_vals(struct ath_hw *ah __unused, u32 coef_scaled,
				   u32 *coef_mantissa, u32 *coef_exponent)
{
	u32 coef_exp, coef_man;

	for (coef_exp = 31; coef_exp > 0; coef_exp--)
		if ((coef_scaled >> coef_exp) & 0x1)
			break;

	coef_exp = 14 - (coef_exp - COEF_SCALE_S);

	coef_man = coef_scaled + (1 << (COEF_SCALE_S - coef_exp - 1));

	*coef_mantissa = coef_man >> (COEF_SCALE_S - coef_exp);
	*coef_exponent = coef_exp - 16;
}

static int ath9k_hw_set_reset(struct ath_hw *ah, int type)
{
	u32 rst_flags;
	u32 tmpReg;

	if (AR_SREV_9100(ah)) {
		REG_RMW_FIELD(ah, AR_RTC_DERIVED_CLK,
			      AR_RTC_DERIVED_CLK_PERIOD, 1);
		(void)REG_READ(ah, AR_RTC_DERIVED_CLK);
	}

	ENABLE_REGWRITE_BUFFER(ah);

	if (AR_SREV_9300_20_OR_LATER(ah)) {
		REG_WRITE(ah, AR_WA, ah->WARegVal);
		udelay(10);
	}

	REG_WRITE(ah, AR_RTC_FORCE_WAKE, AR_RTC_FORCE_WAKE_EN |
		  AR_RTC_FORCE_WAKE_ON_INT);

	if (AR_SREV_9100(ah)) {
		rst_flags = AR_RTC_RC_MAC_WARM | AR_RTC_RC_MAC_COLD |
			AR_RTC_RC_COLD_RESET | AR_RTC_RC_WARM_RESET;
	} else {
		tmpReg = REG_READ(ah, AR_INTR_SYNC_CAUSE);
		if (tmpReg &
		    (AR_INTR_SYNC_LOCAL_TIMEOUT |
		     AR_INTR_SYNC_RADM_CPL_TIMEOUT)) {
			u32 val;
			REG_WRITE(ah, AR_INTR_SYNC_ENABLE, 0);

			val = AR_RC_HOSTIF;
			if (!AR_SREV_9300_20_OR_LATER(ah))
				val |= AR_RC_AHB;
			REG_WRITE(ah, AR_RC, val);

		} else if (!AR_SREV_9300_20_OR_LATER(ah))
			REG_WRITE(ah, AR_RC, AR_RC_AHB);

		rst_flags = AR_RTC_RC_MAC_WARM;
		if (type == ATH9K_RESET_COLD)
			rst_flags |= AR_RTC_RC_MAC_COLD;
	}

	REG_WRITE(ah, AR_RTC_RC, rst_flags);

	REGWRITE_BUFFER_FLUSH(ah);

	udelay(50);

	REG_WRITE(ah, AR_RTC_RC, 0);
	if (!ath9k_hw_wait(ah, AR_RTC_RC, AR_RTC_RC_M, 0, AH_WAIT_TIMEOUT)) {
		DBG("ath9k: "
			"RTC stuck in MAC reset\n");
		return 0;
	}

	if (!AR_SREV_9100(ah))
		REG_WRITE(ah, AR_RC, 0);

	if (AR_SREV_9100(ah))
		udelay(50);

	return 1;
}

static int ath9k_hw_set_reset_power_on(struct ath_hw *ah)
{
	ENABLE_REGWRITE_BUFFER(ah);

	if (AR_SREV_9300_20_OR_LATER(ah)) {
		REG_WRITE(ah, AR_WA, ah->WARegVal);
		udelay(10);
	}

	REG_WRITE(ah, AR_RTC_FORCE_WAKE, AR_RTC_FORCE_WAKE_EN |
		  AR_RTC_FORCE_WAKE_ON_INT);

	if (!AR_SREV_9100(ah) && !AR_SREV_9300_20_OR_LATER(ah))
		REG_WRITE(ah, AR_RC, AR_RC_AHB);

	REG_WRITE(ah, AR_RTC_RESET, 0);

	REGWRITE_BUFFER_FLUSH(ah);

	if (!AR_SREV_9300_20_OR_LATER(ah))
		udelay(2);

	if (!AR_SREV_9100(ah) && !AR_SREV_9300_20_OR_LATER(ah))
		REG_WRITE(ah, AR_RC, 0);

	REG_WRITE(ah, AR_RTC_RESET, 1);

	if (!ath9k_hw_wait(ah,
			   AR_RTC_STATUS,
			   AR_RTC_STATUS_M,
			   AR_RTC_STATUS_ON,
			   AH_WAIT_TIMEOUT)) {
		DBG("ath9k: "
			"RTC not waking up\n");
		return 0;
	}

	return ath9k_hw_set_reset(ah, ATH9K_RESET_WARM);
}

static int ath9k_hw_set_reset_reg(struct ath_hw *ah, u32 type)
{
	if (AR_SREV_9300_20_OR_LATER(ah)) {
		REG_WRITE(ah, AR_WA, ah->WARegVal);
		udelay(10);
	}

	REG_WRITE(ah, AR_RTC_FORCE_WAKE,
		  AR_RTC_FORCE_WAKE_EN | AR_RTC_FORCE_WAKE_ON_INT);

	switch (type) {
	case ATH9K_RESET_POWER_ON:
		return ath9k_hw_set_reset_power_on(ah);
	case ATH9K_RESET_WARM:
	case ATH9K_RESET_COLD:
		return ath9k_hw_set_reset(ah, type);
	default:
		return 0;
	}
}

static int ath9k_hw_chip_reset(struct ath_hw *ah,
				struct ath9k_channel *chan)
{
	if (AR_SREV_9280(ah) && ah->eep_ops->get_eeprom(ah, EEP_OL_PWRCTRL)) {
		if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_POWER_ON))
			return 0;
	} else if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_WARM))
		return 0;

	if (!ath9k_hw_setpower(ah, ATH9K_PM_AWAKE))
		return 0;

	ah->chip_fullsleep = 0;
	ath9k_hw_init_pll(ah, chan);
	ath9k_hw_set_rfmode(ah, chan);

	return 1;
}

static int ath9k_hw_channel_change(struct ath_hw *ah,
				    struct ath9k_channel *chan)
{
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);
	struct net80211_channel *channel = chan->chan;
	u32 qnum;
	int r;

	for (qnum = 0; qnum < AR_NUM_QCU; qnum++) {
		if (ath9k_hw_numtxpending(ah, qnum)) {
			DBG("ath9k: "
				"Transmit frames pending on queue %d\n", qnum);
			return 0;
		}
	}

	if (!ath9k_hw_rfbus_req(ah)) {
		DBG("ath9k: Could not kill baseband RX\n");
		return 0;
	}

	ath9k_hw_set_channel_regs(ah, chan);

	r = ath9k_hw_rf_set_freq(ah, chan);
	if (r) {
		DBG("ath9k: Failed to set channel\n");
		return 0;
	}
	ath9k_hw_set_clockrate(ah);

	ah->eep_ops->set_txpower(ah, chan,
			     ath9k_regd_get_ctl(regulatory, chan),
			     0,
			     channel->maxpower * 2,
			     min((u32) MAX_RATE_POWER,
			     (u32) regulatory->power_limit), 0);

	ath9k_hw_rfbus_done(ah);

	if (IS_CHAN_OFDM(chan) || IS_CHAN_HT(chan))
		ath9k_hw_set_delta_slope(ah, chan);

	ath9k_hw_spur_mitigate_freq(ah, chan);

	return 1;
}

static void ath9k_hw_apply_gpio_override(struct ath_hw *ah)
{
	u32 gpio_mask = ah->gpio_mask;
	int i;

	for (i = 0; gpio_mask; i++, gpio_mask >>= 1) {
		if (!(gpio_mask & 1))
			continue;

		ath9k_hw_cfg_output(ah, i, AR_GPIO_OUTPUT_MUX_AS_OUTPUT);
		ath9k_hw_set_gpio(ah, i, !!(ah->gpio_val & BIT(i)));
	}
}

int ath9k_hw_check_alive(struct ath_hw *ah)
{
	int count = 50;
	u32 reg;

	if (AR_SREV_9285_12_OR_LATER(ah))
		return 1;

	do {
		reg = REG_READ(ah, AR_OBS_BUS_1);

		if ((reg & 0x7E7FFFEF) == 0x00702400)
			continue;

		switch (reg & 0x7E000B00) {
		case 0x1E000000:
		case 0x52000B00:
		case 0x18000B00:
			continue;
		default:
			return 1;
		}
	} while (count-- > 0);

	return 0;
}

int ath9k_hw_reset(struct ath_hw *ah, struct ath9k_channel *chan,
		   struct ath9k_hw_cal_data *caldata, int bChannelChange)
{
	struct ath_common *common = ath9k_hw_common(ah);
	u32 saveLedState;
	struct ath9k_channel *curchan = ah->curchan;
	u32 saveDefAntenna;
	u32 macStaId1;
	int i, r;

	ah->txchainmask = common->tx_chainmask;
	ah->rxchainmask = common->rx_chainmask;

	if (!ath9k_hw_setpower(ah, ATH9K_PM_AWAKE))
		return -EIO;

	if (curchan && !ah->chip_fullsleep)
		ath9k_hw_getnf(ah, curchan);

	ah->caldata = caldata;
	if (caldata &&
	    (chan->channel != caldata->channel ||
	     (chan->channelFlags & ~CHANNEL_CW_INT) !=
	     (caldata->channelFlags & ~CHANNEL_CW_INT))) {
		/* Operating channel changed, reset channel calibration data */
		memset(caldata, 0, sizeof(*caldata));
		ath9k_init_nfcal_hist_buffer(ah, chan);
	}

	if (bChannelChange &&
	    (ah->chip_fullsleep != 1) &&
	    (ah->curchan != NULL) &&
	    (chan->channel != ah->curchan->channel) &&
	    ((chan->channelFlags & CHANNEL_ALL) ==
	     (ah->curchan->channelFlags & CHANNEL_ALL)) &&
	    (!AR_SREV_9280(ah) || AR_DEVID_7010(ah))) {

		if (ath9k_hw_channel_change(ah, chan)) {
			ath9k_hw_loadnf(ah, ah->curchan);
			ath9k_hw_start_nfcal(ah, 1);
			if (AR_SREV_9271(ah))
				ar9002_hw_load_ani_reg(ah, chan);
			return 0;
		}
	}

	saveDefAntenna = REG_READ(ah, AR_DEF_ANTENNA);
	if (saveDefAntenna == 0)
		saveDefAntenna = 1;

	macStaId1 = REG_READ(ah, AR_STA_ID1) & AR_STA_ID1_BASE_RATE_11B;

	saveLedState = REG_READ(ah, AR_CFG_LED) &
		(AR_CFG_LED_ASSOC_CTL | AR_CFG_LED_MODE_SEL |
		 AR_CFG_LED_BLINK_THRESH_SEL | AR_CFG_LED_BLINK_SLOW);

	ath9k_hw_mark_phy_inactive(ah);

	ah->paprd_table_write_done = 0;

	/* Only required on the first reset */
	if (AR_SREV_9271(ah) && ah->htc_reset_init) {
		REG_WRITE(ah,
			  AR9271_RESET_POWER_DOWN_CONTROL,
			  AR9271_RADIO_RF_RST);
		udelay(50);
	}

	if (!ath9k_hw_chip_reset(ah, chan)) {
		DBG("ath9k: Chip reset failed\n");
		return -EINVAL;
	}

	/* Only required on the first reset */
	if (AR_SREV_9271(ah) && ah->htc_reset_init) {
		ah->htc_reset_init = 0;
		REG_WRITE(ah,
			  AR9271_RESET_POWER_DOWN_CONTROL,
			  AR9271_GATE_MAC_CTL);
		udelay(50);
	}

	if (AR_SREV_9280_20_OR_LATER(ah))
		REG_SET_BIT(ah, AR_GPIO_INPUT_EN_VAL, AR_GPIO_JTAG_DISABLE);

	if (!AR_SREV_9300_20_OR_LATER(ah))
		ar9002_hw_enable_async_fifo(ah);

	r = ath9k_hw_process_ini(ah, chan);
	if (r)
		return r;

	/* Setup MFP options for CCMP */
	if (AR_SREV_9280_20_OR_LATER(ah)) {
		/* Mask Retry(b11), PwrMgt(b12), MoreData(b13) to 0 in mgmt
		 * frames when constructing CCMP AAD. */
		REG_RMW_FIELD(ah, AR_AES_MUTE_MASK1, AR_AES_MUTE_MASK1_FC_MGMT,
			      0xc7ff);
		ah->sw_mgmt_crypto = 0;
	} else if (AR_SREV_9160_10_OR_LATER(ah)) {
		/* Disable hardware crypto for management frames */
		REG_CLR_BIT(ah, AR_PCU_MISC_MODE2,
			    AR_PCU_MISC_MODE2_MGMT_CRYPTO_ENABLE);
		REG_SET_BIT(ah, AR_PCU_MISC_MODE2,
			    AR_PCU_MISC_MODE2_NO_CRYPTO_FOR_NON_DATA_PKT);
		ah->sw_mgmt_crypto = 1;
	} else
		ah->sw_mgmt_crypto = 1;

	if (IS_CHAN_OFDM(chan) || IS_CHAN_HT(chan))
		ath9k_hw_set_delta_slope(ah, chan);

	ath9k_hw_spur_mitigate_freq(ah, chan);
	ah->eep_ops->set_board_values(ah, chan);

	ENABLE_REGWRITE_BUFFER(ah);

	REG_WRITE(ah, AR_STA_ID0, get_unaligned_le32(common->macaddr));
	REG_WRITE(ah, AR_STA_ID1, get_unaligned_le16(common->macaddr + 4)
		  | macStaId1
		  | AR_STA_ID1_RTS_USE_DEF
		  | (ah->config.
		     ack_6mb ? AR_STA_ID1_ACKCTS_6MB : 0)
		  | ah->sta_id1_defaults);
	ath_hw_setbssidmask(common);
	REG_WRITE(ah, AR_DEF_ANTENNA, saveDefAntenna);
	ath9k_hw_write_associd(ah);
	REG_WRITE(ah, AR_ISR, ~0);
	REG_WRITE(ah, AR_RSSI_THR, INIT_RSSI_THR);

	REGWRITE_BUFFER_FLUSH(ah);

	ath9k_hw_set_operating_mode(ah);

	r = ath9k_hw_rf_set_freq(ah, chan);
	if (r)
		return r;

	ath9k_hw_set_clockrate(ah);

	ENABLE_REGWRITE_BUFFER(ah);

	for (i = 0; i < AR_NUM_DCU; i++)
		REG_WRITE(ah, AR_DQCUMASK(i), 1 << i);

	REGWRITE_BUFFER_FLUSH(ah);

	ah->intr_txqs = 0;
	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++)
		ath9k_hw_resettxqueue(ah, i);

	ath9k_hw_init_interrupt_masks(ah);
	ath9k_hw_ani_cache_ini_regs(ah);

	if (ah->caps.hw_caps & ATH9K_HW_CAP_RFSILENT)
		ath9k_hw_cfg_gpio_input(ah, ah->rfkill_gpio);

	ath9k_hw_init_global_settings(ah);

	if (!AR_SREV_9300_20_OR_LATER(ah)) {
		ar9002_hw_update_async_fifo(ah);
		ar9002_hw_enable_wep_aggregation(ah);
	}

	REG_SET_BIT(ah, AR_STA_ID1, AR_STA_ID1_PRESERVE_SEQNUM);

	ath9k_hw_set_dma(ah);

	REG_WRITE(ah, AR_OBS, 8);

	if (ah->config.rx_intr_mitigation) {
		REG_RMW_FIELD(ah, AR_RIMT, AR_RIMT_LAST, 500);
		REG_RMW_FIELD(ah, AR_RIMT, AR_RIMT_FIRST, 2000);
	}

	if (ah->config.tx_intr_mitigation) {
		REG_RMW_FIELD(ah, AR_TIMT, AR_TIMT_LAST, 300);
		REG_RMW_FIELD(ah, AR_TIMT, AR_TIMT_FIRST, 750);
	}

	ath9k_hw_init_bb(ah, chan);

	if (!ath9k_hw_init_cal(ah, chan))
		return -EIO;

	ENABLE_REGWRITE_BUFFER(ah);

	ath9k_hw_restore_chainmask(ah);
	REG_WRITE(ah, AR_CFG_LED, saveLedState | AR_CFG_SCLK_32KHZ);

	REGWRITE_BUFFER_FLUSH(ah);

	/*
	 * For big endian systems turn on swapping for descriptors
	 */
	if (AR_SREV_9100(ah)) {
		u32 mask;
		mask = REG_READ(ah, AR_CFG);
		if (mask & (AR_CFG_SWRB | AR_CFG_SWTB | AR_CFG_SWRG)) {
			DBG2("ath9k: "
				"CFG Byte Swap Set 0x%x\n", mask);
		} else {
			mask =
				INIT_CONFIG_STATUS | AR_CFG_SWRB | AR_CFG_SWTB;
			REG_WRITE(ah, AR_CFG, mask);
			DBG2("ath9k: "
				"Setting CFG 0x%x\n", REG_READ(ah, AR_CFG));
		}
	} else {
		if (common->bus_ops->ath_bus_type == ATH_USB) {
			/* Configure AR9271 target WLAN */
			if (AR_SREV_9271(ah))
				REG_WRITE(ah, AR_CFG, AR_CFG_SWRB | AR_CFG_SWTB);
			else
				REG_WRITE(ah, AR_CFG, AR_CFG_SWTD | AR_CFG_SWRD);
		}
#if __BYTE_ORDER == __BIG_ENDIAN
		else if (AR_SREV_9340(ah))
			REG_RMW(ah, AR_CFG, AR_CFG_SWRB | AR_CFG_SWTB, 0);
		else
			REG_WRITE(ah, AR_CFG, AR_CFG_SWTD | AR_CFG_SWRD);
#endif
	}

	if (AR_SREV_9300_20_OR_LATER(ah)) {
		ar9003_hw_disable_phy_restart(ah);
	}

	ath9k_hw_apply_gpio_override(ah);

	return 0;
}

/******************************/
/* Power Management (Chipset) */
/******************************/

/*
 * Notify Power Mgt is disabled in self-generated frames.
 * If requested, force chip to sleep.
 */
static void ath9k_set_power_sleep(struct ath_hw *ah, int setChip)
{
	REG_SET_BIT(ah, AR_STA_ID1, AR_STA_ID1_PWR_SAV);
	if (setChip) {
		/*
		 * Clear the RTC force wake bit to allow the
		 * mac to go to sleep.
		 */
		REG_CLR_BIT(ah, AR_RTC_FORCE_WAKE,
			    AR_RTC_FORCE_WAKE_EN);
		if (!AR_SREV_9100(ah) && !AR_SREV_9300_20_OR_LATER(ah))
			REG_WRITE(ah, AR_RC, AR_RC_AHB | AR_RC_HOSTIF);

		/* Shutdown chip. Active low */
		if (!AR_SREV_5416(ah) && !AR_SREV_9271(ah))
			REG_CLR_BIT(ah, (AR_RTC_RESET),
				    AR_RTC_RESET_EN);
	}

	/* Clear Bit 14 of AR_WA after putting chip into Full Sleep mode. */
	if (AR_SREV_9300_20_OR_LATER(ah))
		REG_WRITE(ah, AR_WA,
			  ah->WARegVal & ~AR_WA_D3_L1_DISABLE);
}

static int ath9k_hw_set_power_awake(struct ath_hw *ah, int setChip)
{
	u32 val;
	int i;

	/* Set Bits 14 and 17 of AR_WA before powering on the chip. */
	if (AR_SREV_9300_20_OR_LATER(ah)) {
		REG_WRITE(ah, AR_WA, ah->WARegVal);
		udelay(10);
	}

	if (setChip) {
		if ((REG_READ(ah, AR_RTC_STATUS) &
		     AR_RTC_STATUS_M) == AR_RTC_STATUS_SHUTDOWN) {
			if (ath9k_hw_set_reset_reg(ah,
					   ATH9K_RESET_POWER_ON) != 1) {
				return 0;
			}
			if (!AR_SREV_9300_20_OR_LATER(ah))
				ath9k_hw_init_pll(ah, NULL);
		}
		if (AR_SREV_9100(ah))
			REG_SET_BIT(ah, AR_RTC_RESET,
				    AR_RTC_RESET_EN);

		REG_SET_BIT(ah, AR_RTC_FORCE_WAKE,
			    AR_RTC_FORCE_WAKE_EN);
		udelay(50);

		for (i = POWER_UP_TIME / 50; i > 0; i--) {
			val = REG_READ(ah, AR_RTC_STATUS) & AR_RTC_STATUS_M;
			if (val == AR_RTC_STATUS_ON)
				break;
			udelay(50);
			REG_SET_BIT(ah, AR_RTC_FORCE_WAKE,
				    AR_RTC_FORCE_WAKE_EN);
		}
		if (i == 0) {
			DBG("ath9k: "
				"Failed to wakeup in %dus\n",
				POWER_UP_TIME / 20);
			return 0;
		}
	}

	REG_CLR_BIT(ah, AR_STA_ID1, AR_STA_ID1_PWR_SAV);

	return 1;
}

int ath9k_hw_setpower(struct ath_hw *ah, enum ath9k_power_mode mode)
{
	int status = 1, setChip = 1;
	static const char *modes[] = {
		"AWAKE",
		"FULL-SLEEP",
		"NETWORK SLEEP",
		"UNDEFINED"
	};

	if (ah->power_mode == mode)
		return status;

	DBG2("ath9k: %s -> %s\n",
		modes[ah->power_mode], modes[mode]);

	switch (mode) {
	case ATH9K_PM_AWAKE:
		status = ath9k_hw_set_power_awake(ah, setChip);
		break;
	case ATH9K_PM_FULL_SLEEP:
		ath9k_set_power_sleep(ah, setChip);
		ah->chip_fullsleep = 1;
		break;
	default:
		DBG("ath9k: Unknown power mode %d\n", mode);
		return 0;
	}
	ah->power_mode = mode;

	return status;
}

/*******************/
/* HW Capabilities */
/*******************/

int ath9k_hw_fill_cap_info(struct ath_hw *ah)
{
	struct ath9k_hw_capabilities *pCap = &ah->caps;
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);
	struct ath_common *common = ath9k_hw_common(ah);

	u16 eeval;
	u8 ant_div_ctl1, tx_chainmask, rx_chainmask;

	eeval = ah->eep_ops->get_eeprom(ah, EEP_REG_0);
	regulatory->current_rd = eeval;

	eeval = ah->eep_ops->get_eeprom(ah, EEP_REG_1);
	if (AR_SREV_9285_12_OR_LATER(ah))
		eeval |= AR9285_RDEXT_DEFAULT;
	regulatory->current_rd_ext = eeval;

	if (ah->hw_version.subvendorid == AR_SUBVENDOR_ID_NEW_A) {
		if (regulatory->current_rd == 0x64 ||
		    regulatory->current_rd == 0x65)
			regulatory->current_rd += 5;
		else if (regulatory->current_rd == 0x41)
			regulatory->current_rd = 0x43;
		DBG2("ath9k: "
			"regdomain mapped to 0x%x\n", regulatory->current_rd);
	}

	eeval = ah->eep_ops->get_eeprom(ah, EEP_OP_MODE);
	if ((eeval & (AR5416_OPFLAGS_11G | AR5416_OPFLAGS_11A)) == 0) {
		DBG("ath9k: "
			"no band has been marked as supported in EEPROM\n");
		return -EINVAL;
	}

	if (eeval & AR5416_OPFLAGS_11A)
		pCap->hw_caps |= ATH9K_HW_CAP_5GHZ;

	if (eeval & AR5416_OPFLAGS_11G)
		pCap->hw_caps |= ATH9K_HW_CAP_2GHZ;

	pCap->tx_chainmask = ah->eep_ops->get_eeprom(ah, EEP_TX_MASK);
	/*
	 * For AR9271 we will temporarilly uses the rx chainmax as read from
	 * the EEPROM.
	 */
	if ((ah->hw_version.devid == AR5416_DEVID_PCI) &&
	    !(eeval & AR5416_OPFLAGS_11A) &&
	    !(AR_SREV_9271(ah)))
		/* CB71: GPIO 0 is pulled down to indicate 3 rx chains */
		pCap->rx_chainmask = ath9k_hw_gpio_get(ah, 0) ? 0x5 : 0x7;
	else if (AR_SREV_9100(ah))
		pCap->rx_chainmask = 0x7;
	else
		/* Use rx_chainmask from EEPROM. */
		pCap->rx_chainmask = ah->eep_ops->get_eeprom(ah, EEP_RX_MASK);

	ah->misc_mode |= AR_PCU_MIC_NEW_LOC_ENA;

	/* enable key search for every frame in an aggregate */
	if (AR_SREV_9300_20_OR_LATER(ah))
		ah->misc_mode |= AR_PCU_ALWAYS_PERFORM_KEYSEARCH;

	common->crypt_caps |= ATH_CRYPT_CAP_CIPHER_AESCCM;

	pCap->hw_caps &= ~ATH9K_HW_CAP_HT;

	if (AR_SREV_9271(ah))
		pCap->num_gpio_pins = AR9271_NUM_GPIO;
	else if (AR_DEVID_7010(ah))
		pCap->num_gpio_pins = AR7010_NUM_GPIO;
	else if (AR_SREV_9285_12_OR_LATER(ah))
		pCap->num_gpio_pins = AR9285_NUM_GPIO;
	else if (AR_SREV_9280_20_OR_LATER(ah))
		pCap->num_gpio_pins = AR928X_NUM_GPIO;
	else
		pCap->num_gpio_pins = AR_NUM_GPIO;

	if (AR_SREV_9160_10_OR_LATER(ah) || AR_SREV_9100(ah)) {
		pCap->hw_caps |= ATH9K_HW_CAP_CST;
		pCap->rts_aggr_limit = ATH_AMPDU_LIMIT_MAX;
	} else {
		pCap->rts_aggr_limit = (8 * 1024);
	}

	ah->rfsilent = ah->eep_ops->get_eeprom(ah, EEP_RF_SILENT);
	if (ah->rfsilent & EEP_RFSILENT_ENABLED) {
		ah->rfkill_gpio =
			MS(ah->rfsilent, EEP_RFSILENT_GPIO_SEL);
		ah->rfkill_polarity =
			MS(ah->rfsilent, EEP_RFSILENT_POLARITY);

		pCap->hw_caps |= ATH9K_HW_CAP_RFSILENT;
	}

	pCap->hw_caps &= ~ATH9K_HW_CAP_AUTOSLEEP;

	if (AR_SREV_9280(ah) || AR_SREV_9285(ah))
		pCap->hw_caps &= ~ATH9K_HW_CAP_4KB_SPLITTRANS;
	else
		pCap->hw_caps |= ATH9K_HW_CAP_4KB_SPLITTRANS;

	if (AR_SREV_9300_20_OR_LATER(ah)) {
		pCap->hw_caps |= ATH9K_HW_CAP_FASTCLOCK;
		if (!AR_SREV_9485(ah))
			pCap->hw_caps |= ATH9K_HW_CAP_LDPC;

		pCap->rx_hp_qdepth = ATH9K_HW_RX_HP_QDEPTH;
		pCap->rx_lp_qdepth = ATH9K_HW_RX_LP_QDEPTH;
		pCap->rx_status_len = sizeof(struct ar9003_rxs);
		pCap->tx_desc_len = sizeof(struct ar9003_txc);
		pCap->txs_len = sizeof(struct ar9003_txs);
		if (!ah->config.paprd_disable &&
		    ah->eep_ops->get_eeprom(ah, EEP_PAPRD))
			pCap->hw_caps |= ATH9K_HW_CAP_PAPRD;
	} else {
		pCap->tx_desc_len = sizeof(struct ath_desc);
		if (AR_SREV_9280_20(ah) &&
		    ((ah->eep_ops->get_eeprom(ah, EEP_MINOR_REV) <=
		      AR5416_EEP_MINOR_VER_16) ||
		     ah->eep_ops->get_eeprom(ah, EEP_FSTCLK_5G)))
			pCap->hw_caps |= ATH9K_HW_CAP_FASTCLOCK;
	}

	if (AR_SREV_9300_20_OR_LATER(ah))
		pCap->hw_caps |= ATH9K_HW_CAP_RAC_SUPPORTED;

	if (AR_SREV_9300_20_OR_LATER(ah))
		ah->ent_mode = REG_READ(ah, AR_ENT_OTP);

	if (AR_SREV_9287_11_OR_LATER(ah) || AR_SREV_9271(ah))
		pCap->hw_caps |= ATH9K_HW_CAP_SGI_20;

	if (AR_SREV_9285(ah))
		if (ah->eep_ops->get_eeprom(ah, EEP_MODAL_VER) >= 3) {
			ant_div_ctl1 =
				ah->eep_ops->get_eeprom(ah, EEP_ANT_DIV_CTL1);
			if ((ant_div_ctl1 & 0x1) && ((ant_div_ctl1 >> 3) & 0x1))
				pCap->hw_caps |= ATH9K_HW_CAP_ANT_DIV_COMB;
		}
	if (AR_SREV_9300_20_OR_LATER(ah)) {
		if (ah->eep_ops->get_eeprom(ah, EEP_CHAIN_MASK_REDUCE))
			pCap->hw_caps |= ATH9K_HW_CAP_APM;
	}


	if (AR_SREV_9485(ah)) {
		ant_div_ctl1 = ah->eep_ops->get_eeprom(ah, EEP_ANT_DIV_CTL1);
		/*
		 * enable the diversity-combining algorithm only when
		 * both enable_lna_div and enable_fast_div are set
		 *		Table for Diversity
		 * ant_div_alt_lnaconf		bit 0-1
		 * ant_div_main_lnaconf		bit 2-3
		 * ant_div_alt_gaintb		bit 4
		 * ant_div_main_gaintb		bit 5
		 * enable_ant_div_lnadiv	bit 6
		 * enable_ant_fast_div		bit 7
		 */
		if ((ant_div_ctl1 >> 0x6) == 0x3)
			pCap->hw_caps |= ATH9K_HW_CAP_ANT_DIV_COMB;
	}

	if (AR_SREV_9485_10(ah)) {
		pCap->pcie_lcr_extsync_en = 1;
		pCap->pcie_lcr_offset = 0x80;
	}

	tx_chainmask = pCap->tx_chainmask;
	rx_chainmask = pCap->rx_chainmask;
	while (tx_chainmask || rx_chainmask) {
		if (tx_chainmask & BIT(0))
			pCap->max_txchains++;
		if (rx_chainmask & BIT(0))
			pCap->max_rxchains++;

		tx_chainmask >>= 1;
		rx_chainmask >>= 1;
	}

	return 0;
}

/****************************/
/* GPIO / RFKILL / Antennae */
/****************************/

static void ath9k_hw_gpio_cfg_output_mux(struct ath_hw *ah,
					 u32 gpio, u32 type)
{
	int addr;
	u32 gpio_shift, tmp;

	if (gpio > 11)
		addr = AR_GPIO_OUTPUT_MUX3;
	else if (gpio > 5)
		addr = AR_GPIO_OUTPUT_MUX2;
	else
		addr = AR_GPIO_OUTPUT_MUX1;

	gpio_shift = (gpio % 6) * 5;

	if (AR_SREV_9280_20_OR_LATER(ah)
	    || (addr != AR_GPIO_OUTPUT_MUX1)) {
		REG_RMW(ah, addr, (type << gpio_shift),
			(0x1f << gpio_shift));
	} else {
		tmp = REG_READ(ah, addr);
		tmp = ((tmp & 0x1F0) << 1) | (tmp & ~0x1F0);
		tmp &= ~(0x1f << gpio_shift);
		tmp |= (type << gpio_shift);
		REG_WRITE(ah, addr, tmp);
	}
}

void ath9k_hw_cfg_gpio_input(struct ath_hw *ah, u32 gpio)
{
	u32 gpio_shift;

	if (AR_DEVID_7010(ah)) {
		gpio_shift = gpio;
		REG_RMW(ah, AR7010_GPIO_OE,
			(AR7010_GPIO_OE_AS_INPUT << gpio_shift),
			(AR7010_GPIO_OE_MASK << gpio_shift));
		return;
	}

	gpio_shift = gpio << 1;
	REG_RMW(ah,
		AR_GPIO_OE_OUT,
		(AR_GPIO_OE_OUT_DRV_NO << gpio_shift),
		(AR_GPIO_OE_OUT_DRV << gpio_shift));
}

u32 ath9k_hw_gpio_get(struct ath_hw *ah, u32 gpio)
{
#define MS_REG_READ(x, y) \
	(MS(REG_READ(ah, AR_GPIO_IN_OUT), x##_GPIO_IN_VAL) & (AR_GPIO_BIT(y)))

	if (gpio >= ah->caps.num_gpio_pins)
		return 0xffffffff;

	if (AR_DEVID_7010(ah)) {
		u32 val;
		val = REG_READ(ah, AR7010_GPIO_IN);
		return (MS(val, AR7010_GPIO_IN_VAL) & AR_GPIO_BIT(gpio)) == 0;
	} else if (AR_SREV_9300_20_OR_LATER(ah))
		return (MS(REG_READ(ah, AR_GPIO_IN), AR9300_GPIO_IN_VAL) &
			AR_GPIO_BIT(gpio)) != 0;
	else if (AR_SREV_9271(ah))
		return MS_REG_READ(AR9271, gpio) != 0;
	else if (AR_SREV_9287_11_OR_LATER(ah))
		return MS_REG_READ(AR9287, gpio) != 0;
	else if (AR_SREV_9285_12_OR_LATER(ah))
		return MS_REG_READ(AR9285, gpio) != 0;
	else if (AR_SREV_9280_20_OR_LATER(ah))
		return MS_REG_READ(AR928X, gpio) != 0;
	else
		return MS_REG_READ(AR, gpio) != 0;
}

void ath9k_hw_cfg_output(struct ath_hw *ah, u32 gpio,
			 u32 ah_signal_type)
{
	u32 gpio_shift;

	if (AR_DEVID_7010(ah)) {
		gpio_shift = gpio;
		REG_RMW(ah, AR7010_GPIO_OE,
			(AR7010_GPIO_OE_AS_OUTPUT << gpio_shift),
			(AR7010_GPIO_OE_MASK << gpio_shift));
		return;
	}

	ath9k_hw_gpio_cfg_output_mux(ah, gpio, ah_signal_type);
	gpio_shift = 2 * gpio;
	REG_RMW(ah,
		AR_GPIO_OE_OUT,
		(AR_GPIO_OE_OUT_DRV_ALL << gpio_shift),
		(AR_GPIO_OE_OUT_DRV << gpio_shift));
}

void ath9k_hw_set_gpio(struct ath_hw *ah, u32 gpio, u32 val)
{
	if (AR_DEVID_7010(ah)) {
		val = val ? 0 : 1;
		REG_RMW(ah, AR7010_GPIO_OUT, ((val&1) << gpio),
			AR_GPIO_BIT(gpio));
		return;
	}

	if (AR_SREV_9271(ah))
		val = ~val;

	REG_RMW(ah, AR_GPIO_IN_OUT, ((val & 1) << gpio),
		AR_GPIO_BIT(gpio));
}

u32 ath9k_hw_getdefantenna(struct ath_hw *ah)
{
	return REG_READ(ah, AR_DEF_ANTENNA) & 0x7;
}

void ath9k_hw_setantenna(struct ath_hw *ah, u32 antenna)
{
	REG_WRITE(ah, AR_DEF_ANTENNA, (antenna & 0x7));
}

/*********************/
/* General Operation */
/*********************/

u32 ath9k_hw_getrxfilter(struct ath_hw *ah)
{
	u32 bits = REG_READ(ah, AR_RX_FILTER);
	u32 phybits = REG_READ(ah, AR_PHY_ERR);

	if (phybits & AR_PHY_ERR_RADAR)
		bits |= ATH9K_RX_FILTER_PHYRADAR;
	if (phybits & (AR_PHY_ERR_OFDM_TIMING | AR_PHY_ERR_CCK_TIMING))
		bits |= ATH9K_RX_FILTER_PHYERR;

	return bits;
}

void ath9k_hw_setrxfilter(struct ath_hw *ah, u32 bits)
{
	u32 phybits;

	ENABLE_REGWRITE_BUFFER(ah);

	REG_WRITE(ah, AR_RX_FILTER, bits);

	phybits = 0;
	if (bits & ATH9K_RX_FILTER_PHYRADAR)
		phybits |= AR_PHY_ERR_RADAR;
	if (bits & ATH9K_RX_FILTER_PHYERR)
		phybits |= AR_PHY_ERR_OFDM_TIMING | AR_PHY_ERR_CCK_TIMING;
	REG_WRITE(ah, AR_PHY_ERR, phybits);

	if (phybits)
		REG_SET_BIT(ah, AR_RXCFG, AR_RXCFG_ZLFDMA);
	else
		REG_CLR_BIT(ah, AR_RXCFG, AR_RXCFG_ZLFDMA);

	REGWRITE_BUFFER_FLUSH(ah);
}

int ath9k_hw_phy_disable(struct ath_hw *ah)
{
	if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_WARM))
		return 0;

	ath9k_hw_init_pll(ah, NULL);
	return 1;
}

int ath9k_hw_disable(struct ath_hw *ah)
{
	if (!ath9k_hw_setpower(ah, ATH9K_PM_AWAKE))
		return 0;

	if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_COLD))
		return 0;

	ath9k_hw_init_pll(ah, NULL);
	return 1;
}

void ath9k_hw_set_txpowerlimit(struct ath_hw *ah, u32 limit, int test)
{
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);
	struct ath9k_channel *chan = ah->curchan;
	struct net80211_channel *channel = chan->chan;

	regulatory->power_limit = min(limit, (u32) MAX_RATE_POWER);

	ah->eep_ops->set_txpower(ah, chan,
				 ath9k_regd_get_ctl(regulatory, chan),
				 0,
				 channel->maxpower * 2,
				 min((u32) MAX_RATE_POWER,
				 (u32) regulatory->power_limit), test);
}

void ath9k_hw_setopmode(struct ath_hw *ah)
{
	ath9k_hw_set_operating_mode(ah);
}

void ath9k_hw_setmcastfilter(struct ath_hw *ah, u32 filter0, u32 filter1)
{
	REG_WRITE(ah, AR_MCAST_FIL0, filter0);
	REG_WRITE(ah, AR_MCAST_FIL1, filter1);
}

void ath9k_hw_write_associd(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);

	REG_WRITE(ah, AR_BSS_ID0, get_unaligned_le32(common->curbssid));
	REG_WRITE(ah, AR_BSS_ID1, get_unaligned_le16(common->curbssid + 4) |
		  ((common->curaid & 0x3fff) << AR_BSS_ID1_AID_S));
}

void ath9k_hw_set11nmac2040(struct ath_hw *ah)
{
	u32 macmode;

	macmode = 0;

	REG_WRITE(ah, AR_2040_MODE, macmode);
}

static struct {
	u32 version;
	const char * name;
} ath_mac_bb_names[] = {
	/* Devices with external radios */
	{ AR_SREV_VERSION_5416_PCI,	"5416" },
	{ AR_SREV_VERSION_5416_PCIE,	"5418" },
	{ AR_SREV_VERSION_9100,		"9100" },
	{ AR_SREV_VERSION_9160,		"9160" },
	/* Single-chip solutions */
	{ AR_SREV_VERSION_9280,		"9280" },
	{ AR_SREV_VERSION_9285,		"9285" },
	{ AR_SREV_VERSION_9287,         "9287" },
	{ AR_SREV_VERSION_9271,         "9271" },
	{ AR_SREV_VERSION_9300,         "9300" },
	{ AR_SREV_VERSION_9485,         "9485" },
};

/* For devices with external radios */
static struct {
	u16 version;
	const char * name;
} ath_rf_names[] = {
	{ 0,				"5133" },
	{ AR_RAD5133_SREV_MAJOR,	"5133" },
	{ AR_RAD5122_SREV_MAJOR,	"5122" },
	{ AR_RAD2133_SREV_MAJOR,	"2133" },
	{ AR_RAD2122_SREV_MAJOR,	"2122" }
};

/*
 * Return the MAC/BB name. "????" is returned if the MAC/BB is unknown.
 */
static const char *ath9k_hw_mac_bb_name(u32 mac_bb_version)
{
	unsigned int i;

	for (i=0; i<ARRAY_SIZE(ath_mac_bb_names); i++) {
		if (ath_mac_bb_names[i].version == mac_bb_version) {
			return ath_mac_bb_names[i].name;
		}
	}

	return "????";
}

/*
 * Return the RF name. "????" is returned if the RF is unknown.
 * Used for devices with external radios.
 */
static const char *ath9k_hw_rf_name(u16 rf_version)
{
	unsigned int i;

	for (i=0; i<ARRAY_SIZE(ath_rf_names); i++) {
		if (ath_rf_names[i].version == rf_version) {
			return ath_rf_names[i].name;
		}
	}

	return "????";
}

void ath9k_hw_name(struct ath_hw *ah, char *hw_name, size_t len)
{
	int used;

	/* chipsets >= AR9280 are single-chip */
	if (AR_SREV_9280_20_OR_LATER(ah)) {
		used = snprintf(hw_name, len,
			       "Atheros AR%s Rev:%x",
			       ath9k_hw_mac_bb_name(ah->hw_version.macVersion),
			       ah->hw_version.macRev);
	}
	else {
		used = snprintf(hw_name, len,
			       "Atheros AR%s MAC/BB Rev:%x AR%s RF Rev:%x",
			       ath9k_hw_mac_bb_name(ah->hw_version.macVersion),
			       ah->hw_version.macRev,
			       ath9k_hw_rf_name((ah->hw_version.analog5GhzRev &
						AR_RADIO_SREV_MAJOR)),
			       ah->hw_version.phyRev);
	}

	hw_name[used] = '\0';
}
