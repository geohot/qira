/*
 * Copyright (c) 2004-2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006-2008 Nick Kossifidis <mickflemm@gmail.com>
 *
 * Modified for iPXE, July 2009, by Joshua Oreman <oremanj@rwcr.net>
 * Original from Linux kernel 2.6.30.
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

/*************************************\
* Attach/Detach Functions and helpers *
\*************************************/

#include <ipxe/pci.h>
#include <unistd.h>
#include <stdlib.h>
#include "ath5k.h"
#include "reg.h"
#include "base.h"

/**
 * ath5k_hw_post - Power On Self Test helper function
 *
 * @ah: The &struct ath5k_hw
 */
static int ath5k_hw_post(struct ath5k_hw *ah)
{

	static const u32 static_pattern[4] = {
		0x55555555,	0xaaaaaaaa,
		0x66666666,	0x99999999
	};
	static const u16 regs[2] = { AR5K_STA_ID0, AR5K_PHY(8) };
	int i, c;
	u16 cur_reg;
	u32 var_pattern;
	u32 init_val;
	u32 cur_val;

	for (c = 0; c < 2; c++) {

		cur_reg = regs[c];

		/* Save previous value */
		init_val = ath5k_hw_reg_read(ah, cur_reg);

		for (i = 0; i < 256; i++) {
			var_pattern = i << 16 | i;
			ath5k_hw_reg_write(ah, var_pattern, cur_reg);
			cur_val = ath5k_hw_reg_read(ah, cur_reg);

			if (cur_val != var_pattern) {
				DBG("ath5k: POST failed!\n");
				return -EAGAIN;
			}

			/* Found on ndiswrapper dumps */
			var_pattern = 0x0039080f;
			ath5k_hw_reg_write(ah, var_pattern, cur_reg);
		}

		for (i = 0; i < 4; i++) {
			var_pattern = static_pattern[i];
			ath5k_hw_reg_write(ah, var_pattern, cur_reg);
			cur_val = ath5k_hw_reg_read(ah, cur_reg);

			if (cur_val != var_pattern) {
				DBG("ath5k: POST failed!\n");
				return -EAGAIN;
			}

			/* Found on ndiswrapper dumps */
			var_pattern = 0x003b080f;
			ath5k_hw_reg_write(ah, var_pattern, cur_reg);
		}

		/* Restore previous value */
		ath5k_hw_reg_write(ah, init_val, cur_reg);

	}

	return 0;

}

/**
 * ath5k_hw_attach - Check if hw is supported and init the needed structs
 *
 * @sc: The &struct ath5k_softc we got from the driver's attach function
 * @mac_version: The mac version id (check out ath5k.h) based on pci id
 * @hw: Returned newly allocated hardware structure, on success
 *
 * Check if the device is supported, perform a POST and initialize the needed
 * structs. Returns -ENOMEM if we don't have memory for the needed structs,
 * -ENODEV if the device is not supported or prints an error msg if something
 * else went wrong.
 */
int ath5k_hw_attach(struct ath5k_softc *sc, u8 mac_version,
		    struct ath5k_hw **hw)
{
	struct ath5k_hw *ah;
	struct pci_device *pdev = sc->pdev;
	int ret;
	u32 srev;

	ah = zalloc(sizeof(struct ath5k_hw));
	if (ah == NULL) {
		ret = -ENOMEM;
		DBG("ath5k: out of memory\n");
		goto err;
	}

	ah->ah_sc = sc;
	ah->ah_iobase = sc->iobase;

	/*
	 * HW information
	 */
	ah->ah_turbo = 0;
	ah->ah_txpower.txp_tpc = 0;
	ah->ah_imr = 0;
	ah->ah_atim_window = 0;
	ah->ah_aifs = AR5K_TUNE_AIFS;
	ah->ah_cw_min = AR5K_TUNE_CWMIN;
	ah->ah_limit_tx_retries = AR5K_INIT_TX_RETRY;
	ah->ah_software_retry = 0;
	ah->ah_ant_diversity = AR5K_TUNE_ANT_DIVERSITY;

	/*
	 * Set the mac version based on the pci id
	 */
	ah->ah_version = mac_version;

	/*Fill the ath5k_hw struct with the needed functions*/
	ret = ath5k_hw_init_desc_functions(ah);
	if (ret)
		goto err_free;

	/* Bring device out of sleep and reset it's units */
	ret = ath5k_hw_nic_wakeup(ah, CHANNEL_B, 1);
	if (ret)
		goto err_free;

	/* Get MAC, PHY and RADIO revisions */
	srev = ath5k_hw_reg_read(ah, AR5K_SREV);
	ah->ah_mac_srev = srev;
	ah->ah_mac_version = AR5K_REG_MS(srev, AR5K_SREV_VER);
	ah->ah_mac_revision = AR5K_REG_MS(srev, AR5K_SREV_REV);
	ah->ah_phy_revision = ath5k_hw_reg_read(ah, AR5K_PHY_CHIP_ID);
	ah->ah_radio_5ghz_revision = ath5k_hw_radio_revision(ah, CHANNEL_5GHZ);
	ah->ah_phy = AR5K_PHY(0);

	/* Try to identify radio chip based on it's srev */
	switch (ah->ah_radio_5ghz_revision & 0xf0) {
	case AR5K_SREV_RAD_5111:
		ah->ah_radio = AR5K_RF5111;
		ah->ah_single_chip = 0;
		ah->ah_radio_2ghz_revision = ath5k_hw_radio_revision(ah,
							CHANNEL_2GHZ);
		break;
	case AR5K_SREV_RAD_5112:
	case AR5K_SREV_RAD_2112:
		ah->ah_radio = AR5K_RF5112;
		ah->ah_single_chip = 0;
		ah->ah_radio_2ghz_revision = ath5k_hw_radio_revision(ah,
							CHANNEL_2GHZ);
		break;
	case AR5K_SREV_RAD_2413:
		ah->ah_radio = AR5K_RF2413;
		ah->ah_single_chip = 1;
		break;
	case AR5K_SREV_RAD_5413:
		ah->ah_radio = AR5K_RF5413;
		ah->ah_single_chip = 1;
		break;
	case AR5K_SREV_RAD_2316:
		ah->ah_radio = AR5K_RF2316;
		ah->ah_single_chip = 1;
		break;
	case AR5K_SREV_RAD_2317:
		ah->ah_radio = AR5K_RF2317;
		ah->ah_single_chip = 1;
		break;
	case AR5K_SREV_RAD_5424:
		if (ah->ah_mac_version == AR5K_SREV_AR2425 ||
		    ah->ah_mac_version == AR5K_SREV_AR2417) {
			ah->ah_radio = AR5K_RF2425;
		} else {
			ah->ah_radio = AR5K_RF5413;
		}
		ah->ah_single_chip = 1;
		break;
	default:
		/* Identify radio based on mac/phy srev */
		if (ah->ah_version == AR5K_AR5210) {
			ah->ah_radio = AR5K_RF5110;
			ah->ah_single_chip = 0;
		} else if (ah->ah_version == AR5K_AR5211) {
			ah->ah_radio = AR5K_RF5111;
			ah->ah_single_chip = 0;
			ah->ah_radio_2ghz_revision = ath5k_hw_radio_revision(ah,
								CHANNEL_2GHZ);
		} else if (ah->ah_mac_version == (AR5K_SREV_AR2425 >> 4) ||
			   ah->ah_mac_version == (AR5K_SREV_AR2417 >> 4) ||
			   ah->ah_phy_revision == AR5K_SREV_PHY_2425) {
			ah->ah_radio = AR5K_RF2425;
			ah->ah_single_chip = 1;
			ah->ah_radio_5ghz_revision = AR5K_SREV_RAD_2425;
		} else if (srev == AR5K_SREV_AR5213A &&
			   ah->ah_phy_revision == AR5K_SREV_PHY_5212B) {
			ah->ah_radio = AR5K_RF5112;
			ah->ah_single_chip = 0;
			ah->ah_radio_5ghz_revision = AR5K_SREV_RAD_5112B;
		} else if (ah->ah_mac_version == (AR5K_SREV_AR2415 >> 4)) {
			ah->ah_radio = AR5K_RF2316;
			ah->ah_single_chip = 1;
			ah->ah_radio_5ghz_revision = AR5K_SREV_RAD_2316;
		} else if (ah->ah_mac_version == (AR5K_SREV_AR5414 >> 4) ||
			   ah->ah_phy_revision == AR5K_SREV_PHY_5413) {
			ah->ah_radio = AR5K_RF5413;
			ah->ah_single_chip = 1;
			ah->ah_radio_5ghz_revision = AR5K_SREV_RAD_5413;
		} else if (ah->ah_mac_version == (AR5K_SREV_AR2414 >> 4) ||
			   ah->ah_phy_revision == AR5K_SREV_PHY_2413) {
			ah->ah_radio = AR5K_RF2413;
			ah->ah_single_chip = 1;
			ah->ah_radio_5ghz_revision = AR5K_SREV_RAD_2413;
		} else {
			DBG("ath5k: Couldn't identify radio revision.\n");
			ret = -ENOTSUP;
			goto err_free;
		}
	}

	/* Return on unsuported chips (unsupported eeprom etc) */
	if ((srev >= AR5K_SREV_AR5416) &&
	    (srev < AR5K_SREV_AR2425)) {
		DBG("ath5k: Device not yet supported.\n");
		ret = -ENOTSUP;
		goto err_free;
	}

	/*
	 * Write PCI-E power save settings
	 */
	if ((ah->ah_version == AR5K_AR5212) &&
	    pci_find_capability(pdev, PCI_CAP_ID_EXP)) {
		ath5k_hw_reg_write(ah, 0x9248fc00, AR5K_PCIE_SERDES);
		ath5k_hw_reg_write(ah, 0x24924924, AR5K_PCIE_SERDES);
		/* Shut off RX when elecidle is asserted */
		ath5k_hw_reg_write(ah, 0x28000039, AR5K_PCIE_SERDES);
		ath5k_hw_reg_write(ah, 0x53160824, AR5K_PCIE_SERDES);
		/* TODO: EEPROM work */
		ath5k_hw_reg_write(ah, 0xe5980579, AR5K_PCIE_SERDES);
		/* Shut off PLL and CLKREQ active in L1 */
		ath5k_hw_reg_write(ah, 0x001defff, AR5K_PCIE_SERDES);
		/* Preserce other settings */
		ath5k_hw_reg_write(ah, 0x1aaabe40, AR5K_PCIE_SERDES);
		ath5k_hw_reg_write(ah, 0xbe105554, AR5K_PCIE_SERDES);
		ath5k_hw_reg_write(ah, 0x000e3007, AR5K_PCIE_SERDES);
		/* Reset SERDES to load new settings */
		ath5k_hw_reg_write(ah, 0x00000000, AR5K_PCIE_SERDES_RESET);
		mdelay(1);
	}

	/*
	 * POST
	 */
	ret = ath5k_hw_post(ah);
	if (ret)
		goto err_free;

	/* Enable pci core retry fix on Hainan (5213A) and later chips */
	if (srev >= AR5K_SREV_AR5213A)
		ath5k_hw_reg_write(ah, AR5K_PCICFG_RETRY_FIX, AR5K_PCICFG);

	/*
	 * Get card capabilities, calibration values etc
	 * TODO: EEPROM work
	 */
	ret = ath5k_eeprom_init(ah);
	if (ret) {
		DBG("ath5k: unable to init EEPROM\n");
		goto err_free;
	}

	/* Get misc capabilities */
	ret = ath5k_hw_set_capabilities(ah);
	if (ret) {
		DBG("ath5k: unable to get device capabilities: 0x%04x\n",
		    sc->pdev->device);
		goto err_free;
	}

	if (srev >= AR5K_SREV_AR2414) {
		ah->ah_combined_mic = 1;
		AR5K_REG_ENABLE_BITS(ah, AR5K_MISC_MODE,
				     AR5K_MISC_MODE_COMBINED_MIC);
	}

	/* Set BSSID to bcast address: ff:ff:ff:ff:ff:ff for now */
	memset(ah->ah_bssid, 0xff, ETH_ALEN);
	ath5k_hw_set_associd(ah, ah->ah_bssid, 0);
	ath5k_hw_set_opmode(ah);

	ath5k_hw_rfgain_opt_init(ah);

	*hw = ah;
	return 0;
err_free:
	free(ah);
err:
	return ret;
}

/**
 * ath5k_hw_detach - Free the ath5k_hw struct
 *
 * @ah: The &struct ath5k_hw
 */
void ath5k_hw_detach(struct ath5k_hw *ah)
{
	free(ah->ah_rf_banks);
	ath5k_eeprom_detach(ah);
	free(ah);
}
