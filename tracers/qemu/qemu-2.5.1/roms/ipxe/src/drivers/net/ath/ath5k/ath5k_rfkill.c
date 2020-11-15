/*
 * RFKILL support for ath5k
 *
 * Copyright (c) 2009 Tobias Doerffel <tobias.doerffel@gmail.com>
 * Lightly modified for iPXE, Sep 2008 by Joshua Oreman <oremanj@rwcr.net>
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
 */

FILE_LICENCE ( MIT );

#include "base.h"


static inline void ath5k_rfkill_disable(struct ath5k_softc *sc)
{
	DBG("ath5k: rfkill disable (gpio:%d polarity:%d)\n",
	    sc->rf_kill.gpio, sc->rf_kill.polarity);
	ath5k_hw_set_gpio_output(sc->ah, sc->rf_kill.gpio);
	ath5k_hw_set_gpio(sc->ah, sc->rf_kill.gpio, !sc->rf_kill.polarity);
}


static inline void ath5k_rfkill_enable(struct ath5k_softc *sc)
{
	DBG("ath5k: rfkill enable (gpio:%d polarity:%d)\n",
	    sc->rf_kill.gpio, sc->rf_kill.polarity);
	ath5k_hw_set_gpio_output(sc->ah, sc->rf_kill.gpio);
	ath5k_hw_set_gpio(sc->ah, sc->rf_kill.gpio, sc->rf_kill.polarity);
}

static inline void ath5k_rfkill_set_intr(struct ath5k_softc *sc, int enable)
{
	struct ath5k_hw *ah = sc->ah;
	u32 curval;

	ath5k_hw_set_gpio_input(ah, sc->rf_kill.gpio);
	curval = ath5k_hw_get_gpio(ah, sc->rf_kill.gpio);
	ath5k_hw_set_gpio_intr(ah, sc->rf_kill.gpio, enable ?
			       !!curval : !curval);
}

static int __unused
ath5k_is_rfkill_set(struct ath5k_softc *sc)
{
	/* configuring GPIO for input for some reason disables rfkill */
	/*ath5k_hw_set_gpio_input(sc->ah, sc->rf_kill.gpio);*/
	return (ath5k_hw_get_gpio(sc->ah, sc->rf_kill.gpio) ==
		sc->rf_kill.polarity);
}

void
ath5k_rfkill_hw_start(struct ath5k_hw *ah)
{
	struct ath5k_softc *sc = ah->ah_sc;

	/* read rfkill GPIO configuration from EEPROM header */
	sc->rf_kill.gpio = ah->ah_capabilities.cap_eeprom.ee_rfkill_pin;
	sc->rf_kill.polarity = ah->ah_capabilities.cap_eeprom.ee_rfkill_pol;

	ath5k_rfkill_disable(sc);

	/* enable interrupt for rfkill switch */
	if (AR5K_EEPROM_HDR_RFKILL(ah->ah_capabilities.cap_eeprom.ee_header))
		ath5k_rfkill_set_intr(sc, 1);
}


void
ath5k_rfkill_hw_stop(struct ath5k_hw *ah)
{
	struct ath5k_softc *sc = ah->ah_sc;

	/* disable interrupt for rfkill switch */
	if (AR5K_EEPROM_HDR_RFKILL(ah->ah_capabilities.cap_eeprom.ee_header))
		ath5k_rfkill_set_intr(sc, 0);

	/* enable RFKILL when stopping HW so Wifi LED is turned off */
	ath5k_rfkill_enable(sc);
}
