/*
 * Copyright (c) 2004-2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006-2008 Nick Kossifidis <mickflemm@gmail.com>
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

/****************\
  GPIO Functions
\****************/

#include "ath5k.h"
#include "reg.h"
#include "base.h"

/*
 * Set GPIO inputs
 */
int ath5k_hw_set_gpio_input(struct ath5k_hw *ah, u32 gpio)
{
	if (gpio >= AR5K_NUM_GPIO)
		return -EINVAL;

	ath5k_hw_reg_write(ah,
		(ath5k_hw_reg_read(ah, AR5K_GPIOCR) & ~AR5K_GPIOCR_OUT(gpio))
		| AR5K_GPIOCR_IN(gpio), AR5K_GPIOCR);

	return 0;
}

/*
 * Set GPIO outputs
 */
int ath5k_hw_set_gpio_output(struct ath5k_hw *ah, u32 gpio)
{
	if (gpio >= AR5K_NUM_GPIO)
		return -EINVAL;

	ath5k_hw_reg_write(ah,
		(ath5k_hw_reg_read(ah, AR5K_GPIOCR) & ~AR5K_GPIOCR_OUT(gpio))
		| AR5K_GPIOCR_OUT(gpio), AR5K_GPIOCR);

	return 0;
}

/*
 * Get GPIO state
 */
u32 ath5k_hw_get_gpio(struct ath5k_hw *ah, u32 gpio)
{
	if (gpio >= AR5K_NUM_GPIO)
		return 0xffffffff;

	/* GPIO input magic */
	return ((ath5k_hw_reg_read(ah, AR5K_GPIODI) & AR5K_GPIODI_M) >> gpio) &
		0x1;
}

/*
 * Set GPIO state
 */
int ath5k_hw_set_gpio(struct ath5k_hw *ah, u32 gpio, u32 val)
{
	u32 data;

	if (gpio >= AR5K_NUM_GPIO)
		return -EINVAL;

	/* GPIO output magic */
	data = ath5k_hw_reg_read(ah, AR5K_GPIODO);

	data &= ~(1 << gpio);
	data |= (val & 1) << gpio;

	ath5k_hw_reg_write(ah, data, AR5K_GPIODO);

	return 0;
}

/*
 * Initialize the GPIO interrupt (RFKill switch)
 */
void ath5k_hw_set_gpio_intr(struct ath5k_hw *ah, unsigned int gpio,
		u32 interrupt_level)
{
	u32 data;

	if (gpio >= AR5K_NUM_GPIO)
		return;

	/*
	 * Set the GPIO interrupt
	 */
	data = (ath5k_hw_reg_read(ah, AR5K_GPIOCR) &
		~(AR5K_GPIOCR_INT_SEL(gpio) | AR5K_GPIOCR_INT_SELH |
		AR5K_GPIOCR_INT_ENA | AR5K_GPIOCR_OUT(gpio))) |
		(AR5K_GPIOCR_INT_SEL(gpio) | AR5K_GPIOCR_INT_ENA);

	ath5k_hw_reg_write(ah, interrupt_level ? data :
		(data | AR5K_GPIOCR_INT_SELH), AR5K_GPIOCR);

	ah->ah_imr |= AR5K_IMR_GPIO;

	/* Enable GPIO interrupts */
	AR5K_REG_ENABLE_BITS(ah, AR5K_PIMR, AR5K_IMR_GPIO);
}

