/*
 *   OpenBIOS native timer driver
 *
 *   (C) 2004 Stefan Reinauer <stepan@openbios.org>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "drivers/drivers.h"
#include "timer.h"
#include "asm/io.h"

#if defined(CONFIG_X86) || defined(CONFIG_AMD64)

void setup_timers(void)
{
	/* nothing to do */
}

static void load_timer2(unsigned int ticks)
{
	/* Set up the timer gate, turn off the speaker */
	outb((inb(PPC_PORTB) & ~PPCB_SPKR) | PPCB_T2GATE, PPC_PORTB);
	outb(TIMER2_SEL | WORD_ACCESS | MODE0 | BINARY_COUNT,
	     TIMER_MODE_PORT);
	outb(ticks & 0xFF, TIMER2_PORT);
	outb(ticks >> 8, TIMER2_PORT);
}

void udelay(unsigned int usecs)
{
	load_timer2((usecs * TICKS_PER_MS) / 1000);
	while ((inb(PPC_PORTB) & PPCB_T2OUT) == 0);
}

unsigned long currticks(void)
{
	static unsigned long totticks = 0UL;	/* High resolution */
	unsigned long ticks = 0;
	unsigned char portb = inb(PPC_PORTB);

	/*
	 * Read the timer, and hope it hasn't wrapped around
	 * (call this again within 54ms), then restart it
	 */
	outb(TIMER2_SEL | LATCH_COUNT, TIMER_MODE_PORT);
	ticks = inb(TIMER2_PORT);
	ticks |= inb(TIMER2_PORT) << 8;
	outb(TIMER2_SEL | WORD_ACCESS | MODE0 | BINARY_COUNT,
	     TIMER_MODE_PORT);
	outb(0, TIMER2_PORT);
	outb(0, TIMER2_PORT);

	/*
	 * Check if the timer was running. If not,
	 * result is rubbish and need to start it
	 */
	if (portb & PPCB_T2GATE) {
		totticks += (0x10000 - ticks);
	} else {
		/* Set up the timer gate, turn off the speaker */
		outb((portb & ~PPCB_SPKR) | PPCB_T2GATE, PPC_PORTB);
	}
	return totticks / TICKS_PER_MS;
}
#endif

#ifdef CONFIG_PPC

void setup_timers(void)
{
	/* nothing to do */
}

/*
 * TODO: pass via lb table
 */
unsigned long timer_freq = 10000000 / 4;

void udelay(unsigned int usecs)
{
	unsigned long ticksperusec = timer_freq / 1000000;
	_wait_ticks(ticksperusec * usecs);
}

#endif

void ndelay(unsigned int nsecs)
{
	udelay((nsecs + 999) / 1000);
}

void mdelay(unsigned int msecs)
{
	udelay(msecs * 1000);
}
