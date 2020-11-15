#ifndef _IPXE_PIT8254_H
#define _IPXE_PIT8254_H

/** @file
 *
 * 8254 Programmable Interval Timer
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** IRQ0 channel */
#define PIT8254_CH_IRQ0 0

/** PC speaker channel */
#define PIT8254_CH_SPKR 2

/** Timer frequency (1.193182MHz) */
#define PIT8254_HZ 1193182UL

/** Data port */
#define PIT8254_DATA(channel) ( 0x40 + (channel) )

/** Mode/command register */
#define PIT8254_CMD 0x43

/** Select channel */
#define PIT8254_CMD_CHANNEL(channel) ( (channel) << 6 )

/** Access modes */
#define PIT8254_CMD_ACCESS_LATCH 0x00	/**< Latch count value command */
#define PIT8254_CMD_ACCESS_LO	0x10	/**< Low byte only */
#define PIT8254_CMD_ACCESS_HI	0x20	/**< High byte only */
#define PIT8254_CMD_ACCESS_LOHI	0x30	/**< Low-byte, high-byte pair */

/* Operating modes */
#define PIT8254_CMD_OP_TERMINAL	0x00	/**< Interrupt on terminal count */
#define PIT8254_CMD_OP_ONESHOT	0x02	/**< Hardware re-triggerable one-shot */
#define PIT8254_CMD_OP_RATE	0x04	/**< Rate generator */
#define PIT8254_CMD_OP_SQUARE	0x06	/**< Square wave generator */
#define PIT8254_CMD_OP_SWSTROBE	0x08	/**< Software triggered strobe */
#define PIT8254_CMD_OP_HWSTROBE	0x0a	/**< Hardware triggered strobe */
#define PIT8254_CMD_OP_RATE2	0x0c	/**< Rate generator (duplicate) */
#define PIT8254_CMD_OP_SQUARE2	0x0e	/**< Square wave generator (duplicate)*/

/** Binary mode */
#define PIT8254_CMD_BINARY 0x00

/** BCD mode */
#define PIT8254_CMD_BCD 0x01

/** PC speaker control register */
#define PIT8254_SPKR 0x61

/** PC speaker channel gate */
#define PIT8254_SPKR_GATE 0x01

/** PC speaker enabled */
#define PIT8254_SPKR_ENABLE 0x02

/** PC speaker channel output */
#define PIT8254_SPKR_OUT 0x20

extern void pit8254_speaker_delay ( unsigned int ticks );

/**
 * Delay for a fixed number of microseconds
 *
 * @v usecs		Number of microseconds for which to delay
 */
static inline __attribute__ (( always_inline )) void
pit8254_udelay ( unsigned long usecs ) {

	/* Delays are invariably compile-time constants; force the
	 * multiplication and division to take place at compilation
	 * time rather than runtime.
	 */
	pit8254_speaker_delay ( ( usecs * PIT8254_HZ ) / 1000000 );
}

#endif /* _IPXE_PIT8254_H */
