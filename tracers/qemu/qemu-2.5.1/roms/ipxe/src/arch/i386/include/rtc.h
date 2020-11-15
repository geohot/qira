#ifndef _RTC_H
#define _RTC_H

/** @file
 *
 * CMOS Real-Time Clock (RTC)
 *
 * The CMOS/RTC registers are documented (with varying degrees of
 * accuracy and consistency) at
 *
 *    http://www.nondot.org/sabre/os/files/MiscHW/RealtimeClockFAQ.txt
 *    http://wiki.osdev.org/RTC
 *    http://wiki.osdev.org/CMOS
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <pic8259.h>

/** RTC IRQ */
#define RTC_IRQ 8

/** RTC interrupt vector */
#define RTC_INT IRQ_INT ( RTC_IRQ )

/** CMOS/RTC address (and NMI) register */
#define CMOS_ADDRESS 0x70

/** NMI disable bit */
#define CMOS_DISABLE_NMI 0x80

/** CMOS/RTC data register */
#define CMOS_DATA 0x71

/** RTC seconds */
#define RTC_SEC 0x00

/** RTC minutes */
#define RTC_MIN 0x02

/** RTC hours */
#define RTC_HOUR 0x04

/** RTC weekday */
#define RTC_WDAY 0x06

/** RTC day of month */
#define RTC_MDAY 0x07

/** RTC month */
#define RTC_MON 0x08

/** RTC year */
#define RTC_YEAR 0x09

/** RTC status register A */
#define RTC_STATUS_A 0x0a

/** RTC update in progress bit */
#define RTC_STATUS_A_UPDATE_IN_PROGRESS 0x80

/** RTC status register B */
#define RTC_STATUS_B 0x0b

/** RTC 24 hour format bit */
#define RTC_STATUS_B_24_HOUR 0x02

/** RTC binary mode bit */
#define RTC_STATUS_B_BINARY 0x04

/** RTC Periodic Interrupt Enabled bit */
#define RTC_STATUS_B_PIE 0x40

/** RTC status register C */
#define RTC_STATUS_C 0x0c

/** RTC status register D */
#define RTC_STATUS_D 0x0d

/** CMOS default address */
#define CMOS_DEFAULT_ADDRESS RTC_STATUS_D

#endif /* _RTC_H */
