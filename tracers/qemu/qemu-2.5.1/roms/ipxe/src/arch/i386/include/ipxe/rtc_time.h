#ifndef _IPXE_RTC_TIME_H
#define _IPXE_RTC_TIME_H

/** @file
 *
 * RTC-based time source
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef TIME_RTC
#define TIME_PREFIX_rtc
#else
#define TIME_PREFIX_rtc __rtc_
#endif

#endif /* _IPXE_RTC_TIME_H */
