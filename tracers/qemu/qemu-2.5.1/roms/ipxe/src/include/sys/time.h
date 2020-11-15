#ifndef _SYS_TIME_H
#define _SYS_TIME_H

/** @file
 *
 * Date and time
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/** Seconds since the Epoch
 *
 * We use a 64-bit type to avoid Y2K38 issues, since we may have to
 * handle distant future dates (e.g. X.509 certificate expiry dates).
 */
typedef int64_t time_t;

#endif /* _SYS_TIME_H */
