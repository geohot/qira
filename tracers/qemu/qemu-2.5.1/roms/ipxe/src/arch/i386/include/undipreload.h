#ifndef _UNDIPRELOAD_H
#define _UNDIPRELOAD_H

/** @file
 *
 * Preloaded UNDI stack
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <realmode.h>
#include <undi.h>

extern struct undi_device __data16 ( preloaded_undi );
#define preloaded_undi __use_data16 ( preloaded_undi )

#endif /* _UNDIPRELOAD_H */
