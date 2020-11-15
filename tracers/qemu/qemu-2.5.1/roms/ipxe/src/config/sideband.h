#ifndef CONFIG_SIDEBAND_H
#define CONFIG_SIDEBAND_H

/** @file
 *
 * Sideband access by platform firmware
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

//#define	CONFIG_BOFM	/* IBM's BladeCenter Open Fabric Manager */

#include <config/named.h>
#include NAMED_CONFIG(sideband.h)
#include <config/local/sideband.h>
#include LOCAL_NAMED_CONFIG(sideband.h)

#endif /* CONFIG_SIDEBAND_H */
