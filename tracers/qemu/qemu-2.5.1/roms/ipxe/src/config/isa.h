#ifndef CONFIG_ISA_H
#define CONFIG_ISA_H

/** @file
 *
 * ISA probe address configuration
 *
 * You can override the list of addresses that will be probed by any
 * ISA drivers.
 *
 */
#undef	ISA_PROBE_ADDRS		/* e.g. 0x200, 0x300 */
#undef	ISA_PROBE_ONLY		/* Do not probe any other addresses */

#include <config/local/isa.h>

#endif /* CONFIG_ISA_H */
