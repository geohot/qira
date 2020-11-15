#ifndef _IPXE_LINUX_NAP_H
#define _IPXE_LINUX_NAP_H

/** @file
 *
 * Linux CPU sleeping
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef NAP_LINUX
#define NAP_PREFIX_linux
#else
#define NAP_PREFIX_linux __linux_
#endif

#endif /* _IPXE_LINUX_NAP_H */
