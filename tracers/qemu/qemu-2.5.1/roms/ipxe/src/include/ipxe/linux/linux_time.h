#ifndef _IPXE_LINUX_TIME_H
#define _IPXE_LINUX_TIME_H

/** @file
 *
 * Linux time source
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef TIME_LINUX
#define TIME_PREFIX_linux
#else
#define TIME_PREFIX_linux __linux_
#endif

#endif /* _IPXE_LINUX_TIME_H */
