#ifndef _IPXE_LINUX_TIMER_H
#define _IPXE_LINUX_TIMER_H

/** @file
 *
 * iPXE timer API for Linux
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef TIMER_LINUX
#define TIMER_PREFIX_linux
#else
#define TIMER_PREFIX_linux __linux_
#endif

#endif /* _IPXE_LINUX_TIMER_H */
