#ifndef _IPXE_LINUX_UMALLOC_H
#define _IPXE_LINUX_UMALLOC_H

/** @file
 *
 * iPXE user memory allocation API for Linux
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef UMALLOC_LINUX
#define UMALLOC_PREFIX_linux
#else
#define UMALLOC_PREFIX_linux __linux_
#endif

#endif /* _IPXE_LINUX_UMALLOC_H */
