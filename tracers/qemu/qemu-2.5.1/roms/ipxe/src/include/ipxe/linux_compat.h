#ifndef _IPXE_LINUX_COMPAT_H
#define _IPXE_LINUX_COMPAT_H

/** @file
 *
 * Linux code compatibility
 *
 * This file exists to ease the building of Linux source code within
 * iPXE.  This is intended to facilitate quick testing; it is not
 * intended to be a substitute for proper porting.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <byteswap.h>
#include <ipxe/bitops.h>

#define __init
#define __exit
#define __initdata
#define __exitdata
#define printk printf

#endif /* _IPXE_LINUX_COMPAT_H */
