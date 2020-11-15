#ifndef _INITRD_H
#define _INITRD_H

/** @file
 *
 * Initial ramdisk (initrd) reshuffling
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/uaccess.h>

/** Minimum alignment for initrds
 *
 * Some versions of Linux complain about initrds that are not
 * page-aligned.
 */
#define INITRD_ALIGN 4096

/** Minimum free space required to reshuffle initrds
 *
 * Chosen to avoid absurdly long reshuffling times
 */
#define INITRD_MIN_FREE_LEN ( 512 * 1024 )

extern void initrd_reshuffle ( userptr_t bottom );
extern int initrd_reshuffle_check ( size_t len, userptr_t bottom );

#endif /* _INITRD_H */
