#ifndef _IPXE_MEMBLOCK_H
#define _IPXE_MEMBLOCK_H

/** @file
 *
 * Largest memory block
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/uaccess.h>

extern size_t largest_memblock ( userptr_t *start );

#endif /* _IPXE_MEMBLOCK_H */
