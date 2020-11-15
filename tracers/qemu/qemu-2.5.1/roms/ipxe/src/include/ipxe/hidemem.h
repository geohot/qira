#ifndef _IPXE_HIDEMEM_H
#define _IPXE_HIDEMEM_H

/**
 * @file
 *
 * Hidden memory regions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

extern void hide_umalloc ( physaddr_t start, physaddr_t end );

#endif /* _IPXE_HIDEMEM_H */
