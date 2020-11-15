#ifndef _IPXE_MEMTOP_UMALLOC_H
#define _IPXE_MEMTOP_UMALLOC_H

/** @file
 *
 * External memory allocation
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef UMALLOC_MEMTOP
#define UMALLOC_PREFIX_memtop
#else
#define UMALLOC_PREFIX_memtop __memtop_
#endif

#endif /* _IPXE_MEMTOP_UMALLOC_H */
