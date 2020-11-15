#ifndef _IPXE_SEGMENT_H
#define _IPXE_SEGMENT_H

/**
 * @file
 *
 * Executable image segments
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/uaccess.h>

extern int prep_segment ( userptr_t segment, size_t filesz, size_t memsz );

#endif /* _IPXE_SEGMENT_H */
