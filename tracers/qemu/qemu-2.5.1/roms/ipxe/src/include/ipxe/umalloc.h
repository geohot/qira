#ifndef _IPXE_UMALLOC_H
#define _IPXE_UMALLOC_H

/**
 * @file
 *
 * User memory allocation
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/api.h>
#include <config/umalloc.h>
#include <ipxe/uaccess.h>

/**
 * Provide a user memory allocation API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_UMALLOC( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( UMALLOC_PREFIX_ ## _subsys, _api_func, _func )

/* Include all architecture-independent I/O API headers */
#include <ipxe/efi/efi_umalloc.h>
#include <ipxe/linux/linux_umalloc.h>

/* Include all architecture-dependent I/O API headers */
#include <bits/umalloc.h>

/**
 * Reallocate external memory
 *
 * @v userptr		Memory previously allocated by umalloc(), or UNULL
 * @v new_size		Requested size
 * @ret userptr		Allocated memory, or UNULL
 *
 * Calling realloc() with a new size of zero is a valid way to free a
 * memory block.
 */
userptr_t urealloc ( userptr_t userptr, size_t new_size );

/**
 * Allocate external memory
 *
 * @v size		Requested size
 * @ret userptr		Memory, or UNULL
 *
 * Memory is guaranteed to be aligned to a page boundary.
 */
static inline __always_inline userptr_t umalloc ( size_t size ) {
	return urealloc ( UNULL, size );
}

/**
 * Free external memory
 *
 * @v userptr		Memory allocated by umalloc(), or UNULL
 *
 * If @c ptr is UNULL, no action is taken.
 */
static inline __always_inline void ufree ( userptr_t userptr ) {
	urealloc ( userptr, 0 );
}

#endif /* _IPXE_UMALLOC_H */
