#ifndef _IPXE_LINUX_UACCESS_H
#define _IPXE_LINUX_UACCESS_H

/** @file
 *
 * iPXE user access API for Linux
 *
 * We run with no distinction between internal and external addresses,
 * so can use trivial_virt_to_user() et al.
 *
 * We have no concept of the underlying physical addresses, since
 * these are not exposed to userspace.  We provide a stub
 * implementation of user_to_phys() since this is required by
 * alloc_memblock().  We provide no implementation of phys_to_user();
 * any code attempting to access physical addresses will therefore
 * (correctly) fail to link.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef UACCESS_LINUX
#define UACCESS_PREFIX_linux
#else
#define UACCESS_PREFIX_linux __linux_
#endif

/**
 * Convert user buffer to physical address
 *
 * @v userptr		User pointer
 * @v offset		Offset from user pointer
 * @ret phys_addr	Physical address
 */
static inline __always_inline unsigned long
UACCESS_INLINE ( linux, user_to_phys ) ( userptr_t userptr, off_t offset ) {

	/* We do not know the real underlying physical address.  We
	 * provide this stub implementation only because it is
	 * required by alloc_memblock() (which allocates memory with
	 * specified physical address alignment).  We assume that the
	 * low-order bits of virtual addresses match the low-order
	 * bits of physical addresses, and so simply returning the
	 * virtual address will suffice for the purpose of determining
	 * alignment.
	 */
	return ( userptr + offset );
}

static inline __always_inline userptr_t
UACCESS_INLINE ( linux, virt_to_user ) ( volatile const void *addr ) {
	return trivial_virt_to_user ( addr );
}

static inline __always_inline void *
UACCESS_INLINE ( linux, user_to_virt ) ( userptr_t userptr, off_t offset ) {
	return trivial_user_to_virt ( userptr, offset );
}

static inline __always_inline userptr_t
UACCESS_INLINE ( linux, userptr_add ) ( userptr_t userptr, off_t offset ) {
	return trivial_userptr_add ( userptr, offset );
}

static inline __always_inline off_t
UACCESS_INLINE ( linux, userptr_sub ) ( userptr_t userptr,
					userptr_t subtrahend ) {
	return trivial_userptr_sub ( userptr, subtrahend );
}

static inline __always_inline void
UACCESS_INLINE ( linux, memcpy_user ) ( userptr_t dest, off_t dest_off,
					userptr_t src, off_t src_off,
					size_t len ) {
	trivial_memcpy_user ( dest, dest_off, src, src_off, len );
}

static inline __always_inline void
UACCESS_INLINE ( linux, memmove_user ) ( userptr_t dest, off_t dest_off,
					 userptr_t src, off_t src_off,
					 size_t len ) {
	trivial_memmove_user ( dest, dest_off, src, src_off, len );
}

static inline __always_inline int
UACCESS_INLINE ( linux, memcmp_user ) ( userptr_t first, off_t first_off,
					userptr_t second, off_t second_off,
					size_t len ) {
	return trivial_memcmp_user ( first, first_off, second, second_off, len);
}

static inline __always_inline void
UACCESS_INLINE ( linux, memset_user ) ( userptr_t buffer, off_t offset,
					int c, size_t len ) {
	trivial_memset_user ( buffer, offset, c, len );
}

static inline __always_inline size_t
UACCESS_INLINE ( linux, strlen_user ) ( userptr_t buffer, off_t offset ) {
	return trivial_strlen_user ( buffer, offset );
}

static inline __always_inline off_t
UACCESS_INLINE ( linux, memchr_user ) ( userptr_t buffer, off_t offset,
					int c, size_t len ) {
	return trivial_memchr_user ( buffer, offset, c, len );
}

#endif /* _IPXE_LINUX_UACCESS_H */
