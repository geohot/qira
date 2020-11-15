#ifndef _IPXE_UACCESS_H
#define _IPXE_UACCESS_H

/**
 * @file
 *
 * Access to external ("user") memory
 *
 * iPXE often needs to transfer data between internal and external
 * buffers.  On i386, the external buffers may require access via a
 * different segment, and the buffer address cannot be encoded into a
 * simple void * pointer.  The @c userptr_t type encapsulates the
 * information needed to identify an external buffer, and the
 * copy_to_user() and copy_from_user() functions provide methods for
 * transferring data between internal and external buffers.
 *
 * Note that userptr_t is an opaque type; in particular, performing
 * arithmetic upon a userptr_t is not allowed.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <string.h>
#include <ipxe/api.h>
#include <config/ioapi.h>

/**
 * A pointer to a user buffer
 *
 */
typedef unsigned long userptr_t;

/** Equivalent of NULL for user pointers */
#define UNULL ( ( userptr_t ) 0 )

/**
 * @defgroup uaccess_trivial Trivial user access API implementations
 *
 * User access API implementations that can be used by environments in
 * which virtual addresses allow access to all of memory.
 *
 * @{
 *
 */

/**
 * Convert virtual address to user pointer
 *
 * @v addr		Virtual address
 * @ret userptr		User pointer
 */
static inline __always_inline userptr_t
trivial_virt_to_user ( volatile const void *addr ) {
	return ( ( userptr_t ) addr );
}

/**
 * Convert user pointer to virtual address
 *
 * @v userptr		User pointer
 * @v offset		Offset from user pointer
 * @ret addr		Virtual address
 *
 * This operation is not available under all memory models.
 */
static inline __always_inline void *
trivial_user_to_virt ( userptr_t userptr, off_t offset ) {
	return ( ( void * ) userptr + offset );
}

/**
 * Add offset to user pointer
 *
 * @v userptr		User pointer
 * @v offset		Offset
 * @ret userptr		New pointer value
 */
static inline __always_inline userptr_t
trivial_userptr_add ( userptr_t userptr, off_t offset ) {
	return ( userptr + offset );
}

/**
 * Subtract user pointers
 *
 * @v userptr		User pointer
 * @v subtrahend	User pointer to be subtracted
 * @ret offset		Offset
 */
static inline __always_inline off_t
trivial_userptr_sub ( userptr_t userptr, userptr_t subtrahend ) {
	return ( userptr - subtrahend );
}

/**
 * Copy data between user buffers
 *
 * @v dest		Destination
 * @v dest_off		Destination offset
 * @v src		Source
 * @v src_off		Source offset
 * @v len		Length
 */
static inline __always_inline void
trivial_memcpy_user ( userptr_t dest, off_t dest_off,
		      userptr_t src, off_t src_off, size_t len ) {
	memcpy ( ( ( void * ) dest + dest_off ),
		 ( ( void * ) src + src_off ), len );
}

/**
 * Copy data between user buffers, allowing for overlap
 *
 * @v dest		Destination
 * @v dest_off		Destination offset
 * @v src		Source
 * @v src_off		Source offset
 * @v len		Length
 */
static inline __always_inline void
trivial_memmove_user ( userptr_t dest, off_t dest_off,
		       userptr_t src, off_t src_off, size_t len ) {
	memmove ( ( ( void * ) dest + dest_off ),
		  ( ( void * ) src + src_off ), len );
}

/**
 * Compare data between user buffers
 *
 * @v first		First buffer
 * @v first_off		First buffer offset
 * @v second		Second buffer
 * @v second_off	Second buffer offset
 * @v len		Length
 * @ret diff		Difference
 */
static inline __always_inline int
trivial_memcmp_user ( userptr_t first, off_t first_off,
		      userptr_t second, off_t second_off, size_t len ) {
	return memcmp ( ( ( void * ) first + first_off ),
			( ( void * ) second + second_off ), len );
}

/**
 * Fill user buffer with a constant byte
 *
 * @v buffer		User buffer
 * @v offset		Offset within buffer
 * @v c			Constant byte with which to fill
 * @v len		Length
 */
static inline __always_inline void
trivial_memset_user ( userptr_t buffer, off_t offset, int c, size_t len ) {
	memset ( ( ( void * ) buffer + offset ), c, len );
}

/**
 * Find length of NUL-terminated string in user buffer
 *
 * @v buffer		User buffer
 * @v offset		Offset within buffer
 * @ret len		Length of string (excluding NUL)
 */
static inline __always_inline size_t
trivial_strlen_user ( userptr_t buffer, off_t offset ) {
	return strlen ( ( void * ) buffer + offset );
}

/**
 * Find character in user buffer
 *
 * @v buffer		User buffer
 * @v offset		Starting offset within buffer
 * @v c			Character to search for
 * @v len		Length of user buffer
 * @ret offset		Offset of character, or <0 if not found
 */
static inline __always_inline off_t
trivial_memchr_user ( userptr_t buffer, off_t offset, int c, size_t len ) {
	void *found;

	found = memchr ( ( ( void * ) buffer + offset ), c, len );
	return ( found ? ( found - ( void * ) buffer ) : -1 );
}

/** @} */

/**
 * Calculate static inline user access API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define UACCESS_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( UACCESS_PREFIX_ ## _subsys, _api_func )

/**
 * Provide an user access API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_UACCESS( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( UACCESS_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline user access API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_UACCESS_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( UACCESS_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent user access API headers */
#include <ipxe/efi/efi_uaccess.h>
#include <ipxe/linux/linux_uaccess.h>

/* Include all architecture-dependent user access API headers */
#include <bits/uaccess.h>

/**
 * Convert physical address to user pointer
 *
 * @v phys_addr		Physical address
 * @ret userptr		User pointer
 */
userptr_t phys_to_user ( unsigned long phys_addr );

/**
 * Convert user pointer to physical address
 *
 * @v userptr		User pointer
 * @v offset		Offset from user pointer
 * @ret phys_addr	Physical address
 */
unsigned long user_to_phys ( userptr_t userptr, off_t offset );

/**
 * Convert virtual address to user pointer
 *
 * @v addr		Virtual address
 * @ret userptr		User pointer
 */
userptr_t virt_to_user ( volatile const void *addr );

/**
 * Convert user pointer to virtual address
 *
 * @v userptr		User pointer
 * @v offset		Offset from user pointer
 * @ret addr		Virtual address
 *
 * This operation is not available under all memory models.
 */
void * user_to_virt ( userptr_t userptr, off_t offset );

/**
 * Add offset to user pointer
 *
 * @v userptr		User pointer
 * @v offset		Offset
 * @ret userptr		New pointer value
 */
userptr_t userptr_add ( userptr_t userptr, off_t offset );

/**
 * Subtract user pointers
 *
 * @v userptr		User pointer
 * @v subtrahend	User pointer to be subtracted
 * @ret offset		Offset
 */
off_t userptr_sub ( userptr_t userptr, userptr_t subtrahend );

/**
 * Convert virtual address to a physical address
 *
 * @v addr		Virtual address
 * @ret phys_addr	Physical address
 */
static inline __always_inline unsigned long
virt_to_phys ( volatile const void *addr ) {
	return user_to_phys ( virt_to_user ( addr ), 0 );
}

/**
 * Convert physical address to a virtual address
 *
 * @v addr		Virtual address
 * @ret phys_addr	Physical address
 *
 * This operation is not available under all memory models.
 */
static inline __always_inline void * phys_to_virt ( unsigned long phys_addr ) {
	return user_to_virt ( phys_to_user ( phys_addr ), 0 );
}

/**
 * Copy data between user buffers
 *
 * @v dest		Destination
 * @v dest_off		Destination offset
 * @v src		Source
 * @v src_off		Source offset
 * @v len		Length
 */
void memcpy_user ( userptr_t dest, off_t dest_off,
		   userptr_t src, off_t src_off, size_t len );

/**
 * Copy data to user buffer
 *
 * @v dest		Destination
 * @v dest_off		Destination offset
 * @v src		Source
 * @v len		Length
 */
static inline __always_inline void
copy_to_user ( userptr_t dest, off_t dest_off, const void *src, size_t len ) {
	memcpy_user ( dest, dest_off, virt_to_user ( src ), 0, len );
}

/**
 * Copy data from user buffer
 *
 * @v dest		Destination
 * @v src		Source
 * @v src_off		Source offset
 * @v len		Length
 */
static inline __always_inline void
copy_from_user ( void *dest, userptr_t src, off_t src_off, size_t len ) {
	memcpy_user ( virt_to_user ( dest ), 0, src, src_off, len );
}

/**
 * Copy data between user buffers, allowing for overlap
 *
 * @v dest		Destination
 * @v dest_off		Destination offset
 * @v src		Source
 * @v src_off		Source offset
 * @v len		Length
 */
void memmove_user ( userptr_t dest, off_t dest_off,
		    userptr_t src, off_t src_off, size_t len );

/**
 * Compare data between user buffers
 *
 * @v first		First buffer
 * @v first_off		First buffer offset
 * @v second		Second buffer
 * @v second_off	Second buffer offset
 * @v len		Length
 * @ret diff		Difference
 */
int memcmp_user ( userptr_t first, off_t first_off,
		  userptr_t second, off_t second_off, size_t len );

/**
 * Fill user buffer with a constant byte
 *
 * @v userptr		User buffer
 * @v offset		Offset within buffer
 * @v c			Constant byte with which to fill
 * @v len		Length
 */
void memset_user ( userptr_t userptr, off_t offset, int c, size_t len );

/**
 * Find length of NUL-terminated string in user buffer
 *
 * @v userptr		User buffer
 * @v offset		Offset within buffer
 * @ret len		Length of string (excluding NUL)
 */
size_t strlen_user ( userptr_t userptr, off_t offset );

/**
 * Find character in user buffer
 *
 * @v userptr		User buffer
 * @v offset		Starting offset within buffer
 * @v c			Character to search for
 * @v len		Length of user buffer
 * @ret offset		Offset of character, or <0 if not found
 */
off_t memchr_user ( userptr_t userptr, off_t offset, int c, size_t len );

#endif /* _IPXE_UACCESS_H */
