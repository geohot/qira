#ifndef _IPXE_POSIX_IO_H
#define _IPXE_POSIX_IO_H

/** @file
 *
 * POSIX-like I/O
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/uaccess.h>

/** Minimum file descriptor that will ever be allocated */
#define POSIX_FD_MIN ( 1 )

/** Maximum file descriptor that will ever be allocated */
#define POSIX_FD_MAX ( 31 )

/** File descriptor set as used for select() */
typedef uint32_t fd_set;

extern int open ( const char *uri_string );
extern ssize_t read_user ( int fd, userptr_t buffer,
			   off_t offset, size_t len );
extern int select ( fd_set *readfds, int wait );
extern ssize_t fsize ( int fd );
extern int close ( int fd );

/**
 * Zero a file descriptor set
 *
 * @v set		File descriptor set
 */
static inline __attribute__ (( always_inline )) void
FD_ZERO ( fd_set *set ) {
	*set = 0;
}

/**
 * Set a bit within a file descriptor set
 *
 * @v fd		File descriptor
 * @v set		File descriptor set
 */
static inline __attribute__ (( always_inline )) void
FD_SET ( int fd, fd_set *set ) {
	*set |= ( 1 << fd );
}

/**
 * Clear a bit within a file descriptor set
 *
 * @v fd		File descriptor
 * @v set		File descriptor set
 */
static inline __attribute__ (( always_inline )) void
FD_CLR ( int fd, fd_set *set ) {
	*set &= ~( 1 << fd );
}

/**
 * Test a bit within a file descriptor set
 *
 * @v fd		File descriptor
 * @v set		File descriptor set
 * @ret is_set		Corresponding bit is set
 */
static inline __attribute__ (( always_inline )) int
FD_ISSET ( int fd, fd_set *set ) {
	return ( *set & ( 1 << fd ) );
}

/**
 * Read data from file
 *
 * @v fd		File descriptor
 * @v buf		Data buffer
 * @v len		Maximum length to read
 * @ret len		Actual length read, or negative error number
 */
static inline ssize_t read ( int fd, void *buf, size_t len ) {
	return read_user ( fd, virt_to_user ( buf ), 0, len );
}

#endif /* _IPXE_POSIX_IO_H */
