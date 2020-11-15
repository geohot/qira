#ifndef _IPXE_ONCRPC_IOB_H
#define _IPXE_ONCRPC_IOB_H

#include <stdint.h>
#include <string.h>
#include <ipxe/iobuf.h>
#include <ipxe/refcnt.h>
#include <ipxe/oncrpc.h>

/** @file
 *
 * SUN ONC RPC protocol.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Add a string to the end of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v val               String
 * @ret size            Size of the data written
 */
#define oncrpc_iob_add_string( buf, str ) \
( { \
	const char * _str = (str); \
	oncrpc_iob_add_array ( (buf), strlen ( _str ), _str ); \
} )

/**
 * Get a 32 bits integer from the beginning of an I/O buffer
 *
 * @v buf               I/O buffer
 * @ret int             Integer
 */

#define oncrpc_iob_get_int( buf ) \
( { \
	uint32_t *_val; \
	_val = (buf)->data; \
	iob_pull ( (buf), sizeof ( uint32_t ) ); \
	ntohl ( *_val ); \
} )

/**
 * Get a 64 bits integer from the beginning of an I/O buffer
 *
 * @v buf               I/O buffer
 * @ret int             Integer
 */
#define oncrpc_iob_get_int64( buf ) \
( { \
	uint64_t *_val; \
	_val = (buf)->data; \
	iob_pull ( (buf), sizeof ( uint64_t ) ); \
	ntohll ( *_val ); \
} )


size_t oncrpc_iob_add_fields ( struct io_buffer *io_buf,
                               const struct oncrpc_field fields[] );

size_t oncrpc_iob_add_array ( struct io_buffer *io_buf, size_t length,
                              const void *data );

size_t oncrpc_iob_add_intarray ( struct io_buffer *io_buf, size_t length,
                                 const uint32_t *array );

size_t oncrpc_iob_add_cred ( struct io_buffer *io_buf,
                             const struct oncrpc_cred *cred );

size_t oncrpc_iob_get_cred ( struct io_buffer *io_buf,
                             struct oncrpc_cred *cred );

/**
 * Add a 32 bits integer to the end of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v val               Integer
 * @ret size            Size of the data written
 */
static inline size_t oncrpc_iob_add_int ( struct io_buffer *io_buf,
                                          uint32_t val ) {
	* ( uint32_t * ) iob_put ( io_buf, sizeof ( val ) ) = htonl ( val );
	return ( sizeof ( val) );
}

/**
 * Add a 64 bits integer to the end of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v val               Integer
 * @ret size            Size of the data written
 */
static inline size_t oncrpc_iob_add_int64 ( struct io_buffer *io_buf,
                                            uint64_t val ) {
	* ( uint64_t * ) iob_put ( io_buf, sizeof ( val ) ) = htonll ( val );
	return ( sizeof ( val) );
}

#endif /* _IPXE_ONCRPC_IOB_H */
