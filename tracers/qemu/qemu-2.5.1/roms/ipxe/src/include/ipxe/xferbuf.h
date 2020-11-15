#ifndef _IPXE_XFERBUF_H
#define _IPXE_XFERBUF_H

/** @file
 *
 * Data transfer buffer
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/iobuf.h>
#include <ipxe/uaccess.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>

/** A data transfer buffer */
struct xfer_buffer {
	/** Data */
	void *data;
	/** Size of data */
	size_t len;
	/** Current offset within data */
	size_t pos;
	/** Data transfer buffer operations */
	struct xfer_buffer_operations *op;
};

/** Data transfer buffer operations */
struct xfer_buffer_operations {
	/** Reallocate data buffer
	 *
	 * @v xferbuf		Data transfer buffer
	 * @v len		New length (or zero to free buffer)
	 * @ret rc		Return status code
	 */
	int ( * realloc ) ( struct xfer_buffer *xferbuf, size_t len );
	/** Write data to buffer
	 *
	 * @v xferbuf		Data transfer buffer
	 * @v offset		Starting offset
	 * @v data		Data to write
	 * @v len		Length of data
	 *
	 * This call is simply a wrapper for the appropriate
	 * memcpy()-like operation: the caller is responsible for
	 * ensuring that the write does not exceed the buffer length.
	 */
	void ( * write ) ( struct xfer_buffer *xferbuf, size_t offset,
			   const void *data, size_t len );
	/** Read data from buffer
	 *
	 * @v xferbuf		Data transfer buffer
	 * @v offset		Starting offset
	 * @v data		Data to read
	 * @v len		Length of data
	 *
	 * This call is simply a wrapper for the appropriate
	 * memcpy()-like operation: the caller is responsible for
	 * ensuring that the read does not exceed the buffer length.
	 */
	void ( * read ) ( struct xfer_buffer *xferbuf, size_t offset,
			  void *data, size_t len );
};

extern struct xfer_buffer_operations xferbuf_malloc_operations;
extern struct xfer_buffer_operations xferbuf_umalloc_operations;

/**
 * Initialise malloc()-based data transfer buffer
 *
 * @v xferbuf		Data transfer buffer
 */
static inline __attribute__ (( always_inline )) void
xferbuf_malloc_init ( struct xfer_buffer *xferbuf ) {
	xferbuf->op = &xferbuf_malloc_operations;
}

/**
 * Initialise umalloc()-based data transfer buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v data		User pointer
 */
static inline __attribute__ (( always_inline )) void
xferbuf_umalloc_init ( struct xfer_buffer *xferbuf, userptr_t *data ) {
	xferbuf->data = data;
	xferbuf->op = &xferbuf_umalloc_operations;
}

extern void xferbuf_free ( struct xfer_buffer *xferbuf );
extern int xferbuf_write ( struct xfer_buffer *xferbuf, size_t offset,
			   const void *data, size_t len );
extern int xferbuf_read ( struct xfer_buffer *xferbuf, size_t offset,
			  void *data, size_t len );
extern int xferbuf_deliver ( struct xfer_buffer *xferbuf,
			     struct io_buffer *iobuf,
			     struct xfer_metadata *meta );

extern struct xfer_buffer * xfer_buffer ( struct interface *intf );
#define xfer_buffer_TYPE( object_type ) \
	typeof ( struct xfer_buffer * ( object_type ) )

#endif /* _IPXE_XFERBUF_H */
