#ifndef _IPXE_IOBUF_H
#define _IPXE_IOBUF_H

/** @file
 *
 * I/O buffers
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <assert.h>
#include <ipxe/list.h>

/**
 * Minimum I/O buffer length
 *
 * alloc_iob() will round up the allocated length to this size if
 * necessary.  This is used on behalf of hardware that is not capable
 * of auto-padding.
 */
#define IOB_ZLEN 64

/**
 * A persistent I/O buffer
 *
 * This data structure encapsulates a long-lived I/O buffer.  The
 * buffer may be passed between multiple owners, queued for possible
 * retransmission, etc.
 */
struct io_buffer {
	/** List of which this buffer is a member
	 *
	 * The list must belong to the current owner of the buffer.
	 * Different owners may maintain different lists (e.g. a
	 * retransmission list for TCP).
	 */
	struct list_head list;

	/** Start of the buffer */
	void *head;
	/** Start of data */
	void *data;
	/** End of data */
	void *tail;
	/** End of the buffer */
        void *end;
};

/**
 * Reserve space at start of I/O buffer
 *
 * @v iobuf	I/O buffer
 * @v len	Length to reserve
 * @ret data	Pointer to new start of buffer
 */
static inline void * iob_reserve ( struct io_buffer *iobuf, size_t len ) {
	iobuf->data += len;
	iobuf->tail += len;
	return iobuf->data;
}
#define iob_reserve( iobuf, len ) ( {			\
	void *__result;					\
	__result = iob_reserve ( (iobuf), (len) );	\
	assert ( (iobuf)->tail <= (iobuf)->end );	\
	__result; } )

/**
 * Add data to start of I/O buffer
 *
 * @v iobuf	I/O buffer
 * @v len	Length to add
 * @ret data	Pointer to new start of buffer
 */
static inline void * iob_push ( struct io_buffer *iobuf, size_t len ) {
	iobuf->data -= len;
	return iobuf->data;
}
#define iob_push( iobuf, len ) ( {			\
	void *__result;					\
	__result = iob_push ( (iobuf), (len) );		\
	assert ( (iobuf)->data >= (iobuf)->head );	\
	__result; } )

/**
 * Remove data from start of I/O buffer
 *
 * @v iobuf	I/O buffer
 * @v len	Length to remove
 * @ret data	Pointer to new start of buffer
 */
static inline void * iob_pull ( struct io_buffer *iobuf, size_t len ) {
	iobuf->data += len;
	assert ( iobuf->data <= iobuf->tail );
	return iobuf->data;
}
#define iob_pull( iobuf, len ) ( {			\
	void *__result;					\
	__result = iob_pull ( (iobuf), (len) );		\
	assert ( (iobuf)->data <= (iobuf)->tail );	\
	__result; } )

/**
 * Add data to end of I/O buffer
 *
 * @v iobuf	I/O buffer
 * @v len	Length to add
 * @ret data	Pointer to newly added space
 */
static inline void * iob_put ( struct io_buffer *iobuf, size_t len ) {
	void *old_tail = iobuf->tail;
	iobuf->tail += len;
	return old_tail;
}
#define iob_put( iobuf, len ) ( {			\
	void *__result;					\
	__result = iob_put ( (iobuf), (len) );		\
	assert ( (iobuf)->tail <= (iobuf)->end );	\
	__result; } )

/**
 * Remove data from end of I/O buffer
 *
 * @v iobuf	I/O buffer
 * @v len	Length to remove
 */
static inline void iob_unput ( struct io_buffer *iobuf, size_t len ) {
	iobuf->tail -= len;
}
#define iob_unput( iobuf, len ) do {			\
	iob_unput ( (iobuf), (len) );			\
	assert ( (iobuf)->tail >= (iobuf)->data );	\
	} while ( 0 )

/**
 * Empty an I/O buffer
 *
 * @v iobuf	I/O buffer
 */
static inline void iob_empty ( struct io_buffer *iobuf ) {
	iobuf->tail = iobuf->data;
}

/**
 * Calculate length of data in an I/O buffer
 *
 * @v iobuf	I/O buffer
 * @ret len	Length of data in buffer
 */
static inline size_t iob_len ( struct io_buffer *iobuf ) {
	return ( iobuf->tail - iobuf->data );
}

/**
 * Calculate available space at start of an I/O buffer
 *
 * @v iobuf	I/O buffer
 * @ret len	Length of data available at start of buffer
 */
static inline size_t iob_headroom ( struct io_buffer *iobuf ) {
	return ( iobuf->data - iobuf->head );
}

/**
 * Calculate available space at end of an I/O buffer
 *
 * @v iobuf	I/O buffer
 * @ret len	Length of data available at end of buffer
 */
static inline size_t iob_tailroom ( struct io_buffer *iobuf ) {
	return ( iobuf->end - iobuf->tail );
}

/**
 * Create a temporary I/O buffer
 *
 * @v iobuf	I/O buffer
 * @v data	Data buffer
 * @v len	Length of data
 * @v max_len	Length of buffer
 *
 * It is sometimes useful to use the iob_xxx() methods on temporary
 * data buffers.
 */
static inline void iob_populate ( struct io_buffer *iobuf,
				  void *data, size_t len, size_t max_len ) {
	iobuf->head = iobuf->data = data;
	iobuf->tail = ( data + len );
	iobuf->end = ( data + max_len );
}

/**
 * Disown an I/O buffer
 *
 * @v iobuf	I/O buffer
 *
 * There are many functions that take ownership of the I/O buffer they
 * are passed as a parameter.  The caller should not retain a pointer
 * to the I/O buffer.  Use iob_disown() to automatically nullify the
 * caller's pointer, e.g.:
 *
 *     xfer_deliver_iob ( xfer, iob_disown ( iobuf ) );
 *
 * This will ensure that iobuf is set to NULL for any code after the
 * call to xfer_deliver_iob().
 */
#define iob_disown( iobuf ) ( {				\
	struct io_buffer *__iobuf = (iobuf);		\
	(iobuf) = NULL;					\
	__iobuf; } )

extern struct io_buffer * __malloc alloc_iob_raw ( size_t len, size_t align,
						   size_t offset );
extern struct io_buffer * __malloc alloc_iob ( size_t len );
extern void free_iob ( struct io_buffer *iobuf );
extern void iob_pad ( struct io_buffer *iobuf, size_t min_len );
extern int iob_ensure_headroom ( struct io_buffer *iobuf, size_t len );
extern struct io_buffer * iob_concatenate ( struct list_head *list );
extern struct io_buffer * iob_split ( struct io_buffer *iobuf, size_t len );

#endif /* _IPXE_IOBUF_H */
