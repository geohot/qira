/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <strings.h>
#include <errno.h>
#include <ipxe/malloc.h>
#include <ipxe/iobuf.h>

/** @file
 *
 * I/O buffers
 *
 */

/**
 * Allocate I/O buffer with specified alignment and offset
 *
 * @v len	Required length of buffer
 * @v align	Physical alignment
 * @v offset	Offset from physical alignment
 * @ret iobuf	I/O buffer, or NULL if none available
 *
 * @c align will be rounded up to the nearest power of two.
 */
struct io_buffer * alloc_iob_raw ( size_t len, size_t align, size_t offset ) {
	struct io_buffer *iobuf;
	void *data;

	/* Align buffer length to ensure that struct io_buffer is aligned */
	len = ( len + __alignof__ ( *iobuf ) - 1 ) &
		~( __alignof__ ( *iobuf ) - 1 );

	/* Round up alignment to the nearest power of two */
	align = ( 1 << fls ( align - 1 ) );

	/* Allocate buffer plus descriptor as a single unit, unless
	 * doing so will push the total size over the alignment
	 * boundary.
	 */
	if ( ( len + sizeof ( *iobuf ) ) <= align ) {

		/* Allocate memory for buffer plus descriptor */
		data = malloc_dma_offset ( len + sizeof ( *iobuf ), align,
					   offset );
		if ( ! data )
			return NULL;
		iobuf = ( data + len );

	} else {

		/* Allocate memory for buffer */
		data = malloc_dma_offset ( len, align, offset );
		if ( ! data )
			return NULL;

		/* Allocate memory for descriptor */
		iobuf = malloc ( sizeof ( *iobuf ) );
		if ( ! iobuf ) {
			free_dma ( data, len );
			return NULL;
		}
	}

	/* Populate descriptor */
	iobuf->head = iobuf->data = iobuf->tail = data;
	iobuf->end = ( data + len );

	return iobuf;
}

/**
 * Allocate I/O buffer
 *
 * @v len	Required length of buffer
 * @ret iobuf	I/O buffer, or NULL if none available
 *
 * The I/O buffer will be physically aligned on its own size (rounded
 * up to the nearest power of two).
 */
struct io_buffer * alloc_iob ( size_t len ) {

	/* Pad to minimum length */
	if ( len < IOB_ZLEN )
		len = IOB_ZLEN;

	/* Align buffer on its own size to avoid potential problems
	 * with boundary-crossing DMA.
	 */
	return alloc_iob_raw ( len, len, 0 );
}

/**
 * Free I/O buffer
 *
 * @v iobuf	I/O buffer
 */
void free_iob ( struct io_buffer *iobuf ) {
	size_t len;

	/* Allow free_iob(NULL) to be valid */
	if ( ! iobuf )
		return;

	/* Sanity checks */
	assert ( iobuf->head <= iobuf->data );
	assert ( iobuf->data <= iobuf->tail );
	assert ( iobuf->tail <= iobuf->end );

	/* Free buffer */
	len = ( iobuf->end - iobuf->head );
	if ( iobuf->end == iobuf ) {

		/* Descriptor is inline */
		free_dma ( iobuf->head, ( len + sizeof ( *iobuf ) ) );

	} else {

		/* Descriptor is detached */
		free_dma ( iobuf->head, len );
		free ( iobuf );
	}
}

/**
 * Ensure I/O buffer has sufficient headroom
 *
 * @v iobuf	I/O buffer
 * @v len	Required headroom
 *
 * This function currently only checks for the required headroom; it
 * does not reallocate the I/O buffer if required.  If we ever have a
 * code path that requires this functionality, it's a fairly trivial
 * change to make.
 */
int iob_ensure_headroom ( struct io_buffer *iobuf, size_t len ) {

	if ( iob_headroom ( iobuf ) >= len )
		return 0;
	return -ENOBUFS;
}

/**
 * Concatenate I/O buffers into a single buffer
 *
 * @v list	List of I/O buffers
 * @ret iobuf	Concatenated I/O buffer, or NULL on allocation failure
 *
 * After a successful concatenation, the list will be empty.
 */
struct io_buffer * iob_concatenate ( struct list_head *list ) {
	struct io_buffer *iobuf;
	struct io_buffer *tmp;
	struct io_buffer *concatenated;
	size_t len = 0;

	/* If the list contains only a single entry, avoid an
	 * unnecessary additional allocation.
	 */
	if ( list_is_singular ( list ) ) {
		iobuf = list_first_entry ( list, struct io_buffer, list );
		INIT_LIST_HEAD ( list );
		return iobuf;
	}

	/* Calculate total length */
	list_for_each_entry ( iobuf, list, list )
		len += iob_len ( iobuf );

	/* Allocate new I/O buffer */
	concatenated = alloc_iob_raw ( len, __alignof__ ( *iobuf ), 0 );
	if ( ! concatenated )
		return NULL;

	/* Move data to new I/O buffer */
	list_for_each_entry_safe ( iobuf, tmp, list, list ) {
		list_del ( &iobuf->list );
		memcpy ( iob_put ( concatenated, iob_len ( iobuf ) ),
			 iobuf->data, iob_len ( iobuf ) );
		free_iob ( iobuf );
	}

	return concatenated;
}

/**
 * Split I/O buffer
 *
 * @v iobuf		I/O buffer
 * @v len		Length to split into a new I/O buffer
 * @ret split		New I/O buffer, or NULL on allocation failure
 *
 * Split the first @c len bytes of the existing I/O buffer into a
 * separate I/O buffer.  The resulting buffers are likely to have no
 * headroom or tailroom.
 *
 * If this call fails, then the original buffer will be unmodified.
 */
struct io_buffer * iob_split ( struct io_buffer *iobuf, size_t len ) {
	struct io_buffer *split;

	/* Sanity checks */
	assert ( len <= iob_len ( iobuf ) );

	/* Allocate new I/O buffer */
	split = alloc_iob ( len );
	if ( ! split )
		return NULL;

	/* Copy in data */
	memcpy ( iob_put ( split, len ), iobuf->data, len );
	iob_pull ( iobuf, len );
	return split;
}
