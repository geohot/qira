#ifndef _IPXE_FRAGMENT_H
#define _IPXE_FRAGMENT_H

/** @file
 *
 * Fragment reassembly
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/list.h>
#include <ipxe/iobuf.h>
#include <ipxe/retry.h>

/** Fragment reassembly timeout */
#define FRAGMENT_TIMEOUT ( TICKS_PER_SEC / 2 )

/** A fragment reassembly buffer */
struct fragment {
	/* List of fragment reassembly buffers */
	struct list_head list;
	/** Reassembled packet */
	struct io_buffer *iobuf;
	/** Length of non-fragmentable portion of reassembled packet */
	size_t hdrlen;
	/** Reassembly timer */
	struct retry_timer timer;
	/** Fragment reassembler */
	struct fragment_reassembler *fragments;
};

/** A fragment reassembler */
struct fragment_reassembler {
	/** List of fragment reassembly buffers */
	struct list_head list;
	/**
	 * Check if fragment matches fragment reassembly buffer
	 *
	 * @v fragment		Fragment reassembly buffer
	 * @v iobuf		I/O buffer
	 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
	 * @ret is_fragment	Fragment matches this reassembly buffer
	 */
	int ( * is_fragment ) ( struct fragment *fragment,
				struct io_buffer *iobuf, size_t hdrlen );
	/**
	 * Get fragment offset
	 *
	 * @v iobuf		I/O buffer
	 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
	 * @ret offset		Offset
	 */
	size_t ( * fragment_offset ) ( struct io_buffer *iobuf, size_t hdrlen );
	/**
	 * Check if more fragments exist
	 *
	 * @v iobuf		I/O buffer
	 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
	 * @ret more_frags	More fragments exist
	 */
	int ( * more_fragments ) ( struct io_buffer *iobuf, size_t hdrlen );
	/** Associated IP statistics */
	struct ip_statistics *stats;
};

extern struct io_buffer *
fragment_reassemble ( struct fragment_reassembler *fragments,
		      struct io_buffer *iobuf, size_t *hdrlen );

#endif /* _IPXE_FRAGMENT_H */
