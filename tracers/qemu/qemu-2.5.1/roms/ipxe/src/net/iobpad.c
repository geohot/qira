/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * I/O buffer padding
 *
 */

#include <string.h>
#include <ipxe/iobuf.h>

/**
 * Pad I/O buffer
 *
 * @v iobuf		I/O buffer
 * @v min_len		Minimum length
 *
 * This function pads and aligns I/O buffers, for devices that
 * aren't capable of padding in hardware, or that require specific
 * alignment in TX buffers.  The packet data will end up aligned to a
 * multiple of @c IOB_ALIGN.
 *
 * @c min_len must not exceed @v IOB_ZLEN.
 */
void iob_pad ( struct io_buffer *iobuf, size_t min_len ) {
	void *data;
	size_t len;
	size_t headroom;
	signed int pad_len;

	assert ( min_len <= IOB_ZLEN );

	/* Move packet data to start of I/O buffer.  This will both
	 * align the data (since I/O buffers are aligned to
	 * IOB_ALIGN) and give us sufficient space for the
	 * zero-padding
	 */
	data = iobuf->data;
	len = iob_len ( iobuf );
	headroom = iob_headroom ( iobuf );
	iob_push ( iobuf, headroom );
	memmove ( iobuf->data, data, len );
	iob_unput ( iobuf, headroom );

	/* Pad to minimum packet length */
	pad_len = ( min_len - iob_len ( iobuf ) );
	if ( pad_len > 0 )
		memset ( iob_put ( iobuf, pad_len ), 0, pad_len );
}
