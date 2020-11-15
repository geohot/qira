/*
 * Copyright (C) 2013 Marin Hannache <ipxe@mareo.fr>.
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
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/socket.h>
#include <ipxe/tcpip.h>
#include <ipxe/in.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/features.h>
#include <ipxe/oncrpc.h>
#include <ipxe/oncrpc_iob.h>

/** @file
 *
 * SUN ONC RPC protocol
 *
 */

size_t oncrpc_iob_add_fields ( struct io_buffer *io_buf,
                               const struct oncrpc_field fields[] ) {
	size_t i;
	size_t s = 0;

	struct oncrpc_field f;

	if ( ! io_buf )
		return 0;

	for ( i = 0; fields[i].type != oncrpc_none; i++ ) {
		f = fields[i];
		switch ( f.type ) {
		case oncrpc_int32:
			s += oncrpc_iob_add_int ( io_buf, f.value.int32 );
			break;

		case oncrpc_int64:
			s += oncrpc_iob_add_int64 ( io_buf, f.value.int64 );
			break;

		case oncrpc_str:
			s += oncrpc_iob_add_string ( io_buf, f.value.str );
			break;

		case oncrpc_array:
			s += oncrpc_iob_add_array ( io_buf,
			                            f.value.array.length,
			                            f.value.array.ptr );
			break;

		case oncrpc_intarray:
			s += oncrpc_iob_add_intarray ( io_buf,
			                               f.value.intarray.length,
			                               f.value.intarray.ptr );
			break;

		case oncrpc_cred:
			s += oncrpc_iob_add_cred ( io_buf, f.value.cred);
			break;

		default:
			return s;
		}
	}

	return s;
}

/**
 * Add an array of bytes to the end of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v val               String
 * @ret size            Size of the data written
 *
 * In the ONC RPC protocol, every data is four byte paded, we add padding when
 * necessary by using oncrpc_align()
 */
size_t oncrpc_iob_add_array ( struct io_buffer *io_buf, size_t length,
                              const void *data ) {
	size_t padding = oncrpc_align ( length ) - length;

	oncrpc_iob_add_int ( io_buf, length );
	memcpy ( iob_put ( io_buf, length ), data, length );
	memset ( iob_put ( io_buf, padding ), 0, padding );

	return length + padding + sizeof ( uint32_t );
}

/**
 * Add an int array to the end of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v length            Length od the array
 * @v val               Int array
 * @ret size            Size of the data written
 */
size_t oncrpc_iob_add_intarray ( struct io_buffer *io_buf, size_t length,
                                 const uint32_t *array ) {
	size_t                  i;

	oncrpc_iob_add_int ( io_buf, length );

	for ( i = 0; i < length; ++i )
		oncrpc_iob_add_int ( io_buf, array[i] );

	return ( ( length + 1 ) * sizeof ( uint32_t ) );
}

/**
 * Add credential information to the end of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v cred              Credential information
 * @ret size            Size of the data written
 */
size_t oncrpc_iob_add_cred ( struct io_buffer *io_buf,
                             const struct oncrpc_cred *cred ) {
	struct oncrpc_cred_sys  *syscred;
	size_t                  s;

	struct oncrpc_field credfields[] = {
		ONCRPC_FIELD ( int32, cred->flavor ),
		ONCRPC_FIELD ( int32, cred->length ),
		ONCRPC_FIELD_END,
	};

	if ( ! io_buf || ! cred )
		return 0;

	s  = oncrpc_iob_add_fields ( io_buf, credfields);

	switch ( cred->flavor ) {
	case ONCRPC_AUTH_NONE:
		break;

	case ONCRPC_AUTH_SYS:
		syscred = container_of ( cred, struct oncrpc_cred_sys,
		                         credential );

		struct oncrpc_field syscredfields[] = {
			ONCRPC_FIELD ( int32, syscred->stamp ),
			ONCRPC_FIELD ( str, syscred->hostname ),
			ONCRPC_FIELD ( int32, syscred->uid ),
			ONCRPC_FIELD ( int32, syscred->gid ),
			ONCRPC_SUBFIELD ( intarray, syscred->aux_gid_len,
			                  syscred->aux_gid ),
			ONCRPC_FIELD_END,
		};

		s += oncrpc_iob_add_fields ( io_buf, syscredfields );
		break;
	}

	return s;
}

/**
 * Get credential information from the beginning of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v cred              Struct where the information will be saved
 * @ret size            Size of the data read
 */
size_t oncrpc_iob_get_cred ( struct io_buffer *io_buf,
                             struct oncrpc_cred *cred ) {
	if ( cred == NULL )
		return * ( uint32_t * ) io_buf->data;

	cred->flavor = oncrpc_iob_get_int ( io_buf );
	cred->length = oncrpc_iob_get_int ( io_buf );

	iob_pull ( io_buf, cred->length );

	return ( 2 * sizeof ( uint32_t ) + cred->length );
}
