/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stddef.h>
#include <errno.h>
#include <ipxe/socket.h>

/** @file
 *
 * Sockets
 *
 */

/**
 * Transcribe socket address
 *
 * @v sa		Socket address
 * @ret string		Socket address string
 */
const char * sock_ntoa ( struct sockaddr *sa ) {
	struct sockaddr_converter *converter;

	for_each_table_entry ( converter, SOCKADDR_CONVERTERS ) {
		if ( converter->family == sa->sa_family )
			return converter->ntoa ( sa );
	}
	return NULL;
}

/**
 * Parse socket address
 *
 * @v string		Socket address string
 * @v sa		Socket address to fill in
 * @ret rc		Return status code
 */
int sock_aton ( const char *string, struct sockaddr *sa ) {
	struct sockaddr_converter *converter;

	for_each_table_entry ( converter, SOCKADDR_CONVERTERS ) {
		if ( converter->aton ( string, sa ) == 0 ) {
			sa->sa_family = converter->family;
			return 0;
		}
	}
	return -EINVAL;
}
