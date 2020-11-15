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
 * Hyper Text Transfer Protocol (HTTP)
 *
 */

#include <ipxe/open.h>
#include <ipxe/http.h>
#include <ipxe/features.h>

FEATURE ( FEATURE_PROTOCOL, "HTTP", DHCP_EB_FEATURE_HTTP, 1 );

/** HTTP URI opener */
struct uri_opener http_uri_opener __uri_opener = {
	.scheme	= "http",
	.open	= http_open_uri,
};

/** HTTP URI scheme */
struct http_scheme http_scheme __http_scheme = {
	.name = "http",
	.port = HTTP_PORT,
};
