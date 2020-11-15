/*
 * Copyright (C) 2010 VMware, Inc.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#ifndef _DHCP_ARCH_H
#define _DHCP_ARCH_H

/** @file
 *
 * Architecture-specific DHCP options
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/dhcp.h>

#define DHCP_ARCH_VENDOR_CLASS_ID \
	DHCP_STRING ( 'P', 'X', 'E', 'C', 'l', 'i', 'e', 'n', 't', ':',      \
		      'A', 'r', 'c', 'h', ':', '0', '0', '0', '0', '9', ':', \
		      'U', 'N', 'D', 'I', ':', '0', '0', '3', '0', '1', '0' )

#define DHCP_ARCH_CLIENT_ARCHITECTURE \
	DHCP_WORD ( DHCP_CLIENT_ARCHITECTURE_X86_64 )

#define DHCP_ARCH_CLIENT_NDI DHCP_OPTION ( 1 /* UNDI */ , 3, 10 /* v3.10 */ )

#endif
