/*
 * Copyright (c) 2009 Joshua Oreman <oremanj@rwcr.net>.
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

#ifndef _IPXE_SEC80211_H
#define _IPXE_SEC80211_H

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/net80211.h>
#include <errno.h>

/** @file
 *
 * Definitions for general secured-network routines.
 */

int sec80211_detect ( struct io_buffer *iob,
		      enum net80211_security_proto *secprot,
		      enum net80211_crypto_alg *crypt );

int sec80211_detect_ie ( int is_rsn, u8 *start, u8 *end,
			 enum net80211_security_proto *secprot,
			 enum net80211_crypto_alg *crypt );
u8 * sec80211_find_rsn ( union ieee80211_ie *ie, void *ie_end,
			 int *is_rsn, u8 **end );

int sec80211_install ( struct net80211_crypto **which,
		       enum net80211_crypto_alg crypt,
		       const void *key, int len, const void *rsc );

u32 sec80211_rsn_get_crypto_desc ( enum net80211_crypto_alg crypt, int rsnie );
u32 sec80211_rsn_get_akm_desc ( enum net80211_security_proto secprot,
				int rsnie );
enum net80211_crypto_alg sec80211_rsn_get_net80211_crypt ( u32 desc );

#endif /* _IPXE_SEC80211_H */

