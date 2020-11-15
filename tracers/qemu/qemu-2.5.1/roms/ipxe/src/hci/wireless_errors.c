/*
 * Copyright (C) 2009 Joshua Oreman <oremanj@rwcr.net>.
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

FILE_LICENCE ( GPL2_OR_LATER );

#include <errno.h>
#include <ipxe/errortab.h>
#include <ipxe/net80211_err.h>

/* Record errors as though they come from the 802.11 stack */
#undef ERRFILE
#define ERRFILE ERRFILE_net80211

/** All 802.11 errors
 */
struct errortab wireless_errors[] __errortab = {
	__einfo_errortab ( EINFO_EINVAL_PKT_TOO_SHORT ),
	__einfo_errortab ( EINFO_EINVAL_PKT_VERSION ),
	__einfo_errortab ( EINFO_EINVAL_PKT_NOT_DATA ),
	__einfo_errortab ( EINFO_EINVAL_PKT_NOT_FROMDS ),
	__einfo_errortab ( EINFO_EINVAL_PKT_LLC_HEADER ),
	__einfo_errortab ( EINFO_EINVAL_CRYPTO_REQUEST ),
	__einfo_errortab ( EINFO_EINVAL_ACTIVE_SCAN ),
	__einfo_errortab ( EINFO_ECONNREFUSED_FAILURE ),
	__einfo_errortab ( EINFO_ECONNREFUSED_CAPAB_UNSUPP ),
	__einfo_errortab ( EINFO_ECONNREFUSED_REASSOC_INVALID ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_DENIED ),
	__einfo_errortab ( EINFO_ECONNREFUSED_AUTH_ALGO_UNSUPP ),
	__einfo_errortab ( EINFO_ECONNREFUSED_AUTH_SEQ_INVALID ),
	__einfo_errortab ( EINFO_ECONNREFUSED_AUTH_CHALL_INVALID ),
	__einfo_errortab ( EINFO_ECONNREFUSED_AUTH_TIMEOUT ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_NO_ROOM ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_NEED_RATE ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_NEED_SHORT_PMBL ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_NEED_PBCC ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_NEED_CHAN_AGILITY ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_NEED_SPECTRUM_MGMT ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_BAD_POWER ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_BAD_CHANNELS ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_NEED_SHORT_SLOT ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_NEED_DSSS_OFDM ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_QOS_FAILURE ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_QOS_NO_ROOM ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_LINK_IS_HORRIBLE ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_ASSOC_NEED_QOS ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_REQUEST_DECLINED ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_REQUEST_INVALID ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_TS_NOT_CREATED_AGAIN ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_INVALID_IE ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_GROUP_CIPHER_INVALID ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_PAIR_CIPHER_INVALID ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_AKMP_INVALID ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_RSN_VERSION_UNSUPP ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_RSN_CAPAB_INVALID ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_CIPHER_REJECTED ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_TS_NOT_CREATED_WAIT ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_DIRECT_LINK_FORBIDDEN ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_DEST_NOT_PRESENT ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_DEST_NOT_QOS ),
	__einfo_errortab ( EINFO_EHOSTUNREACH_ASSOC_LISTEN_TOO_HIGH ),
	__einfo_errortab ( EINFO_ECONNRESET_UNSPECIFIED ),
	__einfo_errortab ( EINFO_ECONNRESET_AUTH_NO_LONGER_VALID ),
	__einfo_errortab ( EINFO_ECONNRESET_LEAVING ),
	__einfo_errortab ( EINFO_ECONNRESET_INACTIVITY ),
	__einfo_errortab ( EINFO_ECONNRESET_OUT_OF_RESOURCES ),
	__einfo_errortab ( EINFO_ECONNRESET_NEED_AUTH ),
	__einfo_errortab ( EINFO_ECONNRESET_NEED_ASSOC ),
	__einfo_errortab ( EINFO_ECONNRESET_LEAVING_TO_ROAM ),
	__einfo_errortab ( EINFO_ECONNRESET_REASSOC_INVALID ),
	__einfo_errortab ( EINFO_ECONNRESET_BAD_POWER ),
	__einfo_errortab ( EINFO_ECONNRESET_BAD_CHANNELS ),
	__einfo_errortab ( EINFO_ECONNRESET_INVALID_IE ),
	__einfo_errortab ( EINFO_ECONNRESET_MIC_FAILURE ),
	__einfo_errortab ( EINFO_ECONNRESET_4WAY_TIMEOUT ),
	__einfo_errortab ( EINFO_ECONNRESET_GROUPKEY_TIMEOUT ),
	__einfo_errortab ( EINFO_ECONNRESET_4WAY_INVALID ),
	__einfo_errortab ( EINFO_ECONNRESET_GROUP_CIPHER_INVALID ),
	__einfo_errortab ( EINFO_ECONNRESET_PAIR_CIPHER_INVALID ),
	__einfo_errortab ( EINFO_ECONNRESET_AKMP_INVALID ),
	__einfo_errortab ( EINFO_ECONNRESET_RSN_VERSION_INVALID ),
	__einfo_errortab ( EINFO_ECONNRESET_RSN_CAPAB_INVALID ),
	__einfo_errortab ( EINFO_ECONNRESET_8021X_FAILURE ),
	__einfo_errortab ( EINFO_ECONNRESET_CIPHER_REJECTED ),
	__einfo_errortab ( EINFO_ENETRESET_QOS_UNSPECIFIED ),
	__einfo_errortab ( EINFO_ENETRESET_QOS_OUT_OF_RESOURCES ),
	__einfo_errortab ( EINFO_ENETRESET_LINK_IS_HORRIBLE ),
	__einfo_errortab ( EINFO_ENETRESET_INVALID_TXOP ),
	__einfo_errortab ( EINFO_ENETRESET_REQUESTED_LEAVING ),
	__einfo_errortab ( EINFO_ENETRESET_REQUESTED_NO_USE ),
	__einfo_errortab ( EINFO_ENETRESET_REQUESTED_NEED_SETUP ),
	__einfo_errortab ( EINFO_ENETRESET_REQUESTED_TIMEOUT ),
	__einfo_errortab ( EINFO_ENETRESET_CIPHER_UNSUPPORTED ),
};
