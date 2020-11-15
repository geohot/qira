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

FILE_LICENCE ( GPL2_OR_LATER );

#include <string.h>
#include <ipxe/net80211.h>
#include <ipxe/sha1.h>
#include <ipxe/wpa.h>
#include <errno.h>

/** @file
 *
 * Frontend for WPA using a pre-shared key.
 */

/**
 * Initialise WPA-PSK state
 *
 * @v dev	802.11 device
 * @ret rc	Return status code
 */
static int wpa_psk_init ( struct net80211_device *dev )
{
	return wpa_make_rsn_ie ( dev, &dev->rsn_ie );
}

/**
 * Start WPA-PSK authentication
 *
 * @v dev	802.11 device
 * @ret rc	Return status code
 */
static int wpa_psk_start ( struct net80211_device *dev )
{
	char passphrase[64+1];
	u8 pmk[WPA_PMK_LEN];
	int len;
	struct wpa_common_ctx *ctx = dev->handshaker->priv;

	len = fetch_string_setting ( netdev_settings ( dev->netdev ),
				     &net80211_key_setting, passphrase,
				     64 + 1 );

	if ( len <= 0 ) {
		DBGC ( ctx, "WPA-PSK %p: no passphrase provided!\n", ctx );
		net80211_deauthenticate ( dev, -EACCES );
		return -EACCES;
	}

	pbkdf2_sha1 ( passphrase, len, dev->essid, strlen ( dev->essid ),
		      4096, pmk, WPA_PMK_LEN );

	DBGC ( ctx, "WPA-PSK %p: derived PMK from passphrase `%s':\n", ctx,
	       passphrase );
	DBGC_HD ( ctx, pmk, WPA_PMK_LEN );

	return wpa_start ( dev, ctx, pmk, WPA_PMK_LEN );
}

/**
 * Step WPA-PSK authentication
 *
 * @v dev	802.11 device
 * @ret rc	Return status code
 */
static int wpa_psk_step ( struct net80211_device *dev )
{
	struct wpa_common_ctx *ctx = dev->handshaker->priv;

	switch ( ctx->state ) {
	case WPA_SUCCESS:
		return 1;
	case WPA_FAILURE:
		return -EACCES;
	default:
		return 0;
	}
}

/**
 * Do-nothing function; you can't change a WPA key post-authentication
 *
 * @v dev	802.11 device
 * @ret rc	Return status code
 */
static int wpa_psk_no_change_key ( struct net80211_device *dev __unused )
{
	return 0;
}

/**
 * Disable handling of received WPA authentication frames
 *
 * @v dev	802.11 device
 */
static void wpa_psk_stop ( struct net80211_device *dev )
{
	wpa_stop ( dev );
}

/** WPA-PSK security handshaker */
struct net80211_handshaker wpa_psk_handshaker __net80211_handshaker = {
	.protocol = NET80211_SECPROT_PSK,
	.init = wpa_psk_init,
	.start = wpa_psk_start,
	.step = wpa_psk_step,
	.change_key = wpa_psk_no_change_key,
	.stop = wpa_psk_stop,
	.priv_len = sizeof ( struct wpa_common_ctx ),
};
