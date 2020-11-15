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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/net80211.h>
#include <ipxe/ethernet.h>
#include <usr/ifmgmt.h>
#include <usr/iwmgmt.h>

/** @file
 *
 * Wireless network interface management
 *
 */

/**
 * Print status of 802.11 device
 *
 * @v dev	802.11 device
 */
void iwstat ( struct net80211_device *dev ) {

	ifstat ( dev->netdev );

	printf ( "  [802.11 ");
	if ( dev->state & NET80211_ASSOCIATED ) {
		printf ( "SSID '%s', ", dev->essid );
	} else {
		printf ( "not associated, " );
	}
	if ( dev->channel < dev->nr_channels && dev->rate < dev->nr_rates ) {
		printf ( "Ch:%d Sig:%d", dev->channels[dev->channel].channel_nr,
			 dev->last_signal );
		switch ( dev->hw->signal_type ) {
		case NET80211_SIGNAL_NONE:
			printf ( "?" );
			break;
		case NET80211_SIGNAL_ARBITRARY:
			printf ( "/%d", dev->hw->signal_max );
			break;
		case NET80211_SIGNAL_DB:
			printf ( "/%d dB", dev->hw->signal_max );
			break;
		case NET80211_SIGNAL_DBM:
			printf ( " dBm" );
			break;
		}
		printf ( ", Qual:%d%% Rate:%d Mbps]\n",
			 ( dev->rx_beacon_interval == 0 ? 0 :
			   100 * dev->tx_beacon_interval /
			   dev->rx_beacon_interval ),
			 dev->rates[dev->rate] / 10 );
	} else {
		printf ( "antenna off]\n" );
	}

	if ( dev->state & NET80211_WORKING ) {
		printf ( "  [associating" );
		if ( dev->associating )
			printf ( " to '%s'", dev->associating->essid );
		printf ( "...]\n" );
	}
}

/** Identifiers for 802.11 cryptography types, indexed by type number */
static const char *crypto_types[] = {
	[NET80211_CRYPT_NONE] = "Open",
	[NET80211_CRYPT_WEP] = "WEP ",
	[NET80211_CRYPT_TKIP] = "WPA ",
	[NET80211_CRYPT_CCMP] = "WPA2",
	[NET80211_CRYPT_UNKNOWN] = "UNK ",
};

/** Number of 802.11 cryptography types defined */
#define NR_CRYPTO_TYPES ( sizeof ( crypto_types ) / sizeof ( crypto_types[0] ) )

/** Identifiers for 802.11 authentication types, indexed by type number */
static const char *auth_types[] = {
	[NET80211_SECPROT_NONE] = "",
	[NET80211_SECPROT_PSK] = "PSK",
	[NET80211_SECPROT_EAP] = "802.1X",
	[NET80211_SECPROT_UNKNOWN] = "UNK",
};

/** Number of 802.11 authentication types defined */
#define NR_AUTH_TYPES ( sizeof ( auth_types ) / sizeof ( auth_types[0] ) )

/**
 * Scan for wireless networks using 802.11 device
 *
 * @v dev	802.11 device
 * @v active	Whether to use active scanning
 *
 * The list of networks found will be printed in tabular format.
 *
 * This function is safe to call at all times, whether the 802.11
 * device is open or not, but if called while the auto-association
 * task is running it will return an error indication.
 */
int iwlist ( struct net80211_device *dev ) {
	struct net80211_probe_ctx *ctx;
	struct list_head *networks;
	struct net80211_wlan *wlan;
	char ssid_buf[22];
	int rc;
	unsigned i;
	int was_opened = netdev_is_open ( dev->netdev );
	int was_channel = dev->channels[dev->channel].channel_nr;

	if ( ! was_opened ) {
		dev->state |= NET80211_NO_ASSOC;
		rc = netdev_open ( dev->netdev );
		if ( rc < 0 )
			goto err;
	}

	if ( dev->state & NET80211_WORKING ) {
		rc = -EINVAL;
		goto err_close_netdev;
	}

	if ( ! was_opened ) {
		rc = net80211_prepare_probe ( dev, dev->hw->bands, 0 );
		if ( rc < 0 )
			goto err_close_netdev;
	}

	ctx = net80211_probe_start ( dev, "", 0 );
	if ( ! ctx ) {
		rc = -ENOMEM;
		goto err_close_netdev;
	}

	while ( ! ( rc = net80211_probe_step ( ctx ) ) ) {
		step();
	}

	networks = net80211_probe_finish_all ( ctx );

	if ( list_empty ( networks ) ) {
		goto err_free_networks;
	}

	rc = 0;

	printf ( "Networks on %s:\n\n", dev->netdev->name );

	/* Output format:
	 * 0         1         2         3         4         5         6
	 * 0123456789012345678901234567890123456789012345678901234567890
	 * [Sig] SSID                  BSSID              Ch  Crypt/Auth
	 * -------------------------------------------------------------
	 * [ 15] abcdefghijklmnopqrst> 00:00:00:00:00:00  11  Open
	 *                                             ... or WPA   PSK etc.
	 */

	/* Quoting the dashes and spaces verbatim uses less code space
	   than generating them programmatically. */
	printf ( "[Sig] SSID                  BSSID              Ch  Crypt/Auth\n"
		 "-------------------------------------------------------------\n" );

	list_for_each_entry ( wlan, networks, list ) {

		/* Format SSID into 22-character string, space-padded,
		   with '>' indicating truncation */

		snprintf ( ssid_buf, sizeof ( ssid_buf ), "%s", wlan->essid );
		for ( i = strlen ( ssid_buf ); i < sizeof ( ssid_buf ) - 1;
		      i++ )
			ssid_buf[i] = ' ';
		if ( ssid_buf[sizeof ( ssid_buf ) - 2] != ' ' )
			ssid_buf[sizeof ( ssid_buf ) - 2] = '>';
		ssid_buf[sizeof ( ssid_buf ) - 1] = 0;

		/* Sanity check */
		if ( wlan->crypto >= NR_CRYPTO_TYPES ||
		     wlan->handshaking >= NR_AUTH_TYPES )
			continue;

		printf ( "[%3d] %s %s  %2d  %s  %s\n",
			 wlan->signal < 0 ? 100 + wlan->signal : wlan->signal,
			 ssid_buf, eth_ntoa ( wlan->bssid ), wlan->channel,
			 crypto_types[wlan->crypto],
			 auth_types[wlan->handshaking] );
	}
	printf ( "\n" );

 err_free_networks:
	net80211_free_wlanlist ( networks );

 err_close_netdev:
	if ( ! was_opened ) {
		dev->state &= ~NET80211_NO_ASSOC;
		netdev_close ( dev->netdev );
	} else {
		net80211_change_channel ( dev, was_channel );
	}

	if ( ! rc )
		return 0;

 err:
	printf ( "Scanning for networks on %s: %s\n",
		 dev->netdev->name, strerror ( rc ) );
	return rc;
}
