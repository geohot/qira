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

#include <ipxe/net80211.h>
#include <ipxe/sec80211.h>
#include <ipxe/wpa.h>
#include <ipxe/eapol.h>
#include <ipxe/crypto.h>
#include <ipxe/arc4.h>
#include <ipxe/crc32.h>
#include <ipxe/sha1.h>
#include <ipxe/hmac.h>
#include <ipxe/list.h>
#include <ipxe/ethernet.h>
#include <ipxe/rbg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>

/** @file
 *
 * Handler for the aspects of WPA handshaking that are independent of
 * 802.1X/PSK or TKIP/CCMP; this mostly involves the 4-Way Handshake.
 */

/** List of WPA contexts in active use. */
struct list_head wpa_contexts = LIST_HEAD_INIT ( wpa_contexts );


/**
 * Return an error code and deauthenticate
 *
 * @v ctx	WPA common context
 * @v rc	Return status code
 * @ret rc	The passed return status code
 */
static int wpa_fail ( struct wpa_common_ctx *ctx, int rc )
{
	net80211_deauthenticate ( ctx->dev, rc );
	return rc;
}


/**
 * Find a cryptosystem handler structure from a crypto ID
 *
 * @v crypt	Cryptosystem ID
 * @ret crypto	Cryptosystem handler structure
 *
 * If support for @a crypt is not compiled in to iPXE, or if @a crypt
 * is NET80211_CRYPT_UNKNOWN, returns @c NULL.
 */
static struct net80211_crypto *
wpa_find_cryptosystem ( enum net80211_crypto_alg crypt )
{
	struct net80211_crypto *crypto;

	for_each_table_entry ( crypto, NET80211_CRYPTOS ) {
		if ( crypto->algorithm == crypt )
			return crypto;
	}

	return NULL;
}


/**
 * Find WPA key integrity and encryption handler from key version field
 *
 * @v ver	Version bits of EAPOL-Key info field
 * @ret kie	Key integrity and encryption handler
 */
struct wpa_kie * wpa_find_kie ( int version )
{
	struct wpa_kie *kie;

	for_each_table_entry ( kie, WPA_KIES ) {
		if ( kie->version == version )
			return kie;
	}

	return NULL;
}


/**
 * Construct RSN or WPA information element
 *
 * @v dev	802.11 device
 * @ret ie_ret	RSN or WPA information element
 * @ret rc	Return status code
 *
 * This function allocates, fills, and returns a RSN or WPA
 * information element suitable for including in an association
 * request frame to the network identified by @c dev->associating.
 * If it is impossible to construct an information element consistent
 * with iPXE's capabilities that is compatible with that network, or
 * if none should be sent because that network's beacon included no
 * security information, returns an error indication and leaves
 * @a ie_ret unchanged.
 *
 * The returned IE will be of the same type (RSN or WPA) as was
 * included in the beacon for the network it is destined for.
 */
int wpa_make_rsn_ie ( struct net80211_device *dev, union ieee80211_ie **ie_ret )
{
	u8 *rsn, *rsn_end;
	int is_rsn;
	u32 group_cipher;
	enum net80211_crypto_alg gcrypt;
	int ie_len;
	u8 *iep;
	struct ieee80211_ie_rsn *ie;
	struct ieee80211_frame *hdr;
	struct ieee80211_beacon *beacon;

	if ( ! dev->associating ) {
		DBG ( "WPA: Can't make RSN IE for a non-associating device\n" );
		return -EINVAL;
	}

	hdr = dev->associating->beacon->data;
	beacon = ( struct ieee80211_beacon * ) hdr->data;
	rsn = sec80211_find_rsn ( beacon->info_element,
				  dev->associating->beacon->tail, &is_rsn,
				  &rsn_end );
	if ( ! rsn ) {
		DBG ( "WPA: Can't make RSN IE when we didn't get one\n" );
		return -EINVAL;
	}

	rsn += 2;		/* skip version */
	group_cipher = *( u32 * ) rsn;
	gcrypt = sec80211_rsn_get_net80211_crypt ( group_cipher );

	if ( ! wpa_find_cryptosystem ( gcrypt ) ||
	     ! wpa_find_cryptosystem ( dev->associating->crypto ) ) {
		DBG ( "WPA: No support for (GC:%d, PC:%d)\n",
		      gcrypt, dev->associating->crypto );
		return -ENOTSUP;
	}

	/* Everything looks good - make our IE. */

	/* WPA IEs need 4 more bytes for the OUI+type */
	ie_len = ieee80211_rsn_size ( 1, 1, 0, is_rsn ) + ( 4 * ! is_rsn );
	iep = malloc ( ie_len );
	if ( ! iep )
		return -ENOMEM;

	*ie_ret = ( union ieee80211_ie * ) iep;

	/* Store ID and length bytes. */
	*iep++ = ( is_rsn ? IEEE80211_IE_RSN : IEEE80211_IE_VENDOR );
	*iep++ = ie_len - 2;

	/* Store OUI+type for WPA IEs. */
	if ( ! is_rsn ) {
		*( u32 * ) iep = IEEE80211_WPA_OUI_VEN;
		iep += 4;
	}

	/* If this is a WPA IE, the id and len bytes in the
	   ieee80211_ie_rsn structure will not be valid, but by doing
	   the cast we can fill all the other fields much more
	   readily. */

	ie = ( struct ieee80211_ie_rsn * ) ( iep - 2 );
	ie->version = IEEE80211_RSN_VERSION;
	ie->group_cipher = group_cipher;
	ie->pairwise_count = 1;
	ie->pairwise_cipher[0] =
		sec80211_rsn_get_crypto_desc ( dev->associating->crypto,
					       is_rsn );
	ie->akm_count = 1;
	ie->akm_list[0] =
		sec80211_rsn_get_akm_desc ( dev->associating->handshaking,
					    is_rsn );
	if ( is_rsn ) {
		ie->rsn_capab = 0;
		ie->pmkid_count = 0;
	}

	return 0;
}


/**
 * Set up generic WPA support to handle 4-Way Handshake
 *
 * @v dev	802.11 device
 * @v ctx	WPA common context
 * @v pmk	Pairwise Master Key to use for session
 * @v pmk_len	Length of PMK, almost always 32
 * @ret rc	Return status code
 */
int wpa_start ( struct net80211_device *dev, struct wpa_common_ctx *ctx,
		const void *pmk, size_t pmk_len )
{
	struct io_buffer *iob;
	struct ieee80211_frame *hdr;
	struct ieee80211_beacon *beacon;
	u8 *ap_rsn_ie = NULL, *ap_rsn_ie_end;

	if ( ! dev->rsn_ie || ! dev->associating )
		return -EINVAL;

	ctx->dev = dev;
	memcpy ( ctx->pmk, pmk, ctx->pmk_len = pmk_len );
	ctx->state = WPA_READY;
	ctx->replay = ~0ULL;

	iob = dev->associating->beacon;
	hdr = iob->data;
	beacon = ( struct ieee80211_beacon * ) hdr->data;
	ap_rsn_ie = sec80211_find_rsn ( beacon->info_element, iob->tail,
					&ctx->ap_rsn_is_rsn, &ap_rsn_ie_end );
	if ( ap_rsn_ie ) {
		ctx->ap_rsn_ie = malloc ( ap_rsn_ie_end - ap_rsn_ie );
		if ( ! ctx->ap_rsn_ie )
			return -ENOMEM;
		memcpy ( ctx->ap_rsn_ie, ap_rsn_ie, ap_rsn_ie_end - ap_rsn_ie );
		ctx->ap_rsn_ie_len = ap_rsn_ie_end - ap_rsn_ie;
	} else {
		return -ENOENT;
	}

	ctx->crypt = dev->associating->crypto;
	ctx->gcrypt = NET80211_CRYPT_UNKNOWN;

	list_add_tail ( &ctx->list, &wpa_contexts );
	return 0;
}


/**
 * Disable handling of received WPA handshake frames
 *
 * @v dev	802.11 device
 */
void wpa_stop ( struct net80211_device *dev )
{
	struct wpa_common_ctx *ctx, *tmp;

	list_for_each_entry_safe ( ctx, tmp, &wpa_contexts, list ) {
		if ( ctx->dev == dev ) {
			free ( ctx->ap_rsn_ie );
			ctx->ap_rsn_ie = NULL;
			list_del ( &ctx->list );
		}
	}
}


/**
 * Derive pairwise transient key
 *
 * @v ctx	WPA common context
 */
static void wpa_derive_ptk ( struct wpa_common_ctx *ctx )
{
	struct {
		u8 mac1[ETH_ALEN];
		u8 mac2[ETH_ALEN];
		u8 nonce1[WPA_NONCE_LEN];
		u8 nonce2[WPA_NONCE_LEN];
	} __attribute__ (( packed )) ptk_data;

	/* The addresses and nonces are stored in numerical order (!) */

	if ( memcmp ( ctx->dev->netdev->ll_addr, ctx->dev->bssid,
		      ETH_ALEN ) < 0 ) {
		memcpy ( ptk_data.mac1, ctx->dev->netdev->ll_addr, ETH_ALEN );
		memcpy ( ptk_data.mac2, ctx->dev->bssid, ETH_ALEN );
	} else {
		memcpy ( ptk_data.mac1, ctx->dev->bssid, ETH_ALEN );
		memcpy ( ptk_data.mac2, ctx->dev->netdev->ll_addr, ETH_ALEN );
	}

	if ( memcmp ( ctx->Anonce, ctx->Snonce, WPA_NONCE_LEN ) < 0 ) {
		memcpy ( ptk_data.nonce1, ctx->Anonce, WPA_NONCE_LEN );
		memcpy ( ptk_data.nonce2, ctx->Snonce, WPA_NONCE_LEN );
	} else {
		memcpy ( ptk_data.nonce1, ctx->Snonce, WPA_NONCE_LEN );
		memcpy ( ptk_data.nonce2, ctx->Anonce, WPA_NONCE_LEN );
	}

	DBGC2 ( ctx, "WPA %p A1 %s, A2 %s\n", ctx, eth_ntoa ( ptk_data.mac1 ),
	       eth_ntoa ( ptk_data.mac2 ) );
	DBGC2 ( ctx, "WPA %p Nonce1, Nonce2:\n", ctx );
	DBGC2_HD ( ctx, ptk_data.nonce1, WPA_NONCE_LEN );
	DBGC2_HD ( ctx, ptk_data.nonce2, WPA_NONCE_LEN );

	prf_sha1 ( ctx->pmk, ctx->pmk_len,
		   "Pairwise key expansion",
		   &ptk_data, sizeof ( ptk_data ),
		   &ctx->ptk, sizeof ( ctx->ptk ) );

	DBGC2 ( ctx, "WPA %p PTK:\n", ctx );
	DBGC2_HD ( ctx, &ctx->ptk, sizeof ( ctx->ptk ) );
}


/**
 * Install pairwise transient key
 *
 * @v ctx	WPA common context
 * @v len	Key length (16 for CCMP, 32 for TKIP)
 * @ret rc	Return status code
 */
static inline int wpa_install_ptk ( struct wpa_common_ctx *ctx, int len )
{
	DBGC ( ctx, "WPA %p: installing %d-byte pairwise transient key\n",
	       ctx, len );
	DBGC2_HD ( ctx, &ctx->ptk.tk, len );

	return sec80211_install ( &ctx->dev->crypto, ctx->crypt,
				  &ctx->ptk.tk, len, NULL );
}

/**
 * Install group transient key
 *
 * @v ctx	WPA common context
 * @v len	Key length (16 for CCMP, 32 for TKIP)
 * @v rsc	Receive sequence counter field in EAPOL-Key packet
 * @ret rc	Return status code
 */
static inline int wpa_install_gtk ( struct wpa_common_ctx *ctx, int len,
				    const void *rsc )
{
	DBGC ( ctx, "WPA %p: installing %d-byte group transient key\n",
	       ctx, len );
	DBGC2_HD ( ctx, &ctx->gtk.tk, len );

	return sec80211_install ( &ctx->dev->gcrypto, ctx->gcrypt,
				  &ctx->gtk.tk, len, rsc );
}

/**
 * Search for group transient key, and install it if found
 *
 * @v ctx	WPA common context
 * @v ie	Pointer to first IE in key data field
 * @v ie_end	Pointer to first byte not in key data field
 * @v rsc	Receive sequence counter field in EAPOL-Key packet
 * @ret rc	Return status code
 */
static int wpa_maybe_install_gtk ( struct wpa_common_ctx *ctx,
				   union ieee80211_ie *ie, void *ie_end,
				   const void *rsc )
{
	struct wpa_kde *kde;

	if ( ! ieee80211_ie_bound ( ie, ie_end ) )
		return -ENOENT;

	while ( ie ) {
		if ( ie->id == IEEE80211_IE_VENDOR &&
		     ie->vendor.oui == WPA_KDE_GTK )
			break;

		ie = ieee80211_next_ie ( ie, ie_end );
	}

	if ( ! ie )
		return -ENOENT;

	if ( ie->len - 6u > sizeof ( ctx->gtk.tk ) ) {
		DBGC ( ctx, "WPA %p: GTK KDE is too long (%d bytes, max %zd)\n",
		       ctx, ie->len - 4, sizeof ( ctx->gtk.tk ) );
		return -EINVAL;
	}

	/* XXX We ignore key ID for now. */
	kde = ( struct wpa_kde * ) ie;
	memcpy ( &ctx->gtk.tk, &kde->gtk_encap.gtk, kde->len - 6 );

	return wpa_install_gtk ( ctx, kde->len - 6, rsc );
}


/**
 * Allocate I/O buffer for construction of outgoing EAPOL-Key frame
 *
 * @v kdlen	Maximum number of bytes in the Key Data field
 * @ret iob	Newly allocated I/O buffer
 *
 * The returned buffer will have space reserved for the link-layer and
 * EAPOL headers, and will have @c iob->tail pointing to the start of
 * the Key Data field. Thus, it is necessary to use iob_put() in
 * filling the Key Data.
 */
static struct io_buffer * wpa_alloc_frame ( int kdlen )
{
	struct io_buffer *ret = alloc_iob ( sizeof ( struct eapol_key_pkt ) +
					    kdlen + EAPOL_HDR_LEN +
					    MAX_LL_HEADER_LEN );
	if ( ! ret )
		return NULL;

	iob_reserve ( ret, MAX_LL_HEADER_LEN + EAPOL_HDR_LEN );
	memset ( iob_put ( ret, sizeof ( struct eapol_key_pkt ) ), 0,
		 sizeof ( struct eapol_key_pkt ) );

	return ret;
}


/**
 * Send EAPOL-Key packet
 *
 * @v iob	I/O buffer, with sufficient headroom for headers
 * @v dev	802.11 device
 * @v kie	Key integrity and encryption handler
 * @v is_rsn	If TRUE, handshake uses new RSN format
 * @ret rc	Return status code
 *
 * If a KIE is specified, the MIC will be filled in before transmission.
 */
static int wpa_send_eapol ( struct io_buffer *iob, struct wpa_common_ctx *ctx,
			    struct wpa_kie *kie )
{
	struct eapol_key_pkt *pkt = iob->data;
	struct eapol_frame *eapol = iob_push ( iob, EAPOL_HDR_LEN );

	pkt->info = htons ( pkt->info );
	pkt->keysize = htons ( pkt->keysize );
	pkt->datalen = htons ( pkt->datalen );
	pkt->replay = cpu_to_be64 ( pkt->replay );
	eapol->version = EAPOL_THIS_VERSION;
	eapol->type = EAPOL_TYPE_KEY;
	eapol->length = htons ( iob->tail - iob->data - sizeof ( *eapol ) );

	memset ( pkt->mic, 0, sizeof ( pkt->mic ) );
	if ( kie )
		kie->mic ( &ctx->ptk.kck, eapol, EAPOL_HDR_LEN +
			   sizeof ( *pkt ) + ntohs ( pkt->datalen ),
			   pkt->mic );

	return net_tx ( iob, ctx->dev->netdev, &eapol_protocol,
			ctx->dev->bssid, ctx->dev->netdev->ll_addr );
}


/**
 * Send second frame in 4-Way Handshake
 *
 * @v ctx	WPA common context
 * @v pkt	First frame, to which this is a reply
 * @v is_rsn	If TRUE, handshake uses new RSN format
 * @v kie	Key integrity and encryption handler
 * @ret rc	Return status code
 */
static int wpa_send_2_of_4 ( struct wpa_common_ctx *ctx,
			     struct eapol_key_pkt *pkt, int is_rsn,
			     struct wpa_kie *kie )
{
	struct io_buffer *iob = wpa_alloc_frame ( ctx->dev->rsn_ie->len + 2 );
	struct eapol_key_pkt *npkt;

	if ( ! iob )
		return -ENOMEM;

	npkt = iob->data;
	memcpy ( npkt, pkt, sizeof ( *pkt ) );
	npkt->info &= ~EAPOL_KEY_INFO_KEY_ACK;
	npkt->info |= EAPOL_KEY_INFO_KEY_MIC;
	if ( is_rsn )
		npkt->keysize = 0;
	memcpy ( npkt->nonce, ctx->Snonce, sizeof ( npkt->nonce ) );
	npkt->datalen = ctx->dev->rsn_ie->len + 2;
	memcpy ( iob_put ( iob, npkt->datalen ), ctx->dev->rsn_ie,
		 npkt->datalen );

	DBGC ( ctx, "WPA %p: sending 2/4\n", ctx );

	return wpa_send_eapol ( iob, ctx, kie );
}


/**
 * Handle receipt of first frame in 4-Way Handshake
 *
 * @v ctx	WPA common context
 * @v pkt	EAPOL-Key packet
 * @v is_rsn	If TRUE, frame uses new RSN format
 * @v kie	Key integrity and encryption handler
 * @ret rc	Return status code
 */
static int wpa_handle_1_of_4 ( struct wpa_common_ctx *ctx,
			       struct eapol_key_pkt *pkt, int is_rsn,
			       struct wpa_kie *kie )
{
	if ( ctx->state == WPA_WAITING )
		return -EINVAL;

	ctx->state = WPA_WORKING;
	memcpy ( ctx->Anonce, pkt->nonce, sizeof ( ctx->Anonce ) );
	if ( ! ctx->have_Snonce ) {
		rbg_generate ( NULL, 0, 0, ctx->Snonce,
			       sizeof ( ctx->Snonce ) );
		ctx->have_Snonce = 1;
	}

	DBGC ( ctx, "WPA %p: received 1/4, looks OK\n", ctx );

	wpa_derive_ptk ( ctx );

	return wpa_send_2_of_4 ( ctx, pkt, is_rsn, kie );
}


/**
 * Send fourth frame in 4-Way Handshake, or second in Group Key Handshake
 *
 * @v ctx	WPA common context
 * @v pkt	EAPOL-Key packet for frame to which we're replying
 * @v is_rsn	If TRUE, frame uses new RSN format
 * @v kie	Key integrity and encryption handler
 * @ret rc	Return status code
 */
static int wpa_send_final ( struct wpa_common_ctx *ctx,
			    struct eapol_key_pkt *pkt, int is_rsn,
			    struct wpa_kie *kie )
{
	struct io_buffer *iob = wpa_alloc_frame ( 0 );
	struct eapol_key_pkt *npkt;

	if ( ! iob )
		return -ENOMEM;

	npkt = iob->data;
	memcpy ( npkt, pkt, sizeof ( *pkt ) );
	npkt->info &= ~( EAPOL_KEY_INFO_KEY_ACK | EAPOL_KEY_INFO_INSTALL |
			 EAPOL_KEY_INFO_KEY_ENC );
	if ( is_rsn )
		npkt->keysize = 0;
	memset ( npkt->nonce, 0, sizeof ( npkt->nonce ) );
	memset ( npkt->iv, 0, sizeof ( npkt->iv ) );
	npkt->datalen = 0;

	if ( npkt->info & EAPOL_KEY_INFO_TYPE )
		DBGC ( ctx, "WPA %p: sending 4/4\n", ctx );
	else
		DBGC ( ctx, "WPA %p: sending 2/2\n", ctx );

	return wpa_send_eapol ( iob, ctx, kie );

}


/**
 * Handle receipt of third frame in 4-Way Handshake
 *
 * @v ctx	WPA common context
 * @v pkt	EAPOL-Key packet
 * @v is_rsn	If TRUE, frame uses new RSN format
 * @v kie	Key integrity and encryption handler
 * @ret rc	Return status code
 */
static int wpa_handle_3_of_4 ( struct wpa_common_ctx *ctx,
			       struct eapol_key_pkt *pkt, int is_rsn,
			       struct wpa_kie *kie )
{
	int rc;
	u8 *this_rsn, *this_rsn_end;
	u8 *new_rsn, *new_rsn_end;
	int this_is_rsn, new_is_rsn;

	if ( ctx->state == WPA_WAITING )
		return -EINVAL;

	ctx->state = WPA_WORKING;

	/* Check nonce */
	if ( memcmp ( ctx->Anonce, pkt->nonce, WPA_NONCE_LEN ) != 0 ) {
		DBGC ( ctx, "WPA %p ALERT: nonce mismatch in 3/4\n", ctx );
		return wpa_fail ( ctx, -EACCES );
	}

	/* Check RSN IE */
	this_rsn = sec80211_find_rsn ( ( union ieee80211_ie * ) pkt->data,
				       pkt->data + pkt->datalen,
				       &this_is_rsn, &this_rsn_end );
	if ( this_rsn )
		new_rsn = sec80211_find_rsn ( ( union ieee80211_ie * )
					              this_rsn_end,
					      pkt->data + pkt->datalen,
					      &new_is_rsn, &new_rsn_end );
	else
		new_rsn = NULL;

	if ( ! ctx->ap_rsn_ie || ! this_rsn ||
	     ctx->ap_rsn_ie_len != ( this_rsn_end - this_rsn ) ||
	     ctx->ap_rsn_is_rsn != this_is_rsn ||
	     memcmp ( ctx->ap_rsn_ie, this_rsn, ctx->ap_rsn_ie_len ) != 0 ) {
		DBGC ( ctx, "WPA %p ALERT: RSN mismatch in 3/4\n", ctx );
		DBGC2 ( ctx, "WPA %p RSNs (in 3/4, in beacon):\n", ctx );
		DBGC2_HD ( ctx, this_rsn, this_rsn_end - this_rsn );
		DBGC2_HD ( ctx, ctx->ap_rsn_ie, ctx->ap_rsn_ie_len );
		return wpa_fail ( ctx, -EACCES );
	}

	/* Don't switch if they just supplied both styles of IE
	   simultaneously; we need two RSN IEs or two WPA IEs to
	   switch ciphers. They'll be immediately consecutive because
	   of ordering guarantees. */
	if ( new_rsn && this_is_rsn == new_is_rsn ) {
		struct net80211_wlan *assoc = ctx->dev->associating;
		DBGC ( ctx, "WPA %p: accommodating bait-and-switch tactics\n",
		       ctx );
		DBGC2 ( ctx, "WPA %p RSNs (in 3/4+beacon, new in 3/4):\n",
			ctx );
		DBGC2_HD ( ctx, this_rsn, this_rsn_end - this_rsn );
		DBGC2_HD ( ctx, new_rsn, new_rsn_end - new_rsn );

		if ( ( rc = sec80211_detect_ie ( new_is_rsn, new_rsn,
						 new_rsn_end,
						 &assoc->handshaking,
						 &assoc->crypto ) ) != 0 )
			DBGC ( ctx, "WPA %p: bait-and-switch invalid, staying "
			       "with original request\n", ctx );
	} else {
		new_rsn = this_rsn;
		new_is_rsn = this_is_rsn;
		new_rsn_end = this_rsn_end;
	}

	/* Grab group cryptosystem ID */
	ctx->gcrypt = sec80211_rsn_get_net80211_crypt ( *( u32 * )
							( new_rsn + 2 ) );

	/* Check for a GTK, if info field is encrypted */
	if ( pkt->info & EAPOL_KEY_INFO_KEY_ENC ) {
		rc = wpa_maybe_install_gtk ( ctx,
					     ( union ieee80211_ie * ) pkt->data,
					     pkt->data + pkt->datalen,
					     pkt->rsc );
		if ( rc < 0 ) {
			DBGC ( ctx, "WPA %p did not install GTK in 3/4: %s\n",
			       ctx, strerror ( rc ) );
			if ( rc != -ENOENT )
				return wpa_fail ( ctx, rc );
		}
	}

	DBGC ( ctx, "WPA %p: received 3/4, looks OK\n", ctx );

	/* Send final message */
	rc = wpa_send_final ( ctx, pkt, is_rsn, kie );
	if ( rc < 0 )
		return wpa_fail ( ctx, rc );

	/* Install PTK */
	rc = wpa_install_ptk ( ctx, pkt->keysize );
	if ( rc < 0 ) {
		DBGC ( ctx, "WPA %p failed to install PTK: %s\n", ctx,
		       strerror ( rc ) );
		return wpa_fail ( ctx, rc );
	}

	/* Mark us as needing a new Snonce if we rekey */
	ctx->have_Snonce = 0;

	/* Done! */
	ctx->state = WPA_SUCCESS;
	return 0;
}


/**
 * Handle receipt of first frame in Group Key Handshake
 *
 * @v ctx	WPA common context
 * @v pkt	EAPOL-Key packet
 * @v is_rsn	If TRUE, frame uses new RSN format
 * @v kie	Key integrity and encryption handler
 * @ret rc	Return status code
 */
static int wpa_handle_1_of_2 ( struct wpa_common_ctx *ctx,
			       struct eapol_key_pkt *pkt, int is_rsn,
			       struct wpa_kie *kie )
{
	int rc;

	/*
	 * WPA and RSN do this completely differently.
	 *
	 * The idea of encoding the GTK (or PMKID, or various other
	 * things) into a KDE that looks like an information element
	 * is an RSN innovation; old WPA code never encapsulates
	 * things like that. If it looks like an info element, it
	 * really is (for the WPA IE check in frames 2/4 and 3/4). The
	 * "key data encrypted" bit in the info field is also specific
	 * to RSN.
	 *
	 * So from an old WPA host, 3/4 does not contain an
	 * encapsulated GTK. The first frame of the GK handshake
	 * contains it, encrypted, but without a KDE wrapper, and with
	 * the key ID field (which iPXE doesn't use) shoved away in
	 * the reserved bits in the info field, and the TxRx bit
	 * stealing the Install bit's spot.
	 */

	if ( is_rsn && ( pkt->info & EAPOL_KEY_INFO_KEY_ENC ) ) {
		rc = wpa_maybe_install_gtk ( ctx,
					     ( union ieee80211_ie * ) pkt->data,
					     pkt->data + pkt->datalen,
					     pkt->rsc );
		if ( rc < 0 ) {
			DBGC ( ctx, "WPA %p: failed to install GTK in 1/2: "
			       "%s\n", ctx, strerror ( rc ) );
			return wpa_fail ( ctx, rc );
		}
	} else {
		rc = kie->decrypt ( &ctx->ptk.kek, pkt->iv, pkt->data,
				    &pkt->datalen );
		if ( rc < 0 ) {
			DBGC ( ctx, "WPA %p: failed to decrypt GTK: %s\n",
			       ctx, strerror ( rc ) );
			return rc; /* non-fatal */
		}
		if ( pkt->datalen > sizeof ( ctx->gtk.tk ) ) {
			DBGC ( ctx, "WPA %p: too much GTK data (%d > %zd)\n",
			       ctx, pkt->datalen, sizeof ( ctx->gtk.tk ) );
			return wpa_fail ( ctx, -EINVAL );
		}

		memcpy ( &ctx->gtk.tk, pkt->data, pkt->datalen );
		wpa_install_gtk ( ctx, pkt->datalen, pkt->rsc );
	}

	DBGC ( ctx, "WPA %p: received 1/2, looks OK\n", ctx );

	return wpa_send_final ( ctx, pkt, is_rsn, kie );
}


/**
 * Handle receipt of EAPOL-Key frame for WPA
 *
 * @v iob	I/O buffer
 * @v netdev	Network device
 * @v ll_dest	Link-layer destination address
 * @v ll_source	Source link-layer address
 */
static int eapol_key_rx ( struct io_buffer *iob, struct net_device *netdev,
			  const void *ll_dest __unused,
			  const void *ll_source )
{
	struct net80211_device *dev = net80211_get ( netdev );
	struct eapol_key_pkt *pkt = iob->data;
	int is_rsn, found_ctx;
	struct wpa_common_ctx *ctx;
	int rc = 0;
	struct wpa_kie *kie;
	u8 their_mic[16], our_mic[16];

	if ( pkt->type != EAPOL_KEY_TYPE_WPA &&
	     pkt->type != EAPOL_KEY_TYPE_RSN ) {
		DBG ( "EAPOL-Key: packet not of 802.11 type\n" );
		rc = -EINVAL;
		goto drop;
	}

	is_rsn = ( pkt->type == EAPOL_KEY_TYPE_RSN );

	if ( ! dev ) {
		DBG ( "EAPOL-Key: packet not from 802.11\n" );
		rc = -EINVAL;
		goto drop;
	}

	if ( memcmp ( dev->bssid, ll_source, ETH_ALEN ) != 0 ) {
		DBG ( "EAPOL-Key: packet not from associated AP\n" );
		rc = -EINVAL;
		goto drop;
	}

	if ( ! ( ntohs ( pkt->info ) & EAPOL_KEY_INFO_KEY_ACK ) ) {
		DBG ( "EAPOL-Key: packet sent in wrong direction\n" );
		rc = -EINVAL;
		goto drop;
	}

	found_ctx = 0;
	list_for_each_entry ( ctx, &wpa_contexts, list ) {
		if ( ctx->dev == dev ) {
			found_ctx = 1;
			break;
		}
	}

	if ( ! found_ctx ) {
		DBG ( "EAPOL-Key: no WPA context to handle packet for %p\n",
		      dev );
		rc = -ENOENT;
		goto drop;
	}

	if ( ( void * ) ( pkt + 1 ) + ntohs ( pkt->datalen ) > iob->tail ) {
		DBGC ( ctx, "WPA %p: packet truncated (has %zd extra bytes, "
		       "states %d)\n", ctx, iob->tail - ( void * ) ( pkt + 1 ),
		       ntohs ( pkt->datalen ) );
		rc = -EINVAL;
		goto drop;
	}

	/* Get a handle on key integrity/encryption handler */
	kie = wpa_find_kie ( ntohs ( pkt->info ) & EAPOL_KEY_INFO_VERSION );
	if ( ! kie ) {
		DBGC ( ctx, "WPA %p: no support for packet version %d\n", ctx,
		       ntohs ( pkt->info ) & EAPOL_KEY_INFO_VERSION );
		rc = wpa_fail ( ctx, -ENOTSUP );
		goto drop;
	}

	/* Check MIC */
	if ( ntohs ( pkt->info ) & EAPOL_KEY_INFO_KEY_MIC ) {
		memcpy ( their_mic, pkt->mic, sizeof ( pkt->mic ) );
		memset ( pkt->mic, 0, sizeof ( pkt->mic ) );
		kie->mic ( &ctx->ptk.kck, ( void * ) pkt - EAPOL_HDR_LEN,
			   EAPOL_HDR_LEN + sizeof ( *pkt ) +
			   ntohs ( pkt->datalen ), our_mic );
		DBGC2 ( ctx, "WPA %p MIC comparison (theirs, ours):\n", ctx );
		DBGC2_HD ( ctx, their_mic, 16 );
		DBGC2_HD ( ctx, our_mic, 16 );
		if ( memcmp ( their_mic, our_mic, sizeof ( pkt->mic ) ) != 0 ) {
			DBGC ( ctx, "WPA %p: EAPOL MIC failure\n", ctx );
			goto drop;
		}
	}

	/* Fix byte order to local */
	pkt->info = ntohs ( pkt->info );
	pkt->keysize = ntohs ( pkt->keysize );
	pkt->datalen = ntohs ( pkt->datalen );
	pkt->replay = be64_to_cpu ( pkt->replay );

	/* Check replay counter */
	if ( ctx->replay != ~0ULL && ctx->replay >= pkt->replay ) {
		DBGC ( ctx, "WPA %p ALERT: Replay detected! "
		       "(%08x:%08x >= %08x:%08x)\n", ctx,
		       ( u32 ) ( ctx->replay >> 32 ), ( u32 ) ctx->replay,
		       ( u32 ) ( pkt->replay >> 32 ), ( u32 ) pkt->replay );
		rc = 0;		/* ignore without error */
		goto drop;
	}
	ctx->replay = pkt->replay;

	/* Decrypt key data */
	if ( pkt->info & EAPOL_KEY_INFO_KEY_ENC ) {
		rc = kie->decrypt ( &ctx->ptk.kek, pkt->iv, pkt->data,
				    &pkt->datalen );
		if ( rc < 0 ) {
			DBGC ( ctx, "WPA %p: failed to decrypt packet: %s\n",
			       ctx, strerror ( rc ) );
			goto drop;
		}
	}

	/* Hand it off to appropriate handler */
	switch ( pkt->info & ( EAPOL_KEY_INFO_TYPE |
			       EAPOL_KEY_INFO_KEY_MIC ) ) {
	case EAPOL_KEY_TYPE_PTK:
		rc = wpa_handle_1_of_4 ( ctx, pkt, is_rsn, kie );
		break;

	case EAPOL_KEY_TYPE_PTK | EAPOL_KEY_INFO_KEY_MIC:
		rc = wpa_handle_3_of_4 ( ctx, pkt, is_rsn, kie );
		break;

	case EAPOL_KEY_TYPE_GTK | EAPOL_KEY_INFO_KEY_MIC:
		rc = wpa_handle_1_of_2 ( ctx, pkt, is_rsn, kie );
		break;

	default:
		DBGC ( ctx, "WPA %p: Invalid combination of key flags %04x\n",
		       ctx, pkt->info );
		rc = -EINVAL;
		break;
	}

 drop:
	free_iob ( iob );
	return rc;
}

struct eapol_handler eapol_key_handler __eapol_handler = {
	.type = EAPOL_TYPE_KEY,
	.rx = eapol_key_rx,
};

/* WPA always needs EAPOL in order to be useful */
REQUIRING_SYMBOL ( eapol_key_handler );
REQUIRE_OBJECT ( eapol );
