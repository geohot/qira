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

#ifndef _IPXE_WPA_H
#define _IPXE_WPA_H

#include <ipxe/ieee80211.h>
#include <ipxe/list.h>

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * Common definitions for all types of WPA-protected networks.
 */


/** EAPOL-Key type field for modern 802.11i/RSN WPA packets */
#define EAPOL_KEY_TYPE_RSN	2

/** Old EAPOL-Key type field used by WPA1 hardware before 802.11i ratified */
#define EAPOL_KEY_TYPE_WPA	254


/**
 * @defgroup eapol_key_info EAPOL-Key Info field bits
 * @{
 */

/** Key descriptor version, indicating WPA or WPA2 */
#define EAPOL_KEY_INFO_VERSION	0x0007

/** Key type bit, indicating pairwise or group */
#define EAPOL_KEY_INFO_TYPE	0x0008

/** Key install bit; set on message 3 except when legacy hacks are used */
#define EAPOL_KEY_INFO_INSTALL	0x0040

/** Key ACK bit; set when a response is required, on all messages except #4 */
#define EAPOL_KEY_INFO_KEY_ACK	0x0080

/** Key MIC bit; set when the MIC field is valid, on messages 3 and 4 */
#define EAPOL_KEY_INFO_KEY_MIC	0x0100

/** Secure bit; set when both sides have both keys, on messages 3 and 4 */
#define EAPOL_KEY_INFO_SECURE	0x0200

/** Error bit; set on a MIC failure for TKIP */
#define EAPOL_KEY_INFO_ERROR	0x0400

/** Request bit; set when authentication is initiated by the Peer (unusual) */
#define EAPOL_KEY_INFO_REQUEST	0x0800

/** Key Encrypted bit; set when the Key Data field is encrypted */
#define EAPOL_KEY_INFO_KEY_ENC	0x1000

/** SMC Message bit; set when this frame is part of an IBSS SMK handshake */
#define EAPOL_KEY_INFO_SMC_MESS	0x2000


/** Key descriptor version field value for WPA (TKIP) */
#define EAPOL_KEY_VERSION_WPA	1

/** Key descriptor version field value for WPA2 (CCMP) */
#define EAPOL_KEY_VERSION_WPA2	2

/** Key type field value for a PTK (pairwise) key handshake */
#define EAPOL_KEY_TYPE_PTK	0x0008

/** Key type field value for a GTK (group) key handshake */
#define EAPOL_KEY_TYPE_GTK	0x0000

/** @} */



/** An EAPOL-Key packet.
 *
 * These are used for the WPA 4-Way Handshake, whether or not prior
 * authentication has been performed using EAP.
 *
 * On LANs, an eapol_key_pkt is always encapsulated in the data field
 * of an eapol_frame, with the frame's type code set to EAPOL_TYPE_KEY.
 *
 * Unlike 802.11 frame headers, the fields in this structure are
 * stored in big-endian!
 */
struct eapol_key_pkt
{
	/** One of the EAPOL_KEY_TYPE_* defines. */
	u8 type;

	/** Bitfield of key characteristics, network byte order */
	u16 info;

	/** Length of encryption key to be used, network byte order
	 *
	 * This is 16 for CCMP, 32 for TKIP, and 5 or 13 for WEP.
	 */
	u16 keysize;

	/** Monotonically increasing value for EAPOL-Key conversations
	 *
	 * In another classic demonstration of overengineering, this
	 * 8-byte value will rarely be anything above 1. It's stored
	 * in network byte order.
	 */
	u64 replay;

	/** Nonce value
	 *
	 * This is the authenticator's ANonce in frame 1, the peer's
	 * SNonce in frame 2, and 0 in frames 3 and 4.
	 */
	u8 nonce[32];

	/** Initialization vector
	 *
	 * This contains the IV used with the Key Encryption Key, or 0
	 * if the key is unencrypted or encrypted using an algorithm
	 * that does not require an IV.
	 */
	u8 iv[16];

	/** Receive sequence counter for GTK
	 *
	 * This is used to synchronize the client's replay counter for
	 * ordinary data packets. The first six bytes contain PN0
	 * through PN5 for CCMP mode, or TSC0 through TSC5 for TKIP
	 * mode. The last two bytes are zero.
	 */
	u8 rsc[8];

	/** Reserved bytes */
	u8 _reserved[8];

	/** Message integrity code over the entire EAPOL frame
	 *
	 * This is calculated using HMAC-MD5 when the key descriptor
	 * version field in @a info is 1, and HMAC-SHA1 ignoring the
	 * last 4 bytes of the hash when the version field in @a info
	 * is 2.
	 */
	u8 mic[16];

	/** Length of the @a data field in bytes, network byte order */
	u16 datalen;

	/** Key data
	 *
	 * This is formatted as a series of 802.11 information
	 * elements, with cryptographic data encapsulated using a
	 * "vendor-specific IE" code and an IEEE-specified OUI.
	 */
	u8 data[0];
} __attribute__ (( packed ));


/** WPA handshaking state */
enum wpa_state {
	/** Waiting for PMK to be set */
	WPA_WAITING = 0,

	/** Ready for 4-Way Handshake */
	WPA_READY,

	/** Performing 4-Way Handshake */
	WPA_WORKING,

	/** 4-Way Handshake succeeded */
	WPA_SUCCESS,

	/** 4-Way Handshake failed */
	WPA_FAILURE,
};

/** Bitfield indicating a selection of WPA transient keys */
enum wpa_keymask {
	/** Pairwise transient key */
	WPA_PTK = 1,

	/** Group transient key */
	WPA_GTK = 2,
};


/** Length of a nonce */
#define WPA_NONCE_LEN		32

/** Length of a TKIP main key */
#define WPA_TKIP_KEY_LEN	16

/** Length of a TKIP MIC key */
#define WPA_TKIP_MIC_KEY_LEN	8

/** Length of a CCMP key */
#define WPA_CCMP_KEY_LEN	16

/** Length of an EAPOL Key Confirmation Key */
#define WPA_KCK_LEN		16

/** Length of an EAPOL Key Encryption Key */
#define WPA_KEK_LEN		16

/** Usual length of a Pairwise Master Key */
#define WPA_PMK_LEN		32

/** Length of a PMKID */
#define WPA_PMKID_LEN		16


/** Structure of the Temporal Key for TKIP encryption */
struct tkip_tk
{
	/** Main key: input to TKIP Phase 1 and Phase 2 key mixing functions */
	u8 key[WPA_TKIP_KEY_LEN];

	/** Michael MIC keys */
	struct {
		/** MIC key for packets from the AP */
		u8 rx[WPA_TKIP_MIC_KEY_LEN];

		/** MIC key for packets to the AP */
		u8 tx[WPA_TKIP_MIC_KEY_LEN];
	} __attribute__ (( packed )) mic;
} __attribute__ (( packed ));

/** Structure of a generic Temporal Key */
union wpa_tk
{
	/** CCMP key */
	u8 ccmp[WPA_CCMP_KEY_LEN];

	/** TKIP keys */
	struct tkip_tk tkip;
};

/** Structure of the Pairwise Transient Key */
struct wpa_ptk
{
	/** EAPOL-Key Key Confirmation Key (KCK) */
	u8 kck[WPA_KCK_LEN];

	/** EAPOL-Key Key Encryption Key (KEK) */
	u8 kek[WPA_KEK_LEN];

	/** Temporal key */
	union wpa_tk tk;
} __attribute__ (( packed ));

/** Structure of the Group Transient Key */
struct wpa_gtk
{
	/** Temporal key */
	union wpa_tk tk;
} __attribute__ (( packed ));


/** Common context for WPA security handshaking
 *
 * Any implementor of a particular handshaking type (e.g. PSK or EAP)
 * must include this structure at the very beginning of their private
 * data context structure, to allow the EAPOL-Key handling code to
 * work. When the preliminary authentication is done, it is necessary
 * to call wpa_start(), passing the PMK (derived from PSK or EAP MSK)
 * as an argument. The handshaker can use its @a step function to
 * monitor @a state in this wpa_ctx structure for success or
 * failure. On success, the keys will be available in @a ptk and @a
 * gtk according to the state of the @a valid bitmask.
 *
 * After an initial success, the parent handshaker does not need to
 * concern itself with rekeying; the WPA common code takes care of
 * that.
 */
struct wpa_common_ctx
{
	/** 802.11 device we are authenticating for */
	struct net80211_device *dev;

	/** The Pairwise Master Key to use in handshaking
	 *
	 * This is set either by running the PBKDF2 algorithm on a
	 * passphrase with the SSID as salt to generate a pre-shared
	 * key, or by copying the first 32 bytes of the EAP Master
	 * Session Key in 802.1X-served authentication.
	 */
	u8 pmk[WPA_PMK_LEN];

	/** Length of the Pairwise Master Key
	 *
	 * This is always 32 except with one EAP method which only
	 * gives 16 bytes.
	 */
	int pmk_len;

	/** State of EAPOL-Key handshaking */
	enum wpa_state state;

	/** Replay counter for this association
	 *
	 * This stores the replay counter value for the most recent
	 * packet we've accepted. It is initially initialised to ~0 to
	 * show we'll accept anything.
	 */
	u64 replay;

	/** Mask of valid keys after authentication success
	 *
	 * If the PTK is not valid, the GTK should be used for both
	 * unicast and multicast decryption; if the GTK is not valid,
	 * multicast packets cannot be decrypted.
	 */
	enum wpa_keymask valid;

	/** The cipher to use for unicast RX and all TX */
	enum net80211_crypto_alg crypt;

	/** The cipher to use for broadcast and multicast RX */
	enum net80211_crypto_alg gcrypt;

	/** The Pairwise Transient Key derived from the handshake */
	struct wpa_ptk ptk;

	/** The Group Transient Key derived from the handshake */
	struct wpa_gtk gtk;

	/** Authenticator-provided nonce */
	u8 Anonce[WPA_NONCE_LEN];

	/** Supplicant-generated nonce (that's us) */
	u8 Snonce[WPA_NONCE_LEN];

	/** Whether we should refrain from generating another SNonce */
	int have_Snonce;

	/** Data in WPA or RSN IE from AP's beacon frame */
	void *ap_rsn_ie;

	/** Length of @a ap_rsn_ie */
	int ap_rsn_ie_len;

	/** Whether @a ap_rsn_ie is an RSN IE (as opposed to old WPA) */
	int ap_rsn_is_rsn;

	/** List entry */
	struct list_head list;
};


/** WPA handshake key integrity and encryption handler
 *
 * Note that due to the structure of the 4-Way Handshake we never
 * actually need to encrypt key data, only decrypt it.
 */
struct wpa_kie {
	/** Value of version bits in EAPOL-Key info field for which to use
	 *
	 * This should be one of the @c EAPOL_KEY_VERSION_* constants.
	 */
	int version;

	/** Calculate MIC over message
	 *
	 * @v kck	Key Confirmation Key, 16 bytes
	 * @v msg	Message to calculate MIC over
	 * @v len	Number of bytes to calculate MIC over
	 * @ret mic	Calculated MIC, 16 bytes long
	 *
	 * The @a mic return may point within @a msg, so it must not
	 * be filled until the calculation has been performed.
	 */
	void ( * mic ) ( const void *kck, const void *msg, size_t len,
			 void *mic );

	/** Decrypt key data
	 *
	 * @v kek	Key Encryption Key, 16 bytes
	 * @v iv	Initialisation vector for encryption, 16 bytes
	 * @v msg	Message to decrypt (Key Data field)
	 * @v len	Length of message
	 * @ret msg	Decrypted message in place of original
	 * @ret len	Updated to reflect encrypted length
	 * @ret rc	Return status code
	 *
	 * The decrypted message is written over the encrypted one.
	 */
	int ( * decrypt ) ( const void *kek, const void *iv, void *msg,
			    u16 *len );
};

#define WPA_KIES	__table ( struct wpa_kie, "wpa_kies" )
#define __wpa_kie	__table_entry ( WPA_KIES, 01 )



/**
 * @defgroup wpa_kde Key descriptor element types
 * @{
 */

/** Payload structure of the GTK-encapsulating KDE
 *
 * This does not include the IE type, length, or OUI bytes, which are
 * generic to all KDEs.
 */
struct wpa_kde_gtk_encap
{
	/** Key ID and TX bit */
	u8 id;

	/** Reserved byte */
	u8 _rsvd;

	/** Encapsulated group transient key */
	struct wpa_gtk gtk;
} __attribute__ (( packed ));

/** Mask for Key ID in wpa_kde_gtk::id field */
#define WPA_GTK_KID	0x03

/** Mask for Tx bit in wpa_kde_gtk::id field */
#define WPA_GTK_TXBIT	0x04


/** KDE type for an encapsulated Group Transient Key (requires encryption) */
#define WPA_KDE_GTK	_MKOUI ( 0x00, 0x0F, 0xAC, 0x01 )

/** KDE type for a MAC address */
#define WPA_KDE_MAC	_MKOUI ( 0x00, 0x0F, 0xAC, 0x03 )

/** KDE type for a PMKID */
#define WPA_KDE_PMKID	_MKOUI ( 0x00, 0x0F, 0xAC, 0x04 )

/** KDE type for a nonce */
#define WPA_KDE_NONCE	_MKOUI ( 0x00, 0x0F, 0xAC, 0x06 )

/** KDE type for a lifetime value */
#define WPA_KDE_LIFETIME _MKOUI ( 0x00, 0x0F, 0xAC, 0x07 )


/** Any key descriptor element type
 *
 * KDEs follow the 802.11 information element format of a type byte
 * (in this case "vendor-specific", with the requisite OUI+subtype
 * after length) and a length byte whose value does not include the
 * length of the type and length bytes.
 */
struct wpa_kde
{
	/** Information element type: always 0xDD (IEEE80211_IE_VENDOR) */
	u8 ie_type;

	/** Length, not including ie_type and length fields */
	u8 len;

	/** OUI + type byte */
	u32 oui_type;

	/** Payload data */
	union {
		/** For GTK-type KDEs, encapsulated GTK */
		struct wpa_kde_gtk_encap gtk_encap;

		/** For MAC-type KDEs, the MAC address */
		u8 mac[ETH_ALEN];

		/** For PMKID-type KDEs, the PMKID */
		u8 pmkid[WPA_PMKID_LEN];

		/** For Nonce-type KDEs, the nonce */
		u8 nonce[WPA_NONCE_LEN];

		/** For Lifetime-type KDEs, the lifetime in seconds
		 *
		 * This is in network byte order!
		 */
		u32 lifetime;
	};
} __attribute__ (( packed ));

/** @} */

int wpa_make_rsn_ie ( struct net80211_device *dev, union ieee80211_ie **ie );
int wpa_start ( struct net80211_device *dev, struct wpa_common_ctx *ctx,
		const void *pmk, size_t pmk_len );
void wpa_stop ( struct net80211_device *dev );

#endif /* _IPXE_WPA_H */
