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
#include <ipxe/crypto.h>
#include <ipxe/arc4.h>
#include <ipxe/crc32.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/** @file
 *
 * The WEP wireless encryption method (insecure!)
 *
 * The data field in a WEP-encrypted packet contains a 3-byte
 * initialisation vector, one-byte Key ID field (only the bottom two
 * bits are ever used), encrypted data, and a 4-byte encrypted CRC of
 * the plaintext data, called the ICV. To decrypt it, the IV is
 * prepended to the shared key and the data stream (including ICV) is
 * run through the ARC4 stream cipher; if the ICV matches a CRC32
 * calculated on the plaintext, the packet is valid.
 *
 * For efficiency and code-size reasons, this file assumes it is
 * running on a little-endian machine.
 */

/** Length of WEP initialisation vector */
#define WEP_IV_LEN	3

/** Length of WEP key ID byte */
#define WEP_KID_LEN	1

/** Length of WEP ICV checksum */
#define WEP_ICV_LEN	4

/** Maximum length of WEP key */
#define WEP_MAX_KEY	16

/** Amount of data placed before the encrypted bytes */
#define WEP_HEADER_LEN	4

/** Amount of data placed after the encrypted bytes */
#define WEP_TRAILER_LEN	4

/** Total WEP overhead bytes */
#define WEP_OVERHEAD	8

/** Context for WEP encryption and decryption */
struct wep_ctx
{
	/** Encoded WEP key
	 *
	 * The actual key bytes are stored beginning at offset 3, to
	 * leave room for easily inserting the IV before a particular
	 * operation.
	 */
	u8 key[WEP_IV_LEN + WEP_MAX_KEY];

	/** Length of WEP key (not including IV bytes) */
	int keylen;

	/** ARC4 context */
	struct arc4_ctx arc4;
};

/**
 * Initialize WEP algorithm
 *
 * @v crypto	802.11 cryptographic algorithm
 * @v key	WEP key to use
 * @v keylen	Length of WEP key
 * @v rsc	Initial receive sequence counter (unused)
 * @ret rc	Return status code
 *
 * Standard key lengths are 5 and 13 bytes; 16-byte keys are
 * occasionally supported as an extension to the standard.
 */
static int wep_init ( struct net80211_crypto *crypto, const void *key,
		      int keylen, const void *rsc __unused )
{
	struct wep_ctx *ctx = crypto->priv;

	ctx->keylen = ( keylen > WEP_MAX_KEY ? WEP_MAX_KEY : keylen );
	memcpy ( ctx->key + WEP_IV_LEN, key, ctx->keylen );

	return 0;
}

/**
 * Encrypt packet using WEP
 *
 * @v crypto	802.11 cryptographic algorithm
 * @v iob	I/O buffer of plaintext packet
 * @ret eiob	Newly allocated I/O buffer for encrypted packet, or NULL
 *
 * If memory allocation fails, @c NULL is returned.
 */
static struct io_buffer * wep_encrypt ( struct net80211_crypto *crypto,
					struct io_buffer *iob )
{
	struct wep_ctx *ctx = crypto->priv;
	struct io_buffer *eiob;
	struct ieee80211_frame *hdr;
	const int hdrlen = IEEE80211_TYP_FRAME_HEADER_LEN;
	int datalen = iob_len ( iob ) - hdrlen;
	int newlen = hdrlen + datalen + WEP_OVERHEAD;
	u32 iv, icv;

	eiob = alloc_iob ( newlen );
	if ( ! eiob )
		return NULL;

	memcpy ( iob_put ( eiob, hdrlen ), iob->data, hdrlen );
	hdr = eiob->data;
	hdr->fc |= IEEE80211_FC_PROTECTED;

	/* Calculate IV, put it in the header (with key ID byte = 0), and
	   set it up at the start of the encryption key. */
	iv = random() & 0xffffff; /* IV in bottom 3 bytes, top byte = KID = 0 */
	memcpy ( iob_put ( eiob, WEP_HEADER_LEN ), &iv, WEP_HEADER_LEN );
	memcpy ( ctx->key, &iv, WEP_IV_LEN );

	/* Encrypt the data using RC4 */
	cipher_setkey ( &arc4_algorithm, &ctx->arc4, ctx->key,
			ctx->keylen + WEP_IV_LEN );
	cipher_encrypt ( &arc4_algorithm, &ctx->arc4, iob->data + hdrlen,
			 iob_put ( eiob, datalen ), datalen );

	/* Add ICV */
	icv = ~crc32_le ( ~0, iob->data + hdrlen, datalen );
	cipher_encrypt ( &arc4_algorithm, &ctx->arc4, &icv,
			 iob_put ( eiob, WEP_ICV_LEN ), WEP_ICV_LEN );

	return eiob;
}

/**
 * Decrypt packet using WEP
 *
 * @v crypto	802.11 cryptographic algorithm
 * @v eiob	I/O buffer of encrypted packet
 * @ret iob	Newly allocated I/O buffer for plaintext packet, or NULL
 *
 * If a consistency check for the decryption fails (usually indicating
 * an invalid key), @c NULL is returned.
 */
static struct io_buffer * wep_decrypt ( struct net80211_crypto *crypto,
					struct io_buffer *eiob )
{
	struct wep_ctx *ctx = crypto->priv;
	struct io_buffer *iob;
	struct ieee80211_frame *hdr;
	const int hdrlen = IEEE80211_TYP_FRAME_HEADER_LEN;
	int datalen = iob_len ( eiob ) - hdrlen - WEP_OVERHEAD;
	int newlen = hdrlen + datalen;
	u32 iv, icv, crc;

	iob = alloc_iob ( newlen );
	if ( ! iob )
		return NULL;

	memcpy ( iob_put ( iob, hdrlen ), eiob->data, hdrlen );
	hdr = iob->data;
	hdr->fc &= ~IEEE80211_FC_PROTECTED;

	/* Strip off IV and use it to initialize cryptosystem */
	memcpy ( &iv, eiob->data + hdrlen, 4 );
	iv &= 0xffffff;		/* ignore key ID byte */
	memcpy ( ctx->key, &iv, WEP_IV_LEN );

	/* Decrypt the data using RC4 */
	cipher_setkey ( &arc4_algorithm, &ctx->arc4, ctx->key,
			ctx->keylen + WEP_IV_LEN );
	cipher_decrypt ( &arc4_algorithm, &ctx->arc4, eiob->data + hdrlen +
			 WEP_HEADER_LEN, iob_put ( iob, datalen ), datalen );

	/* Strip off ICV and verify it */
	cipher_decrypt ( &arc4_algorithm, &ctx->arc4, eiob->data + hdrlen +
			 WEP_HEADER_LEN + datalen, &icv, WEP_ICV_LEN );
	crc = ~crc32_le ( ~0, iob->data + hdrlen, datalen );
	if ( crc != icv ) {
		DBGC ( crypto, "WEP %p CRC mismatch: expect %08x, get %08x\n",
		       crypto, icv, crc );
		free_iob ( iob );
		return NULL;
	}
	return iob;
}

/** WEP cryptosystem for 802.11 */
struct net80211_crypto wep_crypto __net80211_crypto = {
	.algorithm = NET80211_CRYPT_WEP,
	.init = wep_init,
	.encrypt = wep_encrypt,
	.decrypt = wep_decrypt,
	.priv_len = sizeof ( struct wep_ctx ),
};

/**
 * Initialize trivial 802.11 security handshaker
 *
 * @v dev	802.11 device
 * @v ctx	Security handshaker
 *
 * This simply fetches a WEP key from netX/key, and if it exists,
 * installs WEP cryptography on the 802.11 device. No real handshaking
 * is performed.
 */
static int trivial_init ( struct net80211_device *dev )
{
	u8 key[WEP_MAX_KEY];	/* support up to 128-bit keys */
	int len;
	int rc;

	if ( dev->associating &&
	     dev->associating->crypto == NET80211_CRYPT_NONE )
		return 0;	/* no crypto? OK. */

	len = fetch_raw_setting ( netdev_settings ( dev->netdev ),
				  &net80211_key_setting, key, WEP_MAX_KEY );

	if ( len <= 0 ) {
		DBGC ( dev, "802.11 %p cannot do WEP without a key\n", dev );
		return -EACCES;
	}

	/* Full 128-bit keys are a nonstandard extension, but they're
	   utterly trivial to support, so we do. */
	if ( len != 5 && len != 13 && len != 16 ) {
		DBGC ( dev, "802.11 %p invalid WEP key length %d\n",
		       dev, len );
		return -EINVAL;
	}

	DBGC ( dev, "802.11 %p installing %d-bit WEP\n", dev, len * 8 );

	rc = sec80211_install ( &dev->crypto, NET80211_CRYPT_WEP, key, len,
				NULL );
	if ( rc < 0 )
		return rc;

	return 0;
}

/**
 * Check for key change on trivial 802.11 security handshaker
 *
 * @v dev	802.11 device
 * @v ctx	Security handshaker
 */
static int trivial_change_key ( struct net80211_device *dev )
{
	u8 key[WEP_MAX_KEY];
	int len;
	int change = 0;

	/* If going from WEP to clear, or something else to WEP, reassociate. */
	if ( ! dev->crypto || ( dev->crypto->init != wep_init ) )
		change ^= 1;

	len = fetch_raw_setting ( netdev_settings ( dev->netdev ),
				  &net80211_key_setting, key, WEP_MAX_KEY );
	if ( len <= 0 )
		change ^= 1;

	/* Changing crypto type => return nonzero to reassociate. */
	if ( change )
		return -EINVAL;

	/* Going from no crypto to still no crypto => nothing to do. */
	if ( len <= 0 )
		return 0;

	/* Otherwise, reinitialise WEP with new key. */
	return wep_init ( dev->crypto, key, len, NULL );
}

/** Trivial 802.11 security handshaker */
struct net80211_handshaker trivial_handshaker __net80211_handshaker = {
	.protocol = NET80211_SECPROT_NONE,
	.init = trivial_init,
	.change_key = trivial_change_key,
	.priv_len = 0,
};
