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
#include <ipxe/crypto.h>
#include <ipxe/hmac.h>
#include <ipxe/sha1.h>
#include <ipxe/aes.h>
#include <ipxe/wpa.h>
#include <byteswap.h>
#include <errno.h>

/** @file
 *
 * Backend for WPA using the CCMP encryption method
 */

/** Context for CCMP encryption and decryption */
struct ccmp_ctx
{
	/** AES context - only ever used for encryption */
	u8 aes_ctx[AES_CTX_SIZE];

	/** Most recently sent packet number */
	u64 tx_seq;

	/** Most recently received packet number */
	u64 rx_seq;
};

/** Header structure at the beginning of CCMP frame data */
struct ccmp_head
{
	u8 pn_lo[2];		/**< Bytes 0 and 1 of packet number */
	u8 _rsvd;		/**< Reserved byte */
	u8 kid;			/**< Key ID and ExtIV byte */
	u8 pn_hi[4];		/**< Bytes 2-5 (2 first) of packet number */
} __attribute__ (( packed ));


/** CCMP header overhead */
#define CCMP_HEAD_LEN	8

/** CCMP MIC trailer overhead */
#define CCMP_MIC_LEN	8

/** CCMP nonce length */
#define CCMP_NONCE_LEN	13

/** CCMP nonce structure */
struct ccmp_nonce
{
	u8 prio;		/**< Packet priority, 0 for non-QoS */
	u8 a2[ETH_ALEN];	/**< Address 2 from packet header (sender) */
	u8 pn[6];		/**< Packet number */
} __attribute__ (( packed ));

/** CCMP additional authentication data length (for non-QoS, non-WDS frames) */
#define CCMP_AAD_LEN	22

/** CCMP additional authentication data structure */
struct ccmp_aad
{
	u16 fc;			/**< Frame Control field */
	u8 a1[6];		/**< Address 1 */
	u8 a2[6];		/**< Address 2 */
	u8 a3[6];		/**< Address 3 */
	u16 seq;		/**< Sequence Control field */
	/* Address 4 and QoS Control are included if present */
} __attribute__ (( packed ));

/** Mask for Frame Control field in AAD */
#define CCMP_AAD_FC_MASK	0xC38F

/** Mask for Sequence Control field in AAD */
#define CCMP_AAD_SEQ_MASK	0x000F


/**
 * Convert 6-byte LSB packet number to 64-bit integer
 *
 * @v pn	Pointer to 6-byte packet number
 * @ret v	64-bit integer value of @a pn
 */
static u64 pn_to_u64 ( const u8 *pn )
{
	int i;
	u64 ret = 0;

	for ( i = 5; i >= 0; i-- ) {
		ret <<= 8;
		ret |= pn[i];
	}

	return ret;
}

/**
 * Convert 64-bit integer to 6-byte packet number
 *
 * @v v		64-bit integer
 * @v msb	If TRUE, reverse the output PN to be in MSB order
 * @ret pn	6-byte packet number
 *
 * The PN is stored in LSB order in the packet header and in MSB order
 * in the nonce. WHYYYYY?
 */
static void u64_to_pn ( u64 v, u8 *pn, int msb )
{
	int i;
	u8 *pnp = pn + ( msb ? 5 : 0 );
	int delta = ( msb ? -1 : +1 );

	for ( i = 0; i < 6; i++ ) {
		*pnp = v & 0xFF;
		pnp += delta;
		v >>= 8;
	}
}

/** Value for @a msb argument of u64_to_pn() for MSB output */
#define PN_MSB	1

/** Value for @a msb argument of u64_to_pn() for LSB output */
#define PN_LSB	0



/**
 * Initialise CCMP state and install key
 *
 * @v crypto	CCMP cryptosystem structure
 * @v key	Pointer to 16-byte temporal key to install
 * @v keylen	Length of key (16 bytes)
 * @v rsc	Initial receive sequence counter
 */
static int ccmp_init ( struct net80211_crypto *crypto, const void *key,
		       int keylen, const void *rsc )
{
	struct ccmp_ctx *ctx = crypto->priv;

	if ( keylen != 16 )
		return -EINVAL;

	if ( rsc )
		ctx->rx_seq = pn_to_u64 ( rsc );

	cipher_setkey ( &aes_algorithm, ctx->aes_ctx, key, keylen );

	return 0;
}


/**
 * Encrypt or decrypt data stream using AES in Counter mode
 *
 * @v ctx	CCMP cryptosystem context
 * @v nonce	Nonce value, 13 bytes
 * @v srcv	Data to encrypt or decrypt
 * @v len	Number of bytes pointed to by @a src
 * @v msrcv	MIC value to encrypt or decrypt (may be NULL)
 * @ret destv	Encrypted or decrypted data
 * @ret mdestv	Encrypted or decrypted MIC value
 *
 * This assumes CCMP parameters of L=2 and M=8. The algorithm is
 * defined in RFC 3610.
 */
static void ccmp_ctr_xor ( struct ccmp_ctx *ctx, const void *nonce,
			   const void *srcv, void *destv, int len,
			   const void *msrcv, void *mdestv )
{
	u8 A[16], S[16];
	u16 ctr;
	int i;
	const u8 *src = srcv, *msrc = msrcv;
	u8 *dest = destv, *mdest = mdestv;

	A[0] = 0x01;		/* flags, L' = L - 1 = 1, other bits rsvd */
	memcpy ( A + 1, nonce, CCMP_NONCE_LEN );

	if ( msrcv ) {
		A[14] = A[15] = 0;

		cipher_encrypt ( &aes_algorithm, ctx->aes_ctx, A, S, 16 );

		for ( i = 0; i < 8; i++ ) {
			*mdest++ = *msrc++ ^ S[i];
		}
	}

	for ( ctr = 1 ;; ctr++ ) {
		A[14] = ctr >> 8;
		A[15] = ctr & 0xFF;

		cipher_encrypt ( &aes_algorithm, ctx->aes_ctx, A, S, 16 );

		for ( i = 0; i < len && i < 16; i++ )
			*dest++ = *src++ ^ S[i];

		if ( len <= 16 )
			break;	/* we're done */

		len -= 16;
	}
}


/**
 * Advance one block in CBC-MAC calculation
 *
 * @v aes_ctx	AES encryption context with key set
 * @v B		Cleartext block to incorporate (16 bytes)
 * @v X		Previous ciphertext block (16 bytes)
 * @ret B	Clobbered
 * @ret X	New ciphertext block (16 bytes)
 *
 * This function does X := E[key] ( X ^ B ).
 */
static void ccmp_feed_cbc_mac ( void *aes_ctx, u8 *B, u8 *X )
{
	int i;
	for ( i = 0; i < 16; i++ )
		B[i] ^= X[i];
	cipher_encrypt ( &aes_algorithm, aes_ctx, B, X, 16 );
}


/**
 * Calculate MIC on plaintext data using CBC-MAC
 *
 * @v ctx	CCMP cryptosystem context
 * @v nonce	Nonce value, 13 bytes
 * @v data	Data to calculate MIC over
 * @v datalen	Length of @a data
 * @v aad	Additional authentication data, for MIC but not encryption
 * @ret mic	MIC value (unencrypted), 8 bytes
 *
 * @a aadlen is assumed to be 22 bytes long, as it always is for
 * 802.11 use when transmitting non-QoS, not-between-APs frames (the
 * only type we deal with).
 */
static void ccmp_cbc_mac ( struct ccmp_ctx *ctx, const void *nonce,
			   const void *data, u16 datalen,
			   const void *aad, void *mic )
{
	u8 X[16], B[16];

	/* Zeroth block: flags, nonce, length */

	/* Rsv AAD - M'-  - L'-
	 *  0   1  0 1 1  0 0 1   for an 8-byte MAC and 2-byte message length
	 */
	B[0] = 0x59;
	memcpy ( B + 1, nonce, CCMP_NONCE_LEN );
	B[14] = datalen >> 8;
	B[15] = datalen & 0xFF;

	cipher_encrypt ( &aes_algorithm, ctx->aes_ctx, B, X, 16 );

	/* First block: AAD length field and 14 bytes of AAD */
	B[0] = 0;
	B[1] = CCMP_AAD_LEN;
	memcpy ( B + 2, aad, 14 );

	ccmp_feed_cbc_mac ( ctx->aes_ctx, B, X );

	/* Second block: Remaining 8 bytes of AAD, 8 bytes zero pad */
	memcpy ( B, aad + 14, 8 );
	memset ( B + 8, 0, 8 );

	ccmp_feed_cbc_mac ( ctx->aes_ctx, B, X );

	/* Message blocks */
	while ( datalen ) {
		if ( datalen >= 16 ) {
			memcpy ( B, data, 16 );
			datalen -= 16;
		} else {
			memcpy ( B, data, datalen );
			memset ( B + datalen, 0, 16 - datalen );
			datalen = 0;
		}

		ccmp_feed_cbc_mac ( ctx->aes_ctx, B, X );

		data += 16;
	}

	/* Get MIC from final value of X */
	memcpy ( mic, X, 8 );
}


/**
 * Encapsulate and encrypt a packet using CCMP
 *
 * @v crypto	CCMP cryptosystem
 * @v iob	I/O buffer containing cleartext packet
 * @ret eiob	I/O buffer containing encrypted packet
 */
struct io_buffer * ccmp_encrypt ( struct net80211_crypto *crypto,
				  struct io_buffer *iob )
{
	struct ccmp_ctx *ctx = crypto->priv;
	struct ieee80211_frame *hdr = iob->data;
	struct io_buffer *eiob;
	const int hdrlen = IEEE80211_TYP_FRAME_HEADER_LEN;
	int datalen = iob_len ( iob ) - hdrlen;
	struct ccmp_head head;
	struct ccmp_nonce nonce;
	struct ccmp_aad aad;
	u8 mic[8], tx_pn[6];
	void *edata, *emic;

	ctx->tx_seq++;
	u64_to_pn ( ctx->tx_seq, tx_pn, PN_LSB );

	/* Allocate memory */
	eiob = alloc_iob ( iob_len ( iob ) + CCMP_HEAD_LEN + CCMP_MIC_LEN );
	if ( ! eiob )
		return NULL;

	/* Copy frame header */
	memcpy ( iob_put ( eiob, hdrlen ), iob->data, hdrlen );
	hdr = eiob->data;
	hdr->fc |= IEEE80211_FC_PROTECTED;

	/* Fill in packet number and extended IV */
	memcpy ( head.pn_lo, tx_pn, 2 );
	memcpy ( head.pn_hi, tx_pn + 2, 4 );
	head.kid = 0x20;	/* have Extended IV, key ID 0 */
	head._rsvd = 0;
	memcpy ( iob_put ( eiob, sizeof ( head ) ), &head, sizeof ( head ) );

	/* Form nonce */
	nonce.prio = 0;
	memcpy ( nonce.a2, hdr->addr2, ETH_ALEN );
	u64_to_pn ( ctx->tx_seq, nonce.pn, PN_MSB );

	/* Form additional authentication data */
	aad.fc = hdr->fc & CCMP_AAD_FC_MASK;
	memcpy ( aad.a1, hdr->addr1, 3 * ETH_ALEN ); /* all 3 at once */
	aad.seq = hdr->seq & CCMP_AAD_SEQ_MASK;

	/* Calculate MIC over the data */
	ccmp_cbc_mac ( ctx, &nonce, iob->data + hdrlen, datalen, &aad, mic );

	/* Copy and encrypt data and MIC */
	edata = iob_put ( eiob, datalen );
	emic = iob_put ( eiob, CCMP_MIC_LEN );
	ccmp_ctr_xor ( ctx, &nonce,
		       iob->data + hdrlen, edata, datalen,
		       mic, emic );

	/* Done! */
	DBGC2 ( ctx, "WPA-CCMP %p: encrypted packet %p -> %p\n", ctx,
		iob, eiob );

	return eiob;
}

/**
 * Decrypt a packet using CCMP
 *
 * @v crypto	CCMP cryptosystem
 * @v eiob	I/O buffer containing encrypted packet
 * @ret iob	I/O buffer containing cleartext packet
 */
static struct io_buffer * ccmp_decrypt ( struct net80211_crypto *crypto,
					 struct io_buffer *eiob )
{
	struct ccmp_ctx *ctx = crypto->priv;
	struct ieee80211_frame *hdr;
	struct io_buffer *iob;
	const int hdrlen = IEEE80211_TYP_FRAME_HEADER_LEN;
	int datalen = iob_len ( eiob ) - hdrlen - CCMP_HEAD_LEN - CCMP_MIC_LEN;
	struct ccmp_head *head;
	struct ccmp_nonce nonce;
	struct ccmp_aad aad;
	u8 rx_pn[6], their_mic[8], our_mic[8];

	iob = alloc_iob ( hdrlen + datalen );
	if ( ! iob )
		return NULL;

	/* Copy frame header */
	memcpy ( iob_put ( iob, hdrlen ), eiob->data, hdrlen );
	hdr = iob->data;
	hdr->fc &= ~IEEE80211_FC_PROTECTED;

	/* Check and update RX packet number */
	head = eiob->data + hdrlen;
	memcpy ( rx_pn, head->pn_lo, 2 );
	memcpy ( rx_pn + 2, head->pn_hi, 4 );

	if ( pn_to_u64 ( rx_pn ) <= ctx->rx_seq ) {
		DBGC ( ctx, "WPA-CCMP %p: packet received out of order "
		       "(%012llx <= %012llx)\n", ctx, pn_to_u64 ( rx_pn ),
		       ctx->rx_seq );
		free_iob ( iob );
		return NULL;
	}

	ctx->rx_seq = pn_to_u64 ( rx_pn );
	DBGC2 ( ctx, "WPA-CCMP %p: RX packet number %012llx\n", ctx, ctx->rx_seq );

	/* Form nonce */
	nonce.prio = 0;
	memcpy ( nonce.a2, hdr->addr2, ETH_ALEN );
	u64_to_pn ( ctx->rx_seq, nonce.pn, PN_MSB );

	/* Form additional authentication data */
	aad.fc = ( hdr->fc & CCMP_AAD_FC_MASK ) | IEEE80211_FC_PROTECTED;
	memcpy ( aad.a1, hdr->addr1, 3 * ETH_ALEN ); /* all 3 at once */
	aad.seq = hdr->seq & CCMP_AAD_SEQ_MASK;

	/* Copy-decrypt data and MIC */
	ccmp_ctr_xor ( ctx, &nonce, eiob->data + hdrlen + sizeof ( *head ),
		       iob_put ( iob, datalen ), datalen,
		       eiob->tail - CCMP_MIC_LEN, their_mic );

	/* Check MIC */
	ccmp_cbc_mac ( ctx, &nonce, iob->data + hdrlen, datalen, &aad,
		       our_mic );

	if ( memcmp ( their_mic, our_mic, CCMP_MIC_LEN ) != 0 ) {
		DBGC2 ( ctx, "WPA-CCMP %p: MIC failure\n", ctx );
		free_iob ( iob );
		return NULL;
	}

	DBGC2 ( ctx, "WPA-CCMP %p: decrypted packet %p -> %p\n", ctx,
		eiob, iob );

	return iob;
}


/** CCMP cryptosystem */
struct net80211_crypto ccmp_crypto __net80211_crypto = {
	.algorithm = NET80211_CRYPT_CCMP,
	.init = ccmp_init,
	.encrypt = ccmp_encrypt,
	.decrypt = ccmp_decrypt,
	.priv_len = sizeof ( struct ccmp_ctx ),
};




/**
 * Calculate HMAC-SHA1 MIC for EAPOL-Key frame
 *
 * @v kck	Key Confirmation Key, 16 bytes
 * @v msg	Message to calculate MIC over
 * @v len	Number of bytes to calculate MIC over
 * @ret mic	Calculated MIC, 16 bytes long
 */
static void ccmp_kie_mic ( const void *kck, const void *msg, size_t len,
			   void *mic )
{
	u8 sha1_ctx[SHA1_CTX_SIZE];
	u8 kckb[16];
	u8 hash[SHA1_DIGEST_SIZE];
	size_t kck_len = 16;

	memcpy ( kckb, kck, kck_len );

	hmac_init ( &sha1_algorithm, sha1_ctx, kckb, &kck_len );
	hmac_update ( &sha1_algorithm, sha1_ctx, msg, len );
	hmac_final ( &sha1_algorithm, sha1_ctx, kckb, &kck_len, hash );

	memcpy ( mic, hash, 16 );
}

/**
 * Decrypt key data in EAPOL-Key frame
 *
 * @v kek	Key Encryption Key, 16 bytes
 * @v iv	Initialisation vector, 16 bytes (unused)
 * @v msg	Message to decrypt
 * @v len	Length of message
 * @ret msg	Decrypted message in place of original
 * @ret len	Adjusted downward for 8 bytes of overhead
 * @ret rc	Return status code
 *
 * The returned message may still contain padding of 0xDD followed by
 * zero or more 0x00 octets. It is impossible to remove the padding
 * without parsing the IEs in the packet (another design decision that
 * tends to make one question the 802.11i committee's intelligence...)
 */
static int ccmp_kie_decrypt ( const void *kek, const void *iv __unused,
			      void *msg, u16 *len )
{
	if ( *len % 8 != 0 )
		return -EINVAL;

	if ( aes_unwrap ( kek, msg, msg, *len / 8 - 1 ) != 0 )
		return -EINVAL;

	*len -= 8;

	return 0;
}

/** CCMP-style key integrity and encryption handler */
struct wpa_kie ccmp_kie __wpa_kie = {
	.version = EAPOL_KEY_VERSION_WPA2,
	.mic = ccmp_kie_mic,
	.decrypt = ccmp_kie_decrypt,
};
