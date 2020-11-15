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
#include <ipxe/md5.h>
#include <ipxe/crc32.h>
#include <ipxe/arc4.h>
#include <ipxe/wpa.h>
#include <byteswap.h>
#include <errno.h>

/** @file
 *
 * Backend for WPA using the TKIP encryption standard.
 */

/** Context for one direction of TKIP, either encryption or decryption */
struct tkip_dir_ctx
{
	/** High 32 bits of last sequence counter value used */
	u32 tsc_hi;

	/** Low 32 bits of last sequence counter value used */
	u16 tsc_lo;

	/** MAC address used to derive TTAK */
	u8 mac[ETH_ALEN];

	/** If TRUE, TTAK is valid */
	u16 ttak_ok;

	/** TKIP-mixed transmit address and key, depends on tsc_hi and MAC */
	u16 ttak[5];
};

/** Context for TKIP encryption and decryption */
struct tkip_ctx
{
	/** Temporal key to use */
	struct tkip_tk tk;

	/** State for encryption */
	struct tkip_dir_ctx enc;

	/** State for decryption */
	struct tkip_dir_ctx dec;
};

/** Header structure at the beginning of TKIP frame data */
struct tkip_head
{
	u8 tsc1;		/**< High byte of low 16 bits of TSC */
	u8 seed1;		/**< Second byte of WEP seed */
	u8 tsc0;		/**< Low byte of TSC */
	u8 kid;			/**< Key ID and ExtIV byte */
	u32 tsc_hi;		/**< High 32 bits of TSC, as an ExtIV */
} __attribute__ (( packed ));


/** TKIP header overhead (IV + KID + ExtIV) */
#define TKIP_HEAD_LEN	8

/** TKIP trailer overhead (MIC + ICV) [assumes unfragmented] */
#define TKIP_FOOT_LEN	12

/** TKIP MIC length */
#define TKIP_MIC_LEN	8

/** TKIP ICV length */
#define TKIP_ICV_LEN	4


/** TKIP S-box */
static const u16 Sbox[256] = {
	0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
	0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
	0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
	0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
	0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
	0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
	0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
	0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
	0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
	0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
	0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
	0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
	0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
	0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
	0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
	0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
	0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
	0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
	0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
	0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
	0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
	0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
	0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
	0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
	0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
	0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
	0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
	0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
	0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
	0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
	0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
	0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
};

/**
 * Perform S-box mapping on a 16-bit value
 *
 * @v v		Value to perform S-box mapping on
 * @ret Sv	S-box mapped value
 */
static inline u16 S ( u16 v )
{
	return Sbox[v & 0xFF] ^ bswap_16 ( Sbox[v >> 8] );
}

/**
 * Rotate 16-bit value right
 *
 * @v v		Value to rotate
 * @v bits	Number of bits to rotate by
 * @ret rotv	Rotated value
 */
static inline u16 ror16 ( u16 v, int bits )
{
	return ( v >> bits ) | ( v << ( 16 - bits ) );
}

/**
 * Rotate 32-bit value right
 *
 * @v v		Value to rotate
 * @v bits	Number of bits to rotate by
 * @ret rotv	Rotated value
 */
static inline u32 ror32 ( u32 v, int bits )
{
	return ( v >> bits ) | ( v << ( 32 - bits ) );
}

/**
 * Rotate 32-bit value left
 *
 * @v v		Value to rotate
 * @v bits	Number of bits to rotate by
 * @ret rotv	Rotated value
 */
static inline u32 rol32 ( u32 v, int bits )
{
	return ( v << bits ) | ( v >> ( 32 - bits ) );
}


/**
 * Initialise TKIP state and install key
 *
 * @v crypto	TKIP cryptosystem structure
 * @v key	Pointer to tkip_tk to install
 * @v keylen	Length of key (32 bytes)
 * @v rsc	Initial receive sequence counter
 */
static int tkip_init ( struct net80211_crypto *crypto, const void *key,
		       int keylen, const void *rsc )
{
	struct tkip_ctx *ctx = crypto->priv;
	const u8 *rscb = rsc;

	if ( keylen != sizeof ( ctx->tk ) )
		return -EINVAL;

	if ( rscb ) {
		ctx->dec.tsc_lo =   ( rscb[1] <<  8 ) |   rscb[0];
		ctx->dec.tsc_hi = ( ( rscb[5] << 24 ) | ( rscb[4] << 16 ) |
				    ( rscb[3] <<  8 ) |   rscb[2] );
	}

	memcpy ( &ctx->tk, key, sizeof ( ctx->tk ) );

	return 0;
}

/**
 * Perform TKIP key mixing, phase 1
 *
 * @v dctx	TKIP directional context
 * @v tk	TKIP temporal key
 * @v mac	MAC address of transmitter
 *
 * This recomputes the TTAK in @a dctx if necessary, and sets
 * @c dctx->ttak_ok.
 */
static void tkip_mix_1 ( struct tkip_dir_ctx *dctx, struct tkip_tk *tk, u8 *mac )
{
	int i, j;

	if ( dctx->ttak_ok && ! memcmp ( mac, dctx->mac, ETH_ALEN ) )
		return;

	memcpy ( dctx->mac, mac, ETH_ALEN );

	dctx->ttak[0] = dctx->tsc_hi & 0xFFFF;
	dctx->ttak[1] = dctx->tsc_hi >> 16;
	dctx->ttak[2] = ( mac[1] << 8 ) | mac[0];
	dctx->ttak[3] = ( mac[3] << 8 ) | mac[2];
	dctx->ttak[4] = ( mac[5] << 8 ) | mac[4];

	for ( i = 0; i < 8; i++ ) {
		j = 2 * ( i & 1 );

		dctx->ttak[0] += S ( dctx->ttak[4] ^ ( ( tk->key[1 + j] << 8 ) |
						         tk->key[0 + j] ) );
		dctx->ttak[1] += S ( dctx->ttak[0] ^ ( ( tk->key[5 + j] << 8 ) |
						         tk->key[4 + j] ) );
		dctx->ttak[2] += S ( dctx->ttak[1] ^ ( ( tk->key[9 + j] << 8 ) |
						         tk->key[8 + j] ) );
		dctx->ttak[3] += S ( dctx->ttak[2] ^ ( ( tk->key[13+ j] << 8 ) |
						         tk->key[12+ j] ) );
		dctx->ttak[4] += S ( dctx->ttak[3] ^ ( ( tk->key[1 + j] << 8 ) |
						         tk->key[0 + j] ) ) + i;
	}

	dctx->ttak_ok = 1;
}

/**
 * Perform TKIP key mixing, phase 2
 *
 * @v dctx	TKIP directional context
 * @v tk	TKIP temporal key
 * @ret key	ARC4 key, 16 bytes long
 */
static void tkip_mix_2 ( struct tkip_dir_ctx *dctx, struct tkip_tk *tk,
			 void *key )
{
	u8 *kb = key;
	u16 ppk[6];
	int i;

	memcpy ( ppk, dctx->ttak, sizeof ( dctx->ttak ) );
	ppk[5] = dctx->ttak[4] + dctx->tsc_lo;

	ppk[0] += S ( ppk[5] ^ ( ( tk->key[1] << 8 ) | tk->key[0] ) );
	ppk[1] += S ( ppk[0] ^ ( ( tk->key[3] << 8 ) | tk->key[2] ) );
	ppk[2] += S ( ppk[1] ^ ( ( tk->key[5] << 8 ) | tk->key[4] ) );
	ppk[3] += S ( ppk[2] ^ ( ( tk->key[7] << 8 ) | tk->key[6] ) );
	ppk[4] += S ( ppk[3] ^ ( ( tk->key[9] << 8 ) | tk->key[8] ) );
	ppk[5] += S ( ppk[4] ^ ( ( tk->key[11] << 8 ) | tk->key[10] ) );

	ppk[0] += ror16 ( ppk[5] ^ ( ( tk->key[13] << 8 ) | tk->key[12] ), 1 );
	ppk[1] += ror16 ( ppk[0] ^ ( ( tk->key[15] << 8 ) | tk->key[14] ), 1 );
	ppk[2] += ror16 ( ppk[1], 1 );
	ppk[3] += ror16 ( ppk[2], 1 );
	ppk[4] += ror16 ( ppk[3], 1 );
	ppk[5] += ror16 ( ppk[4], 1 );

	kb[0] = dctx->tsc_lo >> 8;
	kb[1] = ( ( dctx->tsc_lo >> 8 ) | 0x20 ) & 0x7F;
	kb[2] = dctx->tsc_lo & 0xFF;
	kb[3] = ( ( ppk[5] ^ ( ( tk->key[1] << 8 ) | tk->key[0] ) ) >> 1 )
		& 0xFF;

	for ( i = 0; i < 6; i++ ) {
		kb[4 + 2*i] = ppk[i] & 0xFF;
		kb[5 + 2*i] = ppk[i] >> 8;
	}
}

/**
 * Update Michael message integrity code based on next 32-bit word of data
 *
 * @v V		Michael code state (two 32-bit words)
 * @v word	Next 32-bit word of data
 */
static void tkip_feed_michael ( u32 *V, u32 word )
{
	V[0] ^= word;
	V[1] ^= rol32 ( V[0], 17 );
	V[0] += V[1];
	V[1] ^= ( ( V[0] & 0xFF00FF00 ) >> 8 ) | ( ( V[0] & 0x00FF00FF ) << 8 );
	V[0] += V[1];
	V[1] ^= rol32 ( V[0], 3 );
	V[0] += V[1];
	V[1] ^= ror32 ( V[0], 2 );
	V[0] += V[1];
}

/**
 * Calculate Michael message integrity code
 *
 * @v key	MIC key to use (8 bytes)
 * @v da	Destination link-layer address
 * @v sa	Source link-layer address
 * @v data	Start of data to calculate over
 * @v len	Length of header + data
 * @ret mic	Calculated Michael MIC (8 bytes)
 */
static void tkip_michael ( const void *key, const void *da, const void *sa,
			   const void *data, size_t len, void *mic )
{
	u32 V[2];		/* V[0] = "l", V[1] = "r" in 802.11 */
	union {
		u8 byte[12];
		u32 word[3];
	} cap;
	const u8 *ptr = data;
	const u8 *end = ptr + len;
	int i;

	memcpy ( V, key, sizeof ( V ) );
	V[0] = le32_to_cpu ( V[0] );
	V[1] = le32_to_cpu ( V[1] );

	/* Feed in header (we assume non-QoS, so Priority = 0) */
	memcpy ( &cap.byte[0], da, ETH_ALEN );
	memcpy ( &cap.byte[6], sa, ETH_ALEN );
	tkip_feed_michael ( V, le32_to_cpu ( cap.word[0] ) );
	tkip_feed_michael ( V, le32_to_cpu ( cap.word[1] ) );
	tkip_feed_michael ( V, le32_to_cpu ( cap.word[2] ) );
	tkip_feed_michael ( V, 0 );

	/* Feed in data */
	while ( ptr + 4 <= end ) {
		tkip_feed_michael ( V, le32_to_cpu ( *( u32 * ) ptr ) );
		ptr += 4;
	}

	/* Add unaligned part and padding */
	for ( i = 0; ptr < end; i++ )
		cap.byte[i] = *ptr++;
	cap.byte[i++] = 0x5a;
	for ( ; i < 8; i++ )
		cap.byte[i] = 0;

	/* Feed in padding */
	tkip_feed_michael ( V, le32_to_cpu ( cap.word[0] ) );
	tkip_feed_michael ( V, le32_to_cpu ( cap.word[1] ) );

	/* Output MIC */
	V[0] = cpu_to_le32 ( V[0] );
	V[1] = cpu_to_le32 ( V[1] );
	memcpy ( mic, V, sizeof ( V ) );
}

/**
 * Encrypt a packet using TKIP
 *
 * @v crypto	TKIP cryptosystem
 * @v iob	I/O buffer containing cleartext packet
 * @ret eiob	I/O buffer containing encrypted packet
 */
static struct io_buffer * tkip_encrypt ( struct net80211_crypto *crypto,
					 struct io_buffer *iob )
{
	struct tkip_ctx *ctx = crypto->priv;
	struct ieee80211_frame *hdr = iob->data;
	struct io_buffer *eiob;
	struct arc4_ctx arc4;
	u8 key[16];
	struct tkip_head head;
	u8 mic[8];
	u32 icv;
	const int hdrlen = IEEE80211_TYP_FRAME_HEADER_LEN;
	int datalen = iob_len ( iob ) - hdrlen;

	ctx->enc.tsc_lo++;
	if ( ctx->enc.tsc_lo == 0 ) {
		ctx->enc.tsc_hi++;
		ctx->enc.ttak_ok = 0;
	}

	tkip_mix_1 ( &ctx->enc, &ctx->tk, hdr->addr2 );
	tkip_mix_2 ( &ctx->enc, &ctx->tk, key );

	eiob = alloc_iob ( iob_len ( iob ) + TKIP_HEAD_LEN + TKIP_FOOT_LEN );
	if ( ! eiob )
		return NULL;

	/* Copy frame header */
	memcpy ( iob_put ( eiob, hdrlen ), iob->data, hdrlen );
	hdr = eiob->data;
	hdr->fc |= IEEE80211_FC_PROTECTED;

	/* Fill in IV and key ID byte, and extended IV */
	memcpy ( &head, key, 3 );
	head.kid = 0x20;		/* have Extended IV, key ID 0 */
	head.tsc_hi = cpu_to_le32 ( ctx->enc.tsc_hi );
	memcpy ( iob_put ( eiob, sizeof ( head ) ), &head, sizeof ( head ) );

	/* Copy and encrypt the data */
	cipher_setkey ( &arc4_algorithm, &arc4, key, 16 );
	cipher_encrypt ( &arc4_algorithm, &arc4, iob->data + hdrlen,
			 iob_put ( eiob, datalen ), datalen );

	/* Add MIC */
	hdr = iob->data;
	tkip_michael ( &ctx->tk.mic.tx, hdr->addr3, hdr->addr2,
		       iob->data + hdrlen, datalen, mic );
	cipher_encrypt ( &arc4_algorithm, &arc4, mic,
			 iob_put ( eiob, sizeof ( mic ) ), sizeof ( mic ) );

	/* Add ICV */
	icv = crc32_le ( ~0, iob->data + hdrlen, datalen );
	icv = crc32_le ( icv, mic, sizeof ( mic ) );
	icv = cpu_to_le32 ( ~icv );
	cipher_encrypt ( &arc4_algorithm, &arc4, &icv,
			 iob_put ( eiob, TKIP_ICV_LEN ), TKIP_ICV_LEN );

	DBGC2 ( ctx, "WPA-TKIP %p: encrypted packet %p -> %p\n", ctx,
		iob, eiob );

	return eiob;
}

/**
 * Decrypt a packet using TKIP
 *
 * @v crypto	TKIP cryptosystem
 * @v eiob	I/O buffer containing encrypted packet
 * @ret iob	I/O buffer containing cleartext packet
 */
static struct io_buffer * tkip_decrypt ( struct net80211_crypto *crypto,
					 struct io_buffer *eiob )
{
	struct tkip_ctx *ctx = crypto->priv;
	struct ieee80211_frame *hdr;
	struct io_buffer *iob;
	const int hdrlen = IEEE80211_TYP_FRAME_HEADER_LEN;
	int datalen = iob_len ( eiob ) - hdrlen - TKIP_HEAD_LEN - TKIP_FOOT_LEN;
	struct tkip_head *head;
	struct arc4_ctx arc4;
	u16 rx_tsc_lo;
	u8 key[16];
	u8 mic[8];
	u32 icv, crc;

	iob = alloc_iob ( hdrlen + datalen + TKIP_FOOT_LEN );
	if ( ! iob )
		return NULL;

	/* Copy frame header */
	memcpy ( iob_put ( iob, hdrlen ), eiob->data, hdrlen );
	hdr = iob->data;
	hdr->fc &= ~IEEE80211_FC_PROTECTED;

	/* Check and update TSC */
	head = eiob->data + hdrlen;
	rx_tsc_lo = ( head->tsc1 << 8 ) | head->tsc0;

	if ( head->tsc_hi < ctx->dec.tsc_hi ||
	     ( head->tsc_hi == ctx->dec.tsc_hi &&
	       rx_tsc_lo <= ctx->dec.tsc_lo ) ) {
		DBGC ( ctx, "WPA-TKIP %p: packet received out of order "
		       "(%08x:%04x <= %08x:%04x)\n", ctx, head->tsc_hi,
		       rx_tsc_lo, ctx->dec.tsc_hi, ctx->dec.tsc_lo );
		free_iob ( iob );
		return NULL;
	}
	ctx->dec.tsc_lo = rx_tsc_lo;
	if ( ctx->dec.tsc_hi != head->tsc_hi ) {
		ctx->dec.ttak_ok = 0;
		ctx->dec.tsc_hi = head->tsc_hi;
	}

	/* Calculate key */
	tkip_mix_1 ( &ctx->dec, &ctx->tk, hdr->addr2 );
	tkip_mix_2 ( &ctx->dec, &ctx->tk, key );

	/* Copy-decrypt data, MIC, ICV */
	cipher_setkey ( &arc4_algorithm, &arc4, key, 16 );
	cipher_decrypt ( &arc4_algorithm, &arc4,
			 eiob->data + hdrlen + TKIP_HEAD_LEN,
			 iob_put ( iob, datalen ), datalen + TKIP_FOOT_LEN );

	/* Check ICV */
	icv = le32_to_cpu ( *( u32 * ) ( iob->tail + TKIP_MIC_LEN ) );
	crc = ~crc32_le ( ~0, iob->data + hdrlen, datalen + TKIP_MIC_LEN );
	if ( crc != icv ) {
		DBGC ( ctx, "WPA-TKIP %p CRC mismatch: expect %08x, get %08x\n",
		       ctx, icv, crc );
		free_iob ( iob );
		return NULL;
	}

	/* Check MIC */
	tkip_michael ( &ctx->tk.mic.rx, hdr->addr1, hdr->addr3,
		       iob->data + hdrlen, datalen, mic );
	if ( memcmp ( mic, iob->tail, TKIP_MIC_LEN ) != 0 ) {
		DBGC ( ctx, "WPA-TKIP %p ALERT! MIC failure\n", ctx );
		/* XXX we should do the countermeasures here */
		free_iob ( iob );
		return NULL;
	}

	DBGC2 ( ctx, "WPA-TKIP %p: decrypted packet %p -> %p\n", ctx,
		eiob, iob );

	return iob;
}

/** TKIP cryptosystem */
struct net80211_crypto tkip_crypto __net80211_crypto = {
	.algorithm = NET80211_CRYPT_TKIP,
	.init = tkip_init,
	.encrypt = tkip_encrypt,
	.decrypt = tkip_decrypt,
	.priv_len = sizeof ( struct tkip_ctx ),
};




/**
 * Calculate HMAC-MD5 MIC for EAPOL-Key frame
 *
 * @v kck	Key Confirmation Key, 16 bytes
 * @v msg	Message to calculate MIC over
 * @v len	Number of bytes to calculate MIC over
 * @ret mic	Calculated MIC, 16 bytes long
 */
static void tkip_kie_mic ( const void *kck, const void *msg, size_t len,
			   void *mic )
{
	uint8_t ctx[MD5_CTX_SIZE];
	u8 kckb[16];
	size_t kck_len = 16;

	memcpy ( kckb, kck, kck_len );

	hmac_init ( &md5_algorithm, ctx, kckb, &kck_len );
	hmac_update ( &md5_algorithm, ctx, msg, len );
	hmac_final ( &md5_algorithm, ctx, kckb, &kck_len, mic );
}

/**
 * Decrypt key data in EAPOL-Key frame
 *
 * @v kek	Key Encryption Key, 16 bytes
 * @v iv	Initialisation vector, 16 bytes
 * @v msg	Message to decrypt
 * @v len	Length of message
 * @ret msg	Decrypted message in place of original
 * @ret len	Unchanged
 * @ret rc	Always 0 for success
 */
static int tkip_kie_decrypt ( const void *kek, const void *iv,
			      void *msg, u16 *len )
{
	u8 key[32];
	memcpy ( key, iv, 16 );
	memcpy ( key + 16, kek, 16 );

	arc4_skip ( key, 32, 256, msg, msg, *len );

	return 0;
}


/** TKIP-style key integrity and encryption handler */
struct wpa_kie tkip_kie __wpa_kie = {
	.version = EAPOL_KEY_VERSION_WPA,
	.mic = tkip_kie_mic,
	.decrypt = tkip_kie_decrypt,
};
