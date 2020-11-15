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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/ieee80211.h>
#include <ipxe/net80211.h>
#include <ipxe/sec80211.h>

/** @file
 *
 * General secured-network routines required whenever any secure
 * network support at all is compiled in. This involves things like
 * installing keys, determining the type of security used by a probed
 * network, and some small helper functions that take advantage of
 * static data in this file.
 */

/* Unsupported cryptosystem error numbers */
#define ENOTSUP_WEP __einfo_error ( EINFO_ENOTSUP_WEP )
#define EINFO_ENOTSUP_WEP __einfo_uniqify ( EINFO_ENOTSUP, \
	( 0x10 | NET80211_CRYPT_WEP ), "WEP not supported" )
#define ENOTSUP_TKIP __einfo_error ( EINFO_ENOTSUP_TKIP )
#define EINFO_ENOTSUP_TKIP __einfo_uniqify ( EINFO_ENOTSUP, \
	( 0x10 | NET80211_CRYPT_TKIP ), "TKIP not supported" )
#define ENOTSUP_CCMP __einfo_error ( EINFO_ENOTSUP_CCMP )
#define EINFO_ENOTSUP_CCMP __einfo_uniqify ( EINFO_ENOTSUP, \
	( 0x10 | NET80211_CRYPT_CCMP ), "CCMP not supported" )
#define ENOTSUP_CRYPT( crypt )			   \
	EUNIQ ( EINFO_ENOTSUP, ( 0x10 | (crypt) ), \
		ENOTSUP_WEP, ENOTSUP_TKIP, ENOTSUP_CCMP )

/** Mapping from net80211 crypto/secprot types to RSN OUI descriptors */
struct descriptor_map {
	/** Value of net80211_crypto_alg or net80211_security_proto */
	u32 net80211_type;

	/** OUI+type in appropriate byte order, masked to exclude vendor */
	u32 oui_type;
};

/** Magic number in @a oui_type showing end of list */
#define END_MAGIC	0xFFFFFFFF

/** Mapping between net80211 cryptosystems and 802.11i cipher IDs */
static struct descriptor_map rsn_cipher_map[] = {
	{ .net80211_type = NET80211_CRYPT_WEP,
	  .oui_type = IEEE80211_RSN_CTYPE_WEP40 },

	{ .net80211_type = NET80211_CRYPT_WEP,
	  .oui_type = IEEE80211_RSN_CTYPE_WEP104 },

	{ .net80211_type = NET80211_CRYPT_TKIP,
	  .oui_type = IEEE80211_RSN_CTYPE_TKIP },

	{ .net80211_type = NET80211_CRYPT_CCMP,
	  .oui_type = IEEE80211_RSN_CTYPE_CCMP },

	{ .net80211_type = NET80211_CRYPT_UNKNOWN,
	  .oui_type = END_MAGIC },
};

/** Mapping between net80211 handshakers and 802.11i AKM IDs */
static struct descriptor_map rsn_akm_map[] = {
	{ .net80211_type = NET80211_SECPROT_EAP,
	  .oui_type = IEEE80211_RSN_ATYPE_8021X },

	{ .net80211_type = NET80211_SECPROT_PSK,
	  .oui_type = IEEE80211_RSN_ATYPE_PSK },

	{ .net80211_type = NET80211_SECPROT_UNKNOWN,
	  .oui_type = END_MAGIC },
};


/**
 * Install 802.11 cryptosystem
 *
 * @v which	Pointer to the cryptosystem structure to install in
 * @v crypt	Cryptosystem ID number
 * @v key	Encryption key to use
 * @v len	Length of encryption key
 * @v rsc	Initial receive sequence counter, if applicable
 * @ret rc	Return status code
 *
 * The encryption key will not be accessed via the provided pointer
 * after this function returns, so you may keep it on the stack.
 *
 * @a which must point to either @c dev->crypto (for the normal case
 * of installing a unicast cryptosystem) or @c dev->gcrypto (to
 * install a cryptosystem that will be used only for decrypting
 * group-source frames).
 */
int sec80211_install ( struct net80211_crypto **which,
		       enum net80211_crypto_alg crypt,
		       const void *key, int len, const void *rsc )
{
	struct net80211_crypto *crypto = *which;
	struct net80211_crypto *tbl_crypto;

	/* Remove old crypto if it exists */
	free ( *which );
	*which = NULL;

	if ( crypt == NET80211_CRYPT_NONE ) {
		DBG ( "802.11-Sec not installing null cryptography\n" );
		return 0;
	}

	/* Find cryptosystem to use */
	for_each_table_entry ( tbl_crypto, NET80211_CRYPTOS ) {
		if ( tbl_crypto->algorithm == crypt ) {
			crypto = zalloc ( sizeof ( *crypto ) +
					  tbl_crypto->priv_len );
			if ( ! crypto ) {
				DBG ( "802.11-Sec out of memory\n" );
				return -ENOMEM;
			}

			memcpy ( crypto, tbl_crypto, sizeof ( *crypto ) );
			crypto->priv = ( ( void * ) crypto +
					 sizeof ( *crypto ) );
			break;
		}
	}

	if ( ! crypto ) {
		DBG ( "802.11-Sec no support for cryptosystem %d\n", crypt );
		return -ENOTSUP_CRYPT ( crypt );
	}

	*which = crypto;

	DBG ( "802.11-Sec installing cryptosystem %d as %p with key of "
	      "length %d\n", crypt, crypto, len );

	return crypto->init ( crypto, key, len, rsc );
}


/**
 * Determine net80211 crypto or handshaking type value to return for RSN info
 *
 * @v rsnp		Pointer to next descriptor count field in RSN IE
 * @v rsn_end		Pointer to end of RSN IE
 * @v map		Descriptor map to use
 * @v tbl_start		Start of linker table to examine for iPXE support
 * @v tbl_end		End of linker table to examine for iPXE support
 * @ret rsnp		Updated to point to first byte after descriptors
 * @ret map_ent		Descriptor map entry of translation to use
 *
 * The entries in the linker table must be either net80211_crypto or
 * net80211_handshaker structures, and @a tbl_stride must be set to
 * sizeof() the appropriate one.
 *
 * This function expects @a rsnp to point at a two-byte descriptor
 * count followed by a list of four-byte cipher or AKM descriptors; it
 * will return @c NULL if the input packet is malformed, and otherwise
 * set @a rsnp to the first byte it has not looked at. It will return
 * the first cipher in the list that is supported by the current build
 * of iPXE, or the first of all if none are supported.
 *
 * We play rather fast and loose with type checking, because this
 * function is only called from two well-defined places in the
 * RSN-checking code. Don't try to use it for anything else.
 */
static struct descriptor_map * rsn_pick_desc ( u8 **rsnp, u8 *rsn_end,
					       struct descriptor_map *map,
					       void *tbl_start, void *tbl_end )
{
	int ndesc;
	int ok = 0;
	struct descriptor_map *map_ent, *map_ret = NULL;
	u8 *rsn = *rsnp;
	void *tblp;
	size_t tbl_stride = ( map == rsn_cipher_map ?
			      sizeof ( struct net80211_crypto ) :
			      sizeof ( struct net80211_handshaker ) );

	if ( map != rsn_cipher_map && map != rsn_akm_map )
		return NULL;

	/* Determine which types we support */
	for ( tblp = tbl_start; tblp < tbl_end; tblp += tbl_stride ) {
		struct net80211_crypto *crypto = tblp;
		struct net80211_handshaker *hs = tblp;

		if ( map == rsn_cipher_map )
			ok |= ( 1 << crypto->algorithm );
		else
			ok |= ( 1 << hs->protocol );
	}

	/* RSN sanity checks */
	if ( rsn + 2 > rsn_end ) {
		DBG ( "RSN detect: malformed descriptor count\n" );
		return NULL;
	}

	ndesc = *( u16 * ) rsn;
	rsn += 2;

	if ( ! ndesc ) {
		DBG ( "RSN detect: no descriptors\n" );
		return NULL;
	}

	/* Determine which net80211 crypto types are listed */
	while ( ndesc-- ) {
		u32 desc;

		if ( rsn + 4 > rsn_end ) {
			DBG ( "RSN detect: malformed descriptor (%d left)\n",
			      ndesc );
			return NULL;
		}

		desc = *( u32 * ) rsn;
		rsn += 4;

		for ( map_ent = map; map_ent->oui_type != END_MAGIC; map_ent++ )
			if ( map_ent->oui_type == ( desc & OUI_TYPE_MASK ) )
				break;

		/* Use first cipher as a fallback */
		if ( ! map_ret )
			map_ret = map_ent;

		/* Once we find one we support, use it */
		if ( ok & ( 1 << map_ent->net80211_type ) ) {
			map_ret = map_ent;
			break;
		}
	}

	if ( ndesc > 0 )
		rsn += 4 * ndesc;

	*rsnp = rsn;
	return map_ret;
}


/**
 * Find the RSN or WPA information element in the provided beacon frame
 *
 * @v ie	Pointer to first information element to check
 * @v ie_end	Pointer to end of information element space
 * @ret is_rsn	TRUE if returned IE is RSN, FALSE if it's WPA
 * @ret end	Pointer to byte immediately after last byte of data
 * @ret data	Pointer to first byte of data (the `version' field)
 *
 * If both an RSN and a WPA information element are found, this
 * function will return the first one seen, which by ordering rules
 * should always prefer the newer RSN IE.
 *
 * If no RSN or WPA infomration element is found, returns @c NULL and
 * leaves @a is_rsn and @a end in an undefined state.
 *
 * This function will not return a pointer to an information element
 * that states it extends past the tail of the io_buffer, or whose @a
 * version field is incorrect.
 */
u8 * sec80211_find_rsn ( union ieee80211_ie *ie, void *ie_end,
			 int *is_rsn, u8 **end )
{
	u8 *rsn = NULL;

	if ( ! ieee80211_ie_bound ( ie, ie_end ) )
		return NULL;

	while ( ie ) {
		if ( ie->id == IEEE80211_IE_VENDOR &&
		     ie->vendor.oui == IEEE80211_WPA_OUI_VEN ) {
			DBG ( "RSN detect: old-style WPA IE found\n" );
			rsn = &ie->vendor.data[0];
			*end = rsn + ie->len - 4;
			*is_rsn = 0;
		} else if ( ie->id == IEEE80211_IE_RSN ) {
			DBG ( "RSN detect: 802.11i RSN IE found\n" );
			rsn = ( u8 * ) &ie->rsn.version;
			*end = rsn + ie->len;
			*is_rsn = 1;
		}

		if ( rsn && ( *end > ( u8 * ) ie_end || rsn >= *end ||
			      *( u16 * ) rsn != IEEE80211_RSN_VERSION ) ) {
			DBG ( "RSN detect: malformed RSN IE or unknown "
			      "version, keep trying\n" );
			rsn = NULL;
		}

		if ( rsn )
			break;

		ie = ieee80211_next_ie ( ie, ie_end );
	}

	if ( ! ie ) {
		DBG ( "RSN detect: no RSN IE found\n" );
		return NULL;
	}

	return rsn;
}


/**
 * Detect crypto and AKM types from RSN information element
 *
 * @v is_rsn	If TRUE, IE is a new-style RSN information element
 * @v start	Pointer to first byte of @a version field
 * @v end	Pointer to first byte not in the RSN IE
 * @ret secprot	Security handshaking protocol used by network
 * @ret crypt	Cryptosystem used by network
 * @ret rc	Return status code
 *
 * If the IE cannot be parsed, returns an error indication and leaves
 * @a secprot and @a crypt unchanged.
 */
int sec80211_detect_ie ( int is_rsn, u8 *start, u8 *end,
			 enum net80211_security_proto *secprot,
			 enum net80211_crypto_alg *crypt )
{
	enum net80211_security_proto sp;
	enum net80211_crypto_alg cr;
	struct descriptor_map *map;
	u8 *rsn = start;

	/* Set some defaults */
	cr = ( is_rsn ? NET80211_CRYPT_CCMP : NET80211_CRYPT_TKIP );
	sp = NET80211_SECPROT_EAP;

	rsn += 2;		/* version - already checked */
	rsn += 4;		/* group cipher - we don't use it here */

	if ( rsn >= end )
		goto done;

	/* Pick crypto algorithm */
	map = rsn_pick_desc ( &rsn, end, rsn_cipher_map,
			      table_start ( NET80211_CRYPTOS ),
			      table_end ( NET80211_CRYPTOS ) );
	if ( ! map )
		goto invalid_rsn;

	cr = map->net80211_type;

	if ( rsn >= end )
		goto done;

	/* Pick handshaking algorithm */
	map = rsn_pick_desc ( &rsn, end, rsn_akm_map,
			      table_start ( NET80211_HANDSHAKERS ),
			      table_end ( NET80211_HANDSHAKERS ) );
	if ( ! map )
		goto invalid_rsn;

	sp = map->net80211_type;

 done:
	DBG ( "RSN detect: OK, crypto type %d, secprot type %d\n", cr, sp );
	*secprot = sp;
	*crypt = cr;
	return 0;

 invalid_rsn:
	DBG ( "RSN detect: invalid RSN IE\n" );
	return -EINVAL;
}


/**
 * Detect the cryptosystem and handshaking protocol used by an 802.11 network
 *
 * @v iob	I/O buffer containing beacon frame
 * @ret secprot	Security handshaking protocol used by network
 * @ret crypt	Cryptosystem used by network
 * @ret rc	Return status code
 *
 * This function uses weak linkage, as it must be called from generic
 * contexts but should only be linked in if some encryption is
 * supported; you must test its address against @c NULL before calling
 * it. If it does not exist, any network with the PRIVACY bit set in
 * beacon->capab should be considered unknown.
 */
int sec80211_detect ( struct io_buffer *iob,
		      enum net80211_security_proto *secprot,
		      enum net80211_crypto_alg *crypt )
{
	struct ieee80211_frame *hdr = iob->data;
	struct ieee80211_beacon *beacon =
		( struct ieee80211_beacon * ) hdr->data;
	u8 *rsn, *rsn_end;
	int is_rsn, rc;

	*crypt = NET80211_CRYPT_UNKNOWN;
	*secprot = NET80211_SECPROT_UNKNOWN;

	/* Find RSN or WPA IE */
	if ( ! ( rsn = sec80211_find_rsn ( beacon->info_element, iob->tail,
					   &is_rsn, &rsn_end ) ) ) {
		/* No security IE at all; either WEP or no security. */
		*secprot = NET80211_SECPROT_NONE;

		if ( beacon->capability & IEEE80211_CAPAB_PRIVACY )
			*crypt = NET80211_CRYPT_WEP;
		else
			*crypt = NET80211_CRYPT_NONE;

		return 0;
	}

	/* Determine type of security */
	if ( ( rc = sec80211_detect_ie ( is_rsn, rsn, rsn_end, secprot,
					 crypt ) ) == 0 )
		return 0;

	/* If we get here, the RSN IE was invalid */

	*crypt = NET80211_CRYPT_UNKNOWN;
	*secprot = NET80211_SECPROT_UNKNOWN;
	DBG ( "Failed to handle RSN IE:\n" );
	DBG_HD ( rsn, rsn_end - rsn );
	return rc;
}


/**
 * Determine RSN descriptor for specified net80211 ID
 *
 * @v id	net80211 ID value
 * @v rsnie	Whether to return a new-format (RSN IE) descriptor
 * @v map	Map to use in translation
 * @ret desc	RSN descriptor, or 0 on error
 *
 * If @a rsnie is false, returns an old-format (WPA vendor IE)
 * descriptor.
 */
static u32 rsn_get_desc ( unsigned id, int rsnie, struct descriptor_map *map )
{
	u32 vendor = ( rsnie ? IEEE80211_RSN_OUI : IEEE80211_WPA_OUI );

	for ( ; map->oui_type != END_MAGIC; map++ ) {
		if ( map->net80211_type == id )
			return map->oui_type | vendor;
	}

	return 0;
}

/**
 * Determine RSN descriptor for specified net80211 cryptosystem number
 *
 * @v crypt	Cryptosystem number
 * @v rsnie	Whether to return a new-format (RSN IE) descriptor
 * @ret desc	RSN descriptor
 *
 * If @a rsnie is false, returns an old-format (WPA vendor IE)
 * descriptor.
 */
u32 sec80211_rsn_get_crypto_desc ( enum net80211_crypto_alg crypt, int rsnie )
{
	return rsn_get_desc ( crypt, rsnie, rsn_cipher_map );
}

/**
 * Determine RSN descriptor for specified net80211 handshaker number
 *
 * @v secprot	Handshaker number
 * @v rsnie	Whether to return a new-format (RSN IE) descriptor
 * @ret desc	RSN descriptor
 *
 * If @a rsnie is false, returns an old-format (WPA vendor IE)
 * descriptor.
 */
u32 sec80211_rsn_get_akm_desc ( enum net80211_security_proto secprot,
				int rsnie )
{
	return rsn_get_desc ( secprot, rsnie, rsn_akm_map );
}

/**
 * Determine net80211 cryptosystem number from RSN descriptor
 *
 * @v desc	RSN descriptor
 * @ret crypt	net80211 cryptosystem enumeration value
 */
enum net80211_crypto_alg sec80211_rsn_get_net80211_crypt ( u32 desc )
{
	struct descriptor_map *map = rsn_cipher_map;

	for ( ; map->oui_type != END_MAGIC; map++ ) {
		if ( map->oui_type == ( desc & OUI_TYPE_MASK ) )
			break;
	}

	return map->net80211_type;
}
