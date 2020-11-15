/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <ipxe/tables.h>
#include <ipxe/asn1.h>

/** @file
 *
 * ASN.1 encoding
 *
 */

/* Disambiguate the various error causes */
#define EINVAL_ASN1_EMPTY \
	__einfo_error ( EINFO_EINVAL_ASN1_EMPTY )
#define EINFO_EINVAL_ASN1_EMPTY \
	__einfo_uniqify ( EINFO_EINVAL, 0x01, "Empty or underlength cursor" )
#define EINVAL_ASN1_LEN_LEN \
	__einfo_error ( EINFO_EINVAL_ASN1_LEN_LEN )
#define EINFO_EINVAL_ASN1_LEN_LEN \
	__einfo_uniqify ( EINFO_EINVAL, 0x02, "Length field overruns cursor" )
#define EINVAL_ASN1_LEN \
	__einfo_error ( EINFO_EINVAL_ASN1_LEN )
#define EINFO_EINVAL_ASN1_LEN \
	__einfo_uniqify ( EINFO_EINVAL, 0x03, "Field overruns cursor" )
#define EINVAL_ASN1_BOOLEAN \
	__einfo_error ( EINFO_EINVAL_ASN1_BOOLEAN )
#define EINFO_EINVAL_ASN1_BOOLEAN \
	__einfo_uniqify ( EINFO_EINVAL, 0x04, "Invalid boolean" )
#define EINVAL_ASN1_INTEGER \
	__einfo_error ( EINFO_EINVAL_ASN1_INTEGER )
#define EINFO_EINVAL_ASN1_INTEGER \
	__einfo_uniqify ( EINFO_EINVAL, 0x04, "Invalid integer" )
#define EINVAL_ASN1_TIME \
	__einfo_error ( EINFO_EINVAL_ASN1_TIME )
#define EINFO_EINVAL_ASN1_TIME \
	__einfo_uniqify ( EINFO_EINVAL, 0x05, "Invalid time" )
#define EINVAL_ASN1_ALGORITHM \
	__einfo_error ( EINFO_EINVAL_ASN1_ALGORITHM )
#define EINFO_EINVAL_ASN1_ALGORITHM \
	__einfo_uniqify ( EINFO_EINVAL, 0x06, "Invalid algorithm" )
#define EINVAL_BIT_STRING \
	__einfo_error ( EINFO_EINVAL_BIT_STRING )
#define EINFO_EINVAL_BIT_STRING \
	__einfo_uniqify ( EINFO_EINVAL, 0x07, "Invalid bit string" )
#define ENOTSUP_ALGORITHM \
	__einfo_error ( EINFO_ENOTSUP_ALGORITHM )
#define EINFO_ENOTSUP_ALGORITHM \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01, "Unsupported algorithm" )
#define ENOTTY_ALGORITHM \
	__einfo_error ( EINFO_ENOTTY_ALGORITHM )
#define EINFO_ENOTTY_ALGORITHM \
	__einfo_uniqify ( EINFO_ENOTTY, 0x01, "Inappropriate algorithm" )

/**
 * Invalidate ASN.1 object cursor
 *
 * @v cursor		ASN.1 object cursor
 */
void asn1_invalidate_cursor ( struct asn1_cursor *cursor ) {
	static uint8_t asn1_invalid_object[] = { ASN1_END, 0 };

	cursor->data = asn1_invalid_object;
	cursor->len = 0;
}

/**
 * Start parsing ASN.1 object
 *
 * @v cursor		ASN.1 object cursor
 * @v type		Expected type, or ASN1_ANY
 * @ret len		Length of object body, or negative error
 *
 * The object cursor will be updated to point to the start of the
 * object body (i.e. the first byte following the length byte(s)), and
 * the length of the object body (i.e. the number of bytes until the
 * following object tag, if any) is returned.
 */
static int asn1_start ( struct asn1_cursor *cursor, unsigned int type ) {
	unsigned int len_len;
	unsigned int len;

	/* Sanity check */
	if ( cursor->len < 2 /* Tag byte and first length byte */ ) {
		if ( cursor->len )
			DBGC ( cursor, "ASN1 %p too short\n", cursor );
		return -EINVAL_ASN1_EMPTY;
	}

	/* Check the tag byte */
	if ( ( type != ASN1_ANY ) && ( type != asn1_type ( cursor ) ) ) {
		DBGC ( cursor, "ASN1 %p type mismatch (expected %d, got %d)\n",
		       cursor, type, *( ( uint8_t * ) cursor->data ) );
		return -ENXIO;
	}
	cursor->data++;
	cursor->len--;

	/* Extract length of the length field and sanity check */
	len_len = *( ( uint8_t * ) cursor->data );
	if ( len_len & 0x80 ) {
		len_len = ( len_len & 0x7f );
		cursor->data++;
		cursor->len--;
	} else {
		len_len = 1;
	}
	if ( cursor->len < len_len ) {
		DBGC ( cursor, "ASN1 %p bad length field length %d (max "
		       "%zd)\n", cursor, len_len, cursor->len );
		return -EINVAL_ASN1_LEN_LEN;
	}

	/* Extract the length and sanity check */
	for ( len = 0 ; len_len ; len_len-- ) {
		len <<= 8;
		len |= *( ( uint8_t * ) cursor->data );
		cursor->data++;
		cursor->len--;
	}
	if ( cursor->len < len ) {
		DBGC ( cursor, "ASN1 %p bad length %d (max %zd)\n",
		       cursor, len, cursor->len );
		return -EINVAL_ASN1_LEN;
	}

	return len;
}

/**
 * Enter ASN.1 object
 *
 * @v cursor		ASN.1 object cursor
 * @v type		Expected type, or ASN1_ANY
 * @ret rc		Return status code
 *
 * The object cursor will be updated to point to the body of the
 * current ASN.1 object.  If any error occurs, the object cursor will
 * be invalidated.
 */
int asn1_enter ( struct asn1_cursor *cursor, unsigned int type ) {
	int len;

	len = asn1_start ( cursor, type );
	if ( len < 0 ) {
		asn1_invalidate_cursor ( cursor );
		return len;
	}

	cursor->len = len;
	DBGC ( cursor, "ASN1 %p entered object type %02x (len %x)\n",
	       cursor, type, len );

	return 0;
}

/**
 * Skip ASN.1 object if present
 *
 * @v cursor		ASN.1 object cursor
 * @v type		Expected type, or ASN1_ANY
 * @ret rc		Return status code
 *
 * The object cursor will be updated to point to the next ASN.1
 * object.  If any error occurs, the object cursor will not be
 * modified.
 */
int asn1_skip_if_exists ( struct asn1_cursor *cursor, unsigned int type ) {
	int len;

	len = asn1_start ( cursor, type );
	if ( len < 0 )
		return len;

	cursor->data += len;
	cursor->len -= len;
	DBGC ( cursor, "ASN1 %p skipped object type %02x (len %x)\n",
	       cursor, type, len );

	if ( ! cursor->len ) {
		DBGC ( cursor, "ASN1 %p reached end of object\n", cursor );
		return -ENOENT;
	}

	return 0;
}

/**
 * Skip ASN.1 object
 *
 * @v cursor		ASN.1 object cursor
 * @v type		Expected type, or ASN1_ANY
 * @ret rc		Return status code
 *
 * The object cursor will be updated to point to the next ASN.1
 * object.  If any error occurs, the object cursor will be
 * invalidated.
 */
int asn1_skip ( struct asn1_cursor *cursor, unsigned int type ) {
	int rc;

	if ( ( rc = asn1_skip_if_exists ( cursor, type ) ) != 0 ) {
		asn1_invalidate_cursor ( cursor );
		return rc;
	}

	return 0;
}

/**
 * Shrink ASN.1 cursor to fit object
 *
 * @v cursor		ASN.1 object cursor
 * @v type		Expected type, or ASN1_ANY
 * @ret rc		Return status code
 *
 * The object cursor will be shrunk to contain only the current ASN.1
 * object.  If any error occurs, the object cursor will be
 * invalidated.
 */
int asn1_shrink ( struct asn1_cursor *cursor, unsigned int type ) {
	struct asn1_cursor temp;
	const void *end;
	int len;

	/* Find end of object */
	memcpy ( &temp, cursor, sizeof ( temp ) );
	len = asn1_start ( &temp, type );
	if ( len < 0 ) {
		asn1_invalidate_cursor ( cursor );
		return len;
	}
	end = ( temp.data + len );

	/* Shrink original cursor to contain only its first object */
	cursor->len = ( end - cursor->data );

	return 0;
}

/**
 * Enter ASN.1 object of any type
 *
 * @v cursor		ASN.1 object cursor
 * @ret rc		Return status code
 */
int asn1_enter_any ( struct asn1_cursor *cursor ) {
	return asn1_enter ( cursor, ASN1_ANY );
}

/**
 * Skip ASN.1 object of any type
 *
 * @v cursor		ASN.1 object cursor
 * @ret rc		Return status code
 */
int asn1_skip_any ( struct asn1_cursor *cursor ) {
	return asn1_skip ( cursor, ASN1_ANY );
}

/**
 * Shrink ASN.1 object of any type
 *
 * @v cursor		ASN.1 object cursor
 * @ret rc		Return status code
 */
int asn1_shrink_any ( struct asn1_cursor *cursor ) {
	return asn1_shrink ( cursor, ASN1_ANY );
}

/**
 * Parse value of ASN.1 boolean
 *
 * @v cursor		ASN.1 object cursor
 * @ret value		Value, or negative error
 */
int asn1_boolean ( const struct asn1_cursor *cursor ) {
	struct asn1_cursor contents;
	const struct {
		uint8_t value;
	} __attribute__ (( packed )) *boolean;

	/* Enter boolean */
	memcpy ( &contents, cursor, sizeof ( contents ) );
	asn1_enter ( &contents, ASN1_BOOLEAN );
	if ( contents.len != sizeof ( *boolean ) )
		return -EINVAL_ASN1_BOOLEAN;

	/* Extract value */
	boolean = contents.data;
	return boolean->value;
}

/**
 * Parse value of ASN.1 integer
 *
 * @v cursor		ASN.1 object cursor
 * @v value		Value to fill in
 * @ret rc		Return status code
 */
int asn1_integer ( const struct asn1_cursor *cursor, int *value ) {
	struct asn1_cursor contents;
	uint8_t high_byte;
	int rc;

	/* Enter integer */
	memcpy ( &contents, cursor, sizeof ( contents ) );
	if ( ( rc = asn1_enter ( &contents, ASN1_INTEGER ) ) != 0 )
		return rc;
	if ( contents.len < 1 )
		return -EINVAL_ASN1_INTEGER;

	/* Initialise value according to sign byte */
	*value = *( ( int8_t * ) contents.data );
	contents.data++;
	contents.len--;

	/* Process value */
	while ( contents.len ) {
		high_byte = ( (*value) >> ( 8 * ( sizeof ( *value ) - 1 ) ) );
		if ( ( high_byte != 0x00 ) && ( high_byte != 0xff ) ) {
			DBGC ( cursor, "ASN1 %p integer overflow\n", cursor );
			return -EINVAL_ASN1_INTEGER;
		}
		*value = ( ( *value << 8 ) | *( ( uint8_t * ) contents.data ) );
		contents.data++;
		contents.len--;
	}

	return 0;
}

/**
 * Parse ASN.1 bit string
 *
 * @v cursor		ASN.1 cursor
 * @v bits		Bit string to fill in
 * @ret rc		Return status code
 */
int asn1_bit_string ( const struct asn1_cursor *cursor,
		      struct asn1_bit_string *bits ) {
	struct asn1_cursor contents;
	const struct {
		uint8_t unused;
		uint8_t data[0];
	} __attribute__ (( packed )) *bit_string;
	size_t len;
	unsigned int unused;
	uint8_t unused_mask;
	const uint8_t *last;
	int rc;

	/* Enter bit string */
	memcpy ( &contents, cursor, sizeof ( contents ) );
	if ( ( rc = asn1_enter ( &contents, ASN1_BIT_STRING ) ) != 0 ) {
		DBGC ( cursor, "ASN1 %p cannot locate bit string:\n", cursor );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return rc;
	}

	/* Validity checks */
	if ( contents.len < sizeof ( *bit_string ) ) {
		DBGC ( cursor, "ASN1 %p invalid bit string:\n", cursor );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -EINVAL_BIT_STRING;
	}
	bit_string = contents.data;
	len = ( contents.len - offsetof ( typeof ( *bit_string ), data ) );
	unused = bit_string->unused;
	unused_mask = ( 0xff >> ( 8 - unused ) );
	last = ( bit_string->data + len - 1 );
	if ( ( unused >= 8 ) ||
	     ( ( unused > 0 ) && ( len == 0 ) ) ||
	     ( ( *last & unused_mask ) != 0 ) ) {
		DBGC ( cursor, "ASN1 %p invalid bit string:\n", cursor );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -EINVAL_BIT_STRING;
	}

	/* Populate bit string */
	bits->data = &bit_string->data;
	bits->len = len;
	bits->unused = unused;

	return 0;
}

/**
 * Parse ASN.1 bit string that must be an integral number of bytes
 *
 * @v cursor		ASN.1 cursor
 * @v bits		Bit string to fill in
 * @ret rc		Return status code
 */
int asn1_integral_bit_string ( const struct asn1_cursor *cursor,
			       struct asn1_bit_string *bits ) {
	int rc;

	/* Parse bit string */
	if ( ( rc = asn1_bit_string ( cursor, bits ) ) != 0 )
		return rc;

	/* Check that there are no unused bits at end of string */
	if ( bits->unused ) {
		DBGC ( cursor, "ASN1 %p invalid integral bit string:\n",
		       cursor );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -EINVAL_BIT_STRING;
	}

	return 0;
}

/**
 * Compare two ASN.1 objects
 *
 * @v cursor1		ASN.1 object cursor
 * @v cursor2		ASN.1 object cursor
 * @ret difference	Difference as returned by memcmp()
 *
 * Note that invalid and empty cursors will compare as equal with each
 * other.
 */
int asn1_compare ( const struct asn1_cursor *cursor1,
		   const struct asn1_cursor *cursor2 ) {
	int difference;

	difference = ( cursor2->len - cursor1->len );
	return ( difference ? difference :
		 memcmp ( cursor1->data, cursor2->data, cursor1->len ) );
}

/**
 * Identify ASN.1 algorithm by OID
 *
 * @v cursor		ASN.1 object cursor

 * @ret algorithm	Algorithm, or NULL
 */
static struct asn1_algorithm *
asn1_find_algorithm ( const struct asn1_cursor *cursor ) {
	struct asn1_algorithm *algorithm;

	for_each_table_entry ( algorithm, ASN1_ALGORITHMS ) {
		if ( asn1_compare ( &algorithm->oid, cursor ) == 0 )
			return algorithm;
	}

	return NULL;
}

/**
 * Parse ASN.1 OID-identified algorithm
 *
 * @v cursor		ASN.1 object cursor
 * @ret algorithm	Algorithm
 * @ret rc		Return status code
 */
int asn1_algorithm ( const struct asn1_cursor *cursor,
		     struct asn1_algorithm **algorithm ) {
	struct asn1_cursor contents;
	int rc;

	/* Enter signatureAlgorithm */
	memcpy ( &contents, cursor, sizeof ( contents ) );
	asn1_enter ( &contents, ASN1_SEQUENCE );

	/* Enter algorithm */
	if ( ( rc = asn1_enter ( &contents, ASN1_OID ) ) != 0 ) {
		DBGC ( cursor, "ASN1 %p cannot locate algorithm OID:\n",
		       cursor );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -EINVAL_ASN1_ALGORITHM;
	}

	/* Identify algorithm */
	*algorithm = asn1_find_algorithm ( &contents );
	if ( ! *algorithm ) {
		DBGC ( cursor, "ASN1 %p unrecognised algorithm:\n", cursor );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -ENOTSUP_ALGORITHM;
	}

	return 0;
}

/**
 * Parse ASN.1 OID-identified public-key algorithm
 *
 * @v cursor		ASN.1 object cursor
 * @ret algorithm	Algorithm
 * @ret rc		Return status code
 */
int asn1_pubkey_algorithm ( const struct asn1_cursor *cursor,
			    struct asn1_algorithm **algorithm ) {
	int rc;

	/* Parse algorithm */
	if ( ( rc = asn1_algorithm ( cursor, algorithm ) ) != 0 )
		return rc;

	/* Check algorithm has a public key */
	if ( ! (*algorithm)->pubkey ) {
		DBGC ( cursor, "ASN1 %p algorithm %s is not a public-key "
		       "algorithm:\n", cursor, (*algorithm)->name );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -ENOTTY_ALGORITHM;
	}

	return 0;
}

/**
 * Parse ASN.1 OID-identified digest algorithm
 *
 * @v cursor		ASN.1 object cursor
 * @ret algorithm	Algorithm
 * @ret rc		Return status code
 */
int asn1_digest_algorithm ( const struct asn1_cursor *cursor,
			    struct asn1_algorithm **algorithm ) {
	int rc;

	/* Parse algorithm */
	if ( ( rc = asn1_algorithm ( cursor, algorithm ) ) != 0 )
		return rc;

	/* Check algorithm has a digest */
	if ( ! (*algorithm)->digest ) {
		DBGC ( cursor, "ASN1 %p algorithm %s is not a digest "
		       "algorithm:\n", cursor, (*algorithm)->name );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -ENOTTY_ALGORITHM;
	}

	return 0;
}

/**
 * Parse ASN.1 OID-identified signature algorithm
 *
 * @v cursor		ASN.1 object cursor
 * @ret algorithm	Algorithm
 * @ret rc		Return status code
 */
int asn1_signature_algorithm ( const struct asn1_cursor *cursor,
			       struct asn1_algorithm **algorithm ) {
	int rc;

	/* Parse algorithm */
	if ( ( rc = asn1_algorithm ( cursor, algorithm ) ) != 0 )
		return rc;

	/* Check algorithm has a public key */
	if ( ! (*algorithm)->pubkey ) {
		DBGC ( cursor, "ASN1 %p algorithm %s is not a signature "
		       "algorithm:\n", cursor, (*algorithm)->name );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -ENOTTY_ALGORITHM;
	}

	/* Check algorithm has a digest */
	if ( ! (*algorithm)->digest ) {
		DBGC ( cursor, "ASN1 %p algorithm %s is not a signature "
		       "algorithm:\n", cursor, (*algorithm)->name );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -ENOTTY_ALGORITHM;
	}

	return 0;
}

/**
 * Parse ASN.1 GeneralizedTime
 *
 * @v cursor		ASN.1 cursor
 * @v time		Time to fill in
 * @ret rc		Return status code
 *
 * RFC 5280 section 4.1.2.5 places several restrictions on the allowed
 * formats for UTCTime and GeneralizedTime, and mandates the
 * interpretation of centuryless year values.
 */
int asn1_generalized_time ( const struct asn1_cursor *cursor, time_t *time ) {
	struct asn1_cursor contents;
	unsigned int have_century;
	unsigned int type;
	union {
		struct {
			uint8_t century;
			uint8_t year;
			uint8_t month;
			uint8_t day;
			uint8_t hour;
			uint8_t minute;
			uint8_t second;
		} __attribute__ (( packed )) named;
		uint8_t raw[7];
	} pairs;
	struct tm tm;
	const uint8_t *data;
	size_t remaining;
	unsigned int tens;
	unsigned int units;
	unsigned int i;
	int rc;

	/* Determine time format utcTime/generalizedTime */
	memcpy ( &contents, cursor, sizeof ( contents ) );
	type = asn1_type ( &contents );
	switch ( type ) {
	case ASN1_UTC_TIME:
		have_century = 0;
		break;
	case ASN1_GENERALIZED_TIME:
		have_century = 1;
		break;
	default:
		DBGC ( cursor, "ASN1 %p invalid time type %02x\n",
		       cursor, type );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -EINVAL_ASN1_TIME;
	}

	/* Enter utcTime/generalizedTime */
	if ( ( rc = asn1_enter ( &contents, type ) ) != 0 ) {
		DBGC ( cursor, "ASN1 %p cannot locate %s time:\n", cursor,
		       ( ( type == ASN1_UTC_TIME ) ? "UTC" : "generalized" ) );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return rc;
	}

	/* Parse digit string a pair at a time */
	memset ( &pairs, 0, sizeof ( pairs ) );
	data = contents.data;
	remaining = contents.len;
	for ( i = ( have_century ? 0 : 1 ) ; i < sizeof ( pairs.raw ) ; i++ ) {
		if ( remaining < 2 ) {
			/* Some certificates violate the X.509 RFC by
			 * omitting the "seconds" value.
			 */
			if ( i == ( sizeof ( pairs.raw ) - 1 ) )
				break;
			DBGC ( cursor, "ASN1 %p invalid time:\n", cursor );
			DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
			return -EINVAL_ASN1_TIME;
		}
		tens = data[0];
		units = data[1];
		if ( ! ( isdigit ( tens ) && isdigit ( units ) ) ) {
			DBGC ( cursor, "ASN1 %p invalid time:\n", cursor );
			DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
			return -EINVAL_ASN1_TIME;
		}
		pairs.raw[i] = ( ( 10 * ( tens - '0' ) ) + ( units - '0' ) );
		data += 2;
		remaining -= 2;
	}

	/* Determine century if applicable */
	if ( ! have_century )
		pairs.named.century = ( ( pairs.named.year >= 50 ) ? 19 : 20 );

	/* Check for trailing "Z" */
	if ( ( remaining != 1 ) || ( data[0] != 'Z' ) ) {
		DBGC ( cursor, "ASN1 %p invalid time:\n", cursor );
		DBGC_HDA ( cursor, 0, cursor->data, cursor->len );
		return -EINVAL_ASN1_TIME;
	}

	/* Fill in time */
	tm.tm_year = ( ( ( pairs.named.century - 19 ) * 100 ) +
		       pairs.named.year );
	tm.tm_mon = ( pairs.named.month - 1 );
	tm.tm_mday = pairs.named.day;
	tm.tm_hour = pairs.named.hour;
	tm.tm_min = pairs.named.minute;
	tm.tm_sec = pairs.named.second;

	/* Convert to seconds since the Epoch */
	*time = mktime ( &tm );

	return 0;
}

/**
 * Construct ASN.1 header
 *
 * @v header		ASN.1 builder header
 * @v type		Type
 * @v len		Content length
 * @ret header_len	Header length
 */
static size_t asn1_header ( struct asn1_builder_header *header,
			    unsigned int type, size_t len ) {
	unsigned int header_len = 2;
	unsigned int len_len = 0;
	size_t temp;

	/* Construct header */
	header->type = type;
	if ( len < 0x80 ) {
		header->length[0] = len;
	} else {
		for ( temp = len ; temp ; temp >>= 8 )
			len_len++;
		header->length[0] = ( 0x80 | len_len );
		header_len += len_len;
		for ( temp = len ; temp ; temp >>= 8 )
			header->length[len_len--] = ( temp & 0xff );
	}

	return header_len;
}

/**
 * Grow ASN.1 builder
 *
 * @v builder		ASN.1 builder
 * @v extra		Extra space to prepend
 * @ret rc		Return status code
 */
static int asn1_grow ( struct asn1_builder *builder, size_t extra ) {
	size_t new_len;
	void *new;

	/* As with the ASN1 parsing functions, make errors permanent */
	if ( builder->len && ! builder->data )
		return -ENOMEM;

	/* Reallocate data buffer */
	new_len = ( builder->len + extra );
	new = realloc ( builder->data, new_len );
	if ( ! new ) {
		free ( builder->data );
		builder->data = NULL;
		return -ENOMEM;
	}
	builder->data = new;

	/* Move existing data to end of buffer */
	memmove ( ( builder->data + extra ), builder->data, builder->len );
	builder->len = new_len;

	return 0;
}

/**
 * Prepend raw data to ASN.1 builder
 *
 * @v builder		ASN.1 builder
 * @v data		Data to prepend
 * @v len		Length of data to prepend
 * @ret rc		Return status code
 */
int asn1_prepend_raw ( struct asn1_builder *builder, const void *data,
		       size_t len ) {
	int rc;

	/* Grow buffer */
	if ( ( rc = asn1_grow ( builder, len ) ) != 0 )
		return rc;

	/* Populate data buffer */
	memcpy ( builder->data, data, len );

	return 0;
}

/**
 * Prepend data to ASN.1 builder
 *
 * @v builder		ASN.1 builder
 * @v type		Type
 * @v data		Data to prepend
 * @v len		Length of data to prepend
 * @ret rc		Return status code
 */
int asn1_prepend ( struct asn1_builder *builder, unsigned int type,
		   const void *data, size_t len ) {
	struct asn1_builder_header header;
	size_t header_len;
	int rc;

	/* Construct header */
	header_len = asn1_header ( &header, type, len );

	/* Grow buffer */
	if ( ( rc = asn1_grow ( builder, header_len + len ) ) != 0 )
		return rc;

	/* Populate data buffer */
	memcpy ( builder->data, &header, header_len );
	memcpy ( ( builder->data + header_len ), data, len );

	return 0;
}

/**
 * Wrap ASN.1 builder
 *
 * @v builder		ASN.1 builder
 * @v type		Type
 * @ret rc		Return status code
 */
int asn1_wrap ( struct asn1_builder *builder, unsigned int type ) {
	struct asn1_builder_header header;
	size_t header_len;
	int rc;

	/* Construct header */
	header_len = asn1_header ( &header, type, builder->len );

	/* Grow buffer */
	if ( ( rc = asn1_grow ( builder, header_len ) ) != 0 )
		return rc;

	/* Populate data buffer */
	memcpy ( builder->data, &header, header_len );

	return 0;
}
