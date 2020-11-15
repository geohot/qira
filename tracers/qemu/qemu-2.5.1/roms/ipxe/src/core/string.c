/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/** @file
 *
 * String functions
 *
 */

/**
 * Fill memory region
 *
 * @v dest		Destination region
 * @v character		Fill character
 * @v len		Length
 * @ret dest		Destination region
 */
void * generic_memset ( void *dest, int character, size_t len ) {
	uint8_t *dest_bytes = dest;

	while ( len-- )
		*(dest_bytes++) = character;
	return dest;
}

/**
 * Copy memory region
 *
 * @v dest		Destination region
 * @v src		Source region
 * @v len		Length
 * @ret dest		Destination region
 */
void * generic_memcpy ( void *dest, const void *src, size_t len ) {
	const uint8_t *src_bytes = src;
	uint8_t *dest_bytes = dest;

	while ( len-- )
		*(dest_bytes++) = *(src_bytes++);
	return dest;
}

/**
 * Copy (possibly overlapping) memory region
 *
 * @v dest		Destination region
 * @v src		Source region
 * @v len		Length
 * @ret dest		Destination region
 */
void * generic_memmove ( void *dest, const void *src, size_t len ) {
	const uint8_t *src_bytes = ( src + len );
	uint8_t *dest_bytes = ( dest + len );

	if ( dest < src )
		return memcpy ( dest, src, len );
	while ( len-- )
		*(--dest_bytes) = *(--src_bytes);
	return dest;
}

/**
 * Compare memory regions
 *
 * @v first		First region
 * @v second		Second region
 * @v len		Length
 * @ret diff		Difference
 */
int memcmp ( const void *first, const void *second, size_t len ) {
	const uint8_t *first_bytes = first;
	const uint8_t *second_bytes = second;
	int diff;

	while ( len-- ) {
		diff = ( *(second_bytes++) - *(first_bytes++) );
		if ( diff )
			return diff;
	}
	return 0;
}

/**
 * Find character within a memory region
 *
 * @v src		Source region
 * @v character		Character to find
 * @v len		Length
 * @ret found		Found character, or NULL if not found
 */
void * memchr ( const void *src, int character, size_t len ) {
	const uint8_t *src_bytes = src;

	for ( ; len-- ; src_bytes++ ) {
		if ( *src_bytes == character )
			return ( ( void * ) src_bytes );
	}
	return NULL;
}

/**
 * Swap memory regions
 *
 * @v first		First region
 * @v second		Second region
 * @v len		Length
 * @ret first		First region
 */
void * memswap ( void *first, void *second, size_t len ) {
	uint8_t *first_bytes = first;
	uint8_t *second_bytes = second;
	uint8_t temp;

	for ( ; len-- ; first_bytes++, second_bytes++ ) {
		temp = *first_bytes;
		*first_bytes = *second_bytes;
		*second_bytes = temp;
	}
	return first;
}

/**
 * Compare strings
 *
 * @v first		First string
 * @v second		Second string
 * @ret diff		Difference
 */
int strcmp ( const char *first, const char *second ) {

	return strncmp ( first, second, ~( ( size_t ) 0 ) );
}

/**
 * Compare strings
 *
 * @v first		First string
 * @v second		Second string
 * @v max		Maximum length to compare
 * @ret diff		Difference
 */
int strncmp ( const char *first, const char *second, size_t max ) {
	const uint8_t *first_bytes = ( ( const uint8_t * ) first );
	const uint8_t *second_bytes = ( ( const uint8_t * ) second );
	int diff;

	for ( ; max-- ; first_bytes++, second_bytes++ ) {
		diff = ( *second_bytes - *first_bytes );
		if ( diff )
			return diff;
		if ( ! *first_bytes )
			return 0;
	}
	return 0;
}

/**
 * Compare case-insensitive strings
 *
 * @v first		First string
 * @v second		Second string
 * @ret diff		Difference
 */
int strcasecmp ( const char *first, const char *second ) {
	const uint8_t *first_bytes = ( ( const uint8_t * ) first );
	const uint8_t *second_bytes = ( ( const uint8_t * ) second );
	int diff;

	for ( ; ; first_bytes++, second_bytes++ ) {
		diff = ( toupper ( *second_bytes ) -
			 toupper ( *first_bytes ) );
		if ( diff )
			return diff;
		if ( ! *first_bytes )
			return 0;
	}
}

/**
 * Get length of string
 *
 * @v src		String
 * @ret len		Length
 */
size_t strlen ( const char *src ) {

	return strnlen ( src, ~( ( size_t ) 0 ) );
}

/**
 * Get length of string
 *
 * @v src		String
 * @v max		Maximum length
 * @ret len		Length
 */
size_t strnlen ( const char *src, size_t max ) {
	const uint8_t *src_bytes = ( ( const uint8_t * ) src );
	size_t len = 0;

	while ( max-- && *(src_bytes++) )
		len++;
	return len;
}

/**
 * Find character within a string
 *
 * @v src		String
 * @v character		Character to find
 * @ret found		Found character, or NULL if not found
 */
char * strchr ( const char *src, int character ) {
	const uint8_t *src_bytes = ( ( const uint8_t * ) src );

	for ( ; ; src_bytes++ ) {
		if ( *src_bytes == character )
			return ( ( char * ) src_bytes );
		if ( ! *src_bytes )
			return NULL;
	}
}

/**
 * Find rightmost character within a string
 *
 * @v src		String
 * @v character		Character to find
 * @ret found		Found character, or NULL if not found
 */
char * strrchr ( const char *src, int character ) {
	const uint8_t *src_bytes = ( ( const uint8_t * ) src );
	const uint8_t *start = src_bytes;

	while ( *src_bytes )
		src_bytes++;
	for ( src_bytes-- ; src_bytes >= start ; src_bytes-- ) {
		if ( *src_bytes == character )
			return ( ( char * ) src_bytes );
	}
	return NULL;
}

/**
 * Find substring
 *
 * @v haystack		String
 * @v needle		Substring
 * @ret found		Found substring, or NULL if not found
 */
char * strstr ( const char *haystack, const char *needle ) {
	size_t len = strlen ( needle );

	for ( ; *haystack ; haystack++ ) {
		if ( memcmp ( haystack, needle, len ) == 0 )
			return ( ( char * ) haystack );
	}
	return NULL;
}

/**
 * Copy string
 *
 * @v dest		Destination string
 * @v src		Source string
 * @ret dest		Destination string
 */
char * strcpy ( char *dest, const char *src ) {
	const uint8_t *src_bytes = ( ( const uint8_t * ) src );
	uint8_t *dest_bytes = ( ( uint8_t * ) dest );

	/* We cannot use strncpy(), since that would pad the destination */
	for ( ; ; src_bytes++, dest_bytes++ ) {
		*dest_bytes = *src_bytes;
		if ( ! *dest_bytes )
			break;
	}
	return dest;
}

/**
 * Copy string
 *
 * @v dest		Destination string
 * @v src		Source string
 * @v max		Maximum length
 * @ret dest		Destination string
 */
char * strncpy ( char *dest, const char *src, size_t max ) {
	const uint8_t *src_bytes = ( ( const uint8_t * ) src );
	uint8_t *dest_bytes = ( ( uint8_t * ) dest );

	for ( ; max ; max--, src_bytes++, dest_bytes++ ) {
		*dest_bytes = *src_bytes;
		if ( ! *dest_bytes )
			break;
	}
	while ( max-- )
		*(dest_bytes++) = '\0';
	return dest;
}

/**
 * Concatenate string
 *
 * @v dest		Destination string
 * @v src		Source string
 * @ret dest		Destination string
 */
char * strcat ( char *dest, const char *src ) {

	strcpy ( ( dest + strlen ( dest ) ), src );
	return dest;
}

/**
 * Duplicate string
 *
 * @v src		Source string
 * @ret dup		Duplicated string, or NULL if allocation failed
 */
char * strdup ( const char *src ) {

	return strndup ( src, ~( ( size_t ) 0 ) );
}

/**
 * Duplicate string
 *
 * @v src		Source string
 * @v max		Maximum length
 * @ret dup		Duplicated string, or NULL if allocation failed
 */
char * strndup ( const char *src, size_t max ) {
	size_t len = strnlen ( src, max );
        char *dup;

        dup = malloc ( len + 1 /* NUL */ );
        if ( dup ) {
		memcpy ( dup, src, len );
		dup[len] = '\0';
        }
        return dup;
}

/**
 * Calculate digit value
 *
 * @v character		Digit character
 * @ret digit		Digit value
 *
 * Invalid digits will be returned as a value greater than or equal to
 * the numeric base.
 */
unsigned int digit_value ( unsigned int character ) {

	if ( character >= 'a' )
		return ( character - ( 'a' - 10 ) );
	if ( character >= 'A' )
		return ( character - ( 'A' - 10 ) );
	if ( character <= '9' )
		return ( character - '0' );
	return character;
}

/**
 * Preprocess string for strtoul() or strtoull()
 *
 * @v string		String
 * @v negate		Final value should be negated
 * @v base		Numeric base
 * @ret string		Remaining string
 */
static const char * strtoul_pre ( const char *string, int *negate, int *base ) {

	/* Skip any leading whitespace */
	while ( isspace ( *string ) )
		string++;

	/* Process arithmetic sign, if present */
	*negate = 0;
	if ( *string == '-' ) {
		string++;
		*negate = 1;
	} else if ( *string == '+' ) {
		string++;
	}

	/* Process base, if present */
	if ( *base == 0 ) {
		*base = 10;
		if ( *string == '0' ) {
			string++;
			*base = 8;
			if ( ( *string & ~0x20 ) == 'X' ) {
				string++;
				*base = 16;
			}
		}
	}

	return string;
}

/**
 * Convert string to numeric value
 *
 * @v string		String
 * @v endp		End pointer (or NULL)
 * @v base		Numeric base (or zero to autodetect)
 * @ret value		Numeric value
 */
unsigned long strtoul ( const char *string, char **endp, int base ) {
	unsigned long value = 0;
	unsigned int digit;
	int negate;

	/* Preprocess string */
	string = strtoul_pre ( string, &negate, &base );

	/* Process digits */
	for ( ; ; string++ ) {
		digit = digit_value ( *string );
		if ( digit >= ( unsigned int ) base )
			break;
		value = ( ( value * base ) + digit );
	}

	/* Negate value if, applicable */
	if ( negate )
		value = -value;

	/* Fill in end pointer, if applicable */
	if ( endp )
		*endp = ( ( char * ) string );

	return value;
}

/**
 * Convert string to numeric value
 *
 * @v string		String
 * @v endp		End pointer (or NULL)
 * @v base		Numeric base (or zero to autodetect)
 * @ret value		Numeric value
 */
unsigned long long strtoull ( const char *string, char **endp, int base ) {
	unsigned long long value = 0;
	unsigned int digit;
	int negate;

	/* Preprocess string */
	string = strtoul_pre ( string, &negate, &base );

	/* Process digits */
	for ( ; ; string++ ) {
		digit = digit_value ( *string );
		if ( digit >= ( unsigned int ) base )
			break;
		value = ( ( value * base ) + digit );
	}

	/* Negate value if, applicable */
	if ( negate )
		value = -value;

	/* Fill in end pointer, if applicable */
	if ( endp )
		*endp = ( ( char * ) string );

	return value;
}
