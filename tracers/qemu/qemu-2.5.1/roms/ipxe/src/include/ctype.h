#ifndef _CTYPE_H
#define _CTYPE_H

/** @file
 *
 * Character types
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Check if character is a decimal digit
 *
 * @v character		ASCII character
 * @ret is_digit	Character is a decimal digit
 */
static inline int isdigit ( int character ) {

	return ( ( character >= '0' ) && ( character <= '9' ) );
}

/**
 * Check if character is a hexadecimal digit
 *
 * @v character		ASCII character
 * @ret is_xdigit	Character is a hexadecimal digit
 */
static inline int isxdigit ( int character ) {

	return ( ( ( character >= '0' ) && ( character <= '9' ) ) ||
		 ( ( character >= 'A' ) && ( character <= 'F' ) ) ||
		 ( ( character >= 'a' ) && ( character <= 'f' ) ) );
}

/**
 * Check if character is an upper-case letter
 *
 * @v character		ASCII character
 * @ret is_upper	Character is an upper-case letter
 */
static inline int isupper ( int character ) {

	return ( ( character >= 'A' ) && ( character <= 'Z' ) );
}

/**
 * Check if character is a lower-case letter
 *
 * @v character		ASCII character
 * @ret is_lower	Character is a lower-case letter
 */
static inline int islower ( int character ) {

	return ( ( character >= 'a' ) && ( character <= 'z' ) );
}

/**
 * Check if character is alphabetic
 *
 * @v character		ASCII character
 * @ret is_alpha	Character is alphabetic
 */
static inline int isalpha ( int character ) {

	return ( isupper ( character ) || islower ( character ) );
}

/**
 * Check if character is alphanumeric
 *
 * @v character		ASCII character
 * @ret is_alnum	Character is alphanumeric
 */
static inline int isalnum ( int character ) {

	return ( isalpha ( character ) || isdigit ( character ) );
}

/**
 * Check if character is printable
 *
 * @v character		ASCII character
 * @ret is_print	Character is printable
 */
static inline int isprint ( int character ) {

	return ( ( character >= ' ' ) && ( character <= '~' ) );
}

/**
 * Convert character to lower case
 *
 * @v character		Character
 * @v character		Lower-case character
 */
static inline int tolower ( int character ) {

	return ( isupper ( character ) ?
		 ( character - 'A' + 'a' ) : character );
}

/**
 * Convert character to upper case
 *
 * @v character		Character
 * @v character		Upper-case character
 */
static inline int toupper ( int character ) {

	return ( islower ( character ) ?
		 ( character - 'a' + 'A' ) : character );
}

extern int isspace ( int character );

#endif /* _CTYPE_H */
