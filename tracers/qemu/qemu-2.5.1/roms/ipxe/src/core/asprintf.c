#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Write a formatted string to newly allocated memory.
 *
 * @v strp		Pointer to hold allocated string
 * @v fmt		Format string
 * @v args		Arguments corresponding to the format string
 * @ret	len		Length of formatted string
 */
int vasprintf ( char **strp, const char *fmt, va_list args ) {
	size_t len;
	va_list args_tmp;

	/* Calculate length needed for string */
	va_copy ( args_tmp, args );
	len = ( vsnprintf ( NULL, 0, fmt, args_tmp ) + 1 );
	va_end ( args_tmp );

	/* Allocate and fill string */
	*strp = malloc ( len );
	if ( ! *strp )
		return -ENOMEM;
	return vsnprintf ( *strp, len, fmt, args );
}

/**
 * Write a formatted string to newly allocated memory.
 *
 * @v strp		Pointer to hold allocated string
 * @v fmt		Format string
 * @v ...		Arguments corresponding to the format string
 * @ret	len		Length of formatted string
 */
int asprintf ( char **strp, const char *fmt, ... ) {
	va_list args;
	int len;

	va_start ( args, fmt );
	len = vasprintf ( strp, fmt, args );
	va_end ( args );
	return len;
}
