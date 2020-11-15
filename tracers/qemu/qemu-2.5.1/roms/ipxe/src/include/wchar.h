#ifndef WCHAR_H
#define WCHAR_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>

typedef void mbstate_t;

/**
 * Convert wide character to multibyte sequence
 *
 * @v buf		Buffer
 * @v wc		Wide character
 * @v ps		Shift state
 * @ret len		Number of characters written
 *
 * This is a stub implementation, sufficient to handle basic ASCII
 * characters.
 */
static inline __attribute__ (( always_inline ))
size_t wcrtomb ( char *buf, wchar_t wc, mbstate_t *ps __unused ) {
	*buf = wc;
	return 1;
}

extern size_t wcslen ( const wchar_t *string );

#endif /* WCHAR_H */
