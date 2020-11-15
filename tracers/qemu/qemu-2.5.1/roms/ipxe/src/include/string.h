#ifndef _STRING_H
#define _STRING_H

/** @file
 *
 * String functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <bits/string.h>

/* Architecture-specific code is expected to provide these functions,
 * but may instead explicitly choose to use the generic versions.
 */
void * memset ( void *dest, int character, size_t len ) __nonnull;
void * memcpy ( void *dest, const void *src, size_t len ) __nonnull;
void * memmove ( void *dest, const void *src, size_t len ) __nonnull;
extern void * generic_memset ( void *dest, int character,
			       size_t len ) __nonnull;
extern void * generic_memcpy ( void *dest, const void *src,
			       size_t len ) __nonnull;
extern void * generic_memmove ( void *dest, const void *src,
				size_t len ) __nonnull;

extern int __pure memcmp ( const void *first, const void *second,
			   size_t len ) __nonnull;
extern void * __pure memchr ( const void *src, int character,
			      size_t len ) __nonnull;
extern void * memswap ( void *dest, void *src, size_t len ) __nonnull;
extern int __pure strcmp ( const char *first, const char *second ) __nonnull;
extern int __pure strncmp ( const char *first, const char *second,
			    size_t max ) __nonnull;
extern size_t __pure strlen ( const char *src ) __nonnull;
extern size_t __pure strnlen ( const char *src, size_t max ) __nonnull;
extern char * __pure strchr ( const char *src, int character ) __nonnull;
extern char * __pure strrchr ( const char *src, int character ) __nonnull;
extern char * __pure strstr ( const char *haystack,
			      const char *needle ) __nonnull;
extern char * strcpy ( char *dest, const char *src ) __nonnull;
extern char * strncpy ( char *dest, const char *src, size_t max ) __nonnull;
extern char * strcat ( char *dest, const char *src ) __nonnull;
extern char * __malloc strdup ( const char *src ) __nonnull;
extern char * __malloc strndup ( const char *src, size_t max ) __nonnull;
extern char * __pure strpbrk ( const char *string,
			       const char *delim ) __nonnull;
extern char * strsep ( char **string, const char *delim ) __nonnull;

extern char * __pure strerror ( int errno );

#endif /* _STRING_H */
