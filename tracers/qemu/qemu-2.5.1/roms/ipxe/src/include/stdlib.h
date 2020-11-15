#ifndef STDLIB_H
#define STDLIB_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <assert.h>

/*****************************************************************************
 *
 * Numeric parsing
 *
 ****************************************************************************
 */

extern unsigned long strtoul ( const char *string, char **endp, int base );
extern unsigned long long strtoull ( const char *string, char **endp,
				     int base );

/*****************************************************************************
 *
 * Memory allocation
 *
 ****************************************************************************
 */

extern void * __malloc malloc ( size_t size );
extern void * realloc ( void *old_ptr, size_t new_size );
extern void free ( void *ptr );
extern void * __malloc zalloc ( size_t len );

/**
 * Allocate cleared memory
 *
 * @v nmemb		Number of members
 * @v size		Size of each member
 * @ret ptr		Allocated memory
 *
 * Allocate memory as per malloc(), and zero it.
 *
 * This is implemented as a static inline, with the body of the
 * function in zalloc(), since in most cases @c nmemb will be 1 and
 * doing the multiply is just wasteful.
 */
static inline void * __malloc calloc ( size_t nmemb, size_t size ) {
	return zalloc ( nmemb * size );
}

/*****************************************************************************
 *
 * Random number generation
 *
 ****************************************************************************
 */

extern long int random ( void );
extern void srandom ( unsigned int seed );

static inline int rand ( void ) {
	return random();
}

static inline void srand ( unsigned int seed ) {
	srandom ( seed );
}

/*****************************************************************************
 *
 * Miscellaneous
 *
 ****************************************************************************
 */

static inline __attribute__ (( always_inline )) int abs ( int value ) {
	return __builtin_abs ( value );
}

extern int system ( const char *command );
extern __asmcall int main ( void );

#endif /* STDLIB_H */
