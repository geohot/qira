/** @file
 *
 * gcc sometimes likes to insert implicit calls to memcpy().
 * Unfortunately, there doesn't seem to be any way to prevent it from
 * doing this, or to force it to use the optimised memcpy() as seen by
 * C code; it insists on inserting a symbol reference to "memcpy".  We
 * therefore include wrapper functions just to keep gcc happy.
 *
 */

#include <string.h>

void * gcc_implicit_memcpy ( void *dest, const void *src,
			     size_t len ) asm ( "memcpy" );

void * gcc_implicit_memcpy ( void *dest, const void *src, size_t len ) {
	return memcpy ( dest, src, len );
}
