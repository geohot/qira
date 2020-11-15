#ifndef _ALLOCA_H
#define _ALLOCA_H

/**
 * @file
 *
 * Temporary memory allocation
 *
 */

#include <stdint.h>

/**
 * Allocate temporary memory from the stack
 *
 * @v size		Size to allocate
 * @ret ptr		Allocated memory
 *
 * This memory will be freed automatically when the containing
 * function returns.  There are several caveats regarding use of
 * alloca(); use it only if you already know what they are.
 */
#define alloca(size) __builtin_alloca ( size )

#endif /* _ALLOCA_H */
