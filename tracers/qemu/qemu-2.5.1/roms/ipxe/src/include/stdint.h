#ifndef _STDINT_H
#define _STDINT_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/*
 * This is a standard predefined macro on all gcc's I've seen. It's
 * important that we define size_t in the same way as the compiler,
 * because that's what it's expecting when it checks %zd/%zx printf
 * format specifiers.
 */
#ifndef __SIZE_TYPE__
#define __SIZE_TYPE__ unsigned long /* safe choice on most systems */
#endif

#include <bits/stdint.h>

typedef int8_t s8;
typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;

typedef int8_t int8;
typedef uint8_t uint8;
typedef int16_t int16;
typedef uint16_t uint16;
typedef int32_t int32;
typedef uint32_t uint32;
typedef int64_t int64;
typedef uint64_t uint64;

#endif /* _STDINT_H */
