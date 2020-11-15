#ifndef _LIBGCC_H
#define _LIBGCC_H

#include "asm/types.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef          int SItype     __attribute__ ((mode (SI)));
typedef unsigned int USItype    __attribute__ ((mode (SI)));
typedef          int DItype     __attribute__ ((mode (DI)));
typedef unsigned int UDItype    __attribute__ ((mode (DI)));
typedef int word_type __attribute__ ((mode (__word__)));

uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t *rem);

int64_t __divdi3(int64_t num, int64_t den);
uint64_t __udivdi3(uint64_t num, uint64_t den);

uint64_t __umoddi3(uint64_t num, uint64_t den);

DItype __ashldi3 (DItype u, word_type b);
DItype __lshrdi3 (DItype u, word_type b);
DItype __ashrdi3 (DItype u, word_type b);

// Must be implemented outside:
void __divide_error(void);

#if defined(__arch64__) || defined(__LP64__)
typedef          int TItype     __attribute__ ((mode (TI)));

__uint128_t __udivmodti4(__uint128_t num, __uint128_t den, __uint128_t *rem);

__int128_t __divti3(__int128_t num, __int128_t den);
__uint128_t __udivti3(__uint128_t num, __uint128_t den);

__uint128_t __umodti3(__uint128_t num, __uint128_t den);

TItype __multi3 (TItype u, TItype v);
TItype __negti2 (TItype u);

#endif

#endif /* _LIBGCC_H */
