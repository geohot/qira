/*
 * arch/i386/libgcc/__umoddi3.c
 */

#include "libgcc.h"

__uint128_t __umodti3(__uint128_t num, __uint128_t den)
{
  __uint128_t v;

  (void) __udivmodti4(num, den, &v);
  return v;
}
