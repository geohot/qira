/*
 * arch/i386/libgcc/__divdi3.c
 */

#include "libgcc.h"

__uint128_t __udivti3(__uint128_t num, __uint128_t den)
{
  return __udivmodti4(num, den, NULL);
}
