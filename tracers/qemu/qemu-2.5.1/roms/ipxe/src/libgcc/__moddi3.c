/*
 * arch/i386/libgcc/__moddi3.c
 */

#include "libgcc.h"

__libgcc int64_t __moddi3(int64_t num, int64_t den)
{
  int minus = 0;
  int64_t v;

  if ( num < 0 ) {
    num = -num;
    minus = 1;
  }
  if ( den < 0 ) {
    den = -den;
    minus ^= 1;
  }

  (void) __udivmoddi4(num, den, (uint64_t *)&v);
  if ( minus )
    v = -v;

  return v;
}
