/*
 * arch/i386/libgcc/__divdi3.c
 */

#include "libgcc.h"

__libgcc int64_t __divdi3(int64_t num, int64_t den)
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

  v = __udivmoddi4(num, den, NULL);
  if ( minus )
    v = -v;

  return v;
}
