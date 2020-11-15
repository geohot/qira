/* Extracted from gcc-3.4.1/gcc/config/mips/_tilibi.c */
/* A few TImode functions needed for TFmode emulated arithmetic.
   Copyright 2002, 2003 Free Software Foundation, Inc.
   Contributed by Alexandre Oliva <aoliva@redhat.com>

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GCC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include "libgcc.h"

#if defined(__sparc__) || defined(__ppc__)
#define LIBGCC2_WORDS_BIG_ENDIAN
#endif

typedef union
{
  struct TIstruct {
#if defined(LIBGCC2_WORDS_BIG_ENDIAN)
    DItype high, low;
#else
    DItype low, high;
#endif
  } s;
  TItype ll;
} TIunion;

TItype
__negti2 (TItype u)
{
  TIunion w;
  TIunion uu;

  uu.ll = u;

  w.s.low = -uu.s.low;
  w.s.high = -uu.s.high - ((UDItype) w.s.low > 0);

  return w.ll;
}
