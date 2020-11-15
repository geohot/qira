/* muldi3.c extracted from gcc-2.7.2.3/libgcc2.c and
			   gcc-2.7.2.3/longlong.h which is: */
/* Copyright (C) 1989, 1992, 1993, 1994, 1995 Free Software Foundation, Inc.

This file is part of GNU CC.

GNU CC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU CC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU CC; see the file COPYING.  If not, write to
the Free Software Foundation, 51 Franklin St, Fifth Floor, Boston,
MA 02110-1301, USA. */

#include "libgcc.h"

#define BITS_PER_UNIT 8
#define DI_TYPE_SIZE 64

#define __BITS4 (DI_TYPE_SIZE / 4)
#define __ll_B (1L << (DI_TYPE_SIZE / 2))
#define __ll_lowpart(t) ((UDItype) (t) % __ll_B)
#define __ll_highpart(t) ((UDItype) (t) / __ll_B)

#define umul_ppmm(w1, w0, u, v)						\
  do {									\
    UDItype __x0, __x1, __x2, __x3;					\
    UDItype __ul, __vl, __uh, __vh;					\
									\
    __ul = __ll_lowpart (u);						\
    __uh = __ll_highpart (u);						\
    __vl = __ll_lowpart (v);						\
    __vh = __ll_highpart (v);						\
									\
    __x0 = (UDItype) __ul * __vl;					\
    __x1 = (UDItype) __ul * __vh;					\
    __x2 = (UDItype) __uh * __vl;					\
    __x3 = (UDItype) __uh * __vh;					\
									\
    __x1 += __ll_highpart (__x0);/* this can't give carry */		\
    __x1 += __x2;		/* but this indeed can */		\
    if (__x1 < __x2)		/* did we get it? */			\
      __x3 += __ll_B;		/* yes, add it in the proper pos. */	\
									\
    (w1) = __x3 + __ll_highpart (__x1);					\
    (w0) = __ll_lowpart (__x1) * __ll_B + __ll_lowpart (__x0);		\
  } while (0)

#define __umulsidi3(u, v) \
  ({TIunion __w;							\
    umul_ppmm (__w.s.high, __w.s.low, u, v);				\
    __w.ll; })

struct TIstruct {DItype high, low;};

typedef union
{
  struct TIstruct s;
  TItype ll;
} TIunion;

TItype
__multi3 (TItype u, TItype v)
{
  TIunion w;
  TIunion uu, vv;

  uu.ll = u,
  vv.ll = v;

  w.ll = __umulsidi3 (uu.s.low, vv.s.low);
  w.s.high += ((UDItype) uu.s.low * (UDItype) vv.s.high
	       + (UDItype) uu.s.high * (UDItype) vv.s.low);

  return w.ll;
}
