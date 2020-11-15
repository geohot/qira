/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 *
 * Copyright (C) 2000 Klaus Halfmann <klaus.halfmann@feri.de>
 * Original work 1996-1998 Robert Leslie <rob@mars.org>
 *
 * This file defines some byte swapping function. I did not find this
 * in any standard or linux way.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * $Id: swab.h,v 1.1.1.1 2002/03/05 19:50:29 klaus Exp $
 */

#include "config.h"
#include "libc/byteorder.h"

 /* basic fuction:
    value = swab_inc(ptr);
	ptr is afterwards incremented by sizeof(value)
 */

#ifndef CONFIG_BIG_ENDIAN

#define bswabU16(val) __bswap16(val)

#define bswabU16_inc(ptr) (__extension__ ({ UInt16 v=__bswap16(*((UInt16*) (ptr))); ptr+=sizeof(UInt16);v;}))
#define bswabU32_inc(ptr) (__extension__ ({ UInt32 v=__bswap32(*((UInt32*) (ptr))); ptr+=sizeof(UInt32);v;}))
#define bswabU64_inc(ptr) (__extension__ ({ UInt64 v=__bswap64(*((UInt64*) (ptr))); ptr+=sizeof(UInt64);v;}))

#define bstoreU16_inc(ptr, val) do {(*((UInt16*) (ptr))) = __bswap16(val); ptr+=sizeof(UInt16);} while (0)
#define bstoreU32_inc(ptr, val) do {(*((UInt32*) (ptr))) = __bswap32(val); ptr+=sizeof(UInt32);} while (0)
#define bstoreU64_inc(ptr, val) do {(*((UInt64*) (ptr))) = __bswap64(val); ptr+=sizeof(UInt64);} while (0)

#else // BYTE_ORDER == BIG_ENDIAN

#define bswabU16(val) val

#define bswabU16_inc(ptr) (__extension__ ({ UInt16 v=(*((UInt16*) (ptr))); ptr+=sizeof(UInt16);v;}))
#define bswabU32_inc(ptr) (__extension__ ({ UInt32 v=(*((UInt32*) (ptr))); ptr+=sizeof(UInt32);v;}))
#define bswabU64_inc(ptr) (__extension__ ({ UInt64 v=(*((UInt64*) (ptr))); ptr+=sizeof(UInt64);v;}))

#define bstoreU16_inc(ptr, val) do {(*((UInt16*) (ptr))) = val; ptr+=sizeof(UInt16);} while (0)
#define bstoreU32_inc(ptr, val) do {(*((UInt32*) (ptr))) = val; ptr+=sizeof(UInt32);} while (0)
#define bstoreU64_inc(ptr, val) do {(*((UInt64*) (ptr))) = val; ptr+=sizeof(UInt64);} while (0)

#endif

/* for the sake of compleetness and readability */
#define bswabU8_inc(ptr)	(__extension__ ({ UInt8 v=(*((UInt8*) (ptr))); ptr+=sizeof(UInt8);v;}))
#define bstoreU8_inc(ptr,val)	do {(*((UInt8*) (ptr))) = val; ptr+=sizeof(UInt8);} while (0)
