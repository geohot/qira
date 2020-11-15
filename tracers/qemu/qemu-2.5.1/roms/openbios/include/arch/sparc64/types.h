/* tag: data types for forth engine
 *
 * Copyright (C) 2003-2005 Patrick Mauritz, Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#ifndef __TYPES_H
#define __TYPES_H

#include "mconfig.h"

#ifdef BOOTSTRAP
#include <inttypes.h>
#else
typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long   uintptr_t;

typedef signed char     int8_t;
typedef short           int16_t;
typedef int             int32_t;
typedef long long       int64_t;
typedef long            intptr_t;

#define PRId32 "d"
#define PRIu32 "u"
#define PRIx32 "x"
#define PRIX32 "X"
#define PRId64 "lld"
#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRIX64 "llX"
#endif

/* endianess */
#include "autoconf.h"

/* physical address */
typedef uint64_t phys_addr_t;

#define FMT_plx "%016" PRIx64

/* cell based types */
typedef int64_t     cell;
typedef uint64_t    ucell;

#define FMT_cell    "%" PRId64
#define FMT_ucell   "%" PRIu64
#define FMT_ucellx  "%016" PRIx64
#define FMT_ucellX  "%016" PRIX64

typedef int64_t         prom_arg_t;
typedef uint64_t        prom_uarg_t;

#define PRIdPROMARG     PRId64
#define PRIuPROMARG     PRIu64
#define PRIxPROMARG     PRIx64
#define FMT_prom_arg    "%" PRIdPROMARG
#define FMT_prom_uarg   "%" PRIuPROMARG
#define FMT_prom_uargx  "%016" PRIxPROMARG

#define FMT_elf	    "%#llx"
#define FMT_sizet   "%lx"
#define FMT_aout_ehdr  "%x"

#ifdef NEED_FAKE_INT128_T
typedef struct {
    uint64_t hi;
    uint64_t lo;
} blob_128_t;

typedef blob_128_t      dcell;
typedef blob_128_t     ducell;
#else
typedef __int128_t	dcell;
typedef __uint128_t    ducell;
#endif

#define bitspercell	(sizeof(cell)<<3)
#define bitsperdcell	(sizeof(dcell)<<3)

#define BITS		64

#define PAGE_SHIFT	13

/* size named types */

typedef unsigned char   u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

typedef signed char	s8;
typedef short		s16;
typedef int		s32;
typedef long long	s64;

#endif
