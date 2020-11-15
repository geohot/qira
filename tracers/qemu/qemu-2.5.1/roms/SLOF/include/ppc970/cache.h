/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef __CACHE_H
#define __CACHE_H

#include <cpu.h>
#include <stdint.h>

#define cache_inhibited_access(type,name) 			\
	static inline type ci_read_##name(type * addr)		\
	{							\
		type val;					\
		set_ci();					\
		val = *addr;					\
		clr_ci();					\
		return val;					\
	}							\
	static inline void ci_write_##name(type * addr, type data)	\
	{							\
		set_ci();					\
		*addr = data;					\
		clr_ci();					\
	}

cache_inhibited_access(uint8_t,  8)
cache_inhibited_access(uint16_t, 16)
cache_inhibited_access(uint32_t, 32)
cache_inhibited_access(uint64_t, 64)

#define _FWOVERLAP(s, d, size) ((d >= s) && ((type_u)d < ((type_u)s + size)))

// 3.1
#define _FWMOVE(s, d, size, t)	\
	{ t *s1=(t *)s, *d1=(t *)d; \
		while (size > 0) { *d1++ = *s1++; size -= sizeof(t); } }

#define _BWMOVE(s, d, size, t)	{ \
	t *s1=(t *)((char *)s+size), *d1=(t *)((char *)d+size); \
	while (size > 0) { *--d1 = *--s1; size -= sizeof(t); } \
}


#define	_MOVE(s, d, size, t) if _FWOVERLAP(s, d, size) _BWMOVE(s, d, size, t) else  _FWMOVE(s, d, size, t)

#define _FASTMOVE(s, d, size) \
	switch (((type_u)s | (type_u)d | size) & (sizeof(type_u)-1)) { \
		case 0:			_MOVE(s, d, size, type_u); break; \
		case 4:			_MOVE(s, d, size, type_l); break; \
		case 2: case 6:		_MOVE(s, d, size, type_w); break; \
		default:		_MOVE(s, d, size, type_c); break; \
	}

// Device IO block data helpers
#define _FWRMOVE(s, d, size, t)	\
	{ t *s1=(t *)s, *d1=(t *)d; SET_CI; \
		while (size > 0) { *d1++ = *s1++; size -= sizeof(t); } \
		CLR_CI; \
}

#define _BWRMOVE(s, d, size, t)	{ \
	t *s1=(t *)((char *)s+size), *d1=(t *)((char *)d+size); SET_CI; \
	while (size > 0) { *--d1 = *--s1; size -= sizeof(t); } \
		CLR_CI; \
}

#define	_RMOVE(s, d, size, t) if _FWOVERLAP(s, d, size) _BWRMOVE(s, d, size, t) else  _FWRMOVE(s, d, size, t)

#define _FASTRMOVE(s, d, size) \
	switch (((type_u)s | (type_u)d | size) & (sizeof(type_u)-1)) { \
		case 0:			_RMOVE(s, d, size, type_u); break; \
		case 4:			_RMOVE(s, d, size, type_l); break; \
		case 2: case 6:		_RMOVE(s, d, size, type_w); break; \
		default:		_RMOVE(s, d, size, type_c); break; \
	}

/* main RAM to IO memory move */
#define FAST_MRMOVE_TYPED(s, d, size, t)	\
{ \
	t *s1 = (s), *d1 = (d); \
	register t tmp; \
	while (size > 0) { \
		tmp = *s1++; SET_CI; *d1++ = tmp; CLR_CI; size -= sizeof(t); \
	} \
}

#define FAST_MRMOVE(s, d, size) \
	switch (((type_u)(s) | (type_u)(d) | (size)) & (sizeof(type_u)-1)) { \
	case 0:		FAST_MRMOVE_TYPED(s, d, size, type_u); break; \
	case 4:		FAST_MRMOVE_TYPED(s, d, size, type_l); break; \
	case 2: case 6:	FAST_MRMOVE_TYPED(s, d, size, type_w); break; \
	default:	FAST_MRMOVE_TYPED(s, d, size, type_c); break; \
	}

/* fill IO memory with pattern */
#define FAST_RFILL_TYPED(dst, size, pat, t) \
{ \
	t *d1 = (dst); \
	register t tmp = 0; \
	int i = sizeof(t); \
	while (i-- > 0) { \
		tmp <<= 8; tmp |= pat & 0xff; \
	} \
	SET_CI; \
	while (size > 0) { \
		*d1++ = tmp; size -= sizeof(t); \
	} \
	CLR_CI; \
}

#define FAST_RFILL(dst, size, pat) \
	switch (((type_u)dst | size) & (sizeof(type_u)-1)) { \
	case 0:		FAST_RFILL_TYPED(dst, size, pat, type_u); break; \
	case 4:		FAST_RFILL_TYPED(dst, size, pat, type_l); break; \
	case 2: case 6:	FAST_RFILL_TYPED(dst, size, pat, type_w); break; \
	default:	FAST_RFILL_TYPED(dst, size, pat, type_c); break; \
	}

#endif
