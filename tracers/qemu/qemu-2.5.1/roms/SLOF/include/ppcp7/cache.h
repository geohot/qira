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

// XXX FIXME: Use proper CI load/store */
#define cache_inhibited_access(type,size) 				\
	static inline type ci_read_##size(type * addr)			\
	{								\
		register uint64_t arg0 asm ("r3");			\
		register uint64_t arg1 asm ("r4");			\
		register uint64_t arg2 asm ("r5");			\
									\
		arg0 = 0x3c; /* H_LOGICAL_CI_LOAD*/			\
		arg1 = size / 8;					\
		arg2 = (uint64_t)addr;					\
									\
		asm volatile(						\
			".long	0x44000022 \n"  /* HVCALL */		\
			: "=&r" (arg0), "=&r"(arg1), "=&r"(arg2)	\
			: "0"(arg0), "1"(arg1), "2"(arg2)		\
			: "r0", "r6", "r7", "r8", "r9", "r10", "r11",	\
			  "r12", "memory", "cr0", "cr1", "cr5",		\
			  "cr6", "cr7", "ctr", "xer");			\
		return arg0 ? (type)-1 : arg1;				\
	}								\
	static inline void ci_write_##size(type * addr, type data)	\
	{								\
		register uint64_t arg0 asm ("r3");			\
		register uint64_t arg1 asm ("r4");			\
		register uint64_t arg2 asm ("r5");			\
		register uint64_t arg3 asm ("r6");			\
									\
		arg0 = 0x40; /* H_LOGICAL_CI_STORE*/			\
		arg1 = size / 8;					\
		arg2 = (uint64_t)addr;					\
		arg3 = (uint64_t)data;					\
									\
		asm volatile(						\
			".long	0x44000022 \n"  /* HVCALL */		\
			: "=&r"(arg0),"=&r"(arg1),"=&r"(arg2),"=&r"(arg3) \
			: "0"(arg0),"1"(arg1),"2"(arg2),"3"(arg3)	\
			: "r0", "r7", "r8", "r9", "r10", "r11",		\
			  "r12", "memory", "cr0", "cr1", "cr5",		\
			  "cr6", "cr7", "ctr", "xer");			\
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
	case 0:			_MOVE(s, d, size, type_u); break;	\
	case 4:			_MOVE(s, d, size, type_l); break;	\
	case 2: case 6:		_MOVE(s, d, size, type_w); break;	\
	default:		_MOVE(s, d, size, type_c); break;	\
	}

static inline void ci_rmove(void *dst, void *src, unsigned long esize,
			    unsigned long count)
{
	register uint64_t arg0 asm ("r3");
	register uint64_t arg1 asm ("r4");
	register uint64_t arg2 asm ("r5");
	register uint64_t arg3 asm ("r6");
	register uint64_t arg4 asm ("r7");
	register uint64_t arg5 asm ("r8");

	arg0 = 0xf001; /* KVMPPC_H_LOGICAL_MEMOP */
	arg1 = (uint64_t)dst;
	arg2 = (uint64_t)src;
	arg3 = esize;
	arg4 = count;
	arg5 = 0; /* 0 = copy */

	asm volatile(".long	0x44000022 \n"  /* HVCALL */
		     : "=&r"(arg0),"=&r"(arg1),"=&r"(arg2),
		       "=&r"(arg3),"=&r"(arg4),"=&r"(arg5)
		     : "0"(arg0),"1"(arg1),"2"(arg2),
		       "3"(arg3),"4"(arg4),"5"(arg5)
		     : "r0", "r9", "r10", "r11",
		       "r12", "memory", "cr0", "cr1", "cr5",
		       "cr6", "cr7", "ctr", "xer");
}

#define _FASTRMOVE(s, d, size) do {					      \
		switch (((type_u)s | (type_u)d | size) & (sizeof(type_u)-1)) {\
		case 0:			ci_rmove(d,s,3,size>>3); break;	      \
		case 4:			ci_rmove(d,s,2,size>>2); break;	      \
		case 2: case 6:		ci_rmove(d,s,1,size>>1); break;	      \
		default:		ci_rmove(d,s,0,size); break;	      \
		}							      \
	} while(0)

#define FAST_MRMOVE(s, d, size) _FASTRMOVE(s, d, size)

#define FAST_RFILL(dst, size, pat) do { \
		type_u buf[64]; \
		char *d = (char *)(dst); \
		memset(buf, pat, size < sizeof(buf) ? size : sizeof(buf)); \
		while (size > sizeof(buf)) { \
			FAST_MRMOVE(buf, d, sizeof(buf)); \
			d += sizeof(buf); \
			size -= sizeof(buf); \
		} \
		FAST_MRMOVE(buf, d, size); \
	} while(0)

static inline uint16_t bswap16_load(uint64_t addr)
{
	unsigned int val;
	asm volatile ("lhbrx %0, 0, %1":"=r" (val):"r"(addr));
	return val;
}

static inline uint32_t bswap32_load(uint64_t addr)
{
	unsigned int val;
	asm volatile ("lwbrx %0, 0, %1":"=r" (val):"r"(addr));
	return val;
}

static inline void bswap16_store(uint64_t addr, uint16_t val)
{
	asm volatile ("sthbrx %0, 0, %1"::"r" (val), "r"(addr));
}

static inline void bswap32_store(uint64_t addr, uint32_t val)
{
	asm volatile ("stwbrx %0, 0, %1"::"r" (val), "r"(addr));
}

#endif /* __CACHE_H */

