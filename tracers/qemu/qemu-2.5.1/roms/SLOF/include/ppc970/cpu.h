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

#ifndef __PPC970_H
#define __PPC970_H

/* SPRs numbers */

#define CTRL_RD 136
#define CTRL_WR 152
#define PVR     287
#define HSPRG0  304
#define HSPRG1  305
#define HIOR    311
#define HID0    1008
#define HID1    1009
#define HID4    1012
#define HID6    1017
#define PIR     1023

#define SETCI(r)	sync; \
			mfspr	r, HID4; \
			sync; \
			rldicl	r, r, 32,0; \
			ori	r, r, 0x0100; \
			rldicl	r, r, 32,0; \
			sync; \
			slbia; \
			mtspr	HID4, r; \
			isync; \
			eieio;

#define CLRCI(r)	sync; \
			mfspr	r, HID4; \
			sync; \
			rldicl	r, r, 32, 0; \
			ori	r, r, 0x0100; \
			xori	r, r, 0x0100; \
			rldicl	r, r, 32, 0; \
			sync; \
			slbia; \
			mtspr	HID4, r; \
			isync; \
			eieio;

/* This macro uses r0 */
#define FLUSH_CACHE(r, n)	add	n, n, r; \
				addi	n, n, 127; \
				rlwinm	r, r, 0,0,24; \
				rlwinm	n, n, 0,0,24; \
				sub	n, n, r; \
				srwi	n, n, 7; \
				mtctr	n; \
			0:	dcbst	0, r; \
				sync; \
				icbi	0, r; \
				sync; \
				isync; \
				addi	r, r, 128; \
				bdnz	0b;

#ifndef __ASSEMBLER__
#define STRINGIFY(x...) #x
#define EXPAND(x) STRINGIFY(x)

static inline void
set_ci(void)
{
	unsigned long tmp;
	asm volatile(EXPAND(SETCI(%0)) : "=r"(tmp) :: "memory", "cc");
}

static inline void
clr_ci(void)
{
	unsigned long tmp;
	asm volatile(EXPAND(CLRCI(%0)) : "=r"(tmp) :: "memory", "cc");
}

static inline void eieio(void)
{
	asm volatile ("eieio":::"memory");
}

static inline void barrier(void)
{
	asm volatile("" : : : "memory");
}
#define cpu_relax() barrier()

static inline void sync(void)
{
	asm volatile ("sync" ::: "memory");
}
#define mb() sync()

static inline void flush_cache(void* r, long n)
{
	asm volatile(EXPAND(FLUSH_CACHE(%0, %1)) : "+r"(r), "+r"(n) :: "memory", "cc", "r0", "ctr");
}

#endif /* __ASSEMBLER__ */

#endif
