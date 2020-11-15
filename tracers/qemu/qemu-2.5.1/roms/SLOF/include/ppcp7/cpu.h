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

#ifndef __CPU_H
#define __CPU_H

/* Used in boot_abort.S, will need something better for KVM */
#define HSPRG0  304

/* XXX FIXME: Can be more efficient, no dcbst nor loop needed on P7 */
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

static inline void flush_cache(void* r, long n)
{
	asm volatile(EXPAND(FLUSH_CACHE(%0, %1))
		     : "+r"(r), "+r"(n)
		     :: "memory", "cc", "r0", "ctr");
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

#endif /* __ASSEMBLER__ */

#endif
