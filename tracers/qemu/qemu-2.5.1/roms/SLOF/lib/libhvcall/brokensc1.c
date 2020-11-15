#include <stdint.h>
#include <stddef.h>
#include <cpu.h>
#include "libhvcall.h"
#include "byteorder.h"

// #define DEBUG_PATCHERY

#define H_SET_DABR	0x28
#define INS_SC1		0x44000022
#define INS_SC1_REPLACE	0x7c000268

extern volatile uint32_t sc1ins;

static unsigned long hcall(uint32_t inst, unsigned long arg0, unsigned long arg1)
{
	register unsigned long r3 asm("r3") = arg0;
	register unsigned long r4 asm("r4") = arg1;
	register unsigned long r5 asm("r5") = inst;
	asm volatile("bl 1f		\n"
		     "1:		\n"
		     "li 11, 2f - 1b	\n"
		     "mflr 12		\n"
		     "add 11, 11, 12	\n"
		     "stw 5, 0(11)	\n"
		     "dcbst 0, 11	\n"
		     "sync		\n"
		     "icbi 0, 11	\n"
		     "isync		\n"
		     "2:		\n"
		     ".long 0		\n"
                     : "=r" (r3)
                     : "r" (r3), "r" (r4), "r" (r5)
                     : "ctr", "r0", "r6", "r7", "r8", "r9", "r10", "r11",
                       "r12", "r13", "r31", "lr", "cc");
	return r3;
}

static int check_broken_sc1(void)
{
	long r;

	/*
	 * Check if we can do a simple hcall. If it works, we are running in
	 * a sane environment and everything's fine. If it doesn't, we need
	 * to patch the hypercall instruction to something that traps into
	 * supervisor mode.
	 */
	r = hcall(INS_SC1, H_SET_DABR, 0);
	if (r == H_SUCCESS || r == H_HARDWARE) {
		/* All is fine */
		return 0;
	}

	/* We found a broken sc1 host! */
	return 1;
}

int patch_broken_sc1(void *start, void *end, uint32_t *test_ins)
{
	uint32_t *p;
	/* The sc 1 instruction */
	uint32_t sc1 = INS_SC1;
	/* An illegal instruction that KVM interprets as sc 1 */
	uint32_t sc1_replacement = INS_SC1_REPLACE;
	int is_le = (test_ins && *test_ins == 0x48000008);
#ifdef DEBUG_PATCHERY
	int cnt = 0;
#endif

	/* The host is sane, get out of here */
	if (!check_broken_sc1())
		return 0;

	/* We only get here with a broken sc1 implementation */

	/* Trim the range we scan to not cover the data section */
	if (test_ins) {
		/* This is the cpu table matcher for 970FX */
		uint32_t end_bytes[] = { 0xffff0000, 0x3c0000 };
		/*
		 * The .__start symbol contains a trap instruction followed
		 * by lots of zeros.
		 */
		uint32_t start_bytes[] = { 0x7fe00008, 0, 0, 0, 0 };

		if (is_le) {
			end_bytes[0] = bswap_32(end_bytes[0]);
			end_bytes[1] = bswap_32(end_bytes[1]);
			start_bytes[1] = bswap_32(start_bytes[1]);
		}

		/* Find the start of the text section */
		for (p = test_ins; (long)p > (long)start; p--) {
			if (p[0] == start_bytes[0] &&
			    p[1] == start_bytes[1] &&
			    p[2] == start_bytes[2] &&
			    p[3] == start_bytes[3] &&
			    p[4] == start_bytes[4]) {
				/*
				 * We found a match of the instruction sequence
				 *     trap
				 *     .long 0
				 *     .long 0
				 *     .long 0
				 *     .long 0
				 * which marks the beginning of the .text
				 * section on all Linux kernels I've checked.
				 */
#ifdef DEBUG_PATCHERY
				printf("Shortened start from %p to %p\n", end, p);
#endif
				start = p;
				break;
			}
		}

		/* Find the end of the text section */
		for (p = start; (long)p < (long)end; p++) {
			if (p[0] == end_bytes[0] && p[1] == end_bytes[1]) {
				/*
				 * We found a match of the PPC970FX entry in the
				 * guest kernel's CPU table. That table is
				 * usually found early in the .data section and
				 * thus marks the end of the .text section for
				 * us which we need to patch.
				 */
#ifdef DEBUG_PATCHERY
				printf("Shortened end from %p to %p\n", end, p);
#endif
				end = p;
				break;
			}
		}
	}

	if (is_le) {
		/*
		 * The kernel was built for LE mode, so our sc1 and replacement
		 * opcodes are in the wrong byte order. Reverse them.
		 */
		sc1 = bswap_32(sc1);
		sc1_replacement = bswap_32(sc1_replacement);
	}

	/* Patch all sc 1 instructions to reserved instruction 31/308 */
	for (p = start; (long)p < (long)end; p++) {
		if (*p == sc1) {
			*p = sc1_replacement;
			flush_cache(p, sizeof(*p));
#ifdef DEBUG_PATCHERY
			cnt++;
#endif
		}
	}

#ifdef DEBUG_PATCHERY
	printf("Patched %d instructions (%p - %p)\n", cnt, start, end);
#endif

	return 1;
}
