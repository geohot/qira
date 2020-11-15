/*
 *   Creation Date: <2000/10/29 01:43:29 samuel>
 *   Time-stamp: <2003/07/27 22:37:49 samuel>
 *
 *	<processor.h>
 *
 *	Extract from <asm/processor.h>
 *
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_PROCESSOR
#define _H_PROCESSOR


#define PTE0_VSID(s)	(((s)>>7) & 0xffffff)
#define PTE0_V		BIT(0)
#define PTE0_H		BIT(25)
#define PTE0_API	0x3f

#define PTE1_R		BIT(23)
#define PTE1_C		BIT(24)
#define PTE1_W		BIT(25)
#define PTE1_I		BIT(26)
#define PTE1_M		BIT(27)
#define PTE1_G		BIT(28)
#define PTE1_WIMG	(PTE1_W | PTE1_I | PTE1_M | PTE1_G)
#define PTE1_PP		0x3
#define PTE1_RPN	(~0xfffUL)

#define VSID_Ks		BIT(1)
#define VSID_Kp		BIT(2)
#define VSID_N		BIT(3)



#ifndef MSR_VEC

#define MSR_SF      (1 << 63)   /* Sixty-Four Bit Mode */

#define MSR_VEC		(1<<25)		/*  6: Enable AltiVec */
#define MSR_POW		(1<<18)		/* 13: Enable Power Management */
#define MSR_TGPR	(1<<17)		/* 14: TLB Update registers in use */
#define MSR_ILE		(1<<16)		/* 15: Interrupt Little Endian */
#define MSR_EE		(1<<15)		/* 16: External Interrupt Enable */
#define MSR_PR		(1<<14)		/* 17: Privilege Level */
#define MSR_FP		(1<<13)		/* 18: Floating Point enable */
#define MSR_ME		(1<<12)		/* 19: Machine Check Enable */
#define MSR_FE0		(1<<11)		/* 20: Floating Exception mode 0 */
#define MSR_SE		(1<<10)		/* 21: Single Step */
#define MSR_BE		(1<<9)		/* 22: Branch Trace */
#define MSR_FE1		(1<<8)		/* 23: Floating Exception mode 1 */
#define MSR_IP		(1<<6)		/* 25: Exception prefix 0x000/0xFFF */
#define MSR_IR		(1<<5) 		/* 26: Instruction Relocate */
#define MSR_DR		(1<<4) 		/* 27: Data Relocate */
#define MSR_PE		(1<<2)		/* 29: Performance Monitor Flag */
#define MSR_RI		(1<<1)		/* 30: Recoverable Exception */
#define MSR_LE		(1<<0) 		/* 31: Little Endian */

#endif /* MSR_VEC */

#ifndef S_SPRG0

#define NUM_SPRS	1024
//#define S_XER		1
#define S_RTCU_R    	4	/* 601 RTC Upper/Lower (Reading) */
#define S_RTCL_R       	5
//#define S_LR		8
//#define S_CTR		9
#define	S_DSISR		18	/* Source Instruction Service Register */
#define S_DAR		19	/* Data Address Register */
#define S_RTCU_W    	20	/* 601 RTC Upper/Lower (Writing) */
#define S_RTCL_W       	21
#define S_DEC		22	/* Decrementer Register */
#define S_SDR1		25	/* Table Search Description Register */
#define S_SRR0		26	/* Save and Restore Register 0 */
#define S_SRR1		27	/* Save and Restore Register 1 */
#define S_VRSAVE	256	/* (AltiVec) Vector Register Save Register */
#define S_TBRL		268	/* Time base Upper/Lower (Reading) */
#define S_TBRU		269
#define S_SPRG0		272	/* SPR General 0-3 */
#define S_SPRG1		273
#define S_SPRG2		274
#define S_SPRG3		275
#define S_SPRG4		276	/* SPR General 4-7 (7445/7455) */
#define S_SPRG5		277
#define S_SPRG6		278
#define S_SPRG7		279
#define S_EAR		282	/* External Access Register */
#define S_TBWL		284	/* Time base Upper/Lower (Writing) */
#define S_TBWU		285
#define S_PVR		287	/* Processor Version Register */
#define S_HIOR		311	/* Hardware Interrupt Offset Register */
#define S_IBAT0U	528
#define S_IBAT0L	529
#define S_IBAT1U	530
#define S_IBAT1L	531
#define S_IBAT2U	532
#define S_IBAT2L	533
#define S_IBAT3U	534
#define S_IBAT3L	535
#define S_DBAT0U	536
#define S_DBAT0L	537
#define S_DBAT1U	538
#define S_DBAT1L	539
#define S_DBAT2U	540
#define S_DBAT2L	541
#define S_DBAT3U	542
#define S_DBAT3L	543
#define S_UMMCR2	928
#define S_UPMC5		929	/* User Performance Monitor Counter Register */
#define S_UPMC6		930
#define S_UBAMR		935
#define S_UMMCR0	936	/* User Monitor Mode Control Register */
#define S_UPMC1		937
#define S_UPMC2		938
#define S_USIAR		939	/* User Sampled Instruction Address Register */
#define S_UMMCR1	940
#define S_UPMC3		941
#define S_UPMC4		942	/* User Performance Monitor Counter Register 4 */
#define S_USDAR		943	/* User Sampled Data Address Register */
#define S_MMCR2		944	/* Monitor Mode Control Register */
#define S_PMC5		945
#define S_PMC6		946
#define S_BAMR		951	/* Breakpoint Address Mask Register (74xx) */
#define S_MMCR0		952	/* Monitor Mode Control Register 0 */
#define S_PMC1		953	/* Performance Counter Register */
#define S_PMC2		954
#define S_SIAR		955	/* Sampled Instruction Address Register */
#define S_MMCR1		956
#define S_PMC3		957
#define S_PMC4		958
#define S_SDAR		959	/* Sampled Data Address Register */
#define S_DMISS		976	/* 603 */
#define S_DCMP		977	/* 603 */
#define S_HASH1		978	/* 603 */
#define S_HASH2		979	/* 603 */
#define S_IMISS		980	/* 603 */
#define S_TLBMISS	980	/* 7445/7455 */
#define S_ICMP		981	/* 603 */
#define S_PTEHI		981	/* 7445/7455 */
#define S_RPA		982	/* 603 */
#define S_PTELO		982	/* 7445/7455 */
#define S_L3PM		983	/* L3 Private Memory Address Control Register */
#define S_L3ITCR0	984	/* ??? */
#define S_L3OHCR	1000	/* ??? */
#define S_L3ITCR1	1001	/* ??? */
#define S_L3ITCR2	1002	/* ??? */
#define S_L3ITCR3	1003	/* ??? */
#define S_HID0		1008	/* Hardware Implementation Registers */
#define S_HID1		1009
#define S_HID2		1010
#define S_IABR		S_HID2	/* HID2 - Instruction Address Breakpoint Register */
#define S_ICTRL		1011	/* HID3 - Instruction Cache & Interrupt control reg */
#define S_HID4		1012	/* HID4 - Instruction Address Compare 1 (?) */
#define S_HID5		1013
#define S_DABR		S_HID5	/* HID5 - Data Address Breakpoint */
#define S_MSSCR0	1014	/* HID6 - Memory Subsystem Control Register 0 */
#define S_MSSCR1	1015	/* HID7 - Memory Subsystem Control Register 1 */
#define S_LDSTCR	1016	/* HID8 - Load/Store Control Register */
#define S_L2CR		1017	/* HID9 - Level 2 Cache Control Regsiter */
#define S_L3CR		1018	/* HID10 - Level 3 Cache Control Regsiter (7450) */
#define S_HID11		1019
#define S_ICTC		S_HID11	/* HID11 - Instruction Cache Throttling Control Reg */
#define S_ICCR		S_HID11 /* Instruction Cache Cacheability Reigster */
#define S_THRM1		1020	/* HID12 - Thermal Management Register 1 */
#define S_THRM2		1021	/* HID13 - Thermal Management Register 2 */
#define S_THRM3		1022	/* HID14 - Thermal Management Register 3 */
#define S_HID15		1023
#define S_PIR		S_HID15	/* HID15 - Processor Identification Register */

#endif /* S_SPRG0 */

/* the kernel might define these too... */
#if !defined(__KERNEL__) || defined(__ASSEMBLY__)

/* Floating Point Status and Control Register (FPSCR) Fields */
#define FPSCR_FX	0x80000000	/* FPU exception summary */
#define FPSCR_FEX	0x40000000	/* FPU enabled exception summary */
#define FPSCR_VX	0x20000000	/* Invalid operation summary */
#define FPSCR_OX	0x10000000	/* Overflow exception summary */
#define FPSCR_UX	0x08000000	/* Underflow exception summary */
#define FPSCR_ZX	0x04000000	/* Zero-devide exception summary */
#define FPSCR_XX	0x02000000	/* Inexact exception summary */
#define FPSCR_VXSNAN	0x01000000	/* Invalid op for SNaN */
#define FPSCR_VXISI	0x00800000	/* Invalid op for Inv - Inv */
#define FPSCR_VXIDI	0x00400000	/* Invalid op for Inv / Inv */
#define FPSCR_VXZDZ	0x00200000	/* Invalid op for Zero / Zero */
#define FPSCR_VXIMZ	0x00100000	/* Invalid op for Inv * Zero */
#define FPSCR_VXVC	0x00080000	/* Invalid op for Compare */
#define FPSCR_FR	0x00040000	/* Fraction rounded */
#define FPSCR_FI	0x00020000	/* Fraction inexact */
#define FPSCR_FPRF	0x0001f000	/* FPU Result Flags */
#define FPSCR_FPCC	0x0000f000	/* FPU Condition Codes */
#define FPSCR_VXSOFT	0x00000400	/* Invalid op for software request */
#define FPSCR_VXSQRT	0x00000200	/* Invalid op for square root */
#define FPSCR_VXCVI	0x00000100	/* Invalid op for integer convert */
#define FPSCR_VE	0x00000080	/* Invalid op exception enable */
#define FPSCR_OE	0x00000040	/* IEEE overflow exception enable */
#define FPSCR_UE	0x00000020	/* IEEE underflow exception enable */
#define FPSCR_ZE	0x00000010	/* IEEE zero divide exception enable */
#define FPSCR_XE	0x00000008	/* FP inexact exception enable */
#define FPSCR_NI	0x00000004	/* FPU non IEEE-Mode */
#define FPSCR_RN	0x00000003	/* FPU rounding control */

/* SPR_HID0 */
#define	HID0_EMCP	(1<<31)		/* Enable Machine Check pin */
#define	HID0_EBA	(1<<29)		/* Enable Bus Address Parity */
#define	HID0_EBD	(1<<28)		/* Enable Bus Data Parity */
#define	HID0_SBCLK	(1<<27)
#define	HID0_EICE	(1<<26)
#define	HID0_ECLK	(1<<25)
#define	HID0_PAR	(1<<24)
#define	HID0_DOZE	(1<<23)
#define	HID0_NAP	(1<<22)
#define	HID0_SLEEP	(1<<21)
#define	HID0_DPM	(1<<20)
#define	HID0_NHR	(1<<16)		/* Not Hard Reset */
#define	HID0_ICE	(1<<15)		/* Instruction Cache Enable */
#define	HID0_DCE	(1<<14)		/* Data Cache Enable */
#define	HID0_ILOCK	(1<<13)		/* Instruction Cache Lock */
#define	HID0_DLOCK	(1<<12)		/* Data Cache Lock */
#define	HID0_ICFI	(1<<11)		/* Instr. Cache Flash Invalidate */
#define	HID0_DCFI	(1<<10)		/* Data Cache Flash Invalidate */
#define HID0_SPD	(1<<9)		/* Speculative disable */
#define HID0_SGE	(1<<7)		/* Store Gathering Enable */
#define	HID0_SIED	(1<<7)		/* Serial Instr. Execution [Disable] */
#define HID0_BTIC	(1<<5)		/* Branch Target Instruction Cache Enable */
#define HID0_ABE	(1<<3)		/* Address Broadcast Enable */
#define	HID0_BHT	(1<<2)		/* Branch History Table Enable */
#define	HID0_BTCD	(1<<1)		/* Branch target cache disable */

#define L2CR_L2E	BIT(0)		/* L2 enable */
#define L2CR_L2PE	BIT(1)		/* L2 data parity generation and checking */
#define L2CR_L2SIZ_512K	BIT(2)
#define L2CR_L2SIZ_256K	BIT(3)
#define L2CR_L2SIZ_1MB	(BIT(2)|BIT(3))
#define L2CR_L2CLK_1	BIT(6)		/* L2 clock ration */
#define L2CR_L2CLK_15	(BIT(6)*2)
#define L2CR_L2CLK_2	(BIT(6)*4)
#define L2CR_L2CLK_25	(BIT(6)*5)
#define L2CR_L2CLK_3	(BIT(6)*6)
#define L2CR_L2RAM_FT	0		/* flow-through (reg-buf) synchronous SRAM */
#define L2CR_L2RAM_PB	BIT(7)		/* Piplined (reg-reg) synchronous burst SRAM */
#define L2CR_L2RAM_PLW	(BIT(7)|BIT(8))	/* Piplined (reg-reg) synchronous late-write */
#define L2CR_L2DO	BIT(9)		/* L2 data-only */
#define L2CR_L2I	BIT(10)		/* L2 global invalidate */
#define L2CR_L2CTL	BIT(11)		/* L2 RAM control (ZZ enable, low-power mode) */
#define L2CR_L2WT	BIT(12)		/* L2 write-through */
#define L2CR_L2TS	BIT(13)		/* L2 test support */
#define L2CR_L2OH_05	0		/* L2 output hold 0.5 nS */
#define L2CR_L2OH_10	BIT(15)		/* L2 output hold 1.0 nS */
#define L2CR_L2SL	BIT(16)		/* L2 DLL slow (use if bus freq < 150 MHz) */
#define L2CR_L2DF	BIT(17)		/* L2 differential clock */
#define L2CR_L2BYP	BIT(18)		/* L2 DLL bypass */
#define L2CR_L2IP	BIT(31)		/* L2 global invalidate in progress */

/* SPR_THRM1 */
#define THRM1_TIN	(1 << 31)
#define THRM1_TIV	(1 << 30)
#define THRM1_THRES(x)	((x&0x7f)<<23)
#define THRM3_SITV(x)	((x&0x3fff)<<1)
#define THRM1_TID	(1<<2)
#define THRM1_TIE	(1<<1)
#define THRM1_V		(1<<0)

/* SPR_THRM3 */
#define THRM3_E		(1<<0)

/* Processor Version Numbers */

#define	PVR_VER(pvr)  (((pvr) >>  16) & 0xFFFF)	/* Version field */
#define	PVR_REV(pvr)  (((pvr) >>   0) & 0xFFFF)	/* Revison field */

#define	PVR_403GA	0x00200000
#define	PVR_403GB	0x00200100
#define	PVR_403GC	0x00200200
#define	PVR_403GCX	0x00201400
#define	PVR_405GP	0x40110000
#define	PVR_601		0x00010000
#define	PVR_602		0x00050000
#define	PVR_603		0x00030000
#define	PVR_603e	0x00060000
#define	PVR_603ev	0x00070000
#define	PVR_603r	0x00071000
#define	PVR_604		0x00040000
#define	PVR_604e	0x00090000
#define	PVR_604r	0x000A0000
#define	PVR_620		0x00140000
#define	PVR_740		0x00080000
#define	PVR_750		PVR_740
#define	PVR_740P	0x10080000
#define	PVR_750P	PVR_740P
#define	PVR_821		0x00500000
#define	PVR_823		PVR_821
#define	PVR_850		PVR_821
#define	PVR_860		PVR_821
#define	PVR_7400       	0x000C0000
#define	PVR_8240	0x00810100
#define	PVR_8260	PVR_8240

/* Vector VSCR register */
#define VSCR_NJ	0x10000
#define VSCR_SAT 0x1

#endif /* __KERNEL__ */


#ifdef __ASSEMBLY__

#define	CTR	S_CTR		/* Counter Register */
#define	DAR	S_DAR		/* Data Address Register */
#define	DABR	S_DABR		/* Data Address Breakpoint Register */
#define	DBAT0L	S_DBAT0L	/* Data BAT 0 Lower Register */
#define	DBAT0U	S_DBAT0U	/* Data BAT 0 Upper Register */
#define	DBAT1L	S_DBAT1L	/* Data BAT 1 Lower Register */
#define	DBAT1U	S_DBAT1U	/* Data BAT 1 Upper Register */
#define	DBAT2L	S_DBAT2L	/* Data BAT 2 Lower Register */
#define	DBAT2U	S_DBAT2U	/* Data BAT 2 Upper Register */
#define	DBAT3L	S_DBAT3L	/* Data BAT 3 Lower Register */
#define	DBAT3U	S_DBAT3U	/* Data BAT 3 Upper Register */
#define	DCMP	S_DCMP      	/* Data TLB Compare Register */
#define	DEC	S_DEC       	/* Decrement Register */
#define	DMISS	S_DMISS     	/* Data TLB Miss Register */
#define	DSISR	S_DSISR		/* Data Storage Interrupt Status Register */
#define	EAR	S_EAR       	/* External Address Register */
#define	HASH1	S_HASH1		/* Primary Hash Address Register */
#define	HASH2	S_HASH2		/* Secondary Hash Address Register */
#define	HID0	S_HID0		/* Hardware Implementation Register 0 */
#define	HID1	S_HID1	/* Hardware Implementation Register 1 */
#define	IABR	S_IABR      	/* Instruction Address Breakpoint Register */
#define	IBAT0L	S_IBAT0L	/* Instruction BAT 0 Lower Register */
#define	IBAT0U	S_IBAT0U	/* Instruction BAT 0 Upper Register */
#define	IBAT1L	S_IBAT1L	/* Instruction BAT 1 Lower Register */
#define	IBAT1U	S_IBAT1U	/* Instruction BAT 1 Upper Register */
#define	IBAT2L	S_IBAT2L	/* Instruction BAT 2 Lower Register */
#define	IBAT2U	S_IBAT2U	/* Instruction BAT 2 Upper Register */
#define	IBAT3L	S_IBAT3L	/* Instruction BAT 3 Lower Register */
#define	IBAT3U	S_IBAT3U	/* Instruction BAT 3 Upper Register */
#define	ICMP	S_ICMP	/* Instruction TLB Compare Register */
#define	IMISS	S_IMISS	/* Instruction TLB Miss Register */
#define	IMMR	S_IMMR      	/* PPC 860/821 Internal Memory Map Register */
#define	L2CR	S_L2CR    	/* PPC 750 L2 control register */
#define	PVR	S_PVR	/* Processor Version */
#define	RPA	S_RPA	/* Required Physical Address Register */
#define	SDR1	S_SDR1      	/* MMU hash base register */
#define	SPR0	S_SPRG0	/* Supervisor Private Registers */
#define	SPR1	S_SPRG1
#define	SPR2	S_SPRG2
#define	SPR3	S_SPRG3
#define	SPRG0   S_SPRG0
#define	SPRG1   S_SPRG1
#define	SPRG2   S_SPRG2
#define	SPRG3   S_SPRG3
#define	SRR0	S_SRR0		/* Save and Restore Register 0 */
#define	SRR1	S_SRR1		/* Save and Restore Register 1 */
#define	TBRL	S_STBRL		/* Time Base Read Lower Register */
#define	TBRU	S_TBRU		/* Time Base Read Upper Register */
#define	TBWL	S_TBWL		/* Time Base Write Lower Register */
#define	TBWU	S_TBWU		/* Time Base Write Upper Register */
#define ICTC	S_ICTC
#define	THRM1	S_THRM1		/* Thermal Management Register 1 */
#define	THRM2	S_THRM2		/* Thermal Management Register 2 */
#define	THRM3	S_THRM3		/* Thermal Management Register 3 */
#define SIAR	S_SIAR
#define SDAR	S_SDAR
#define	XER	1

#define	SR0	0		/* Segment registers */
#define	SR1	1
#define	SR2	2
#define	SR3	3
#define	SR4	4
#define	SR5	5
#define	SR6	6
#define	SR7	7
#define	SR8	8
#define	SR9	9
#define	SR10	10
#define	SR11	11
#define	SR12	12
#define	SR13	13
#define	SR14	14
#define	SR15	15

#endif /* __ASSEMBLY__ */

/* opcode macros */

#define OPCODE_PRIM(n)		( ((unsigned long)(n)) >> 26 )
#define OPCODE_EXT(n)		( (((unsigned long)(n)) >> 1) & 0x3ff )
#define OPCODE(op,op_ext)	( ((op)<<10) + op_ext )

#define	B1(n)			( (((unsigned long)(n)) >> 21) & 0x1f )
#define	B2(n)			( (((unsigned long)(n)) >> 16) & 0x1f )
#define	B3(n)			( (((unsigned long)(n)) >> 11) & 0x1f )

#define BD(n)	((unsigned long)((n) & 0x7fff) + (((n) & 0x8000) ? (unsigned long)0xffff8000 : 0))

#define SPRNUM_FLIP( v )	( (((v)>>5) & 0x1f) | (((v)<<5) & 0x3e0) )

/* C helpers */

#ifndef __ASSEMBLER__

#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)
#define mtspr(rn, v)		asm volatile("mtspr " __stringify(rn) ",%0" : : "r" (v))

static inline unsigned long mfmsr(void)
{
    unsigned long msr;
    asm volatile("mfmsr %0" : "=r" (msr));
    return msr;
}

static inline void mtmsr(unsigned long msr)
{
#ifdef __powerpc64__
    asm volatile("mtmsrd %0" :: "r" (msr));
#else
    asm volatile("mtmsr  %0" :: "r" (msr));
#endif
}

#ifdef __powerpc64__
#define SDR1_HTABORG_MASK 0x3FFFFFFFFFFC0000UL
#else
#define SDR1_HTABORG_MASK 0xffff0000
#endif

static inline unsigned long mfsdr1(void)
{
    unsigned long sdr1;
    asm volatile("mfsdr1 %0" : "=r" (sdr1));
    return sdr1;
}

static inline void mtsdr1(unsigned long sdr1)
{
    asm volatile("mtsdr1 %0" :: "r" (sdr1));
}

static inline unsigned int mfpvr(void)
{
    unsigned int pvr;
    asm volatile("mfspr %0, 0x11f" : "=r" (pvr) );
    return pvr;
}

static inline void slbia(void)
{
    asm volatile("slbia" ::: "memory");
}

static inline void slbmte(unsigned long rs, unsigned long rb)
{
    asm volatile("slbmte %0,%1 ; isync" :: "r" (rs), "r" (rb) : "memory");
}

#endif /* !__ASSEMBLER__ */

#endif   /* _H_PROCESSOR */
