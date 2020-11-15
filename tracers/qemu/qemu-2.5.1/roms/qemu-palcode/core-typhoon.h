/* Memory layout and register descriptions for the TSUNAMI/TYPHOON chipset.

   Copyright (C) 2011 Richard Henderson

   This file is part of QEMU PALcode.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the text
   of the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

#ifndef TYPHOON_H
#define TYPHOON_H 1

/* Assume a 43-bit KSEG for now.  */
#define PIO_PHYS_ADDR   0x80000000000
#define PIO_KSEG_ADDR   (0xfffffc0000000000 + 0x10000000000)

/* CCHIP REGISTERS */

#define TYPHOON_CCHIP		0x1a0000000

#define TYPHOON_CCHIP_CSC	0x0000
#define TYPHOON_CCHIP_MTR	0x0040
#define TYPHOON_CCHIP_MISC	0x0080
#define TYPHOON_CCHIP_MPD	0x00c0
#define TYPHOON_CCHIP_AAR0	0x0100
#define TYPHOON_CCHIP_AAR1	0x0140
#define TYPHOON_CCHIP_AAR2	0x0180
#define TYPHOON_CCHIP_AAR3	0x01c0
#define TYPHOON_CCHIP_DIM0	0x0200
#define TYPHOON_CCHIP_DIM1	0x0240
#define TYPHOON_CCHIP_DIR0	0x0280
#define TYPHOON_CCHIP_DIR1	0x02c0
#define TYPHOON_CCHIP_DRIR	0x0300
#define TYPHOON_CCHIP_PRBEN	0x0340
#define TYPHOON_CCHIP_IIC0	0x0380
#define TYPHOON_CCHIP_IIC1	0x03c0
#define TYPHOON_CCHIP_MPR0	0x0400
#define TYPHOON_CCHIP_MPR1	0x0440
#define TYPHOON_CCHIP_MPR2	0x0480
#define TYPHOON_CCHIP_MPR3	0x04c0
#define TYPHOON_CCHIP_TTR	0x0580
#define TYPHOON_CCHIP_TDR	0x05c0
#define TYPHOON_CCHIP_DIM2	0x0600
#define TYPHOON_CCHIP_DIM3	0x0640
#define TYPHOON_CCHIP_DIR2	0x0680
#define TYPHOON_CCHIP_DIR3	0x06c0
#define TYPHOON_CCHIP_IIC2	0x0700
#define TYPHOON_CCHIP_IIC3	0x0740
#define TYPHOON_CCHIP_PWR	0x0780
#define TYPHOON_CCHIP_CMONCTLA	0x0c00
#define TYPHOON_CCHIP_CMONCTLB	0x0c40
#define TYPHOON_CCHIP_CMONCNT01	0x0c80
#define TYPHOON_CCHIP_CMONCNT23	0x0cc0

/* DCHIP REGISTERS */

#define TYPHOON_DCHIP		0x1b0000000

#define TYPHOON_DCHIP_DSC	0x0800
#define TYPHOON_DCHIP_STR	0x0840
#define TYPHOON_DCHIP_DREV	0x0880
#define TYPHOON_DCHIP_DSC2	0x08c0

/* PCHIP REGISTERS */

#define TYPHOON_PCHIP0		0x180000000
#define TYPHOON_PCHIP1		0x380000000

#define TYPHOON_PCHIP_WSBA0	0x0000
#define TYPHOON_PCHIP_WSBA1	0x0040
#define TYPHOON_PCHIP_WSBA2	0x0080
#define TYPHOON_PCHIP_WSBA3	0x00c0
#define TYPHOON_PCHIP_WSM0	0x0100
#define TYPHOON_PCHIP_WSM1	0x0140
#define TYPHOON_PCHIP_WSM2	0x0180
#define TYPHOON_PCHIP_WSM3	0x01c0
#define TYPHOON_PCHIP_TBA0	0x0200
#define TYPHOON_PCHIP_TBA1	0x0240
#define TYPHOON_PCHIP_TBA2	0x0280
#define TYPHOON_PCHIP_TBA3	0x02c0
#define TYPHOON_PCHIP_PCTL	0x0300
#define TYPHOON_PCHIP_PLAT	0x0340
#define TYPHOON_PCHIP_PERROR	0x03c0
#define TYPHOON_PCHIP_PERRMASK	0x0400
#define TYPHOON_PCHIP_PERRSET	0x0440
#define TYPHOON_PCHIP_TLBIV	0x0480
#define TYPHOON_PCHIP_TLBIA	0x04c0
#define TYPHOON_PCHIP_PMONCTL	0x0500
#define TYPHOON_PCHIP_PMONCNT	0x0540
#define TYPHOON_PCHIP_SPRST	0x0800

/* PCI ADDRESSES */

#define TYPHOON_PCHIP0_PCI_MEM	0
#define TYPHOON_PCHIP0_PCI_IO	0x1fc000000
#define TYPHOON_PCHIP0_PCI_CONF	0x1fe000000
#define TYPHOON_PCHIP0_PCI_IACK	0x1f8000000

#ifdef __ASSEMBLER__

#include "pal.h"

#define	ptCpuDIR	ptSys0
#define	ptCpuIIC	ptSys1

/* Unfortunately, GAS doesn't attempt any interesting constructions of
   64-bit constants, dropping them all into the .lit8 section.  It is
   better for us to build these by hand.  */
.macro	LOAD_PHYS_CCHIP ret
	lda	\ret, (PIO_PHYS_ADDR + TYPHOON_CCHIP) >> 29
	sll	\ret, 29, \ret
.endm

.macro	LOAD_PHYS_PCHIP0 ret
	lda	\ret, (PIO_PHYS_ADDR + TYPHOON_PCHIP0) >> 29
	sll	\ret, 29, \ret
.endm

.macro	LOAD_PHYS_PCHIP0_IACK ret
	.set	macro
	lda	\ret, (PIO_PHYS_ADDR + TYPHOON_PCHIP0_PCI_IACK) >> 24
	.set	nomacro
	sll	\ret, 24, \ret
.endm

.macro	LOAD_KSEG_PCI_IO ret
	.set	macro
	// Note that GAS shifts are logical.  Force arithmetic shift style
	// results by negating before and after the shift.
	lda	\ret, -(-(PIO_KSEG_ADDR + TYPHOON_PCHIP0_PCI_IO) >> 20)
	.set	nomacro
	sll	\ret, 20, \ret
.endm

.macro	LOAD_KSEG_PCI_CONF ret
	.set	macro
	// Note that GAS shifts are logical.  Force arithmetic shift style
	// results by negating before and after the shift.
	lda	\ret, -(-(PIO_KSEG_ADDR + TYPHOON_PCHIP0_PCI_CONF) >> 20)
	.set	nomacro
	sll	\ret, 20, \ret
.endm

.macro	SYS_WHAMI	ret
	LOAD_PHYS_CCHIP	\ret
	ldq_p		\ret, TYPHOON_CCHIP_MISC(\ret)
	and		\ret, 3, \ret
.endm

/* ACK the Interprocessor Interrupt.  */
.macro	SYS_ACK_SMP	t0, t1, t2
	LOAD_PHYS_CCHIP	\t0
	ldq_p		\t1, TYPHOON_CCHIP_MISC(\t0)
	and		\t1, 3, \t1
	addq		\t1, 8, \t1
	lda		\t2, 1
	sll		\t2, \t1, \t2
	stq_p		\t2, TYPHOON_CCHIP_MISC(\t0)
.endm

/* ACK the Clock Interrupt.  */
.macro	SYS_ACK_CLK	t0, t1, t2
	LOAD_PHYS_CCHIP	\t0
	ldq_p		\t1, TYPHOON_CCHIP_MISC(\t0)
	and		\t1, 3, \t1
	addq		\t1, 4, \t1
	lda		\t2, 1
	sll		\t2, \t1, \t2
	stq_p		\t2, TYPHOON_CCHIP_MISC(\t0)
.endm

/* Interrupt another CPU.  */
.macro SYS_WRIPIR	target, t0, t1, t2
	LOAD_PHYS_CCHIP	\t0
	mov		1, \t1
	and		\target, 3, \t2
	addq		\t2, 12, \t2
	sll		\t1, \t2, \t1
	stq_p		\t1, TYPHOON_CCHIP_MISC(\t0)
.endm

#endif /* ASSEMBLER */
#endif /* TYPHOON_H */
