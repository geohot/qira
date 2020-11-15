/* PALcode and C runtime functions for the CLIPPER system emulation.

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

#include "pal.h"
#include SYSTEM_H

/*
 * Sys_Setup
 *
 * Do any system specific setup necessary.
 *
 * INPUT PARAMETERS
 *
 *	a0 = whami
 *	p7 = return address
 */
	.globl	Sys_Setup
	.ent	Sys_Setup
Sys_Setup:
	.frame	$sp, 0, p7, 0
	lda		t0, TYPHOON_CCHIP_DIR0
	lda		t1, TYPHOON_CCHIP_DIR2
	lda		t2, TYPHOON_CCHIP_IIC0
	lda		t3, TYPHOON_CCHIP_IIC2
	and		a0, 2, t4
	cmovne		t4, t1, t0
	cmovne		t4, t3, t2
	and		a0, 1, t4
	sll		t4, 6, t4
	addq		t0, t4, t0
	addq		t2, t4, t2
	LOAD_PHYS_CCHIP	t4
	addq		t0, t4, t0
	addq		t2, t4, t2
	mtpr		t0, ptCpuDIR
	mtpr		t2, ptCpuIIC
	ret
	.end	Sys_Setup

/*
 * Sys_Dev_Vector
 *
 * Load the SRM interrupt vector for the system.
 *
 * INPUT PARAMETERS
 *
 *	p7 = return address
 *
 * OUTPUT PARAMETERS
 *
 *	a1 = interrupt vector
 */

	.globl	Sys_Dev_Vector
	.ent	Sys_Dev_Vector
Sys_Dev_Vector:
	.frame	$sp, 0, p7, 0
	mfpr	a1, ptCpuDIR		// Load int mask for this CPU
	ldq_p	a1, 0(a1)
	beq	a1, CallPal_Rti		// No interrupts asserted?

	cttz	a1, a1			// Find the first asserted interrupt.

	cmpeq	a1, 55, a0		// Is this an ISA interrupt?
	addq	a1, 16, a1		// PCI interrupt numbers start at 16
	beq	a0, 1f

	LOAD_PHYS_PCHIP0_IACK a1	// IACK results in the ISA irq
	ldl_p	a1, 0(a1)

1:	sll	a1, 4, a1
	lda	a1, 0x800(a1)
	ret	$31, (p7), 0
	.end Sys_Dev_Vector

/*
 * Cserve_Ena
 *
 * Unmask a PCI interrupt
 */
	.globl	Cserve_Ena
Cserve_Ena:
	// FIXME
	hw_rei
ENDFN	Cserve_Ena

/*
 * Cserve_Dis
 *
 * Mask a PCI interrupt
 */
	.globl	Cserve_Dis
Cserve_Dis:
	// FIXME
	hw_rei
ENDFN	Cserve_Dis

/*
 * PCI parameters
 */

	.section .sdata

	.align	3
	.globl	pci_io_base
	.type	pci_io_base, @object
	.size	pci_io_base, 8
pci_io_base:
	.quad	PIO_KSEG_ADDR + TYPHOON_PCHIP0_PCI_IO

	.globl	pci_conf_base
	.type	pci_conf_base, @object
	.size	pci_conf_base, 8
pci_conf_base:
	.quad	PIO_KSEG_ADDR + TYPHOON_PCHIP0_PCI_CONF

	.align	3
	.globl	pci_mem_base
	.type	pci_mem_base, @object
	.size	pci_mem_base, 8
pci_mem_base:
	.quad	PIO_KSEG_ADDR + TYPHOON_PCHIP0_PCI_MEM

