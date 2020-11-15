/* Memory layout and register descriptions for the CIA/PYXIS chipset.

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

#ifndef CIA_H
#define CIA_H

#define IDENT_ADDR 0xfffffc0000000000UL

#define CIA_MEM_R1_MASK 0x1fffffff  /* SPARSE Mem region 1 mask is 29 bits */
#define CIA_MEM_R2_MASK 0x07ffffff  /* SPARSE Mem region 2 mask is 27 bits */
#define CIA_MEM_R3_MASK 0x03ffffff  /* SPARSE Mem region 3 mask is 26 bits */

/*
 * 21171-CA Control and Status Registers
 */
#define CIA_IOC_CIA_REV			(IDENT_ADDR + 0x8740000080UL)
#  define CIA_REV_MASK			0xff
#define CIA_IOC_PCI_LAT			(IDENT_ADDR + 0x87400000C0UL)
#define CIA_IOC_CIA_CTRL		(IDENT_ADDR + 0x8740000100UL)
#  define CIA_CTRL_PCI_EN		(1 << 0)
#  define CIA_CTRL_PCI_LOCK_EN		(1 << 1)
#  define CIA_CTRL_PCI_LOOP_EN		(1 << 2)
#  define CIA_CTRL_FST_BB_EN		(1 << 3)
#  define CIA_CTRL_PCI_MST_EN		(1 << 4)
#  define CIA_CTRL_PCI_MEM_EN		(1 << 5)
#  define CIA_CTRL_PCI_REQ64_EN		(1 << 6)
#  define CIA_CTRL_PCI_ACK64_EN		(1 << 7)
#  define CIA_CTRL_ADDR_PE_EN		(1 << 8)
#  define CIA_CTRL_PERR_EN		(1 << 9)
#  define CIA_CTRL_FILL_ERR_EN		(1 << 10)
#  define CIA_CTRL_MCHK_ERR_EN		(1 << 11)
#  define CIA_CTRL_ECC_CHK_EN		(1 << 12)
#  define CIA_CTRL_ASSERT_IDLE_BC	(1 << 13)
#  define CIA_CTRL_COM_IDLE_BC		(1 << 14)
#  define CIA_CTRL_CSR_IOA_BYPASS	(1 << 15)
#  define CIA_CTRL_IO_FLUSHREQ_EN	(1 << 16)
#  define CIA_CTRL_CPU_FLUSHREQ_EN	(1 << 17)
#  define CIA_CTRL_ARB_CPU_EN		(1 << 18)
#  define CIA_CTRL_EN_ARB_LINK		(1 << 19)
#  define CIA_CTRL_RD_TYPE_SHIFT	20
#  define CIA_CTRL_RL_TYPE_SHIFT	24
#  define CIA_CTRL_RM_TYPE_SHIFT	28
#  define CIA_CTRL_EN_DMA_RD_PERF	(1 << 31)
#define CIA_IOC_CIA_CNFG		(IDENT_ADDR + 0x8740000140UL)
#  define CIA_CNFG_IOA_BWEN		(1 << 0)
#  define CIA_CNFG_PCI_MWEN		(1 << 4)
#  define CIA_CNFG_PCI_DWEN		(1 << 5)
#  define CIA_CNFG_PCI_WLEN		(1 << 8)
#define CIA_IOC_FLASH_CTRL		(IDENT_ADDR + 0x8740000200UL)
#define CIA_IOC_HAE_MEM			(IDENT_ADDR + 0x8740000400UL)
#define CIA_IOC_HAE_IO			(IDENT_ADDR + 0x8740000440UL)
#define CIA_IOC_CFG			(IDENT_ADDR + 0x8740000480UL)
#define CIA_IOC_CACK_EN			(IDENT_ADDR + 0x8740000600UL)
#  define CIA_CACK_EN_LOCK_EN		(1 << 0)
#  define CIA_CACK_EN_MB_EN		(1 << 1)
#  define CIA_CACK_EN_SET_DIRTY_EN	(1 << 2)
#  define CIA_CACK_EN_BC_VICTIM_EN	(1 << 3)


/*
 * 21171-CA Diagnostic Registers
 */
#define CIA_IOC_CIA_DIAG		(IDENT_ADDR + 0x8740002000UL)
#define CIA_IOC_DIAG_CHECK		(IDENT_ADDR + 0x8740003000UL)

/*
 * 21171-CA Performance Monitor registers
 */
#define CIA_IOC_PERF_MONITOR		(IDENT_ADDR + 0x8740004000UL)
#define CIA_IOC_PERF_CONTROL		(IDENT_ADDR + 0x8740004040UL)

/*
 * 21171-CA Error registers
 */
#define CIA_IOC_CPU_ERR0		(IDENT_ADDR + 0x8740008000UL)
#define CIA_IOC_CPU_ERR1		(IDENT_ADDR + 0x8740008040UL)
#define CIA_IOC_CIA_ERR			(IDENT_ADDR + 0x8740008200UL)
#  define CIA_ERR_COR_ERR		(1 << 0)
#  define CIA_ERR_UN_COR_ERR		(1 << 1)
#  define CIA_ERR_CPU_PE		(1 << 2)
#  define CIA_ERR_MEM_NEM		(1 << 3)
#  define CIA_ERR_PCI_SERR		(1 << 4)
#  define CIA_ERR_PERR			(1 << 5)
#  define CIA_ERR_PCI_ADDR_PE		(1 << 6)
#  define CIA_ERR_RCVD_MAS_ABT		(1 << 7)
#  define CIA_ERR_RCVD_TAR_ABT		(1 << 8)
#  define CIA_ERR_PA_PTE_INV		(1 << 9)
#  define CIA_ERR_FROM_WRT_ERR		(1 << 10)
#  define CIA_ERR_IOA_TIMEOUT		(1 << 11)
#  define CIA_ERR_LOST_CORR_ERR		(1 << 16)
#  define CIA_ERR_LOST_UN_CORR_ERR	(1 << 17)
#  define CIA_ERR_LOST_CPU_PE		(1 << 18)
#  define CIA_ERR_LOST_MEM_NEM		(1 << 19)
#  define CIA_ERR_LOST_PERR		(1 << 21)
#  define CIA_ERR_LOST_PCI_ADDR_PE	(1 << 22)
#  define CIA_ERR_LOST_RCVD_MAS_ABT	(1 << 23)
#  define CIA_ERR_LOST_RCVD_TAR_ABT	(1 << 24)
#  define CIA_ERR_LOST_PA_PTE_INV	(1 << 25)
#  define CIA_ERR_LOST_FROM_WRT_ERR	(1 << 26)
#  define CIA_ERR_LOST_IOA_TIMEOUT	(1 << 27)
#  define CIA_ERR_VALID			(1 << 31)
#define CIA_IOC_CIA_STAT		(IDENT_ADDR + 0x8740008240UL)
#define CIA_IOC_ERR_MASK		(IDENT_ADDR + 0x8740008280UL)
#define CIA_IOC_CIA_SYN			(IDENT_ADDR + 0x8740008300UL)
#define CIA_IOC_MEM_ERR0		(IDENT_ADDR + 0x8740008400UL)
#define CIA_IOC_MEM_ERR1		(IDENT_ADDR + 0x8740008440UL)
#define CIA_IOC_PCI_ERR0		(IDENT_ADDR + 0x8740008800UL)
#define CIA_IOC_PCI_ERR1		(IDENT_ADDR + 0x8740008840UL)
#define CIA_IOC_PCI_ERR3		(IDENT_ADDR + 0x8740008880UL)

/*
 * 21171-CA System configuration registers
 */
#define CIA_IOC_MCR			(IDENT_ADDR + 0x8750000000UL)
#define CIA_IOC_MBA0			(IDENT_ADDR + 0x8750000600UL)
#define CIA_IOC_MBA2			(IDENT_ADDR + 0x8750000680UL)
#define CIA_IOC_MBA4			(IDENT_ADDR + 0x8750000700UL)
#define CIA_IOC_MBA6			(IDENT_ADDR + 0x8750000780UL)
#define CIA_IOC_MBA8			(IDENT_ADDR + 0x8750000800UL)
#define CIA_IOC_MBAA			(IDENT_ADDR + 0x8750000880UL)
#define CIA_IOC_MBAC			(IDENT_ADDR + 0x8750000900UL)
#define CIA_IOC_MBAE			(IDENT_ADDR + 0x8750000980UL)
#define CIA_IOC_TMG0			(IDENT_ADDR + 0x8750000B00UL)
#define CIA_IOC_TMG1			(IDENT_ADDR + 0x8750000B40UL)
#define CIA_IOC_TMG2			(IDENT_ADDR + 0x8750000B80UL)

/*
 * 2117A-CA PCI Address and Scatter-Gather Registers.
 */
#define CIA_IOC_PCI_TBIA		(IDENT_ADDR + 0x8760000100UL)

#define CIA_IOC_PCI_W0_BASE		(IDENT_ADDR + 0x8760000400UL)
#define CIA_IOC_PCI_W0_MASK		(IDENT_ADDR + 0x8760000440UL)
#define CIA_IOC_PCI_T0_BASE		(IDENT_ADDR + 0x8760000480UL)

#define CIA_IOC_PCI_W1_BASE		(IDENT_ADDR + 0x8760000500UL)
#define CIA_IOC_PCI_W1_MASK		(IDENT_ADDR + 0x8760000540UL)
#define CIA_IOC_PCI_T1_BASE		(IDENT_ADDR + 0x8760000580UL)

#define CIA_IOC_PCI_W2_BASE		(IDENT_ADDR + 0x8760000600UL)
#define CIA_IOC_PCI_W2_MASK		(IDENT_ADDR + 0x8760000640UL)
#define CIA_IOC_PCI_T2_BASE		(IDENT_ADDR + 0x8760000680UL)

#define CIA_IOC_PCI_W3_BASE		(IDENT_ADDR + 0x8760000700UL)
#define CIA_IOC_PCI_W3_MASK		(IDENT_ADDR + 0x8760000740UL)
#define CIA_IOC_PCI_T3_BASE		(IDENT_ADDR + 0x8760000780UL)

#define CIA_IOC_PCI_Wn_BASE(N)	(IDENT_ADDR + 0x8760000400UL + (N)*0x100) 
#define CIA_IOC_PCI_Wn_MASK(N)	(IDENT_ADDR + 0x8760000440UL + (N)*0x100) 
#define CIA_IOC_PCI_Tn_BASE(N)	(IDENT_ADDR + 0x8760000480UL + (N)*0x100) 

#define CIA_IOC_PCI_W_DAC		(IDENT_ADDR + 0x87600007C0UL)

/*
 * 2117A-CA Address Translation Registers.
 */

/* 8 tag registers, the first 4 of which are lockable.  */
#define CIA_IOC_TB_TAGn(n) \
	(IDENT_ADDR + 0x8760000800UL + (n)*0x40)

/* 4 page registers per tag register.  */
#define CIA_IOC_TBn_PAGEm(n,m) \
	(IDENT_ADDR + 0x8760001000UL + (n)*0x100 + (m)*0x40)

/*
 * Memory spaces:
 */
#define CIA_IACK_SC			(IDENT_ADDR + 0x8720000000UL)
#define CIA_CONF			(IDENT_ADDR + 0x8700000000UL)
#define CIA_IO				(IDENT_ADDR + 0x8580000000UL)
#define CIA_SPARSE_MEM			(IDENT_ADDR + 0x8000000000UL)
#define CIA_SPARSE_MEM_R2		(IDENT_ADDR + 0x8400000000UL)
#define CIA_SPARSE_MEM_R3		(IDENT_ADDR + 0x8500000000UL)
#define CIA_DENSE_MEM		        (IDENT_ADDR + 0x8600000000UL)
#define CIA_BW_MEM			(IDENT_ADDR + 0x8800000000UL)
#define CIA_BW_IO			(IDENT_ADDR + 0x8900000000UL)
#define CIA_BW_CFG_0			(IDENT_ADDR + 0x8a00000000UL)
#define CIA_BW_CFG_1			(IDENT_ADDR + 0x8b00000000UL)

/*
 * ALCOR's GRU ASIC registers
 */
#define GRU_INT_REQ			(IDENT_ADDR + 0x8780000000UL)
#define GRU_INT_MASK			(IDENT_ADDR + 0x8780000040UL)
#define GRU_INT_EDGE			(IDENT_ADDR + 0x8780000080UL)
#define GRU_INT_HILO			(IDENT_ADDR + 0x87800000C0UL)
#define GRU_INT_CLEAR			(IDENT_ADDR + 0x8780000100UL)

#define GRU_CACHE_CNFG			(IDENT_ADDR + 0x8780000200UL)
#define GRU_SCR				(IDENT_ADDR + 0x8780000300UL)
#define GRU_LED				(IDENT_ADDR + 0x8780000800UL)
#define GRU_RESET			(IDENT_ADDR + 0x8780000900UL)

#define ALCOR_GRU_INT_REQ_BITS		0x800fffffUL
#define XLT_GRU_INT_REQ_BITS		0x80003fffUL
#define GRU_INT_REQ_BITS		(alpha_mv.sys.cia.gru_int_req_bits+0)

/*
 * PYXIS interrupt control registers
 */
#define PYXIS_INT_REQ			(IDENT_ADDR + 0x87A0000000UL)
#define PYXIS_INT_MASK			(IDENT_ADDR + 0x87A0000040UL)
#define PYXIS_INT_HILO			(IDENT_ADDR + 0x87A00000C0UL)
#define PYXIS_INT_ROUTE			(IDENT_ADDR + 0x87A0000140UL)
#define PYXIS_GPO			(IDENT_ADDR + 0x87A0000180UL)
#define PYXIS_INT_CNFG			(IDENT_ADDR + 0x87A00001C0UL)
#define PYXIS_RT_COUNT			(IDENT_ADDR + 0x87A0000200UL)
#define PYXIS_INT_TIME			(IDENT_ADDR + 0x87A0000240UL)
#define PYXIS_IIC_CTRL			(IDENT_ADDR + 0x87A00002C0UL)
#define PYXIS_RESET			(IDENT_ADDR + 0x8780000900UL)

/* Offset between ram physical addresses and pci64 DAC bus addresses.  */
#define PYXIS_DAC_OFFSET		(1UL << 40)

#ifdef __ASSEMBLER__

/* Unfortunately, GAS doesn't attempt any interesting constructions of
   64-bit constants, dropping them all into the .lit8 section.  It is
   better for us to build these by hand.  */
.macro	LOAD_PHYS_PYXIS_INT ret
	lda	\ret, 0x87a
	sll	\ret, 28, \ret
.endm

.macro	LOAD_KSEG_PCI_IO ret
	lda	\ret, -887
	sll	\ret, 32, \ret
.endm

.macro	SYS_WHAMI	ret
	mov	0, \ret
.endm

.macro	SYS_ACK_SMP	t0, t1, t2
	br	MchkBugCheck
.endm

#else

static inline unsigned long inb(unsigned long port)
{
  return *(volatile unsigned char *)(CIA_BW_IO + port);
}

static inline void outb(unsigned long port, unsigned char val)
{
  *(volatile unsigned char *)(CIA_BW_IO + port) = val;
}


#endif

#endif /* CIA_H */
