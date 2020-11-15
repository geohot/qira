#ifndef _PHANTOM_H
#define _PHANTOM_H

/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
 * Copyright (C) 2008 NetXen, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * @file
 *
 * NetXen Phantom NICs
 *
 */

#include <stdint.h>

/* Drag in hardware definitions */
#include "nx_bitops.h"
#include "phantom_hw.h"
struct phantom_rds { NX_PSEUDO_BIT_STRUCT ( struct phantom_rds_pb ) };
struct phantom_sds { NX_PSEUDO_BIT_STRUCT ( struct phantom_sds_pb ) };
union phantom_cds { NX_PSEUDO_BIT_STRUCT ( union phantom_cds_pb ) };

/* Drag in firmware interface definitions */
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint64_t U64;
typedef uint32_t nx_rcode_t;
#define NXHAL_VERSION 1
#include "nxhal_nic_interface.h"

/** DMA buffer alignment */
#define UNM_DMA_BUFFER_ALIGN 16

/** Mark structure as DMA-aligned */
#define __unm_dma_aligned __attribute__ (( aligned ( UNM_DMA_BUFFER_ALIGN ) ))

/******************************************************************************
 *
 * Register definitions
 *
 */

#define UNM_128M_CRB_WINDOW		0x6110210UL
#define UNM_32M_CRB_WINDOW		0x0110210UL
#define UNM_2M_CRB_WINDOW		0x0130060UL

/**
 * Phantom register blocks
 *
 * The upper address bits vary between cards.  We define an abstract
 * address space in which the upper 8 bits of the 32-bit register
 * address encode the register block.  This gets translated to a bus
 * address by the phantom_crb_access_xxx() methods.
 */
enum unm_reg_blocks {
	UNM_CRB_BLK_PCIE	= 0x01,
	UNM_CRB_BLK_CAM		= 0x22,
	UNM_CRB_BLK_ROMUSB	= 0x33,
	UNM_CRB_BLK_TEST	= 0x02,
	UNM_CRB_BLK_PEG_0	= 0x11,
	UNM_CRB_BLK_PEG_1	= 0x12,
	UNM_CRB_BLK_PEG_2	= 0x13,
	UNM_CRB_BLK_PEG_3	= 0x14,
	UNM_CRB_BLK_PEG_4	= 0x0f,
};
#define UNM_CRB_BASE(blk)		( (blk) << 20 )
#define UNM_CRB_BLK(reg)		( (reg) >> 20 )
#define UNM_CRB_OFFSET(reg)		( (reg) & 0x000fffff )

#define UNM_CRB_PCIE			UNM_CRB_BASE ( UNM_CRB_BLK_PCIE )
#define UNM_PCIE_SEM2_LOCK		( UNM_CRB_PCIE + 0x1c010 )
#define UNM_PCIE_SEM2_UNLOCK		( UNM_CRB_PCIE + 0x1c014 )
#define UNM_PCIE_IRQ_VECTOR		( UNM_CRB_PCIE + 0x10100 )
#define UNM_PCIE_IRQ_VECTOR_BIT(n)		( 1 << ( (n) + 7 ) )
#define UNM_PCIE_IRQ_STATE		( UNM_CRB_PCIE + 0x1206c )
#define UNM_PCIE_IRQ_STATE_TRIGGERED(state)	(( (state) & 0x300 ) == 0x200 )
#define UNM_PCIE_IRQ_MASK_F0		( UNM_CRB_PCIE + 0x10128 )
#define UNM_PCIE_IRQ_MASK_F1		( UNM_CRB_PCIE + 0x10170 )
#define UNM_PCIE_IRQ_MASK_F2		( UNM_CRB_PCIE + 0x10174 )
#define UNM_PCIE_IRQ_MASK_F3		( UNM_CRB_PCIE + 0x10178 )
#define UNM_PCIE_IRQ_MASK_F4		( UNM_CRB_PCIE + 0x10370 )
#define UNM_PCIE_IRQ_MASK_F5		( UNM_CRB_PCIE + 0x10374 )
#define UNM_PCIE_IRQ_MASK_F6		( UNM_CRB_PCIE + 0x10378 )
#define UNM_PCIE_IRQ_MASK_F7		( UNM_CRB_PCIE + 0x1037c )
#define UNM_PCIE_IRQ_MASK_MAGIC			0x0000fbffUL
#define UNM_PCIE_IRQ_STATUS_F0		( UNM_CRB_PCIE + 0x10118 )
#define UNM_PCIE_IRQ_STATUS_F1		( UNM_CRB_PCIE + 0x10160 )
#define UNM_PCIE_IRQ_STATUS_F2		( UNM_CRB_PCIE + 0x10164 )
#define UNM_PCIE_IRQ_STATUS_F3		( UNM_CRB_PCIE + 0x10168 )
#define UNM_PCIE_IRQ_STATUS_F4		( UNM_CRB_PCIE + 0x10360 )
#define UNM_PCIE_IRQ_STATUS_F5		( UNM_CRB_PCIE + 0x10364 )
#define UNM_PCIE_IRQ_STATUS_F6		( UNM_CRB_PCIE + 0x10368 )
#define UNM_PCIE_IRQ_STATUS_F7		( UNM_CRB_PCIE + 0x1036c )
#define UNM_PCIE_IRQ_STATUS_MAGIC		0xffffffffUL

#define UNM_CRB_CAM			UNM_CRB_BASE ( UNM_CRB_BLK_CAM )

#define UNM_CAM_RAM			( UNM_CRB_CAM + 0x02000 )
#define UNM_CAM_RAM_PORT_MODE		( UNM_CAM_RAM + 0x00024 )
#define UNM_CAM_RAM_PORT_MODE_AUTO_NEG		4
#define UNM_CAM_RAM_PORT_MODE_AUTO_NEG_1G	5
#define UNM_CAM_RAM_DMESG_HEAD(n)	( UNM_CAM_RAM + 0x00030 + (n) * 0x10 )
#define UNM_CAM_RAM_DMESG_LEN(n)	( UNM_CAM_RAM + 0x00034 + (n) * 0x10 )
#define UNM_CAM_RAM_DMESG_TAIL(n)	( UNM_CAM_RAM + 0x00038 + (n) * 0x10 )
#define UNM_CAM_RAM_DMESG_SIG(n)	( UNM_CAM_RAM + 0x0003c + (n) * 0x10 )
#define UNM_CAM_RAM_DMESG_SIG_MAGIC		0xcafebabeUL
#define UNM_CAM_RAM_NUM_DMESG_BUFFERS		5
#define UNM_CAM_RAM_CLP_COMMAND		( UNM_CAM_RAM + 0x000c0 )
#define UNM_CAM_RAM_CLP_COMMAND_LAST		0x00000080UL
#define UNM_CAM_RAM_CLP_DATA_LO		( UNM_CAM_RAM + 0x000c4 )
#define UNM_CAM_RAM_CLP_DATA_HI		( UNM_CAM_RAM + 0x000c8 )
#define UNM_CAM_RAM_CLP_STATUS		( UNM_CAM_RAM + 0x000cc )
#define UNM_CAM_RAM_CLP_STATUS_START		0x00000001UL
#define UNM_CAM_RAM_CLP_STATUS_DONE		0x00000002UL
#define UNM_CAM_RAM_CLP_STATUS_ERROR		0x0000ff00UL
#define UNM_CAM_RAM_CLP_STATUS_UNINITIALISED	0xffffffffUL
#define UNM_CAM_RAM_BOOT_ENABLE		( UNM_CAM_RAM + 0x000fc )
#define UNM_CAM_RAM_WOL_PORT_MODE	( UNM_CAM_RAM + 0x00198 )
#define UNM_CAM_RAM_MAC_ADDRS		( UNM_CAM_RAM + 0x001c0 )
#define UNM_CAM_RAM_COLD_BOOT		( UNM_CAM_RAM + 0x001fc )
#define UNM_CAM_RAM_COLD_BOOT_MAGIC		0x55555555UL

#define UNM_NIC_REG			( UNM_CRB_CAM + 0x02200 )
#define UNM_NIC_REG_NX_CDRP		( UNM_NIC_REG + 0x00018 )
#define UNM_NIC_REG_NX_ARG1		( UNM_NIC_REG + 0x0001c )
#define UNM_NIC_REG_NX_ARG2		( UNM_NIC_REG + 0x00020 )
#define UNM_NIC_REG_NX_ARG3		( UNM_NIC_REG + 0x00024 )
#define UNM_NIC_REG_NX_SIGN		( UNM_NIC_REG + 0x00028 )
#define UNM_NIC_REG_DUMMY_BUF_ADDR_HI	( UNM_NIC_REG + 0x0003c )
#define UNM_NIC_REG_DUMMY_BUF_ADDR_LO	( UNM_NIC_REG + 0x00040 )
#define UNM_NIC_REG_CMDPEG_STATE	( UNM_NIC_REG + 0x00050 )
#define UNM_NIC_REG_CMDPEG_STATE_INITIALIZED	0xff01
#define UNM_NIC_REG_CMDPEG_STATE_INITIALIZE_ACK	0xf00f
#define UNM_NIC_REG_DUMMY_BUF		( UNM_NIC_REG + 0x000fc )
#define UNM_NIC_REG_DUMMY_BUF_INIT		0
#define UNM_NIC_REG_XG_STATE_P3		( UNM_NIC_REG + 0x00098 )
#define UNM_NIC_REG_XG_STATE_P3_LINK( port, state_p3 ) \
	( ( (state_p3) >> ( (port) * 4 ) ) & 0x0f )
#define UNM_NIC_REG_XG_STATE_P3_LINK_UP		0x01
#define UNM_NIC_REG_XG_STATE_P3_LINK_DOWN	0x02
#define UNM_NIC_REG_RCVPEG_STATE	( UNM_NIC_REG + 0x0013c )
#define UNM_NIC_REG_RCVPEG_STATE_INITIALIZED	0xff01

#define UNM_CRB_ROMUSB			UNM_CRB_BASE ( UNM_CRB_BLK_ROMUSB )

#define UNM_ROMUSB_GLB			( UNM_CRB_ROMUSB + 0x00000 )
#define UNM_ROMUSB_GLB_STATUS		( UNM_ROMUSB_GLB + 0x00004 )
#define UNM_ROMUSB_GLB_STATUS_ROM_DONE		( 1 << 1 )
#define UNM_ROMUSB_GLB_SW_RESET		( UNM_ROMUSB_GLB + 0x00008 )
#define UNM_ROMUSB_GLB_SW_RESET_MAGIC		0x0080000fUL
#define UNM_ROMUSB_GLB_PEGTUNE_DONE	( UNM_ROMUSB_GLB + 0x0005c )
#define UNM_ROMUSB_GLB_PEGTUNE_DONE_MAGIC	0x31

#define UNM_ROMUSB_ROM			( UNM_CRB_ROMUSB + 0x10000 )
#define UNM_ROMUSB_ROM_INSTR_OPCODE	( UNM_ROMUSB_ROM + 0x00004 )
#define UNM_ROMUSB_ROM_ADDRESS		( UNM_ROMUSB_ROM + 0x00008 )
#define UNM_ROMUSB_ROM_WDATA		( UNM_ROMUSB_ROM + 0x0000c )
#define UNM_ROMUSB_ROM_ABYTE_CNT	( UNM_ROMUSB_ROM + 0x00010 )
#define UNM_ROMUSB_ROM_DUMMY_BYTE_CNT	( UNM_ROMUSB_ROM + 0x00014 )
#define UNM_ROMUSB_ROM_RDATA		( UNM_ROMUSB_ROM + 0x00018 )

#define UNM_CRB_TEST			UNM_CRB_BASE ( UNM_CRB_BLK_TEST )

#define UNM_TEST_CONTROL		( UNM_CRB_TEST + 0x00090 )
#define UNM_TEST_CONTROL_START			0x01
#define UNM_TEST_CONTROL_ENABLE			0x02
#define UNM_TEST_CONTROL_BUSY			0x08
#define UNM_TEST_ADDR_LO		( UNM_CRB_TEST + 0x00094 )
#define UNM_TEST_ADDR_HI		( UNM_CRB_TEST + 0x00098 )
#define UNM_TEST_RDDATA_LO		( UNM_CRB_TEST + 0x000a8 )
#define UNM_TEST_RDDATA_HI		( UNM_CRB_TEST + 0x000ac )

#define UNM_CRB_PEG_0			UNM_CRB_BASE ( UNM_CRB_BLK_PEG_0 )
#define UNM_PEG_0_HALT_STATUS		( UNM_CRB_PEG_0 + 0x00030 )
#define UNM_PEG_0_HALT			( UNM_CRB_PEG_0 + 0x0003c )

#define UNM_CRB_PEG_1			UNM_CRB_BASE ( UNM_CRB_BLK_PEG_1 )
#define UNM_PEG_1_HALT_STATUS		( UNM_CRB_PEG_1 + 0x00030 )
#define UNM_PEG_1_HALT			( UNM_CRB_PEG_1 + 0x0003c )

#define UNM_CRB_PEG_2			UNM_CRB_BASE ( UNM_CRB_BLK_PEG_2 )
#define UNM_PEG_2_HALT_STATUS		( UNM_CRB_PEG_2 + 0x00030 )
#define UNM_PEG_2_HALT			( UNM_CRB_PEG_2 + 0x0003c )

#define UNM_CRB_PEG_3			UNM_CRB_BASE ( UNM_CRB_BLK_PEG_3 )
#define UNM_PEG_3_HALT_STATUS		( UNM_CRB_PEG_3 + 0x00030 )
#define UNM_PEG_3_HALT			( UNM_CRB_PEG_3 + 0x0003c )

#define UNM_CRB_PEG_4			UNM_CRB_BASE ( UNM_CRB_BLK_PEG_4 )
#define UNM_PEG_4_HALT_STATUS		( UNM_CRB_PEG_4 + 0x00030 )
#define UNM_PEG_4_HALT			( UNM_CRB_PEG_4 + 0x0003c )

#endif /* _PHANTOM_H */
