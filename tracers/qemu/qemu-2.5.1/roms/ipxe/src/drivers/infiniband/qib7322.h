#ifndef _QIB7322_H
#define _QIB7322_H

/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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
 * QLogic QIB7322 Infiniband HCA
 *
 */

#define BITOPS_LITTLE_ENDIAN
#include <ipxe/bitops.h>
#include "qib_7322_regs.h"

/** A QIB7322 GPIO register */
struct QIB_7322_GPIO_pb {
	pseudo_bit_t GPIO[16];
	pseudo_bit_t Reserved[48];
};
struct QIB_7322_GPIO {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_GPIO_pb );
};

/** A QIB7322 general scalar register */
struct QIB_7322_scalar_pb {
	pseudo_bit_t Value[64];
};
struct QIB_7322_scalar {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_scalar_pb );
};

/** QIB7322 feature mask */
struct QIB_7322_feature_mask_pb {
	pseudo_bit_t Port0_Link_Speed_Supported[3];
	pseudo_bit_t Port1_Link_Speed_Supported[3];
	pseudo_bit_t _unused_0[58];
};
struct QIB_7322_feature_mask {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_feature_mask_pb );
};

/** QIB7322 send per-buffer control word */
struct QIB_7322_SendPbc_pb {
	pseudo_bit_t LengthP1_toibc[11];
	pseudo_bit_t Reserved1[4];
	pseudo_bit_t LengthP1_trigger[11];
	pseudo_bit_t Reserved2[3];
	pseudo_bit_t TestEbp[1];
	pseudo_bit_t Test[1];
	pseudo_bit_t Intr[1];
	pseudo_bit_t StaticRateControlCnt[14];
	pseudo_bit_t Reserved3[12];
	pseudo_bit_t Port[1];
	pseudo_bit_t VLane[3];
	pseudo_bit_t Reserved4[1];
	pseudo_bit_t VL15[1];
};
struct QIB_7322_SendPbc {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendPbc_pb );
};

/** QIB7322 send buffer availability */
struct QIB_7322_SendBufAvail_pb {
	pseudo_bit_t InUseCheck[162][2];
	pseudo_bit_t Reserved[60];
};
struct QIB_7322_SendBufAvail {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_SendBufAvail_pb );
};

/** DMA alignment for send buffer availability */
#define QIB7322_SENDBUFAVAIL_ALIGN 64

/** QIB7322 port-specific receive control */
struct QIB_7322_RcvCtrl_P_pb {
	pseudo_bit_t ContextEnable[18];
	pseudo_bit_t _unused_1[21];
	pseudo_bit_t RcvIBPortEnable[1];
	pseudo_bit_t RcvQPMapEnable[1];
	pseudo_bit_t RcvPartitionKeyDisable[1];
	pseudo_bit_t RcvResetCredit[1];
	pseudo_bit_t _unused_2[21];
};
struct QIB_7322_RcvCtrl_P {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvCtrl_P_pb );
};

/** A QIB7322 eager receive descriptor */
struct QIB_7322_RcvEgr_pb {
	pseudo_bit_t Addr[37];
	pseudo_bit_t BufSize[3];
	pseudo_bit_t Reserved[24];
};
struct QIB_7322_RcvEgr {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvEgr_pb );
};

/** QIB7322 receive header flags */
struct QIB_7322_RcvHdrFlags_pb {
	pseudo_bit_t PktLen[11];
	pseudo_bit_t RcvType[3];
	pseudo_bit_t SoftB[1];
	pseudo_bit_t SoftA[1];
	pseudo_bit_t EgrIndex[12];
	pseudo_bit_t Reserved1[3];
	pseudo_bit_t UseEgrBfr[1];
	pseudo_bit_t RcvSeq[4];
	pseudo_bit_t HdrqOffset[11];
	pseudo_bit_t Reserved2[8];
	pseudo_bit_t IBErr[1];
	pseudo_bit_t MKErr[1];
	pseudo_bit_t TIDErr[1];
	pseudo_bit_t KHdrErr[1];
	pseudo_bit_t MTUErr[1];
	pseudo_bit_t LenErr[1];
	pseudo_bit_t ParityErr[1];
	pseudo_bit_t VCRCErr[1];
	pseudo_bit_t ICRCErr[1];
};
struct QIB_7322_RcvHdrFlags {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_RcvHdrFlags_pb );
};

/** QIB7322 DDS tuning parameters */
struct QIB_7322_IBSD_DDS_MAP_TABLE_pb {
	pseudo_bit_t Pre[3];
	pseudo_bit_t PreXtra[2];
	pseudo_bit_t Post[4];
	pseudo_bit_t Main[5];
	pseudo_bit_t Amp[4];
	pseudo_bit_t _unused_0[46];
};
struct QIB_7322_IBSD_DDS_MAP_TABLE {
	PSEUDO_BIT_STRUCT ( struct QIB_7322_IBSD_DDS_MAP_TABLE_pb );
};

/** QIB7322 memory BAR size */
#define QIB7322_BAR0_SIZE 0x400000

/** QIB7322 base port number */
#define QIB7322_PORT_BASE 1

/** QIB7322 maximum number of ports */
#define QIB7322_MAX_PORTS 2

/** QIB7322 maximum width */
#define QIB7322_MAX_WIDTH 4

/** QIB7322 board identifiers */
enum qib7322_board_id {
	QIB7322_BOARD_QLE7342_EMULATION = 0,
	QIB7322_BOARD_QLE7340 = 1,
	QIB7322_BOARD_QLE7342 = 2,
	QIB7322_BOARD_QMI7342 = 3,
	QIB7322_BOARD_QMH7342_UNSUPPORTED = 4,
	QIB7322_BOARD_QME7342 = 5,
	QIB7322_BOARD_QMH7342 = 6,
	QIB7322_BOARD_QLE7342_TEST = 15,
};

/** QIB7322 I2C SCL line GPIO number */
#define QIB7322_GPIO_SCL 0

/** QIB7322 I2C SDA line GPIO number */
#define QIB7322_GPIO_SDA 1

/** GUID offset within EEPROM */
#define QIB7322_EEPROM_GUID_OFFSET 3

/** GUID size within EEPROM */
#define QIB7322_EEPROM_GUID_SIZE 8

/** Board serial number offset within EEPROM */
#define QIB7322_EEPROM_SERIAL_OFFSET 12

/** Board serial number size within EEPROM */
#define QIB7322_EEPROM_SERIAL_SIZE 12

/** QIB7322 small send buffer size */
#define QIB7322_SMALL_SEND_BUF_SIZE 4096

/** QIB7322 small send buffer starting index */
#define QIB7322_SMALL_SEND_BUF_START 0

/** QIB7322 small send buffer count */
#define QIB7322_SMALL_SEND_BUF_COUNT 128

/** QIB7322 large send buffer size */
#define QIB7322_LARGE_SEND_BUF_SIZE 8192

/** QIB7322 large send buffer starting index */
#define QIB7322_LARGE_SEND_BUF_START 128

/** QIB7322 large send buffer count */
#define QIB7322_LARGE_SEND_BUF_COUNT 32

/** QIB7322 VL15 port 0 send buffer starting index */
#define QIB7322_VL15_PORT0_SEND_BUF_START 160

/** QIB7322 VL15 port 0 send buffer count */
#define QIB7322_VL15_PORT0_SEND_BUF_COUNT 1

/** QIB7322 VL15 port 0 send buffer size */
#define QIB7322_VL15_PORT0_SEND_BUF_SIZE 8192

/** QIB7322 VL15 port 0 send buffer starting index */
#define QIB7322_VL15_PORT1_SEND_BUF_START 161

/** QIB7322 VL15 port 0 send buffer count */
#define QIB7322_VL15_PORT1_SEND_BUF_COUNT 1

/** QIB7322 VL15 port 0 send buffer size */
#define QIB7322_VL15_PORT1_SEND_BUF_SIZE 8192

/** Number of small send buffers used
 *
 * This is a policy decision.  Must be less than or equal to the total
 * number of small send buffers supported by the hardware
 * (QIB7322_SMALL_SEND_BUF_COUNT).
 */
#define QIB7322_SMALL_SEND_BUF_USED 32

/** Number of contexts (including kernel context)
 *
 * This is a policy decision.  Must be 6, 10 or 18.
 */
#define QIB7322_NUM_CONTEXTS 6

/** ContextCfg values for different numbers of contexts */
enum qib7322_contextcfg {
	QIB7322_CONTEXTCFG_6CTX = 0,
	QIB7322_CONTEXTCFG_10CTX = 1,
	QIB7322_CONTEXTCFG_18CTX = 2,
};

/** ContextCfg values for different numbers of contexts */
#define QIB7322_EAGER_ARRAY_SIZE_6CTX_KERNEL 1024
#define QIB7322_EAGER_ARRAY_SIZE_6CTX_USER 4096
#define QIB7322_EAGER_ARRAY_SIZE_10CTX_KERNEL 1024
#define QIB7322_EAGER_ARRAY_SIZE_10CTX_USER 2048
#define QIB7322_EAGER_ARRAY_SIZE_18CTX_KERNEL 1024
#define QIB7322_EAGER_ARRAY_SIZE_18CTX_USER 1024

/** Eager buffer required alignment */
#define QIB7322_EAGER_BUFFER_ALIGN 2048

/** Eager buffer size encodings */
enum qib7322_eager_buffer_size {
	QIB7322_EAGER_BUFFER_NONE = 0,
	QIB7322_EAGER_BUFFER_2K = 1,
	QIB7322_EAGER_BUFFER_4K = 2,
	QIB7322_EAGER_BUFFER_8K = 3,
	QIB7322_EAGER_BUFFER_16K = 4,
	QIB7322_EAGER_BUFFER_32K = 5,
	QIB7322_EAGER_BUFFER_64K = 6,
};

/** Number of RX headers per context
 *
 * This is a policy decision.
 */
#define QIB7322_RECV_HEADER_COUNT 8

/** Maximum size of each RX header
 *
 * This is a policy decision.  Must be divisible by 4.
 */
#define QIB7322_RECV_HEADER_SIZE 96

/** Total size of an RX header ring */
#define QIB7322_RECV_HEADERS_SIZE \
	( QIB7322_RECV_HEADER_SIZE * QIB7322_RECV_HEADER_COUNT )

/** RX header alignment */
#define QIB7322_RECV_HEADERS_ALIGN 64

/** RX payload size
 *
 * This is a policy decision.  Must be a valid eager buffer size.
 */
#define QIB7322_RECV_PAYLOAD_SIZE 2048

/** Maximum number of credits per port
 *
 * 64kB of internal RX buffer space, in units of 64 bytes, split
 * between two ports.
 */
#define QIB7322_MAX_CREDITS ( ( 65536 / 64 ) / QIB7322_MAX_PORTS )

/** Number of credits to advertise for VL15
 *
 * This is a policy decision.  Using 9 credits allows for 9*64=576
 * bytes, which is enough for two MADs.
 */
#define QIB7322_MAX_CREDITS_VL15 9

/** Number of credits to advertise for VL0
 *
 * This is a policy decision.
 */
#define QIB7322_MAX_CREDITS_VL0 \
	( QIB7322_MAX_CREDITS - QIB7322_MAX_CREDITS_VL15 )

/** QPN used for Infinipath Packets
 *
 * This is a policy decision.  Must have bit 0 clear.  Must not be a
 * QPN that we will use.
 */
#define QIB7322_QP_IDETH 0xdead0

/** Maximum time for wait for AHB, in us */
#define QIB7322_AHB_MAX_WAIT_US 500

/** QIB7322 AHB locations */
#define QIB7322_AHB_LOC_ADDRESS( _location ) ( (_location) & 0xffff )
#define QIB7322_AHB_LOC_TARGET( _location ) ( (_location) >> 16 )
#define QIB7322_AHB_CHAN_0 0
#define QIB7322_AHB_CHAN_1 1
#define QIB7322_AHB_PLL 2
#define QIB7322_AHB_CHAN_2 3
#define QIB7322_AHB_CHAN_3 4
#define QIB7322_AHB_SUBSYS 5
#define QIB7322_AHB_CHAN( _channel ) ( (_channel) + ( (_channel) >> 1 ) )
#define QIB7322_AHB_TARGET_0 2
#define QIB7322_AHB_TARGET_1 3
#define QIB7322_AHB_TARGET( _port ) ( (_port) + 2 )
#define QIB7322_AHB_LOCATION( _port, _channel, _register )	\
	( ( QIB7322_AHB_TARGET(_port) << 16 ) |			\
	  ( QIB7322_AHB_CHAN(_channel) << 7 ) |			\
	  ( (_register) << 1 ) )

/** QIB7322 link states */
enum qib7322_link_state {
	QIB7322_LINK_STATE_DOWN = 0,
	QIB7322_LINK_STATE_INIT = 1,
	QIB7322_LINK_STATE_ARM = 2,
	QIB7322_LINK_STATE_ACTIVE = 3,
	QIB7322_LINK_STATE_ACT_DEFER = 4,
};

/** Maximum time to wait for link state changes, in us */
#define QIB7322_LINK_STATE_MAX_WAIT_US 20

#endif /* _QIB7322_H */
