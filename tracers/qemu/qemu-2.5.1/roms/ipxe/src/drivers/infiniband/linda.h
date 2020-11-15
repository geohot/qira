#ifndef _LINDA_H
#define _LINDA_H

/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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
 * QLogic Linda Infiniband HCA
 *
 */

#define BITOPS_LITTLE_ENDIAN
#include <ipxe/bitops.h>
#include "qib_7220_regs.h"

struct ib_device;

/** A Linda GPIO register */
struct QIB_7220_GPIO_pb {
	pseudo_bit_t GPIO[16];
	pseudo_bit_t Reserved[48];
};
struct QIB_7220_GPIO {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_GPIO_pb );
};

/** A Linda general scalar register */
struct QIB_7220_scalar_pb {
	pseudo_bit_t Value[64];
};
struct QIB_7220_scalar {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_scalar_pb );
};

/** Linda send per-buffer control word */
struct QIB_7220_SendPbc_pb {
	pseudo_bit_t LengthP1_toibc[11];
	pseudo_bit_t Reserved1[4];
	pseudo_bit_t LengthP1_trigger[11];
	pseudo_bit_t Reserved2[3];
	pseudo_bit_t TestEbp[1];
	pseudo_bit_t Test[1];
	pseudo_bit_t Intr[1];
	pseudo_bit_t Reserved3[31];
	pseudo_bit_t VL15[1];
};
struct QIB_7220_SendPbc {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendPbc_pb );
};

/** Linda send buffer availability */
struct QIB_7220_SendBufAvail_pb {
	pseudo_bit_t InUseCheck[144][2];
	pseudo_bit_t Reserved[32];
};
struct QIB_7220_SendBufAvail {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_SendBufAvail_pb );
};

/** DMA alignment for send buffer availability */
#define LINDA_SENDBUFAVAIL_ALIGN 64

/** A Linda eager receive descriptor */
struct QIB_7220_RcvEgr_pb {
	pseudo_bit_t Addr[37];
	pseudo_bit_t BufSize[3];
	pseudo_bit_t Reserved[24];
};
struct QIB_7220_RcvEgr {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvEgr_pb );
};

/** Linda receive header flags */
struct QIB_7220_RcvHdrFlags_pb {
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
struct QIB_7220_RcvHdrFlags {
	PSEUDO_BIT_STRUCT ( struct QIB_7220_RcvHdrFlags_pb );
};

/** Linda memory BAR size */
#define LINDA_BAR0_SIZE 0x400000

/** Linda I2C SCL line GPIO number */
#define LINDA_GPIO_SCL 0

/** Linda I2C SDA line GPIO number */
#define LINDA_GPIO_SDA 1

/** GUID offset within EEPROM */
#define LINDA_EEPROM_GUID_OFFSET 3

/** GUID size within EEPROM */
#define LINDA_EEPROM_GUID_SIZE 8

/** Board serial number offset within EEPROM */
#define LINDA_EEPROM_SERIAL_OFFSET 12

/** Board serial number size within EEPROM */
#define LINDA_EEPROM_SERIAL_SIZE 12

/** Maximum number of send buffers used
 *
 * This is a policy decision.  Must be less than or equal to the total
 * number of send buffers supported by the hardware (128).
 */
#define LINDA_MAX_SEND_BUFS 32

/** Linda send buffer size */
#define LINDA_SEND_BUF_SIZE 4096

/** Number of contexts (including kernel context)
 *
 * This is a policy decision.  Must be 5, 9 or 17.
 */
#define LINDA_NUM_CONTEXTS 5

/** PortCfg values for different numbers of contexts */
enum linda_portcfg {
	LINDA_PORTCFG_5CTX = 0,
	LINDA_PORTCFG_9CTX = 1,
	LINDA_PORTCFG_17CTX = 2,
};

/** PortCfg values for different numbers of contexts */
#define LINDA_EAGER_ARRAY_SIZE_5CTX_0 2048
#define LINDA_EAGER_ARRAY_SIZE_5CTX_OTHER 4096
#define LINDA_EAGER_ARRAY_SIZE_9CTX_0 2048
#define LINDA_EAGER_ARRAY_SIZE_9CTX_OTHER 2048
#define LINDA_EAGER_ARRAY_SIZE_17CTX_0 2048
#define LINDA_EAGER_ARRAY_SIZE_17CTX_OTHER 1024

/** Eager buffer required alignment */
#define LINDA_EAGER_BUFFER_ALIGN 2048

/** Eager buffer size encodings */
enum linda_eager_buffer_size {
	LINDA_EAGER_BUFFER_NONE = 0,
	LINDA_EAGER_BUFFER_2K = 1,
	LINDA_EAGER_BUFFER_4K = 2,
	LINDA_EAGER_BUFFER_8K = 3,
	LINDA_EAGER_BUFFER_16K = 4,
	LINDA_EAGER_BUFFER_32K = 5,
	LINDA_EAGER_BUFFER_64K = 6,
};

/** Number of RX headers per context
 *
 * This is a policy decision.
 */
#define LINDA_RECV_HEADER_COUNT 8

/** Maximum size of each RX header
 *
 * This is a policy decision.  Must be divisible by 4.
 */
#define LINDA_RECV_HEADER_SIZE 96

/** Total size of an RX header ring */
#define LINDA_RECV_HEADERS_SIZE \
	( LINDA_RECV_HEADER_SIZE * LINDA_RECV_HEADER_COUNT )

/** RX header alignment */
#define LINDA_RECV_HEADERS_ALIGN 64

/** RX payload size
 *
 * This is a policy decision.  Must be a valid eager buffer size.
 */
#define LINDA_RECV_PAYLOAD_SIZE 2048

/** QPN used for Infinipath Packets
 *
 * This is a policy decision.  Must have bit 0 clear.  Must not be a
 * QPN that we will use.
 */
#define LINDA_QP_IDETH 0xdead0

/** Maximum time for wait for external parallel bus request, in us */
#define LINDA_EPB_REQUEST_MAX_WAIT_US 500

/** Maximum time for wait for external parallel bus transaction, in us */
#define LINDA_EPB_XACT_MAX_WAIT_US 500

/** Linda external parallel bus chip selects */
#define LINDA_EPB_CS_SERDES 1
#define LINDA_EPB_CS_UC 2

/** Linda external parallel bus read/write operations */
#define LINDA_EPB_WRITE 0
#define LINDA_EPB_READ 1

/** Linda external parallel bus register addresses */
#define LINDA_EPB_ADDRESS( _channel, _element, _reg ) \
	( (_element) | ( (_channel) << 4 ) | ( (_reg) << 9 ) )
#define LINDA_EPB_ADDRESS_CHANNEL( _address )	( ( (_address) >> 4 ) & 0x1f )
#define LINDA_EPB_ADDRESS_ELEMENT( _address )	( ( (_address) >> 0 ) & 0x0f )
#define LINDA_EPB_ADDRESS_REG( _address )	( ( (_address) >> 9 ) & 0x3f )

/** Linda external parallel bus locations
 *
 * The location is used by the driver to encode both the chip select
 * and the EPB address.
 */
#define LINDA_EPB_LOC( _cs, _channel, _element, _reg) \
	( ( (_cs) << 16 ) | LINDA_EPB_ADDRESS ( _channel, _element, _reg ) )
#define LINDA_EPB_LOC_ADDRESS( _loc )	( (_loc) & 0xffff )
#define LINDA_EPB_LOC_CS( _loc )	( (_loc) >> 16 )

/** Linda external parallel bus microcontroller register addresses */
#define LINDA_EPB_UC_CHANNEL 6
#define LINDA_EPB_UC_LOC( _reg ) \
	LINDA_EPB_LOC ( LINDA_EPB_CS_UC, LINDA_EPB_UC_CHANNEL, 0, (_reg) )
#define LINDA_EPB_UC_CTL	LINDA_EPB_UC_LOC ( 0 )
#define LINDA_EPB_UC_CTL_WRITE	1
#define LINDA_EPB_UC_CTL_READ	2
#define LINDA_EPB_UC_ADDR_LO	LINDA_EPB_UC_LOC ( 2 )
#define LINDA_EPB_UC_ADDR_HI	LINDA_EPB_UC_LOC ( 3 )
#define LINDA_EPB_UC_DATA	LINDA_EPB_UC_LOC ( 4 )
#define LINDA_EPB_UC_CHUNK_SIZE	64

extern uint8_t linda_ib_fw[8192];

/** Maximum time to wait for "trim done" signal, in ms */
#define LINDA_TRIM_DONE_MAX_WAIT_MS 1000

/** Linda link states */
enum linda_link_state {
	LINDA_LINK_STATE_DOWN = 0,
	LINDA_LINK_STATE_INIT = 1,
	LINDA_LINK_STATE_ARM = 2,
	LINDA_LINK_STATE_ACTIVE = 3,
	LINDA_LINK_STATE_ACT_DEFER = 4,
};

/** Maximum time to wait for link state changes, in us */
#define LINDA_LINK_STATE_MAX_WAIT_US 20

#endif /* _LINDA_H */
