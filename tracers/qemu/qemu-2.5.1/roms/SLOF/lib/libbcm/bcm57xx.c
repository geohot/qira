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

/*
 *
 ******************************************************************************
 * reference:
 * Broadcom 57xx
 * Host Programmer Interface Specification for the
 * NetXtreme Family of Highly-Integrated Media Access Controlers
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <byteorder.h>
#include <helpers.h>
#include <netdriver.h>
#include "bcm57xx.h"

/*
 * local defines
 ******************************************************************************
 */


// #define BCM_VLAN_TAG    ( (uint32_t) 0x1 )

// number of tx/rx rings
// NOTE: 5714 only uses 1 rx/tx ring, but memory
// for the other rings is cleaned anyways for
// sanity & future use
#define BCM_MAX_TX_RING         16
#define BCM_MAX_RXRET_RING      16
#define BCM_MAX_RXPROD_RCB       3

// bd descriptions
#define BCM_RXPROD_RING_SIZE     512    // don't change
#define BCM_RXRET_RING_SIZE	 512    // don't change
#define BCM_TX_RING_SIZE         512    // don't change
#define BCM_BUF_SIZE            1536    // don't change
#define BCM_MTU_MAX_LEN         1522
#define BCM_MAX_RX_BUF            64
#define BCM_MAX_TX_BUF            16

// number of MAC addresses in NIC
#define BCM_NUM_MAC_ADDR	   4
#define BCM_NUM_MAC5704_ADDR	  12
// offset of mac address field(s) in bcm register space
#define MAC5704_ADDR_OFFS	( (uint16_t) 0x0530 )

// offset of NIC memory start address from base address
#define BCM_MEMORY_OFFS         ( (uint64_t) 0x8000 )

// offset of statistics block in NIC memory
#define BCM_STATISTIC_OFFS	( (uint64_t) 0x0300 )
// size of statistic block in NIC memory
#define BCM_STATISTIC_SIZE	0x800

// offsets of NIC rx/tx rings in NIC memory
#define BCM_NIC_TX_OFFS		( (uint16_t) 0x4000 )
#define BCM_NIC_RX_OFFS		( (uint16_t) 0x6000 )
#define BCM_NIC_TX_SIZE		( (uint16_t) ( ( BCM_TX_RING_SIZE * BCM_RCB_SIZE_u16 ) / 4 ) )

// device mailboxes
#define BCM_FW_MBX          	( (uint16_t) 0x0b50 )
#define BCM_FW_MBX_CMD      	( (uint16_t) 0x0b78 )
#define BCM_FW_MBX_LEN      	( (uint16_t) 0x0b7c )
#define BCM_FW_MBX_DATA     	( (uint16_t) 0x0b80 )
#define BCM_NICDRV_STATE_MBX	( (uint16_t) 0x0c04 )

// device mailbox commands
#define BCM_NICDRV_ALIVE	( (uint32_t) 0x00000001 )
#define BCM_NICDRV_PAUSE_FW	( (uint32_t) 0x00000002 )

// device values
#define BCM_MAGIC_NUMBER           	( (uint32_t) 0x4b657654 )

// device states
#define NIC_FWDRV_STATE_START      	( (uint32_t) 0x00000001 )
#define NIC_FWDRV_STATE_START_DONE 	( (uint32_t) 0x80000001 )
#define NIC_FWDRV_STATE_UNLOAD     	( (uint32_t) 0x00000002 )
#define NIC_FWDRV_STATE_UNLOAD_DONE	( (uint32_t) 0x80000002 )
#define NIC_FWDRV_STATE_SUSPEND    	( (uint32_t) 0x00000004 )

// timer prescaler value
#define BCM_TMR_PRESCALE        ( (uint32_t) 0x41 )

// offset of transmit rcb's in NIC memory
#define BCM_TX_RCB_OFFS         ( (uint16_t) 0x0100 )
// offset of receive return rcb's in NIC memory
#define BCM_RXRET_RCB_OFFS      ( (uint16_t) 0x0200 )

// register offsets for ring indices
#define TX_PROD_IND             ( (uint16_t) 0x0304 )
#define TX_CONS_IND             ( (uint16_t) 0x3cc0 )
#define RXPROD_PROD_IND         ( (uint16_t) 0x026c )
#define RXPROD_CONS_IND         ( (uint16_t) 0x3c54 )
#define RXRET_PROD_IND          ( (uint16_t) 0x3c80 )
#define RXRET_CONS_IND          ( (uint16_t) 0x0284 )
// NIC producer index only needed for initialization
#define TX_NIC_PROD_IND         ( (uint16_t) 0x0384 )

/*
 * predefined register values used during initialization
 * may be adapted by user
 */
#define DMA_RW_CTRL_VAL_5714    ( (uint32_t) 0x76144000 )
#define DMA_RW_CTRL_VAL         ( (uint32_t) 0x760F0000 )
#define TX_MAC_LEN_VAL          ( (uint32_t) 0x00002620 )

#define RX_LST_PLC_CFG_VAL      ( (uint32_t) 0x00000109 )
#define RX_LST_PLC_STAT_EN_VAL  ( (uint32_t) 0x007e000f )
#define NVM_ADDR_MSK            ( (uint32_t) 0x000fffff )

// Number of Receive Rules /w or /wo SOL enabled
#define RX_RULE_CFG_VAL		( (uint32_t) 0x00000008 )
#define NUM_RX_RULE		( (uint32_t) 16 )
#define NUM_RX_RULE_ASF		( (uint32_t) ( NUM_RX_RULE - 4 ) )

// RCB register offsets
#define BCM_RXPROD_RCB_JUM      ( (uint16_t) 0x2440 )
#define BCM_RXPROD_RCB_STD      ( (uint16_t) 0x2450 )
#define BCM_RXPROD_RCB_MIN      ( (uint16_t) 0x2460 )

// macros needed for new addressing method
#define BCM_RCB_HOSTADDR_HI_u16( rcb )	( (uint16_t) rcb + 0x00 )
#define BCM_RCB_HOSTADDR_LOW_u16( rcb ) ( (uint16_t) rcb + 0x04 )
#define BCM_RCB_LENFLAG_u16( rcb )      ( (uint16_t) rcb + 0x08 )
#define BCM_RCB_NICADDR_u16( rcb )      ( (uint16_t) rcb + 0x0c )
#define BCM_RCB_SIZE_u16		( (uint16_t) 0x0010 )

// RCB flags
#define RCB_FLAG_RING_DISABLED  BIT32( 1 )

// BCM device ID masks
#define BCM_DEV_5714   ( (uint64_t) 0x1 )
#define BCM_DEV_5704   ( (uint64_t) 0x2 )
#define BCM_DEV_5703   ( (uint64_t) 0x4 )
#define BCM_DEV_SERDES ( (uint64_t) 0x80000000 )
#define BCM_DEV_COPPER ( (uint64_t) 0x40000000 )

#define IS_5714        ( ( bcm_device_u64 & BCM_DEV_5714 ) != 0 )
#define IS_5704        ( ( bcm_device_u64 & BCM_DEV_5704 ) != 0 )
#define IS_5703        ( ( bcm_device_u64 & BCM_DEV_5703 ) != 0 )
#define IS_SERDES      ( ( bcm_device_u64 & BCM_DEV_SERDES ) != 0 )
#define IS_COPPER_PHY  ( ( bcm_device_u64 & BCM_DEV_COPPER ) != 0 )

#define BUFFERED_FLASH_PAGE_POS		9
#define BUFFERED_FLASH_BYTE_ADDR_MASK	((<<BUFFERED_FLASH_PAGE_POS) - 1)
#define BUFFERED_FLASH_PAGE_SIZE	264
#define BUFFERED_FLASH_PHY_SIZE		512
#define MANUFACTURING_INFO_SIZE		140
#define CRC32_POLYNOMIAL		0xEDB88320

/*
 * local types
 ******************************************************************************
 */
typedef struct {
	uint32_t m_dev_u32;
	uint64_t m_devmsk_u64;
}	bcm_dev_t;

/*
 * BCM common data structures
 * BCM57xx Programmer's Guide: Section 5
 */

/*
 * 64bit host address in a way the NIC is able to understand it
 */
typedef struct {
	uint32_t m_hi_u32;
	uint32_t m_lo_u32;
}	bcm_addr64_t;
/*
 * ring control block
 */
typedef struct {
	bcm_addr64_t m_hostaddr_st;
	uint32_t        m_lenflags_u32;	// upper 16b: len, lower 16b: flags
	uint32_t        m_nicaddr_u32;
}	bcm_rcb_t;

/*
 * tx buffer descriptor
 */
typedef struct {
	bcm_addr64_t m_hostaddr_st;
	uint32_t        m_lenflags_u32;	// upper 16b: len, lower 16b: flags
	uint32_t        m_VLANtag_u32;	// lower 16b: vtag
}       bcm_txbd_t;

/*
 * rx buffer descriptor
 */
typedef struct {
	bcm_addr64_t m_hostaddr_st;
	uint32_t        m_idxlen_u32;	// upper 16b: idx, lower 16b: len
	uint32_t        m_typeflags_u32;	// upper 16b: type, lower 16b: flags
	uint32_t        m_chksum_u32;	// upper 16b: ip, lower 16b: tcp/udp
	uint32_t        m_errvlan_u32;	// upper 16b: err, lower 16b: vlan tag
	uint32_t        m_reserved_u32;
	uint32_t        m_opaque_u32;
}	bcm_rxbd_t;

/*
 * bcm status block
 * NOTE: in fact the status block is not used and configured
 * so that it is not updated by the NIC. Still it has to be
 * set up so the NIC is satisfied
 */
typedef struct {
	uint32_t   m_st_word_u32;
	uint32_t   m_st_tag_u32;
	uint16_t   m_rxprod_cons_u16;
	uint16_t   m_unused_u16;
	uint32_t   m_unused_u32;
	uint16_t   m_tx_cons_u16;
	uint16_t   m_rxret_prod_u16;
}	bcm_status_t;

/*
 * local constants
 ******************************************************************************
 */
static const bcm_dev_t bcm_dev[] = {
	{ 0x166b, BCM_DEV_5714  		},
	{ 0x1668, BCM_DEV_5714  		},
	{ 0x1669, BCM_DEV_5714  		},
	{ 0x166a, BCM_DEV_5714			},
	{ 0x1648, BCM_DEV_5704  		},
	{ 0x1649, BCM_DEV_5704 | BCM_DEV_SERDES },
	{ 0x16a8, BCM_DEV_5704 | BCM_DEV_SERDES },
	{ 0x16a7, BCM_DEV_5703 | BCM_DEV_SERDES },
	{ 0x16c7, BCM_DEV_5703 | BCM_DEV_SERDES },
	{ 0     , 0             		}
};

/*
 * local variables
 ******************************************************************************
 */
static uint64_t       bcm_device_u64;
static uint32_t       bcm_rxret_ring_sz;
static uint64_t       bcm_baseaddr_u64;
static uint64_t       bcm_memaddr_u64;

/*
 * rings & their buffers
 */
// the rings made of buffer descriptors
static bcm_txbd_t  bcm_tx_ring[BCM_TX_RING_SIZE];
static bcm_rxbd_t  bcm_rxprod_ring[BCM_RXPROD_RING_SIZE];
static bcm_rxbd_t  bcm_rxret_ring[BCM_RXRET_RING_SIZE*2];

// the buffers used in the rings
static uint8_t       bcm_tx_buffer_pu08[BCM_MAX_TX_BUF][BCM_BUF_SIZE];
static uint8_t       bcm_rx_buffer_pu08[BCM_MAX_RX_BUF][BCM_BUF_SIZE];

// tx ring index of first/last bd
static uint32_t       bcm_tx_start_u32;
static uint32_t       bcm_tx_stop_u32;
static uint32_t       bcm_tx_bufavail_u32;

/*
 * status block
 */
static bcm_status_t bcm_status;

/*
 * implementation
 ******************************************************************************
 */


/*
 * global functions
 ******************************************************************************
 */


/*
 * local helper functions
 ******************************************************************************
 */
#if 0
static char *
memcpy( char *dest, const char *src, size_t n )
{
        char *ret = dest;
        while( n-- ) {
                *dest++ = *src++;
        }

        return( ret );
}
#endif

static char *
memset_ci( char *dest, int c, size_t n )
{
        char *ret = dest;
        
        while( n-- ) {
                wr08( dest, c );
		dest++;
        }

        return( ret );
}

#if 0
static char *
memset( char *dest, int c, size_t n )
{
        char *ret = dest;
        while( n-- ) {
                *dest++ = (char) c;
        }

        return( ret );
}
#endif

static uint32_t
bcm_nvram_logical_to_physical_address(uint32_t address)
{
	uint32_t page_no   = address / BUFFERED_FLASH_PAGE_SIZE;
	uint32_t page_addr = address % BUFFERED_FLASH_PAGE_SIZE;

	return (page_no << BUFFERED_FLASH_PAGE_POS) + page_addr;
}

/*
 * read/write functions to access NIC registers & memory
 * NOTE: all functions are executed with cache inhibitation (dead slow :-) )
 */
static uint32_t
bcm_read_mem32( uint16_t f_offs_u16 )
{       // caution: shall only be used after initialization!
	return rd32( bcm_memaddr_u64 + (uint64_t) f_offs_u16 );
}

/* not used so far
static uint16_t
bcm_read_mem16( uint16_t f_offs_u16 )
{       // caution: shall only be used after initialization!
	return rd16( bcm_memaddr_u64 + (uint64_t) f_offs_u16 );
}*/
/* not used so far
static uint8_t
bcm_read_mem08( uint16_t f_offs_u16 )
{       // caution: shall only be used after initialization!
	return rd08( bcm_memaddr_u64 + (uint64_t) f_offs_u16 );
}*/

static uint32_t
bcm_read_reg32_indirect( uint16_t f_offs_u16 )
{       // caution: shall only be used after initialization!
	SLOF_pci_config_write32(REG_BASE_ADDR_REG, f_offs_u16);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        REG_BASE_ADDR_REG,
	                                        f_offs_u16 );*/
	return bswap_32(SLOF_pci_config_read32(REG_DATA_REG));
	/*return (uint32_t) bswap_32( snk_kernel_interface->pci_config_read( bcm_pcicfg_puid,
	                                                                4,
	                                                                bcm_pcicfg_bus,
	                                                                bcm_pcicfg_devfn,
	                                                                REG_DATA_REG ) ) ;*/
}

static uint32_t
bcm_read_reg32( uint16_t f_offs_u16 )
{       // caution: shall only be used after initialization!
	if(f_offs_u16 >= 0x200 && f_offs_u16 <0x400)
		return bcm_read_reg32_indirect( f_offs_u16 + 0x5600 );
	return rd32( bcm_baseaddr_u64 + (uint64_t) f_offs_u16 );
}

static uint16_t
bcm_read_reg16( uint16_t f_offs_u16 )
{       // caution: shall only be used after initialization!
	return rd16( bcm_baseaddr_u64 + (uint64_t) f_offs_u16 );
}
/* not used so far
static uint8_t
bcm_read_reg08( uint16_t f_offs_u16 )
{       // caution: shall only be used after initialization!
	return rd08( bcm_baseaddr_u64 + (uint64_t) f_offs_u16 );
}*/

static void
bcm_write_mem32_indirect( uint16_t f_offs_u16, uint32_t f_val_u32 )
{       // caution: shall only be used after initialization!
	SLOF_pci_config_write32(MEM_BASE_ADDR_REG, f_offs_u16);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        MEM_BASE_ADDR_REG,
	                                        f_offs_u16 );*/
	SLOF_pci_config_write32(MEM_DATA_REG, bswap_32(f_val_u32));
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        MEM_DATA_REG,
	                                        bswap_32 ( f_val_u32 ) );*/
}

static void
bcm_write_mem32( uint16_t f_offs_u16, uint32_t f_val_u32 )
{       // caution: shall only be used after initialization!
	if(f_offs_u16 >= BCM_RXRET_RCB_OFFS &&
           f_offs_u16 < BCM_RXRET_RCB_OFFS + (BCM_MAX_RXRET_RING*BCM_RCB_SIZE_u16))
		bcm_write_mem32_indirect( f_offs_u16, f_val_u32 );
	else if(f_offs_u16 >= BCM_TX_RCB_OFFS &&
           f_offs_u16 < BCM_TX_RCB_OFFS + (BCM_MAX_TX_RING*BCM_RCB_SIZE_u16))
		bcm_write_mem32_indirect( f_offs_u16, f_val_u32 );
	else
		wr32( bcm_memaddr_u64 + (uint64_t) f_offs_u16, f_val_u32 );
}
/* not used so far
static void
bcm_write_mem16( uint16_t f_offs_u16, uint16_t f_val_u16 )
{       // caution: shall only be used after initialization!
	wr16( bcm_memaddr_u64 + (uint64_t) f_offs_u16, f_val_u16 );
}*/
/* not used so far
static void
bcm_write_mem08( uint16_t f_offs_u16, uint8_t f_val_u08 )
{       // caution: shall only be used after initialization!
	wr08( bcm_memaddr_u64 + (uint64_t) f_offs_u16, f_val_u08 );
}*/

static void
bcm_write_reg32_indirect( uint16_t f_offs_u16, uint32_t f_val_u32 )
{       // caution: shall only be used after initialization!
	SLOF_pci_config_write32(REG_BASE_ADDR_REG, f_offs_u16);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        REG_BASE_ADDR_REG,
	                                        f_offs_u16 );*/
	SLOF_pci_config_write32(REG_DATA_REG, bswap_32(f_val_u32));
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        REG_DATA_REG,
	                                        bswap_32 ( f_val_u32 ) );*/
}

static void
bcm_write_reg32( uint16_t f_offs_u16, uint32_t f_val_u32 )
{       // caution: shall only be used after initialization!
	if(f_offs_u16 >= 0x200 && f_offs_u16 <0x400)
		bcm_write_reg32_indirect( f_offs_u16 + 0x5600, f_val_u32 );
	else
		wr32( bcm_baseaddr_u64 + (uint64_t) f_offs_u16, f_val_u32 );
}

static void
bcm_write_reg16( uint16_t f_offs_u16, uint16_t f_val_u16 )
{       // caution: shall only be used after initialization!
	wr16( bcm_baseaddr_u64 + (uint64_t) f_offs_u16, f_val_u16 );
}
/* not used so far
static void
bcm_write_reg08( uint16_t f_offs_u16, uint8_t f_val_u08 )
{       // caution: shall only be used after initialization!
        wr08( bcm_baseaddr_u64 + (uint64_t) f_offs_u16, f_val_u08 );
}*/

static void
bcm_setb_reg32( uint16_t f_offs_u16, uint32_t f_mask_u32 )
{
	uint32_t v;

	v  = bcm_read_reg32( f_offs_u16 );
	v |= f_mask_u32;
	bcm_write_reg32( f_offs_u16, v );
}
/* not used so far
static void
bcm_setb_reg16( uint16_t f_offs_u16, uint16_t f_mask_u16 )
{
	uint16_t v;
	v  = rd16( bcm_baseaddr_u64 + (uint64_t) f_offs_u16 );
        v |= f_mask_u16;
	wr16( bcm_baseaddr_u64 + (uint64_t) f_offs_u16, v );
}*/
/* not used so far
static void
bcm_setb_reg08( uint16_t f_offs_u16, uint8_t f_mask_u08 )
{
	uint8_t v;
	v  = rd08( bcm_baseaddr_u64 + (uint64_t) f_offs_u16 );
        v |= f_mask_u08;
	wr08( bcm_baseaddr_u64 + (uint64_t) f_offs_u16, v );
}*/

static void
bcm_clrb_reg32( uint16_t f_offs_u16, uint32_t f_mask_u32 )
{
	uint32_t v;

	v  = bcm_read_reg32( f_offs_u16 );
	v &= ~f_mask_u32;
	bcm_write_reg32( f_offs_u16, v );
}

static void
bcm_clrb_reg16( uint16_t f_offs_u16, uint16_t f_mask_u16 )
{
	uint16_t v;

	v  = bcm_read_reg16( f_offs_u16 );
	v &= ~f_mask_u16;
	bcm_write_reg16( f_offs_u16, v );
}
/* not used so far
static void
bcm_clrb_reg08( uint16_t f_offs_u16, uint8_t f_mask_u08 )
{
	uint8_t v;
	v  = rd08( bcm_baseaddr_u64 + (uint64_t) f_offs_u16 );
        v &= ~f_mask_u32;
	wr08( bcm_baseaddr_u64 + (uint64_t) f_offs_u16, v );
}*/

static void
bcm_clr_wait_bit32( uint16_t r, uint32_t b )
{
	uint32_t i;

	bcm_clrb_reg32( r, b );

	i = 1000;
	while( --i ) {

		if( ( bcm_read_reg32( r ) & b ) == 0 ) {
			break;
		}

		SLOF_usleep( 10 );
	}
#ifdef BCM_DEBUG
	if( ( bcm_read_reg32( r ) & b ) != 0 ) {
		printf( "bcm57xx: bcm_clear_wait_bit32 failed (0x%04X)!\n", r );
	}
#endif
}

/*
 * (g)mii bus access
 */
#if 0
// not used so far
static int32_t
bcm_mii_write16( uint32_t f_reg_u32, uint16_t f_value_u16 )
{
	static const uint32_t WR_VAL = ( ( ((uint32_t) 0x1) << 21 ) | BIT32( 29 ) | BIT32( 26 ) );
	int32_t              l_autopoll_i32 = 0;
	uint32_t              l_wrval_u32;
	uint32_t              i;

	/*
	 * only 0x00-0x1f are valid registers
	 */
	if( f_reg_u32 > (uint32_t) 0x1f ) {
		return -1;
	}

	/*
	 * disable auto polling if enabled
	 */
	if( ( bcm_read_reg32( MI_MODE_R ) & BIT32( 4 ) ) != 0 ) {
		l_autopoll_i32 = (int32_t) !0;
		bcm_clrb_reg32( MI_MODE_R, BIT32( 4 ) );
		SLOF_usleep( 40 );
	}

	/*
	 * construct & write mi com register value
	 */
	l_wrval_u32 = ( WR_VAL | ( f_reg_u32 << 16 ) | (uint32_t) f_value_u16 );
	bcm_write_reg32( MI_COM_R, l_wrval_u32 );

	/*
	 * wait for transaction to complete
	 */
	i = 25;
	while( ( --i ) &&
	       ( ( bcm_read_reg32( MI_COM_R ) & BIT32( 29 ) ) != 0 ) ) {
		SLOF_usleep( 10 );
	}

	/*
	 * re-enable auto polling if necessary
	 */
	if( l_autopoll_i32 ) {
		bcm_setb_reg32( MI_MODE_R, BIT32( 4 ) );
	}

	// return on error
	if( i == 0 ) {
		return -1;
	}

	return 0;
}
#endif

static int32_t
bcm_mii_read16( uint32_t f_reg_u32, uint16_t *f_value_pu16 )
{
	static const uint32_t RD_VAL = ( ( ((uint32_t) 0x1) << 21 ) | BIT32( 29 ) | BIT32( 27 ) );
	int32_t l_autopoll_i32 = 0;
	uint32_t l_rdval_u32;
	uint32_t i;
	uint16_t first_not_busy;

	/*
	 * only 0x00-0x1f are valid registers
	 */
	if( f_reg_u32 > (uint32_t) 0x1f ) {
		return -1;
	}

	/*
	 * disable auto polling if enabled
	 */
	if( ( bcm_read_reg32( MI_MODE_R ) & BIT32( 4 ) ) != 0 ) {
		l_autopoll_i32 = ( int32_t ) !0;
		bcm_clrb_reg32( MI_MODE_R, BIT32( 4 ) );
		SLOF_usleep( 40 );
	}

	/*
	 * construct & write mi com register value
	 */
	l_rdval_u32 = ( RD_VAL | ( f_reg_u32 << 16 ) );
	bcm_write_reg32( MI_COM_R, l_rdval_u32 );

	/*
	 * wait for transaction to complete
	 * ERRATA workaround: must read two "not busy" states to indicate transaction complete
	 */
	i = 25;
	first_not_busy = 0;
	l_rdval_u32 = bcm_read_reg32( MI_COM_R );
	while( ( --i ) &&
	       ( (first_not_busy == 0) || ( ( l_rdval_u32 & BIT32( 29 ) ) != 0 ) ) ) {
                /* Is this the first clear BUSY state? */
		if ( ( l_rdval_u32 & BIT32( 29 ) ) == 0 )
			first_not_busy++;
		SLOF_usleep( 10 );
		l_rdval_u32 = bcm_read_reg32( MI_COM_R );
	}

	/*
	 * re-enable autopolling if necessary
	 */
	if( l_autopoll_i32 ) {
		bcm_setb_reg32( MI_MODE_R, BIT32( 4 ) );
	}

	/*
	 * return on read transaction error
	 * (check read failed bit)
	 */
	if( ( i == 0 ) ||
	    ( ( l_rdval_u32 & BIT32( 28 ) ) != 0 ) ) {
		return -1;
	}

	/*
	 * return read value
	 */
	*f_value_pu16 = (uint16_t) ( l_rdval_u32 & (uint32_t) 0xffff );

	return 0;
}

/*
 * ht2000 dump (not complete)
 */
#if 0
static void
bcm_dump( void )
{
	uint32_t i, j;

	printf( "*** DUMP ***********************************************************************\n\n" );

	printf( "* PCI Configuration Registers:\n" );
	for( i = 0, j = 0; i < 0x40; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* Private PCI Configuration Registers:\n" );
	for( i = 0x68, j = 0; i < 0x88; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* VPD Config:\n" );
	printf( "%04X: %08X  \n", 0x94, bcm_read_reg32( 0x94 ) );

	printf( "\n* Dual MAC Control Registers:\n" );
	for( i = 0xb8, j = 0; i < 0xd0; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* Ethernet MAC Control Registers:\n" );
	for( i = 0x400, j = 0; i < 0x590; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* Send Data Initiator Control:\n" );
	for( i = 0xc00, j = 0; i < 0xc10; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* Send Data Completion Control:\n" );
	printf( "%04X: %08X  ", 0x1000, bcm_read_reg32( 0x1000 ) );
	printf( "%04X: %08X  \n", 0x1008, bcm_read_reg32( 0x1008 ) );
	
	printf( "\n* Send BD Ring Selector Control:\n" );
	printf( "%04X: %08X  ", 0x1400, bcm_read_reg32( 0x1400 ) );
	printf( "%04X: %08X  ", 0x1404, bcm_read_reg32( 0x1404 ) );
	printf( "%04X: %08X  \n", 0x1408, bcm_read_reg32( 0x1408 ) );

	printf( "\n* Send BD Initiator Control:\n" );
	printf( "%04X: %08X  ", 0x1800, bcm_read_reg32( 0x1800 ) );
	printf( "%04X: %08X  \n", 0x1804, bcm_read_reg32( 0x1804 ) );

	printf( "\n* Send BD Completion Control:\n" );
	printf( "%04X: %08X  ", 0x1c00, bcm_read_reg32( 0x1c00 ) );

	printf( "\n* Receive List Placement Control:\n" );
	for( i = 0x2000, j = 0; i < 0x2020; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* Receive Data & Receive BD Initiator Control:\n" );
	printf( "%04X: %08X  ", 0x2400, bcm_read_reg32( 0x2400 ) );
	printf( "%04X: %08X  \n", 0x2404, bcm_read_reg32( 0x2404 ) );

	printf( "\n* Jumbo Receive BD Ring RCB:\n" );
	for( i = 0x2440, j = 0; i < 0x2450; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* Standard Receive BD Ring RCB:\n" );
	for( i = 0x2450, j = 0; i < 0x2460; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* Mini Receive BD Ring RCB:\n" );
	for( i = 0x2460, j = 0; i < 0x2470; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\nRDI Timer Mode Register:\n" );
	printf( "%04X: %08X  \n", 0x24f0, bcm_read_reg32( 0x24f0 ) );

	printf( "\n* Receive BD Initiator Control:\n" );
	for( i = 0x2c00, j = 0; i < 0x2c20; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}

	printf( "\n* Receive BD Completion Control:\n" );
	for( i = 0x3000, j = 0; i < 0x3014; i += 4 ) {

		printf( "%04X: %08X  ", i, bcm_read_reg32( i ) );

		if( ( ++j & 0x3 ) == 0 ) {
			printf( "\n" );
		}

	}
}
#endif



/*
 * NVRAM access
 */

static int
bcm_nvram_lock( void )
{
	int i;

	/*
	 * Acquire NVRam lock (REQ0) & wait for arbitration won (ARB0_WON)
	 */
//	bcm_setb_reg32( SW_ARB_R, BIT32( 0 ) );
	bcm_setb_reg32( SW_ARB_R, BIT32( 1 ) );

	i = 2000;
	while( ( --i ) && 
//	       ( bcm_read_reg32( SW_ARB_R ) & BIT32( 8 ) ) == 0 ) {
	       ( bcm_read_reg32( SW_ARB_R ) & BIT32( 9 ) ) == 0 ) {
		SLOF_msleep( 1 );
	}

	// return on error
	if( i == 0 ) {
#ifdef BCM_DEBUG
		printf("bcm57xx: failed to lock nvram");
#endif
		return -1;
	}

	return 0;
}

static void
bcm_nvram_unlock( void )
{
	/*
	 * release NVRam lock (CLR0)
	 */
//	bcm_setb_reg32( SW_ARB_R, BIT32( 4 ) );
	bcm_setb_reg32( SW_ARB_R, BIT32( 5 ) );
}

static void
bcm_nvram_init( void )
{
	/*
	 * enable access to NVRAM registers
	 */
	if(IS_5714) {
		bcm_setb_reg32( NVM_ACC_R, BIT32( 1 ) | BIT32( 0 ) );
	}

	/*
	 * disable bit-bang method 19& disable interface bypass
	 */
	bcm_clrb_reg32( NVM_CFG1_R, BIT32( 31 ) | BIT32( 3 ) | BIT32( 2 ) | BIT32( 14 ) | BIT32( 16 ) );
	bcm_setb_reg32( NVM_CFG1_R, BIT32 ( 13 ) | BIT32 ( 17 ));

	/*
	 * enable Auto SEEPROM Access
	 */
	bcm_setb_reg32( MISC_LOCAL_CTRL_R, BIT32 ( 24 ) );

	/*
	 * NVRAM write enable
	 */
	bcm_setb_reg32( MODE_CTRL_R, BIT32 ( 21 ) );
}

static int32_t
bcm_nvram_read( uint32_t f_addr_u32, uint32_t *f_val_pu32, uint32_t lock )
{
	uint32_t i;

	/*
	 * parameter check
	 */
	if( f_addr_u32 > NVM_ADDR_MSK ) {
		return -1;
	}

	/*
	 * Acquire NVRam lock (REQ0) & wait for arbitration won (ARB0_WON)
	 */
	if( lock && (bcm_nvram_lock() == -1) ) {
		return -1;
	}

	/*
	 * setup address to read
	 */
	bcm_write_reg32( NVM_ADDR_R,
		bcm_nvram_logical_to_physical_address(f_addr_u32) );
//	bcm_write_reg32( NVM_ADDR_R, f_addr_u32 );

	/*
	 * get the command going
	 */
	bcm_write_reg32( NVM_COM_R, BIT32( 8 ) | BIT32( 7 ) |
	                            BIT32( 4 ) | BIT32( 3 ) );

	/*
	 * wait for command completion
	 */
	i = 2000;
        while( ( --i ) &&
               ( ( bcm_read_reg32( NVM_COM_R ) & BIT32( 3 ) ) == 0 ) ) {
		SLOF_msleep( 1 );
	}

	/*
	 * read back data if no error
	 */
	if( i != 0 ) {
		/*
		 * read back data
		 */
		*f_val_pu32 = bcm_read_reg32( NVM_READ_R );
	}

	if(lock)
		bcm_nvram_unlock();

	// error
	if( i == 0 ) {
#ifdef BCM_DEBUG
		printf("bcm57xx: reading from NVRAM failed\n");
#endif
		return -1;
	}

	// success
	return 0;
}

static int32_t
bcm_nvram_write( uint32_t f_addr_u32, uint32_t f_value_u32, uint32_t lock )
{
	uint32_t i;

	/*
	 * parameter check
	 */
	if( f_addr_u32 > NVM_ADDR_MSK ) {
		return -1;
	}

	/*
	 * Acquire NVRam lock (REQ0) & wait for arbitration won (ARB0_WON)
	 */
	if( lock && (bcm_nvram_lock() == -1) ) {
			return -1;
	}

	/*
	 * setup address to write
	 */
	bcm_write_reg32( NVM_ADDR_R, bcm_nvram_logical_to_physical_address( f_addr_u32 ) );

	/*
	 * setup write data
	 */
	bcm_write_reg32( NVM_WRITE_R, f_value_u32 );

	/*
	 * get the command going
	 */
	bcm_write_reg32( NVM_COM_R, BIT32( 8 ) | BIT32( 7 ) |
	                            BIT32( 5 ) | BIT32( 4 ) | BIT32( 3 ) );

	/*
	 * wait for command completion
	 */
	i = 2000;
	while( ( --i ) &&
	       ( ( bcm_read_reg32( NVM_COM_R ) & BIT32( 3 ) ) == 0 ) ) {
		SLOF_msleep( 1 );
	}

	/*
	 * release NVRam lock (CLR0)
	 */
	if(lock)
		bcm_nvram_unlock();

	// error
	if( i == 0 ) {
#ifdef BCM_DEBUG
		printf("bcm57xx: writing to NVRAM failed\n");
#endif
		return -1;
	}

	// success
	return 0;
}

/*
 * PHY initialization
 */
static int32_t
bcm_mii_phy_init( void )
{
	static const uint32_t PHY_STAT_R   = (uint32_t) 0x01;
	static const uint32_t AUX_STAT_R   = (uint32_t) 0x19;
	static const uint32_t MODE_GMII    = BIT32( 3 );
	static const uint32_t MODE_MII     = BIT32( 2 );
	static const uint32_t NEG_POLARITY = BIT32( 10 );
	static const uint32_t MII_MSK      = ( MODE_GMII | MODE_MII );
	static const uint16_t GIGA_ETH     = ( BIT16( 10 ) | BIT16( 9 ) );
	int32_t i;
	uint16_t v;

	/*
	 * enable MDI communication
	 */
	bcm_write_reg32( MDI_CTRL_R, (uint32_t) 0x0 );

	/*
	 * check link up
	 */
	i = 2500;
	do {
		SLOF_msleep( 1 );
		// register needs to be read twice!
		bcm_mii_read16( PHY_STAT_R, &v );
		bcm_mii_read16( PHY_STAT_R, &v );
	} while( ( --i ) &&
		 ( ( v & BIT16( 2 ) ) == 0 ) );

	if( i == 0 ) {
#ifdef BCM_DEBUG	
		printf( "bcm57xx: link is down\n" );
#endif
		return -1;
	}

#ifdef BCM_DEBUG	
	printf( "bcm57xx: link is up\n" );
#endif
	if( !IS_COPPER_PHY ) {
		return 0;
	}

	/*
	 * setup GMII or MII interface
	 */
	i = bcm_read_reg32( ETH_MAC_MODE_R );
	/*
	 * read status register twice, since the first
	 * read fails once between here and the moon...
	 */
	bcm_mii_read16( AUX_STAT_R, &v );
	bcm_mii_read16( AUX_STAT_R, &v );

	if( ( v & GIGA_ETH ) == GIGA_ETH ) {
#ifdef BCM_DEBUG	
	printf( "bcm57xx: running PHY in GMII mode (1000BaseT)\n" );
#endif
		// GMII device
		if( ( i & MII_MSK ) != MODE_GMII ) {
			i &= ~MODE_MII;
			i |=  MODE_GMII;
		}

	} else {
#ifdef BCM_DEBUG	
	printf( "bcm57xx: running PHY in MII mode (10/100BaseT)\n" );
#endif
		// MII device
		if( ( i & MII_MSK ) != MODE_MII ) {
			i &= ~MODE_GMII;
			i |=  MODE_MII;
		}

	}

	if( IS_5704 && !IS_SERDES ) {
#ifdef BCM_DEBUG	
		printf( "bcm57xx: set the link ready signal for 5704C to negative polarity\n" );
#endif
		i |= NEG_POLARITY; // set the link ready signal for 5704C to negative polarity
	}

	bcm_write_reg32( ETH_MAC_MODE_R, i );

	return 0;
}

static int32_t
bcm_tbi_phy_init( void )
{
	int32_t i;
#if 0
	/*
	 * set TBI mode full duplex
	 */
	bcm_clrb_reg32( ETH_MAC_MODE_R, BIT32( 1 ) );
	bcm_setb_reg32( ETH_MAC_MODE_R, BIT32( 2 ) | BIT32( 3 ) );

	/*
	 * enable MDI communication
	 */
	bcm_write_reg32( MDI_CTRL_R, (uint32_t) 0x0 );

	/* Disable link change interrupt.  */
	bcm_write_reg32( ETH_MAC_EVT_EN_R, 0 );

	/*
	 * set link polarity
	 */
	bcm_clrb_reg32( ETH_MAC_MODE_R, BIT32( 10 ) );

	/*
	 * wait for sync/config changes
	 */
	for( i = 0; i < 100; i++ ) {
		bcm_write_reg32( ETH_MAC_STAT_R,
				 BIT32( 3 ) | BIT32( 4 ) );

		SLOF_usleep( 20 );

		if( ( bcm_read_reg32( ETH_MAC_STAT_R ) &
		    ( BIT32( 3 ) | BIT32( 4 ) ) ) == 0 ) {
			break;
		}

	}
#endif
	/*
	 * wait for sync to come up
	 */
	for( i = 0; i < 100; i++ ) {

		if( ( bcm_read_reg32( ETH_MAC_STAT_R ) & BIT32( 0 ) ) != 0 ) {
			break;
		}

		SLOF_usleep( 20 ); 
	}

	if( ( bcm_read_reg32( ETH_MAC_STAT_R ) & BIT32( 0 ) ) == 0) {
#ifdef BCM_DEBUG	
		printf( "bcm57xx: link is down\n" );
#endif
		return -1;
	}
#if 0
	/*
	 * clear all attentions
	 */
	bcm_write_reg32( ETH_MAC_STAT_R, (uint32_t) ~0 );
#endif

#ifdef BCM_DEBUG	
	printf( "bcm57xx: link is up\n" );
#endif
	return 0;
}

static int32_t
bcm_phy_init( void )
{
	static const uint16_t SRAM_HW_CFG = (uint16_t) 0x0b58;
	uint32_t l_val_u32;
	int32_t l_ret_i32 = 0;

	/*
         * get HW configuration from SRAM
	 */
	l_val_u32  = bcm_read_mem32( SRAM_HW_CFG );
	l_val_u32 &= ( BIT32( 5 ) | BIT32( 4 ) );

	switch( l_val_u32 ) {
		case 0x10: {
			#ifdef BCM_DEBUG
			printf( "bcm57xx: copper PHY detected\n" );
			#endif

			bcm_device_u64 |= BCM_DEV_COPPER;
			l_ret_i32       = bcm_mii_phy_init();
		} break;

		case 0x20: {
			#ifdef BCM_DEBUG
			printf( "bcm57xx: fiber PHY detected\n" );
			#endif

			if( !IS_SERDES ) {
				#ifdef BCM_DEBUG
				printf( "bcm57xx: running PHY in gmii/mii mode\n" );
				#endif
				l_ret_i32 = bcm_mii_phy_init();
			} else {
				#ifdef BCM_DEBUG
				printf( "bcm57xx: running PHY in tbi mode\n" );
				#endif
				l_ret_i32 = bcm_tbi_phy_init();
			}

		} break;

		default: {
			#ifdef BCM_DEBUG
			printf( "bcm57xx: unknown PHY type detected, terminating\n" );
			#endif
			l_ret_i32 = -1;
		}

	}

	return l_ret_i32;
}

/*
 * ring initialization
 */
static void
bcm_init_rxprod_ring( void )
{
	uint32_t      v;
	uint32_t      i;

	/*
	 * clear out the whole rx prod ring for sanity
	 */
	memset( (void *) &bcm_rxprod_ring,
		0,
		BCM_RXPROD_RING_SIZE * sizeof( bcm_rxbd_t ) );
	mb();

	/*
	 * assign buffers & indices to the ring members
	 */
	for( i = 0; i < BCM_MAX_RX_BUF; i++ ) {
		bcm_rxprod_ring[i].m_hostaddr_st.m_hi_u32 =
			(uint32_t) ( (uint64_t) &bcm_rx_buffer_pu08[i] >> 32 );
		bcm_rxprod_ring[i].m_hostaddr_st.m_lo_u32 =
			(uint32_t) ( (uint64_t) &bcm_rx_buffer_pu08[i] &
			          (uint64_t) 0xffffffff );
		bcm_rxprod_ring[i].m_idxlen_u32  = ( i << 16 );
		bcm_rxprod_ring[i].m_idxlen_u32 += BCM_BUF_SIZE;
	}

	/*
	 * clear rcb registers & disable rings
	 * NOTE: mini & jumbo rings are not supported,
	 * still rcb's are cleaned out for sanity
	 */
	bcm_write_reg32( BCM_RCB_LENFLAG_u16(      BCM_RXPROD_RCB_JUM ), RCB_FLAG_RING_DISABLED );
	bcm_write_reg32( BCM_RCB_HOSTADDR_HI_u16(  BCM_RXPROD_RCB_JUM ), 0 );
	bcm_write_reg32( BCM_RCB_HOSTADDR_LOW_u16( BCM_RXPROD_RCB_JUM ), 0 );
	bcm_write_reg32( BCM_RCB_NICADDR_u16(      BCM_RXPROD_RCB_JUM ), 0 );

	bcm_write_reg32( BCM_RCB_LENFLAG_u16(      BCM_RXPROD_RCB_STD ), RCB_FLAG_RING_DISABLED );
	bcm_write_reg32( BCM_RCB_HOSTADDR_HI_u16(  BCM_RXPROD_RCB_STD ), 0 );
	bcm_write_reg32( BCM_RCB_HOSTADDR_LOW_u16( BCM_RXPROD_RCB_STD ), 0 );
	bcm_write_reg32( BCM_RCB_NICADDR_u16(      BCM_RXPROD_RCB_STD ), 0 );

	bcm_write_reg32( BCM_RCB_LENFLAG_u16(      BCM_RXPROD_RCB_MIN ), RCB_FLAG_RING_DISABLED );
	bcm_write_reg32( BCM_RCB_HOSTADDR_HI_u16(  BCM_RXPROD_RCB_MIN ), 0 );
	bcm_write_reg32( BCM_RCB_HOSTADDR_LOW_u16( BCM_RXPROD_RCB_MIN ), 0 );
	bcm_write_reg32( BCM_RCB_NICADDR_u16(      BCM_RXPROD_RCB_MIN ), 0 );

	/*
	 * clear rx producer index of std producer ring
	 */
	bcm_write_reg32( RXPROD_PROD_IND, 0 );

	/*
	 * setup rx standard rcb using recommended NIC addr (hard coded)
	 */
	bcm_write_reg32( BCM_RCB_HOSTADDR_HI_u16( BCM_RXPROD_RCB_STD ),
			 (uint32_t) ( (uint64_t) &bcm_rxprod_ring >> 32 ) );
	bcm_write_reg32( BCM_RCB_HOSTADDR_LOW_u16( BCM_RXPROD_RCB_STD ),
		         (uint32_t) ( (uint64_t) &bcm_rxprod_ring & (uint64_t) 0xffffffff ) );
	bcm_write_reg32( BCM_RCB_NICADDR_u16( BCM_RXPROD_RCB_STD ),
			 (uint32_t) BCM_NIC_RX_OFFS );

	if( IS_5704 || IS_5703 ) {
		// 5704: length field = max buffer len
		v = (uint32_t) BCM_BUF_SIZE << 16;
	} else {
		// 5714: length field = number of ring entries
		v = (uint32_t) BCM_RXPROD_RING_SIZE << 16;
	}

	v &= (uint32_t) ~RCB_FLAG_RING_DISABLED;
	bcm_write_reg32( BCM_RCB_LENFLAG_u16( BCM_RXPROD_RCB_STD ), v );
}

static void
bcm_init_rxret_ring( void )
{
	uint32_t      i;
	uint16_t      v;

	/*
	 * clear out the whole rx ret ring for sanity
	 */
	memset( (void *) &bcm_rxret_ring,
		0,
		2 * BCM_RXRET_RING_SIZE * sizeof( bcm_rxbd_t ) );
	mb();

	/*
	 * setup return ring size dependent on installed device
	 */
	bcm_rxret_ring_sz = BCM_RXRET_RING_SIZE;
	if( IS_5704 || IS_5703 ) {
		bcm_rxret_ring_sz *= 2;
	}

        /*
	 * clear rcb memory & disable rings
	 * NOTE: 5714 only supports one return ring,
	 * still all possible rcb's are cleaned out for sanity
	 */
	v = BCM_RXRET_RCB_OFFS;
	for( i = 0; i < BCM_MAX_RXRET_RING; i++ ) {
		bcm_write_mem32( BCM_RCB_LENFLAG_u16( v ),      RCB_FLAG_RING_DISABLED );
		bcm_write_mem32( BCM_RCB_HOSTADDR_HI_u16( v ),  0 );
		bcm_write_mem32( BCM_RCB_HOSTADDR_LOW_u16( v ), 0 );
		bcm_write_mem32( BCM_RCB_NICADDR_u16( v ),      0 );

		v += BCM_RCB_SIZE_u16;
        }

	/*
	 * clear rx consumer index of return ring
	 */
	bcm_write_reg32( RXRET_CONS_IND, 0 );

	/*
	 * setup rx ret rcb
	 * NOTE: NIC address not aplicable in return rings
	 */
	bcm_write_mem32( BCM_RCB_HOSTADDR_HI_u16( BCM_RXRET_RCB_OFFS ),
	                 (uint32_t) ( (uint64_t) &bcm_rxret_ring >> 32 ) );
	bcm_write_mem32( BCM_RCB_HOSTADDR_LOW_u16( BCM_RXRET_RCB_OFFS ),
	                 (uint32_t) ( (uint64_t) &bcm_rxret_ring  &
				   (uint64_t) 0xffffffff ) );
	bcm_write_mem32( BCM_RCB_NICADDR_u16( BCM_RXRET_RCB_OFFS ), 0 );

	i   = bcm_rxret_ring_sz;
	i <<= 16;
	i  &= (uint32_t) ~RCB_FLAG_RING_DISABLED;
	bcm_write_reg32( BCM_RCB_LENFLAG_u16( BCM_RXRET_RCB_OFFS ), i );
}

static void
bcm_init_tx_ring( void )
{
	uint32_t      i;
	uint16_t	   v;

	/*
	 * clear out the whole tx ring for sanity
	 */
	memset( (void *) &bcm_tx_ring,
		0,
		BCM_TX_RING_SIZE * sizeof( bcm_txbd_t ) );
	mb();

        /*
	 * assign buffers to the ring members & setup invariant flags
	 */
        for( i = 0; i < BCM_MAX_TX_BUF; i++ ) {
		bcm_tx_ring[i].m_hostaddr_st.m_hi_u32 =
			(uint32_t) ( (uint64_t) &bcm_tx_buffer_pu08[i] >> 32 );
		bcm_tx_ring[i].m_hostaddr_st.m_lo_u32 =
			(uint32_t) ( (uint64_t) &bcm_tx_buffer_pu08[i] &
			          (uint64_t) 0xffffffff );
		// flags: indicate last packet & coal now
		// -last packet is always true (only one send packet supported)
		// -coal now needed to always get the consumed bd's (since
		//  only a few bd's are set up which permanently are recycled)
		bcm_tx_ring[i].m_lenflags_u32 = ( BIT32( 2 ) | BIT32( 7 ) );
		bcm_tx_ring[i].m_VLANtag_u32  = (uint32_t) 0;	// not used
        }

        /*
	 * clear rcb memory & disable rings
	 * NOTE: 5714 only supports one send ring,
	 * still all possible rcb's are cleaned out for sanity
	 */
        v = BCM_TX_RCB_OFFS;
	for( i = 0; i < BCM_MAX_TX_RING; i++ ) {
		bcm_write_mem32( BCM_RCB_LENFLAG_u16( v ),      RCB_FLAG_RING_DISABLED );
		bcm_write_mem32( BCM_RCB_HOSTADDR_HI_u16( v ),  0 );
		bcm_write_mem32( BCM_RCB_HOSTADDR_LOW_u16( v ), 0 );
		bcm_write_mem32( BCM_RCB_NICADDR_u16( v ),      0 );

		v += BCM_RCB_SIZE_u16;
	}

	/*
	 * clear host/nic producer indices
	 */
	bcm_write_reg32( TX_NIC_PROD_IND, 0 );
	bcm_write_reg32( TX_PROD_IND, 0 );

	/*
	 * setup tx rcb using recommended NIC addr (hard coded)
	 */
	bcm_write_mem32( BCM_RCB_HOSTADDR_HI_u16( BCM_TX_RCB_OFFS ),
			          (uint32_t) ( (uint64_t) &bcm_tx_ring >> 32 ) );
	bcm_write_mem32( BCM_RCB_HOSTADDR_LOW_u16( BCM_TX_RCB_OFFS ),
			          (uint32_t) ( (uint64_t) &bcm_tx_ring &
				            (uint64_t) 0xffffffff ) );
	bcm_write_mem32( BCM_RCB_NICADDR_u16( BCM_TX_RCB_OFFS ),
			          (uint32_t) BCM_NIC_TX_OFFS );

	if( IS_5704 || IS_5703 ) {
		// 5704: length field = max buffer len
		i = (uint32_t) BCM_BUF_SIZE << 16;
	} else {
		// 5714: length field = number of ring entries
		i = (uint32_t) BCM_TX_RING_SIZE << 16;
	}

	i &= ( uint32_t ) ~RCB_FLAG_RING_DISABLED;
	bcm_write_mem32( BCM_RCB_LENFLAG_u16( BCM_TX_RCB_OFFS ), i );

	/*
	 * remember the next bd index to be used
	 * & number of available buffers
	 */
	bcm_tx_stop_u32     = BCM_MAX_TX_BUF;
	bcm_tx_bufavail_u32 = BCM_MAX_TX_BUF;
}

static int32_t
bcm_mac_init( uint8_t *f_mac_pu08 )
{
	static const uint16_t MEM_MAC_LO = (uint16_t) 0x0c18;
	static const uint16_t MEM_MAC_HI = (uint16_t) 0x0c14;

	uint32_t              NVR_MAC_LO = (uint16_t) 0x80;
	uint32_t              NVR_MAC_HI = (uint16_t) 0x7c;

	bcm_addr64_t       l_mac_st;
	uint32_t              i;
	uint32_t              v;

	/*
	 * Use MAC address from device tree if possible
	 */
	for( i = 0, v = 0; i < 6; i++ ) {
		v += (uint32_t) f_mac_pu08[i];
	}

	if( v != 0 ) {
		l_mac_st.m_hi_u32  = ( ( (uint32_t) f_mac_pu08[0]) <<  8 );
		l_mac_st.m_hi_u32 |= ( ( (uint32_t) f_mac_pu08[1]) <<  0 );
		l_mac_st.m_lo_u32  = ( ( (uint32_t) f_mac_pu08[2]) << 24 );
		l_mac_st.m_lo_u32 |= ( ( (uint32_t) f_mac_pu08[3]) << 16 );
		l_mac_st.m_lo_u32 |= ( ( (uint32_t) f_mac_pu08[4]) <<  8 );
		l_mac_st.m_lo_u32 |= ( ( (uint32_t) f_mac_pu08[5]) <<  0 );
	} else {
		/*
		 * try to read MAC address from MAC mailbox
		 */
		l_mac_st.m_hi_u32 = bcm_read_mem32( MEM_MAC_HI );

		if( ( l_mac_st.m_hi_u32 >> 16 ) == (uint32_t) 0x484b ) {
			l_mac_st.m_hi_u32 &= (uint32_t) 0xffff;
			l_mac_st.m_lo_u32  = bcm_read_mem32( MEM_MAC_LO );
		} else {
			int32_t l_err_i32;

			/*
			 * otherwise retrieve MAC address from NVRam
			 */
			if( ( bcm_read_reg32( MAC_FUNC_R ) & BIT32( 2 ) ) != 0 ) {
				// secondary MAC is in use, address in NVRAM changes
				NVR_MAC_LO += 0x50;
				NVR_MAC_HI += 0x50;
			}
		
			l_err_i32  = bcm_nvram_read( NVR_MAC_LO, &l_mac_st.m_lo_u32, 1 );
			l_err_i32 += bcm_nvram_read( NVR_MAC_HI, &l_mac_st.m_hi_u32, 1 );

			// return on read error
			if( l_err_i32 < 0 ) {
#ifdef BCM_DEBUG
				printf( "bcm57xx: failed to retrieve MAC address\n" );
#endif
				return -1;
			}
		}
	}

        /*
         * write the mac addr into the NIC's register area
         */
	bcm_write_reg32( MAC_ADDR_OFFS_HI(0), l_mac_st.m_hi_u32 );
	bcm_write_reg32( MAC_ADDR_OFFS_LO(0), l_mac_st.m_lo_u32 );
	for( i = 1; i < BCM_NUM_MAC_ADDR; i++ ) {
		bcm_write_reg32( MAC_ADDR_OFFS_HI(i), 0 );
		bcm_write_reg32( MAC_ADDR_OFFS_LO(i), 0 );
	}
	
	/*
	 * WY 26.01.07
	 * not needed anymore, s.a.
	if( IS_5704 != 0 ) {

		v = MAC5704_ADDR_OFFS;
		for( i = 0; i < BCM_NUM_MAC5704_ADDR; i++ ) {
			bcm_write_reg32( v, l_mac_st.m_hi_u32 );
			v += sizeof( uint32_t );
			bcm_write_reg32( v, l_mac_st.m_lo_u32 );
			v += sizeof( uint32_t );
		}

	}
	*/

        /*
         * return MAC address as string
         */
        f_mac_pu08[0] = (uint8_t) ( ( l_mac_st.m_hi_u32 >>  8 ) & (uint32_t) 0xff );
        f_mac_pu08[1] = (uint8_t) ( ( l_mac_st.m_hi_u32       ) & (uint32_t) 0xff );
        f_mac_pu08[2] = (uint8_t) ( ( l_mac_st.m_lo_u32 >> 24 ) & (uint32_t) 0xff );
        f_mac_pu08[3] = (uint8_t) ( ( l_mac_st.m_lo_u32 >> 16 ) & (uint32_t) 0xff );
        f_mac_pu08[4] = (uint8_t) ( ( l_mac_st.m_lo_u32 >>  8 ) & (uint32_t) 0xff );
        f_mac_pu08[5] = (uint8_t) ( ( l_mac_st.m_lo_u32       ) & (uint32_t) 0xff );

#ifdef BCM_DEBUG
	do {
		int32_t i;
		printf( "bcm57xx: retrieved MAC address " );

		for( i = 0; i < 6; i++ ) {
			printf( "%02X", f_mac_pu08[i] );

			if( i != 5 ) {
				printf( ":" );
			}

		}

		printf( "\n" );
	} while( 0 );
#endif 

	return 0;
}


/*
 ******************************************************************************
 * ASF Firmware
 ******************************************************************************
 */


#ifdef BCM_DEBUG
#ifdef BCM_SHOW_ASF_REGS
static void
bcm_asf_check_register( void )
{
	uint32_t i;

	i = bcm_read_reg32( ASF_CTRL_R );
	printf( "bcm57xx: ASF control          : %x\n", i );

	i = bcm_read_reg32( ASF_WATCHDOG_TIMER_R );
	printf( "bcm57xx: ASF Watchdog Timer   : %x\n", i );

	i = bcm_read_reg32( ASF_HEARTBEAT_TIMER_R );
	printf( "bcm57xx: ASF Heartbeat Timer  : %x\n", i );

	i = bcm_read_reg32( ASF_POLL_TIMER_R );
	printf( "bcm57xx: ASF Poll Timer       : %x\n", i );

	i = bcm_read_reg32( POLL_LEGACY_TIMER_R );
	printf( "bcm57xx: Poll Legacy Timer    : %x\n", i );

	i = bcm_read_reg32( RETRANSMISSION_TIMER_R );
	printf( "bcm57xx: Retransmission Timer : %x\n", i );

	i = bcm_read_reg32( TIME_STAMP_COUNTER_R );
	printf( "bcm57xx: Time Stamp Counter   : %x\n", i );

	i = bcm_read_reg32( RX_CPU_MODE_R );
	printf( "bcm57xx: RX RISC Mode         : %x\n", i );

	i = bcm_read_reg32( RX_CPU_STATE_R );
	printf( "bcm57xx: RX RISC State        : %x\n", i );

	i = bcm_read_reg32( RX_CPU_PC_R );
	printf( "bcm57xx: RX RISC Prg. Counter : %x\n", i );
}
#endif
#endif

static int
bcm_fw_halt( void )
{
	int i;

	bcm_write_mem32( BCM_FW_MBX_CMD, BCM_NICDRV_PAUSE_FW );
	bcm_setb_reg32( RX_CPU_EVENT_R, BIT32( 14 ) );

	/* Wait for RX cpu to ACK the event.  */
	for (i = 0; i < 100; i++) {
		if(bcm_read_reg32( RX_CPU_EVENT_R ) & BIT32( 14 ))
			break;
		SLOF_msleep(1);
	}
	if( i>= 100)
		return -1;
	return 0;
}


#ifdef BCM_SW_AUTONEG
static void
bcm_sw_autoneg( void ) {
	uint32_t i, j, k;
	uint32_t SerDesCfg;
	uint32_t SgDigControl;
	uint32_t SgDigStatus;
	uint32_t ExpectedSgDigControl;
	int   AutoNegJustInitiated = 0;

	// step 1: init TX 1000BX Autoneg. Register to zero
	bcm_write_reg32(TX_1000BX_AUTONEG_R, 0);

	// step 2&3: set TBI mode
	bcm_setb_reg32( ETH_MAC_MODE_R, BIT32( 2 ) | BIT32( 3 ) );
	SLOF_usleep(10);

	// step 4: enable link attention
	bcm_setb_reg32( ETH_MAC_EVT_EN_R, BIT32( 12 ) );

	// step 5: preserve voltage regulator bits
	SerDesCfg = bcm_read_reg32(SERDES_CTRL_R) & ( BIT32( 20 ) | BIT32( 21 )
	                                            | BIT32( 22 ) | BIT32( 23 ) );

	// step 6: preserve voltage regulator bits
	SgDigControl = bcm_read_reg32(HW_AUTONEG_CTRL_R);

	// step 7: if device is NOT set-up for auto negotiation, then go to step 26
	// goto bcm_setup_phy_step26;

	// We want to use auto negotiation

	// step 8: we don't want to use flow control
	ExpectedSgDigControl = 0x81388400; // no flow control

	// step 9: compare SgDigControl with 0x81388400
	if(SgDigControl == ExpectedSgDigControl) {
		goto bcm_setup_phy_step17;
	}
#ifdef BCM_DEBUG
	printf("bcm57xx: SgDigControl = %08X\n", SgDigControl);
#endif
	// step 10
	bcm_write_reg32(SERDES_CTRL_R, SerDesCfg | 0xC011880);

	// step 11: restart auto negotiation
	bcm_write_reg32(HW_AUTONEG_CTRL_R, ExpectedSgDigControl | BIT32( 30 ) );

	// step 12: read back HW_AUTONEG_CTRL_R
	bcm_read_reg32(HW_AUTONEG_CTRL_R);

	// step 13
	SLOF_usleep( 5 );

	// step 14,15,16: same as step 11, but don't restart auto neg.
	bcm_write_reg32(HW_AUTONEG_CTRL_R, ExpectedSgDigControl);
	AutoNegJustInitiated = 1;
	goto bcm_setup_phy_step30;

	// step 17:
	bcm_setup_phy_step17:
	if( ( bcm_read_reg32(ETH_MAC_STAT_R) & ( BIT32( 1 ) | BIT32( 0 ) ) ) == 0 ) {
		goto bcm_setup_phy_step30;
	}

	// step 18: Get HW Autoneg. Status
	SgDigStatus = bcm_read_reg32(HW_AUTONEG_STAT_R);

	// step 19:
	if( ( SgDigStatus & BIT32(1) )
	&&  ( bcm_read_reg32(ETH_MAC_STAT_R) & BIT32(0) ) ) {
		// resolve the current flow control?
		AutoNegJustInitiated = 0;
		goto bcm_setup_phy_step30;
	}

	// step 20
	if( SgDigStatus & BIT32(1) ) {
		goto bcm_setup_phy_step30;
	}
	if( AutoNegJustInitiated != 0) {
		AutoNegJustInitiated = 0;
		goto bcm_setup_phy_step29;
	}

	// step 21, 22, 23, 24: fallback to 1000Mbps-FullDuplex forced mode
	if( ( bcm_read_reg32( MAC_FUNC_R ) & BIT32( 2 ) ) == 0 ) {
		// port 0
		bcm_write_reg32( SERDES_CTRL_R, 0xC010880 );
	}
	else {	// port 1
		bcm_write_reg32( SERDES_CTRL_R, 0x4010880 );
	}
	// set to 1000Mbps-FullDuplex
	bcm_write_reg32(HW_AUTONEG_CTRL_R, 0x1388400);
	// read back
	bcm_read_reg32(HW_AUTONEG_CTRL_R);
	SLOF_usleep( 40 );

	// step 25: a little bit reduces...
	goto bcm_setup_phy_step30;

	// step 26: check if auto negotiation bit is NOT set
//	bcm_setup_phy_step26:
	if( ( SgDigControl & BIT32(31) )== 0 ) {
		printf("No autoneg.\n");
		goto bcm_setup_phy_step29;
	}

	// step 27:
	if( ( bcm_read_reg32( MAC_FUNC_R ) & BIT32( 2 ) ) == 0 ) {
		// port 0
		bcm_write_reg32( SERDES_CTRL_R, 0xC010880 );
	}
	else {	// port 1
		bcm_write_reg32( SERDES_CTRL_R, 0x4010880 );
	}

	// step 28: disable auto neg. and force 1000FD mode
	bcm_write_reg32(HW_AUTONEG_CTRL_R, 0x1388400);

	// step 29-31: omitted for 5704S
	bcm_setup_phy_step29:
	bcm_setup_phy_step30:

	// step 32: clear link attentions
	i = bcm_read_reg32( ETH_MAC_STAT_R ) | BIT32( 3 ) | BIT32( 4 );
	k = 100;
	do {
		bcm_write_reg32( ETH_MAC_STAT_R, i );
		j = bcm_read_reg32( ETH_MAC_STAT_R );
		if( ( j & BIT32( 3 ) ) != 0 )
			i = i & ~(BIT32( 3 ));
		if( ( j & BIT32( 4 ) ) != 0 )
			i = i & ~(BIT32( 4 ));
		--k;
	} while( i & k);

	// step 33
	if( ( bcm_read_reg32( ETH_MAC_STAT_R ) & BIT32( 0 ) ) == 0 ) {
		goto bcm_setup_phy_step35;
	}

	// step 34
	i = bcm_read_reg32( ETH_MAC_MODE_R );
	i|= BIT32( 17 );
	bcm_write_reg32( ETH_MAC_MODE_R, i );

	SLOF_usleep( 1 );

	i = bcm_read_reg32( ETH_MAC_STAT_R );
	i&= ~BIT32( 17 );
	bcm_write_reg32( ETH_MAC_STAT_R, i );

	// step 35 & 36: done
	bcm_setup_phy_step35:
#ifdef BCM_DEBUG
	printf("bcm57xx: SetupPhy\n");
#endif
	return;
}
#endif

static int
bcm_handle_events( void ) {
#ifdef BCM_DEBUG
#ifdef BCM_SHOW_ASF_REGS
	// ASF REGISTER CHECK
	// ------------------
	// check if watchdog timer expired
	if( bcm_read_reg32( ASF_WATCHDOG_TIMER_R ) == 0 ) {
		// Show ASF registers
		bcm_asf_check_register();

		// rearm watchdog timer
		bcm_write_reg32( ASF_WATCHDOG_TIMER_R, 5 );
	}
#endif
#endif

#ifdef BCM_SW_AUTONEG
	// AUTO NEGOTIATION
	// ----------------

	// Check event for Auto Negotiation
	if( ( bcm_read_reg32( ETH_MAC_STAT_R ) &
	    ( BIT32( 12 ) | BIT32( 3 ) | BIT32( 0 ) ) ) != 0 ) {
		// link timer procedure
		bcm_sw_autoneg();
	}
#endif

	// ASF FW HEARTBEAT
	// ----------------

	// check if heartsbeat timer expired
	if( bcm_read_reg32( ASF_HEARTBEAT_TIMER_R ) <= 2) {
		int i;

		// Send heartbeat event
		bcm_write_mem32( BCM_FW_MBX_CMD, BCM_NICDRV_ALIVE );
		bcm_write_mem32( BCM_FW_MBX_LEN, 4 );
		bcm_write_mem32( BCM_FW_MBX_DATA, 5 );
		bcm_setb_reg32( RX_CPU_EVENT_R, BIT32( 14 ) );

		// Wait for RX cpu to ACK the event.
		for (i = 100; i > 0; i--) {
			if(bcm_read_reg32( RX_CPU_EVENT_R ) & BIT32( 14 ))
				break;
			SLOF_msleep(1);
		}
		if( i == 0) {
#ifdef BCM_DEBUG
			printf( "bcm57xx: RX cpu did not acknowledge heartbeat event\n" );
#endif
			return -1;
		}

		// rearm heartbeat timer
		bcm_write_reg32( ASF_HEARTBEAT_TIMER_R, 5 );
	}
	return 0;
}

/*
 * interface
 ******************************************************************************
 */
  
/*
 * bcm_receive
 */
static int
bcm_receive( char *f_buffer_pc, int f_len_i )
{
	uint32_t l_rxret_prod_u32  = bcm_read_reg32( RXRET_PROD_IND );
	uint32_t l_rxret_cons_u32  = bcm_read_reg32( RXRET_CONS_IND );
	uint32_t l_rxprod_prod_u32 = bcm_read_reg32( RXPROD_PROD_IND );
	int   l_ret_i;
#ifdef BCM_DEBUG
#ifdef BCM_SHOW_RCV_DATA
	int i, j;
#endif
#endif

	/*
	 * NOTE: dummy read to ensure data has already been DMA'd is
	 *       done by the indice reads
	 */

	bcm_handle_events();

	/*
	 * if producer index == consumer index then nothing was received
	 */
	if( l_rxret_prod_u32 == l_rxret_cons_u32 ) {
		return 0;
	}

	/*
	 * discard erroneous packets
	 */
	if( ( bcm_rxret_ring[l_rxret_cons_u32].m_typeflags_u32 & BIT32( 10 ) ) != 0 ) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: erroneous frame received\n" );
		printf( "       : frame discarded\n" );
#endif
		l_ret_i = 0;
	} else {
	        /*
	         * get packet length, throw away checksum (last 4 bytes)
	         */
	        l_ret_i = (int) ( bcm_rxret_ring[l_rxret_cons_u32].m_idxlen_u32 &
	                          (uint32_t) 0xffff ) - (int) 4;

		/*
		 * discard oversized packets
	         */
		if( l_ret_i > f_len_i ) {
#ifdef BCM_DEBUG
			printf( "bcm57xx: receive packet length error:\n" );
			printf( "       : incoming 0x%X bytes, available buffer 0x%X bytes\n", l_ret_i, f_len_i );
			printf( "       : frame discarded\n" );
#endif		
			l_ret_i = 0;
		}

        }

        /*
         * copy & update data & indices
         */
	if( l_ret_i != 0 ) {
		uint64_t l_cpyaddr_u64;

		l_cpyaddr_u64  = 
		( (uint64_t) bcm_rxret_ring[l_rxret_cons_u32].m_hostaddr_st.m_hi_u32 << 32 );
		l_cpyaddr_u64 += 
		( (uint64_t) bcm_rxret_ring[l_rxret_cons_u32].m_hostaddr_st.m_lo_u32 );

// FIXME:
		if(l_cpyaddr_u64 == 0) {
#ifdef BCM_DEBUG
			printf("bcm57xx: NULL address\n");
#endif
			return 0;
		}
// 
		memcpy( (void *) f_buffer_pc,
		        (void *) l_cpyaddr_u64,
		        (size_t) l_ret_i );

	}

	/*
	 * replenish bd to producer ring
	 */
	bcm_rxprod_ring[l_rxprod_prod_u32] =
	                                bcm_rxret_ring[l_rxret_cons_u32];
        bcm_rxprod_ring[l_rxprod_prod_u32].m_idxlen_u32 = 
	                                ( l_rxprod_prod_u32 << 16 );
	bcm_rxprod_ring[l_rxprod_prod_u32].m_idxlen_u32 +=
	                                (uint32_t) BCM_BUF_SIZE;

        /*
         * update producer ring's producer index
         */
        l_rxprod_prod_u32 = ( l_rxprod_prod_u32 + 1 ) & ( BCM_RXPROD_RING_SIZE - 1 );

        /*
         * move to the next bd in return ring
         */
        l_rxret_cons_u32 = ( l_rxret_cons_u32 + 1 ) & (  bcm_rxret_ring_sz - 1 );

	/*
	 * synchronize before new indices are send to NIC
	 */
	mb();

        /*
         * write back new indices
         */
        bcm_write_reg32( RXRET_CONS_IND,  l_rxret_cons_u32  );
        bcm_write_reg32( RXPROD_PROD_IND, l_rxprod_prod_u32 );

#ifdef BCM_DEBUG
#ifdef BCM_SHOW_RCV
	if( l_ret_i != 0 ) {
		printf( "bcm57xx: received bytes: %d\n", l_ret_i );
	}
#ifdef BCM_SHOW_RCV_DATA
	for( i = 0, j = 0; i < l_ret_i; i++ ) {
		printf( "%02X ", ( uint32_t ) f_buffer_pc[i] );

		if( ( ++j % 0x18 ) == 0 ) {
			printf( "\n" );
		}
	}

	if( ( i % 0x18 ) != 0 ) {
		printf( "\n" );
	}
#endif
#endif
#endif

        /*
         * return packet length
         */
        return l_ret_i;
}

static int
bcm_xmit( char *f_buffer_pc, int f_len_i )
{
	uint32_t l_tx_cons_u32 = bcm_read_reg32( TX_CONS_IND );
	uint32_t l_tx_prod_u32 = bcm_read_reg32( TX_PROD_IND );
	uint64_t l_cpyaddr_u64;

#ifdef BCM_DEBUG
#ifdef BCM_SHOW_XMIT_DATA
	int i, j;
#endif
#ifdef BCM_SHOW_IDX
	printf( "\n" );
	printf( "bcm57xx: TX_PROD_IND    : 0x%03X\n", l_tx_prod_u32 );
	printf( "bcm57xx: TX_CONS_IND    : 0x%03X\n", l_tx_cons_u32 );
	printf( "bcm57xx: RXPROD_PROD_IND: 0x%03X\n", bcm_read_reg32( RXPROD_PROD_IND ) );
	printf( "bcm57xx: RXPROD_CONS_IND: 0x%03X\n", bcm_read_reg32( RXPROD_CONS_IND ) );
	printf( "bcm57xx: RXRET_PROD_IND : 0x%03X\n", bcm_read_reg32( RXRET_PROD_IND ) );
	printf( "bcm57xx: RXRET_CONS_IND : 0x%03X\n", bcm_read_reg32( RXRET_CONS_IND ) );
	printf( "bcm57xx: available txb  : 0x%03X\n", bcm_tx_bufavail_u32 );
#endif
#ifdef BCM_SHOW_STATS
	printf( "bcm57xx: bcm_status.m_st_word_u32:    %08X\n",               bcm_status.m_st_word_u32 );
	printf( "bcm57xx: bcm_status.m_st_tag_u32 :    %08X\n",               bcm_status.m_st_tag_u32 );
	printf( "bcm57xx: bcm_status.m_rxprod_cons_u16:    %04X\n", ( uint32_t ) bcm_status.m_rxprod_cons_u16 );
	printf( "bcm57xx: bcm_status.m_unused_u16:         %04X\n", ( uint32_t ) bcm_status.m_unused_u16 );
	printf( "bcm57xx: bcm_status.m_unused_u32:     %08X\n",               bcm_status.m_unused_u32 );
	printf( "bcm57xx: bcm_status.m_tx_cons_u16:        %04X\n", ( uint32_t ) bcm_status.m_tx_cons_u16 );
	printf( "bcm57xx: bcm_status.m_rxret_prod_u16:     %04X\n", ( uint32_t ) bcm_status.m_rxret_prod_u16 );
#endif
#endif

	bcm_handle_events();

	/*
	 * make all consumed bd's available in the ring again
	 * this way only a few buffers are needed instead of
	 * having 512 buffers allocated
	 */
	while( bcm_tx_start_u32 != l_tx_cons_u32 ) {
		bcm_tx_ring[bcm_tx_stop_u32] = bcm_tx_ring[bcm_tx_start_u32];
		bcm_tx_stop_u32  = ( bcm_tx_stop_u32  + 1 ) & ( BCM_TX_RING_SIZE - 1 );
		bcm_tx_start_u32 = ( bcm_tx_start_u32 + 1 ) & ( BCM_TX_RING_SIZE - 1 );
		bcm_tx_bufavail_u32++;
	}

	/*
	 * check for tx buffer availability
	 */
	if( bcm_tx_bufavail_u32 == 0 ) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: no more transmit buffers available\n" );
#endif
		return 0;
	}

	/*
	 * setup next available bd in tx ring
	 */
	bcm_tx_ring[l_tx_prod_u32].m_lenflags_u32  = ( BIT32( 2 ) | BIT32( 7 ) /*| BIT32( 6 )*/ );
	bcm_tx_ring[l_tx_prod_u32].m_lenflags_u32 += ( (uint32_t) f_len_i << 16 );
//	bcm_tx_ring[l_tx_prod_u32].m_VLANtag_u32   = BCM_VLAN_TAG;

	l_cpyaddr_u64  = ( (uint64_t) bcm_tx_ring[l_tx_prod_u32].m_hostaddr_st.m_hi_u32 << 32 );
	l_cpyaddr_u64 += ( (uint64_t) bcm_tx_ring[l_tx_prod_u32].m_hostaddr_st.m_lo_u32 );

#ifdef BCM_DEBUG
#ifdef BCM_SHOW_XMIT_STATS
	printf("bcm57xx: xmit: l_cpyaddr_u64: 0x%lx\n", l_cpyaddr_u64 );
	printf("               f_buffer_pc  : 0x%lx\n", f_buffer_pc );
	printf("               f_len_i      : %d\n", f_len_i );
#endif
#endif
	memcpy( (void *) l_cpyaddr_u64, (void *) f_buffer_pc, (size_t) f_len_i );

	/*
	 * update tx producer index & available buffers
	 */
	l_tx_prod_u32 = ( l_tx_prod_u32 + 1 ) & ( BCM_TX_RING_SIZE - 1 );
	bcm_tx_bufavail_u32--;

	/*
	 * synchronize before new index is send to NIC
	 */
	mb();

	bcm_write_reg32( TX_PROD_IND, l_tx_prod_u32 );

#ifdef BCM_DEBUG
#ifdef BCM_SHOW_XMIT
	printf( "bcm57xx: sent bytes: %d\n", f_len_i );
#ifdef BCM_SHOW_XMIT_DATA
	for( i = 0, j = 0; i < f_len_i; i++ ) {
		printf( "%02X ", ( uint32_t ) f_buffer_pc[i] );

		if( ( ++j % 0x18 ) == 0 ) {
			printf( "\n" );
		}

	}
	if( ( i % 0x18 ) != 0 ) {
		printf( "\n" );
	}
#endif
#endif

#ifdef BCM_SHOW_STATS
	// coalesce status block now
	bcm_setb_reg32( HOST_COAL_MODE_R, BIT32( 3 ) | BIT32( 1 ) );
#endif

#endif
	return f_len_i;
}

static int
check_driver( uint16_t vendor_id, uint16_t device_id )
{
	uint64_t i;

	/*
	 * checks whether the driver is handling this device
	 * by verifying vendor & device id
	 * vendor id 0x14e4 == Broadcom
	 */
        if( vendor_id != 0x14e4 ) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: netdevice not supported, illegal vendor id\n" );
#endif
		return -1;
	}

	for( i = 0; bcm_dev[i].m_dev_u32 != 0; i++ ) {
		if( bcm_dev[i].m_dev_u32 == (uint32_t) device_id ) {
			// success
			break;
		}
	}

	if(bcm_dev[i].m_dev_u32 == 0) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: netdevice not supported, illegal device ID\n" );
#endif
		return -1;
	}

	/*
	 * initialize static variables
	 */
	bcm_device_u64 = bcm_dev[i].m_devmsk_u64;
	bcm_rxret_ring_sz = 0;
	bcm_baseaddr_u64  = 0;
	bcm_memaddr_u64   = 0;

	bcm_tx_start_u32    = 0;
	bcm_tx_stop_u32     = 0;
	bcm_tx_bufavail_u32 = 0;

	return 0;
}

static void
bcm_wol_activate(void)
{
#ifdef BCM_DEBUG
	uint16_t reg_pwr_cap;
#endif
	uint16_t reg_pwr_crtl;
	uint32_t wol_mode;

	wol_mode = bcm_read_reg32( WOL_MODE_R );
	bcm_write_reg32( WOL_MODE_R, wol_mode | BIT32(0) );

#ifdef BCM_DEBUG
	printf( "bcm57xx: WOL activating..." );
#endif

//	bcm_write_mem32( BCM_NICDRV_STATE_MBX, NIC_FWDRV_STATE_WOL );
//	SLOF_msleep( 100 );

#ifdef BCM_DEBUG
	reg_pwr_cap = SLOF_pci_config_read16(0x4a);
	/*reg_pwr_cap = snk_kernel_interface->pci_config_read( bcm_pcicfg_puid,
	                                                     2,
	                                                     bcm_pcicfg_bus,
	                                                     bcm_pcicfg_devfn,
	                                                     0x4a );*/
	printf( "bcm57xx: PM Capability Register: %04X\n", reg_pwr_cap );
#endif
	/* get curretn power control register */
	reg_pwr_crtl = SLOF_pci_config_read16(0x4c);
	/*reg_pwr_crtl = snk_kernel_interface->pci_config_read( bcm_pcicfg_puid,
	                                                      2,
	                                                      bcm_pcicfg_bus,
	                                                      bcm_pcicfg_devfn,
	                                                      0x4c );*/

#ifdef BCM_DEBUG
	printf( "bcm57xx: PM Control/Status Register: %04X\n", reg_pwr_crtl );
#endif

	/* switch to power state D0 */
	reg_pwr_crtl |= 0x8000;
	reg_pwr_crtl &= ~(0x0003);
	SLOF_pci_config_write16(0x4c, reg_pwr_crtl);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        2,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        0x4c,
	                                        reg_pwr_crtl );*/
	SLOF_msleep(10);

/*
	bcm_write_mem32( BCM_NICDRV_WOL_MBX, BCM_WOL_MAGIC_NUMBER |
	                                     NIC_WOLDRV_STATE_SHUTDOWN |
	                                     NIC_WOLDRV_WOL |
	                                     NIC_WOLDRV_SET_MAGIC_PKT );
*/

	/* switch to power state D3hot */
/*
	reg_pwr_crtl |= 0x0103;
	SLOF_pci_config_write16(0x4c, reg_pwr_crtl);
	snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        2,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        0x4c,
	                                        reg_pwr_crtl );
	SLOF_msleep(10);
*/

#ifdef BCM_DEBUG
	reg_pwr_crtl = SLOF_pci_config_read16(0x4c);
	/*reg_pwr_crtl = snk_kernel_interface->pci_config_read( bcm_pcicfg_puid,
	                                                      2,
	                                                      bcm_pcicfg_bus,
	                                                      bcm_pcicfg_devfn,
	                                                      0x4c );*/

	printf( "bcm57xx: PM Control/Status Register: %04X\n", reg_pwr_crtl );
#endif

#ifdef BCM_DEBUG
	printf( "bcm57xx: WOL activated" );
#endif
}

static int
bcm_init( net_driver_t *driver )
{
	static const uint32_t  lc_Maxwait_u32 = (uint32_t) 1000;
	uint32_t               l_baseaddrL_u32;
	uint32_t               l_baseaddrH_u32;
	uint32_t               i;
	uint8_t                *mac_addr = driver->mac_addr;

	if(driver->running != 0) {
		return 0;
	}
#ifdef BCM_DEBUG
	printf( "bcm57xx: detected device " );
	if( IS_5703 ) {
		printf( "5703S\n" );
	} else if( IS_5704 ) {
		printf( "5704" );

		if( IS_SERDES ) {
			printf( "S\n" );
		} else {
			printf( "C\n" );
		}

	} else if( IS_5714 ) {
		printf( "5714\n" );
	}
#endif
	/*
	 * setup register & memory base addresses of NIC
	 */
	l_baseaddrL_u32 = (uint32_t) ~0xf &
			  (uint32_t) SLOF_pci_config_read32(PCI_BAR1_R);
	/*l_baseaddrL_u32 = ( (uint32_t) ~0xf &
	      (uint32_t) snk_kernel_interface->pci_config_read( bcm_pcicfg_puid,
	                                                     4,
	                                                     bcm_pcicfg_bus,
	                                                     bcm_pcicfg_devfn,
	                                                     PCI_BAR1_R ) );*/

	l_baseaddrH_u32 = (uint32_t) SLOF_pci_config_read32(PCI_BAR2_R);
	/*l_baseaddrH_u32 = 
	      (uint32_t) snk_kernel_interface->pci_config_read( bcm_pcicfg_puid,
	                                                     4,
	                                                     bcm_pcicfg_bus,
	                                                     bcm_pcicfg_devfn,
	                                                     PCI_BAR2_R );*/
	bcm_baseaddr_u64   = (uint64_t) l_baseaddrH_u32;
	bcm_baseaddr_u64 <<= 32;
	bcm_baseaddr_u64  += (uint64_t) l_baseaddrL_u32;
	bcm_baseaddr_u64 =
		(uint64_t) SLOF_translate_my_address((void *)bcm_baseaddr_u64);
	/*snk_kernel_interface->translate_addr(((void *)&(bcm_baseaddr_u64)));*/
	bcm_memaddr_u64    = bcm_baseaddr_u64 + BCM_MEMORY_OFFS;

#ifdef BCM_DEBUG
	printf( "bcm57xx: device's register base high address = 0x%08X\n", l_baseaddrH_u32 );
	printf( "bcm57xx: device's register base low address  = 0x%08X\n", l_baseaddrL_u32 );
	printf( "bcm57xx: device's register address           = 0x%llx\n", bcm_baseaddr_u64 );
#endif

	/*
	 * 57xx hardware initialization
	 * BCM57xx Programmer's Guide: Section 8, "Initialization"
	 * steps 1 through 101
	 */

	// step 1: enable bus master & memory space in command reg
	i = ( BIT32( 10 ) | BIT32( 2 ) | BIT32( 1 ) );
	SLOF_pci_config_write16(PCI_COM_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        2,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_COM_R,
	                                        ( int ) i );*/
	// step 2: disable & mask interrupts & enable pci byte/word swapping & enable indirect addressing mode
	i = ( BIT32( 8 ) | BIT32( 7 ) | BIT32( 3 ) | BIT32( 2 ) | BIT32( 1 ) | BIT32( 0 ) );

	SLOF_pci_config_write32(PCI_MISC_HCTRL_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_MISC_HCTRL_R,
	                                        ( int ) i );*/

	/*
	 * from now on access may be made through the local
	 * read/write functions
	 */

	// step 3: Save ahche line size register
	// omitted, because register is not used for 5704

	// step 4: acquire the nvram lock
	if( bcm_nvram_lock() != 0 ) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: locking NVRAM failed\n" );
#endif
		return -1;
	}

	// step 5: prepare the chip for writing TG3_MAGIC_NUMBER
	bcm_setb_reg32( MEMARB_MODE_R, BIT32( 1 ) );
	i = ( BIT32( 8 ) | BIT32( 7 ) | BIT32( 3 ) | BIT32( 2 ) | BIT32( 1 ) | BIT32( 0 ) );
	SLOF_pci_config_write32(PCI_MISC_HCTRL_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_MISC_HCTRL_R,
	                                        ( int ) i );*/
	bcm_write_reg32( MODE_CTRL_R, BIT32( 23 ) | BIT32( 20 ) |
	                              BIT32( 17 ) | BIT32( 16 ) |
	                              BIT32( 14 ) | BIT32( 13 ) |
	                              BIT32(  5 ) | BIT32(  4 ) |
	                              BIT32(  2 ) | BIT32(  1 ) );

	// step 6: write TG3_MAGIC_NUMBER
	bcm_write_mem32( BCM_FW_MBX, BCM_MAGIC_NUMBER );

	// step 7: reset core clocks

	if( IS_5714 ) {
		bcm_setb_reg32( MISC_CFG_R, BIT32( 26 ) | BIT32( 0 ) );
	} else {
		bcm_setb_reg32( MISC_CFG_R, BIT32( 0 ) );
	}
	// step 8
	SLOF_msleep( 20 );

	// step 9: disable & mask interrupts & enable indirect addressing mode &
	//              enable pci byte/word swapping initialize the misc host control register
	i = ( BIT32( 8 ) | BIT32( 7 ) | BIT32( 3 ) | BIT32( 2 ) | BIT32( 1 ) | BIT32( 0 ) );
	SLOF_pci_config_write32(PCI_MISC_HCTRL_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_MISC_HCTRL_R,
	                                        ( int ) i );*/

	// step 10: set but master et cetera
	i = ( BIT32( 10 ) | BIT32( 2 ) | BIT32( 1 ) );
	SLOF_pci_config_write16(PCI_COM_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        2,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_COM_R,
	                                        ( int ) i );*/

	// step 11: disable PCI-X relaxed ordering
	bcm_clrb_reg16( PCI_X_COM_R, BIT16( 1 ) );

	// step 12: enable the MAC memory arbiter
	bcm_setb_reg32( MEMARB_MODE_R, BIT32( 1 ) );

	// step 13: omitted, only for BCM5700
	// step 14: s. step 10
	i = ( BIT32( 8 ) | BIT32( 7 ) | BIT32( 3 ) | BIT32( 2 ) | BIT32( 1 ) | BIT32( 0 ) );
	SLOF_pci_config_write32(PCI_MISC_HCTRL_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_MISC_HCTRL_R,
	                                        ( int ) i );*/
	// step 15: set byte swapping (incl. step 27/28/29/30)
	// included prohibition of tx/rx interrupts
	bcm_write_reg32( MODE_CTRL_R, BIT32( 23 ) | BIT32( 20 ) |
	                              BIT32( 17 ) | BIT32( 16 ) |
	                              BIT32( 14 ) | BIT32( 13 ) |
			  	      BIT32(  5 ) | BIT32(  4 ) |
	                              BIT32(  2 ) | BIT32(  1 ) );
	// step 16: omitted
	i = 1000;
	while( ( --i ) &&
	       ( bcm_read_mem32( BCM_FW_MBX ) != ~BCM_MAGIC_NUMBER ) ) {
#ifdef BCM_DEBUG
		printf( "." );
#endif
		SLOF_msleep( 1 );
	}

	// return on error
	if( bcm_read_mem32( BCM_FW_MBX ) != ~BCM_MAGIC_NUMBER ) {
		printf( "bootcode not loaded: %x\n", bcm_read_mem32( BCM_FW_MBX ) );
#ifdef BCM_DEBUG
		printf( "failed\n" );
#endif
		return -1;
	}


	// if ASF Firmware enabled
	bcm_write_mem32( BCM_NICDRV_STATE_MBX, NIC_FWDRV_STATE_START );
	SLOF_msleep( 10 );

	// step 17: write ethernet mac mode register
	/*
	 * WY 07.02.07
	 * omitted for correct SOL function
	 */
	/*
	if( IS_SERDES ) {
		bcm_write_reg32( ETH_MAC_MODE_R, (uint32_t) 0xc );
	} else {
		bcm_write_reg32( ETH_MAC_MODE_R, (uint32_t) 0x0 );
	}
	*/

	// step 18/19: omitted
	// step 20: enable hw bugfix for 5704
	if( IS_5704 || IS_5703 ) {
		bcm_setb_reg32( MSG_DATA_R, BIT32( 26 ) |
		                            BIT32( 28 ) |
		                            BIT32( 29 ) );
	}

	// step 21: omitted
	// step 22: omitted
	// step 23: 5704 clear statistics block
	if( IS_5703 || IS_5704 ) {
		memset_ci( (void *) ( bcm_memaddr_u64 + BCM_STATISTIC_OFFS ),
		           0,
		           BCM_STATISTIC_SIZE );
	}

	// step 24/25: omitted
	// step 26: set DMA Read/Write Control register
	// NOTE: recommended values from the spec are used here
	if( IS_5714 ) {
		bcm_write_reg32( DMA_RW_CTRL_R, DMA_RW_CTRL_VAL_5714 );
	} else {
		uint32_t l_PCIState_u32 = bcm_read_reg32( PCI_STATE_R );
		uint32_t l_DMAVal_u32   = DMA_RW_CTRL_VAL;

		if( ( l_PCIState_u32 & BIT32( 2 ) ) != 0 ) {	// PCI
			l_DMAVal_u32 |= (uint32_t) 0x300000;
		} else {					// PCI-X
			l_DMAVal_u32 |= (uint32_t) 0x900000;

			if( ( bcm_read_reg32( PCI_CLK_CTRL_R ) & (uint32_t) 0x1f )
			    >= (uint32_t) 6 ) {
				l_DMAVal_u32 |= (uint32_t) 0x4000;
			}

		}

		bcm_write_reg32( DMA_RW_CTRL_R, l_DMAVal_u32 );
	}

	// step 27/28/29: s. step 14

	// step 30: Configure TCP/UDP pseudo header checksum offloading
	// already done in step 14: offloading disabled

	// step 31: setup timer prescaler
	i  = bcm_read_reg32( MISC_CFG_R );
	i &= (uint32_t) ~0xfe;   // clear bits 7-1 first
	i |= ( BCM_TMR_PRESCALE << 1 );
	bcm_write_reg32( MISC_CFG_R, i );

	// step 32: 5703/4 configure Mbuf pool address/length
	// step 33: 5703/4 configure MAC DMA resource pool
	// step 34: configure MAC memory pool watermarks
	// step 35: 5703/4 configure DMA resource watermarks
	//          using recommended settings (hard coded)
	if( IS_5703 || IS_5704 ) {

		if( IS_5703 ) {
			bcm_write_reg32( MBUF_POOL_ADDR_R, (uint32_t) 0x8000 );
			bcm_write_reg32( MBUF_POOL_LEN_R,  (uint32_t) 0x18000 );
		} else {
			bcm_write_reg32( MBUF_POOL_ADDR_R, (uint32_t) 0x10000 );
			bcm_write_reg32( MBUF_POOL_LEN_R,  (uint32_t) 0x10000 );
		}

		bcm_write_reg32( DMA_DESC_POOL_ADDR_R,   (uint32_t) 0x2000 );
		bcm_write_reg32( DMA_DESC_POOL_LEN_R,    (uint32_t) 0x2000 );

		bcm_write_reg32( DMA_RMBUF_LOW_WMARK_R,  (uint32_t) 0x50 );
		bcm_write_reg32( MAC_RXMBUF_LOW_WMARK_R, (uint32_t) 0x20 );
		bcm_write_reg32( MBUF_HIGH_WMARK_R,      (uint32_t) 0x60 );

		bcm_write_reg32( DMA_DESC_LOW_WM_R,      (uint32_t)  5 );
		bcm_write_reg32( DMA_DESC_HIGH_WM_R,     (uint32_t) 10 );
	} else {
		bcm_write_reg32( DMA_RMBUF_LOW_WMARK_R,  (uint32_t) 0x00 );
		bcm_write_reg32( MAC_RXMBUF_LOW_WMARK_R, (uint32_t) 0x10 );
		bcm_write_reg32( MBUF_HIGH_WMARK_R,      (uint32_t) 0x60 );
	}

	// step 35: omitted
	// step 36: Configure flow control behaviour
	//          using recommended settings (hard coded)
	bcm_write_reg32( LOW_WMARK_MAX_RXFRAM_R, (uint32_t) 0x02 );

	// step 37/38: enable buffer manager & wait for successful start
	bcm_setb_reg32( BUF_MAN_MODE_R, BIT32( 2 ) | BIT32( 1 ) );

	i = lc_Maxwait_u32;
	while( ( --i ) &&
	       ( ( bcm_read_reg32( BUF_MAN_MODE_R ) & BIT32( 1 ) ) == 0 ) ) {
		SLOF_usleep( 10 );
	}

	// return on error
	if( i == 0 ) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: init step 38: enable buffer manager failed\n" );
#endif
		return -1;
	}

	// step 39: enable internal hardware queues
	bcm_write_reg32( FTQ_RES_R, (uint32_t) ~0 );
	bcm_write_reg32( FTQ_RES_R, (uint32_t)  0 );

	// step 40/41/42: initialize rx producer ring
	bcm_init_rxprod_ring();

	// step 43: set rx producer ring replenish threshold
	// using recommended setting of maximum allocated BD's/8
	bcm_write_reg32( STD_RXPR_REP_THR_R, (uint32_t) BCM_MAX_RX_BUF / 8 );

	// step 44/45/46: initialize send rings
	bcm_init_tx_ring();
	bcm_init_rxret_ring();

	// steps 47-50 done in ring init functions
	// step 51: configure MAC unicast address
	bcm_nvram_init();
	if( bcm_mac_init( (uint8_t *) mac_addr ) < 0 ) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: init step 51: configure MAC unicast address failed\n" );
#endif
		return -1;
	}
	memcpy(driver->mac_addr, mac_addr, 6);

	// step 52: configure backoff random seed for transmit
	// using recommended algorithm
	i  = (uint32_t) mac_addr[0] + (uint32_t) mac_addr[1] +
	     (uint32_t) mac_addr[2] + (uint32_t) mac_addr[3] +
	     (uint32_t) mac_addr[4] + (uint32_t) mac_addr[5];
	i &= (uint32_t) 0x03ff; 
	bcm_write_reg32( ETH_TX_RND_BO_R, i );

	// step 53: configure message transfer unit MTU size
	bcm_write_reg32( RX_MTU_SIZE_R, (uint32_t) BCM_MTU_MAX_LEN );

	// step 54: configure IPG for transmit
	// using recommended value (through #define)
	bcm_write_reg32( TX_MAC_LEN_R, TX_MAC_LEN_VAL );

	// step 55: configure receive rules

	// set RX rule default class
	bcm_write_reg32( RX_RULE_CFG_R, RX_RULE_CFG_VAL );

	// step 56: configure the number of receive lists
	bcm_write_reg32( RX_LST_PLACE_CFG_R, RX_LST_PLC_CFG_VAL );
	bcm_write_reg32( RX_LST_PLACE_STAT_EN_R, RX_LST_PLC_STAT_EN_VAL );

/*
	// rule 1: accept frames for our MAC address
	bcm_write_reg32( RX_RULE_CTRL_R ( 0 ),
			 BIT32( 31 ) | 	// enable rule
			 BIT32( 30 ) | 	// and with next
			 BIT32( 26 ) | 	// split value register
			 BIT32(  8 ) );	// class 1
	bcm_write_reg32( RX_RULE_VAL_R  ( 0 ),
			 (uint32_t) 0xffff0000 |
			 ( bcm_read_reg32( MAC_ADDR_OFFS_HI(0) ) &
			   (uint32_t) 0xffff ) );

	bcm_write_reg32( RX_RULE_CTRL_R ( 1 ),
			 BIT32( 31 ) | 	// enable rule
			 BIT32(  8 ) | 	// class 1
			 BIT32(  1 ) );	// offset 2
	bcm_write_reg32( RX_RULE_VAL_R  ( 1 ),
			 bcm_read_reg32( MAC_ADDR_OFFS_LO(0) ) );

	// rule 2: accept broadcast frames
	bcm_write_reg32( RX_RULE_CTRL_R ( 2 ),
			 BIT32( 31 ) | 	// enable rule
			 BIT32( 30 ) | 	// and with next
			 BIT32( 26 ) | 	// split value register
			 BIT32(  8 ) );	// class 1
	bcm_write_reg32( RX_RULE_VAL_R  ( 2 ),
			 (uint32_t) ~0 );

	bcm_write_reg32( RX_RULE_CTRL_R ( 3 ),
			 BIT32( 31 ) | 	// enable rule
			 BIT32(  8 ) | 	// class 1
			 BIT32(  1 ) );	// offset 2
	bcm_write_reg32( RX_RULE_VAL_R  ( 3 ),
			 (uint32_t) ~0 );
*/
	for( i=0; i<NUM_RX_RULE_ASF; ++i) {
		bcm_write_reg32( RX_RULE_CTRL_R ( i ),  0 );
		bcm_write_reg32( RX_RULE_VAL_R  ( i ),  0 );
	}

	// step 57-60: enable rx/tx statistics
	// omitted, no need for statistics (so far)

	// step 61/62: disable host coalescing engine/wait 20ms
	bcm_write_reg32( HOST_COAL_MODE_R, (uint32_t) 0 );

	i = lc_Maxwait_u32 * 2;
	while( ( --i ) &&
	       ( bcm_read_reg32( HOST_COAL_MODE_R ) != 0 ) ) {
		SLOF_usleep( 10 );
	}

	// return on error
	if( i == 0 ) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: init step 62: disable host coal. engine failed\n" );
#endif
		return -1;
	}

	// step 63-66: initialize coalescing engine
	// NOTE: status block is unused in this driver,
	//       therefore the coal. engine status block
	//       automatic update is disabled (by writing
	//       0 to every counter
	bcm_write_reg32( RX_COAL_TICKS_R, 0 );
	bcm_write_reg32( TX_COAL_TICKS_R, 0 );
	bcm_write_reg32( RX_COAL_MAX_BD_R, 0 );
	bcm_write_reg32( TX_COAL_MAX_BD_R, 0 );
	bcm_write_reg32( RX_COAL_TICKS_INT_R, 0 );
	bcm_write_reg32( TX_COAL_TICKS_INT_R, 0 );
	bcm_write_reg32( RX_COAL_MAX_BD_INT_R, 0 );
	bcm_write_reg32( TX_COAL_MAX_BD_INT_R, 0 );

	// step 67: initialize host status block address
	// NOTE: status block is not needed in this driver,
	//       still it needs to be set up
	i = (uint32_t) ( (uint64_t) &bcm_status >> 32 );
	bcm_write_reg32( STB_HOST_ADDR_HI_R, i );
	i = (uint32_t) ( (uint64_t) &bcm_status & (uint64_t) 0xffffffff );
	bcm_write_reg32( STB_HOST_ADDR_LO_R, i );

	// 5704/3 adaption
	if( IS_5703 || IS_5704 ) {
		// step 68: 5704, for now omitted
		// step 69: 5704 set the statistics coalescing tick counter
		bcm_write_reg32( STAT_TICK_CNT_R, 0 );
		// step 70: 5704 configure statistics block address in NIC memory
		//          using recommended values (hard coded)
		bcm_write_reg32( STAT_NIC_ADDR_R, (uint32_t) 0x300 );
		// step 71: 5704 configure status block address in NIC memory
		//          using recommended values (hard coded)
		bcm_write_reg32( STB_NIC_ADDR_R, (uint32_t) 0xb00 );
	}

	// step 72: enable host coalescing engine
	bcm_setb_reg32( HOST_COAL_MODE_R, BIT32( 12 ) | BIT32( 11 ) | BIT32( 1 ) );

	// step 73: enable rx bd completion functional block
	bcm_write_reg32( RX_BD_COMPL_MODE_R, BIT32( 1 ) | BIT32( 2 ) );

	// step 74: enable rx list placement functional block
	bcm_write_reg32( RX_LST_PLACE_MODE_R, BIT32( 1 ) );
	// 5704/3 adaption
	if( IS_5703 || IS_5704 ) {
		// step 75: 5704/3 enable receive list selector func block
		bcm_write_reg32( RX_LST_SEL_MODE_R, BIT32( 1 ) | BIT32( 2 ) );
	}

	// step 76: enable DMA engines
	bcm_setb_reg32( ETH_MAC_MODE_R, BIT32( 23 ) | BIT32( 22 ) | BIT32( 21 ) );
	/*
	 * WY 26.10.07 This is wrong for 5714, better leave it alone
	if( IS_5714 ) {
		bcm_setb_reg32( ETH_MAC_MODE_R, BIT32( 20 ) );
	}
	*/

	// step 77: omitted, statistics are not used
	// step 78: Configure the General Misc Local Control register
	// NOTE:    as known so far nothing needs to be done here,
	//          default values should work fine
	//bcm_setb_reg32( MISC_LOCAL_CTRL_R, 0 );

	// step 79: clear interrupts in INT_MBX0_R low word
	bcm_write_reg32( INT_MBX0_R, 0 );
	// 5704/3 adaption
	// step 80: 5704/3 enable DMA completion functional block
	if( IS_5703 || IS_5704 ) {
		bcm_write_reg32( DMA_COMPL_MODE_R, BIT32( 1 ) );
	}

	// step 81/82: configure write/read DMA mode registers
	//             disable MSI
	bcm_write_reg32( RD_DMA_MODE_R, BIT32( 10 ) | BIT32( 9 ) | BIT32( 8 ) |
	                                BIT32(  7 ) | BIT32( 6 ) | BIT32( 5 ) |
	                                BIT32(  4 ) | BIT32( 3 ) | BIT32( 2 ) |
	                                BIT32(  1 ) );
	bcm_write_reg32( WR_DMA_MODE_R, BIT32( 9 ) | BIT32( 8 ) | BIT32( 7 ) |
	                                BIT32( 6 ) | BIT32( 5 ) | BIT32( 4 ) |
	                                BIT32( 3 ) | BIT32( 2 ) | BIT32( 1 ) );
	bcm_clrb_reg32( MSI_MODE_R,     BIT32( 1 ) );
	SLOF_usleep( 100 );

	// step 83-91: enable all these functional blocks...
	bcm_write_reg32( RX_DAT_COMPL_MODE_R,   BIT32( 1 ) | BIT32( 2 ) );

	if( IS_5703 || IS_5704 ) {
		bcm_write_reg32( MBUF_CLSTR_FREE_MODE_R, BIT32( 1 ) );
	}

	bcm_write_reg32( TX_DAT_COMPL_MODE_R,   BIT32( 1 ) );
	bcm_write_reg32( TX_BD_COMPL_MODE_R,    BIT32( 1 ) | BIT32( 2 ) );
	bcm_write_reg32( RX_BD_INIT_MODE_R,     BIT32( 1 ) | BIT32( 2 ) );
	bcm_write_reg32( RX_DAT_BD_INIT_MODE_R, BIT32( 1 ) );
	bcm_write_reg32( TX_DAT_INIT_MODE_R,    BIT32( 1 ) | BIT32( 3 ) );
	bcm_write_reg32( TX_BD_INIT_MODE_R,     BIT32( 1 ) | BIT32( 2 ) );
	bcm_write_reg32( TX_BD_RING_SEL_MODE_R, BIT32( 1 ) | BIT32( 2 ) );

	// step 92: omitted
	// step 93/94: Enable Tx/Rx MAC
	bcm_setb_reg32( TX_MAC_MODE_R, BIT32( 1 ) );
//	bcm_setb_reg32( RX_MAC_MODE_R, BIT32( 1 ) | BIT32( 2 ) );	// set BIT32( 8 ) for promiscious mode!
	bcm_setb_reg32( RX_MAC_MODE_R, BIT32( 1 ) );	// set BIT32( 8 ) for promiscious mode!
	                                            	// set BIT32( 10) for VLAN

	// step 95: disable auto polling:
	//          bcm_phy_init takes care of this
	// step 96: omitted
	// step 97: omitted, may change though, but is not important
	// step 98: activate link & enable MAC functional block
	// NOTE     autopolling is enabled so bit 0 needs not to be set
	//bcm_setb_reg32( MI_STATUS_R, BIT32( 0 ) );

	// step 99: setup PHY
	// return if link is down
	if( bcm_phy_init() < 0 ) {
#ifdef BCM_DEBUG
		printf( "bcm57xx: init step 99: PHY initialization failed\n" );
#endif
		return -1;
	}

	// step 100: setup multicast filters
	bcm_write_reg32( MAC_HASH0_R, (uint32_t) 0 );
	bcm_write_reg32( MAC_HASH1_R, (uint32_t) 0 );
	bcm_write_reg32( MAC_HASH2_R, (uint32_t) 0 );
	bcm_write_reg32( MAC_HASH3_R, (uint32_t) 0 );
/*
	// accept all multicast frames
	bcm_write_reg32( MAC_HASH0_R, (uint32_t) 0xffffffff );
	bcm_write_reg32( MAC_HASH1_R, (uint32_t) 0xffffffff );
	bcm_write_reg32( MAC_HASH2_R, (uint32_t) 0xffffffff );
	bcm_write_reg32( MAC_HASH3_R, (uint32_t) 0xffffffff );
*/
	// step 101: omitted, no interrupts used

	// make initial receive buffers available for NIC
	// this step has to be done here after RX DMA engine has started (step 94)
	bcm_write_reg32( RXPROD_PROD_IND, BCM_MAX_RX_BUF );

	// if ASF Firmware enabled
	bcm_write_mem32( BCM_NICDRV_STATE_MBX, NIC_FWDRV_STATE_START_DONE );
	SLOF_msleep( 10 );

	// enable heartbeat timer

	bcm_write_reg32( ASF_HEARTBEAT_TIMER_R, 0x5 );

	driver->running = 1;
	// off we go..
	return 0;
}

static int
bcm_reset( void )
{
	uint32_t i;

#ifdef BCM_DEBUG
	printf( "bcm57xx: resetting controller.." );
#endif

	bcm_write_mem32( BCM_FW_MBX, BCM_MAGIC_NUMBER );

	if( IS_5714 ) {
		bcm_setb_reg32( MISC_CFG_R, BIT32( 26 ) | BIT32( 0 ) );
	} else {
		bcm_setb_reg32( MISC_CFG_R, BIT32( 0 ) );
	}

	SLOF_msleep( 20 );

	/*
	 * after reset local read/write functions cannot be used annymore
	 * until bus master & stuff is set up again
	 */

	i = ( BIT32( 10 ) | BIT32( 2 ) | BIT32( 1 ) );
	SLOF_pci_config_write16(PCI_COM_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        2,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_COM_R,
	                                        ( int ) i );*/

	// step 9 & 13: disable & mask interrupts & enable indirect addressing mode &
	//              enable pci byte/word swapping initialize the misc host control register
	i = ( BIT32( 7 ) | BIT32( 5 ) | BIT32( 4 ) |
	      BIT32( 3 ) | BIT32( 2 ) | BIT32( 1 ) | BIT32( 0 ) );
	SLOF_pci_config_write32(PCI_MISC_HCTRL_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_MISC_HCTRL_R,
	                                        ( int ) i );*/

	// step 16: poll for bootcode completion by waiting for the one's
	//          complement of the magic number previously written
	i = 1000;
	while( ( --i ) &&
	       ( bcm_read_mem32( BCM_FW_MBX ) != ~BCM_MAGIC_NUMBER ) ) {
#ifdef BCM_DEBUG
		printf( "." );
#else
		SLOF_msleep( 1 );
#endif
	}

	// return on error
	if( bcm_read_mem32( BCM_FW_MBX ) != ~BCM_MAGIC_NUMBER ) {
#ifdef BCM_DEBUG
		printf( "failed\n" );
#endif
		return -1;
	}

#ifdef BCM_DEBUG
	printf( "done\n" );
#endif
	return 0;
}

static int
bcm_term( void )
{
	uint32_t i;
	uint16_t v;

#ifdef BCM_DEBUG
	printf( "bcm57xx: driver shutdown.." );
#endif

	/*
	 * halt ASF firmware
	 */
	bcm_fw_halt();

	/*
	 * unload ASF firmware
	 */
	bcm_write_mem32( BCM_NICDRV_STATE_MBX, NIC_FWDRV_STATE_UNLOAD );

	/*
	 * disable RX producer rings
	 */
	bcm_write_reg32( BCM_RCB_LENFLAG_u16(      BCM_RXPROD_RCB_JUM ), RCB_FLAG_RING_DISABLED );
	bcm_write_reg32( BCM_RCB_HOSTADDR_HI_u16(  BCM_RXPROD_RCB_JUM ), 0 );
	bcm_write_reg32( BCM_RCB_HOSTADDR_LOW_u16( BCM_RXPROD_RCB_JUM ), 0 );
	bcm_write_reg32( BCM_RCB_NICADDR_u16(      BCM_RXPROD_RCB_JUM ), 0 );

	bcm_write_reg32( BCM_RCB_LENFLAG_u16(      BCM_RXPROD_RCB_STD ), RCB_FLAG_RING_DISABLED );
	bcm_write_reg32( BCM_RCB_HOSTADDR_HI_u16(  BCM_RXPROD_RCB_STD ), 0 );
	bcm_write_reg32( BCM_RCB_HOSTADDR_LOW_u16( BCM_RXPROD_RCB_STD ), 0 );
	bcm_write_reg32( BCM_RCB_NICADDR_u16(      BCM_RXPROD_RCB_STD ), 0 );

	bcm_write_reg32( BCM_RCB_LENFLAG_u16(      BCM_RXPROD_RCB_MIN ), RCB_FLAG_RING_DISABLED );
	bcm_write_reg32( BCM_RCB_HOSTADDR_HI_u16(  BCM_RXPROD_RCB_MIN ), 0 );
	bcm_write_reg32( BCM_RCB_HOSTADDR_LOW_u16( BCM_RXPROD_RCB_MIN ), 0 );
	bcm_write_reg32( BCM_RCB_NICADDR_u16(      BCM_RXPROD_RCB_MIN ), 0 );

	/*
	 * disable RX return rings
	 */
	v = BCM_RXRET_RCB_OFFS;
	for( i = 0; i < BCM_MAX_RXRET_RING; i++ ) {
		bcm_write_mem32( BCM_RCB_LENFLAG_u16( v ),      RCB_FLAG_RING_DISABLED );
		bcm_write_mem32( BCM_RCB_HOSTADDR_HI_u16( v ),  0 );
		bcm_write_mem32( BCM_RCB_HOSTADDR_LOW_u16( v ), 0 );
		bcm_write_mem32( BCM_RCB_NICADDR_u16( v ),      0 );

		v += BCM_RCB_SIZE_u16;
        }

	/*
	 * disable TX rings
	 */
        v = BCM_TX_RCB_OFFS;
	for( i = 0; i < BCM_MAX_TX_RING; i++ ) {
		bcm_write_mem32( BCM_RCB_LENFLAG_u16( v ),      RCB_FLAG_RING_DISABLED );
		bcm_write_mem32( BCM_RCB_HOSTADDR_HI_u16( v ),  0 );
		bcm_write_mem32( BCM_RCB_HOSTADDR_LOW_u16( v ), 0 );
		bcm_write_mem32( BCM_RCB_NICADDR_u16( v ),      0 );

		v += BCM_RCB_SIZE_u16;
	}

	/*
	 * remove receive rules
	 */
	bcm_write_reg32( RX_RULE_CTRL_R (  0 ), 0 );
	bcm_write_reg32( RX_RULE_VAL_R  (  0 ), 0 );
	bcm_write_reg32( RX_RULE_CTRL_R (  1 ), 0 );
	bcm_write_reg32( RX_RULE_VAL_R  (  1 ), 0 );

	/*
	 * shutdown sequence
	 * BCM57xx Programmer's Guide: Section 8, "Shutdown"
	 * the enable bit of every state machine of the 57xx
	 * has to be reset.
	 */

	/*
	 * receive path shutdown sequence
	 */
	bcm_clr_wait_bit32( RX_MAC_MODE_R,         BIT32( 1 ) );
	bcm_clr_wait_bit32( RX_LST_PLACE_MODE_R,   BIT32( 1 ) );
	bcm_clr_wait_bit32( RX_BD_INIT_MODE_R,     BIT32( 1 ) );
	bcm_clr_wait_bit32( RX_DAT_BD_INIT_MODE_R, BIT32( 1 ) );
	bcm_clr_wait_bit32( RX_DAT_COMPL_MODE_R,   BIT32( 1 ) );
	bcm_clr_wait_bit32( RX_BD_COMPL_MODE_R,    BIT32( 1 ) );

	if( IS_5704 || IS_5703 ) {
		bcm_clr_wait_bit32( RX_LST_SEL_MODE_R, BIT32( 1 ) );
	}

	/*
	 * transmit path & memory shutdown sequence
	 */
	bcm_clr_wait_bit32( TX_BD_RING_SEL_MODE_R, BIT32( 1 ) );
	bcm_clr_wait_bit32( TX_BD_INIT_MODE_R,     BIT32( 1 ) );
	bcm_clr_wait_bit32( TX_DAT_INIT_MODE_R,    BIT32( 1 ) );
	bcm_clr_wait_bit32( RD_DMA_MODE_R,         BIT32( 1 ) );
	bcm_clr_wait_bit32( TX_DAT_COMPL_MODE_R,   BIT32( 1 ) );

	if( IS_5704 ) {
		bcm_clr_wait_bit32( DMA_COMPL_MODE_R, BIT32( 1 ) );
	}

	bcm_clr_wait_bit32( TX_BD_COMPL_MODE_R,    BIT32( 1 ) );
	bcm_clr_wait_bit32( ETH_MAC_MODE_R,        BIT32( 21 ) );
	bcm_clr_wait_bit32( TX_MAC_MODE_R,         BIT32( 1 ) );

	bcm_clr_wait_bit32( HOST_COAL_MODE_R,      BIT32( 1 ) );
	bcm_clr_wait_bit32( WR_DMA_MODE_R,         BIT32( 1 ) );

	if( IS_5704 || IS_5703 ) {
		bcm_clr_wait_bit32( MBUF_CLSTR_FREE_MODE_R, BIT32( 1 ) );
	}

	bcm_write_reg32( FTQ_RES_R, (uint32_t) ~0 );
	bcm_write_reg32( FTQ_RES_R, (uint32_t)  0 );

	if( IS_5704 || IS_5703 ) {
		bcm_clr_wait_bit32( BUF_MAN_MODE_R, BIT32( 1 ) );
		bcm_clr_wait_bit32( MEMARB_MODE_R,  BIT32( 1 ) );
	}

#ifdef BCM_DEBUG
	printf( "done.\n" );
#endif
	/*
	 * controller reset
	 */
	if( bcm_reset() != 0 ) {
		return -1;
	}

	/*
	 * restart ASF firmware
	 */
	bcm_write_mem32( BCM_NICDRV_STATE_MBX, NIC_FWDRV_STATE_UNLOAD );
	SLOF_msleep( 10 );
	bcm_write_mem32( BCM_NICDRV_STATE_MBX, NIC_FWDRV_STATE_UNLOAD_DONE );
	SLOF_msleep( 100 );
	bcm_write_mem32( BCM_NICDRV_STATE_MBX, NIC_FWDRV_STATE_START );
	SLOF_msleep( 10 );
	bcm_write_mem32( BCM_NICDRV_STATE_MBX, NIC_FWDRV_STATE_START_DONE );

	/*
	 * activate Wake-on-LAN
	 */
	bcm_wol_activate();

	/*
	 * PCI shutdown
	 */
	bcm_clrb_reg32( PCI_MISC_HCTRL_R, BIT32( 3 ) | BIT32( 2 ) );

	/*
	 * from now on local rw functions cannot be used anymore
	 */

//	bcm_clrb_reg32( PCI_COM_R, BIT32( 10 ) | BIT32( 2 ) | BIT32( 1 ) );

	SLOF_pci_config_write32(PCI_COM_R, BIT32(8) | BIT32(6));
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        2,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_COM_R,
	                                        BIT32(8) | BIT32(6) );*/

	// no more networking...
	return 0;
}

static int
bcm_getmac(uint32_t addr, char mac[6])
{
	uint32_t t1, t2;
	uint64_t t3;

	if (bcm_nvram_read(addr, &t1, 1) != 0)
		return -1;
	if (bcm_nvram_read(addr+4, &t2, 1) != 0)
		return -1;
	t3 = ((uint64_t)t1 << 32) + t2;

	mac[0] = (t3 >> 40) & 0xFF;
	mac[1] = (t3 >> 32) & 0xFF;
	mac[2] = (t3 >> 24) & 0xFF;
	mac[3] = (t3 >> 16) & 0xFF;
	mac[4] = (t3 >>  8) & 0xFF;
	mac[5] = (t3 >>  0) & 0xFF;

	return 0;
}

static char*
print_itoa(char *text, uint32_t value)
{
	if(value >= 10)
		text = print_itoa(text, value / 10);
	*text = '0' + (value % 10);
	++text;
	return text;
}

static int
bcm_get_version(char *text)
{
	uint32_t t1;

	if (bcm_nvram_read(0x94, &t1, 1) != 0)
		return -1;

	text = print_itoa(text, (t1 >> 8) & 0xFF);
	text[0] = '.';
	text = print_itoa(&text[1], t1 & 0xFF);
	text[0] = '\n';
	return 0;
}

static uint32_t
util_gen_crc( char *pcDatabuf, uint32_t ulDatalen, uint32_t ulCrc_in)
{
	unsigned char data;
	uint32_t idx, bit, crc = ulCrc_in;

	for(idx = 0; idx < ulDatalen; idx++) {
		data = *pcDatabuf++;
		for(bit = 0; bit < 8; bit++, data >>= 1) {
			crc = (crc >> 1) ^ (((crc ^ data) & 1) ?
				CRC32_POLYNOMIAL : 0);
		}
	}
	return bswap_32(~crc);
}

static int
bcm_setmac(char mac_addr1[6], char mac_addr2[6])
{
	uint64_t mac1 = 0, mac2 = 0;
	uint32_t manu[MANUFACTURING_INFO_SIZE/4];
	int addr, i;
	uint32_t crc, val1, val2, val3, val4;

#ifdef BCM_DEBUG
	printf("Flashing MAC 1: %02X:%02X:%02X:%02X:%02X:%02X\n",
		((unsigned int) mac_addr1[0]) & 0xFF,
		((unsigned int) mac_addr1[1]) & 0xFF,
		((unsigned int) mac_addr1[2]) & 0xFF,
		((unsigned int) mac_addr1[3]) & 0xFF,
		((unsigned int) mac_addr1[4]) & 0xFF,
		((unsigned int) mac_addr1[5]) & 0xFF);

	printf("Flashing MAC 2: %02X:%02X:%02X:%02X:%02X:%02X\n",
		((unsigned int) mac_addr2[0]) & 0xFF,
		((unsigned int) mac_addr2[1]) & 0xFF,
		((unsigned int) mac_addr2[2]) & 0xFF,
		((unsigned int) mac_addr2[3]) & 0xFF,
		((unsigned int) mac_addr2[4]) & 0xFF,
		((unsigned int) mac_addr2[5]) & 0xFF);
#endif

	mac1 |= ((uint64_t) mac_addr1[0]) & 0xFF; mac1 = mac1 << 8;
	mac1 |= ((uint64_t) mac_addr1[1]) & 0xFF; mac1 = mac1 << 8;
	mac1 |= ((uint64_t) mac_addr1[2]) & 0xFF; mac1 = mac1 << 8;
	mac1 |= ((uint64_t) mac_addr1[3]) & 0xFF; mac1 = mac1 << 8;
	mac1 |= ((uint64_t) mac_addr1[4]) & 0xFF; mac1 = mac1 << 8;
	mac1 |= ((uint64_t) mac_addr1[5]) & 0xFF;

	mac2 |= ((uint64_t) mac_addr2[0]) & 0xFF; mac2 = mac2 << 8;
	mac2 |= ((uint64_t) mac_addr2[1]) & 0xFF; mac2 = mac2 << 8;
	mac2 |= ((uint64_t) mac_addr2[2]) & 0xFF; mac2 = mac2 << 8;
	mac2 |= ((uint64_t) mac_addr2[3]) & 0xFF; mac2 = mac2 << 8;
	mac2 |= ((uint64_t) mac_addr2[4]) & 0xFF; mac2 = mac2 << 8;
	mac2 |= ((uint64_t) mac_addr2[5]) & 0xFF;

	/* Extract the manufacturing data, starts at 0x74 */
	if(bcm_nvram_lock() == -1) {
		return -1;
	}

	addr = 0x74;
	for (i = 0; i < (MANUFACTURING_INFO_SIZE/4); i++) {
		if (bcm_nvram_read(addr, &manu[i], 0) != 0) {
			printf("\nREAD FAILED\n");
			bcm_nvram_unlock();
			return -1;
		}
		addr+=4;
	}
	bcm_nvram_unlock();

	/* Store the new MAC address in the manufacturing data */
	val1 = mac1 >> 32;
	val2 = mac1 & 0xFFFFFFFF;
	val3 = mac2 >> 32;
	val4 = mac2 & 0xFFFFFFFF;
	manu[(0x7C-0x74)/4] = val1;
	manu[(0x80-0x74)/4] = val2;
	manu[(0xCC-0x74)/4] = val3;
	manu[(0xD0-0x74)/4] = val4;

	/* Calculate the new manufacturing datas CRC */
	crc = util_gen_crc(((char *)manu),
		MANUFACTURING_INFO_SIZE - 4, 0xFFFFFFFF);

	/* Now write the new MAC addresses and CRC */
	if ((bcm_nvram_write(0x7C, val1, 1) != 0) ||
	    (bcm_nvram_write(0x80, val2, 1) != 0) ||
	    (bcm_nvram_write(0xCC, val3, 1) != 0) ||
	    (bcm_nvram_write(0xD0, val4, 1) != 0) ||
	    (bcm_nvram_write(0xFC, crc,  1) != 0) )
	{
		/* Disastor ! */
#ifdef BCM_DEBUG
		printf("failed to write MAC address\n");
#endif
		return -1;
	}

	/* Success !!!! */
	return 0;
}

static int
bcm_ioctl( int request, void* data )
{
	uint32_t                l_baseaddrL_u32;
	uint32_t                l_baseaddrH_u32;
	uint32_t                i;
	int                  ret_val = 0;
	char                 mac_addr[6];
	ioctl_net_data_t     *ioctl_data = (ioctl_net_data_t*) data;

	if(request != SIOCETHTOOL) {
		return -1;
	}

#ifdef BCM_DEBUG
	printf( "bcm57xx: detected device " );
	if( IS_5703 ) {
		printf( "5703S" );
	} else if( IS_5704 ) {
		printf( "5704" );
		if( IS_SERDES ) {
			printf( "S\n" );
		} else {
			printf( "C\n" );
		}
	} else if( IS_5714 ) {
		printf( "5714\n" );
	}
#endif
	/*
	 * setup register & memory base addresses of NIC
	 */
	l_baseaddrL_u32 = (uint32_t) ~0xf &
			  SLOF_pci_config_read32(PCI_BAR1_R);
	/*l_baseaddrL_u32 = ( (uint32_t) ~0xf &
	(uint32_t) snk_kernel_interface->pci_config_read( bcm_pcicfg_puid,
	                                               4,
	                                               bcm_pcicfg_bus,
	                                               bcm_pcicfg_devfn,
	                                               PCI_BAR1_R ) );*/

	l_baseaddrH_u32 = SLOF_pci_config_read32(PCI_BAR2_R);
	/*l_baseaddrH_u32 = 
	(uint32_t) snk_kernel_interface->pci_config_read( bcm_pcicfg_puid,
	                                               4,
	                                               bcm_pcicfg_bus,
	                                               bcm_pcicfg_devfn,
	                                               PCI_BAR2_R );*/

	bcm_baseaddr_u64   = (uint64_t) l_baseaddrH_u32;
	bcm_baseaddr_u64 <<= 32;
	bcm_baseaddr_u64  += (uint64_t) l_baseaddrL_u32;
	bcm_baseaddr_u64 =
		(uint64_t)SLOF_translate_my_address((void *)bcm_baseaddr_u64);
	/*snk_kernel_interface->translate_addr(((void *)&(bcm_baseaddr_u64)));*/
	bcm_memaddr_u64    = bcm_baseaddr_u64 + BCM_MEMORY_OFFS;

	/*
	 * 57xx hardware initialization
	 * BCM57xx Programmer's Guide: Section 8, "Initialization"
	 * steps 1 through 101
	 */

	// step 1: enable bus master & memory space in command reg
	i = ( BIT32( 10 ) | BIT32( 2 ) | BIT32( 1 ) );
	SLOF_pci_config_write16(PCI_COM_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        2,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_COM_R,
	                                        ( int ) i );*/

	// step 2: disable & mask interrupts & enable pci byte/word swapping & enable indirect addressing mode
	i = ( BIT32( 7 ) | BIT32( 3 ) | BIT32( 2 ) | BIT32( 1 ) | BIT32( 0 ) );
	SLOF_pci_config_write32(PCI_MISC_HCTRL_R, i);
	/*snk_kernel_interface->pci_config_write( bcm_pcicfg_puid,
	                                        4,
	                                        bcm_pcicfg_bus,
	                                        bcm_pcicfg_devfn,
	                                        PCI_MISC_HCTRL_R,
	                                        ( int ) i );*/

	bcm_nvram_init();

	switch(ioctl_data->subcmd) {
	case ETHTOOL_GMAC:
		switch(ioctl_data->data.mac.idx) {
		case 0:
			ret_val = bcm_getmac(0x7C, ioctl_data->data.mac.address);
			break;
		case 1:
			ret_val = bcm_getmac(0xCC, ioctl_data->data.mac.address);
			break;
		default:
			ret_val = -1;
			break;
		}
		break;
	case ETHTOOL_SMAC:
		switch(ioctl_data->data.mac.idx) {
		case 0:
			ret_val = bcm_getmac(0xCC, mac_addr);
			if(ret_val == 0)
				ret_val = bcm_setmac(ioctl_data->data.mac.address, mac_addr);
			break;
		case 1:
			ret_val = bcm_getmac(0x7C, mac_addr);
			if(ret_val == 0)
				ret_val = bcm_setmac(mac_addr, ioctl_data->data.mac.address);
			break;
		default:
			ret_val = -1;
			break;
		}
		break;
	case ETHTOOL_VERSION: {
		char *text = ioctl_data->data.version.text;
		memcpy(text, "  BCM57xx Boot code level: ", 27);
		ret_val = bcm_get_version(&text[27]);
		break;
	}
	default:
		ret_val = -1;
		break;
	}
	
	bcm_term();
	return ret_val;
}

net_driver_t *bcm57xx_open(void)
{
	net_driver_t *driver;
	uint16_t vendor_id, device_id;

	vendor_id = SLOF_pci_config_read16(0);
	device_id = SLOF_pci_config_read16(2);
	if (check_driver(vendor_id, device_id))
		return NULL;

	driver = SLOF_alloc_mem(sizeof(*driver));
	if (!driver) {
		printf("Unable to allocate virtio-net driver\n");
		return NULL;
	}
	memset(driver, 0, sizeof(*driver));

	if (bcm_init(driver))
		goto FAIL;

	return driver;

FAIL:	SLOF_free_mem(driver, sizeof(*driver));
	return NULL;

	return 0;
}

void bcm57xx_close(net_driver_t *driver)
{
	if (driver->running == 0)
		return;

	bcm_term();
	driver->running = 0;
	SLOF_free_mem(driver, sizeof(*driver));
}

int bcm57xx_read(char *buf, int len)
{
	if (buf)
		return bcm_receive(buf, len);
	return -1;
}

int bcm57xx_write(char *buf, int len)
{
	if (buf)
		return bcm_xmit(buf, len);
	return -1;
}
