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

#include <cache.h>
#include <netdriver.h>

// Debug switches
//#define BCM_DEBUG	// main debug switch, w/o it the other ones don't work
//#define BCM_SHOW_RCV
//#define BCM_SHOW_RCV_DATA
//#define BCM_SHOW_XMIT
//#define BCM_SHOW_XMIT_DATA
//#define BCM_SHOW_XMIT_STATS
//#define BCM_SHOW_IDX
//#define BCM_SHOW_STATS
//#define BCM_SHOW_ASF_REGS

// Switch to enable SW AUTO-NEG
// don't try, it's still incomplete
//#define BCM_SW_AUTONEG

/*
 * used register offsets
 */
// PCI command register
#define PCI_COM_R               ( (uint16_t) 0x0004 )
// PCI Cache Line Size register
#define PCI_CACHELS_R           ( (uint16_t) 0x000c )
// PCI bar1 register
#define PCI_BAR1_R              ( (uint16_t) 0x0010 )
// PCI bar2 register
#define PCI_BAR2_R              ( (uint16_t) 0x0014 )
// PCI bar1 register
#define PCI_SUBID_R             ( (uint16_t) 0x002e )
// PCI-X Comand register
#define PCI_X_COM_R             ( (uint16_t) 0x0042 )
// Message Data Register
#define MSG_DATA_R		( (uint16_t) 0x0064 )
// PCI misc host contrl register
#define PCI_MISC_HCTRL_R        ( (uint16_t) 0x0068 )
// DMA Read/Write Control register
#define DMA_RW_CTRL_R           ( (uint16_t) 0x006c )
// PCI State register
#define PCI_STATE_R		( (uint16_t) 0x0070 )
// PCI_Clock Control register
#define PCI_CLK_CTRL_R		( (uint16_t) 0x0074 )
// Register Base Address Register
#define REG_BASE_ADDR_REG	( (uint16_t) 0x0078 )
// Memory Window Base Address Register
#define MEM_BASE_ADDR_REG	( (uint16_t) 0x007c )
// Register Data Register
#define REG_DATA_REG		( (uint16_t) 0x0080 )
// Memory Window Data Register
#define MEM_DATA_REG		( (uint16_t) 0x0084 )
// MAC Function register
#define MAC_FUNC_R		( (uint16_t) 0x00b8 )
// Interrupt Mailbox 0 register
#define INT_MBX0_R              ( (uint16_t) 0x0204 )
// Ethernet MAC Mode register
#define ETH_MAC_MODE_R          ( (uint16_t) 0x0400 )
// Ethernet MAC Addresses registers
#define MAC_ADDR_OFFS_HI( idx )	( (uint16_t) ( (idx*2 + 0)*sizeof( uint32_t ) + 0x0410 ) )
#define MAC_ADDR_OFFS_LO( idx )	( (uint16_t) ( (idx*2 + 1)*sizeof( uint32_t ) + 0x0410 ) )
// Ethernet MAC Status register
#define ETH_MAC_STAT_R		( (uint16_t) 0x0404 )
// Ethernet MAC Event Enable register
#define ETH_MAC_EVT_EN_R	( (uint16_t) 0x0408 )
// Ethernet Transmit Random Backoff register
#define ETH_TX_RND_BO_R         ( (uint16_t) 0x0438 )
// Receive MTU Size register
#define RX_MTU_SIZE_R           ( (uint16_t) 0x043c )
// Transmit 1000BASE-X Auto Negotiation register
#define TX_1000BX_AUTONEG_R	( (uint16_t) 0x0444 )
// Receive 1000BASE-X Auto Negotiation register
#define RX_1000BX_AUTONEG_R	( (uint16_t) 0x0448 )
// MI Communication register
#define MI_COM_R                ( (uint16_t) 0x044c )
// MI Status Register
#define MI_STATUS_R             ( (uint16_t) 0x0450 )
// MI Mode register
#define MI_MODE_R		( (uint16_t) 0x0454 )
// Transmit MAC Mode register
#define TX_MAC_MODE_R           ( (uint16_t) 0x045c )
// Transmit MAC Length register
#define TX_MAC_LEN_R            ( (uint16_t) 0x0464 )
// Receive MAC Mode register
#define RX_MAC_MODE_R           ( (uint16_t) 0x0468 )
// MAC Hash 0 register* VPD Config:
#define MAC_HASH0_R		( (uint16_t) 0x0470 )
// MAC Hash 1 register
#define MAC_HASH1_R		( (uint16_t) 0x0474 )
// MAC Hash 2 register
#define MAC_HASH2_R		( (uint16_t) 0x0478 )
// MAC Hash 3 register
#define MAC_HASH3_R		( (uint16_t) 0x047c )
// Receive Rules Control register
#define RX_RULE_CTRL_R( idx )	( (uint16_t) ( idx*8 + 0x0480 ) )
// Receive Rules Value register
#define RX_RULE_VAL_R( idx )	( (uint16_t) ( idx*8 + 0x0484 ) )
// Receive Rules Configuration register
#define RX_RULE_CFG_R           ( (uint16_t) 0x0500 )
// Low Watermark Max Receive Frames register
#define LOW_WMARK_MAX_RXFRAM_R  ( (uint16_t) 0x0504 )
// SerDes Control Register
#define SERDES_CTRL_R           ( (uint16_t) 0x0590 )
// Hardware Auto Negotiation Control Register
#define HW_AUTONEG_CTRL_R       ( (uint16_t) 0x05B0 )
// Hardware Auto Negotiation Status Register
#define HW_AUTONEG_STAT_R       ( (uint16_t) 0x05B4 )
// Send Data Initiator Mode register
#define TX_DAT_INIT_MODE_R      ( (uint16_t) 0x0c00 )
// Send Data Completion Mode register
#define TX_DAT_COMPL_MODE_R     ( (uint16_t) 0x1000 )
// Send BD Ring Selector Mode register
#define TX_BD_RING_SEL_MODE_R   ( (uint16_t) 0x1400 )
// Send BD Initiator Mode register
#define TX_BD_INIT_MODE_R       ( (uint16_t) 0x1800 )
// Send BD Completion Mode register
#define TX_BD_COMPL_MODE_R      ( (uint16_t) 0x1c00 )
// Receive List Placement Mode register
#define RX_LST_PLACE_MODE_R     ( (uint16_t) 0x2000 )
// Receive List Placement Configuration register
#define RX_LST_PLACE_CFG_R      ( (uint16_t) 0x2010 )
// Receive List Placement Statistics Enable Mask register
#define RX_LST_PLACE_STAT_EN_R	( (uint16_t) 0x2018 )
// Receive Data & Receive BD Initiator Mode register
#define RX_DAT_BD_INIT_MODE_R   ( (uint16_t) 0x2400 )
// Receive Data Completion Mode register
#define RX_DAT_COMPL_MODE_R     ( (uint16_t) 0x2800 )
// Receive BD Initiator Mode register
#define RX_BD_INIT_MODE_R       ( (uint16_t) 0x2c00 )
// Standard Receive Producer Ring Replenish Threshold register
#define STD_RXPR_REP_THR_R      ( (uint16_t) 0x2c18 )
// Receive BD Completion Mode register
#define RX_BD_COMPL_MODE_R      ( (uint16_t) 0x3000 )
// Receive List Selector Mode register
#define RX_LST_SEL_MODE_R	( (uint16_t) 0x3400 )
// MBUF Cluster Free Mode register
#define MBUF_CLSTR_FREE_MODE_R	( (uint16_t) 0x3800 )
// Host Coalescing Mode register
#define HOST_COAL_MODE_R        ( (uint16_t) 0x3c00 )
// Receive Coalescing Ticks register
#define RX_COAL_TICKS_R         ( (uint16_t) 0x3c08 )
// Send Coalescing Ticks register
#define TX_COAL_TICKS_R         ( (uint16_t) 0x3c0c )
// Receive Max Coalesced BD Count register
#define RX_COAL_MAX_BD_R        ( (uint16_t) 0x3c10 )
// Send Max Coalesced BD Count register
#define TX_COAL_MAX_BD_R        ( (uint16_t) 0x3c14 )
// Receive Coalescing Ticks During Int register
#define RX_COAL_TICKS_INT_R     ( (uint16_t) 0x3c18 )
// Send Coalescing Ticks During Int register
#define TX_COAL_TICKS_INT_R     ( (uint16_t) 0x3c1c )
// Receive Max Coalesced BD Count During Int register
#define RX_COAL_MAX_BD_INT_R    ( (uint16_t) 0x3c18 )
// Send Max Coalesced BD Count During Int register
#define TX_COAL_MAX_BD_INT_R    ( (uint16_t) 0x3c1c )
// Statistics Ticks Counter register
#define STAT_TICK_CNT_R		( (uint16_t) 0x3c28 )
// Status Block Host Address Low register
#define STB_HOST_ADDR_HI_R      ( (uint16_t) 0x3c38 )
// Status Block Host Address High register
#define STB_HOST_ADDR_LO_R	( (uint16_t) 0x3c3c )
// Statistics Base Address register
#define STAT_NIC_ADDR_R		( (uint16_t) 0x3c40 )
// Status Block Base Address register
#define STB_NIC_ADDR_R		( (uint16_t) 0x3c44 )
// Memory Arbiter Mode register
#define MEMARB_MODE_R           ( (uint16_t) 0x4000 )
// Buffer Manager Mode register
#define BUF_MAN_MODE_R          ( (uint16_t) 0x4400 )
// MBuf Pool Address register
#define MBUF_POOL_ADDR_R	( (uint16_t) 0x4408 )
// MBuf Pool Length register
#define MBUF_POOL_LEN_R		( (uint16_t) 0x440c )
// Read DMA Mbuf Low Watermark register
#define DMA_RMBUF_LOW_WMARK_R   ( (uint16_t) 0x4410 )
// MAC Rx Mbuf Low Watermark register
#define MAC_RXMBUF_LOW_WMARK_R  ( (uint16_t) 0x4414 )
// Mbuf High Watermark register
#define MBUF_HIGH_WMARK_R       ( (uint16_t) 0x4418 )
// DMA Descriptor Pool Address register
#define DMA_DESC_POOL_ADDR_R	( (uint16_t) 0x442c )
// DMA Descriptor Pool Length register
#define DMA_DESC_POOL_LEN_R	( (uint16_t) 0x4430 )
// DMA Descriptor Low Watermark register
#define DMA_DESC_LOW_WM_R	( (uint16_t) 0x4434 )
// DMA Descriptor HIGH Watermark register
#define DMA_DESC_HIGH_WM_R	( (uint16_t) 0x4438 )
// Read DMA Mode register
#define RD_DMA_MODE_R           ( (uint16_t) 0x4800 )
// Write DMA Mode register
#define WR_DMA_MODE_R           ( (uint16_t) 0x4c00 )
// FTQ Reset register
#define FTQ_RES_R               ( (uint16_t) 0x5c00 )
// MSI Mode register
#define MSI_MODE_R		( (uint16_t) 0x6000 )
// DMA completion Mode register
#define DMA_COMPL_MODE_R	( (uint16_t) 0x6400 )
// Mode Control register
#define MODE_CTRL_R             ( (uint16_t) 0x6800 )
// Misc Configuration register
#define MISC_CFG_R              ( (uint16_t) 0x6804 )
// Misc Local Control register
#define MISC_LOCAL_CTRL_R       ( (uint16_t) 0x6808 )
// RX-Risc Mode Register
#define RX_CPU_MODE_R    	( (uint16_t) 0x5000 )
// RX-Risc State Register
#define RX_CPU_STATE_R    	( (uint16_t) 0x5004 )
// RX-Risc Program Counter
#define RX_CPU_PC_R  		( (uint16_t) 0x501c )
// RX-Risc Event Register
#define RX_CPU_EVENT_R    	( (uint16_t) 0x6810 )
// MDI Control register
#define MDI_CTRL_R		( (uint16_t) 0x6844 )
// WOL Mode register
#define WOL_MODE_R		( (uint16_t) 0x6880 )
// WOL Config register
#define WOL_CFG_R		( (uint16_t) 0x6884 )
// WOL Status register
#define WOL_STATUS_R		( (uint16_t) 0x6888 )

// ASF Control register
#define ASF_CTRL_R		( (uint16_t) 0x6c00 )
// ASF Watchdog Timer register
#define ASF_WATCHDOG_TIMER_R	( (uint16_t) 0x6c0c )
// ASF Heartbeat Timer register
#define ASF_HEARTBEAT_TIMER_R	( (uint16_t) 0x6c10 )
// Poll ASF Timer register
#define ASF_POLL_TIMER_R	( (uint16_t) 0x6c14 )
// Poll Legacy Timer register
#define POLL_LEGACY_TIMER_R	( (uint16_t) 0x6c18 )
// Retransmission Timer register
#define RETRANSMISSION_TIMER_R	( (uint16_t) 0x6c1c )
// Time Stamp Counter register
#define TIME_STAMP_COUNTER_R	( (uint16_t) 0x6c20 )

// NVM Command register
#define NVM_COM_R		( (uint16_t) 0x7000 )
// NVM Write register
#define NVM_WRITE_R		( (uint16_t) 0x7008 )
// NVM Address register
#define NVM_ADDR_R		( (uint16_t) 0x700c )
// NVM Read registertg3_phy_copper_begin
#define NVM_READ_R		( (uint16_t) 0x7010 )
// NVM Access register
#define NVM_ACC_R		( (uint16_t) 0x7024 )
// NVM Config 1 register
#define NVM_CFG1_R		( (uint16_t) 0x7014 )
// Software arbitration register
#define SW_ARB_R                ( (uint16_t) 0x7020 )

/*
 * useful def's
 */
#define rd08(a) 	ci_read_8((uint8_t *)(a))
#define rd16(a) 	ci_read_16((uint16_t *)(a))
#define rd32(a) 	ci_read_32((uint32_t *)(a))
#define wr08(a,v)	ci_write_8((uint8_t *)(a), (v))
#define wr16(a,v)	ci_write_16((uint16_t *)(a), (v))
#define wr32(a,v)	ci_write_32((uint32_t *)(a), (v))

#define BIT08( bit )     ( (uint8_t) 0x1 << (bit) )
#define BIT16( bit )     ( (uint16_t) 0x1 << (bit) )
#define BIT32( bit )     ( (uint32_t) 0x1 << (bit) )

/*
 * type definition
 */

/*
 * Constants for different kinds of IOCTL requests
 */

#define SIOCETHTOOL  0x1000

/*
 * special structure and constants for IOCTL requests of type ETHTOOL
 */

#define ETHTOOL_GMAC         0x03
#define ETHTOOL_SMAC         0x04
#define ETHTOOL_VERSION      0x05

typedef struct {
	int idx;
	char address[6];
} ioctl_ethtool_mac_t;

typedef struct {
	unsigned int length;
	char *text;
} ioctl_ethtool_version_t;


/*
 * default structure and constants for IOCTL requests
 */

#define IF_NAME_SIZE 0xFF

typedef struct {
	char if_name[IF_NAME_SIZE];
	int subcmd;
	union {
		ioctl_ethtool_mac_t mac;
		ioctl_ethtool_version_t version;
	} data;
} ioctl_net_data_t;

extern net_driver_t *bcm57xx_open(void);
extern void bcm57xx_close(net_driver_t *driver);
extern int bcm57xx_read(char *buf, int len);
extern int bcm57xx_write(char *buf, int len);
