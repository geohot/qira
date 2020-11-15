/******************************************************************************
 * Copyright (c) 2007, 2011, 2013 IBM Corporation
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
 * e1000 Gigabit Ethernet Driver for SLOF
 *
 * Reference:
 *   PCI/PCI-X Family of Gigabit Ethernet Controllers
 *   Software Developer's Manual Rev. 3.3, Intel, December 2006
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <byteorder.h>
#include <helpers.h>
#include <netdriver.h>
#include "e1k.h"

/*
 * local defines
 ******************************************************************************
 */
#define E1K_NUM_RX_DESC	128	// do not change
#define E1K_NUM_TX_DESC	128	// do not change
#define E1K_BUF_SIZE	2096	// do not change

#define NUM_MAC_ADDR	16	// number of mac address register pairs
#define EEPROM_MAC_OFFS	0	// position of mac address in eeprom

/*
 * local types
 ******************************************************************************
 */
typedef struct {
	uint32_t m_dev_u32;
	uint64_t m_devmsk_u64;
	char *m_name;
}	e1k_dev_t;

/*
 * e1k common data structures
 */

/*
 * transmit buffer descriptor
 */
typedef struct {
	uint64_t m_buffer_u64;
	uint16_t m_len_u16;
	uint8_t m_cso_u08;
	uint8_t m_cmd_u08;
	uint8_t m_sta_u08;
	uint8_t m_css_u08;
	uint16_t m_spe_u16;
}	__attribute__ ((packed)) e1k_tx_desc_st;


/*
 * receive buffer descriptor
 */
typedef struct {
	uint64_t m_buffer_u64;
	uint16_t m_len_u16;
	uint16_t m_csm_u16;
	uint8_t m_sta_u08;
	uint8_t m_err_u08;
	uint16_t m_spe_u16;
}	__attribute__ ((packed)) e1k_rx_desc_st;

/*
 * e1k device structure
 */
typedef struct {
	/*
	 * device identification mask
	 */
	uint64_t	m_device_u64;

	/*
	 * memory mapped base address of NIC
	 */
	uint64_t	m_baseaddr_u64;

	/*
	 * transmit & receive rings
	 * must be 16 byte aligned
	 */
	e1k_tx_desc_st	m_tx_ring_pst[E1K_NUM_TX_DESC];
	e1k_rx_desc_st	m_rx_ring_pst[E1K_NUM_RX_DESC];

	/*
	 * transmit & receive buffers
	 * must be 16 byte aligned
	 */
	uint8_t		m_tx_buffer_pu08[E1K_NUM_TX_DESC][E1K_BUF_SIZE];
	uint8_t		m_rx_buffer_pu08[E1K_NUM_RX_DESC][E1K_BUF_SIZE];

	/*
	 * next receive descriptor index
	 */
	uint32_t	m_rx_next_u32;

	/*
	 * command register storage
	 */
	uint16_t	m_com_r_u16;

	/*
	 * padding to make the size of the structure a multiple of 16 byte
	 */
	uint16_t	m_pad16_u16;
	uint64_t	m_pad64_u32;

}	__attribute__ ((packed)) e1k_st;

/*
 * local constants
 ******************************************************************************
 */
#define E1K_82540	((uint64_t) 0x1)
#define E1K_82541	((uint64_t) 0x2)
#define E1K_82544	((uint64_t) 0x4)
#define E1K_82545	((uint64_t) 0x8)
#define E1K_82546	((uint64_t) 0x10)
#define E1K_82547	((uint64_t) 0x20)

#define IS_82541	((m_e1k.m_device_u64 & E1K_82541) != 0)
#define IS_82546	((m_e1k.m_device_u64 & E1K_82546) != 0)
#define IS_82547	((m_e1k.m_device_u64 & E1K_82547) != 0)

static const e1k_dev_t e1k_dev[] = {
	{ 0x1019, E1K_82547, "82547EI/GI Copper" },
	{ 0x101A, E1K_82547, "82547EI Mobile" },
	{ 0x1010, E1K_82546, "52546EB Copper, Dual Port" },
	{ 0x1012, E1K_82546, "82546EB Fiber, Dual Port" },
/*	{ 0x101D, E1K_82546, "82546EB Copper, Quad Port" }, */
	{ 0x1079, E1K_82546, "82546GB Copper, Dual Port" },
	{ 0x107A, E1K_82546, "82546GB Fiber, Dual Port" },
	{ 0x107B, E1K_82546, "82546GB SerDes, Dual Port" },
	{ 0x100F, E1K_82545, "82545EM Copper" },
	{ 0x1011, E1K_82545, "82545EM Fiber" },
	{ 0x1026, E1K_82545, "82545GM Copper" },
	{ 0x1027, E1K_82545, "82545GM Fiber" },
	{ 0x1028, E1K_82545, "82545GM SerDes" },
	{ 0x1107, E1K_82544, "82544EI Copper" },
	{ 0x1112, E1K_82544, "82544GC Copper" },
	{ 0x1013, E1K_82541, "82541EI Copper" },
	{ 0x1018, E1K_82541, "82541EI Mobile" },
	{ 0x1076, E1K_82541, "82541GI Copper" },
	{ 0x1077, E1K_82541, "82541GI Mobile" },
	{ 0x1078, E1K_82541, "82541ER Copper" },
	{ 0x107C, E1K_82541, "82541PI" },
	{ 0x1015, E1K_82540, "82540EM Mobile" },
	{ 0x1016, E1K_82540, "82540EP Mobile" },
	{ 0x1017, E1K_82540, "82540EP Desktop" },
	{ 0x100E, E1K_82540, "82540EM Desktop" },
	{ 0     , 0 }
};

/*
 * local variables
 ******************************************************************************
 */
static e1k_st	m_e1k __attribute__ ((aligned(16)));
static long dma_offset;

/*
 * global functions
 ******************************************************************************
 */
int
check_driver(uint16_t vendor_id, uint16_t device_id);

static int e1k_init(net_driver_t *driver);
static int e1k_term(void);
static int e1k_xmit(char *f_buffer_pc, int f_len_i);
static int e1k_receive(char *f_buffer_pc, int f_len_i);

/**
 * Translate virtual to "physical" address, ie. an address
 * which can be used for DMA transfers.
 */
static uint64_t
virt2dma(void *addr)
{
	return (uint64_t)addr + dma_offset;
}

static void *
dma2virt(uint64_t addr)
{
	return (void *)(addr - dma_offset);
}

/*
 * local inline functions for e1k register access
 ******************************************************************************
 */
static uint32_t
e1k_rd32(uint16_t f_offs_u16)
{	// caution: shall only be used after initialization!
	return bswap_32(rd32(m_e1k.m_baseaddr_u64 + (uint64_t) f_offs_u16));
}

/* not used so far
static uint16_t
e1k_rd16(uint16_t f_offs_u16)
{	// caution: shall only be used after initialization!
	return bswap_16(rd16(m_e1k.m_baseaddr_u64 + (uint64_t) f_offs_u16));
}*/

/* not used so far
static uint8_t
e1k_rd08(uint16_t f_offs_u16)
{	// caution: shall only be used after initialization!
	return rd08(m_e1k.m_baseaddr_u64 + (uint64_t) f_offs_u16);
}*/

static void
e1k_wr32(uint16_t f_offs_u16, uint32_t f_val_u32)
{	// caution: shall only be used after initialization!
	wr32(m_e1k.m_baseaddr_u64 + (uint64_t) f_offs_u16, bswap_32(f_val_u32));
}

/* not used so far
static void
e1k_wr16(uint16_t f_offs_u16, uint16_t f_val_u16)
{	// caution: shall only be used after initialization!
	wr16(m_e1k.m_baseaddr_u64 + (uint64_t) f_offs_u16, bswap_16(f_val_u16));
}*/

/* not used so far
static void
e1k_wr08(uint16_t f_offs_u16, uint8_t f_val_u08)
{	// caution: shall only be used after initialization!
	wr08(m_e1k.m_baseaddr_u64 + (uint64_t) f_offs_u16, f_val_u08);
}*/

static void
e1k_setb32(uint16_t f_offs_u16, uint32_t f_mask_u32)
{
	uint32_t v;

	v  = e1k_rd32(f_offs_u16);
	v |= f_mask_u32;
	e1k_wr32(f_offs_u16, v);
}

/* not used so far
static void
e1k_setb16(uint16_t f_offs_u16, uint16_t f_mask_u16)
{
	uint16_t v;
	v  = e1k_rd16(f_offs_u16);
	v |= f_mask_u16;
	e1k_wr16(f_offs_u16, v);
}*/

/* not used so far
static void
e1k_setb08(uint16_t f_offs_u16, uint8_t f_mask_u08)
{
	uint8_t v;
	v  = e1k_rd08(f_offs_u16);
	v |= f_mask_u08;
	e1k_wr08(f_offs_u16, v);
}*/

static void
e1k_clrb32(uint16_t f_offs_u16, uint32_t f_mask_u32)
{
	uint32_t v;

	v  = e1k_rd32(f_offs_u16);
	v &= ~f_mask_u32;
	e1k_wr32(f_offs_u16, v);
}

/* not used so far
static void
e1k_clrb16(uint16_t f_offs_u16, uint16_t f_mask_u16)
{
	uint16_t v;

	v  = e1k_rd16(f_offs_u16);
	v &= ~f_mask_u16;
	e1k_wr16(f_offs_u16, v);
}*/

/* not used so far
static void
e1k_clrb08(uint16_t f_offs_u16, uint8_t f_mask_u08)
{
	uint8_t v;
	v  = e1k_rd08(f_offs_u16);
	v &= ~f_mask_u08;
	e1k_wr08(f_offs_u16, v);
}*/

static int32_t
e1k_eep_rd16(uint8_t f_offs_u08, uint16_t *f_data_pu16)
{
	uint32_t i;
	uint32_t v;
	int32_t done_shft;
	int32_t addr_shft;

	if(IS_82541 || IS_82547) {
		addr_shft = 2;
		done_shft = 1;
	} else {
		addr_shft = 8;
		done_shft = 4;
	}

	/*
	 * initiate eeprom read
	 */
	e1k_wr32(EERD, ((uint32_t) f_offs_u08 << addr_shft) |	// address
		  BIT32(0));					// start read

	/*
	 * wait for read done bit to be set
	 */
	i = 1000;
	v = e1k_rd32(EERD);
	while ((--i) &&
	       ((v & BIT32(done_shft)) == 0)) {
		SLOF_msleep(1);
		v = e1k_rd32(EERD);
	}

	/*
	 * return on error
	 */
	if ((v & BIT32(done_shft)) == 0) {
		return -1;
	}
	
	/*
	 * return data
	 */
	*f_data_pu16 = (uint16_t) ((v >> 16) & 0xffff);

	return 0;
}

/*
 * ring initialization
 */
static void
e1k_init_receiver(void)
{
	uint32_t i;
	uint64_t addr;

	/*
	 * disable receiver for initialization
	 */
	e1k_wr32(RCTL, 0);

	/*
	 * clear receive desciptors and setup buffer pointers
	 */
	for (i = 0; i < E1K_NUM_RX_DESC; i++) {
		memset((uint8_t *) &m_e1k.m_rx_ring_pst[i], 0,
			sizeof(e1k_rx_desc_st));
		mb();

		m_e1k.m_rx_ring_pst[i].m_buffer_u64 =
			bswap_64(virt2dma(&m_e1k.m_rx_buffer_pu08[i][0]));
	}

	/*
	 * initialize previously received index
	 */
	m_e1k.m_rx_next_u32 = 0;

	/*
	 * setup the base address and the length of the rx descriptor ring
	 */
	addr = virt2dma(&m_e1k.m_rx_ring_pst[0]);
	e1k_wr32(RDBAH, (uint32_t) ((uint64_t) addr >> 32));
	e1k_wr32(RDBAL, (uint32_t) ((uint64_t) addr & 0xffffffff));
	e1k_wr32(RDLEN, E1K_NUM_RX_DESC * sizeof(e1k_rx_desc_st));

	/*
	 * setup the rx head and tail descriptor indices
	 */
	e1k_wr32(RDH, 0);
	e1k_wr32(RDT, E1K_NUM_RX_DESC - 1);

	/*
	 * setup the receive delay timer register
	 */
	e1k_wr32(RDTR, 0);

	/*
	 * setup the receive control register
	 */
	e1k_wr32(RCTL,  BIT32( 1) |	// enable receiver
			BIT32( 4) |	// enable multicast reception
			BIT32(15));	// broadcast accept mode
					// packet size 2048
					// no buffer extension
}

static void
e1k_init_transmitter(void)
{
	uint32_t i;
	uint64_t addr;

	/*
	 * clear transmit desciptors and setup buffer pointers
	 */
	for (i = 0; i < E1K_NUM_TX_DESC; i++) {
		memset((uint8_t *) &m_e1k.m_tx_ring_pst[i], 0,
			sizeof(e1k_tx_desc_st));
		mb();

		m_e1k.m_tx_ring_pst[i].m_buffer_u64 =
			bswap_64(virt2dma(&m_e1k.m_tx_buffer_pu08[i][0]));
	}

	/*
	 * setup the base address and the length of the tx descriptor ring
	 */
	addr = virt2dma(&m_e1k.m_tx_ring_pst[0]);
	e1k_wr32(TDBAH, (uint32_t) ((uint64_t) addr >> 32));
	e1k_wr32(TDBAL, (uint32_t) ((uint64_t) addr & 0xffffffff));
	e1k_wr32(TDLEN, E1K_NUM_TX_DESC * sizeof(e1k_tx_desc_st));

	/*
	 * setup the rx head and tail descriptor indices
	 */
	e1k_wr32(TDH, 0);
	e1k_wr32(TDT, 0);

	/*
	 * initialize the transmit control register
	 */
	e1k_wr32(TCTL, BIT32(1) |			// enable transmitter
			BIT32(3) |			// pad short packets
			((uint32_t) 0x0f <<  4) |	// collision threshhold
			((uint32_t) 0x40 << 12));	// collision distance
}

static int32_t
e1k_mac_init(uint8_t *f_mac_pu08)
{
	uint32_t l_ah_u32;
	uint32_t l_al_u32;
	uint32_t i;
	uint32_t v;

	/*
	 * Use MAC address from device tree if possible
	 */
	for (i = 0, v = 0; i < 6; i++) {
		v += (uint32_t) f_mac_pu08[i];
	}

	if (v != 0) {
		/*
		 * use passed mac address for transmission to nic
		 */
		l_al_u32  = ((uint32_t) f_mac_pu08[3] << 24);
		l_al_u32 |= ((uint32_t) f_mac_pu08[2] << 16);
		l_al_u32 |= ((uint32_t) f_mac_pu08[1] <<  8);
		l_al_u32 |= ((uint32_t) f_mac_pu08[0] <<  0);
		l_ah_u32  = ((uint32_t) f_mac_pu08[5] <<  8);
		l_ah_u32 |= ((uint32_t) f_mac_pu08[4] <<  0);
	} else {
		/*
		 * read mac address from eeprom
		 */
		uint16_t w[3];	// 3 16 bit words from eeprom

		for (i = 0; i < 3; i++) {
			if (e1k_eep_rd16(EEPROM_MAC_OFFS + i, &w[i]) != 0) {
				printf("Failed to read MAC address from EEPROM!\n");
				return -1;
			}
		}

		/*
		 * invert the least significant bit for 82546 dual port
		 * if the second device is in use (remember word is byteswapped)
		 */
		if ((IS_82546) &&
		    ((e1k_rd32(STATUS) & BIT32(2)) != 0)) {
			w[2] ^= (uint16_t) 0x100;
		}

		/*
		 * store mac address for transmission to nic
		 */
		l_ah_u32  = ((uint32_t) w[2] <<  0);
		l_al_u32  = ((uint32_t) w[1] << 16);
		l_al_u32 |= ((uint32_t) w[0] <<  0);

		/*
		 * return mac address
		 * mac address in eeprom is stored byteswapped
		 */
		f_mac_pu08[1] = (uint8_t) ((w[0] >> 8) & 0xff);
		f_mac_pu08[0] = (uint8_t) ((w[0] >> 0) & 0xff);
		f_mac_pu08[3] = (uint8_t) ((w[1] >> 8) & 0xff);
		f_mac_pu08[2] = (uint8_t) ((w[1] >> 0) & 0xff);
		f_mac_pu08[5] = (uint8_t) ((w[2] >> 8) & 0xff);
		f_mac_pu08[4] = (uint8_t) ((w[2] >> 0) & 0xff);
	}

	/*
	 * insert mac address in receive address register
	 * and set AV bit
	 */
	e1k_wr32(RAL0, l_al_u32);
	e1k_wr32(RAH0, l_ah_u32 | BIT32(31));

	/*
	 * clear remaining receive address registers
	 */
	for (i = 1; i < NUM_MAC_ADDR; i++) {
		e1k_wr32(RAL0 + i * sizeof(uint64_t), 0);
		e1k_wr32(RAH0 + i * sizeof(uint64_t), 0);
	}

	return 0;
}


/*
 * interface
 ******************************************************************************
 */
  
/*
 * e1k_receive
 */
static int
e1k_receive(char *f_buffer_pc, int f_len_i)
{
	uint32_t	l_rdh_u32 = e1k_rd32(RDH);	// this includes needed dummy read
	e1k_rx_desc_st	*rx;
	int		l_ret_i;

	#ifdef E1K_DEBUG
	#ifdef E1K_SHOW_RCV_DATA
	int		i;
	#endif
	#endif

	/*
	 * check whether new packets have arrived
	 */
	if (m_e1k.m_rx_next_u32 == l_rdh_u32) {
		return 0;
	}

	/*
	 * get a pointer to the next rx descriptor for ease of use
	 */
	rx = &m_e1k.m_rx_ring_pst[m_e1k.m_rx_next_u32];

	/*
	 * check whether the descriptor done bit is set
	 */
	if ((rx->m_sta_u08 & 0x1) == 0) {
		return 0;
	}

	/*
	 * get the length of the packet, throw away checksum
	 */
	l_ret_i = (int) bswap_16(rx->m_len_u16) - (int) 4;

	/*
	 * copy the data
	 */
	memcpy((uint8_t *) f_buffer_pc, dma2virt(bswap_64(rx->m_buffer_u64)),
		(size_t) l_ret_i);

	#ifdef E1K_DEBUG
	#if defined(E1K_SHOW_RCV) || defined(E1K_SHOW_RCV_DATA)
	printf("e1k: %d bytes received\n", l_ret_i);
	#endif

	#ifdef E1K_SHOW_RCV_DATA
	for (i = 0; i < l_ret_i; i++) {

		if ((i & 0x1f) == 0) {
			printf("\n       ");
		}

		printf("%02X ", f_buffer_pc[i]);
	}

	printf("\n\n");
	#endif
	#endif

	/*
	 * clear descriptor for reusage, but leave buffer pointer untouched
	 */
	memset((uint8_t *) &rx->m_len_u16, 0,
		sizeof(e1k_rx_desc_st) - sizeof(uint64_t));
	mb();

	/*
	 * write new tail pointer
	 */
	e1k_wr32(RDT, m_e1k.m_rx_next_u32);

	/*
	 * update next receive index
	 */
	m_e1k.m_rx_next_u32 = (m_e1k.m_rx_next_u32 + 1) & (E1K_NUM_RX_DESC - 1);

	return l_ret_i;
}

static int
e1k_xmit(char *f_buffer_pc, int f_len_i)
{
	uint32_t	l_tdh_u32 = e1k_rd32(TDH);
	uint32_t	l_tdt_u32 = e1k_rd32(TDT);
	uint32_t	l_pre_u32 = (l_tdh_u32 + (E1K_NUM_TX_DESC - 1)) &
				    (E1K_NUM_TX_DESC - 1);
	e1k_tx_desc_st	*tx;
	#if defined(E1K_DEBUG) && defined(E1K_SHOW_XMIT_DATA)
	int		i;
	#endif

	/*
	 * check for available buffers
	 */
	if (l_pre_u32 == l_tdt_u32) {
		return 0;
	}

	/*
	 * get a pointer to the next tx descriptor for ease of use
	 */
	tx = &m_e1k.m_tx_ring_pst[l_tdt_u32];

	/*
	 * copy the data
	 */
	memcpy(dma2virt(bswap_64(tx->m_buffer_u64)), (uint8_t *) f_buffer_pc,
		(size_t) f_len_i);

	/*
	 * insert length & command flags
	 */
	tx->m_len_u16 = bswap_16((uint16_t) f_len_i);
	tx->m_cmd_u08 = (BIT08(0) |		// EOP
			  BIT08(1));		// IFCS
	tx->m_sta_u08 = 0;
	mb();

	/*
	 * update tail index
	 */
	l_tdt_u32 = (l_tdt_u32 + 1) & (E1K_NUM_TX_DESC - 1);
	e1k_wr32(TDT, l_tdt_u32);

	#ifdef E1K_DEBUG
	#if defined(E1K_SHOW_XMIT) || defined(E1K_SHOW_XMIT_DATA)
	printf("e1k: %d bytes transmitted\n", bswap_16(tx->m_len_u16));
	#endif

	#ifdef E1K_SHOW_XMIT_DATA
	for (i = 0; i < bswap_16(tx->m_len_u16); i++) {

		if ((i & 0x1f) == 0) {
			printf("\n       ");
		}

		f_buffer_pc = dma2virt(bswap_64(tx->m_buffer_u64));
		printf("%02X ", f_buffer_pc[i]);
	}

	printf("\n\n");
	#endif
	#endif

	return f_len_i;
}

int
check_driver(uint16_t vendor_id, uint16_t device_id)
{
	uint64_t i;

	/*
	 * checks whether the driver is handling this device
	 * by verifying vendor & device id
	 * vendor id 0x8086 == Intel
	 */
	if (vendor_id != 0x8086) {
		#ifdef E1K_DEBUG
		printf("e1k: netdevice with vendor id %04X not supported\n",
			vendor_id);
		#endif
		return -1;
	}

	for (i = 0; e1k_dev[i].m_dev_u32 != 0; i++) {
		if (e1k_dev[i].m_dev_u32 == (uint32_t) device_id) {
			break;
		}
	}

	if (e1k_dev[i].m_dev_u32 == 0) {
		#ifdef E1K_DEBUG
		printf("e1k: netdevice with device id %04X not supported\n",
			device_id);
		#endif
		return -1;
	}

	/*
	 * initialize static variables
	 */
	m_e1k.m_device_u64   = e1k_dev[i].m_devmsk_u64;
	m_e1k.m_baseaddr_u64 = 0;

	// success
	#ifdef E1K_DEBUG
	printf("e1k: found device %s\n", e1k_dev[i].m_name);
	#endif

	return 0;
}

static int
e1k_init(net_driver_t *driver)
{
	uint32_t i;
	uint32_t v;

	if (!driver)
		return -1;

	#ifdef E1K_DEBUG
	printf("\ne1k: initializing\n");
	#endif

	dma_offset = SLOF_dma_map_in(&m_e1k, sizeof(m_e1k), 0);
	#ifdef E1K_DEBUG
	printf("e1k: dma offset: %lx - %lx = %lx\n", dma_offset, (long)&m_e1k,
		dma_offset - (long)&m_e1k);
	#endif
	dma_offset = dma_offset - (long)&m_e1k;

	/*
	 * setup register & memory base addresses of NIC
	 */
	//m_e1k.m_baseaddr_u64 = baseaddr;
	#ifdef E1K_DEBUG
	printf("e1k: base address register = 0x%llx\n", m_e1k.m_baseaddr_u64);
	#endif

	/*
	 * e1k hardware initialization
	 */

	/*
	 * at first disable all interrupts
	 */
	e1k_wr32(IMC, (uint32_t) ~0);

	/*
	 * check for link up
	 */
	#ifdef E1K_DEBUG
	printf("e1k: checking link status..\n");
	#endif

	i = 50;
	v = e1k_rd32(STATUS);
	while ((--i) &&
	       ((v & BIT32(1)) == 0)) {
		SLOF_msleep(100);
		v = e1k_rd32(STATUS);
	}

	if ((v & BIT32(1)) == 0) {
		#ifdef E1K_DEBUG
		printf("e1k: link is down.\n");
		printf("       terminating.\n");
		#endif

		return -1;
	}

	#ifdef E1K_DEBUG
	printf("e1k: link is up\n");

	switch ((v >> 6) & 0x3) {
		case 0: {
			printf("       10 Mb/s\n");
		}	break;
		case 1: {
			printf("       100 Mb/s\n");
		}	break;
		case 2:
		case 3: {
			printf("       1000 Mb/s\n");
		}	break;
	}

	if ((v & BIT32(0)) == 0) {
		printf("       half-duplex\n");
	} else {
		printf("       full-duplex\n");
	}
	#endif

	/*
	 * initialize mac address
	 */
	#ifdef E1K_DEBUG
	printf("e1k: initializing mac address.. ");
	#endif
	if (e1k_mac_init((uint8_t *)driver->mac_addr) != 0) {
		#ifdef E1K_DEBUG
		printf("failed.\n");
		printf("       terminating.\n");
		#endif

		return -1;
	}

	#ifdef E1K_DEBUG
	printf("done.\n");
	printf("       mac address = %02X:%02X:%02X:%02X:%02X:%02X\n",
		driver->mac_addr[0], driver->mac_addr[1], driver->mac_addr[2],
		driver->mac_addr[3], driver->mac_addr[4], driver->mac_addr[5]);
	#endif

	/*
	 * initialize transmitter
	 */
	#ifdef E1K_DEBUG
	printf("e1k: initializing transmitter.. ");
	#endif
	e1k_init_transmitter();
	#ifdef E1K_DEBUG
	printf("done.\n");
	#endif

	/*
	 * initialize receiver
	 */
	#ifdef E1K_DEBUG
	printf("e1k: initializing receiver.. ");
	#endif
	e1k_init_receiver();
	#ifdef E1K_DEBUG
	printf("done.\n");
	printf("e1k: initialization complete\n");
	#endif

	driver->running = 1;

	return 0;
}

static int
e1k_reset(void)
{
	/*
	 * reset the PHY
	 */
	e1k_setb32(CTRL, BIT32(31));
	SLOF_msleep(10);

	/*
	 * reset the MAC
	 */
	e1k_setb32(CTRL, BIT32(26));
	SLOF_msleep(10);

	return 0;
}

static int 
e1k_term(void)
{
	#ifdef E1K_DEBUG
	printf("e1k: shutdown.. ");
	#endif

	/*
	 * disable receiver & transmitter
	 */
	e1k_wr32(RCTL, 0);
	e1k_wr32(TCTL, 0);
	SLOF_msleep(10);

	/*
	 * reset the ring indices
	 */
	e1k_wr32(RDH, 0);
	e1k_wr32(RDT, 0);
	e1k_wr32(TDH, 0);
	e1k_wr32(TDT, 0);

	/*
	 * disable receive address
	 */
	e1k_clrb32(RAH0, BIT32(31));

	/*
	 * reset the mac/phy
	 */
	e1k_reset();

	/*
	 * Disable DMA translation
	 */
	SLOF_dma_map_out((long)virt2dma(&m_e1k), (void *)&m_e1k, (long)sizeof(m_e1k));

	#ifdef E1K_DEBUG
	printf("done.\n");
	#endif

	return 0;
}

net_driver_t *e1k_open(uint64_t baseaddr)
{
	net_driver_t *driver;

	m_e1k.m_baseaddr_u64 = baseaddr;
	driver = SLOF_alloc_mem(sizeof(*driver));
	if (!driver) {
		printf("Unable to allocate virtio-net driver\n");
		return NULL;
	}
	memset(driver, 0, sizeof(*driver));

	if (e1k_init(driver))
		goto FAIL;

	return driver;

FAIL:	SLOF_free_mem(driver, sizeof(*driver));
	return NULL;

	return 0;
}

void e1k_close(net_driver_t *driver)
{
	if (driver->running == 0)
		return;

	e1k_term();
	driver->running = 0;
	SLOF_free_mem(driver, sizeof(*driver));
}

int e1k_read(char *buf, int len)
{
	if (buf)
		return e1k_receive(buf, len);
	return -1;
}

int e1k_write(char *buf, int len)
{
	if (buf)
		return e1k_xmit(buf, len);
	return -1;
}

int e1k_mac_setup(uint16_t vendor_id, uint16_t device_id,
			uint64_t baseaddr, char *mac_addr)
{
	if (check_driver(vendor_id, device_id))
		return -1;

	m_e1k.m_baseaddr_u64 = baseaddr;
	memset(mac_addr, 0, 6);
	
	return e1k_mac_init((uint8_t *)mac_addr);
}
