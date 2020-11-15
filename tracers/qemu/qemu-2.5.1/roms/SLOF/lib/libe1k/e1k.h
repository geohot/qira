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
 * Definitions for the e1000 Gigabit Ethernet Driver for SLOF
 */

#include <stdint.h>
#include <cache.h>

// compiler switches

// Debug switches
//#define E1K_DEBUG		// main debug switch, w/o it the other ones don't work
//#define E1K_SHOW_RCV
//#define E1K_SHOW_RCV_DATA
//#define E1K_SHOW_XMIT
//#define E1K_SHOW_XMIT_DATA

/*
 * pci register offsets
 */
// PCI command register
#define PCI_COM_R               ((uint16_t) 0x0004)
// PCI Cache Line Size register
#define PCI_CACHELS_R           ((uint16_t) 0x000c)
// PCI bar1 register
#define PCI_BAR1_R              ((uint16_t) 0x0010)
// PCI bar2 register
#define PCI_BAR2_R              ((uint16_t) 0x0014)
// PCI bar1 register
#define PCI_SUBID_R             ((uint16_t) 0x002e)

/*
 * e1000 register offsets
 */
// Device Control register
#define CTRL			((uint16_t) 0x0000)
// Device Status register
#define STATUS			((uint16_t) 0x0008)
// Eeprom Read register
#define EERD			((uint16_t) 0x0014)
// Interrupt Mask Clear register
#define IMC			((uint16_t) 0x00d8)
// Receive Control register
#define RCTL			((uint16_t) 0x0100)
// Receive Descriptor Base Address Low register
#define RDBAL			((uint16_t) 0x2800)
// Receive Descriptor Base Address High register
#define RDBAH			((uint16_t) 0x2804)
// Receive Descriptor Length register
#define RDLEN			((uint16_t) 0x2808)
// Receive Descriptor Head register
#define RDH			((uint16_t) 0x2810)
// Receive Descriptor Tail register
#define RDT			((uint16_t) 0x2818)
// Receive Delay Timer register
#define RDTR			((uint16_t) 0x2820)
// Transmit Control register
#define TCTL			((uint16_t) 0x0400)
// Transmit Descriptor Base Address Low register
#define TDBAL			((uint16_t) 0x3800)
// Transmit Descriptor Base Address High register
#define TDBAH			((uint16_t) 0x3804)
// Transmit Descriptor Length register
#define TDLEN			((uint16_t) 0x3808)
// Transmit Descriptor Head register
#define TDH			((uint16_t) 0x3810)
// Transmit Descriptor Tail register
#define TDT			((uint16_t) 0x3818)
// Receive Address Low register
#define RAL0			((uint16_t) 0x5400)
// Receive Address High register
#define RAH0			((uint16_t) 0x5404)


/*
 * useful def's
 */
#define rd08(a) 	ci_read_8((uint32_t *)(a))
#define rd16(a) 	ci_read_16((uint32_t *)(a))
#define rd32(a) 	ci_read_32((uint32_t *)(a))
#define wr08(a,v)	ci_write_8((uint32_t *)(a), (v))
#define wr16(a,v)	ci_write_16((uint32_t *)(a), (v))
#define wr32(a,v)	ci_write_32((uint32_t *)(a), (v))
//#define printk	snk_kernel_interface->print
//#define ms_delay	snk_kernel_interface->ms_delay

#define BIT08(bit)	((uint8_t) 0x1 << (bit))
#define BIT16(bit)	((uint16_t) 0x1 << (bit))
#define BIT32(bit)	((uint32_t) 0x1 << (bit))

//#define mb()	asm volatile("sync" ::: "memory");

extern net_driver_t *e1k_open(uint64_t baseaddr);
extern void e1k_close(net_driver_t *driver);
extern int e1k_read(char *buf, int len);
extern int e1k_write(char *buf, int len);
extern int e1k_mac_setup(uint16_t vendor_id, uint16_t device_id,
			uint64_t baseaddr, char *mac_addr);
