/**************************************************************************
*
*    dmfe.c -- Etherboot device driver for the Davicom 
*	DM9102/DM9102A/DM9102A+DM9801/DM9102A+DM9802 NIC fast ethernet card
*
*    Written 2003-2003 by Timothy Legge <tlegge@rogers.com>
*
*    This program is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
*    02110-1301, USA.
*
*    Portions of this code based on:
*
*       dmfe.c:     A Davicom DM9102/DM9102A/DM9102A+DM9801/DM9102A+DM9802 
*		NIC fast ethernet driver for Linux.
*       Copyright (C) 1997  Sten Wang
*       (C)Copyright 1997-1998 DAVICOM Semiconductor,Inc. All Rights Reserved.
*
*
*    REVISION HISTORY:
*    ================
*    v1.0       10-02-2004      timlegge        Boots ltsp needs cleanup 
*
*    Indent Options: indent -kr -i8
*
*
***************************************************************************/

FILE_LICENCE ( GPL2_OR_LATER );

/* to get some global routines like printf */
#include "etherboot.h"
/* to get the interface to the body of the program */
#include "nic.h"
/* to get the PCI support functions, if this is a PCI NIC */
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>

/* #define EDEBUG 1 */
#ifdef EDEBUG
#define dprintf(x) printf x
#else
#define dprintf(x)
#endif

/* Condensed operations for readability. */
#define virt_to_le32desc(addr)  cpu_to_le32(virt_to_bus(addr))
#define le32desc_to_virt(addr)  bus_to_virt(le32_to_cpu(addr))

/* Board/System/Debug information/definition ---------------- */
#define PCI_DM9132_ID   0x91321282	/* Davicom DM9132 ID */
#define PCI_DM9102_ID   0x91021282	/* Davicom DM9102 ID */
#define PCI_DM9100_ID   0x91001282	/* Davicom DM9100 ID */
#define PCI_DM9009_ID   0x90091282	/* Davicom DM9009 ID */

#define DM9102_IO_SIZE  0x80
#define DM9102A_IO_SIZE 0x100
#define TX_MAX_SEND_CNT 0x1	/* Maximum tx packet per time */
#define TX_DESC_CNT     0x10	/* Allocated Tx descriptors */
#define RX_DESC_CNT     0x20	/* Allocated Rx descriptors */
#define TX_FREE_DESC_CNT (TX_DESC_CNT - 2)	/* Max TX packet count */
#define TX_WAKE_DESC_CNT (TX_DESC_CNT - 3)	/* TX wakeup count */
#define DESC_ALL_CNT    (TX_DESC_CNT + RX_DESC_CNT)
#define TX_BUF_ALLOC    0x600
#define RX_ALLOC_SIZE   0x620
#define DM910X_RESET    1
#define CR0_DEFAULT     0x00E00000	/* TX & RX burst mode */
#define CR6_DEFAULT     0x00080000	/* HD */
#define CR7_DEFAULT     0x180c1
#define CR15_DEFAULT    0x06	/* TxJabber RxWatchdog */
#define TDES0_ERR_MASK  0x4302	/* TXJT, LC, EC, FUE */
#define MAX_PACKET_SIZE 1514
#define DMFE_MAX_MULTICAST 14
#define RX_COPY_SIZE	100
#define MAX_CHECK_PACKET 0x8000
#define DM9801_NOISE_FLOOR 8
#define DM9802_NOISE_FLOOR 5

#define DMFE_10MHF      0
#define DMFE_100MHF     1
#define DMFE_10MFD      4
#define DMFE_100MFD     5
#define DMFE_AUTO       8
#define DMFE_1M_HPNA    0x10

#define DMFE_TXTH_72	0x400000	/* TX TH 72 byte */
#define DMFE_TXTH_96	0x404000	/* TX TH 96 byte */
#define DMFE_TXTH_128	0x0000	/* TX TH 128 byte */
#define DMFE_TXTH_256	0x4000	/* TX TH 256 byte */
#define DMFE_TXTH_512	0x8000	/* TX TH 512 byte */
#define DMFE_TXTH_1K	0xC000	/* TX TH 1K  byte */

#define DMFE_TIMER_WUT  (jiffies + HZ * 1)	/* timer wakeup time : 1 second */
#define DMFE_TX_TIMEOUT ((3*HZ)/2)	/* tx packet time-out time 1.5 s" */
#define DMFE_TX_KICK 	(HZ/2)	/* tx packet Kick-out time 0.5 s" */

#define DMFE_DBUG(dbug_now, msg, value) if (dmfe_debug || (dbug_now)) printk(KERN_ERR DRV_NAME ": %s %lx\n", (msg), (long) (value))

#define SHOW_MEDIA_TYPE(mode) printk(KERN_ERR DRV_NAME ": Change Speed to %sMhz %s duplex\n",mode & 1 ?"100":"10", mode & 4 ? "full":"half");


/* CR9 definition: SROM/MII */
#define CR9_SROM_READ   0x4800
#define CR9_SRCS        0x1
#define CR9_SRCLK       0x2
#define CR9_CRDOUT      0x8
#define SROM_DATA_0     0x0
#define SROM_DATA_1     0x4
#define PHY_DATA_1      0x20000
#define PHY_DATA_0      0x00000
#define MDCLKH          0x10000

#define PHY_POWER_DOWN	0x800

#define SROM_V41_CODE   0x14

#define SROM_CLK_WRITE(data, ioaddr) outl(data|CR9_SROM_READ|CR9_SRCS,ioaddr);udelay(5);outl(data|CR9_SROM_READ|CR9_SRCS|CR9_SRCLK,ioaddr);udelay(5);outl(data|CR9_SROM_READ|CR9_SRCS,ioaddr);udelay(5);

#define __CHK_IO_SIZE(pci_id, dev_rev) ( ((pci_id)==PCI_DM9132_ID) || ((dev_rev) >= 0x02000030) ) ? DM9102A_IO_SIZE: DM9102_IO_SIZE
#define CHK_IO_SIZE(pci_dev, dev_rev) __CHK_IO_SIZE(((pci_dev)->device << 16) | (pci_dev)->vendor, dev_rev)

/* Sten Check */
#define DEVICE net_device

/* Structure/enum declaration ------------------------------- */
struct tx_desc {
	u32 tdes0, tdes1, tdes2, tdes3;	/* Data for the card */
	void * tx_buf_ptr;		/* Data for us */
	struct tx_desc * next_tx_desc;
} __attribute__ ((aligned(32)));

struct rx_desc {
	u32 rdes0, rdes1, rdes2, rdes3;	/* Data for the card */
	void * rx_skb_ptr;		/* Data for us */
	struct rx_desc * next_rx_desc;
} __attribute__ ((aligned(32)));

static struct dmfe_private {
	u32 chip_id;		/* Chip vendor/Device ID */
	u32 chip_revision;	/* Chip revision */
	u32 cr0_data;
//	u32 cr5_data;
	u32 cr6_data;
	u32 cr7_data;
	u32 cr15_data;

	u16 HPNA_command;	/* For HPNA register 16 */
	u16 HPNA_timer;		/* For HPNA remote device check */
	u16 NIC_capability;	/* NIC media capability */
	u16 PHY_reg4;		/* Saved Phyxcer register 4 value */

	u8 HPNA_present;	/* 0:none, 1:DM9801, 2:DM9802 */
	u8 chip_type;		/* Keep DM9102A chip type */
	u8 media_mode;		/* user specify media mode */
	u8 op_mode;		/* real work media mode */
	u8 phy_addr;
	u8 dm910x_chk_mode;	/* Operating mode check */

	/* NIC SROM data */
	unsigned char srom[128];
	/* Etherboot Only */
	u8 cur_tx;
	u8 cur_rx;
} dfx;

static struct dmfe_private *db;

enum dmfe_offsets {
	DCR0 = 0x00, DCR1 = 0x08, DCR2 = 0x10, DCR3 = 0x18, DCR4 = 0x20,
	DCR5 = 0x28, DCR6 = 0x30, DCR7 = 0x38, DCR8 = 0x40, DCR9 = 0x48,
	DCR10 = 0x50, DCR11 = 0x58, DCR12 = 0x60, DCR13 = 0x68, DCR14 =
	    0x70,
	DCR15 = 0x78
};

enum dmfe_CR6_bits {
	CR6_RXSC = 0x2, CR6_PBF = 0x8, CR6_PM = 0x40, CR6_PAM = 0x80,
	CR6_FDM = 0x200, CR6_TXSC = 0x2000, CR6_STI = 0x100000,
	CR6_SFT = 0x200000, CR6_RXA = 0x40000000, CR6_NO_PURGE = 0x20000000
};

/* Global variable declaration ----------------------------- */
static struct nic_operations dmfe_operations;

static unsigned char dmfe_media_mode = DMFE_AUTO;
static u32 dmfe_cr6_user_set;

/* For module input parameter */
static u8 chkmode = 1;
static u8 HPNA_mode;		/* Default: Low Power/High Speed */
static u8 HPNA_rx_cmd;		/* Default: Disable Rx remote command */
static u8 HPNA_tx_cmd;		/* Default: Don't issue remote command */
static u8 HPNA_NoiseFloor;	/* Default: HPNA NoiseFloor */
static u8 SF_mode;		/* Special Function: 1:VLAN, 2:RX Flow Control
				   4: TX pause packet */


/**********************************************
* Descriptor Ring and Buffer defination
***********************************************/
struct {
	struct tx_desc txd[TX_DESC_CNT] __attribute__ ((aligned(32)));
	unsigned char txb[TX_BUF_ALLOC * TX_DESC_CNT]
	__attribute__ ((aligned(32)));
	struct rx_desc rxd[RX_DESC_CNT] __attribute__ ((aligned(32)));
	unsigned char rxb[RX_ALLOC_SIZE * RX_DESC_CNT]
	__attribute__ ((aligned(32)));
} dmfe_bufs __shared;
#define txd dmfe_bufs.txd
#define txb dmfe_bufs.txb
#define rxd dmfe_bufs.rxd
#define rxb dmfe_bufs.rxb

/* NIC specific static variables go here */
static long int BASE;

static u16 read_srom_word(long ioaddr, int offset);
static void dmfe_init_dm910x(struct nic *nic);
static void dmfe_descriptor_init(struct nic *, unsigned long ioaddr);
static void update_cr6(u32, unsigned long);
static void send_filter_frame(struct nic *nic);
static void dm9132_id_table(struct nic *nic);

static u16 phy_read(unsigned long, u8, u8, u32);
static void phy_write(unsigned long, u8, u8, u16, u32);
static void phy_write_1bit(unsigned long, u32);
static u16 phy_read_1bit(unsigned long);
static void dmfe_set_phyxcer(struct nic *nic);

static void dmfe_parse_srom(struct nic *nic);
static void dmfe_program_DM9801(struct nic *nic, int);
static void dmfe_program_DM9802(struct nic *nic);

static void dmfe_reset(struct nic *nic)
{
	/* system variable init */
	db->cr6_data = CR6_DEFAULT | dmfe_cr6_user_set;

	db->NIC_capability = 0xf;	/* All capability */
	db->PHY_reg4 = 0x1e0;

	/* CR6 operation mode decision */
	if (!chkmode || (db->chip_id == PCI_DM9132_ID) ||
	    (db->chip_revision >= 0x02000030)) {
		db->cr6_data |= DMFE_TXTH_256;
		db->cr0_data = CR0_DEFAULT;
		db->dm910x_chk_mode = 4;	/* Enter the normal mode */
	} else {
		db->cr6_data |= CR6_SFT;	/* Store & Forward mode */
		db->cr0_data = 0;
		db->dm910x_chk_mode = 1;	/* Enter the check mode */
	}
	/* Initialize DM910X board */
	dmfe_init_dm910x(nic);

	return;
}

/*	Initialize DM910X board
 *	Reset DM910X board
 *	Initialize TX/Rx descriptor chain structure
 *	Send the set-up frame
 *	Enable Tx/Rx machine
 */

static void dmfe_init_dm910x(struct nic *nic)
{
	unsigned long ioaddr = BASE;

	/* Reset DM910x MAC controller */
	outl(DM910X_RESET, ioaddr + DCR0);	/* RESET MAC */
	udelay(100);
	outl(db->cr0_data, ioaddr + DCR0);
	udelay(5);

	/* Phy addr : DM910(A)2/DM9132/9801, phy address = 1 */
	db->phy_addr = 1;

	/* Parser SROM and media mode */
	dmfe_parse_srom(nic);
	db->media_mode = dmfe_media_mode;

	/* RESET Phyxcer Chip by GPR port bit 7 */
	outl(0x180, ioaddr + DCR12);	/* Let bit 7 output port */
	if (db->chip_id == PCI_DM9009_ID) {
		outl(0x80, ioaddr + DCR12);	/* Issue RESET signal */
		mdelay(300);	/* Delay 300 ms */
	}
	outl(0x0, ioaddr + DCR12);	/* Clear RESET signal */

	/* Process Phyxcer Media Mode */
	if (!(db->media_mode & 0x10))	/* Force 1M mode */
		dmfe_set_phyxcer(nic);

	/* Media Mode Process */
	if (!(db->media_mode & DMFE_AUTO))
		db->op_mode = db->media_mode;	/* Force Mode */

	/* Initiliaze Transmit/Receive descriptor and CR3/4 */
	dmfe_descriptor_init(nic, ioaddr);

	/* tx descriptor start pointer */
	outl(virt_to_le32desc(&txd[0]), ioaddr + DCR4);	/* TX DESC address */

	/* rx descriptor start pointer */
	outl(virt_to_le32desc(&rxd[0]), ioaddr + DCR3);	/* RX DESC address */

	/* Init CR6 to program DM910x operation */
	update_cr6(db->cr6_data, ioaddr);

	/* Send setup frame */
	if (db->chip_id == PCI_DM9132_ID) {
		dm9132_id_table(nic);	/* DM9132 */
	} else {
		send_filter_frame(nic);	/* DM9102/DM9102A */
	}

	/* Init CR7, interrupt active bit */
	db->cr7_data = CR7_DEFAULT;
	outl(db->cr7_data, ioaddr + DCR7);
	/* Init CR15, Tx jabber and Rx watchdog timer */
	outl(db->cr15_data, ioaddr + DCR15);
	/* Enable DM910X Tx/Rx function */
	db->cr6_data |= CR6_RXSC | CR6_TXSC | 0x40000;
	update_cr6(db->cr6_data, ioaddr);
}
#ifdef EDEBUG
void hex_dump(const char *data, const unsigned int len);
#endif
/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static int dmfe_poll(struct nic *nic, int retrieve)
{
	u32 rdes0;
	int entry = db->cur_rx % RX_DESC_CNT;
	int rxlen;
	rdes0 = le32_to_cpu(rxd[entry].rdes0);
	if (rdes0 & 0x80000000)
		return 0;

	if (!retrieve)
		return 1;

	if ((rdes0 & 0x300) != 0x300) {
		/* A packet without First/Last flag */
		printf("strange Packet\n");
		rxd[entry].rdes0 = cpu_to_le32(0x80000000);
		return 0;
	} else {
		/* A packet with First/Last flag */
		rxlen = ((rdes0 >> 16) & 0x3fff) - 4;
		/* error summary bit check */
		if (rdes0 & 0x8000) {
			printf("Error\n");
			return 0;
		}
		if (!(rdes0 & 0x8000) ||
		    ((db->cr6_data & CR6_PM) && (rxlen > 6))) {
			if (db->dm910x_chk_mode & 1)
				printf("Silly check mode\n");

			nic->packetlen = rxlen;
			memcpy(nic->packet, rxb + (entry * RX_ALLOC_SIZE),
			       nic->packetlen);
		}
	}
	rxd[entry].rdes0 = cpu_to_le32(0x80000000);
	db->cur_rx++;
	return 1;
}

static void dmfe_irq(struct nic *nic __unused, irq_action_t action __unused)
{
	switch ( action ) {
		case DISABLE :
			break;
		case ENABLE :
			break;
		case FORCE :
			break;
	}
}

/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static void dmfe_transmit(struct nic *nic, 
	const char *dest,	/* Destination */
	unsigned int type,	/* Type */
	unsigned int size,	/* size */
	const char *packet)	/* Packet */
{	
	u16 nstype;
	u8 *ptxb;

	ptxb = &txb[db->cur_tx];

	/* Stop Tx */
	outl(0, BASE + DCR7);
	memcpy(ptxb, dest, ETH_ALEN);
	memcpy(ptxb + ETH_ALEN, nic->node_addr, ETH_ALEN);
	nstype = htons((u16) type);
	memcpy(ptxb + 2 * ETH_ALEN, (u8 *) & nstype, 2);
	memcpy(ptxb + ETH_HLEN, packet, size);

	size += ETH_HLEN;
	while (size < ETH_ZLEN)
		ptxb[size++] = '\0';

	/* setup the transmit descriptor */
	txd[db->cur_tx].tdes1 = cpu_to_le32(0xe1000000 | size);
	txd[db->cur_tx].tdes0 = cpu_to_le32(0x80000000);	/* give ownership to device */

	/* immediate transmit demand */
	outl(0x1, BASE + DCR1);
	outl(db->cr7_data, BASE + DCR7);

	/* Point to next TX descriptor */
	db->cur_tx++;
	db->cur_tx = db->cur_tx % TX_DESC_CNT;
}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void dmfe_disable ( struct nic *nic __unused ) {
	/* Reset & stop DM910X board */
	outl(DM910X_RESET, BASE + DCR0);
	udelay(5);
	phy_write(BASE, db->phy_addr, 0, 0x8000, db->chip_id);

}

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
***************************************************************************/

#define board_found 1
#define valid_link 0
static int dmfe_probe ( struct nic *nic, struct pci_device *pci ) {

	uint32_t dev_rev, pci_pmr;
	int i;

	if (pci->ioaddr == 0)
		return 0;

	BASE = pci->ioaddr;
	printf("dmfe.c: Found %s Vendor=0x%hX Device=0x%hX\n",
	       pci->id->name, pci->vendor, pci->device);

	/* Read Chip revision */
	pci_read_config_dword(pci, PCI_REVISION, &dev_rev);
	dprintf(("Revision %lX\n", dev_rev));

	/* point to private storage */
	db = &dfx;

	db->chip_id = ((u32) pci->device << 16) | pci->vendor;
	BASE = pci_bar_start(pci, PCI_BASE_ADDRESS_0);
	db->chip_revision = dev_rev;

	pci_read_config_dword(pci, 0x50, &pci_pmr);
	pci_pmr &= 0x70000;
	if ((pci_pmr == 0x10000) && (dev_rev == 0x02000031))
		db->chip_type = 1;	/* DM9102A E3 */
	else
		db->chip_type = 0;

	dprintf(("Chip type : %d\n", db->chip_type));

	/* read 64 word srom data */
	for (i = 0; i < 64; i++)
		((u16 *) db->srom)[i] = cpu_to_le16(read_srom_word(BASE, i));

	/* Set Node address */
	for (i = 0; i < 6; i++)
		nic->node_addr[i] = db->srom[20 + i];

	/* Print out some hardware info */
	DBG ( "%s: %s at ioaddr %4.4lx\n",
	      pci->id->name, eth_ntoa ( nic->node_addr ), BASE );

	/* Set the card as PCI Bus Master */
	adjust_pci_device(pci);

	dmfe_reset(nic);

	nic->irqno  = 0;
	nic->ioaddr = pci->ioaddr;

	/* point to NIC specific routines */
	nic->nic_op	= &dmfe_operations;

	return 1;
}

/*
 *	Initialize transmit/Receive descriptor
 *	Using Chain structure, and allocate Tx/Rx buffer
 */

static void dmfe_descriptor_init(struct nic *nic __unused, unsigned long ioaddr)
{
	int i;
	db->cur_tx = 0;
	db->cur_rx = 0;

	/* tx descriptor start pointer */
	outl(virt_to_le32desc(&txd[0]), ioaddr + DCR4);	/* TX DESC address */

	/* rx descriptor start pointer */
	outl(virt_to_le32desc(&rxd[0]), ioaddr + DCR3);	/* RX DESC address */

	/* Init Transmit chain */
	for (i = 0; i < TX_DESC_CNT; i++) {
		txd[i].tx_buf_ptr = &txb[i];
		txd[i].tdes0 = cpu_to_le32(0);
		txd[i].tdes1 = cpu_to_le32(0x81000000);	/* IC, chain */
		txd[i].tdes2 = cpu_to_le32(virt_to_bus(&txb[i]));
		txd[i].tdes3 = cpu_to_le32(virt_to_bus(&txd[i + 1]));
		txd[i].next_tx_desc = &txd[i + 1];
	}
	/* Mark the last entry as wrapping the ring */
	txd[i - 1].tdes3 = virt_to_le32desc(&txd[0]);
	txd[i - 1].next_tx_desc = &txd[0];

	/* receive descriptor chain */
	for (i = 0; i < RX_DESC_CNT; i++) {
		rxd[i].rx_skb_ptr = &rxb[i * RX_ALLOC_SIZE];
		rxd[i].rdes0 = cpu_to_le32(0x80000000);
		rxd[i].rdes1 = cpu_to_le32(0x01000600);
		rxd[i].rdes2 =
		    cpu_to_le32(virt_to_bus(&rxb[i * RX_ALLOC_SIZE]));
		rxd[i].rdes3 = cpu_to_le32(virt_to_bus(&rxd[i + 1]));
		rxd[i].next_rx_desc = &rxd[i + 1];
	}
	/* Mark the last entry as wrapping the ring */
	rxd[i - 1].rdes3 = cpu_to_le32(virt_to_bus(&rxd[0]));
	rxd[i - 1].next_rx_desc = &rxd[0];

}

/*
 *	Update CR6 value
 *	Firstly stop DM910X , then written value and start
 */

static void update_cr6(u32 cr6_data, unsigned long ioaddr)
{
	u32 cr6_tmp;

	cr6_tmp = cr6_data & ~0x2002;	/* stop Tx/Rx */
	outl(cr6_tmp, ioaddr + DCR6);
	udelay(5);
	outl(cr6_data, ioaddr + DCR6);
	udelay(5);
}


/*
 *	Send a setup frame for DM9132
 *	This setup frame initialize DM910X address filter mode
*/

static void dm9132_id_table(struct nic *nic __unused)
{
#ifdef LINUX
	u16 *addrptr;
	u8 dmi_addr[8];
	unsigned long ioaddr = BASE + 0xc0;	/* ID Table */
	u32 hash_val;
	u16 i, hash_table[4];
#endif
	dprintf(("dm9132_id_table\n"));

	printf("FIXME: This function is broken.  If you have this card contact "
		"Timothy Legge at the etherboot-user list\n");

#ifdef LINUX
	//DMFE_DBUG(0, "dm9132_id_table()", 0);

	/* Node address */
	addrptr = (u16 *) nic->node_addr;
	outw(addrptr[0], ioaddr);
	ioaddr += 4;
	outw(addrptr[1], ioaddr);
	ioaddr += 4;
	outw(addrptr[2], ioaddr);
	ioaddr += 4;

	/* Clear Hash Table */
	for (i = 0; i < 4; i++)
		hash_table[i] = 0x0;

	/* broadcast address */
	hash_table[3] = 0x8000;

	/* the multicast address in Hash Table : 64 bits */
	for (mcptr = mc_list, i = 0; i < mc_cnt; i++, mcptr = mcptr->next) {
		hash_val = cal_CRC((char *) mcptr->dmi_addr, 6, 0) & 0x3f;
		hash_table[hash_val / 16] |= (u16) 1 << (hash_val % 16);
	}

	/* Write the hash table to MAC MD table */
	for (i = 0; i < 4; i++, ioaddr += 4)
		outw(hash_table[i], ioaddr);
#endif
}


/*
 *	Send a setup frame for DM9102/DM9102A
 *	This setup frame initialize DM910X address filter mode
 */

static void send_filter_frame(struct nic *nic)
{

	u8 *ptxb;
	int i;

	dprintf(("send_filter_frame\n"));
	/* point to the current txb incase multiple tx_rings are used */
	ptxb = &txb[db->cur_tx];

	/* construct perfect filter frame with mac address as first match
	   and broadcast address for all others */
	for (i = 0; i < 192; i++)
		ptxb[i] = 0xFF;
	ptxb[0] = nic->node_addr[0];
	ptxb[1] = nic->node_addr[1];
	ptxb[4] = nic->node_addr[2];
	ptxb[5] = nic->node_addr[3];
	ptxb[8] = nic->node_addr[4];
	ptxb[9] = nic->node_addr[5];

	/* prepare the setup frame */
	txd[db->cur_tx].tdes1 = cpu_to_le32(0x890000c0);
	txd[db->cur_tx].tdes0 = cpu_to_le32(0x80000000);
	update_cr6(db->cr6_data | 0x2000, BASE);
	outl(0x1, BASE + DCR1);	/* Issue Tx polling */
	update_cr6(db->cr6_data, BASE);
	db->cur_tx++;
}

/*
 *	Read one word data from the serial ROM
 */

static u16 read_srom_word(long ioaddr, int offset)
{
	int i;
	u16 srom_data = 0;
	long cr9_ioaddr = ioaddr + DCR9;

	outl(CR9_SROM_READ, cr9_ioaddr);
	outl(CR9_SROM_READ | CR9_SRCS, cr9_ioaddr);

	/* Send the Read Command 110b */
	SROM_CLK_WRITE(SROM_DATA_1, cr9_ioaddr);
	SROM_CLK_WRITE(SROM_DATA_1, cr9_ioaddr);
	SROM_CLK_WRITE(SROM_DATA_0, cr9_ioaddr);

	/* Send the offset */
	for (i = 5; i >= 0; i--) {
		srom_data =
		    (offset & (1 << i)) ? SROM_DATA_1 : SROM_DATA_0;
		SROM_CLK_WRITE(srom_data, cr9_ioaddr);
	}

	outl(CR9_SROM_READ | CR9_SRCS, cr9_ioaddr);

	for (i = 16; i > 0; i--) {
		outl(CR9_SROM_READ | CR9_SRCS | CR9_SRCLK, cr9_ioaddr);
		udelay(5);
		srom_data =
		    (srom_data << 1) | ((inl(cr9_ioaddr) & CR9_CRDOUT) ? 1
					: 0);
		outl(CR9_SROM_READ | CR9_SRCS, cr9_ioaddr);
		udelay(5);
	}

	outl(CR9_SROM_READ, cr9_ioaddr);
	return srom_data;
}


/*
 *	Auto sense the media mode
 */

#if 0 /* not used */
static u8 dmfe_sense_speed(struct nic *nic __unused)
{
	u8 ErrFlag = 0;
	u16 phy_mode;

	/* CR6 bit18=0, select 10/100M */
	update_cr6((db->cr6_data & ~0x40000), BASE);

	phy_mode = phy_read(BASE, db->phy_addr, 1, db->chip_id);
	phy_mode = phy_read(BASE, db->phy_addr, 1, db->chip_id);

	if ((phy_mode & 0x24) == 0x24) {
		if (db->chip_id == PCI_DM9132_ID)	/* DM9132 */
			phy_mode =
			    phy_read(BASE, db->phy_addr, 7,
				     db->chip_id) & 0xf000;
		else		/* DM9102/DM9102A */
			phy_mode =
			    phy_read(BASE, db->phy_addr, 17,
				     db->chip_id) & 0xf000;
		/* printk(DRV_NAME ": Phy_mode %x ",phy_mode); */
		switch (phy_mode) {
		case 0x1000:
			db->op_mode = DMFE_10MHF;
			break;
		case 0x2000:
			db->op_mode = DMFE_10MFD;
			break;
		case 0x4000:
			db->op_mode = DMFE_100MHF;
			break;
		case 0x8000:
			db->op_mode = DMFE_100MFD;
			break;
		default:
			db->op_mode = DMFE_10MHF;
			ErrFlag = 1;
			break;
		}
	} else {
		db->op_mode = DMFE_10MHF;
		//DMFE_DBUG(0, "Link Failed :", phy_mode);
		ErrFlag = 1;
	}

	return ErrFlag;
}
#endif

/*
 *	Set 10/100 phyxcer capability
 *	AUTO mode : phyxcer register4 is NIC capability
 *	Force mode: phyxcer register4 is the force media
 */

static void dmfe_set_phyxcer(struct nic *nic __unused)
{
	u16 phy_reg;

	/* Select 10/100M phyxcer */
	db->cr6_data &= ~0x40000;
	update_cr6(db->cr6_data, BASE);

	/* DM9009 Chip: Phyxcer reg18 bit12=0 */
	if (db->chip_id == PCI_DM9009_ID) {
		phy_reg =
		    phy_read(BASE, db->phy_addr, 18,
			     db->chip_id) & ~0x1000;
		phy_write(BASE, db->phy_addr, 18, phy_reg, db->chip_id);
	}

	/* Phyxcer capability setting */
	phy_reg = phy_read(BASE, db->phy_addr, 4, db->chip_id) & ~0x01e0;

	if (db->media_mode & DMFE_AUTO) {
		/* AUTO Mode */
		phy_reg |= db->PHY_reg4;
	} else {
		/* Force Mode */
		switch (db->media_mode) {
		case DMFE_10MHF:
			phy_reg |= 0x20;
			break;
		case DMFE_10MFD:
			phy_reg |= 0x40;
			break;
		case DMFE_100MHF:
			phy_reg |= 0x80;
			break;
		case DMFE_100MFD:
			phy_reg |= 0x100;
			break;
		}
		if (db->chip_id == PCI_DM9009_ID)
			phy_reg &= 0x61;
	}

	/* Write new capability to Phyxcer Reg4 */
	if (!(phy_reg & 0x01e0)) {
		phy_reg |= db->PHY_reg4;
		db->media_mode |= DMFE_AUTO;
	}
	phy_write(BASE, db->phy_addr, 4, phy_reg, db->chip_id);

	/* Restart Auto-Negotiation */
	if (db->chip_type && (db->chip_id == PCI_DM9102_ID))
		phy_write(BASE, db->phy_addr, 0, 0x1800, db->chip_id);
	if (!db->chip_type)
		phy_write(BASE, db->phy_addr, 0, 0x1200, db->chip_id);
}


/*
 *	Process op-mode
 *	AUTO mode : PHY controller in Auto-negotiation Mode
 *	Force mode: PHY controller in force mode with HUB
 *			N-way force capability with SWITCH
 */

#if 0 /* not used */
static void dmfe_process_mode(struct nic *nic __unused)
{
	u16 phy_reg;

	/* Full Duplex Mode Check */
	if (db->op_mode & 0x4)
		db->cr6_data |= CR6_FDM;	/* Set Full Duplex Bit */
	else
		db->cr6_data &= ~CR6_FDM;	/* Clear Full Duplex Bit */

	/* Transciver Selection */
	if (db->op_mode & 0x10)	/* 1M HomePNA */
		db->cr6_data |= 0x40000;	/* External MII select */
	else
		db->cr6_data &= ~0x40000;	/* Internal 10/100 transciver */

	update_cr6(db->cr6_data, BASE);

	/* 10/100M phyxcer force mode need */
	if (!(db->media_mode & 0x18)) {
		/* Forece Mode */
		phy_reg = phy_read(BASE, db->phy_addr, 6, db->chip_id);
		if (!(phy_reg & 0x1)) {
			/* parter without N-Way capability */
			phy_reg = 0x0;
			switch (db->op_mode) {
			case DMFE_10MHF:
				phy_reg = 0x0;
				break;
			case DMFE_10MFD:
				phy_reg = 0x100;
				break;
			case DMFE_100MHF:
				phy_reg = 0x2000;
				break;
			case DMFE_100MFD:
				phy_reg = 0x2100;
				break;
			}
			phy_write(BASE, db->phy_addr, 0, phy_reg,
				  db->chip_id);
			if (db->chip_type
			    && (db->chip_id == PCI_DM9102_ID))
				mdelay(20);
			phy_write(BASE, db->phy_addr, 0, phy_reg,
				  db->chip_id);
		}
	}
}
#endif

/*
 *	Write a word to Phy register
 */

static void phy_write(unsigned long iobase, u8 phy_addr, u8 offset,
		      u16 phy_data, u32 chip_id)
{
	u16 i;
	unsigned long ioaddr;

	if (chip_id == PCI_DM9132_ID) {
		ioaddr = iobase + 0x80 + offset * 4;
		outw(phy_data, ioaddr);
	} else {
		/* DM9102/DM9102A Chip */
		ioaddr = iobase + DCR9;

		/* Send 33 synchronization clock to Phy controller */
		for (i = 0; i < 35; i++)
			phy_write_1bit(ioaddr, PHY_DATA_1);

		/* Send start command(01) to Phy */
		phy_write_1bit(ioaddr, PHY_DATA_0);
		phy_write_1bit(ioaddr, PHY_DATA_1);

		/* Send write command(01) to Phy */
		phy_write_1bit(ioaddr, PHY_DATA_0);
		phy_write_1bit(ioaddr, PHY_DATA_1);

		/* Send Phy address */
		for (i = 0x10; i > 0; i = i >> 1)
			phy_write_1bit(ioaddr,
				       phy_addr & i ? PHY_DATA_1 :
				       PHY_DATA_0);

		/* Send register address */
		for (i = 0x10; i > 0; i = i >> 1)
			phy_write_1bit(ioaddr,
				       offset & i ? PHY_DATA_1 :
				       PHY_DATA_0);

		/* written trasnition */
		phy_write_1bit(ioaddr, PHY_DATA_1);
		phy_write_1bit(ioaddr, PHY_DATA_0);

		/* Write a word data to PHY controller */
		for (i = 0x8000; i > 0; i >>= 1)
			phy_write_1bit(ioaddr,
				       phy_data & i ? PHY_DATA_1 :
				       PHY_DATA_0);
	}
}


/*
 *	Read a word data from phy register
 */

static u16 phy_read(unsigned long iobase, u8 phy_addr, u8 offset,
		    u32 chip_id)
{
	int i;
	u16 phy_data;
	unsigned long ioaddr;

	if (chip_id == PCI_DM9132_ID) {
		/* DM9132 Chip */
		ioaddr = iobase + 0x80 + offset * 4;
		phy_data = inw(ioaddr);
	} else {
		/* DM9102/DM9102A Chip */
		ioaddr = iobase + DCR9;

		/* Send 33 synchronization clock to Phy controller */
		for (i = 0; i < 35; i++)
			phy_write_1bit(ioaddr, PHY_DATA_1);

		/* Send start command(01) to Phy */
		phy_write_1bit(ioaddr, PHY_DATA_0);
		phy_write_1bit(ioaddr, PHY_DATA_1);

		/* Send read command(10) to Phy */
		phy_write_1bit(ioaddr, PHY_DATA_1);
		phy_write_1bit(ioaddr, PHY_DATA_0);

		/* Send Phy address */
		for (i = 0x10; i > 0; i = i >> 1)
			phy_write_1bit(ioaddr,
				       phy_addr & i ? PHY_DATA_1 :
				       PHY_DATA_0);

		/* Send register address */
		for (i = 0x10; i > 0; i = i >> 1)
			phy_write_1bit(ioaddr,
				       offset & i ? PHY_DATA_1 :
				       PHY_DATA_0);

		/* Skip transition state */
		phy_read_1bit(ioaddr);

		/* read 16bit data */
		for (phy_data = 0, i = 0; i < 16; i++) {
			phy_data <<= 1;
			phy_data |= phy_read_1bit(ioaddr);
		}
	}

	return phy_data;
}


/*
 *	Write one bit data to Phy Controller
 */

static void phy_write_1bit(unsigned long ioaddr, u32 phy_data)
{
	outl(phy_data, ioaddr);	/* MII Clock Low */
	udelay(1);
	outl(phy_data | MDCLKH, ioaddr);	/* MII Clock High */
	udelay(1);
	outl(phy_data, ioaddr);	/* MII Clock Low */
	udelay(1);
}


/*
 *	Read one bit phy data from PHY controller
 */

static u16 phy_read_1bit(unsigned long ioaddr)
{
	u16 phy_data;

	outl(0x50000, ioaddr);
	udelay(1);
	phy_data = (inl(ioaddr) >> 19) & 0x1;
	outl(0x40000, ioaddr);
	udelay(1);

	return phy_data;
}


/*
 *	Parser SROM and media mode
 */

static void dmfe_parse_srom(struct nic *nic)
{
	unsigned char *srom = db->srom;
	int dmfe_mode, tmp_reg;

	/* Init CR15 */
	db->cr15_data = CR15_DEFAULT;

	/* Check SROM Version */
	if (((int) srom[18] & 0xff) == SROM_V41_CODE) {
		/* SROM V4.01 */
		/* Get NIC support media mode */
		db->NIC_capability = *(u16 *) (srom + 34);
		db->PHY_reg4 = 0;
		for (tmp_reg = 1; tmp_reg < 0x10; tmp_reg <<= 1) {
			switch (db->NIC_capability & tmp_reg) {
			case 0x1:
				db->PHY_reg4 |= 0x0020;
				break;
			case 0x2:
				db->PHY_reg4 |= 0x0040;
				break;
			case 0x4:
				db->PHY_reg4 |= 0x0080;
				break;
			case 0x8:
				db->PHY_reg4 |= 0x0100;
				break;
			}
		}

		/* Media Mode Force or not check */
		dmfe_mode = *((int *) srom + 34) & *((int *) srom + 36);
		switch (dmfe_mode) {
		case 0x4:
			dmfe_media_mode = DMFE_100MHF;
			break;	/* 100MHF */
		case 0x2:
			dmfe_media_mode = DMFE_10MFD;
			break;	/* 10MFD */
		case 0x8:
			dmfe_media_mode = DMFE_100MFD;
			break;	/* 100MFD */
		case 0x100:
		case 0x200:
			dmfe_media_mode = DMFE_1M_HPNA;
			break;	/* HomePNA */
		}

		/* Special Function setting */
		/* VLAN function */
		if ((SF_mode & 0x1) || (srom[43] & 0x80))
			db->cr15_data |= 0x40;

		/* Flow Control */
		if ((SF_mode & 0x2) || (srom[40] & 0x1))
			db->cr15_data |= 0x400;

		/* TX pause packet */
		if ((SF_mode & 0x4) || (srom[40] & 0xe))
			db->cr15_data |= 0x9800;
	}

	/* Parse HPNA parameter */
	db->HPNA_command = 1;

	/* Accept remote command or not */
	if (HPNA_rx_cmd == 0)
		db->HPNA_command |= 0x8000;

	/* Issue remote command & operation mode */
	if (HPNA_tx_cmd == 1)
		switch (HPNA_mode) {	/* Issue Remote Command */
		case 0:
			db->HPNA_command |= 0x0904;
			break;
		case 1:
			db->HPNA_command |= 0x0a00;
			break;
		case 2:
			db->HPNA_command |= 0x0506;
			break;
		case 3:
			db->HPNA_command |= 0x0602;
			break;
	} else
		switch (HPNA_mode) {	/* Don't Issue */
		case 0:
			db->HPNA_command |= 0x0004;
			break;
		case 1:
			db->HPNA_command |= 0x0000;
			break;
		case 2:
			db->HPNA_command |= 0x0006;
			break;
		case 3:
			db->HPNA_command |= 0x0002;
			break;
		}

	/* Check DM9801 or DM9802 present or not */
	db->HPNA_present = 0;
	update_cr6(db->cr6_data | 0x40000, BASE);
	tmp_reg = phy_read(BASE, db->phy_addr, 3, db->chip_id);
	if ((tmp_reg & 0xfff0) == 0xb900) {
		/* DM9801 or DM9802 present */
		db->HPNA_timer = 8;
		if (phy_read(BASE, db->phy_addr, 31, db->chip_id) ==
		    0x4404) {
			/* DM9801 HomeRun */
			db->HPNA_present = 1;
			dmfe_program_DM9801(nic, tmp_reg);
		} else {
			/* DM9802 LongRun */
			db->HPNA_present = 2;
			dmfe_program_DM9802(nic);
		}
	}

}

/*
 *	Init HomeRun DM9801
 */

static void dmfe_program_DM9801(struct nic *nic __unused, int HPNA_rev)
{
	u32 reg17, reg25;

	if (!HPNA_NoiseFloor)
		HPNA_NoiseFloor = DM9801_NOISE_FLOOR;
	switch (HPNA_rev) {
	case 0xb900:		/* DM9801 E3 */
		db->HPNA_command |= 0x1000;
		reg25 = phy_read(BASE, db->phy_addr, 24, db->chip_id);
		reg25 = ((reg25 + HPNA_NoiseFloor) & 0xff) | 0xf000;
		reg17 = phy_read(BASE, db->phy_addr, 17, db->chip_id);
		break;
	case 0xb901:		/* DM9801 E4 */
		reg25 = phy_read(BASE, db->phy_addr, 25, db->chip_id);
		reg25 = (reg25 & 0xff00) + HPNA_NoiseFloor;
		reg17 = phy_read(BASE, db->phy_addr, 17, db->chip_id);
		reg17 = (reg17 & 0xfff0) + HPNA_NoiseFloor + 3;
		break;
	case 0xb902:		/* DM9801 E5 */
	case 0xb903:		/* DM9801 E6 */
	default:
		db->HPNA_command |= 0x1000;
		reg25 = phy_read(BASE, db->phy_addr, 25, db->chip_id);
		reg25 = (reg25 & 0xff00) + HPNA_NoiseFloor - 5;
		reg17 = phy_read(BASE, db->phy_addr, 17, db->chip_id);
		reg17 = (reg17 & 0xfff0) + HPNA_NoiseFloor;
		break;
	}
	phy_write(BASE, db->phy_addr, 16, db->HPNA_command, db->chip_id);
	phy_write(BASE, db->phy_addr, 17, reg17, db->chip_id);
	phy_write(BASE, db->phy_addr, 25, reg25, db->chip_id);
}


/*
 *	Init HomeRun DM9802
 */

static void dmfe_program_DM9802(struct nic *nic __unused)
{
	u32 phy_reg;

	if (!HPNA_NoiseFloor)
		HPNA_NoiseFloor = DM9802_NOISE_FLOOR;
	phy_write(BASE, db->phy_addr, 16, db->HPNA_command, db->chip_id);
	phy_reg = phy_read(BASE, db->phy_addr, 25, db->chip_id);
	phy_reg = (phy_reg & 0xff00) + HPNA_NoiseFloor;
	phy_write(BASE, db->phy_addr, 25, phy_reg, db->chip_id);
}

static struct nic_operations dmfe_operations = {
	.connect	= dummy_connect,
	.poll		= dmfe_poll,
	.transmit	= dmfe_transmit,
	.irq		= dmfe_irq,

};

static struct pci_device_id dmfe_nics[] = {
	PCI_ROM(0x1282, 0x9100, "dmfe9100", "Davicom 9100", 0),
	PCI_ROM(0x1282, 0x9102, "dmfe9102", "Davicom 9102", 0),
	PCI_ROM(0x1282, 0x9009, "dmfe9009", "Davicom 9009", 0),
	PCI_ROM(0x1282, 0x9132, "dmfe9132", "Davicom 9132", 0),	/* Needs probably some fixing */
};

PCI_DRIVER ( dmfe_driver, dmfe_nics, PCI_NO_CLASS );

DRIVER ( "DMFE/PCI", nic_driver, pci_driver, dmfe_driver,
	 dmfe_probe, dmfe_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
