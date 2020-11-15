/**************************************************************************
*
*    tlan.c -- Etherboot device driver for the Texas Instruments ThunderLAN
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
*	lan.c: Linux ThunderLan Driver:
*
*	by James Banks
*
*  	(C) 1997-1998 Caldera, Inc.
*	(C) 1998 James Banks
*	(C) 1999-2001 Torben Mathiasen
*	(C) 2002 Samuel Chessman
*
*    REVISION HISTORY:
*    ================
*    v1.0	07-08-2003	timlegge	Initial not quite working version
*    v1.1	07-27-2003	timlegge	Sync 5.0 and 5.1 versions
*    v1.2	08-19-2003	timlegge	Implement Multicast Support
*    v1.3	08-23-2003	timlegge	Fix the transmit Function
*    v1.4	01-17-2004	timlegge	Initial driver output cleanup    
*    
*    Indent Options: indent -kr -i8
***************************************************************************/

FILE_LICENCE ( GPL2_OR_LATER );

#include "etherboot.h"
#include "nic.h"
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>
#include <mii.h>
#include "tlan.h"

#define drv_version "v1.4"
#define drv_date "01-17-2004"

/* NIC specific static variables go here */
#define HZ 100
#define TX_TIME_OUT	  (6*HZ)

/* Condensed operations for readability. */
#define virt_to_le32desc(addr)  cpu_to_le32(virt_to_bus(addr))
#define le32desc_to_virt(addr)  bus_to_virt(le32_to_cpu(addr))

static void TLan_ResetLists(struct nic *nic __unused);
static void TLan_ResetAdapter(struct nic *nic __unused);
static void TLan_FinishReset(struct nic *nic __unused);

static void TLan_EeSendStart(u16);
static int TLan_EeSendByte(u16, u8, int);
static void TLan_EeReceiveByte(u16, u8 *, int);
static int TLan_EeReadByte(u16 io_base, u8, u8 *);

static void TLan_PhyDetect(struct nic *nic);
static void TLan_PhyPowerDown(struct nic *nic);
static void TLan_PhyPowerUp(struct nic *nic);


static void TLan_SetMac(struct nic *nic __unused, int areg, unsigned char *mac);

static void TLan_PhyReset(struct nic *nic);
static void TLan_PhyStartLink(struct nic *nic);
static void TLan_PhyFinishAutoNeg(struct nic *nic);

#ifdef MONITOR
static void TLan_PhyMonitor(struct nic *nic);
#endif


static void refill_rx(struct nic *nic __unused);

static int TLan_MiiReadReg(struct nic *nic __unused, u16, u16, u16 *);
static void TLan_MiiSendData(u16, u32, unsigned);
static void TLan_MiiSync(u16);
static void TLan_MiiWriteReg(struct nic *nic __unused, u16, u16, u16);


static const char *media[] = {
	"10BaseT-HD ", "10BaseT-FD ", "100baseTx-HD ",
	"100baseTx-FD", "100baseT4", NULL
};

/* This much match tlan_pci_tbl[]!  */
enum tlan_nics {
	NETEL10 = 0, NETEL100 = 1, NETFLEX3I = 2, THUNDER = 3, NETFLEX3B =
	    4, NETEL100PI = 5,
	NETEL100D = 6, NETEL100I = 7, OC2183 = 8, OC2325 = 9, OC2326 =
	    10, NETELLIGENT_10_100_WS_5100 = 11,
	NETELLIGENT_10_T2 = 12
};

struct pci_id_info {
	const char *name;
	int nic_id;
	struct match_info {
		u32 pci, pci_mask, subsystem, subsystem_mask;
		u32 revision, revision_mask;	/* Only 8 bits. */
	} id;
	u32 flags;
	u16 addrOfs;		/* Address Offset */
};

static const struct pci_id_info tlan_pci_tbl[] = {
	{"Compaq Netelligent 10 T PCI UTP", NETEL10,
	 {0xae340e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_ACTIVITY_LED, 0x83},
	{"Compaq Netelligent 10/100 TX PCI UTP", NETEL100,
	 {0xae320e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_ACTIVITY_LED, 0x83},
	{"Compaq Integrated NetFlex-3/P", NETFLEX3I,
	 {0xae350e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_NONE, 0x83},
	{"Compaq NetFlex-3/P", THUNDER,
	 {0xf1300e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_UNMANAGED_PHY | TLAN_ADAPTER_BIT_RATE_PHY, 0x83},
	{"Compaq NetFlex-3/P", NETFLEX3B,
	 {0xf1500e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_NONE, 0x83},
	{"Compaq Netelligent Integrated 10/100 TX UTP", NETEL100PI,
	 {0xae430e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_ACTIVITY_LED, 0x83},
	{"Compaq Netelligent Dual 10/100 TX PCI UTP", NETEL100D,
	 {0xae400e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_NONE, 0x83},
	{"Compaq Netelligent 10/100 TX Embedded UTP", NETEL100I,
	 {0xb0110e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_NONE, 0x83},
	{"Olicom OC-2183/2185", OC2183,
	 {0x0013108d, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_USE_INTERN_10, 0x83},
	{"Olicom OC-2325", OC2325,
	 {0x0012108d, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_UNMANAGED_PHY, 0xF8},
	{"Olicom OC-2326", OC2326,
	 {0x0014108d, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_USE_INTERN_10, 0xF8},
	{"Compaq Netelligent 10/100 TX UTP", NETELLIGENT_10_100_WS_5100,
	 {0xb0300e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_ACTIVITY_LED, 0x83},
	{"Compaq Netelligent 10 T/2 PCI UTP/Coax", NETELLIGENT_10_T2,
	 {0xb0120e11, 0xffffffff, 0, 0, 0, 0},
	 TLAN_ADAPTER_NONE, 0x83},
	{"Compaq NetFlex-3/E", 0,	/* EISA card */
	 {0, 0, 0, 0, 0, 0},
	 TLAN_ADAPTER_ACTIVITY_LED | TLAN_ADAPTER_UNMANAGED_PHY |
	 TLAN_ADAPTER_BIT_RATE_PHY, 0x83},
	{"Compaq NetFlex-3/E", 0,	/* EISA card */
	 {0, 0, 0, 0, 0, 0},
	 TLAN_ADAPTER_ACTIVITY_LED, 0x83},
	{NULL, 0,
	 {0, 0, 0, 0, 0, 0},
	 0, 0},
};

struct TLanList {
	u32 forward;
	u16 cStat;
	u16 frameSize;
	struct {
		u32 count;
		u32 address;
	} buffer[TLAN_BUFFERS_PER_LIST];
};

struct {
	struct TLanList tx_ring[TLAN_NUM_TX_LISTS];
	unsigned char txb[TLAN_MAX_FRAME_SIZE * TLAN_NUM_TX_LISTS];
	struct TLanList rx_ring[TLAN_NUM_RX_LISTS];
	unsigned char rxb[TLAN_MAX_FRAME_SIZE * TLAN_NUM_RX_LISTS];
} tlan_buffers __shared;
#define tx_ring tlan_buffers.tx_ring
#define txb tlan_buffers.txb
#define rx_ring tlan_buffers.rx_ring
#define rxb tlan_buffers.rxb

typedef u8 TLanBuffer[TLAN_MAX_FRAME_SIZE];

static int chip_idx;

/*****************************************************************
* TLAN Private Information Structure
*
****************************************************************/
static struct tlan_private {
	unsigned short vendor_id;	/* PCI Vendor code */
	unsigned short dev_id;	/* PCI Device code */
	const char *nic_name;
	unsigned int cur_rx, dirty_rx;	/* Producer/consumer ring indices */
	unsigned rx_buf_sz;	/* Based on mtu + Slack */
	struct TLanList *txList;
	u32 txHead;
	u32 txInProgress;
	u32 txTail;
	int eoc;
	u32 phyOnline;
	u32 aui;
	u32 duplex;
	u32 phy[2];
	u32 phyNum;
	u32 speed;
	u8 tlanRev;
	u8 tlanFullDuplex;
	u8 link;
	u8 neg_be_verbose;
} TLanPrivateInfo;

static struct tlan_private *priv;

static u32 BASE;

/***************************************************************
*	TLan_ResetLists
*
*	Returns:
*		Nothing
*	Parms:
*		dev	The device structure with the list
*			stuctures to be reset.
*
*	This routine sets the variables associated with managing
*	the TLAN lists to their initial values.
*
**************************************************************/

static void TLan_ResetLists(struct nic *nic __unused)
{

	int i;
	struct TLanList *list;
	priv->txHead = 0;
	priv->txTail = 0;

	for (i = 0; i < TLAN_NUM_TX_LISTS; i++) {
		list = &tx_ring[i];
		list->cStat = TLAN_CSTAT_UNUSED;
		list->buffer[0].address = virt_to_bus(txb + 
				(i * TLAN_MAX_FRAME_SIZE)); 
		list->buffer[2].count = 0;
		list->buffer[2].address = 0;
		list->buffer[9].address = 0;
	}

	priv->cur_rx = 0;
	priv->rx_buf_sz = (TLAN_MAX_FRAME_SIZE);
//	priv->rx_head_desc = &rx_ring[0];

	/* Initialize all the Rx descriptors */
	for (i = 0; i < TLAN_NUM_RX_LISTS; i++) {
		rx_ring[i].forward = virt_to_le32desc(&rx_ring[i + 1]);
		rx_ring[i].cStat = TLAN_CSTAT_READY;
		rx_ring[i].frameSize = TLAN_MAX_FRAME_SIZE;
		rx_ring[i].buffer[0].count =
		    TLAN_MAX_FRAME_SIZE | TLAN_LAST_BUFFER;
		rx_ring[i].buffer[0].address =
		    virt_to_le32desc(&rxb[i * TLAN_MAX_FRAME_SIZE]);
		rx_ring[i].buffer[1].count = 0;
		rx_ring[i].buffer[1].address = 0;
	}

	/* Mark the last entry as wrapping the ring */
	rx_ring[i - 1].forward = virt_to_le32desc(&rx_ring[0]);
	priv->dirty_rx = (unsigned int) (i - TLAN_NUM_RX_LISTS);

} /* TLan_ResetLists */

/***************************************************************
*	TLan_Reset
*
*	Returns:
*		0
*	Parms:
*		dev	Pointer to device structure of adapter
*			to be reset.
*
*	This function resets the adapter and it's physical
*	device.  See Chap. 3, pp. 9-10 of the "ThunderLAN
*	Programmer's Guide" for details.  The routine tries to
*	implement what is detailed there, though adjustments
*	have been made.
*
**************************************************************/

void TLan_ResetAdapter(struct nic *nic __unused)
{
	int i;
	u32 addr;
	u32 data;
	u8 data8;

	priv->tlanFullDuplex = FALSE;
	priv->phyOnline = 0;
/*  1.	Assert reset bit. */

	data = inl(BASE + TLAN_HOST_CMD);
	data |= TLAN_HC_AD_RST;
	outl(data, BASE + TLAN_HOST_CMD);

	udelay(1000);

/*  2.	Turn off interrupts. ( Probably isn't necessary ) */

	data = inl(BASE + TLAN_HOST_CMD);
	data |= TLAN_HC_INT_OFF;
	outl(data, BASE + TLAN_HOST_CMD);
/*  3.	Clear AREGs and HASHs. */

	for (i = TLAN_AREG_0; i <= TLAN_HASH_2; i += 4) {
		TLan_DioWrite32(BASE, (u16) i, 0);
	}

/*  4.	Setup NetConfig register. */

	data =
	    TLAN_NET_CFG_1FRAG | TLAN_NET_CFG_1CHAN | TLAN_NET_CFG_PHY_EN;
	TLan_DioWrite16(BASE, TLAN_NET_CONFIG, (u16) data);

/*  5.	Load Ld_Tmr and Ld_Thr in HOST_CMD. */

	outl(TLAN_HC_LD_TMR | 0x3f, BASE + TLAN_HOST_CMD);
	outl(TLAN_HC_LD_THR | 0x0, BASE + TLAN_HOST_CMD);

/*  6.	Unreset the MII by setting NMRST (in NetSio) to 1. */

	outw(TLAN_NET_SIO, BASE + TLAN_DIO_ADR);
	addr = BASE + TLAN_DIO_DATA + TLAN_NET_SIO;
	TLan_SetBit(TLAN_NET_SIO_NMRST, addr);

/*  7.	Setup the remaining registers. */

	if (priv->tlanRev >= 0x30) {
		data8 = TLAN_ID_TX_EOC | TLAN_ID_RX_EOC;
		TLan_DioWrite8(BASE, TLAN_INT_DIS, data8);
	}
	TLan_PhyDetect(nic);
	data = TLAN_NET_CFG_1FRAG | TLAN_NET_CFG_1CHAN;

	if (tlan_pci_tbl[chip_idx].flags & TLAN_ADAPTER_BIT_RATE_PHY) {
		data |= TLAN_NET_CFG_BIT;
		if (priv->aui == 1) {
			TLan_DioWrite8(BASE, TLAN_ACOMMIT, 0x0a);
		} else if (priv->duplex == TLAN_DUPLEX_FULL) {
			TLan_DioWrite8(BASE, TLAN_ACOMMIT, 0x00);
			priv->tlanFullDuplex = TRUE;
		} else {
			TLan_DioWrite8(BASE, TLAN_ACOMMIT, 0x08);
		}
	}

	if (priv->phyNum == 0) {
		data |= TLAN_NET_CFG_PHY_EN;
	}
	TLan_DioWrite16(BASE, TLAN_NET_CONFIG, (u16) data);

	if (tlan_pci_tbl[chip_idx].flags & TLAN_ADAPTER_UNMANAGED_PHY) {
		TLan_FinishReset(nic);
	} else {
		TLan_PhyPowerDown(nic);
	}

}	/* TLan_ResetAdapter */

void TLan_FinishReset(struct nic *nic)
{

	u8 data;
	u32 phy;
	u8 sio;
	u16 status;
	u16 partner;
	u16 tlphy_ctl;
	u16 tlphy_par;
	u16 tlphy_id1, tlphy_id2;
	int i;

	phy = priv->phy[priv->phyNum];

	data = TLAN_NET_CMD_NRESET | TLAN_NET_CMD_NWRAP;
	if (priv->tlanFullDuplex) {
		data |= TLAN_NET_CMD_DUPLEX;
	}
	TLan_DioWrite8(BASE, TLAN_NET_CMD, data);
	data = TLAN_NET_MASK_MASK4 | TLAN_NET_MASK_MASK5;
	if (priv->phyNum == 0) {
		data |= TLAN_NET_MASK_MASK7;
	}
	TLan_DioWrite8(BASE, TLAN_NET_MASK, data);
	TLan_DioWrite16(BASE, TLAN_MAX_RX, ((1536) + 7) & ~7);
	TLan_MiiReadReg(nic, phy, MII_PHYSID1, &tlphy_id1);
	TLan_MiiReadReg(nic, phy, MII_PHYSID2, &tlphy_id2);

	if ((tlan_pci_tbl[chip_idx].flags & TLAN_ADAPTER_UNMANAGED_PHY)
	    || (priv->aui)) {
		status = BMSR_LSTATUS;
		DBG ( "TLAN:  %s: Link forced.\n", priv->nic_name );
	} else {
		TLan_MiiReadReg(nic, phy, MII_BMSR, &status);
		udelay(1000);
		TLan_MiiReadReg(nic, phy, MII_BMSR, &status);
		if ((status & BMSR_LSTATUS) &&	/* We only support link info on Nat.Sem. PHY's */
		    (tlphy_id1 == NAT_SEM_ID1)
		    && (tlphy_id2 == NAT_SEM_ID2)) {
			TLan_MiiReadReg(nic, phy, MII_LPA, &partner);
			TLan_MiiReadReg(nic, phy, TLAN_TLPHY_PAR,
					&tlphy_par);

			DBG ( "TLAN: %s: Link active with ",
			       priv->nic_name );
			if (!(tlphy_par & TLAN_PHY_AN_EN_STAT)) {
				DBG ( "forced 10%sMbps %s-Duplex\n",
				       tlphy_par & TLAN_PHY_SPEED_100 ? ""
				       : "0",
				       tlphy_par & TLAN_PHY_DUPLEX_FULL ?
				       "Full" : "Half" );
			} else {
				DBG 
				    ( "AutoNegotiation enabled, at 10%sMbps %s-Duplex\n",
				     tlphy_par & TLAN_PHY_SPEED_100 ? "" :
				     "0",
				     tlphy_par & TLAN_PHY_DUPLEX_FULL ?
				     "Full" : "Half" );
				DBG ( "TLAN: Partner capability: " );
				for (i = 5; i <= 10; i++)
					if (partner & (1 << i)) {
						DBG ( "%s", media[i - 5] );
					}
				DBG ( "\n" );
			}

			TLan_DioWrite8(BASE, TLAN_LED_REG, TLAN_LED_LINK);
#ifdef MONITOR
			/* We have link beat..for now anyway */
			priv->link = 1;
			/*Enabling link beat monitoring */
			/* TLan_SetTimer( nic, (10*HZ), TLAN_TIMER_LINK_BEAT ); */
			mdelay(10000);
			TLan_PhyMonitor(nic);
#endif
		} else if (status & BMSR_LSTATUS) {
			DBG ( "TLAN: %s: Link active\n", priv->nic_name );
			TLan_DioWrite8(BASE, TLAN_LED_REG, TLAN_LED_LINK);
		}
	}

	if (priv->phyNum == 0) {
		TLan_MiiReadReg(nic, phy, TLAN_TLPHY_CTL, &tlphy_ctl);
		tlphy_ctl |= TLAN_TC_INTEN;
		TLan_MiiWriteReg(nic, phy, TLAN_TLPHY_CTL, tlphy_ctl);
		sio = TLan_DioRead8(BASE, TLAN_NET_SIO);
		sio |= TLAN_NET_SIO_MINTEN;
		TLan_DioWrite8(BASE, TLAN_NET_SIO, sio);
	}

	if (status & BMSR_LSTATUS) {
		TLan_SetMac(nic, 0, nic->node_addr);
		priv->phyOnline = 1;
		outb((TLAN_HC_INT_ON >> 8), BASE + TLAN_HOST_CMD + 1);
		outl(virt_to_bus(&rx_ring), BASE + TLAN_CH_PARM);
		outl(TLAN_HC_GO | TLAN_HC_RT, BASE + TLAN_HOST_CMD);
	} else {
		DBG 
		    ( "TLAN: %s: Link inactive, will retry in 10 secs...\n",
		     priv->nic_name );
		/* TLan_SetTimer( nic, (10*HZ), TLAN_TIMER_FINISH_RESET ); */
		mdelay(10000);
		TLan_FinishReset(nic);
		return;

	}

}	/* TLan_FinishReset */

/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static int tlan_poll(struct nic *nic, int retrieve)
{
	/* return true if there's an ethernet packet ready to read */
	/* nic->packet should contain data on return */
	/* nic->packetlen should contain length of data */
	u32 framesize;
	u32 host_cmd = 0;
	u32 ack = 1;
	int eoc = 0;
	int entry = priv->cur_rx % TLAN_NUM_RX_LISTS;
	u16 tmpCStat = le32_to_cpu(rx_ring[entry].cStat);
	u16 host_int = inw(BASE + TLAN_HOST_INT);

	if ((tmpCStat & TLAN_CSTAT_FRM_CMP) && !retrieve)
	  return 1;

	outw(host_int, BASE + TLAN_HOST_INT);

	if (!(tmpCStat & TLAN_CSTAT_FRM_CMP))
		return 0;

	/* printf("PI-1: 0x%hX\n", host_int); */
	if (tmpCStat & TLAN_CSTAT_EOC)
		eoc = 1;

	framesize = rx_ring[entry].frameSize;

	nic->packetlen = framesize;

	DBG ( ".%d.", (unsigned int) framesize ); 
     
	memcpy(nic->packet, rxb +
	       (priv->cur_rx * TLAN_MAX_FRAME_SIZE), nic->packetlen);

	rx_ring[entry].cStat = 0;

	DBG ( "%d", entry );  

	entry = (entry + 1) % TLAN_NUM_RX_LISTS;
	priv->cur_rx = entry;
	if (eoc) {
		if ((rx_ring[entry].cStat & TLAN_CSTAT_READY) ==
		    TLAN_CSTAT_READY) {
			ack |= TLAN_HC_GO | TLAN_HC_RT;
			host_cmd = TLAN_HC_ACK | ack | 0x001C0000;
			outl(host_cmd, BASE + TLAN_HOST_CMD);
		}
	} else {
		host_cmd = TLAN_HC_ACK | ack | (0x000C0000);
		outl(host_cmd, BASE + TLAN_HOST_CMD);
		
		DBG ( "AC: 0x%hX\n", inw(BASE + TLAN_CH_PARM) ); 
		DBG ( "PI-2: 0x%hX\n", inw(BASE + TLAN_HOST_INT) );
	}
	refill_rx(nic);
	return (1);		/* initially as this is called to flush the input */
}

static void refill_rx(struct nic *nic __unused)
{
	int entry = 0;

	for (;
	     (priv->cur_rx - priv->dirty_rx +
	      TLAN_NUM_RX_LISTS) % TLAN_NUM_RX_LISTS > 0;
	     priv->dirty_rx = (priv->dirty_rx + 1) % TLAN_NUM_RX_LISTS) {
		entry = priv->dirty_rx % TLAN_NUM_TX_LISTS;
		rx_ring[entry].frameSize = TLAN_MAX_FRAME_SIZE;
		rx_ring[entry].cStat = TLAN_CSTAT_READY;
	}

}

/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static void tlan_transmit(struct nic *nic, const char *d,	/* Destination */
			  unsigned int t,	/* Type */
			  unsigned int s,	/* size */
			  const char *p)
{				/* Packet */
	u16 nstype;
	u32 to;
	struct TLanList *tail_list;
	struct TLanList *head_list;
	u8 *tail_buffer;
	u32 ack = 0;
	u32 host_cmd;
	int eoc = 0;
	u16 tmpCStat;
	u16 host_int = inw(BASE + TLAN_HOST_INT);

	int entry = 0;

	DBG ( "INT0-0x%hX\n", host_int );

	if (!priv->phyOnline) {
		printf("TRANSMIT:  %s PHY is not ready\n", priv->nic_name);
		return;
	}

	tail_list = priv->txList + priv->txTail;

	if (tail_list->cStat != TLAN_CSTAT_UNUSED) {
		printf("TRANSMIT: %s is busy (Head=%p Tail=%x)\n",
		       priv->nic_name, priv->txList, (unsigned int) priv->txTail);
		tx_ring[entry].cStat = TLAN_CSTAT_UNUSED;
//		priv->txBusyCount++;
		return;
	}

	tail_list->forward = 0;

	tail_buffer = txb + (priv->txTail * TLAN_MAX_FRAME_SIZE);

	/* send the packet to destination */
	memcpy(tail_buffer, d, ETH_ALEN);
	memcpy(tail_buffer + ETH_ALEN, nic->node_addr, ETH_ALEN);
	nstype = htons((u16) t);
	memcpy(tail_buffer + 2 * ETH_ALEN, (u8 *) & nstype, 2);
	memcpy(tail_buffer + ETH_HLEN, p, s);

	s += ETH_HLEN;
	s &= 0x0FFF;
	while (s < ETH_ZLEN)
		tail_buffer[s++] = '\0';

	/*=====================================================*/
	/* Receive
	 * 0000 0000 0001 1100
	 * 0000 0000 0000 1100
	 * 0000 0000 0000 0011 = 0x0003
	 *
	 * 0000 0000 0000 0000 0000 0000 0000 0011
	 * 0000 0000 0000 1100 0000 0000 0000 0000 = 0x000C0000
	 *
	 * Transmit
	 * 0000 0000 0001 1100
	 * 0000 0000 0000 0100
	 * 0000 0000 0000 0001 = 0x0001
	 *
	 * 0000 0000 0000 0000 0000 0000 0000 0001
	 * 0000 0000 0000 0100 0000 0000 0000 0000 = 0x00040000
	 * */

	/* Setup the transmit descriptor */
	tail_list->frameSize = (u16) s;
	tail_list->buffer[0].count = TLAN_LAST_BUFFER | (u32) s;
	tail_list->buffer[1].count = 0;
	tail_list->buffer[1].address = 0;

	tail_list->cStat = TLAN_CSTAT_READY;

	DBG ( "INT1-0x%hX\n", inw(BASE + TLAN_HOST_INT) );

	if (!priv->txInProgress) {
		priv->txInProgress = 1;
		outl(virt_to_le32desc(tail_list), BASE + TLAN_CH_PARM);
		outl(TLAN_HC_GO, BASE + TLAN_HOST_CMD);
	} else {
		if (priv->txTail == 0) {
			DBG ( "Out buffer\n" );
			(priv->txList + (TLAN_NUM_TX_LISTS - 1))->forward =
			    virt_to_le32desc(tail_list);
		} else {
			DBG ( "Fix this \n" );
			(priv->txList + (priv->txTail - 1))->forward =
			    virt_to_le32desc(tail_list);
		}
	}
	
	CIRC_INC(priv->txTail, TLAN_NUM_TX_LISTS);

	DBG ( "INT2-0x%hX\n", inw(BASE + TLAN_HOST_INT) );

	to = currticks() + TX_TIME_OUT;
	while ((tail_list->cStat == TLAN_CSTAT_READY) && currticks() < to);

	head_list = priv->txList + priv->txHead;
	while (((tmpCStat = head_list->cStat) & TLAN_CSTAT_FRM_CMP) 
			&& (ack < 255)) {
		ack++;
		if(tmpCStat & TLAN_CSTAT_EOC)
			eoc =1;
		head_list->cStat = TLAN_CSTAT_UNUSED;
		CIRC_INC(priv->txHead, TLAN_NUM_TX_LISTS);
		head_list = priv->txList + priv->txHead;
		
	}
	if(!ack)
		printf("Incomplete TX Frame\n");

	if(eoc) {
		head_list = priv->txList + priv->txHead;
		if ((head_list->cStat & TLAN_CSTAT_READY) == TLAN_CSTAT_READY) {
			outl(virt_to_le32desc(head_list), BASE + TLAN_CH_PARM);
			ack |= TLAN_HC_GO;
		} else {
			priv->txInProgress = 0;
		}
	}
	if(ack) {
		host_cmd = TLAN_HC_ACK | ack;
		outl(host_cmd, BASE + TLAN_HOST_CMD);
	}
	
	if(priv->tlanRev < 0x30 ) {
		ack = 1;
		head_list = priv->txList + priv->txHead;
		if ((head_list->cStat & TLAN_CSTAT_READY) == TLAN_CSTAT_READY) {
			outl(virt_to_le32desc(head_list), BASE + TLAN_CH_PARM);
			ack |= TLAN_HC_GO;
		} else {
			priv->txInProgress = 0;
		}
		host_cmd = TLAN_HC_ACK | ack | 0x00140000;
		outl(host_cmd, BASE + TLAN_HOST_CMD);
		
	}
			
	if (currticks() >= to) {
		printf("TX Time Out");
	}
}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void tlan_disable ( struct nic *nic __unused ) {
	/* put the card in its initial state */
	/* This function serves 3 purposes.
	 * This disables DMA and interrupts so we don't receive
	 *  unexpected packets or interrupts from the card after
	 *  etherboot has finished.
	 * This frees resources so etherboot may use
	 *  this driver on another interface
	 * This allows etherboot to reinitialize the interface
	 *  if something is something goes wrong.
	 *
	 */
	outl(TLAN_HC_AD_RST, BASE + TLAN_HOST_CMD);
}

/**************************************************************************
IRQ - Enable, Disable, or Force interrupts
***************************************************************************/
static void tlan_irq(struct nic *nic __unused, irq_action_t action __unused)
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

static struct nic_operations tlan_operations = {
	.connect	= dummy_connect,
	.poll		= tlan_poll,
	.transmit	= tlan_transmit,
	.irq		= tlan_irq,

};

static void TLan_SetMulticastList(struct nic *nic) {
	int i;
	u8 tmp;

	/* !IFF_PROMISC */
	tmp = TLan_DioRead8(BASE, TLAN_NET_CMD);
	TLan_DioWrite8(BASE, TLAN_NET_CMD, tmp & ~TLAN_NET_CMD_CAF);

	/* IFF_ALLMULTI */
	for(i = 0; i< 3; i++)
		TLan_SetMac(nic, i + 1, NULL);
	TLan_DioWrite32(BASE, TLAN_HASH_1, 0xFFFFFFFF);
	TLan_DioWrite32(BASE, TLAN_HASH_2, 0xFFFFFFFF);

	
}
/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
***************************************************************************/

#define board_found 1
#define valid_link 0
static int tlan_probe ( struct nic *nic, struct pci_device *pci ) {

	u16 data = 0;
	int err;
	int i;

	if (pci->ioaddr == 0)
		return 0;

	nic->irqno  = 0;
	nic->ioaddr = pci->ioaddr;

	BASE = pci->ioaddr;

	/* Set nic as PCI bus master */
	adjust_pci_device(pci);
	
	/* Point to private storage */
	priv = &TLanPrivateInfo;

	/* Figure out which chip we're dealing with */
	i = 0;
	chip_idx = -1;
	while (tlan_pci_tbl[i].name) {
		if ((((u32) pci->device << 16) | pci->vendor) ==
		    (tlan_pci_tbl[i].id.pci & 0xffffffff)) {
			chip_idx = i;
			break;
		}
		i++;
	}

	priv->vendor_id = pci->vendor;
	priv->dev_id = pci->device;
	priv->nic_name = pci->id->name;
	priv->eoc = 0;

	err = 0;
	for (i = 0; i < 6; i++)
		err |= TLan_EeReadByte(BASE,
				       (u8) tlan_pci_tbl[chip_idx].
				       addrOfs + i,
				       (u8 *) & nic->node_addr[i]);
	if (err) {
  	    printf ( "TLAN: %s: Error reading MAC from eeprom: %d\n",
		    pci->id->name, err);
	} else {
	    DBG ( "%s: %s at ioaddr %#lX, ", 
		  pci->id->name, eth_ntoa ( nic->node_addr ), pci->ioaddr );
	}

	priv->tlanRev = TLan_DioRead8(BASE, TLAN_DEF_REVISION);
	printf("revision: 0x%hX\n", priv->tlanRev);

	TLan_ResetLists(nic);
	TLan_ResetAdapter(nic);

	data = inl(BASE + TLAN_HOST_CMD);
	data |= TLAN_HC_INT_OFF;
	outw(data, BASE + TLAN_HOST_CMD);

	TLan_SetMulticastList(nic);
	udelay(100); 
	priv->txList = tx_ring;

/*	if (board_found && valid_link)
	{*/
	/* point to NIC specific routines */
	nic->nic_op	= &tlan_operations;
	return 1;
}


/*****************************************************************************
******************************************************************************

	ThunderLAN Driver Eeprom routines

	The Compaq Netelligent 10 and 10/100 cards use a Microchip 24C02A
	EEPROM.  These functions are based on information in Microchip's
	data sheet.  I don't know how well this functions will work with
	other EEPROMs.

******************************************************************************
*****************************************************************************/


/***************************************************************
*	TLan_EeSendStart
*
*	Returns:
*		Nothing
*	Parms:
*		io_base		The IO port base address for the
*				TLAN device with the EEPROM to
*				use.
*
*	This function sends a start cycle to an EEPROM attached
*	to a TLAN chip.
*
**************************************************************/

void TLan_EeSendStart(u16 io_base)
{
	u16 sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;

	TLan_SetBit(TLAN_NET_SIO_ECLOK, sio);
	TLan_SetBit(TLAN_NET_SIO_EDATA, sio);
	TLan_SetBit(TLAN_NET_SIO_ETXEN, sio);
	TLan_ClearBit(TLAN_NET_SIO_EDATA, sio);
	TLan_ClearBit(TLAN_NET_SIO_ECLOK, sio);

}	/* TLan_EeSendStart */

/***************************************************************
*	TLan_EeSendByte
*
*	Returns:
*		If the correct ack was received, 0, otherwise 1
*	Parms:	io_base		The IO port base address for the
*				TLAN device with the EEPROM to
*				use.
*		data		The 8 bits of information to
*				send to the EEPROM.
*		stop		If TLAN_EEPROM_STOP is passed, a
*				stop cycle is sent after the
*				byte is sent after the ack is
*				read.
*
*	This function sends a byte on the serial EEPROM line,
*	driving the clock to send each bit. The function then
*	reverses transmission direction and reads an acknowledge
*	bit.
*
**************************************************************/

int TLan_EeSendByte(u16 io_base, u8 data, int stop)
{
	int err;
	u8 place;
	u16 sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;

	/* Assume clock is low, tx is enabled; */
	for (place = 0x80; place != 0; place >>= 1) {
		if (place & data)
			TLan_SetBit(TLAN_NET_SIO_EDATA, sio);
		else
			TLan_ClearBit(TLAN_NET_SIO_EDATA, sio);
		TLan_SetBit(TLAN_NET_SIO_ECLOK, sio);
		TLan_ClearBit(TLAN_NET_SIO_ECLOK, sio);
	}
	TLan_ClearBit(TLAN_NET_SIO_ETXEN, sio);
	TLan_SetBit(TLAN_NET_SIO_ECLOK, sio);
	err = TLan_GetBit(TLAN_NET_SIO_EDATA, sio);
	TLan_ClearBit(TLAN_NET_SIO_ECLOK, sio);
	TLan_SetBit(TLAN_NET_SIO_ETXEN, sio);

	if ((!err) && stop) {
		TLan_ClearBit(TLAN_NET_SIO_EDATA, sio);	/* STOP, raise data while clock is high */
		TLan_SetBit(TLAN_NET_SIO_ECLOK, sio);
		TLan_SetBit(TLAN_NET_SIO_EDATA, sio);
	}

	return (err);

}	/* TLan_EeSendByte */

/***************************************************************
*	TLan_EeReceiveByte
*
*	Returns:
*		Nothing
*	Parms:
*		io_base		The IO port base address for the
*				TLAN device with the EEPROM to
*				use.
*		data		An address to a char to hold the
*				data sent from the EEPROM.
*		stop		If TLAN_EEPROM_STOP is passed, a
*				stop cycle is sent after the
*				byte is received, and no ack is
*				sent.
*
*	This function receives 8 bits of data from the EEPROM
*	over the serial link.  It then sends and ack bit, or no
*	ack and a stop bit.  This function is used to retrieve
*	data after the address of a byte in the EEPROM has been
*	sent.
*
**************************************************************/

void TLan_EeReceiveByte(u16 io_base, u8 * data, int stop)
{
	u8 place;
	u16 sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;
	*data = 0;

	/* Assume clock is low, tx is enabled; */
	TLan_ClearBit(TLAN_NET_SIO_ETXEN, sio);
	for (place = 0x80; place; place >>= 1) {
		TLan_SetBit(TLAN_NET_SIO_ECLOK, sio);
		if (TLan_GetBit(TLAN_NET_SIO_EDATA, sio))
			*data |= place;
		TLan_ClearBit(TLAN_NET_SIO_ECLOK, sio);
	}

	TLan_SetBit(TLAN_NET_SIO_ETXEN, sio);
	if (!stop) {
		TLan_ClearBit(TLAN_NET_SIO_EDATA, sio);	/* Ack = 0 */
		TLan_SetBit(TLAN_NET_SIO_ECLOK, sio);
		TLan_ClearBit(TLAN_NET_SIO_ECLOK, sio);
	} else {
		TLan_SetBit(TLAN_NET_SIO_EDATA, sio);	/* No ack = 1 (?) */
		TLan_SetBit(TLAN_NET_SIO_ECLOK, sio);
		TLan_ClearBit(TLAN_NET_SIO_ECLOK, sio);
		TLan_ClearBit(TLAN_NET_SIO_EDATA, sio);	/* STOP, raise data while clock is high */
		TLan_SetBit(TLAN_NET_SIO_ECLOK, sio);
		TLan_SetBit(TLAN_NET_SIO_EDATA, sio);
	}

}	/* TLan_EeReceiveByte */

/***************************************************************
*	TLan_EeReadByte
*
*	Returns:
*		No error = 0, else, the stage at which the error
*		occurred.
*	Parms:
*		io_base		The IO port base address for the
*				TLAN device with the EEPROM to
*				use.
*		ee_addr		The address of the byte in the
*				EEPROM whose contents are to be
*				retrieved.
*		data		An address to a char to hold the
*				data obtained from the EEPROM.
*
*	This function reads a byte of information from an byte
*	cell in the EEPROM.
*
**************************************************************/

int TLan_EeReadByte(u16 io_base, u8 ee_addr, u8 * data)
{
	int err;
	int ret = 0;


	TLan_EeSendStart(io_base);
	err = TLan_EeSendByte(io_base, 0xA0, TLAN_EEPROM_ACK);
	if (err) {
		ret = 1;
		goto fail;
	}
	err = TLan_EeSendByte(io_base, ee_addr, TLAN_EEPROM_ACK);
	if (err) {
		ret = 2;
		goto fail;
	}
	TLan_EeSendStart(io_base);
	err = TLan_EeSendByte(io_base, 0xA1, TLAN_EEPROM_ACK);
	if (err) {
		ret = 3;
		goto fail;
	}
	TLan_EeReceiveByte(io_base, data, TLAN_EEPROM_STOP);
      fail:

	return ret;

}	/* TLan_EeReadByte */


/*****************************************************************************
******************************************************************************

ThunderLAN Driver MII Routines

These routines are based on the information in Chap. 2 of the
"ThunderLAN Programmer's Guide", pp. 15-24.

******************************************************************************
*****************************************************************************/


/***************************************************************
*	TLan_MiiReadReg
*
*	Returns:
*		0	if ack received ok
*		1	otherwise.
*
*	Parms:
*		dev		The device structure containing
*				The io address and interrupt count
*				for this device.
*		phy		The address of the PHY to be queried.
*		reg		The register whose contents are to be
*				retrieved.
*		val		A pointer to a variable to store the
*				retrieved value.
*
*	This function uses the TLAN's MII bus to retrieve the contents
*	of a given register on a PHY.  It sends the appropriate info
*	and then reads the 16-bit register value from the MII bus via
*	the TLAN SIO register.
*
**************************************************************/

int TLan_MiiReadReg(struct nic *nic __unused, u16 phy, u16 reg, u16 * val)
{
	u8 nack;
	u16 sio, tmp;
	u32 i;
	int err;
	int minten;

	err = FALSE;
	outw(TLAN_NET_SIO, BASE + TLAN_DIO_ADR);
	sio = BASE + TLAN_DIO_DATA + TLAN_NET_SIO;

	TLan_MiiSync(BASE);

	minten = TLan_GetBit(TLAN_NET_SIO_MINTEN, sio);
	if (minten)
		TLan_ClearBit(TLAN_NET_SIO_MINTEN, sio);

	TLan_MiiSendData(BASE, 0x1, 2);	/* Start ( 01b ) */
	TLan_MiiSendData(BASE, 0x2, 2);	/* Read  ( 10b ) */
	TLan_MiiSendData(BASE, phy, 5);	/* Device #      */
	TLan_MiiSendData(BASE, reg, 5);	/* Register #    */


	TLan_ClearBit(TLAN_NET_SIO_MTXEN, sio);	/* Change direction */

	TLan_ClearBit(TLAN_NET_SIO_MCLK, sio);	/* Clock Idle bit */
	TLan_SetBit(TLAN_NET_SIO_MCLK, sio);
	TLan_ClearBit(TLAN_NET_SIO_MCLK, sio);	/* Wait 300ns */

	nack = TLan_GetBit(TLAN_NET_SIO_MDATA, sio);	/* Check for ACK */
	TLan_SetBit(TLAN_NET_SIO_MCLK, sio);	/* Finish ACK */
	if (nack) {		/* No ACK, so fake it */
		for (i = 0; i < 16; i++) {
			TLan_ClearBit(TLAN_NET_SIO_MCLK, sio);
			TLan_SetBit(TLAN_NET_SIO_MCLK, sio);
		}
		tmp = 0xffff;
		err = TRUE;
	} else {		/* ACK, so read data */
		for (tmp = 0, i = 0x8000; i; i >>= 1) {
			TLan_ClearBit(TLAN_NET_SIO_MCLK, sio);
			if (TLan_GetBit(TLAN_NET_SIO_MDATA, sio))
				tmp |= i;
			TLan_SetBit(TLAN_NET_SIO_MCLK, sio);
		}
	}


	TLan_ClearBit(TLAN_NET_SIO_MCLK, sio);	/* Idle cycle */
	TLan_SetBit(TLAN_NET_SIO_MCLK, sio);

	if (minten)
		TLan_SetBit(TLAN_NET_SIO_MINTEN, sio);

	*val = tmp;

	return err;

}				/* TLan_MiiReadReg */

/***************************************************************
*	TLan_MiiSendData
*
*	Returns:
*		Nothing
*	Parms:
*		base_port	The base IO port of the adapter	in
*				question.
*		dev		The address of the PHY to be queried.
*		data		The value to be placed on the MII bus.
*		num_bits	The number of bits in data that are to
*				be placed on the MII bus.
*
*	This function sends on sequence of bits on the MII
*	configuration bus.
*
**************************************************************/

void TLan_MiiSendData(u16 base_port, u32 data, unsigned num_bits)
{
	u16 sio;
	u32 i;

	if (num_bits == 0)
		return;

	outw(TLAN_NET_SIO, base_port + TLAN_DIO_ADR);
	sio = base_port + TLAN_DIO_DATA + TLAN_NET_SIO;
	TLan_SetBit(TLAN_NET_SIO_MTXEN, sio);

	for (i = (0x1 << (num_bits - 1)); i; i >>= 1) {
		TLan_ClearBit(TLAN_NET_SIO_MCLK, sio);
		(void) TLan_GetBit(TLAN_NET_SIO_MCLK, sio);
		if (data & i)
			TLan_SetBit(TLAN_NET_SIO_MDATA, sio);
		else
			TLan_ClearBit(TLAN_NET_SIO_MDATA, sio);
		TLan_SetBit(TLAN_NET_SIO_MCLK, sio);
		(void) TLan_GetBit(TLAN_NET_SIO_MCLK, sio);
	}

}				/* TLan_MiiSendData */

/***************************************************************
*	TLan_MiiSync
*
*	Returns:
*		Nothing
*	Parms:
*		base_port	The base IO port of the adapter in
*				question.
*
*	This functions syncs all PHYs in terms of the MII configuration
*	bus.
*
**************************************************************/

void TLan_MiiSync(u16 base_port)
{
	int i;
	u16 sio;

	outw(TLAN_NET_SIO, base_port + TLAN_DIO_ADR);
	sio = base_port + TLAN_DIO_DATA + TLAN_NET_SIO;

	TLan_ClearBit(TLAN_NET_SIO_MTXEN, sio);
	for (i = 0; i < 32; i++) {
		TLan_ClearBit(TLAN_NET_SIO_MCLK, sio);
		TLan_SetBit(TLAN_NET_SIO_MCLK, sio);
	}

}				/* TLan_MiiSync */

/***************************************************************
*	TLan_MiiWriteReg
*
*	Returns:
*		Nothing
*	Parms:
*		dev		The device structure for the device
*				to write to.
*		phy		The address of the PHY to be written to.
*		reg		The register whose contents are to be
*				written.
*		val		The value to be written to the register.
*
*	This function uses the TLAN's MII bus to write the contents of a
*	given register on a PHY.  It sends the appropriate info and then
*	writes the 16-bit register value from the MII configuration bus
*	via the TLAN SIO register.
*
**************************************************************/

void TLan_MiiWriteReg(struct nic *nic __unused, u16 phy, u16 reg, u16 val)
{
	u16 sio;
	int minten;

	outw(TLAN_NET_SIO, BASE + TLAN_DIO_ADR);
	sio = BASE + TLAN_DIO_DATA + TLAN_NET_SIO;

	TLan_MiiSync(BASE);

	minten = TLan_GetBit(TLAN_NET_SIO_MINTEN, sio);
	if (minten)
		TLan_ClearBit(TLAN_NET_SIO_MINTEN, sio);

	TLan_MiiSendData(BASE, 0x1, 2);	/* Start ( 01b ) */
	TLan_MiiSendData(BASE, 0x1, 2);	/* Write ( 01b ) */
	TLan_MiiSendData(BASE, phy, 5);	/* Device #      */
	TLan_MiiSendData(BASE, reg, 5);	/* Register #    */

	TLan_MiiSendData(BASE, 0x2, 2);	/* Send ACK */
	TLan_MiiSendData(BASE, val, 16);	/* Send Data */

	TLan_ClearBit(TLAN_NET_SIO_MCLK, sio);	/* Idle cycle */
	TLan_SetBit(TLAN_NET_SIO_MCLK, sio);

	if (minten)
		TLan_SetBit(TLAN_NET_SIO_MINTEN, sio);


}				/* TLan_MiiWriteReg */

/***************************************************************
*	TLan_SetMac
*
*	Returns:
*		Nothing
*	Parms:
*		dev	Pointer to device structure of adapter
*			on which to change the AREG.
*		areg	The AREG to set the address in (0 - 3).
*		mac	A pointer to an array of chars.  Each
*			element stores one byte of the address.
*			IE, it isn't in ascii.
*
*	This function transfers a MAC address to one of the
*	TLAN AREGs (address registers).  The TLAN chip locks
*	the register on writing to offset 0 and unlocks the
*	register after writing to offset 5.  If NULL is passed
*	in mac, then the AREG is filled with 0's.
*
**************************************************************/

void TLan_SetMac(struct nic *nic __unused, int areg, unsigned char *mac)
{
	int i;

	areg *= 6;

	if (mac != NULL) {
		for (i = 0; i < 6; i++)
			TLan_DioWrite8(BASE, TLAN_AREG_0 + areg + i,
				       mac[i]);
	} else {
		for (i = 0; i < 6; i++)
			TLan_DioWrite8(BASE, TLAN_AREG_0 + areg + i, 0);
	}

}				/* TLan_SetMac */

/*********************************************************************
*	TLan_PhyDetect
*
*	Returns:
*		Nothing
*	Parms:
*		dev	A pointer to the device structure of the adapter
*			for which the PHY needs determined.
*
*	So far I've found that adapters which have external PHYs
*	may also use the internal PHY for part of the functionality.
*	(eg, AUI/Thinnet).  This function finds out if this TLAN
*	chip has an internal PHY, and then finds the first external
*	PHY (starting from address 0) if it exists).
*
********************************************************************/

void TLan_PhyDetect(struct nic *nic)
{
	u16 control;
	u16 hi;
	u16 lo;
	u32 phy;

	if (tlan_pci_tbl[chip_idx].flags & TLAN_ADAPTER_UNMANAGED_PHY) {
		priv->phyNum = 0xFFFF;
		return;
	}

	TLan_MiiReadReg(nic, TLAN_PHY_MAX_ADDR, MII_PHYSID1, &hi);

	if (hi != 0xFFFF) {
		priv->phy[0] = TLAN_PHY_MAX_ADDR;
	} else {
		priv->phy[0] = TLAN_PHY_NONE;
	}

	priv->phy[1] = TLAN_PHY_NONE;
	for (phy = 0; phy <= TLAN_PHY_MAX_ADDR; phy++) {
		TLan_MiiReadReg(nic, phy, MII_BMCR, &control);
		TLan_MiiReadReg(nic, phy, MII_PHYSID1, &hi);
		TLan_MiiReadReg(nic, phy, MII_PHYSID2, &lo);
		if ((control != 0xFFFF) || (hi != 0xFFFF)
		    || (lo != 0xFFFF)) {
			printf("PHY found at %hX %hX %hX %hX\n", 
			       (unsigned int) phy, control, hi, lo);
			if ((priv->phy[1] == TLAN_PHY_NONE)
			    && (phy != TLAN_PHY_MAX_ADDR)) {
				priv->phy[1] = phy;
			}
		}
	}

	if (priv->phy[1] != TLAN_PHY_NONE) {
		priv->phyNum = 1;
	} else if (priv->phy[0] != TLAN_PHY_NONE) {
		priv->phyNum = 0;
	} else {
		printf
		    ("TLAN:  Cannot initialize device, no PHY was found!\n");
	}

}				/* TLan_PhyDetect */

void TLan_PhyPowerDown(struct nic *nic)
{

	u16 value;
	DBG ( "%s: Powering down PHY(s).\n", priv->nic_name );
	value = BMCR_PDOWN | BMCR_LOOPBACK | BMCR_ISOLATE;
	TLan_MiiSync(BASE);
	TLan_MiiWriteReg(nic, priv->phy[priv->phyNum], MII_BMCR, value);
	if ((priv->phyNum == 0) && (priv->phy[1] != TLAN_PHY_NONE)
	    &&
	    (!(tlan_pci_tbl[chip_idx].
	       flags & TLAN_ADAPTER_USE_INTERN_10))) {
		TLan_MiiSync(BASE);
		TLan_MiiWriteReg(nic, priv->phy[1], MII_BMCR, value);
	}

	/* Wait for 50 ms and powerup
	 * This is abitrary.  It is intended to make sure the
	 * tranceiver settles.
	 */
	/* TLan_SetTimer( dev, (HZ/20), TLAN_TIMER_PHY_PUP ); */
	mdelay(50);
	TLan_PhyPowerUp(nic);

}				/* TLan_PhyPowerDown */


void TLan_PhyPowerUp(struct nic *nic)
{
	u16 value;

	DBG ( "%s: Powering up PHY.\n", priv->nic_name );
	TLan_MiiSync(BASE);
	value = BMCR_LOOPBACK;
	TLan_MiiWriteReg(nic, priv->phy[priv->phyNum], MII_BMCR, value);
	TLan_MiiSync(BASE);
	/* Wait for 500 ms and reset the
	 * tranceiver.  The TLAN docs say both 50 ms and
	 * 500 ms, so do the longer, just in case.
	 */
	mdelay(500);
	TLan_PhyReset(nic);
	/* TLan_SetTimer( dev, (HZ/20), TLAN_TIMER_PHY_RESET ); */

}				/* TLan_PhyPowerUp */

void TLan_PhyReset(struct nic *nic)
{
	u16 phy;
	u16 value;

	phy = priv->phy[priv->phyNum];

	DBG ( "%s: Reseting PHY.\n", priv->nic_name );
	TLan_MiiSync(BASE);
	value = BMCR_LOOPBACK | BMCR_RESET;
	TLan_MiiWriteReg(nic, phy, MII_BMCR, value);
	TLan_MiiReadReg(nic, phy, MII_BMCR, &value);
	while (value & BMCR_RESET) {
		TLan_MiiReadReg(nic, phy, MII_BMCR, &value);
	}

	/* Wait for 500 ms and initialize.
	 * I don't remember why I wait this long.
	 * I've changed this to 50ms, as it seems long enough.
	 */
	/* TLan_SetTimer( dev, (HZ/20), TLAN_TIMER_PHY_START_LINK ); */
	mdelay(50);
	TLan_PhyStartLink(nic);

}				/* TLan_PhyReset */


void TLan_PhyStartLink(struct nic *nic)
{

	u16 ability;
	u16 control;
	u16 data;
	u16 phy;
	u16 status;
	u16 tctl;

	phy = priv->phy[priv->phyNum];
	DBG ( "%s: Trying to activate link.\n", priv->nic_name );
	TLan_MiiReadReg(nic, phy, MII_BMSR, &status);
	TLan_MiiReadReg(nic, phy, MII_BMSR, &ability);

	if ((status & BMSR_ANEGCAPABLE) && (!priv->aui)) {
		ability = status >> 11;
		if (priv->speed == TLAN_SPEED_10 &&
		    priv->duplex == TLAN_DUPLEX_HALF) {
			TLan_MiiWriteReg(nic, phy, MII_BMCR, 0x0000);
		} else if (priv->speed == TLAN_SPEED_10 &&
			   priv->duplex == TLAN_DUPLEX_FULL) {
			priv->tlanFullDuplex = TRUE;
			TLan_MiiWriteReg(nic, phy, MII_BMCR, 0x0100);
		} else if (priv->speed == TLAN_SPEED_100 &&
			   priv->duplex == TLAN_DUPLEX_HALF) {
			TLan_MiiWriteReg(nic, phy, MII_BMCR, 0x2000);
		} else if (priv->speed == TLAN_SPEED_100 &&
			   priv->duplex == TLAN_DUPLEX_FULL) {
			priv->tlanFullDuplex = TRUE;
			TLan_MiiWriteReg(nic, phy, MII_BMCR, 0x2100);
		} else {

			/* Set Auto-Neg advertisement */
			TLan_MiiWriteReg(nic, phy, MII_ADVERTISE,
					 (ability << 5) | 1);
			/* Enablee Auto-Neg */
			TLan_MiiWriteReg(nic, phy, MII_BMCR, 0x1000);
			/* Restart Auto-Neg */
			TLan_MiiWriteReg(nic, phy, MII_BMCR, 0x1200);
			/* Wait for 4 sec for autonegotiation
			 * to complete.  The max spec time is less than this
			 * but the card need additional time to start AN.
			 * .5 sec should be plenty extra.
			 */
			DBG ( "TLAN: %s: Starting autonegotiation.\n",
			       priv->nic_name );
			mdelay(4000);
			TLan_PhyFinishAutoNeg(nic);
			/* TLan_SetTimer( dev, (2*HZ), TLAN_TIMER_PHY_FINISH_AN ); */
			return;
		}

	}

	if ((priv->aui) && (priv->phyNum != 0)) {
		priv->phyNum = 0;
		data =
		    TLAN_NET_CFG_1FRAG | TLAN_NET_CFG_1CHAN |
		    TLAN_NET_CFG_PHY_EN;
		TLan_DioWrite16(BASE, TLAN_NET_CONFIG, data);
		mdelay(50);
		/* TLan_SetTimer( dev, (40*HZ/1000), TLAN_TIMER_PHY_PDOWN ); */
		TLan_PhyPowerDown(nic);
		return;
	} else if (priv->phyNum == 0) {
		control = 0;
		TLan_MiiReadReg(nic, phy, TLAN_TLPHY_CTL, &tctl);
		if (priv->aui) {
			tctl |= TLAN_TC_AUISEL;
		} else {
			tctl &= ~TLAN_TC_AUISEL;
			if (priv->duplex == TLAN_DUPLEX_FULL) {
				control |= BMCR_FULLDPLX;
				priv->tlanFullDuplex = TRUE;
			}
			if (priv->speed == TLAN_SPEED_100) {
				control |= BMCR_SPEED100;
			}
		}
		TLan_MiiWriteReg(nic, phy, MII_BMCR, control);
		TLan_MiiWriteReg(nic, phy, TLAN_TLPHY_CTL, tctl);
	}

	/* Wait for 2 sec to give the tranceiver time
	 * to establish link.
	 */
	/* TLan_SetTimer( dev, (4*HZ), TLAN_TIMER_FINISH_RESET ); */
	mdelay(2000);
	TLan_FinishReset(nic);

}				/* TLan_PhyStartLink */

void TLan_PhyFinishAutoNeg(struct nic *nic)
{

	u16 an_adv;
	u16 an_lpa;
	u16 data;
	u16 mode;
	u16 phy;
	u16 status;

	phy = priv->phy[priv->phyNum];

	TLan_MiiReadReg(nic, phy, MII_BMSR, &status);
	udelay(1000);
	TLan_MiiReadReg(nic, phy, MII_BMSR, &status);

	if (!(status & BMSR_ANEGCOMPLETE)) {
		/* Wait for 8 sec to give the process
		 * more time.  Perhaps we should fail after a while.
		 */
		if (!priv->neg_be_verbose++) {
			printf
			    ("TLAN:  Giving autonegotiation more time.\n");
			printf
			    ("TLAN:  Please check that your adapter has\n");
			printf
			    ("TLAN:  been properly connected to a HUB or Switch.\n");
			printf
			    ("TLAN:  Trying to establish link in the background...\n");
		}
		mdelay(8000);
		TLan_PhyFinishAutoNeg(nic);
		/* TLan_SetTimer( dev, (8*HZ), TLAN_TIMER_PHY_FINISH_AN ); */
		return;
	}

	DBG ( "TLAN: %s: Autonegotiation complete.\n", priv->nic_name );
	TLan_MiiReadReg(nic, phy, MII_ADVERTISE, &an_adv);
	TLan_MiiReadReg(nic, phy, MII_LPA, &an_lpa);
	mode = an_adv & an_lpa & 0x03E0;
	if (mode & 0x0100) {
		printf("Full Duplex\n");
		priv->tlanFullDuplex = TRUE;
	} else if (!(mode & 0x0080) && (mode & 0x0040)) {
		priv->tlanFullDuplex = TRUE;
		printf("Full Duplex\n");
	}

	if ((!(mode & 0x0180))
	    && (tlan_pci_tbl[chip_idx].flags & TLAN_ADAPTER_USE_INTERN_10)
	    && (priv->phyNum != 0)) {
		priv->phyNum = 0;
		data =
		    TLAN_NET_CFG_1FRAG | TLAN_NET_CFG_1CHAN |
		    TLAN_NET_CFG_PHY_EN;
		TLan_DioWrite16(BASE, TLAN_NET_CONFIG, data);
		/* TLan_SetTimer( nic, (400*HZ/1000), TLAN_TIMER_PHY_PDOWN ); */
		mdelay(400);
		TLan_PhyPowerDown(nic);
		return;
	}

	if (priv->phyNum == 0) {
		if ((priv->duplex == TLAN_DUPLEX_FULL)
		    || (an_adv & an_lpa & 0x0040)) {
			TLan_MiiWriteReg(nic, phy, MII_BMCR,
					 BMCR_ANENABLE | BMCR_FULLDPLX);
			DBG 
			    ( "TLAN:  Starting internal PHY with FULL-DUPLEX\n" );
		} else {
			TLan_MiiWriteReg(nic, phy, MII_BMCR,
					 BMCR_ANENABLE);
			DBG 
			    ( "TLAN:  Starting internal PHY with HALF-DUPLEX\n" );
		}
	}

	/* Wait for 100 ms.  No reason in partiticular.
	 */
	/* TLan_SetTimer( dev, (HZ/10), TLAN_TIMER_FINISH_RESET ); */
	mdelay(100);
	TLan_FinishReset(nic);

}				/* TLan_PhyFinishAutoNeg */

#ifdef MONITOR

/*********************************************************************
*
*      TLan_phyMonitor
*
*      Returns:
*              None
*
*      Params:
*              dev             The device structure of this device.
*
*
*      This function monitors PHY condition by reading the status
*      register via the MII bus. This can be used to give info
*      about link changes (up/down), and possible switch to alternate
*      media.
*
********************************************************************/

void TLan_PhyMonitor(struct net_device *dev)
{
	TLanPrivateInfo *priv = dev->priv;
	u16 phy;
	u16 phy_status;

	phy = priv->phy[priv->phyNum];

	/* Get PHY status register */
	TLan_MiiReadReg(nic, phy, MII_BMSR, &phy_status);

	/* Check if link has been lost */
	if (!(phy_status & BMSR_LSTATUS)) {
		if (priv->link) {
			priv->link = 0;
			printf("TLAN: %s has lost link\n", priv->nic_name);
			priv->flags &= ~IFF_RUNNING;
			mdelay(2000);
			TLan_PhyMonitor(nic);
			/* TLan_SetTimer( dev, (2*HZ), TLAN_TIMER_LINK_BEAT ); */
			return;
		}
	}

	/* Link restablished? */
	if ((phy_status & BMSR_LSTATUS) && !priv->link) {
		priv->link = 1;
		printf("TLAN: %s has reestablished link\n",
		       priv->nic_name);
		priv->flags |= IFF_RUNNING;
	}

	/* Setup a new monitor */
	/* TLan_SetTimer( dev, (2*HZ), TLAN_TIMER_LINK_BEAT ); */
	mdelay(2000);
	TLan_PhyMonitor(nic);
}

#endif				/* MONITOR */

static struct pci_device_id tlan_nics[] = {
	PCI_ROM(0x0e11, 0xae34, "netel10", "Compaq Netelligent 10 T PCI UTP", 0),
	PCI_ROM(0x0e11, 0xae32, "netel100","Compaq Netelligent 10/100 TX PCI UTP", 0),
	PCI_ROM(0x0e11, 0xae35, "netflex3i", "Compaq Integrated NetFlex-3/P", 0),
	PCI_ROM(0x0e11, 0xf130, "thunder", "Compaq NetFlex-3/P", 0),
	PCI_ROM(0x0e11, 0xf150, "netflex3b", "Compaq NetFlex-3/P", 0),
	PCI_ROM(0x0e11, 0xae43, "netel100pi", "Compaq Netelligent Integrated 10/100 TX UTP", 0),
	PCI_ROM(0x0e11, 0xae40, "netel100d", "Compaq Netelligent Dual 10/100 TX PCI UTP", 0),
	PCI_ROM(0x0e11, 0xb011, "netel100i", "Compaq Netelligent 10/100 TX Embedded UTP", 0),
	PCI_ROM(0x108d, 0x0013, "oc2183", "Olicom OC-2183/2185", 0),
	PCI_ROM(0x108d, 0x0012, "oc2325", "Olicom OC-2325", 0),
	PCI_ROM(0x108d, 0x0014, "oc2326", "Olicom OC-2326", 0),
	PCI_ROM(0x0e11, 0xb030, "netelligent_10_100_ws_5100", "Compaq Netelligent 10/100 TX UTP", 0),
	PCI_ROM(0x0e11, 0xb012, "netelligent_10_t2", "Compaq Netelligent 10 T/2 PCI UTP/Coax", 0),
};

PCI_DRIVER ( tlan_driver, tlan_nics, PCI_NO_CLASS );

DRIVER ( "TLAN/PCI", nic_driver, pci_driver, tlan_driver,
	 tlan_probe, tlan_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
