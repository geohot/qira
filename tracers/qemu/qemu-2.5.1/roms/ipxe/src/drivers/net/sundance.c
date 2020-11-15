/**************************************************************************
*
*    sundance.c -- Etherboot device driver for the Sundance ST201 "Alta".
*    Written 2002-2002 by Timothy Legge <tlegge@rogers.com>
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
*               sundance.c: A Linux device driver for the Sundance ST201 "Alta"
*               Written 1999-2002 by Donald Becker
*
*               tulip.c: Tulip and Clone Etherboot Driver
*               By Marty Conner
*               Copyright (C) 2001 Entity Cyber, Inc.
*
*    Linux Driver Version LK1.09a, 10-Jul-2003 (2.4.25)
*
*    REVISION HISTORY:
*    ================
*    v1.1	01-01-2003	timlegge	Initial implementation
*    v1.7	04-10-2003	timlegge	Transfers Linux Kernel (30 sec)
*    v1.8	04-13-2003	timlegge	Fix multiple transmission bug
*    v1.9	08-19-2003	timlegge	Support Multicast
*    v1.10	01-17-2004	timlegge	Initial driver output cleanup
*    v1.11	03-21-2004	timlegge	Remove unused variables
*    v1.12	03-21-2004	timlegge	Remove excess MII defines
*    v1.13	03-24-2004	timlegge	Update to Linux 2.4.25 driver
*
****************************************************************************/

FILE_LICENCE ( GPL2_OR_LATER );

/* to get some global routines like printf */
#include "etherboot.h"
/* to get the interface to the body of the program */
#include "nic.h"
/* to get the PCI support functions, if this is a PCI NIC */
#include <ipxe/pci.h>
#include "mii.h"

#define drv_version "v1.12"
#define drv_date "2004-03-21"

#define HZ 100

/* Condensed operations for readability. */
#define virt_to_le32desc(addr)  cpu_to_le32(virt_to_bus(addr))
#define le32desc_to_virt(addr)  bus_to_virt(le32_to_cpu(addr))

/* Set the mtu */
static int mtu = 1514;

/* Maximum number of multicast addresses to filter (vs. rx-all-multicast).
   The sundance uses a 64 element hash table based on the Ethernet CRC.  */
// static int multicast_filter_limit = 32;

/* Set the copy breakpoint for the copy-only-tiny-frames scheme.
   Setting to > 1518 effectively disables this feature.
   This chip can receive into any byte alignment buffers, so word-oriented
   archs do not need a copy-align of the IP header. */
static int rx_copybreak = 0;
static int flowctrl = 1;

/* Allow forcing the media type */
/* media[] specifies the media type the NIC operates at.
		 autosense	Autosensing active media.
		 10mbps_hd 	10Mbps half duplex.
		 10mbps_fd 	10Mbps full duplex.
		 100mbps_hd 	100Mbps half duplex.
		 100mbps_fd 	100Mbps full duplex.
*/
static char media[] = "autosense";

/* Operational parameters that are set at compile time. */

/* As Etherboot uses a Polling driver  we can keep the number of rings
to the minimum number required.  In general that is 1 transmit and 4 receive receive rings.  However some cards require that
there be a minimum of 2 rings  */
#define TX_RING_SIZE	2
#define TX_QUEUE_LEN	10	/* Limit ring entries actually used.  */
#define RX_RING_SIZE	4


/* Operational parameters that usually are not changed. */
/* Time in jiffies before concluding the transmitter is hung. */
#define TX_TIME_OUT	  (4*HZ)
#define PKT_BUF_SZ	1536

/* Offsets to the device registers.
   Unlike software-only systems, device drivers interact with complex hardware.
   It's not useful to define symbolic names for every register bit in the
   device.  The name can only partially document the semantics and make
   the driver longer and more difficult to read.
   In general, only the important configuration values or bits changed
   multiple times should be defined symbolically.
*/
enum alta_offsets {
	DMACtrl = 0x00,
	TxListPtr = 0x04,
	TxDMABurstThresh = 0x08,
	TxDMAUrgentThresh = 0x09,
	TxDMAPollPeriod = 0x0a,
	RxDMAStatus = 0x0c,
	RxListPtr = 0x10,
	DebugCtrl0 = 0x1a,
	DebugCtrl1 = 0x1c,
	RxDMABurstThresh = 0x14,
	RxDMAUrgentThresh = 0x15,
	RxDMAPollPeriod = 0x16,
	LEDCtrl = 0x1a,
	ASICCtrl = 0x30,
	EEData = 0x34,
	EECtrl = 0x36,
	TxStartThresh = 0x3c,
	RxEarlyThresh = 0x3e,
	FlashAddr = 0x40,
	FlashData = 0x44,
	TxStatus = 0x46,
	TxFrameId = 0x47,
	DownCounter = 0x18,
	IntrClear = 0x4a,
	IntrEnable = 0x4c,
	IntrStatus = 0x4e,
	MACCtrl0 = 0x50,
	MACCtrl1 = 0x52,
	StationAddr = 0x54,
	MaxFrameSize = 0x5A,
	RxMode = 0x5c,
	MIICtrl = 0x5e,
	MulticastFilter0 = 0x60,
	MulticastFilter1 = 0x64,
	RxOctetsLow = 0x68,
	RxOctetsHigh = 0x6a,
	TxOctetsLow = 0x6c,
	TxOctetsHigh = 0x6e,
	TxFramesOK = 0x70,
	RxFramesOK = 0x72,
	StatsCarrierError = 0x74,
	StatsLateColl = 0x75,
	StatsMultiColl = 0x76,
	StatsOneColl = 0x77,
	StatsTxDefer = 0x78,
	RxMissed = 0x79,
	StatsTxXSDefer = 0x7a,
	StatsTxAbort = 0x7b,
	StatsBcastTx = 0x7c,
	StatsBcastRx = 0x7d,
	StatsMcastTx = 0x7e,
	StatsMcastRx = 0x7f,
	/* Aliased and bogus values! */
	RxStatus = 0x0c,
};
enum ASICCtrl_HiWord_bit {
	GlobalReset = 0x0001,
	RxReset = 0x0002,
	TxReset = 0x0004,
	DMAReset = 0x0008,
	FIFOReset = 0x0010,
	NetworkReset = 0x0020,
	HostReset = 0x0040,
	ResetBusy = 0x0400,
};

/* Bits in the interrupt status/mask registers. */
enum intr_status_bits {
	IntrSummary = 0x0001, IntrPCIErr = 0x0002, IntrMACCtrl = 0x0008,
	IntrTxDone = 0x0004, IntrRxDone = 0x0010, IntrRxStart = 0x0020,
	IntrDrvRqst = 0x0040,
	StatsMax = 0x0080, LinkChange = 0x0100,
	IntrTxDMADone = 0x0200, IntrRxDMADone = 0x0400,
};

/* Bits in the RxMode register. */
enum rx_mode_bits {
	AcceptAllIPMulti = 0x20, AcceptMultiHash = 0x10, AcceptAll = 0x08,
	AcceptBroadcast = 0x04, AcceptMulticast = 0x02, AcceptMyPhys =
	    0x01,
};
/* Bits in MACCtrl. */
enum mac_ctrl0_bits {
	EnbFullDuplex = 0x20, EnbRcvLargeFrame = 0x40,
	EnbFlowCtrl = 0x100, EnbPassRxCRC = 0x200,
};
enum mac_ctrl1_bits {
	StatsEnable = 0x0020, StatsDisable = 0x0040, StatsEnabled = 0x0080,
	TxEnable = 0x0100, TxDisable = 0x0200, TxEnabled = 0x0400,
	RxEnable = 0x0800, RxDisable = 0x1000, RxEnabled = 0x2000,
};

/* The Rx and Tx buffer descriptors.
   Using only 32 bit fields simplifies software endian correction.
   This structure must be aligned, and should avoid spanning cache lines.
*/
struct netdev_desc {
	u32 next_desc;
	u32 status;
	u32 addr;
	u32 length;
};

/* Bits in netdev_desc.status */
enum desc_status_bits {
	DescOwn = 0x8000,
	DescEndPacket = 0x4000,
	DescEndRing = 0x2000,
	LastFrag = 0x80000000,
	DescIntrOnTx = 0x8000,
	DescIntrOnDMADone = 0x80000000,
	DisableAlign = 0x00000001,
};

/**********************************************
* Descriptor Ring and Buffer defination
***********************************************/
/* Define the TX Descriptor */
static struct netdev_desc tx_ring[TX_RING_SIZE];

/* Define the RX Descriptor */
static struct netdev_desc rx_ring[RX_RING_SIZE];

/* Create a static buffer of size PKT_BUF_SZ for each RX and TX descriptor.
   All descriptors point to a part of this buffer */
struct {
	unsigned char txb[PKT_BUF_SZ * TX_RING_SIZE];
	unsigned char rxb[RX_RING_SIZE * PKT_BUF_SZ];
} rx_tx_buf __shared;
#define rxb rx_tx_buf.rxb
#define txb rx_tx_buf.txb

/* FIXME: Move BASE to the private structure */
static u32 BASE;
#define EEPROM_SIZE	128

enum pci_id_flags_bits {
	PCI_USES_IO = 1, PCI_USES_MEM = 2, PCI_USES_MASTER = 4,
	PCI_ADDR0 = 0 << 4, PCI_ADDR1 = 1 << 4, PCI_ADDR2 =
	    2 << 4, PCI_ADDR3 = 3 << 4,
};

enum chip_capability_flags { CanHaveMII = 1, KendinPktDropBug = 2, };
#define PCI_IOTYPE (PCI_USES_MASTER | PCI_USES_IO  | PCI_ADDR0)

#define MII_CNT		4
static struct sundance_private {
	const char *nic_name;
	/* Frequently used values */

	unsigned int cur_rx;	/* Producer/consumer ring indices */
	unsigned int mtu;

	/* These values keep track of the tranceiver/media in use */
	unsigned int flowctrl:1;
	unsigned int an_enable:1;

	unsigned int speed;

	/* MII tranceiver section */
	struct mii_if_info mii_if;
	int mii_preamble_required;
	unsigned char phys[MII_CNT];
	unsigned char pci_rev_id;
} sdx;

static struct sundance_private *sdc;

/* Station Address location within the EEPROM */
#define EEPROM_SA_OFFSET	0x10
#define DEFAULT_INTR (IntrRxDMADone | IntrPCIErr | \
                        IntrDrvRqst | IntrTxDone | StatsMax | \
                        LinkChange)

static int eeprom_read(long ioaddr, int location);
static int mdio_read(struct nic *nic, int phy_id, unsigned int location);
static void mdio_write(struct nic *nic, int phy_id, unsigned int location,
		       int value);
static void set_rx_mode(struct nic *nic);

static void check_duplex(struct nic *nic)
{
	int mii_lpa = mdio_read(nic, sdc->phys[0], MII_LPA);
	int negotiated = mii_lpa & sdc->mii_if.advertising;
	int duplex;

	/* Force media */
	if (!sdc->an_enable || mii_lpa == 0xffff) {
		if (sdc->mii_if.full_duplex)
			outw(inw(BASE + MACCtrl0) | EnbFullDuplex,
			     BASE + MACCtrl0);
		return;
	}

	/* Autonegotiation */
	duplex = (negotiated & 0x0100) || (negotiated & 0x01C0) == 0x0040;
	if (sdc->mii_if.full_duplex != duplex) {
		sdc->mii_if.full_duplex = duplex;
		DBG ("%s: Setting %s-duplex based on MII #%d "
			 "negotiated capability %4.4x.\n", sdc->nic_name,
			 duplex ? "full" : "half", sdc->phys[0],
			 negotiated );
		outw(inw(BASE + MACCtrl0) | duplex ? 0x20 : 0,
		     BASE + MACCtrl0);
	}
}


/**************************************************************************
 *  init_ring - setup the tx and rx descriptors
 *************************************************************************/
static void init_ring(struct nic *nic __unused)
{
	int i;

	sdc->cur_rx = 0;

	/* Initialize all the Rx descriptors */
	for (i = 0; i < RX_RING_SIZE; i++) {
		rx_ring[i].next_desc = virt_to_le32desc(&rx_ring[i + 1]);
		rx_ring[i].status = 0;
		rx_ring[i].length = 0;
		rx_ring[i].addr = 0;
	}

	/* Mark the last entry as wrapping the ring */
	rx_ring[i - 1].next_desc = virt_to_le32desc(&rx_ring[0]);

	for (i = 0; i < RX_RING_SIZE; i++) {
		rx_ring[i].addr = virt_to_le32desc(&rxb[i * PKT_BUF_SZ]);
		rx_ring[i].length = cpu_to_le32(PKT_BUF_SZ | LastFrag);
	}

	/* We only use one transmit buffer, but two
	 * descriptors so transmit engines have somewhere
	 * to point should they feel the need */
	tx_ring[0].status = 0x00000000;
	tx_ring[0].addr = virt_to_bus(&txb[0]);
	tx_ring[0].next_desc = 0;	/* virt_to_bus(&tx_ring[1]); */

	/* This descriptor is never used */
	tx_ring[1].status = 0x00000000;
	tx_ring[1].addr = 0;	/*virt_to_bus(&txb[0]); */
	tx_ring[1].next_desc = 0;

	/* Mark the last entry as wrapping the ring,
	 * though this should never happen */
	tx_ring[1].length = cpu_to_le32(LastFrag | PKT_BUF_SZ);
}

/**************************************************************************
 *  RESET - Reset Adapter
 * ***********************************************************************/
static void sundance_reset(struct nic *nic)
{
	int i;

	init_ring(nic);

	outl(virt_to_le32desc(&rx_ring[0]), BASE + RxListPtr);
	/* The Tx List Pointer is written as packets are queued */

	/* Initialize other registers. */
	/* __set_mac_addr(dev); */
	{
		u16 addr16;

		addr16 = (nic->node_addr[0] | (nic->node_addr[1] << 8));
		outw(addr16, BASE + StationAddr);
		addr16 = (nic->node_addr[2] | (nic->node_addr[3] << 8));
		outw(addr16, BASE + StationAddr + 2);
		addr16 = (nic->node_addr[4] | (nic->node_addr[5] << 8));
		outw(addr16, BASE + StationAddr + 4);
	}

	outw(sdc->mtu + 14, BASE + MaxFrameSize);
	if (sdc->mtu > 2047)	/* this will never happen with default options */
		outl(inl(BASE + ASICCtrl) | 0x0c, BASE + ASICCtrl);

	set_rx_mode(nic);

	outw(0, BASE + DownCounter);
	/* Set the chip to poll every N*30nsec */
	outb(100, BASE + RxDMAPollPeriod);

	/* Fix DFE-580TX packet drop issue */
	if (sdc->pci_rev_id >= 0x14)
		writeb(0x01, BASE + DebugCtrl1);

	outw(RxEnable | TxEnable, BASE + MACCtrl1);

	/* Construct a perfect filter frame with the mac address as first match
	 * and broadcast for all others */
	for (i = 0; i < 192; i++)
		txb[i] = 0xFF;

	txb[0] = nic->node_addr[0];
	txb[1] = nic->node_addr[1];
	txb[2] = nic->node_addr[2];
	txb[3] = nic->node_addr[3];
	txb[4] = nic->node_addr[4];
	txb[5] = nic->node_addr[5];

	DBG ( "%s: Done sundance_reset, status: Rx %hX Tx %hX "
	      "MAC Control %hX, %hX %hX\n",
	      sdc->nic_name, (int) inl(BASE + RxStatus),
	      (int) inw(BASE + TxStatus), (int) inl(BASE + MACCtrl0),
	      (int) inw(BASE + MACCtrl1), (int) inw(BASE + MACCtrl0) );
}

/**************************************************************************
IRQ - Wait for a frame
***************************************************************************/
static void sundance_irq ( struct nic *nic, irq_action_t action ) {
        unsigned int intr_status;

	switch ( action ) {
	case DISABLE :
	case ENABLE :
		intr_status = inw(nic->ioaddr + IntrStatus);
		intr_status = intr_status & ~DEFAULT_INTR;
		if ( action == ENABLE ) 
			intr_status = intr_status | DEFAULT_INTR;
		outw(intr_status, nic->ioaddr + IntrEnable);
		break;
        case FORCE :
		outw(0x0200, BASE + ASICCtrl);
		break;
        }
}
/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static int sundance_poll(struct nic *nic, int retrieve)
{
	/* return true if there's an ethernet packet ready to read */
	/* nic->packet should contain data on return */
	/* nic->packetlen should contain length of data */
	int entry = sdc->cur_rx % RX_RING_SIZE;
	u32 frame_status = le32_to_cpu(rx_ring[entry].status);
	int intr_status;
	int pkt_len = 0;

	if (!(frame_status & DescOwn))
		return 0;

	/* There is a packet ready */
	if(!retrieve)
		return 1;

	intr_status = inw(nic->ioaddr + IntrStatus);
	outw(intr_status, nic->ioaddr + IntrStatus);

	pkt_len = frame_status & 0x1fff;

	if (frame_status & 0x001f4000) {
		DBG ( "Polling frame_status error\n" );	/* Do we really care about this */
	} else {
		if (pkt_len < rx_copybreak) {
			/* FIXME: What should happen Will this ever occur */
			printf("Poll Error: pkt_len < rx_copybreak");
		} else {
			nic->packetlen = pkt_len;
			memcpy(nic->packet, rxb +
			       (sdc->cur_rx * PKT_BUF_SZ), nic->packetlen);

		}
	}
	rx_ring[entry].length = cpu_to_le32(PKT_BUF_SZ | LastFrag);
	rx_ring[entry].status = 0;
	entry++;
	sdc->cur_rx = entry % RX_RING_SIZE;
	outw(DEFAULT_INTR & ~(IntrRxDone|IntrRxDMADone), 
		nic->ioaddr + IntrStatus);
	return 1;
}

/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static void sundance_transmit(struct nic *nic, const char *d,	/* Destination */
			      unsigned int t,	/* Type */
			      unsigned int s,	/* size */
			      const char *p)
{				/* Packet */
	u16 nstype;
	u32 to;

	/* Disable the Tx */
	outw(TxDisable, BASE + MACCtrl1);

	memcpy(txb, d, ETH_ALEN);
	memcpy(txb + ETH_ALEN, nic->node_addr, ETH_ALEN);
	nstype = htons((u16) t);
	memcpy(txb + 2 * ETH_ALEN, (u8 *) & nstype, 2);
	memcpy(txb + ETH_HLEN, p, s);

	s += ETH_HLEN;
	s &= 0x0FFF;
	while (s < ETH_ZLEN)
		txb[s++] = '\0';

	/* Setup the transmit descriptor */
	tx_ring[0].length = cpu_to_le32(s | LastFrag);
	tx_ring[0].status = cpu_to_le32(0x00000001);

	/* Point to transmit descriptor */
	outl(virt_to_le32desc(&tx_ring[0]), BASE + TxListPtr);

	/* Enable Tx */
	outw(TxEnable, BASE + MACCtrl1);
	/* Trigger an immediate send */
	outw(0, BASE + TxStatus);

	to = currticks() + TX_TIME_OUT;
	while (!(tx_ring[0].status & 0x00010000) && (currticks() < to));	/* wait */

	if (currticks() >= to) {
		printf("TX Time Out");
	}
	/* Disable Tx */
	outw(TxDisable, BASE + MACCtrl1);

}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void sundance_disable ( struct nic *nic __unused ) {
	/* put the card in its initial state */
	/* This function serves 3 purposes.
	 * This disables DMA and interrupts so we don't receive
	 *  unexpected packets or interrupts from the card after
	 *  etherboot has finished.
	 * This frees resources so etherboot may use
	 *  this driver on another interface
	 * This allows etherboot to reinitialize the interface
	 *  if something is something goes wrong.
	 */
	outw(0x0000, BASE + IntrEnable);
	/* Stop the Chipchips Tx and Rx Status */
	outw(TxDisable | RxDisable | StatsDisable, BASE + MACCtrl1);
}

static struct nic_operations sundance_operations = {
	.connect	= dummy_connect,
	.poll		= sundance_poll,
	.transmit	= sundance_transmit,
	.irq		= sundance_irq,

};

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
***************************************************************************/
static int sundance_probe ( struct nic *nic, struct pci_device *pci ) {

	u8 ee_data[EEPROM_SIZE];
	u16 mii_ctl;
	int i;
	int speed;

	if (pci->ioaddr == 0)
		return 0;

	/* BASE is used throughout to address the card */
	BASE = pci->ioaddr;
	printf(" sundance.c: Found %s Vendor=0x%hX Device=0x%hX\n",
	       pci->id->name, pci->vendor, pci->device);

	/* Get the MAC Address by reading the EEPROM */
	for (i = 0; i < 3; i++) {
		((u16 *) ee_data)[i] =
		    le16_to_cpu(eeprom_read(BASE, i + EEPROM_SA_OFFSET));
	}
	/* Update the nic structure with the MAC Address */
	for (i = 0; i < ETH_ALEN; i++) {
		nic->node_addr[i] = ee_data[i];
	}

	/* Set the card as PCI Bus Master */
	adjust_pci_device(pci);

//      sdc->mii_if.dev = pci;
//      sdc->mii_if.phy_id_mask = 0x1f;
//      sdc->mii_if.reg_num_mask = 0x1f;

	/* point to private storage */
	sdc = &sdx;

	sdc->nic_name = pci->id->name;
	sdc->mtu = mtu;

	pci_read_config_byte(pci, PCI_REVISION, &sdc->pci_rev_id);

	DBG ( "Device revision id: %hx\n", sdc->pci_rev_id );

	/* Print out some hardware info */
	DBG ( "%s: %s at ioaddr %hX, ",
	      pci->id->name, nic->node_addr, (unsigned int) BASE);

	sdc->mii_preamble_required = 0;
	if (1) {
		int phy, phy_idx = 0;
		sdc->phys[0] = 1;	/* Default Setting */
		sdc->mii_preamble_required++;
		for (phy = 1; phy < 32 && phy_idx < MII_CNT; phy++) {
			int mii_status = mdio_read(nic, phy, MII_BMSR);
			if (mii_status != 0xffff && mii_status != 0x0000) {
				sdc->phys[phy_idx++] = phy;
				sdc->mii_if.advertising =
				    mdio_read(nic, phy, MII_ADVERTISE);
				if ((mii_status & 0x0040) == 0)
					sdc->mii_preamble_required++;
				DBG 
				    ( "%s: MII PHY found at address %d, status " "%hX advertising %hX\n", sdc->nic_name, phy, mii_status, sdc->mii_if.advertising );
			}
		}
		sdc->mii_preamble_required--;
		if (phy_idx == 0)
			printf("%s: No MII transceiver found!\n",
			       sdc->nic_name);
		sdc->mii_if.phy_id = sdc->phys[0];
	}

	/* Parse override configuration */
	sdc->an_enable = 1;
	if (strcasecmp(media, "autosense") != 0) {
		sdc->an_enable = 0;
		if (strcasecmp(media, "100mbps_fd") == 0 ||
		    strcasecmp(media, "4") == 0) {
			sdc->speed = 100;
			sdc->mii_if.full_duplex = 1;
		} else if (strcasecmp(media, "100mbps_hd") == 0
			   || strcasecmp(media, "3") == 0) {
			sdc->speed = 100;
			sdc->mii_if.full_duplex = 0;
		} else if (strcasecmp(media, "10mbps_fd") == 0 ||
			   strcasecmp(media, "2") == 0) {
			sdc->speed = 10;
			sdc->mii_if.full_duplex = 1;
		} else if (strcasecmp(media, "10mbps_hd") == 0 ||
			   strcasecmp(media, "1") == 0) {
			sdc->speed = 10;
			sdc->mii_if.full_duplex = 0;
		} else {
			sdc->an_enable = 1;
		}
	}
	if (flowctrl == 1)
		sdc->flowctrl = 1;

	/* Fibre PHY? */
	if (inl(BASE + ASICCtrl) & 0x80) {
		/* Default 100Mbps Full */
		if (sdc->an_enable) {
			sdc->speed = 100;
			sdc->mii_if.full_duplex = 1;
			sdc->an_enable = 0;
		}
	}

	/* The Linux driver uses flow control and resets the link here.  This means the
	   mii section from above would need to be re done I believe.  Since it serves
	   no real purpose leave it out. */

	/* Force media type */
	if (!sdc->an_enable) {
		mii_ctl = 0;
		mii_ctl |= (sdc->speed == 100) ? BMCR_SPEED100 : 0;
		mii_ctl |= (sdc->mii_if.full_duplex) ? BMCR_FULLDPLX : 0;
		mdio_write(nic, sdc->phys[0], MII_BMCR, mii_ctl);
		printf("Override speed=%d, %s duplex\n",
		       sdc->speed,
		       sdc->mii_if.full_duplex ? "Full" : "Half");
	}

	/* Reset the chip to erase previous misconfiguration */
	DBG ( "ASIC Control is %#x\n", inl(BASE + ASICCtrl) );
	outw(0x007f, BASE + ASICCtrl + 2);

	/*
	* wait for reset to complete
	* this is heavily inspired by the linux sundance driver
	* according to the linux driver it can take up to 1ms for the reset
	* to complete
	*/
	i = 0;
	while(inl(BASE + ASICCtrl) & (ResetBusy << 16)) {
		if(i++ >= 10) {
			DBG("sundance: NIC reset did not complete.\n");
			break;
		}
		udelay(100);
	}

	DBG ( "ASIC Control is now %#x.\n", inl(BASE + ASICCtrl) );

	sundance_reset(nic);
	if (sdc->an_enable) {
		u16 mii_advertise, mii_lpa;
		mii_advertise =
		    mdio_read(nic, sdc->phys[0], MII_ADVERTISE);
		mii_lpa = mdio_read(nic, sdc->phys[0], MII_LPA);
		mii_advertise &= mii_lpa;
		if (mii_advertise & ADVERTISE_100FULL)
			sdc->speed = 100;
		else if (mii_advertise & ADVERTISE_100HALF)
			sdc->speed = 100;
		else if (mii_advertise & ADVERTISE_10FULL)
			sdc->speed = 10;
		else if (mii_advertise & ADVERTISE_10HALF)
			sdc->speed = 10;
	} else {
		mii_ctl = mdio_read(nic, sdc->phys[0], MII_BMCR);
		speed = (mii_ctl & BMCR_SPEED100) ? 100 : 10;
		sdc->speed = speed;
		printf("%s: Link changed: %dMbps ,", sdc->nic_name, speed);
		printf("%s duplex.\n", (mii_ctl & BMCR_FULLDPLX) ?
		       "full" : "half");
	}
	check_duplex(nic);
	if (sdc->flowctrl && sdc->mii_if.full_duplex) {
		outw(inw(BASE + MulticastFilter1 + 2) | 0x0200,
		     BASE + MulticastFilter1 + 2);
		outw(inw(BASE + MACCtrl0) | EnbFlowCtrl, BASE + MACCtrl0);
	}
	printf("%dMbps, %s-Duplex\n", sdc->speed,
	       sdc->mii_if.full_duplex ? "Full" : "Half");

	/* point to NIC specific routines */
	nic->nic_op	= &sundance_operations;

	nic->irqno  = pci->irq;
	nic->ioaddr = BASE;

	return 1;
}


/* Read the EEPROM and MII Management Data I/O (MDIO) interfaces. */
static int eeprom_read(long ioaddr, int location)
{
	int boguscnt = 10000;	/* Typical 1900 ticks */
	outw(0x0200 | (location & 0xff), ioaddr + EECtrl);
	do {
		if (!(inw(ioaddr + EECtrl) & 0x8000)) {
			return inw(ioaddr + EEData);
		}
	}
	while (--boguscnt > 0);
	return 0;
}

/*  MII transceiver control section.
	Read and write the MII registers using software-generated serial
	MDIO protocol.  See the MII specifications or DP83840A data sheet
	for details.

	The maximum data clock rate is 2.5 Mhz.
	The timing is decoupled from the processor clock by flushing the write
	from the CPU write buffer with a following read, and using PCI
	transaction time. */

#define mdio_in(mdio_addr) inb(mdio_addr)
#define mdio_out(value, mdio_addr) outb(value, mdio_addr)
#define mdio_delay(mdio_addr) inb(mdio_addr)

enum mii_reg_bits {
	MDIO_ShiftClk = 0x0001, MDIO_Data = 0x0002, MDIO_EnbOutput =
	    0x0004,
};
#define MDIO_EnbIn  (0)
#define MDIO_WRITE0 (MDIO_EnbOutput)
#define MDIO_WRITE1 (MDIO_Data | MDIO_EnbOutput)

/* Generate the preamble required for initial synchronization and
   a few older transceivers. */
static void mdio_sync(long mdio_addr)
{
	int bits = 32;

	/* Establish sync by sending at least 32 logic ones. */
	while (--bits >= 0) {
		mdio_out(MDIO_WRITE1, mdio_addr);
		mdio_delay(mdio_addr);
		mdio_out(MDIO_WRITE1 | MDIO_ShiftClk, mdio_addr);
		mdio_delay(mdio_addr);
	}
}

static int
mdio_read(struct nic *nic __unused, int phy_id, unsigned int location)
{
	long mdio_addr = BASE + MIICtrl;
	int mii_cmd = (0xf6 << 10) | (phy_id << 5) | location;
	int i, retval = 0;

	if (sdc->mii_preamble_required)
		mdio_sync(mdio_addr);

	/* Shift the read command bits out. */
	for (i = 15; i >= 0; i--) {
		int dataval =
		    (mii_cmd & (1 << i)) ? MDIO_WRITE1 : MDIO_WRITE0;

		mdio_out(dataval, mdio_addr);
		mdio_delay(mdio_addr);
		mdio_out(dataval | MDIO_ShiftClk, mdio_addr);
		mdio_delay(mdio_addr);
	}
	/* Read the two transition, 16 data, and wire-idle bits. */
	for (i = 19; i > 0; i--) {
		mdio_out(MDIO_EnbIn, mdio_addr);
		mdio_delay(mdio_addr);
		retval = (retval << 1) | ((mdio_in(mdio_addr) & MDIO_Data)
					  ? 1 : 0);
		mdio_out(MDIO_EnbIn | MDIO_ShiftClk, mdio_addr);
		mdio_delay(mdio_addr);
	}
	return (retval >> 1) & 0xffff;
}

static void
mdio_write(struct nic *nic __unused, int phy_id,
	   unsigned int location, int value)
{
	long mdio_addr = BASE + MIICtrl;
	int mii_cmd =
	    (0x5002 << 16) | (phy_id << 23) | (location << 18) | value;
	int i;

	if (sdc->mii_preamble_required)
		mdio_sync(mdio_addr);

	/* Shift the command bits out. */
	for (i = 31; i >= 0; i--) {
		int dataval =
		    (mii_cmd & (1 << i)) ? MDIO_WRITE1 : MDIO_WRITE0;
		mdio_out(dataval, mdio_addr);
		mdio_delay(mdio_addr);
		mdio_out(dataval | MDIO_ShiftClk, mdio_addr);
		mdio_delay(mdio_addr);
	}
	/* Clear out extra bits. */
	for (i = 2; i > 0; i--) {
		mdio_out(MDIO_EnbIn, mdio_addr);
		mdio_delay(mdio_addr);
		mdio_out(MDIO_EnbIn | MDIO_ShiftClk, mdio_addr);
		mdio_delay(mdio_addr);
	}
	return;
}

static void set_rx_mode(struct nic *nic __unused)
{
	int i;
	u16 mc_filter[4];	/* Multicast hash filter */
	u32 rx_mode;

	memset(mc_filter, 0xff, sizeof(mc_filter));
	rx_mode = AcceptBroadcast | AcceptMulticast | AcceptMyPhys;

	if (sdc->mii_if.full_duplex && sdc->flowctrl)
		mc_filter[3] |= 0x0200;
	for (i = 0; i < 4; i++)
		outw(mc_filter[i], BASE + MulticastFilter0 + i * 2);
	outb(rx_mode, BASE + RxMode);
	return;
}

static struct pci_device_id sundance_nics[] = {
	PCI_ROM(0x13f0, 0x0201, "sundance", "ST201 Sundance 'Alta' based Adaptor", 0),
	PCI_ROM(0x1186, 0x1002, "dfe530txs", "D-Link DFE530TXS (Sundance ST201 Alta)", 0),
	PCI_ROM(0x13f0, 0x0200, "ip100a", "IC+ IP100A", 0),
};

PCI_DRIVER ( sundance_driver, sundance_nics, PCI_NO_CLASS );

DRIVER ( "SUNDANCE/PCI", nic_driver, pci_driver, sundance_driver,
	 sundance_probe, sundance_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
