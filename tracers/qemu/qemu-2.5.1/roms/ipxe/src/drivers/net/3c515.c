/*
*    3c515.c -- 3COM 3C515 Fast Etherlink ISA 10/100BASE-TX driver for etherboot
*    Copyright (C) 2002 Timothy Legge <tlegge@rogers.com>
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
* Portions of this code:
* Copyright (C) 1997-2002 Donald Becker  3c515.c: A 3Com ISA EtherLink XL "Corkscrew" ethernet driver for linux.
* Copyright (C) 2001 P.J.H.Fox (fox@roestock.demon.co.uk) ISAPNP Tools
* Copyright (c) 2002 Jaroslav Kysela <perex@suse.cz>  ISA Plug & Play support Linux Kernel
* Copyright (C) 2000 Shusuke Nisiyama <shu@athena.qe.eng.hokudai.ac.jp> etherboot-5.0.5 3c595.c
* Coptright (C) 1995 Martin Renters etherboot-5.0.5 3c509.c
* Copyright (C) 1999 LightSys Technology Services, Inc. etherboot-5.0.5 3c90x.c
* Portions Copyright (C) 1999 Steve Smith etherboot-5.0.5 3c90x.c
*
* The probe and reset functions and defines are direct copies from the
* Becker code modified where necessary to make it work for etherboot
*
* The poll and transmit functions either contain code from or were written by referencing
* the above referenced etherboot drivers.  This driver would not have been
* possible without this prior work
*
* REVISION HISTORY:
* ================
* v0.10	4-17-2002	TJL	Initial implementation.
* v0.11 4-17-2002       TJL     Cleanup of the code
* v0.12 4-26-2002       TJL     Added ISA Plug and Play for Non-PNP Bioses
* v0.13 6-10-2002       TJL     Fixed ISA_PNP MAC Address problem
* v0.14 9-23-2003	TJL	Replaced delay with currticks
*
* Indent Options: indent -kr -i8
* *********************************************************/

FILE_LICENCE ( GPL2_OR_LATER );

/* to get some global routines like printf */
#include "etherboot.h"
/* to get the interface to the body of the program */
#include "nic.h"
#include <ipxe/isapnp.h>
#include <ipxe/isa.h> /* for ISA_ROM */
#include <ipxe/ethernet.h>

static void t3c515_wait(unsigned int nticks)
{
	unsigned int to = currticks() + nticks;
	while (currticks() < to)
		/* wait */ ;
}

/* TJL definations */
#define HZ      100
static int if_port;
static struct corkscrew_private *vp;
/* Brought directly from 3c515.c by Becker */
#define CORKSCREW 1

/* Maximum events (Rx packets, etc.) to handle at each interrupt.
static int max_interrupt_work = 20;
*/

/* Enable the automatic media selection code -- usually set. */
#define AUTOMEDIA 1

/* Allow the use of fragment bus master transfers instead of only
   programmed-I/O for Vortex cards.  Full-bus-master transfers are always
   enabled by default on Boomerang cards.  If VORTEX_BUS_MASTER is defined,
   the feature may be turned on using 'options'. */
#define VORTEX_BUS_MASTER

/* A few values that may be tweaked. */
/* Keep the ring sizes a power of two for efficiency. */
#define TX_RING_SIZE	16
#define RX_RING_SIZE	16
#define PKT_BUF_SZ		1536	/* Size of each temporary Rx buffer. */

/* "Knobs" for adjusting internal parameters. */
/* Put out somewhat more debugging messages. (0 - no msg, 1 minimal msgs). */
#define DRIVER_DEBUG 1
/* Some values here only for performance evaluation and path-coverage
   debugging.
static int rx_nocopy, rx_copy, queued_packet;
*/

#define CORKSCREW_ID 10

#define EL3WINDOW(win_num) \
	outw(SelectWindow + (win_num), nic->ioaddr + EL3_CMD)
#define EL3_CMD 0x0e
#define EL3_STATUS 0x0e
#define RX_BYTES_MASK			(unsigned short) (0x07ff)

enum corkscrew_cmd {
	TotalReset = 0 << 11, SelectWindow = 1 << 11, StartCoax = 2 << 11,
	RxDisable = 3 << 11, RxEnable = 4 << 11, RxReset = 5 << 11,
	UpStall = 6 << 11, UpUnstall = (6 << 11) + 1,
	DownStall = (6 << 11) + 2, DownUnstall = (6 << 11) + 3,
	RxDiscard = 8 << 11, TxEnable = 9 << 11, TxDisable =
	    10 << 11, TxReset = 11 << 11,
	FakeIntr = 12 << 11, AckIntr = 13 << 11, SetIntrEnb = 14 << 11,
	SetStatusEnb = 15 << 11, SetRxFilter = 16 << 11, SetRxThreshold =
	    17 << 11,
	SetTxThreshold = 18 << 11, SetTxStart = 19 << 11,
	StartDMAUp = 20 << 11, StartDMADown = (20 << 11) + 1, StatsEnable =
	    21 << 11,
	StatsDisable = 22 << 11, StopCoax = 23 << 11,
};

/* The SetRxFilter command accepts the following classes: */
enum RxFilter {
	RxStation = 1, RxMulticast = 2, RxBroadcast = 4, RxProm = 8
};

/* Bits in the general status register. */
enum corkscrew_status {
	IntLatch = 0x0001, AdapterFailure = 0x0002, TxComplete = 0x0004,
	TxAvailable = 0x0008, RxComplete = 0x0010, RxEarly = 0x0020,
	IntReq = 0x0040, StatsFull = 0x0080,
	DMADone = 1 << 8, DownComplete = 1 << 9, UpComplete = 1 << 10,
	DMAInProgress = 1 << 11,	/* DMA controller is still busy. */
	CmdInProgress = 1 << 12,	/* EL3_CMD is still busy. */
};

/* Register window 1 offsets, the window used in normal operation.
   On the Corkscrew this window is always mapped at offsets 0x10-0x1f. */
enum Window1 {
	TX_FIFO = 0x10, RX_FIFO = 0x10, RxErrors = 0x14,
	RxStatus = 0x18, Timer = 0x1A, TxStatus = 0x1B,
	TxFree = 0x1C,		/* Remaining free bytes in Tx buffer. */
};
enum Window0 {
	Wn0IRQ = 0x08,
#if defined(CORKSCREW)
	Wn0EepromCmd = 0x200A,	/* Corkscrew EEPROM command register. */
	Wn0EepromData = 0x200C,	/* Corkscrew EEPROM results register. */
#else
	Wn0EepromCmd = 10,	/* Window 0: EEPROM command register. */
	Wn0EepromData = 12,	/* Window 0: EEPROM results register. */
#endif
};
enum Win0_EEPROM_bits {
	EEPROM_Read = 0x80, EEPROM_WRITE = 0x40, EEPROM_ERASE = 0xC0,
	EEPROM_EWENB = 0x30,	/* Enable erasing/writing for 10 msec. */
	EEPROM_EWDIS = 0x00,	/* Disable EWENB before 10 msec timeout. */
};

enum Window3 {			/* Window 3: MAC/config bits. */
	Wn3_Config = 0, Wn3_MAC_Ctrl = 6, Wn3_Options = 8,
};
union wn3_config {
	int i;
	struct w3_config_fields {
		unsigned int ram_size:3, ram_width:1, ram_speed:2,
		    rom_size:2;
		int pad8:8;
		unsigned int ram_split:2, pad18:2, xcvr:3, pad21:1,
		    autoselect:1;
		int pad24:7;
	} u;
};

enum Window4 {
	Wn4_NetDiag = 6, Wn4_Media = 10,	/* Window 4: Xcvr/media bits. */
};
enum Win4_Media_bits {
	Media_SQE = 0x0008,	/* Enable SQE error counting for AUI. */
	Media_10TP = 0x00C0,	/* Enable link beat and jabber for 10baseT. */
	Media_Lnk = 0x0080,	/* Enable just link beat for 100TX/100FX. */
	Media_LnkBeat = 0x0800,
};
enum Window7 {			/* Window 7: Bus Master control. */
	Wn7_MasterAddr = 0, Wn7_MasterLen = 6, Wn7_MasterStatus = 12,
};

/* Boomerang-style bus master control registers.  Note ISA aliases! */
enum MasterCtrl {
	PktStatus = 0x400, DownListPtr = 0x404, FragAddr = 0x408, FragLen =
	    0x40c,
	TxFreeThreshold = 0x40f, UpPktStatus = 0x410, UpListPtr = 0x418,
};

/* The Rx and Tx descriptor lists.
   Caution Alpha hackers: these types are 32 bits!  Note also the 8 byte
   alignment contraint on tx_ring[] and rx_ring[]. */
struct boom_rx_desc {
	u32 next;
	s32 status;
	u32 addr;
	s32 length;
};

/* Values for the Rx status entry. */
enum rx_desc_status {
	RxDComplete = 0x00008000, RxDError = 0x4000,
	/* See boomerang_rx() for actual error bits */
};

struct boom_tx_desc {
	u32 next;
	s32 status;
	u32 addr;
	s32 length;
};

struct corkscrew_private {
	const char *product_name;
	struct net_device *next_module;
	/* The Rx and Tx rings are here to keep them quad-word-aligned. */
	struct boom_rx_desc rx_ring[RX_RING_SIZE];
	struct boom_tx_desc tx_ring[TX_RING_SIZE];
	/* The addresses of transmit- and receive-in-place skbuffs. */
	struct sk_buff *rx_skbuff[RX_RING_SIZE];
	struct sk_buff *tx_skbuff[TX_RING_SIZE];
	unsigned int cur_rx, cur_tx;	/* The next free ring entry */
	unsigned int dirty_rx, dirty_tx;	/* The ring entries to be free()ed. */
	struct sk_buff *tx_skb;	/* Packet being eaten by bus master ctrl.  */
	int capabilities;	/* Adapter capabilities word. */
	int options;		/* User-settable misc. driver options. */
	int last_rx_packets;	/* For media autoselection. */
	unsigned int available_media:8,	/* From Wn3_Options */
	 media_override:3,	/* Passed-in media type. */
	 default_media:3,	/* Read from the EEPROM. */
	 full_duplex:1, autoselect:1, bus_master:1,	/* Vortex can only do a fragment bus-m. */
	 full_bus_master_tx:1, full_bus_master_rx:1,	/* Boomerang  */
	 tx_full:1;
};

/* The action to take with a media selection timer tick.
   Note that we deviate from the 3Com order by checking 10base2 before AUI.
 */
enum xcvr_types {
	XCVR_10baseT =
	    0, XCVR_AUI, XCVR_10baseTOnly, XCVR_10base2, XCVR_100baseTx,
	XCVR_100baseFx, XCVR_MII = 6, XCVR_Default = 8,
};

static struct media_table {
	char *name;
	unsigned int media_bits:16,	/* Bits to set in Wn4_Media register. */
	 mask:8,		/* The transceiver-present bit in Wn3_Config. */
	 next:8;		/* The media type to try next. */
	short wait;		/* Time before we check media status. */
} media_tbl[] = {
	{
	"10baseT", Media_10TP, 0x08, XCVR_10base2, (14 * HZ) / 10}
	, {
	"10Mbs AUI", Media_SQE, 0x20, XCVR_Default, (1 * HZ) / 10}
	, {
	"undefined", 0, 0x80, XCVR_10baseT, 10000}
	, {
	"10base2", 0, 0x10, XCVR_AUI, (1 * HZ) / 10}
	, {
	"100baseTX", Media_Lnk, 0x02, XCVR_100baseFx,
		    (14 * HZ) / 10}
	, {
	"100baseFX", Media_Lnk, 0x04, XCVR_MII, (14 * HZ) / 10}
	, {
	"MII", 0, 0x40, XCVR_10baseT, 3 * HZ}
	, {
	"undefined", 0, 0x01, XCVR_10baseT, 10000}
	, {
	"Default", 0, 0xFF, XCVR_10baseT, 10000}
,};

/* TILEG Modified to remove reference to dev */
static int corkscrew_found_device(int ioaddr, int irq, int product_index,
				  int options, struct nic *nic);
static int corkscrew_probe1(int ioaddr, int irq, int product_index,
			    struct nic *nic);

/* This driver uses 'options' to pass the media type, full-duplex flag, etc. */
/* Note: this is the only limit on the number of cards supported!! */
static int options = -1;

/* End Brought directly from 3c515.c by Becker */

/**************************************************************************
RESET - Reset adapter
***************************************************************************/
static void t515_reset(struct nic *nic)
{
	union wn3_config config;
	int i;

	/* Before initializing select the active media port. */
	EL3WINDOW(3);
	if (vp->full_duplex)
		outb(0x20, nic->ioaddr + Wn3_MAC_Ctrl);	/* Set the full-duplex bit. */
	config.i = inl(nic->ioaddr + Wn3_Config);

	if (vp->media_override != 7) {
		DBG ( "Media override to transceiver %d (%s).\n",
		      vp->media_override,
		      media_tbl[vp->media_override].name);
		if_port = vp->media_override;
	} else if (vp->autoselect) {
		/* Find first available media type, starting with 100baseTx. */
		if_port = 4;
		while (!(vp->available_media & media_tbl[if_port].mask))
			if_port = media_tbl[if_port].next;

		DBG ( "Initial media type %s.\n",
		      media_tbl[if_port].name);
	} else
		if_port = vp->default_media;

	config.u.xcvr = if_port;
	outl(config.i, nic->ioaddr + Wn3_Config);

	DBG ( "corkscrew_open() InternalConfig 0x%hX.\n",
	      config.i);

	outw(TxReset, nic->ioaddr + EL3_CMD);
	for (i = 20; i >= 0; i--)
		if (!(inw(nic->ioaddr + EL3_STATUS) & CmdInProgress))
			break;

	outw(RxReset, nic->ioaddr + EL3_CMD);
	/* Wait a few ticks for the RxReset command to complete. */
	for (i = 20; i >= 0; i--)
		if (!(inw(nic->ioaddr + EL3_STATUS) & CmdInProgress))
			break;

	outw(SetStatusEnb | 0x00, nic->ioaddr + EL3_CMD);

#ifdef debug_3c515
		EL3WINDOW(4);
		DBG ( "FIXME: fix print for irq, not 9" );
		DBG ( "corkscrew_open() irq %d media status 0x%hX.\n",
		      9, inw(nic->ioaddr + Wn4_Media) );
#endif

	/* Set the station address and mask in window 2 each time opened. */
	EL3WINDOW(2);
	for (i = 0; i < 6; i++)
		outb(nic->node_addr[i], nic->ioaddr + i);
	for (; i < 12; i += 2)
		outw(0, nic->ioaddr + i);

	if (if_port == 3)
		/* Start the thinnet transceiver. We should really wait 50ms... */
		outw(StartCoax, nic->ioaddr + EL3_CMD);
	EL3WINDOW(4);
	outw((inw(nic->ioaddr + Wn4_Media) & ~(Media_10TP | Media_SQE)) |
	     media_tbl[if_port].media_bits, nic->ioaddr + Wn4_Media);

	/* Switch to the stats window, and clear all stats by reading. */
/*	outw(StatsDisable, nic->ioaddr + EL3_CMD);*/
	EL3WINDOW(6);
	for (i = 0; i < 10; i++)
		inb(nic->ioaddr + i);
	inw(nic->ioaddr + 10);
	inw(nic->ioaddr + 12);
	/* New: On the Vortex we must also clear the BadSSD counter. */
	EL3WINDOW(4);
	inb(nic->ioaddr + 12);
	/* ..and on the Boomerang we enable the extra statistics bits. */
	outw(0x0040, nic->ioaddr + Wn4_NetDiag);

	/* Switch to register set 7 for normal use. */
	EL3WINDOW(7);

	/* Temporarily left in place.  If these FIXMEs are printed
	   it meand that special logic for that card may need to be added
	   see Becker's 3c515.c driver */
	if (vp->full_bus_master_rx) {	/* Boomerang bus master. */
		printf("FIXME: Is this if necessary");
		vp->cur_rx = vp->dirty_rx = 0;
		DBG ( "   Filling in the Rx ring.\n" );
		for (i = 0; i < RX_RING_SIZE; i++) {
			printf("FIXME: Is this if necessary");
		}
	}
	if (vp->full_bus_master_tx) {	/* Boomerang bus master Tx. */
		vp->cur_tx = vp->dirty_tx = 0;
		outb(PKT_BUF_SZ >> 8, nic->ioaddr + TxFreeThreshold);	/* Room for a packet. */
		/* Clear the Tx ring. */
		for (i = 0; i < TX_RING_SIZE; i++)
			vp->tx_skbuff[i] = NULL;
		outl(0, nic->ioaddr + DownListPtr);
	}
	/* Set receiver mode: presumably accept b-case and phys addr only. */
	outw(SetRxFilter | RxStation | RxMulticast | RxBroadcast | RxProm,
	     nic->ioaddr + EL3_CMD);

	outw(RxEnable, nic->ioaddr + EL3_CMD);	/* Enable the receiver. */
	outw(TxEnable, nic->ioaddr + EL3_CMD);	/* Enable transmitter. */
	/* Allow status bits to be seen. */
	outw(SetStatusEnb | AdapterFailure | IntReq | StatsFull |
	     (vp->full_bus_master_tx ? DownComplete : TxAvailable) |
	     (vp->full_bus_master_rx ? UpComplete : RxComplete) |
	     (vp->bus_master ? DMADone : 0), nic->ioaddr + EL3_CMD);
	/* Ack all pending events, and set active indicator mask. */
	outw(AckIntr | IntLatch | TxAvailable | RxEarly | IntReq,
	     nic->ioaddr + EL3_CMD);
	outw(SetIntrEnb | IntLatch | TxAvailable | RxComplete | StatsFull
	     | (vp->bus_master ? DMADone : 0) | UpComplete | DownComplete,
	     nic->ioaddr + EL3_CMD);

}

/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static int t515_poll(struct nic *nic, int retrieve)
{
	short status, cst;
	register short rx_fifo;

	cst = inw(nic->ioaddr + EL3_STATUS);

	if ((cst & RxComplete) == 0) {
		/* Ack all pending events, and set active indicator mask. */
		outw(AckIntr | IntLatch | TxAvailable | RxEarly | IntReq,
		     nic->ioaddr + EL3_CMD);
		outw(SetIntrEnb | IntLatch | TxAvailable | RxComplete |
		     StatsFull | (vp->
				  bus_master ? DMADone : 0) | UpComplete |
		     DownComplete, nic->ioaddr + EL3_CMD);
		return 0;
	}
	status = inw(nic->ioaddr + RxStatus);

	if (status & RxDError) {
		printf("RxDError\n");
		outw(RxDiscard, nic->ioaddr + EL3_CMD);
		return 0;
	}

	rx_fifo = status & RX_BYTES_MASK;
	if (rx_fifo == 0)
		return 0;

	if ( ! retrieve ) return 1;

	DBG ( "[l=%d", rx_fifo );
	insw(nic->ioaddr + RX_FIFO, nic->packet, rx_fifo / 2);
	if (rx_fifo & 1)
		nic->packet[rx_fifo - 1] = inb(nic->ioaddr + RX_FIFO);
	nic->packetlen = rx_fifo;

	while (1) {
		status = inw(nic->ioaddr + RxStatus);
		DBG ( "0x%hX*", status );
		rx_fifo = status & RX_BYTES_MASK;

		if (rx_fifo > 0) {
			insw(nic->ioaddr + RX_FIFO, nic->packet + nic->packetlen,
			     rx_fifo / 2);
			if (rx_fifo & 1)
				nic->packet[nic->packetlen + rx_fifo - 1] =
				    inb(nic->ioaddr + RX_FIFO);
			nic->packetlen += rx_fifo;
			DBG ( "+%d", rx_fifo );
		}
		if ((status & RxComplete) == 0) {
			DBG ( "=%d", nic->packetlen );
			break;
		}
		udelay(1000);
	}

	/* acknowledge reception of packet */
	outw(RxDiscard, nic->ioaddr + EL3_CMD);
	while (inw(nic->ioaddr + EL3_STATUS) & CmdInProgress);
#ifdef debug_3c515
	{
		unsigned short type = 0;
		type = (nic->packet[12] << 8) | nic->packet[13];
		if (nic->packet[0] + nic->packet[1] + nic->packet[2] +
		    nic->packet[3] + nic->packet[4] + nic->packet[5] ==
		    0xFF * ETH_ALEN)
			DBG ( ",t=0x%hX,b]", type );
		else
			DBG ( ",t=0x%hX]", type );
	}
#endif

	return 1;
}

/*************************************************************************
	3Com 515 - specific routines
**************************************************************************/
static char padmap[] = {
	0, 3, 2, 1
};
/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static void t515_transmit(struct nic *nic, const char *d,	/* Destination */
			  unsigned int t,	/* Type */
			  unsigned int s,	/* size */
			  const char *p)
{				/* Packet */
	register int len;
	int pad;
	int status;

	DBG ( "{l=%d,t=0x%hX}", s + ETH_HLEN, t );

	/* swap bytes of type */
	t = htons(t);

	len = s + ETH_HLEN;	/* actual length of packet */
	pad = padmap[len & 3];

	/*
	 * The 3c515 automatically pads short packets to minimum ethernet length,
	 * but we drop packets that are too large. Perhaps we should truncate
	 * them instead?
	 Copied from 3c595.  Is this true for the 3c515?
	 */
	if (len + pad > ETH_FRAME_LEN) {
		return;
	}
	/* drop acknowledgements */
	while ((status = inb(nic->ioaddr + TxStatus)) & TxComplete) {
		/*if(status & (TXS_UNDERRUN|0x88|TXS_STATUS_OVERFLOW)) { */
		outw(TxReset, nic->ioaddr + EL3_CMD);
		outw(TxEnable, nic->ioaddr + EL3_CMD);
/*		}                                                          */

		outb(0x0, nic->ioaddr + TxStatus);
	}

	while (inw(nic->ioaddr + TxFree) < len + pad + 4) {
		/* no room in FIFO */
	}

	outw(len, nic->ioaddr + TX_FIFO);
	outw(0x0, nic->ioaddr + TX_FIFO);	/* Second dword meaningless */

	/* write packet */
	outsw(nic->ioaddr + TX_FIFO, d, ETH_ALEN / 2);
	outsw(nic->ioaddr + TX_FIFO, nic->node_addr, ETH_ALEN / 2);
	outw(t, nic->ioaddr + TX_FIFO);
	outsw(nic->ioaddr + TX_FIFO, p, s / 2);

	if (s & 1)
		outb(*(p + s - 1), nic->ioaddr + TX_FIFO);

	while (pad--)
		outb(0, nic->ioaddr + TX_FIFO);	/* Padding */

	/* wait for Tx complete */
	while ((inw(nic->ioaddr + EL3_STATUS) & CmdInProgress) != 0);
}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void t515_disable ( struct nic *nic,
			   struct isapnp_device *isapnp ) {

	t515_reset(nic);

	/* This is a hack.  Since ltsp worked on my
	   system without any disable functionality I
	   have no way to determine if this works */

	/* Disable the receiver and transmitter. */
	outw(RxDisable, nic->ioaddr + EL3_CMD);
	outw(TxDisable, nic->ioaddr + EL3_CMD);

	if (if_port == XCVR_10base2)
		/* Turn off thinnet power.  Green! */
		outw(StopCoax, nic->ioaddr + EL3_CMD);


	outw(SetIntrEnb | 0x0000, nic->ioaddr + EL3_CMD);

	deactivate_isapnp_device ( isapnp );
	return;
}

static void t515_irq(struct nic *nic __unused, irq_action_t action __unused)
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

static struct nic_operations t515_operations = {
	.connect	= dummy_connect,
	.poll		= t515_poll,
	.transmit	= t515_transmit,
	.irq		= t515_irq,

};

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
You should omit the last argument struct pci_device * for a non-PCI NIC
***************************************************************************/
static int t515_probe ( struct nic *nic, struct isapnp_device *isapnp ) {

	/* Direct copy from Beckers 3c515.c removing any ISAPNP sections */

	nic->ioaddr = isapnp->ioaddr;
	nic->irqno = isapnp->irqno;
	activate_isapnp_device ( isapnp );

	/* Check the resource configuration for a matching ioaddr. */
	if ((unsigned)(inw(nic->ioaddr + 0x2002) & 0x1f0)
	    != (nic->ioaddr & 0x1f0)) {
		DBG ( "3c515 ioaddr mismatch\n" );
		return 0;
	}

	/* Verify by reading the device ID from the EEPROM. */
	{
		int timer;
		outw(EEPROM_Read + 7, nic->ioaddr + Wn0EepromCmd);
		/* Pause for at least 162 us. for the read to take place. */
		for (timer = 4; timer >= 0; timer--) {
			t3c515_wait(1);
			if ((inw(nic->ioaddr + Wn0EepromCmd) & 0x0200) == 0)
				break;
		}
		if (inw(nic->ioaddr + Wn0EepromData) != 0x6d50) {
			DBG ( "3c515 read incorrect vendor ID from EEPROM" );
			return 0;
		}

	}
	DBG ( "3c515 Resource configuration register 0x%X, DCR 0x%hX.\n",
	      inl(nic->ioaddr + 0x2002), inw(nic->ioaddr + 0x2000) );
	corkscrew_found_device(nic->ioaddr, nic->irqno, CORKSCREW_ID,
			       options, nic);
	
	t515_reset(nic);	
	nic->nic_op	= &t515_operations;
	return 1;
}

static int
corkscrew_found_device(int ioaddr, int irq,
		       int product_index, int options, struct nic *nic)
{
	/* Direct copy from Becker 3c515.c with unnecessary parts removed */
	vp->product_name = "3c515";
	vp->options = options;
	if (options >= 0) {
		vp->media_override =
		    ((options & 7) == 2) ? 0 : options & 7;
		vp->full_duplex = (options & 8) ? 1 : 0;
		vp->bus_master = (options & 16) ? 1 : 0;
	} else {
		vp->media_override = 7;
		vp->full_duplex = 0;
		vp->bus_master = 0;
	}

	corkscrew_probe1(ioaddr, irq, product_index, nic);
	return 0;
}

static int
corkscrew_probe1(int ioaddr, int irq, int product_index __unused,
		 struct nic *nic)
{
	unsigned int eeprom[0x40], checksum = 0;	/* EEPROM contents */
	int i;

	printf("3Com %s at 0x%hX, ", vp->product_name, ioaddr);

	/* Read the station address from the EEPROM. */
	EL3WINDOW(0);
	for (i = 0; i < 0x18; i++) {
		short *phys_addr = (short *) nic->node_addr;
		int timer;
		outw(EEPROM_Read + i, ioaddr + Wn0EepromCmd);
		/* Pause for at least 162 us. for the read to take place. */
		for (timer = 4; timer >= 0; timer--) {
			t3c515_wait(1);
			if ((inw(ioaddr + Wn0EepromCmd) & 0x0200) == 0)
				break;
		}
		eeprom[i] = inw(ioaddr + Wn0EepromData);
		DBG ( "Value %d: %hX        ", i, eeprom[i] );
		checksum ^= eeprom[i];
		if (i < 3)
			phys_addr[i] = htons(eeprom[i]);
	}
	checksum = (checksum ^ (checksum >> 8)) & 0xff;
	if (checksum != 0x00)
		printf(" ***INVALID CHECKSUM 0x%hX*** ", checksum);

        DBG ( "%s", eth_ntoa ( nic->node_addr ) );

	if (eeprom[16] == 0x11c7) {	/* Corkscrew */

	}
	printf(", IRQ %d\n", irq);
	/* Tell them about an invalid IRQ. */
	if ( (irq <= 0 || irq > 15) ) {
		DBG (" *** Warning: this IRQ is unlikely to work! ***\n" );
	}

	{
		char *ram_split[] = { "5:3", "3:1", "1:1", "3:5" };
		union wn3_config config;
		EL3WINDOW(3);
		vp->available_media = inw(ioaddr + Wn3_Options);
		config.i = inl(ioaddr + Wn3_Config);
		DBG ( "  Internal config register is %4.4x, "
		      "transceivers 0x%hX.\n",
		      config.i, inw(ioaddr + Wn3_Options) );
		printf
		    ("  %dK %s-wide RAM %s Rx:Tx split, %s%s interface.\n",
		     8 << config.u.ram_size,
		     config.u.ram_width ? "word" : "byte",
		     ram_split[config.u.ram_split],
		     config.u.autoselect ? "autoselect/" : "",
		     media_tbl[config.u.xcvr].name);
		if_port = config.u.xcvr;
		vp->default_media = config.u.xcvr;
		vp->autoselect = config.u.autoselect;
	}
	if (vp->media_override != 7) {
		printf("  Media override to transceiver type %d (%s).\n",
		       vp->media_override,
		       media_tbl[vp->media_override].name);
		if_port = vp->media_override;
	}

	vp->capabilities = eeprom[16];
	vp->full_bus_master_tx = (vp->capabilities & 0x20) ? 1 : 0;
	/* Rx is broken at 10mbps, so we always disable it. */
	/* vp->full_bus_master_rx = 0; */
	vp->full_bus_master_rx = (vp->capabilities & 0x20) ? 1 : 0;

	return 0;
}

static struct isapnp_device_id t515_adapters[] = {
	{ "3c515 (ISAPnP)", ISAPNP_VENDOR('T','C','M'), 0x5051 },
};

ISAPNP_DRIVER ( t515_driver, t515_adapters );

DRIVER ( "3c515", nic_driver, isapnp_driver, t515_driver,
	 t515_probe, t515_disable );

ISA_ROM ( "3c515", "3c515 Fast EtherLink ISAPnP" );
