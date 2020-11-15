/**************************************************************************
 ETHERBOOT -  BOOTP/TFTP Bootstrap Program

 Author: Martin Renters
 Date: May/94

 This code is based heavily on David Greenman's if_ed.c driver

 Copyright (C) 1993-1994, David Greenman, Martin Renters.
 This software may be used, modified, copied, distributed, and sold, in
 both source and binary form provided that the above copyright and these
 terms are retained. Under no circumstances are the authors responsible for
 the proper functioning of this software, nor do the authors assume any
 responsibility for damages incurred with its use.

 Multicast support added by Timothy Legge (timlegge@users.sourceforge.net) 09/28/2003
 Relocation support added by Ken Yap (ken_yap@users.sourceforge.net) 28/12/02
 Card Detect support adapted from the eCos driver (Christian Plessl <cplessl@ee.ethz.ch>)
 Extracted from ns8390.c and adapted by Pantelis Koukousoulas <pktoss@gmail.com>
 **************************************************************************/

FILE_LICENCE ( BSD2 );

#include "ns8390.h"
#include "etherboot.h"
#include "nic.h"
#include <ipxe/ethernet.h>
#include <ipxe/isa.h>
#include <errno.h>

#define ASIC_PIO NE_DATA

static unsigned char eth_vendor, eth_flags;
static unsigned short eth_nic_base, eth_asic_base;
static unsigned char eth_memsize, eth_rx_start, eth_tx_start;
static Address eth_bmem, eth_rmem;
static unsigned char eth_drain_receiver;

static struct nic_operations ne_operations;
static void ne_reset(struct nic *nic, struct isa_device *isa);

static isa_probe_addr_t ne_probe_addrs[] = { 0x300, 0x280, 0x320, 0x340, 0x380, 0x220, };

/**************************************************************************
 ETH_PIO_READ - Read a frame via Programmed I/O
 **************************************************************************/
static void eth_pio_read(unsigned int src, unsigned char *dst, unsigned int cnt) {
	outb(D8390_COMMAND_RD2 | D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);
	outb(cnt, eth_nic_base + D8390_P0_RBCR0);
	outb(cnt >> 8, eth_nic_base + D8390_P0_RBCR1);
	outb(src, eth_nic_base + D8390_P0_RSAR0);
	outb(src >> 8, eth_nic_base + D8390_P0_RSAR1);
	outb(D8390_COMMAND_RD0 | D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);
	if (eth_flags & FLAG_16BIT)
		cnt = (cnt + 1) >> 1;

	while (cnt--) {
		if (eth_flags & FLAG_16BIT) {
			*((unsigned short *) dst) = inw(eth_asic_base + ASIC_PIO);
			dst += 2;
		} else
			*(dst++) = inb(eth_asic_base + ASIC_PIO);
	}
}

/**************************************************************************
 ETH_PIO_WRITE - Write a frame via Programmed I/O
 **************************************************************************/
static void eth_pio_write(const unsigned char *src, unsigned int dst,
		unsigned int cnt) {
	outb(D8390_COMMAND_RD2 | D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);
	outb(D8390_ISR_RDC, eth_nic_base + D8390_P0_ISR);
	outb(cnt, eth_nic_base + D8390_P0_RBCR0);
	outb(cnt >> 8, eth_nic_base + D8390_P0_RBCR1);
	outb(dst, eth_nic_base + D8390_P0_RSAR0);
	outb(dst >> 8, eth_nic_base + D8390_P0_RSAR1);
	outb(D8390_COMMAND_RD1 | D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);
	if (eth_flags & FLAG_16BIT)
		cnt = (cnt + 1) >> 1;

	while (cnt--) {

		if (eth_flags & FLAG_16BIT) {
			outw(*((unsigned short *) src), eth_asic_base + ASIC_PIO);
			src += 2;
		} else
			outb(*(src++), eth_asic_base + ASIC_PIO);
	}
}

/**************************************************************************
 enable_multicast - Enable Multicast
 **************************************************************************/
static void enable_multicast(unsigned short eth_nic_base) {
	unsigned char mcfilter[8];
	int i;

	memset(mcfilter, 0xFF, 8);
	outb(4, eth_nic_base + D8390_P0_RCR);
	outb(D8390_COMMAND_RD2 + D8390_COMMAND_PS1, eth_nic_base + D8390_P0_COMMAND);
	for (i = 0; i < 8; i++) {
		outb(mcfilter[i], eth_nic_base + 8 + i);
		if (inb(eth_nic_base + 8 + i) != mcfilter[i])
			DBG("Error SMC 83C690 Multicast filter read/write mishap %d\n",
					i);
	}
	outb(D8390_COMMAND_RD2 + D8390_COMMAND_PS0, eth_nic_base + D8390_P0_COMMAND);
	outb(4 | 0x08, eth_nic_base + D8390_P0_RCR);
}

/**************************************************************************
 NE_PROBE1 - Look for an adapter on the ISA bus
 **************************************************************************/
static int ne_probe1(isa_probe_addr_t ioaddr) {
	//From the eCos driver
	unsigned int regd;
	unsigned int state;

	state = inb(ioaddr);
	outb(ioaddr, D8390_COMMAND_RD2 | D8390_COMMAND_PS1 | D8390_COMMAND_STP);
	regd = inb(ioaddr + D8390_P0_TCR);

	if (inb(ioaddr + D8390_P0_TCR)) {
		outb(ioaddr, state);
		outb(ioaddr + 0x0d, regd);
		return 0;
	}

	return 1;
}

/**************************************************************************
 NE_PROBE - Initialize an adapter ???
 **************************************************************************/
static int ne_probe(struct nic *nic, struct isa_device *isa) {
	int i;
	unsigned char c;
	unsigned char romdata[16];
	unsigned char testbuf[32];

	eth_vendor = VENDOR_NONE;
	eth_drain_receiver = 0;

	nic->irqno = 0;
	nic->ioaddr = isa->ioaddr;
	eth_nic_base = isa->ioaddr;

	/******************************************************************
	 Search for NE1000/2000 if no WD/SMC or 3com cards
	 ******************************************************************/
	if (eth_vendor == VENDOR_NONE) {

		static unsigned char test[] = "NE*000 memory";

		eth_bmem = 0; /* No shared memory */

		eth_flags = FLAG_PIO;
		eth_asic_base = eth_nic_base + NE_ASIC_OFFSET;
		eth_memsize = MEM_16384;
		eth_tx_start = 32;
		eth_rx_start = 32 + D8390_TXBUF_SIZE;
		c = inb(eth_asic_base + NE_RESET);
		outb(c, eth_asic_base + NE_RESET);
		(void) inb(0x84);
		outb(D8390_COMMAND_STP | D8390_COMMAND_RD2, eth_nic_base
				+ D8390_P0_COMMAND);
		outb(D8390_RCR_MON, eth_nic_base + D8390_P0_RCR);
		outb(D8390_DCR_FT1 | D8390_DCR_LS, eth_nic_base + D8390_P0_DCR);
		outb(MEM_8192, eth_nic_base + D8390_P0_PSTART);
		outb(MEM_16384, eth_nic_base + D8390_P0_PSTOP);
		eth_pio_write((unsigned char *) test, 8192, sizeof(test));
		eth_pio_read(8192, testbuf, sizeof(test));
		if (!memcmp(test, testbuf, sizeof(test)))
			goto out;
		eth_flags |= FLAG_16BIT;
		eth_memsize = MEM_32768;
		eth_tx_start = 64;
		eth_rx_start = 64 + D8390_TXBUF_SIZE;
		outb(D8390_DCR_WTS | D8390_DCR_FT1 | D8390_DCR_LS, eth_nic_base
				+ D8390_P0_DCR);
		outb(MEM_16384, eth_nic_base + D8390_P0_PSTART);
		outb(MEM_32768, eth_nic_base + D8390_P0_PSTOP);
		eth_pio_write((unsigned char *) test, 16384, sizeof(test));
		eth_pio_read(16384, testbuf, sizeof(test));
		if (!memcmp(testbuf, test, sizeof(test)))
			goto out;


out:
		if (eth_nic_base == 0)
			return (0);
		if (eth_nic_base > ISA_MAX_ADDR) /* PCI probably */
			eth_flags |= FLAG_16BIT;
		eth_vendor = VENDOR_NOVELL;
		eth_pio_read(0, romdata, sizeof(romdata));
		for (i = 0; i < ETH_ALEN; i++) {
			nic->node_addr[i] = romdata[i + ((eth_flags & FLAG_16BIT) ? i : 0)];
		}
		nic->ioaddr = eth_nic_base;
		DBG("\nNE%c000 base %4.4x, MAC Addr %s\n",
				(eth_flags & FLAG_16BIT) ? '2' : '1', eth_nic_base, eth_ntoa(
						nic->node_addr));
	}

	if (eth_vendor == VENDOR_NONE)
		return (0);

	if (eth_vendor != VENDOR_3COM)
		eth_rmem = eth_bmem;

	ne_reset(nic, isa);
	nic->nic_op = &ne_operations;
	return 1;
}


/**************************************************************************
 NE_DISABLE - Turn off adapter
 **************************************************************************/
static void ne_disable(struct nic *nic, struct isa_device *isa) {
	ne_reset(nic, isa);
}


/**************************************************************************
 NE_RESET - Reset adapter
 **************************************************************************/
static void ne_reset(struct nic *nic, struct isa_device *isa __unused)
{
	int i;

	eth_drain_receiver = 0;
	outb(D8390_COMMAND_PS0 | D8390_COMMAND_RD2 |
			D8390_COMMAND_STP, eth_nic_base+D8390_P0_COMMAND);
	if (eth_flags & FLAG_16BIT)
	outb(0x49, eth_nic_base+D8390_P0_DCR);
	else
	outb(0x48, eth_nic_base+D8390_P0_DCR);
	outb(0, eth_nic_base+D8390_P0_RBCR0);
	outb(0, eth_nic_base+D8390_P0_RBCR1);
	outb(0x20, eth_nic_base+D8390_P0_RCR); /* monitor mode */
	outb(2, eth_nic_base+D8390_P0_TCR);
	outb(eth_tx_start, eth_nic_base+D8390_P0_TPSR);
	outb(eth_rx_start, eth_nic_base+D8390_P0_PSTART);

	outb(eth_memsize, eth_nic_base+D8390_P0_PSTOP);
	outb(eth_memsize - 1, eth_nic_base+D8390_P0_BOUND);
	outb(0xFF, eth_nic_base+D8390_P0_ISR);
	outb(0, eth_nic_base+D8390_P0_IMR);
	outb(D8390_COMMAND_PS1 |
			D8390_COMMAND_RD2 | D8390_COMMAND_STP, eth_nic_base+D8390_P0_COMMAND);

	for (i=0; i<ETH_ALEN; i++)
	outb(nic->node_addr[i], eth_nic_base+D8390_P1_PAR0+i);
	for (i=0; i<ETH_ALEN; i++)
	outb(0xFF, eth_nic_base+D8390_P1_MAR0+i);
	outb(eth_rx_start, eth_nic_base+D8390_P1_CURR);
	outb(D8390_COMMAND_PS0 |
			D8390_COMMAND_RD2 | D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);
	outb(0xFF, eth_nic_base+D8390_P0_ISR);
	outb(0, eth_nic_base+D8390_P0_TCR); /* transmitter on */
	outb(4, eth_nic_base+D8390_P0_RCR); /* allow rx broadcast frames */

	enable_multicast(eth_nic_base);
}


/**************************************************************************
 NE_POLL - Wait for a frame
 **************************************************************************/
static int ne_poll(struct nic *nic __unused, int retrieve __unused)
{
	int ret = 0;
	unsigned char rstat, curr, next;
	unsigned short len, frag;
	unsigned short pktoff;
	unsigned char *p;
	struct ringbuffer pkthdr;

	rstat = inb(eth_nic_base+D8390_P0_RSR);
	if (!(rstat & D8390_RSTAT_PRX)) return(0);
	next = inb(eth_nic_base+D8390_P0_BOUND)+1;
	if (next >= eth_memsize) next = eth_rx_start;
	outb(D8390_COMMAND_PS1, eth_nic_base+D8390_P0_COMMAND);
	curr = inb(eth_nic_base+D8390_P1_CURR);
	outb(D8390_COMMAND_PS0, eth_nic_base+D8390_P0_COMMAND);
	if (curr >= eth_memsize) curr=eth_rx_start;
	if (curr == next) return(0);

	if ( ! retrieve ) return 1;

	pktoff = next << 8;
	if (eth_flags & FLAG_PIO)
	eth_pio_read(pktoff, (unsigned char *)&pkthdr, 4);
	else
	memcpy(&pkthdr, bus_to_virt(eth_rmem + pktoff), 4);
	pktoff += sizeof(pkthdr);
	/* incoming length includes FCS so must sub 4 */
	len = pkthdr.len - 4;
	if ((pkthdr.status & D8390_RSTAT_PRX) == 0 || len < ETH_ZLEN
			|| len> ETH_FRAME_LEN) {
		DBG("Bogus packet, ignoring\n");
		return (0);
	}
	else {
		p = nic->packet;
		nic->packetlen = len; /* available to caller */
		frag = (eth_memsize << 8) - pktoff;
		if (len> frag) { /* We have a wrap-around */
			/* read first part */
			if (eth_flags & FLAG_PIO)
			eth_pio_read(pktoff, p, frag);
			else
			memcpy(p, bus_to_virt(eth_rmem + pktoff), frag);
			pktoff = eth_rx_start << 8;
			p += frag;
			len -= frag;
		}
		/* read second part */
		if (eth_flags & FLAG_PIO)
		eth_pio_read(pktoff, p, len);
		else
		memcpy(p, bus_to_virt(eth_rmem + pktoff), len);
		ret = 1;
	}
	next = pkthdr.next; /* frame number of next packet */
	if (next == eth_rx_start)
	next = eth_memsize;
	outb(next-1, eth_nic_base+D8390_P0_BOUND);
	return(ret);
}


/**************************************************************************
 NE_TRANSMIT - Transmit a frame
 **************************************************************************/
static void ne_transmit(struct nic *nic, const char *d, /* Destination */
unsigned int t, /* Type */
unsigned int s, /* size */
const char *p) { /* Packet */

	/* Programmed I/O */
	unsigned short type;
	type = (t >> 8) | (t << 8);
	eth_pio_write((unsigned char *) d, eth_tx_start << 8, ETH_ALEN);
	eth_pio_write(nic->node_addr, (eth_tx_start << 8) + ETH_ALEN, ETH_ALEN);
	/* bcc generates worse code without (const+const) below */
	eth_pio_write((unsigned char *) &type, (eth_tx_start << 8) + (ETH_ALEN
			+ ETH_ALEN), 2);
	eth_pio_write((unsigned char *) p, (eth_tx_start << 8) + ETH_HLEN, s);
	s += ETH_HLEN;
	if (s < ETH_ZLEN)
		s = ETH_ZLEN;

	outb(D8390_COMMAND_PS0 | D8390_COMMAND_RD2 | D8390_COMMAND_STA,
			eth_nic_base + D8390_P0_COMMAND);
	outb(eth_tx_start, eth_nic_base + D8390_P0_TPSR);
	outb(s, eth_nic_base + D8390_P0_TBCR0);
	outb(s >> 8, eth_nic_base + D8390_P0_TBCR1);

	outb(D8390_COMMAND_PS0 | D8390_COMMAND_TXP | D8390_COMMAND_RD2
			| D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);
}

static struct nic_operations ne_operations = { .connect = dummy_connect,
		.poll = ne_poll, .transmit = ne_transmit, .irq = dummy_irq,
};

ISA_DRIVER ( ne_driver, ne_probe_addrs, ne_probe1,
		GENERIC_ISAPNP_VENDOR, 0x0600 );

DRIVER ( "ne", nic_driver, isapnp_driver, ne_driver,
		ne_probe, ne_disable );

ISA_ROM("ne","NE1000/2000 and clones");
