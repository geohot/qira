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
3c503 support added by Bill Paul (wpaul@ctr.columbia.edu) on 11/15/94
SMC8416 support added by Bill Paul (wpaul@ctr.columbia.edu) on 12/25/94
3c503 PIO support added by Jim Hague (jim.hague@acm.org) on 2/17/98
RX overrun by Klaus Espenlaub (espenlaub@informatik.uni-ulm.de) on 3/10/99
  parts taken from the Linux 8390 driver (by Donald Becker and Paul Gortmaker)
SMC8416 PIO support added by Andrew Bettison (andrewb@zip.com.au) on 4/3/02
  based on the Linux 8390 driver (by Donald Becker and Paul Gortmaker)

**************************************************************************/

FILE_LICENCE ( BSD2 );

/* #warning "ns8390.c: FIXME: split ISA and PCI, clean up" */

#if 1

#if !defined(INCLUDE_NS8390) && !defined(INCLUDE_WD) && \
    !defined(INCLUDE_NE) && !defined(INCLUDE_3C503)
  /* The driver named ns8390 is the PCI driver, often called
     "PCI ne2000 clones". */
# define INCLUDE_NS8390 1
#endif

#include "etherboot.h"
#include "nic.h"
#include "ns8390.h"
#include <ipxe/ethernet.h>
#ifdef	INCLUDE_NS8390
#include <ipxe/pci.h>
#else
#include <ipxe/isa.h>
#endif

static unsigned char	eth_vendor, eth_flags;
#ifdef	INCLUDE_WD
static unsigned char	eth_laar;
#endif
static unsigned short	eth_nic_base, eth_asic_base;
static unsigned char	eth_memsize, eth_rx_start, eth_tx_start;
static Address		eth_bmem, eth_rmem;
static unsigned char	eth_drain_receiver;

#ifdef	INCLUDE_WD
static struct wd_board {
	const char *name;
	char id;
	char flags;
	char memsize;
} wd_boards[] = {
	{"WD8003S",	TYPE_WD8003S,	0,			MEM_8192},
	{"WD8003E",	TYPE_WD8003E,	0,			MEM_8192},
	{"WD8013EBT",	TYPE_WD8013EBT,	FLAG_16BIT,		MEM_16384},
	{"WD8003W",	TYPE_WD8003W,	0,			MEM_8192},
	{"WD8003EB",	TYPE_WD8003EB,	0,			MEM_8192},
	{"WD8013W",	TYPE_WD8013W,	FLAG_16BIT,		MEM_16384},
	{"WD8003EP/WD8013EP",
			TYPE_WD8013EP,	0,			MEM_8192},
	{"WD8013WC",	TYPE_WD8013WC,	FLAG_16BIT,		MEM_16384},
	{"WD8013EPC",	TYPE_WD8013EPC,	FLAG_16BIT,		MEM_16384},
	{"SMC8216T",	TYPE_SMC8216T,	FLAG_16BIT | FLAG_790,	MEM_16384},
	{"SMC8216C",	TYPE_SMC8216C,	FLAG_16BIT | FLAG_790,	MEM_16384},
	{"SMC8416T",	TYPE_SMC8416T,	FLAG_16BIT | FLAG_790,	MEM_8192},
	{"SMC8416C/BT",	TYPE_SMC8416C,	FLAG_16BIT | FLAG_790,	MEM_8192},
	{"SMC8013EBP",	TYPE_SMC8013EBP,FLAG_16BIT,		MEM_16384},
	{NULL,		0,		0,			0}
};
#endif

#ifdef	INCLUDE_3C503
static unsigned char	t503_output;	/* AUI or internal xcvr (Thinnet) */
#endif

#if	defined(INCLUDE_WD)
#define	ASIC_PIO	WD_IAR
#define	eth_probe	wd_probe
#if	defined(INCLUDE_3C503) || defined(INCLUDE_NE) || defined(INCLUDE_NS8390)
Error you must only define one of INCLUDE_WD, INCLUDE_3C503, INCLUDE_NE, INCLUDE_NS8390
#endif
#endif

#if	defined(INCLUDE_3C503)
#define	eth_probe	t503_probe
#if	defined(INCLUDE_NE) || defined(INCLUDE_NS8390) || defined(INCLUDE_WD)
Error you must only define one of INCLUDE_WD, INCLUDE_3C503, INCLUDE_NE, INCLUDE_NS8390
#endif
#endif

#if	defined(INCLUDE_NE)
#define	eth_probe	ne_probe
#if	defined(INCLUDE_NS8390) || defined(INCLUDE_3C503) || defined(INCLUDE_WD)
Error you must only define one of INCLUDE_WD, INCLUDE_3C503, INCLUDE_NE, INCLUDE_NS8390
#endif
#endif

#if	defined(INCLUDE_NS8390)
#define	eth_probe	nepci_probe
#if	defined(INCLUDE_NE) || defined(INCLUDE_3C503) || defined(INCLUDE_WD)
Error you must only define one of INCLUDE_WD, INCLUDE_3C503, INCLUDE_NE, INCLUDE_NS8390
#endif
#endif

#if	defined(INCLUDE_3C503)
#define	ASIC_PIO	_3COM_RFMSB
#else
#if	defined(INCLUDE_NE) || defined(INCLUDE_NS8390)
#define	ASIC_PIO	NE_DATA
#endif
#endif

#if	defined(INCLUDE_NE) || defined(INCLUDE_NS8390) || (defined(INCLUDE_3C503) && !defined(T503_SHMEM)) || (defined(INCLUDE_WD) && defined(WD_790_PIO))
/**************************************************************************
ETH_PIO_READ - Read a frame via Programmed I/O
**************************************************************************/
static void eth_pio_read(unsigned int src, unsigned char *dst, unsigned int cnt)
{
#ifdef	INCLUDE_WD
	outb(src & 0xff, eth_asic_base + WD_GP2);
	outb(src >> 8, eth_asic_base + WD_GP2);
#else
	outb(D8390_COMMAND_RD2 |
		D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);
	outb(cnt, eth_nic_base + D8390_P0_RBCR0);
	outb(cnt>>8, eth_nic_base + D8390_P0_RBCR1);
	outb(src, eth_nic_base + D8390_P0_RSAR0);
	outb(src>>8, eth_nic_base + D8390_P0_RSAR1);
	outb(D8390_COMMAND_RD0 |
		D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);

#ifdef	INCLUDE_3C503
	outb(src & 0xff, eth_asic_base + _3COM_DALSB);
	outb(src >> 8, eth_asic_base + _3COM_DAMSB);
	outb(t503_output | _3COM_CR_START, eth_asic_base + _3COM_CR);
#endif
#endif

	if (eth_flags & FLAG_16BIT)
		cnt = (cnt + 1) >> 1;

	while(cnt--) {
#ifdef	INCLUDE_3C503
		while((inb(eth_asic_base + _3COM_STREG) & _3COM_STREG_DPRDY) == 0)
			;
#endif

		if (eth_flags & FLAG_16BIT) {
			*((unsigned short *)dst) = inw(eth_asic_base + ASIC_PIO);
			dst += 2;
		}
		else
			*(dst++) = inb(eth_asic_base + ASIC_PIO);
	}

#ifdef	INCLUDE_3C503
	outb(t503_output, eth_asic_base + _3COM_CR);
#endif
}

/**************************************************************************
ETH_PIO_WRITE - Write a frame via Programmed I/O
**************************************************************************/
static void eth_pio_write(const unsigned char *src, unsigned int dst, unsigned int cnt)
{
#ifdef	COMPEX_RL2000_FIX
	unsigned int x;
#endif	/* COMPEX_RL2000_FIX */
#ifdef	INCLUDE_WD
	outb(dst & 0xff, eth_asic_base + WD_GP2);
	outb(dst >> 8, eth_asic_base + WD_GP2);
#else
	outb(D8390_COMMAND_RD2 |
		D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);
	outb(D8390_ISR_RDC, eth_nic_base + D8390_P0_ISR);
	outb(cnt, eth_nic_base + D8390_P0_RBCR0);
	outb(cnt>>8, eth_nic_base + D8390_P0_RBCR1);
	outb(dst, eth_nic_base + D8390_P0_RSAR0);
	outb(dst>>8, eth_nic_base + D8390_P0_RSAR1);
	outb(D8390_COMMAND_RD1 |
		D8390_COMMAND_STA, eth_nic_base + D8390_P0_COMMAND);

#ifdef	INCLUDE_3C503
	outb(dst & 0xff, eth_asic_base + _3COM_DALSB);
	outb(dst >> 8, eth_asic_base + _3COM_DAMSB);

	outb(t503_output | _3COM_CR_DDIR | _3COM_CR_START, eth_asic_base + _3COM_CR);
#endif
#endif

	if (eth_flags & FLAG_16BIT)
		cnt = (cnt + 1) >> 1;

	while(cnt--)
	{
#ifdef	INCLUDE_3C503
		while((inb(eth_asic_base + _3COM_STREG) & _3COM_STREG_DPRDY) == 0)
			;
#endif

		if (eth_flags & FLAG_16BIT) {
			outw(*((unsigned short *)src), eth_asic_base + ASIC_PIO);
			src += 2;
		}
		else
			outb(*(src++), eth_asic_base + ASIC_PIO);
	}

#ifdef	INCLUDE_3C503
	outb(t503_output, eth_asic_base + _3COM_CR);
#else
#ifdef	COMPEX_RL2000_FIX
	for (x = 0;
		x < COMPEX_RL2000_TRIES &&
		(inb(eth_nic_base + D8390_P0_ISR) & D8390_ISR_RDC)
		!= D8390_ISR_RDC;
		++x);
	if (x >= COMPEX_RL2000_TRIES)
		printf("Warning: Compex RL2000 aborted wait!\n");
#endif	/* COMPEX_RL2000_FIX */
#ifndef	INCLUDE_WD
	while((inb(eth_nic_base + D8390_P0_ISR) & D8390_ISR_RDC)
		!= D8390_ISR_RDC);
#endif
#endif
}
#else
/**************************************************************************
ETH_PIO_READ - Dummy routine when NE2000 not compiled in
**************************************************************************/
static void eth_pio_read(unsigned int src __unused, unsigned char *dst  __unused, unsigned int cnt __unused) {}
#endif


/**************************************************************************
enable_multycast - Enable Multicast
**************************************************************************/
static void enable_multicast(unsigned short eth_nic_base) 
{
	unsigned char mcfilter[8];
	int i;
	memset(mcfilter, 0xFF, 8);
	outb(4, eth_nic_base+D8390_P0_RCR);	
	outb(D8390_COMMAND_RD2 + D8390_COMMAND_PS1, eth_nic_base + D8390_P0_COMMAND);
	for(i=0;i<8;i++)
	{
		outb(mcfilter[i], eth_nic_base + 8 + i);
		if(inb(eth_nic_base + 8 + i)!=mcfilter[i])
			printf("Error SMC 83C690 Multicast filter read/write mishap %d\n",i);
	}
	outb(D8390_COMMAND_RD2 + D8390_COMMAND_PS0, eth_nic_base + D8390_P0_COMMAND);
	outb(4 | 0x08, eth_nic_base+D8390_P0_RCR);
}

/**************************************************************************
NS8390_RESET - Reset adapter
**************************************************************************/
static void ns8390_reset(struct nic *nic)
{
	int i;

	eth_drain_receiver = 0;
#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_790)
		outb(D8390_COMMAND_PS0 | D8390_COMMAND_STP, eth_nic_base+D8390_P0_COMMAND);
	else
#endif
		outb(D8390_COMMAND_PS0 | D8390_COMMAND_RD2 |
			D8390_COMMAND_STP, eth_nic_base+D8390_P0_COMMAND);
	if (eth_flags & FLAG_16BIT)
		outb(0x49, eth_nic_base+D8390_P0_DCR);
	else
		outb(0x48, eth_nic_base+D8390_P0_DCR);
	outb(0, eth_nic_base+D8390_P0_RBCR0);
	outb(0, eth_nic_base+D8390_P0_RBCR1);
	outb(0x20, eth_nic_base+D8390_P0_RCR);	/* monitor mode */
	outb(2, eth_nic_base+D8390_P0_TCR);
	outb(eth_tx_start, eth_nic_base+D8390_P0_TPSR);
	outb(eth_rx_start, eth_nic_base+D8390_P0_PSTART);
#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_790) {
#ifdef	WD_790_PIO
		outb(0x10, eth_asic_base + 0x06); /* disable interrupts, enable PIO */
		outb(0x01, eth_nic_base + 0x09); /* enable ring read auto-wrap */
#else
		outb(0, eth_nic_base + 0x09);
#endif
	}
#endif
	outb(eth_memsize, eth_nic_base+D8390_P0_PSTOP);
	outb(eth_memsize - 1, eth_nic_base+D8390_P0_BOUND);
	outb(0xFF, eth_nic_base+D8390_P0_ISR);
	outb(0, eth_nic_base+D8390_P0_IMR);
#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_790)
		outb(D8390_COMMAND_PS1 |
			D8390_COMMAND_STP, eth_nic_base+D8390_P0_COMMAND);
	else
#endif
		outb(D8390_COMMAND_PS1 |
			D8390_COMMAND_RD2 | D8390_COMMAND_STP, eth_nic_base+D8390_P0_COMMAND);
	for (i=0; i<ETH_ALEN; i++)
		outb(nic->node_addr[i], eth_nic_base+D8390_P1_PAR0+i);
	for (i=0; i<ETH_ALEN; i++)
		outb(0xFF, eth_nic_base+D8390_P1_MAR0+i);
	outb(eth_rx_start, eth_nic_base+D8390_P1_CURR);
#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_790)
		outb(D8390_COMMAND_PS0 |
			D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);
	else
#endif
		outb(D8390_COMMAND_PS0 |
			D8390_COMMAND_RD2 | D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);
	outb(0xFF, eth_nic_base+D8390_P0_ISR);
	outb(0, eth_nic_base+D8390_P0_TCR);	/* transmitter on */
	outb(4, eth_nic_base+D8390_P0_RCR);	/* allow rx broadcast frames */

	enable_multicast(eth_nic_base);

#ifdef	INCLUDE_3C503
        /*
         * No way to tell whether or not we're supposed to use
         * the 3Com's transceiver unless the user tells us.
         * 'flags' should have some compile time default value
         * which can be changed from the command menu.
         */
	t503_output = (nic->flags) ? 0 : _3COM_CR_XSEL;
	outb(t503_output, eth_asic_base + _3COM_CR);
#endif
}

static int ns8390_poll(struct nic *nic, int retrieve);

#ifndef	INCLUDE_3C503
/**************************************************************************
ETH_RX_OVERRUN - Bring adapter back to work after an RX overrun
**************************************************************************/
static void eth_rx_overrun(struct nic *nic)
{
	int start_time;

#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_790)
		outb(D8390_COMMAND_PS0 | D8390_COMMAND_STP, eth_nic_base+D8390_P0_COMMAND);
	else
#endif
		outb(D8390_COMMAND_PS0 | D8390_COMMAND_RD2 |
			D8390_COMMAND_STP, eth_nic_base+D8390_P0_COMMAND);

	/* wait for at least 1.6ms - we wait one timer tick */
	start_time = currticks();
	while (currticks() - start_time <= 1)
		/* Nothing */;

	outb(0, eth_nic_base+D8390_P0_RBCR0);	/* reset byte counter */
	outb(0, eth_nic_base+D8390_P0_RBCR1);

	/*
	 * Linux driver checks for interrupted TX here. This is not necessary,
	 * because the transmit routine waits until the frame is sent.
	 */

	/* enter loopback mode and restart NIC */
	outb(2, eth_nic_base+D8390_P0_TCR);
#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_790)
		outb(D8390_COMMAND_PS0 | D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);
	else
#endif
		outb(D8390_COMMAND_PS0 | D8390_COMMAND_RD2 |
			D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);

	/* clear the RX ring, acknowledge overrun interrupt */
	eth_drain_receiver = 1;
	while (ns8390_poll(nic, 1))
		/* Nothing */;
	eth_drain_receiver = 0;
	outb(D8390_ISR_OVW, eth_nic_base+D8390_P0_ISR);

	/* leave loopback mode - no packets to be resent (see Linux driver) */
	outb(0, eth_nic_base+D8390_P0_TCR);
}
#endif	/* INCLUDE_3C503 */

/**************************************************************************
NS8390_TRANSMIT - Transmit a frame
**************************************************************************/
static void ns8390_transmit(
	struct nic *nic,
	const char *d,			/* Destination */
	unsigned int t,			/* Type */
	unsigned int s,			/* size */
	const char *p)			/* Packet */
{
#if defined(INCLUDE_3C503) || (defined(INCLUDE_WD) && ! defined(WD_790_PIO))
	Address		eth_vmem = bus_to_virt(eth_bmem);
#endif
#ifdef	INCLUDE_3C503
        if (!(eth_flags & FLAG_PIO)) {
                memcpy((char *)eth_vmem, d, ETH_ALEN);	/* dst */
                memcpy((char *)eth_vmem+ETH_ALEN, nic->node_addr, ETH_ALEN); /* src */
                *((char *)eth_vmem+12) = t>>8;		/* type */
                *((char *)eth_vmem+13) = t;
                memcpy((char *)eth_vmem+ETH_HLEN, p, s);
                s += ETH_HLEN;
                while (s < ETH_ZLEN) *((char *)eth_vmem+(s++)) = 0;
        }
#endif

#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_16BIT) {
		outb(eth_laar | WD_LAAR_M16EN, eth_asic_base + WD_LAAR);
		inb(0x84);
	}
#ifndef	WD_790_PIO
	/* Memory interface */
	if (eth_flags & FLAG_790) {
		outb(WD_MSR_MENB, eth_asic_base + WD_MSR);
		inb(0x84);
	}
	inb(0x84);
	memcpy((char *)eth_vmem, d, ETH_ALEN);	/* dst */
	memcpy((char *)eth_vmem+ETH_ALEN, nic->node_addr, ETH_ALEN); /* src */
	*((char *)eth_vmem+12) = t>>8;		/* type */
	*((char *)eth_vmem+13) = t;
	memcpy((char *)eth_vmem+ETH_HLEN, p, s);
	s += ETH_HLEN;
	while (s < ETH_ZLEN) *((char *)eth_vmem+(s++)) = 0;
	if (eth_flags & FLAG_790) {
		outb(0, eth_asic_base + WD_MSR);
		inb(0x84);
	}
#else
	inb(0x84);
#endif
#endif

#if	defined(INCLUDE_3C503)
	if (eth_flags & FLAG_PIO)
#endif
#if	defined(INCLUDE_NE) || defined(INCLUDE_NS8390) || (defined(INCLUDE_3C503) && !defined(T503_SHMEM)) || (defined(INCLUDE_WD) && defined(WD_790_PIO))
	{
		/* Programmed I/O */
		unsigned short type;
		type = (t >> 8) | (t << 8);
		eth_pio_write( (unsigned char *) d, eth_tx_start<<8, ETH_ALEN);
		eth_pio_write(nic->node_addr, (eth_tx_start<<8)+ETH_ALEN, ETH_ALEN);
		/* bcc generates worse code without (const+const) below */
		eth_pio_write((unsigned char *)&type, (eth_tx_start<<8)+(ETH_ALEN+ETH_ALEN), 2);
		eth_pio_write( (unsigned char *) p, (eth_tx_start<<8)+ETH_HLEN, s);
		s += ETH_HLEN;
		if (s < ETH_ZLEN) s = ETH_ZLEN;
	}
#endif
#if	defined(INCLUDE_3C503)
#endif

#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_16BIT) {
		outb(eth_laar & ~WD_LAAR_M16EN, eth_asic_base + WD_LAAR);
		inb(0x84);
	}
	if (eth_flags & FLAG_790)
		outb(D8390_COMMAND_PS0 |
			D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);
	else
#endif
		outb(D8390_COMMAND_PS0 |
			D8390_COMMAND_RD2 | D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);
	outb(eth_tx_start, eth_nic_base+D8390_P0_TPSR);
	outb(s, eth_nic_base+D8390_P0_TBCR0);
	outb(s>>8, eth_nic_base+D8390_P0_TBCR1);
#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_790)
		outb(D8390_COMMAND_PS0 |
			D8390_COMMAND_TXP | D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);
	else
#endif
		outb(D8390_COMMAND_PS0 |
			D8390_COMMAND_TXP | D8390_COMMAND_RD2 |
			D8390_COMMAND_STA, eth_nic_base+D8390_P0_COMMAND);
}

/**************************************************************************
NS8390_POLL - Wait for a frame
**************************************************************************/
static int ns8390_poll(struct nic *nic, int retrieve)
{
	int ret = 0;
	unsigned char rstat, curr, next;
	unsigned short len, frag;
	unsigned short pktoff;
	unsigned char *p;
	struct ringbuffer pkthdr;

#ifndef	INCLUDE_3C503
	/* avoid infinite recursion: see eth_rx_overrun() */
	if (!eth_drain_receiver && (inb(eth_nic_base+D8390_P0_ISR) & D8390_ISR_OVW)) {
		eth_rx_overrun(nic);
		return(0);
	}
#endif	/* INCLUDE_3C503 */
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

#ifdef	INCLUDE_WD
	if (eth_flags & FLAG_16BIT) {
		outb(eth_laar | WD_LAAR_M16EN, eth_asic_base + WD_LAAR);
		inb(0x84);
	}
#ifndef	WD_790_PIO
	if (eth_flags & FLAG_790) {
		outb(WD_MSR_MENB, eth_asic_base + WD_MSR);
		inb(0x84);
	}
#endif
	inb(0x84);
#endif
	pktoff = next << 8;
	if (eth_flags & FLAG_PIO)
		eth_pio_read(pktoff, (unsigned char *)&pkthdr, 4);
	else
		memcpy(&pkthdr, bus_to_virt(eth_rmem + pktoff), 4);
	pktoff += sizeof(pkthdr);
	/* incoming length includes FCS so must sub 4 */
	len = pkthdr.len - 4;
	if ((pkthdr.status & D8390_RSTAT_PRX) == 0 || len < ETH_ZLEN
		|| len > ETH_FRAME_LEN) {
		printf("Bogus packet, ignoring\n");
		return (0);
	}
	else {
		p = nic->packet;
		nic->packetlen = len;		/* available to caller */
		frag = (eth_memsize << 8) - pktoff;
		if (len > frag) {		/* We have a wrap-around */
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
#ifdef	INCLUDE_WD
#ifndef	WD_790_PIO
	if (eth_flags & FLAG_790) {
		outb(0, eth_asic_base + WD_MSR);
		inb(0x84);
	}
#endif
	if (eth_flags & FLAG_16BIT) {
		outb(eth_laar & ~WD_LAAR_M16EN, eth_asic_base + WD_LAAR);
		inb(0x84);
	}
	inb(0x84);
#endif
	next = pkthdr.next;		/* frame number of next packet */
	if (next == eth_rx_start)
		next = eth_memsize;
	outb(next-1, eth_nic_base+D8390_P0_BOUND);
	return(ret);
}

/**************************************************************************
NS8390_DISABLE - Turn off adapter
**************************************************************************/
static void ns8390_disable ( struct nic *nic ) {
	ns8390_reset(nic);
}

/**************************************************************************
NS8390_IRQ - Enable, Disable, or Force interrupts
**************************************************************************/
static void ns8390_irq(struct nic *nic __unused, irq_action_t action __unused)
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

static struct nic_operations ns8390_operations;
static struct nic_operations ns8390_operations = {
	.connect	= dummy_connect,
	.poll		= ns8390_poll,
	.transmit	= ns8390_transmit,
	.irq		= ns8390_irq,
};

/**************************************************************************
ETH_PROBE - Look for an adapter
**************************************************************************/
#ifdef	INCLUDE_NS8390
static int eth_probe (struct nic *nic, struct pci_device *pci)
#else
static int eth_probe (struct dev *dev, unsigned short *probe_addrs __unused)
#endif
{
	int i;
#ifdef INCLUDE_NS8390
	unsigned short pci_probe_addrs[] = { pci->ioaddr, 0 };
	unsigned short *probe_addrs = pci_probe_addrs;
#endif
	eth_vendor = VENDOR_NONE;
	eth_drain_receiver = 0;

	nic->irqno  = 0;

#ifdef	INCLUDE_WD
{
	/******************************************************************
	Search for WD/SMC cards
	******************************************************************/
	struct wd_board *brd;
	unsigned short chksum;
	unsigned char c;
	for (eth_asic_base = WD_LOW_BASE; eth_asic_base <= WD_HIGH_BASE;
		eth_asic_base += 0x20) {
		chksum = 0;
		for (i=8; i<16; i++)
			chksum += inb(eth_asic_base+i);
		/* Extra checks to avoid soundcard */
		if ((chksum & 0xFF) == 0xFF &&
			inb(eth_asic_base+8) != 0xFF &&
			inb(eth_asic_base+9) != 0xFF)
			break;
	}
	if (eth_asic_base > WD_HIGH_BASE)
		return (0);
	/* We've found a board */
	eth_vendor = VENDOR_WD;
	eth_nic_base = eth_asic_base + WD_NIC_ADDR;

	nic->ioaddr = eth_nic_base;

	c = inb(eth_asic_base+WD_BID);	/* Get board id */
	for (brd = wd_boards; brd->name; brd++)
		if (brd->id == c) break;
	if (!brd->name) {
		printf("Unknown WD/SMC NIC type %hhX\n", c);
		return (0);	/* Unknown type */
	}
	eth_flags = brd->flags;
	eth_memsize = brd->memsize;
	eth_tx_start = 0;
	eth_rx_start = D8390_TXBUF_SIZE;
	if ((c == TYPE_WD8013EP) &&
		(inb(eth_asic_base + WD_ICR) & WD_ICR_16BIT)) {
			eth_flags = FLAG_16BIT;
			eth_memsize = MEM_16384;
	}
	if ((c & WD_SOFTCONFIG) && (!(eth_flags & FLAG_790))) {
		eth_bmem = (0x80000 |
		 ((inb(eth_asic_base + WD_MSR) & 0x3F) << 13));
	} else
		eth_bmem = WD_DEFAULT_MEM;
	if (brd->id == TYPE_SMC8216T || brd->id == TYPE_SMC8216C) {
		/* from Linux driver, 8416BT detects as 8216 sometimes */
		unsigned int addr = inb(eth_asic_base + 0xb);
		if (((addr >> 4) & 3) == 0) {
			brd += 2;
			eth_memsize = brd->memsize;
		}
	}
	outb(0x80, eth_asic_base + WD_MSR);	/* Reset */
	for (i=0; i<ETH_ALEN; i++) {
		nic->node_addr[i] = inb(i+eth_asic_base+WD_LAR);
	}
	DBG ( "\n%s base %4.4x", brd->name, eth_asic_base );
	if (eth_flags & FLAG_790) {
#ifdef	WD_790_PIO
		DBG ( ", PIO mode, addr %s\n", eth_ntoa ( nic->node_addr ) );
		eth_bmem = 0;
		eth_flags |= FLAG_PIO;		/* force PIO mode */
		outb(0, eth_asic_base+WD_MSR);
#else
		DBG ( ", Memory %x, MAC Addr %s\n", eth_bmem, eth_ntoa ( nic->node_addr) );

		outb(WD_MSR_MENB, eth_asic_base+WD_MSR);
		outb((inb(eth_asic_base+0x04) |
			0x80), eth_asic_base+0x04);
		outb(((unsigned)(eth_bmem >> 13) & 0x0F) |
			((unsigned)(eth_bmem >> 11) & 0x40) |
			(inb(eth_asic_base+0x0B) & 0xB0), eth_asic_base+0x0B);
		outb((inb(eth_asic_base+0x04) &
			~0x80), eth_asic_base+0x04);
#endif
	} else {

		DBG (", Memory %x, MAC Addr %s\n", eth_bmem, eth_ntoa ( nic->node_addr) );

		outb(((unsigned)(eth_bmem >> 13) & 0x3F) | 0x40, eth_asic_base+WD_MSR);
	}
	if (eth_flags & FLAG_16BIT) {
		if (eth_flags & FLAG_790) {
			eth_laar = inb(eth_asic_base + WD_LAAR);
			outb(WD_LAAR_M16EN, eth_asic_base + WD_LAAR);
		} else {
			outb((eth_laar =
				WD_LAAR_L16EN | 1), eth_asic_base + WD_LAAR);
/*
	The previous line used to be
				WD_LAAR_M16EN | WD_LAAR_L16EN | 1));
	jluke@deakin.edu.au reported that removing WD_LAAR_M16EN made
	it work for WD8013s.  This seems to work for my 8013 boards. I
	don't know what is really happening.  I wish I had data sheets
	or more time to decode the Linux driver. - Ken
*/
		}
		inb(0x84);
	}
}
#endif
#ifdef	INCLUDE_3C503
#ifdef	T503_AUI
	nic->flags = 1;		/* aui */
#else
	nic->flags = 0;		/* no aui */
#endif
        /******************************************************************
        Search for 3Com 3c503 if no WD/SMC cards
        ******************************************************************/
	if (eth_vendor == VENDOR_NONE) {
		int	idx;
		int	iobase_reg, membase_reg;
		static unsigned short	base[] = {
			0x300, 0x310, 0x330, 0x350,
			0x250, 0x280, 0x2A0, 0x2E0, 0 };

		/* Loop through possible addresses checking each one */

		for (idx = 0; (eth_nic_base = base[idx]) != 0; ++idx) {

			eth_asic_base = eth_nic_base + _3COM_ASIC_OFFSET;
/*
 * Note that we use the same settings for both 8 and 16 bit cards:
 * both have an 8K bank of memory at page 1 while only the 16 bit
 * cards have a bank at page 0.
 */
			eth_memsize = MEM_16384;
			eth_tx_start = 32;
			eth_rx_start = 32 + D8390_TXBUF_SIZE;

		/* Check our base address. iobase and membase should */
		/* both have a maximum of 1 bit set or be 0. */

			iobase_reg = inb(eth_asic_base + _3COM_BCFR);
			membase_reg = inb(eth_asic_base + _3COM_PCFR);

			if ((iobase_reg & (iobase_reg - 1)) ||
				(membase_reg & (membase_reg - 1)))
				continue;		/* nope */

		/* Now get the shared memory address */

			eth_flags = 0;

			switch (membase_reg) {
				case _3COM_PCFR_DC000:
					eth_bmem = 0xdc000;
					break;
				case _3COM_PCFR_D8000:
					eth_bmem = 0xd8000;
					break;
				case _3COM_PCFR_CC000:
					eth_bmem = 0xcc000;
					break;
				case _3COM_PCFR_C8000:
					eth_bmem = 0xc8000;
					break;
				case _3COM_PCFR_PIO:
					eth_flags |= FLAG_PIO;
					eth_bmem = 0;
					break;
				default:
					continue;	/* nope */
				}
			break;
		}

		if (base[idx] == 0)		/* not found */
			return (0);
#ifndef	T503_SHMEM
		eth_flags |= FLAG_PIO;		/* force PIO mode */
		eth_bmem = 0;
#endif
		eth_vendor = VENDOR_3COM;


        /* Need this to make ns8390_poll() happy. */

                eth_rmem = eth_bmem - 0x2000;

        /* Reset NIC and ASIC */

                outb(_3COM_CR_RST | _3COM_CR_XSEL, eth_asic_base + _3COM_CR );
                outb(_3COM_CR_XSEL, eth_asic_base + _3COM_CR );

        /* Get our ethernet address */

                outb(_3COM_CR_EALO | _3COM_CR_XSEL, eth_asic_base + _3COM_CR);
		nic->ioaddr = eth_nic_base;
                DBG ( "\n3Com 3c503 base %4.4x, ", eth_nic_base );
                if (eth_flags & FLAG_PIO)
			DBG ( "PIO mode" );
                else
			DBG ( "memory %4.4x", eth_bmem );
                for (i=0; i<ETH_ALEN; i++) {
                        nic->node_addr[i] = inb(eth_nic_base+i);
                }
                DBG ( ", %s, MAC Addr %s\n", nic->flags ? "AUI" : "internal xcvr",
		      eth_ntoa ( nic->node_addr ) );

                outb(_3COM_CR_XSEL, eth_asic_base + _3COM_CR);
        /*
         * Initialize GA configuration register. Set bank and enable shared
         * mem. We always use bank 1. Disable interrupts.
         */
                outb(_3COM_GACFR_RSEL |
			_3COM_GACFR_MBS0 | _3COM_GACFR_TCM | _3COM_GACFR_NIM, eth_asic_base + _3COM_GACFR);

                outb(0xff, eth_asic_base + _3COM_VPTR2);
                outb(0xff, eth_asic_base + _3COM_VPTR1);
                outb(0x00, eth_asic_base + _3COM_VPTR0);
        /*
         * Clear memory and verify that it worked (we use only 8K)
         */

		if (!(eth_flags & FLAG_PIO)) {
			memset(bus_to_virt(eth_bmem), 0, 0x2000);
			for(i = 0; i < 0x2000; ++i)
				if (*((char *)(bus_to_virt(eth_bmem+i)))) {
					printf ("Failed to clear 3c503 shared mem.\n");
					return (0);
				}
		}
        /*
         * Initialize GA page/start/stop registers.
         */
                outb(eth_tx_start, eth_asic_base + _3COM_PSTR);
                outb(eth_memsize, eth_asic_base + _3COM_PSPR);
        }
#endif
#if	defined(INCLUDE_NE) || defined(INCLUDE_NS8390)
{
	/******************************************************************
	Search for NE1000/2000 if no WD/SMC or 3com cards
	******************************************************************/
	unsigned char c;
	if (eth_vendor == VENDOR_NONE) {
		unsigned char romdata[16];
		unsigned char testbuf[32];
		int idx;
		static unsigned char test[] = "NE*000 memory";
		static unsigned short base[] = {
#ifdef	NE_SCAN
			NE_SCAN,
#endif
			0 };
		/* if no addresses supplied, fall back on defaults */
		if (probe_addrs == NULL || probe_addrs[0] == 0)
			probe_addrs = base;
		eth_bmem = 0;		/* No shared memory */
		for (idx = 0; (eth_nic_base = probe_addrs[idx]) != 0; ++idx) {
			eth_flags = FLAG_PIO;
			eth_asic_base = eth_nic_base + NE_ASIC_OFFSET;
			eth_memsize = MEM_16384;
			eth_tx_start = 32;
			eth_rx_start = 32 + D8390_TXBUF_SIZE;
			c = inb(eth_asic_base + NE_RESET);
			outb(c, eth_asic_base + NE_RESET);
			(void) inb(0x84);
			outb(D8390_COMMAND_STP |
				D8390_COMMAND_RD2, eth_nic_base + D8390_P0_COMMAND);
			outb(D8390_RCR_MON, eth_nic_base + D8390_P0_RCR);
			outb(D8390_DCR_FT1 | D8390_DCR_LS, eth_nic_base + D8390_P0_DCR);
			outb(MEM_8192, eth_nic_base + D8390_P0_PSTART);
			outb(MEM_16384, eth_nic_base + D8390_P0_PSTOP);
#ifdef	NS8390_FORCE_16BIT
			eth_flags |= FLAG_16BIT;	/* force 16-bit mode */
#endif

			eth_pio_write( (unsigned char *) test, 8192, sizeof(test));
			eth_pio_read(8192, testbuf, sizeof(test));
			if (!memcmp(test, testbuf, sizeof(test)))
				break;
			eth_flags |= FLAG_16BIT;
			eth_memsize = MEM_32768;
			eth_tx_start = 64;
			eth_rx_start = 64 + D8390_TXBUF_SIZE;
			outb(D8390_DCR_WTS |
				D8390_DCR_FT1 | D8390_DCR_LS, eth_nic_base + D8390_P0_DCR);
			outb(MEM_16384, eth_nic_base + D8390_P0_PSTART);
			outb(MEM_32768, eth_nic_base + D8390_P0_PSTOP);
			eth_pio_write( (unsigned char *) test, 16384, sizeof(test));
			eth_pio_read(16384, testbuf, sizeof(test));
			if (!memcmp(testbuf, test, sizeof(test)))
				break;
		}
		if (eth_nic_base == 0)
			return (0);
		if (eth_nic_base > ISA_MAX_ADDR)	/* PCI probably */
			eth_flags |= FLAG_16BIT;
		eth_vendor = VENDOR_NOVELL;
		eth_pio_read(0, romdata, sizeof(romdata));
		for (i=0; i<ETH_ALEN; i++) {
			nic->node_addr[i] = romdata[i + ((eth_flags & FLAG_16BIT) ? i : 0)];
		}
		nic->ioaddr = eth_nic_base;
		DBG ( "\nNE%c000 base %4.4x, MAC Addr %s\n",
		      (eth_flags & FLAG_16BIT) ? '2' : '1', eth_nic_base,
		      eth_ntoa ( nic->node_addr ) );
	}
}
#endif
	if (eth_vendor == VENDOR_NONE)
		return(0);
        if (eth_vendor != VENDOR_3COM)
		eth_rmem = eth_bmem;
	ns8390_reset(nic);
	nic->nic_op	= &ns8390_operations;

        /* Based on PnP ISA map */
#ifdef	INCLUDE_WD
        dev->devid.vendor_id = htons(GENERIC_ISAPNP_VENDOR);
        dev->devid.device_id = htons(0x812a);
#endif
#ifdef	INCLUDE_3C503
        dev->devid.vendor_id = htons(GENERIC_ISAPNP_VENDOR);
        dev->devid.device_id = htons(0x80f3);
#endif
#ifdef	INCLUDE_NE
        dev->devid.vendor_id = htons(GENERIC_ISAPNP_VENDOR);
        dev->devid.device_id = htons(0x80d6);
#endif
	return 1;
}

#ifdef	INCLUDE_WD
struct isa_driver wd_driver __isa_driver = {
	.type    = NIC_DRIVER,
	.name    = "WD",
	.probe   = wd_probe,
	.ioaddrs = 0, 
};
ISA_ROM("wd","WD8003/8013, SMC8216/8416, SMC 83c790 (EtherEZ)");
#endif

#ifdef	INCLUDE_3C503
struct isa_driver t503_driver __isa_driver = {
	.type    = NIC_DRIVER,
	.name    = "3C503",
	.probe   = t503_probe,
	.ioaddrs = 0, 
};
ISA_ROM("3c503","3Com503, Etherlink II[/16]");
#endif

#ifdef	INCLUDE_NE
struct isa_driver ne_driver __isa_driver = {
	.type    = NIC_DRIVER,
	.name    = "NE*000",
	.probe   = ne_probe,
	.ioaddrs = 0, 
};
ISA_ROM("ne","NE1000/2000 and clones");
#endif

#ifdef	INCLUDE_NS8390
static struct pci_device_id nepci_nics[] = {
/* A few NE2000 PCI clones, list not exhaustive */
PCI_ROM(0x10ec, 0x8029, "rtl8029",      "Realtek 8029", 0),
PCI_ROM(0x1186, 0x0300, "dlink-528",    "D-Link DE-528", 0),
PCI_ROM(0x1050, 0x0940, "winbond940",   "Winbond NE2000-PCI", 0),		/* Winbond 86C940 / 89C940 */
PCI_ROM(0x1050, 0x5a5a, "winbond940f",  "Winbond W89c940F", 0),		/* Winbond 89C940F */
PCI_ROM(0x11f6, 0x1401, "compexrl2000", "Compex ReadyLink 2000", 0),
PCI_ROM(0x8e2e, 0x3000, "ktiet32p2",    "KTI ET32P2", 0),
PCI_ROM(0x4a14, 0x5000, "nv5000sc",     "NetVin NV5000SC", 0),
PCI_ROM(0x12c3, 0x0058, "holtek80232",  "Holtek HT80232", 0),
PCI_ROM(0x12c3, 0x5598, "holtek80229",  "Holtek HT80229", 0),
PCI_ROM(0x10bd, 0x0e34, "surecom-ne34", "Surecom NE34", 0),
PCI_ROM(0x1106, 0x0926, "via86c926",    "Via 86c926", 0),
};

PCI_DRIVER ( nepci_driver, nepci_nics, PCI_NO_CLASS );

DRIVER ( "NE2000/PCI", nic_driver, pci_driver, nepci_driver,
	 nepci_probe, ns8390_disable );

#endif /* INCLUDE_NS8390 */

#endif

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
