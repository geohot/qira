#ifdef ALLMULTI
#error multicast support is not yet implemented
#endif

/**
   Per an email message from Russ Nelson <nelson@crynwr.com> on
   18 March 2008 this file is now licensed under GPL Version 2.

   From: Russ Nelson <nelson@crynwr.com>
   Date: Tue, 18 Mar 2008 12:42:00 -0400
   Subject: Re: [Etherboot-developers] cs89x0 driver in etherboot
   -- quote from email 
   As copyright holder, if I say it doesn't conflict with the GPL,
   then it doesn't conflict with the GPL.

   However, there's no point in causing people's brains to overheat,
   so yes, I grant permission for the code to be relicensed under the
   GPLv2.  Please make sure that this change in licensing makes its
   way upstream.  -russ 
   -- quote from email
**/

FILE_LICENCE ( GPL2_ONLY );

/* cs89x0.c: A Crystal Semiconductor CS89[02]0 driver for etherboot. */
/*
  Permission is granted to distribute the enclosed cs89x0.[ch] driver
  only in conjunction with the Etherboot package.  The code is
  ordinarily distributed under the GPL.
  
  Russ Nelson, January 2000

  ChangeLog:

  Thu Dec 6 22:40:00 1996  Markus Gutschke  <gutschk@math.uni-muenster.de>

  * disabled all "advanced" features; this should make the code more reliable

  * reorganized the reset function

  * always reset the address port, so that autoprobing will continue working

  * some cosmetic changes

  * 2.5

  Thu Dec 5 21:00:00 1996  Markus Gutschke  <gutschk@math.uni-muenster.de>

  * tested the code against a CS8900 card

  * lots of minor bug fixes and adjustments

  * this is the first release, that actually works! it still requires some
    changes in order to be more tolerant to different environments

  * 4

  Fri Nov 22 23:00:00 1996  Markus Gutschke  <gutschk@math.uni-muenster.de>

  * read the manuals for the CS89x0 chipsets and took note of all the
    changes that will be necessary in order to adapt Russel Nelson's code
    to the requirements of a BOOT-Prom

  * 6

  Thu Nov 19 22:00:00 1996  Markus Gutschke  <gutschk@math.uni-muenster.de>

  * Synched with Russel Nelson's current code (v1.00)

  * 2

  Thu Nov 12 18:00:00 1996  Markus Gutschke  <gutschk@math.uni-muenster.de>

  * Cleaned up some of the code and tried to optimize the code size.

  * 1.5

  Sun Nov 10 16:30:00 1996  Markus Gutschke  <gutschk@math.uni-muenster.de>

  * First experimental release. This code compiles fine, but I
  have no way of testing whether it actually works.

  * I did not (yet) bother to make the code 16bit aware, so for
  the time being, it will only work for Etherboot/32.

  * 12

  */

#include <errno.h>
#include <ipxe/ethernet.h>
#include "etherboot.h"
#include "nic.h"
#include <ipxe/isa.h>
#include "cs89x0.h"

static unsigned short	eth_nic_base;
static unsigned long    eth_mem_start;
static unsigned short   eth_irqno;
static unsigned short   eth_cs_type;	/* one of: CS8900, CS8920, CS8920M  */
static unsigned short   eth_auto_neg_cnf;
static unsigned short   eth_adapter_cnf;
static unsigned short	eth_linectl;

/*************************************************************************
	CS89x0 - specific routines
**************************************************************************/

static inline int readreg(int portno)
{
	outw(portno, eth_nic_base + ADD_PORT);
	return inw(eth_nic_base + DATA_PORT);
}

static inline void writereg(int portno, int value)
{
	outw(portno, eth_nic_base + ADD_PORT);
	outw(value, eth_nic_base + DATA_PORT);
	return;
}

/*************************************************************************
EEPROM access
**************************************************************************/

static int wait_eeprom_ready(void)
{
	unsigned long tmo = currticks() + 4*TICKS_PER_SEC;

	/* check to see if the EEPROM is ready, a timeout is used -
	   just in case EEPROM is ready when SI_BUSY in the
	   PP_SelfST is clear */
	while(readreg(PP_SelfST) & SI_BUSY) {
		if (currticks() >= tmo)
			return -1; }
	return 0;
}

static int get_eeprom_data(int off, int len, unsigned short *buffer)
{
	int i;

#ifdef	EDEBUG
	printf("\ncs: EEPROM data from %hX for %hX:",off,len);
#endif
	for (i = 0; i < len; i++) {
		if (wait_eeprom_ready() < 0)
			return -1;
		/* Now send the EEPROM read command and EEPROM location
		   to read */
		writereg(PP_EECMD, (off + i) | EEPROM_READ_CMD);
		if (wait_eeprom_ready() < 0)
			return -1;
		buffer[i] = readreg(PP_EEData);
#ifdef	EDEBUG
		if (!(i%10))
			printf("\ncs: ");
		printf("%hX ", buffer[i]);
#endif
	}
#ifdef	EDEBUG
	putchar('\n');
#endif

	return(0);
}

static int get_eeprom_chksum(int off __unused, int len, unsigned short *buffer)
{
	int  i, cksum;

	cksum = 0;
	for (i = 0; i < len; i++)
		cksum += buffer[i];
	cksum &= 0xffff;
	if (cksum == 0)
		return 0;
	return -1;
}

/*************************************************************************
Activate all of the available media and probe for network
**************************************************************************/

static void clrline(void)
{
	int i;

	putchar('\r');
	for (i = 79; i--; ) putchar(' ');
	printf("\rcs: ");
	return;
}

static void control_dc_dc(int on_not_off)
{
	unsigned int selfcontrol;
	unsigned long tmo = currticks() + TICKS_PER_SEC;

	/* control the DC to DC convertor in the SelfControl register.  */
	selfcontrol = HCB1_ENBL; /* Enable the HCB1 bit as an output */
	if (((eth_adapter_cnf & A_CNF_DC_DC_POLARITY) != 0) ^ on_not_off)
		selfcontrol |= HCB1;
	else
		selfcontrol &= ~HCB1;
	writereg(PP_SelfCTL, selfcontrol);

	/* Wait for the DC/DC converter to power up - 1000ms */
	while (currticks() < tmo);

	return;
}

static int detect_tp(void)
{
	unsigned long tmo;

	/* Turn on the chip auto detection of 10BT/ AUI */

	clrline(); printf("attempting %s:","TP");

        /* If connected to another full duplex capable 10-Base-T card
	   the link pulses seem to be lost when the auto detect bit in
	   the LineCTL is set.  To overcome this the auto detect bit
	   will be cleared whilst testing the 10-Base-T interface.
	   This would not be necessary for the sparrow chip but is
	   simpler to do it anyway. */
	writereg(PP_LineCTL, eth_linectl &~ AUI_ONLY);
	control_dc_dc(0);

        /* Delay for the hardware to work out if the TP cable is
	   present - 150ms */
	for (tmo = currticks() + 4; currticks() < tmo; );

	if ((readreg(PP_LineST) & LINK_OK) == 0)
		return 0;

	if (eth_cs_type != CS8900) {

		writereg(PP_AutoNegCTL, eth_auto_neg_cnf & AUTO_NEG_MASK);

		if ((eth_auto_neg_cnf & AUTO_NEG_BITS) == AUTO_NEG_ENABLE) {
			printf(" negotiating duplex... ");
			while (readreg(PP_AutoNegST) & AUTO_NEG_BUSY) {
				if (currticks() - tmo > 40*TICKS_PER_SEC) {
					printf("time out ");
					break;
				}
			}
		}
		if (readreg(PP_AutoNegST) & FDX_ACTIVE)
			printf("using full duplex");
		else
			printf("using half duplex");
	}

	return A_CNF_MEDIA_10B_T;
}

/* send a test packet - return true if carrier bits are ok */
static int send_test_pkt(struct nic *nic)
{
	static unsigned char testpacket[] = { 0,0,0,0,0,0, 0,0,0,0,0,0,
				     0, 46, /*A 46 in network order       */
				     0, 0,  /*DSAP=0 & SSAP=0 fields      */
				     0xf3,0 /*Control (Test Req+P bit set)*/ };
	unsigned long tmo;

	writereg(PP_LineCTL, readreg(PP_LineCTL) | SERIAL_TX_ON);

	memcpy(testpacket, nic->node_addr, ETH_ALEN);
	memcpy(testpacket+ETH_ALEN, nic->node_addr, ETH_ALEN);

	outw(TX_AFTER_ALL, eth_nic_base + TX_CMD_PORT);
	outw(ETH_ZLEN, eth_nic_base + TX_LEN_PORT);

	/* Test to see if the chip has allocated memory for the packet */
	for (tmo = currticks() + 2;
	     (readreg(PP_BusST) & READY_FOR_TX_NOW) == 0; )
		if (currticks() >= tmo)
			return(0);

	/* Write the contents of the packet */
	outsw(eth_nic_base + TX_FRAME_PORT, testpacket,
	      (ETH_ZLEN+1)>>1);

	printf(" sending test packet ");
	/* wait a couple of timer ticks for packet to be received */
	for (tmo = currticks() + 2; currticks() < tmo; );

	if ((readreg(PP_TxEvent) & TX_SEND_OK_BITS) == TX_OK) {
			printf("succeeded");
			return 1;
	}
	printf("failed");
	return 0;
}


static int detect_aui(struct nic *nic)
{
	clrline(); printf("attempting %s:","AUI");
	control_dc_dc(0);

	writereg(PP_LineCTL, (eth_linectl & ~AUTO_AUI_10BASET) | AUI_ONLY);

	if (send_test_pkt(nic)) {
		return A_CNF_MEDIA_AUI; }
	else
		return 0;
}

static int detect_bnc(struct nic *nic)
{
	clrline(); printf("attempting %s:","BNC");
	control_dc_dc(1);

	writereg(PP_LineCTL, (eth_linectl & ~AUTO_AUI_10BASET) | AUI_ONLY);

	if (send_test_pkt(nic)) {
		return A_CNF_MEDIA_10B_2; }
	else
		return 0;
}

/**************************************************************************
ETH_RESET - Reset adapter
***************************************************************************/

static void cs89x0_reset(struct nic *nic)
{
	int  i;
	unsigned long reset_tmo;

	writereg(PP_SelfCTL, readreg(PP_SelfCTL) | POWER_ON_RESET);

	/* wait for two ticks; that is 2*55ms */
	for (reset_tmo = currticks() + 2; currticks() < reset_tmo; );

	if (eth_cs_type != CS8900) {
		/* Hardware problem requires PNP registers to be reconfigured
		   after a reset */
		if (eth_irqno != 0xFFFF) {
			outw(PP_CS8920_ISAINT, eth_nic_base + ADD_PORT);
			outb(eth_irqno, eth_nic_base + DATA_PORT);
			outb(0, eth_nic_base + DATA_PORT + 1); }

		if (eth_mem_start) {
			outw(PP_CS8920_ISAMemB, eth_nic_base + ADD_PORT);
			outb((eth_mem_start >> 8) & 0xff, eth_nic_base + DATA_PORT);
			outb((eth_mem_start >> 24) & 0xff, eth_nic_base + DATA_PORT + 1); } }

	/* Wait until the chip is reset */
	for (reset_tmo = currticks() + 2;
	     (readreg(PP_SelfST) & INIT_DONE) == 0 &&
		     currticks() < reset_tmo; );

	/* disable interrupts and memory accesses */
	writereg(PP_BusCTL, 0);

	/* set the ethernet address */
	for (i=0; i < ETH_ALEN/2; i++)
		writereg(PP_IA+i*2,
			 nic->node_addr[i*2] |
			 (nic->node_addr[i*2+1] << 8));

	/* receive only error free packets addressed to this card */
	writereg(PP_RxCTL, DEF_RX_ACCEPT);

	/* do not generate any interrupts on receive operations */
	writereg(PP_RxCFG, 0);

	/* do not generate any interrupts on transmit operations */
	writereg(PP_TxCFG, 0);

	/* do not generate any interrupts on buffer operations */
	writereg(PP_BufCFG, 0);

	/* reset address port, so that autoprobing will keep working */
	outw(PP_ChipID, eth_nic_base + ADD_PORT);

	return;
}

/**************************************************************************
ETH_TRANSMIT - Transmit a frame
***************************************************************************/

static void cs89x0_transmit(
	struct nic *nic,
	const char *d,			/* Destination */
	unsigned int t,			/* Type */
	unsigned int s,			/* size */
	const char *p)			/* Packet */
{
	unsigned long tmo;
	int           sr;

	/* does this size have to be rounded??? please,
	   somebody have a look in the specs */
	if ((sr = ((s + ETH_HLEN + 1)&~1)) < ETH_ZLEN)
		sr = ETH_ZLEN;

retry:
	/* initiate a transmit sequence */
	outw(TX_AFTER_ALL, eth_nic_base + TX_CMD_PORT);
	outw(sr, eth_nic_base + TX_LEN_PORT);

	/* Test to see if the chip has allocated memory for the packet */
	if ((readreg(PP_BusST) & READY_FOR_TX_NOW) == 0) {
		/* Oops... this should not happen! */
		printf("cs: unable to send packet; retrying...\n");
		for (tmo = currticks() + 5*TICKS_PER_SEC; currticks() < tmo; );
		cs89x0_reset(nic);
		goto retry; }

	/* Write the contents of the packet */
	outsw(eth_nic_base + TX_FRAME_PORT, d, ETH_ALEN/2);
	outsw(eth_nic_base + TX_FRAME_PORT, nic->node_addr,
	      ETH_ALEN/2);
	outw(((t >> 8)&0xFF)|(t << 8), eth_nic_base + TX_FRAME_PORT);
	outsw(eth_nic_base + TX_FRAME_PORT, p, (s+1)/2);
	for (sr = sr/2 - (s+1)/2 - ETH_ALEN - 1; sr > 0; sr--)
		outw(0, eth_nic_base + TX_FRAME_PORT);

	/* wait for transfer to succeed */
	for (tmo = currticks()+5*TICKS_PER_SEC;
	     (s = readreg(PP_TxEvent)&~0x1F) == 0 && currticks() < tmo;)
		/* nothing */ ;
	if ((s & TX_SEND_OK_BITS) != TX_OK) {
		printf("\ntransmission error %#hX\n", s);
	}

	return;
}

/**************************************************************************
ETH_POLL - Wait for a frame
***************************************************************************/

static int cs89x0_poll(struct nic *nic, int retrieve)
{
	int status;

	status = readreg(PP_RxEvent);

	if ((status & RX_OK) == 0)
		return(0);

	if ( ! retrieve ) return 1;

	status = inw(eth_nic_base + RX_FRAME_PORT);
	nic->packetlen = inw(eth_nic_base + RX_FRAME_PORT);
	insw(eth_nic_base + RX_FRAME_PORT, nic->packet, nic->packetlen >> 1);
	if (nic->packetlen & 1)
		nic->packet[nic->packetlen-1] = inw(eth_nic_base + RX_FRAME_PORT);
	return 1;
}

static void cs89x0_irq(struct nic *nic __unused, irq_action_t action __unused)
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

static struct nic_operations cs89x0_operations = {
	.connect	= dummy_connect,
	.poll		= cs89x0_poll,
	.transmit	= cs89x0_transmit,
	.irq		= cs89x0_irq,
};

/**************************************************************************
ETH_PROBE - Look for an adapter
***************************************************************************/

static int cs89x0_probe_addr ( isa_probe_addr_t ioaddr ) {
	/* if they give us an odd I/O address, then do ONE write to
	   the address port, to get it back to address zero, where we
	   expect to find the EISA signature word. */
	if (ioaddr & 1) {
		ioaddr &= ~1;
		if ((inw(ioaddr + ADD_PORT) & ADD_MASK) != ADD_SIG)
			return 0;
		outw(PP_ChipID, ioaddr + ADD_PORT);
	}
	
	if (inw(ioaddr + DATA_PORT) != CHIP_EISA_ID_SIG)
		return 0;

	return 1;
}

static int cs89x0_probe ( struct nic *nic, struct isa_device *isa __unused ) {
	int      i, result = -1;
	unsigned rev_type = 0, isa_cnf, cs_revision;
	unsigned short eeprom_buff[CHKSUM_LEN];

	nic->ioaddr &= ~1; /* LSB = 1 indicates a more aggressive probe */
	eth_nic_base = nic->ioaddr;

	/* get the chip type */
	rev_type = readreg(PRODUCT_ID_ADD);
	eth_cs_type = rev_type &~ REVISON_BITS;
	cs_revision = ((rev_type & REVISON_BITS) >> 8) + 'A';
	
	printf("\ncs: cs89%c0%s rev %c, base %#hX",
	       eth_cs_type==CS8900?'0':'2',
	       eth_cs_type==CS8920M?"M":"",
	       cs_revision,
	       eth_nic_base);
#ifndef EMBEDDED 
	/* First check to see if an EEPROM is attached*/
	if ((readreg(PP_SelfST) & EEPROM_PRESENT) == 0) {
		printf("\ncs: no EEPROM...\n");
		outw(PP_ChipID, eth_nic_base + ADD_PORT);
		return 0;
	} else if (get_eeprom_data(START_EEPROM_DATA,CHKSUM_LEN,
				   eeprom_buff) < 0) {
		printf("\ncs: EEPROM read failed...\n");
		outw(PP_ChipID, eth_nic_base + ADD_PORT);
		return 0;
	} else if (get_eeprom_chksum(START_EEPROM_DATA,CHKSUM_LEN,
				     eeprom_buff) < 0) {
		printf("\ncs: EEPROM checksum bad...\n");
		outw(PP_ChipID, eth_nic_base + ADD_PORT);
		return 0;
	}

	/* get transmission control word but keep the
	   autonegotiation bits */
	eth_auto_neg_cnf = eeprom_buff[AUTO_NEG_CNF_OFFSET/2];
	/* Store adapter configuration */
	eth_adapter_cnf = eeprom_buff[ADAPTER_CNF_OFFSET/2];
	/* Store ISA configuration */
	isa_cnf = eeprom_buff[ISA_CNF_OFFSET/2];
	
	/* store the initial memory base address */
	eth_mem_start = eeprom_buff[PACKET_PAGE_OFFSET/2] << 8;
	
	printf("%s%s%s, addr ",
	       (eth_adapter_cnf & A_CNF_10B_T)?", RJ-45":"",
	       (eth_adapter_cnf & A_CNF_AUI)?", AUI":"",
	       (eth_adapter_cnf & A_CNF_10B_2)?", BNC":"");
	
	/* If this is a CS8900 then no pnp soft */
	if (eth_cs_type != CS8900 &&
	    /* Check if the ISA IRQ has been set  */
	    (i = readreg(PP_CS8920_ISAINT) & 0xff,
	     (i != 0 && i < CS8920_NO_INTS)))
		eth_irqno = i;
	else {
		i = isa_cnf & INT_NO_MASK;
		if (eth_cs_type == CS8900) {
			/* the table that follows is dependent
			   upon how you wired up your cs8900
			   in your system.  The table is the
			   same as the cs8900 engineering demo
			   board.  irq_map also depends on the
			   contents of the table.  Also see
			   write_irq, which is the reverse
			   mapping of the table below. */
			if (i < 4) i = "\012\013\014\005"[i];
			else printf("\ncs: BUG: isa_config is %d\n", i); }
		eth_irqno = i; }
	
        nic->irqno = eth_irqno;

	/* Retrieve and print the ethernet address. */
	for (i=0; i<ETH_ALEN; i++) {
		nic->node_addr[i] = ((unsigned char *)eeprom_buff)[i];
	}

	DBG ( "%s\n", eth_ntoa ( nic->node_addr ) );

#endif
#ifdef EMBEDDED
	/* Retrieve and print the ethernet address. */
	{
		unsigned char MAC_HW_ADDR[6]={MAC_HW_ADDR_DRV};
		memcpy(nic->node_addr, MAC_HW_ADDR, 6);
	}

	DBG ( "%s\n", eth_ntoa ( nic->node_addr ) );
	
	eth_adapter_cnf = A_CNF_10B_T | A_CNF_MEDIA_10B_T;
	eth_auto_neg_cnf = EE_AUTO_NEG_ENABLE | IMM_BIT;
#endif
#ifndef EMBEDDED 
	/* Set the LineCTL quintuplet based on adapter
	   configuration read from EEPROM */
	if ((eth_adapter_cnf & A_CNF_EXTND_10B_2) &&
	    (eth_adapter_cnf & A_CNF_LOW_RX_SQUELCH))
		eth_linectl = LOW_RX_SQUELCH;
	else
		eth_linectl = 0;
	
	/* check to make sure that they have the "right"
	   hardware available */
	switch(eth_adapter_cnf & A_CNF_MEDIA_TYPE) {
	case A_CNF_MEDIA_10B_T: result = eth_adapter_cnf & A_CNF_10B_T;
		break;
	case A_CNF_MEDIA_AUI:   result = eth_adapter_cnf & A_CNF_AUI;
		break;
	case A_CNF_MEDIA_10B_2: result = eth_adapter_cnf & A_CNF_10B_2;
		break;
	default: result = eth_adapter_cnf & (A_CNF_10B_T | A_CNF_AUI |
					     A_CNF_10B_2);
	}
	if (!result) {
		printf("cs: EEPROM is configured for unavailable media\n");
	error:
		writereg(PP_LineCTL, readreg(PP_LineCTL) &
			 ~(SERIAL_TX_ON | SERIAL_RX_ON));
		outw(PP_ChipID, eth_nic_base + ADD_PORT);
		return 0;
	}
#endif
	/* Initialize the card for probing of the attached media */
	cs89x0_reset(nic);
	
	/* set the hardware to the configured choice */
	switch(eth_adapter_cnf & A_CNF_MEDIA_TYPE) {
	case A_CNF_MEDIA_10B_T:
		result = detect_tp();
		if (!result) {
			clrline();
			printf("10Base-T (RJ-45%s",
			       ") has no cable\n"); }
		/* check "ignore missing media" bit */
		if (eth_auto_neg_cnf & IMM_BIT)
			/* Yes! I don't care if I see a link pulse */
			result = A_CNF_MEDIA_10B_T;
		break;
	case A_CNF_MEDIA_AUI:
		result = detect_aui(nic);
		if (!result) {
			clrline();
			printf("10Base-5 (AUI%s",
			       ") has no cable\n"); }
		/* check "ignore missing media" bit */
		if (eth_auto_neg_cnf & IMM_BIT)
			/* Yes! I don't care if I see a carrrier */
			result = A_CNF_MEDIA_AUI;
		break;
	case A_CNF_MEDIA_10B_2:
		result = detect_bnc(nic);
		if (!result) {
			clrline();
			printf("10Base-2 (BNC%s",
			       ") has no cable\n"); }
		/* check "ignore missing media" bit */
		if (eth_auto_neg_cnf & IMM_BIT)
			/* Yes! I don't care if I can xmit a packet */
			result = A_CNF_MEDIA_10B_2;
		break;
	case A_CNF_MEDIA_AUTO:
		writereg(PP_LineCTL, eth_linectl | AUTO_AUI_10BASET);
		if (eth_adapter_cnf & A_CNF_10B_T)
			if ((result = detect_tp()) != 0)
				break;
		if (eth_adapter_cnf & A_CNF_AUI)
			if ((result = detect_aui(nic)) != 0)
				break;
		if (eth_adapter_cnf & A_CNF_10B_2)
			if ((result = detect_bnc(nic)) != 0)
				break;
		clrline(); printf("no media detected\n");
		goto error;
	}
	clrline();
	switch(result) {
	case 0:                 printf("no network cable attached to configured media\n");
		goto error;
	case A_CNF_MEDIA_10B_T: printf("using 10Base-T (RJ-45)\n");
		break;
	case A_CNF_MEDIA_AUI:   printf("using 10Base-5 (AUI)\n");
		break;
	case A_CNF_MEDIA_10B_2: printf("using 10Base-2 (BNC)\n");
		break;
	}
	
	/* Turn on both receive and transmit operations */
	writereg(PP_LineCTL, readreg(PP_LineCTL) | SERIAL_RX_ON |
		 SERIAL_TX_ON);
	
	return 0;
#ifdef EMBEDDED
 error:
	writereg(PP_LineCTL, readreg(PP_LineCTL) &
		 ~(SERIAL_TX_ON | SERIAL_RX_ON));
	outw(PP_ChipID, eth_nic_base + ADD_PORT);
	return 0;
#endif

	nic->nic_op   = &cs89x0_operations;
	return 1;
}

static void cs89x0_disable ( struct nic *nic,
			     struct isa_device *isa __unused ) {
	cs89x0_reset(nic);
}
	
static isa_probe_addr_t cs89x0_probe_addrs[] = { 
#ifndef EMBEDDED
	/* use "conservative" default values for autoprobing */
	0x300, 0x320, 0x340, 0x200, 0x220, 0x240,
	0x260, 0x280, 0x2a0, 0x2c0, 0x2e0,
	/* if that did not work, then be more aggressive */
	0x301, 0x321, 0x341, 0x201, 0x221, 0x241,
	0x261, 0x281, 0x2a1, 0x2c1, 0x2e1,
#else
	0x01000300,
#endif
};

ISA_DRIVER ( cs89x0_driver, cs89x0_probe_addrs, cs89x0_probe_addr,
	     ISAPNP_VENDOR('C','S','C'), 0x0007 );

DRIVER ( "cs89x0", nic_driver, isa_driver, cs89x0_driver,
	 cs89x0_probe, cs89x0_disable );

ISA_ROM ( "cs89x0", "Crystal Semiconductor CS89x0" );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
