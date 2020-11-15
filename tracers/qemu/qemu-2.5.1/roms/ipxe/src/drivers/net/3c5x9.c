/**************************************************************************
ETHERBOOT -  BOOTP/TFTP Bootstrap Program

Author: Martin Renters.
  Date: Mar 22 1995

 This code is based heavily on David Greenman's if_ed.c driver and
  Andres Vega Garcia's if_ep.c driver.

 Copyright (C) 1993-1994, David Greenman, Martin Renters.
 Copyright (C) 1993-1995, Andres Vega Garcia.
 Copyright (C) 1995, Serge Babkin.
  This software may be used, modified, copied, distributed, and sold, in
  both source and binary form provided that the above copyright and these
  terms are retained. Under no circumstances are the authors responsible for
  the proper functioning of this software, nor do the authors assume any
  responsibility for damages incurred with its use.

3c509 support added by Serge Babkin (babkin@hq.icb.chel.su)

$Id$

***************************************************************************/

FILE_LICENCE ( BSD2 );

/* #define EDEBUG */

#include <ipxe/ethernet.h>
#include "etherboot.h"
#include "nic.h"
#include <ipxe/isa.h>
#include "3c509.h"

static enum { none, bnc, utp } connector = none;	/* for 3C509 */

/**************************************************************************
ETH_RESET - Reset adapter
***************************************************************************/
void t5x9_disable ( struct nic *nic ) {
	/* stop card */
	outw(RX_DISABLE, nic->ioaddr + EP_COMMAND);
	outw(RX_DISCARD_TOP_PACK, nic->ioaddr + EP_COMMAND);
	while (inw(nic->ioaddr + EP_STATUS) & S_COMMAND_IN_PROGRESS)
		;
	outw(TX_DISABLE, nic->ioaddr + EP_COMMAND);
	outw(STOP_TRANSCEIVER, nic->ioaddr + EP_COMMAND);
	udelay(1000);
	outw(RX_RESET, nic->ioaddr + EP_COMMAND);
	outw(TX_RESET, nic->ioaddr + EP_COMMAND);
	outw(C_INTR_LATCH, nic->ioaddr + EP_COMMAND);
	outw(SET_RD_0_MASK, nic->ioaddr + EP_COMMAND);
	outw(SET_INTR_MASK, nic->ioaddr + EP_COMMAND);
	outw(SET_RX_FILTER, nic->ioaddr + EP_COMMAND);

	/*
	 * wait for reset to complete
	 */
	while (inw(nic->ioaddr + EP_STATUS) & S_COMMAND_IN_PROGRESS)
		;

	GO_WINDOW(nic->ioaddr,0);

	/* Disable the card */
	outw(0, nic->ioaddr + EP_W0_CONFIG_CTRL);

	/* Configure IRQ to none */
	outw(SET_IRQ(0), nic->ioaddr + EP_W0_RESOURCE_CFG);
}

static void t509_enable ( struct nic *nic ) {
	int i;

	/* Enable the card */
	GO_WINDOW(nic->ioaddr,0);
	outw(ENABLE_DRQ_IRQ, nic->ioaddr + EP_W0_CONFIG_CTRL);

	GO_WINDOW(nic->ioaddr,2);

	/* Reload the ether_addr. */
	for (i = 0; i < ETH_ALEN; i++)
		outb(nic->node_addr[i], nic->ioaddr + EP_W2_ADDR_0 + i);

	outw(RX_RESET, nic->ioaddr + EP_COMMAND);
	outw(TX_RESET, nic->ioaddr + EP_COMMAND);

	/* Window 1 is operating window */
	GO_WINDOW(nic->ioaddr,1);
	for (i = 0; i < 31; i++)
		inb(nic->ioaddr + EP_W1_TX_STATUS);

	/* get rid of stray intr's */
	outw(ACK_INTR | 0xff, nic->ioaddr + EP_COMMAND);

	outw(SET_RD_0_MASK | S_5_INTS, nic->ioaddr + EP_COMMAND);

	outw(SET_INTR_MASK, nic->ioaddr + EP_COMMAND);

	outw(SET_RX_FILTER | FIL_GROUP | FIL_INDIVIDUAL | FIL_BRDCST,
	     nic->ioaddr + EP_COMMAND);

	/* configure BNC */
	if (connector == bnc) {
		outw(START_TRANSCEIVER, nic->ioaddr + EP_COMMAND);
		udelay(1000);
	}
	/* configure UTP */
	else if (connector == utp) {
		GO_WINDOW(nic->ioaddr,4);
		outw(ENABLE_UTP, nic->ioaddr + EP_W4_MEDIA_TYPE);
		sleep(2);	/* Give time for media to negotiate */
		GO_WINDOW(nic->ioaddr,1);
	}

	/* start transceiver and receiver */
	outw(RX_ENABLE, nic->ioaddr + EP_COMMAND);
	outw(TX_ENABLE, nic->ioaddr + EP_COMMAND);

	/* set early threshold for minimal packet length */
	outw(SET_RX_EARLY_THRESH | ETH_ZLEN, nic->ioaddr + EP_COMMAND);
	outw(SET_TX_START_THRESH | 16, nic->ioaddr + EP_COMMAND);
}

static void t509_reset ( struct nic *nic ) {
	t5x9_disable ( nic );
	t509_enable ( nic );
}    

/**************************************************************************
ETH_TRANSMIT - Transmit a frame
***************************************************************************/
static char padmap[] = {
	0, 3, 2, 1};

static void t509_transmit(
struct nic *nic,
const char *d,			/* Destination */
unsigned int t,			/* Type */
unsigned int s,			/* size */
const char *p)			/* Packet */
{
	register unsigned int len;
	int pad;
	int status;

#ifdef	EDEBUG
	printf("{l=%d,t=%hX}",s+ETH_HLEN,t);
#endif

	/* swap bytes of type */
	t= htons(t);

	len=s+ETH_HLEN; /* actual length of packet */
	pad = padmap[len & 3];

	/*
	* The 3c509 automatically pads short packets to minimum ethernet length,
	* but we drop packets that are too large. Perhaps we should truncate
	* them instead?
	*/
	if (len + pad > ETH_FRAME_LEN) {
		return;
	}

	/* drop acknowledgements */
	while ((status=inb(nic->ioaddr + EP_W1_TX_STATUS)) & TXS_COMPLETE ) {
		if (status & (TXS_UNDERRUN|TXS_MAX_COLLISION|TXS_STATUS_OVERFLOW)) {
			outw(TX_RESET, nic->ioaddr + EP_COMMAND);
			outw(TX_ENABLE, nic->ioaddr + EP_COMMAND);
		}
		outb(0x0, nic->ioaddr + EP_W1_TX_STATUS);
	}

	while (inw(nic->ioaddr + EP_W1_FREE_TX) < (unsigned short)len + pad + 4)
		; /* no room in FIFO */

	outw(len, nic->ioaddr + EP_W1_TX_PIO_WR_1);
	outw(0x0, nic->ioaddr + EP_W1_TX_PIO_WR_1);	/* Second dword meaningless */

	/* write packet */
	outsw(nic->ioaddr + EP_W1_TX_PIO_WR_1, d, ETH_ALEN/2);
	outsw(nic->ioaddr + EP_W1_TX_PIO_WR_1, nic->node_addr, ETH_ALEN/2);
	outw(t, nic->ioaddr + EP_W1_TX_PIO_WR_1);
	outsw(nic->ioaddr + EP_W1_TX_PIO_WR_1, p, s / 2);
	if (s & 1)
		outb(*(p+s - 1), nic->ioaddr + EP_W1_TX_PIO_WR_1);

	while (pad--)
		outb(0, nic->ioaddr + EP_W1_TX_PIO_WR_1);	/* Padding */

	/* wait for Tx complete */
	while((inw(nic->ioaddr + EP_STATUS) & S_COMMAND_IN_PROGRESS) != 0)
		;
}

/**************************************************************************
ETH_POLL - Wait for a frame
***************************************************************************/
static int t509_poll(struct nic *nic, int retrieve)
{
	/* common variables */
	/* variables for 3C509 */
	short status, cst;
	register short rx_fifo;

	cst=inw(nic->ioaddr + EP_STATUS);

#ifdef	EDEBUG
	if(cst & 0x1FFF)
		printf("-%hX-",cst);
#endif

	if( (cst & S_RX_COMPLETE)==0 ) {
		/* acknowledge  everything */
		outw(ACK_INTR| (cst & S_5_INTS), nic->ioaddr + EP_COMMAND);
		outw(C_INTR_LATCH, nic->ioaddr + EP_COMMAND);

		return 0;
	}

	status = inw(nic->ioaddr + EP_W1_RX_STATUS);
#ifdef	EDEBUG
	printf("*%hX*",status);
#endif

	if (status & ERR_RX) {
		outw(RX_DISCARD_TOP_PACK, nic->ioaddr + EP_COMMAND);
		return 0;
	}

	rx_fifo = status & RX_BYTES_MASK;
	if (rx_fifo==0)
		return 0;

	if ( ! retrieve ) return 1;

		/* read packet */
#ifdef	EDEBUG
	printf("[l=%d",rx_fifo);
#endif
	insw(nic->ioaddr + EP_W1_RX_PIO_RD_1, nic->packet, rx_fifo / 2);
	if(rx_fifo & 1)
		nic->packet[rx_fifo-1]=inb(nic->ioaddr + EP_W1_RX_PIO_RD_1);
	nic->packetlen=rx_fifo;

	while(1) {
		status = inw(nic->ioaddr + EP_W1_RX_STATUS);
#ifdef	EDEBUG
		printf("*%hX*",status);
#endif
		rx_fifo = status & RX_BYTES_MASK;
		if(rx_fifo>0) {
			insw(nic->ioaddr + EP_W1_RX_PIO_RD_1, nic->packet+nic->packetlen, rx_fifo / 2);
			if(rx_fifo & 1)
				nic->packet[nic->packetlen+rx_fifo-1]=inb(nic->ioaddr + EP_W1_RX_PIO_RD_1);
			nic->packetlen+=rx_fifo;
#ifdef	EDEBUG
			printf("+%d",rx_fifo);
#endif
		}
		if(( status & RX_INCOMPLETE )==0) {
#ifdef	EDEBUG
			printf("=%d",nic->packetlen);
#endif
			break;
		}
		udelay(1000);	/* if incomplete wait 1 ms */
	}
	/* acknowledge reception of packet */
	outw(RX_DISCARD_TOP_PACK, nic->ioaddr + EP_COMMAND);
	while (inw(nic->ioaddr + EP_STATUS) & S_COMMAND_IN_PROGRESS)
		;
#ifdef	EDEBUG
{
	unsigned short type = 0;	/* used by EDEBUG */
	type = (nic->packet[12]<<8) | nic->packet[13];
	if(nic->packet[0]+nic->packet[1]+nic->packet[2]+nic->packet[3]+nic->packet[4]+
	    nic->packet[5] == 0xFF*ETH_ALEN)
		printf(",t=%hX,b]",type);
	else
		printf(",t=%hX]",type);
}
#endif
	return (1);
}

/**************************************************************************
ETH_IRQ - interrupt handling
***************************************************************************/
static void t509_irq(struct nic *nic __unused, irq_action_t action __unused)
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

/*************************************************************************
	3Com 509 - specific routines
**************************************************************************/

static int eeprom_rdy ( uint16_t ioaddr ) {
	int i;

	for (i = 0; is_eeprom_busy(ioaddr) && i < MAX_EEPROMBUSY; i++);
	if (i >= MAX_EEPROMBUSY) {
		/* printf("3c509: eeprom failed to come ready.\n"); */
		/* memory in EPROM is tight */
		/* printf("3c509: eeprom busy.\n"); */
		return (0);
	}
	return (1);
}

/*
 * get_e: gets a 16 bits word from the EEPROM.
 */
static int get_e ( uint16_t ioaddr, int offset ) {
	GO_WINDOW(ioaddr,0);
	if (!eeprom_rdy(ioaddr))
		return (0xffff);
	outw(EEPROM_CMD_RD | offset, ioaddr + EP_W0_EEPROM_COMMAND);
	if (!eeprom_rdy(ioaddr))
		return (0xffff);
	return (inw(ioaddr + EP_W0_EEPROM_DATA));
}

static struct nic_operations t509_operations = {
	.connect	= dummy_connect,
	.poll		= t509_poll,
	.transmit	= t509_transmit,
	.irq		= t509_irq,
};

/**************************************************************************
ETH_PROBE - Look for an adapter
***************************************************************************/
int t5x9_probe ( struct nic *nic,
		 uint16_t prod_id_check, uint16_t prod_id_mask ) {
	uint16_t prod_id;
	int i,j;
	unsigned short *p;
	
	/* Check product ID */
	prod_id = get_e ( nic->ioaddr, EEPROM_PROD_ID );
	if ( ( prod_id & prod_id_mask ) != prod_id_check ) {
		printf ( "EEPROM Product ID is incorrect (%hx & %hx != %hx)\n",
			 prod_id, prod_id_mask, prod_id_check );
		return 0;
	}

	/* test for presence of connectors */
	GO_WINDOW(nic->ioaddr,0);
	i = inw(nic->ioaddr + EP_W0_CONFIG_CTRL);
	j = (inw(nic->ioaddr + EP_W0_ADDRESS_CFG) >> 14) & 0x3;

	switch(j) {
	case 0:
		if (i & IS_UTP) {
			printf("10baseT\n");
			connector = utp;
		} else {
			printf("10baseT not present\n");
			return 0;
		}
		break;
	case 1:
		if (i & IS_AUI) {
			printf("10base5\n");
		} else {
			printf("10base5 not present\n");
			return 0;
		}
		break;
	case 3:
		if (i & IS_BNC) {
			printf("10base2\n");
			connector = bnc;
		} else {
			printf("10base2 not present\n");
			return 0;
		}
		break;
	default:
		printf("unknown connector\n");
		return 0;
	}

	/*
	* Read the station address from the eeprom
	*/
	p = (unsigned short *) nic->node_addr;
	for (i = 0; i < ETH_ALEN / 2; i++) {
		p[i] = htons(get_e(nic->ioaddr,i));
		GO_WINDOW(nic->ioaddr,2);
		outw(ntohs(p[i]), nic->ioaddr + EP_W2_ADDR_0 + (i * 2));
	}

	DBG ( "Ethernet Address: %s\n", eth_ntoa ( nic->node_addr ) );

	t509_reset(nic);

	nic->nic_op = &t509_operations;
	return 1;

}

/*
 * Local variables:
 *  c-basic-offset: 8
 * End:
 */
