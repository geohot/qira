#ifdef ALLMULTI
#error multicast support is not yet implemented
#endif
/**************************************************************************
Etherboot -  BOOTP/TFTP Bootstrap Program
Intel EEPRO/10 NIC driver for Etherboot
Adapted from Linux eepro.c from kernel 2.2.17

This board accepts a 32 pin EEPROM (29C256), however a test with a
27C010 shows that this EPROM also works in the socket, but it's not clear
how repeatably. The two top address pins appear to be held low, thus
the bottom 32kB of the 27C010 is visible in the CPU's address space.
To be sure you could put 4 copies of the code in the 27C010, then
it doesn't matter whether the extra lines are held low or high, just
hopefully not floating as CMOS chips don't like floating inputs.

Be careful with seating the EPROM as the socket on my board actually
has 34 pins, the top row of 2 are not used.
***************************************************************************/

/*

 timlegge	2005-05-18	remove the relocation changes cards that 
				write directly to the hardware don't need it
*/

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include "etherboot.h"
#include <errno.h>
#include "nic.h"
#include <ipxe/isa.h>
#include <ipxe/ethernet.h>

/* Different 82595 chips */
#define LAN595		0
#define LAN595TX	1
#define LAN595FX	2
#define LAN595FX_10ISA	3

#define	SLOW_DOWN	inb(0x80);

/* The station (ethernet) address prefix, used for IDing the board. */
#define SA_ADDR0 0x00	/* Etherexpress Pro/10 */
#define SA_ADDR1 0xaa
#define SA_ADDR2 0x00

#define GetBit(x,y) ((x & (1<<y))>>y)

/* EEPROM Word 0: */
#define ee_PnP       0  /* Plug 'n Play enable bit */
#define ee_Word1     1  /* Word 1? */
#define ee_BusWidth  2  /* 8/16 bit */
#define ee_FlashAddr 3  /* Flash Address */
#define ee_FlashMask 0x7   /* Mask */
#define ee_AutoIO    6  /* */
#define ee_reserved0 7  /* =0! */
#define ee_Flash     8  /* Flash there? */
#define ee_AutoNeg   9  /* Auto Negotiation enabled? */
#define ee_IO0       10 /* IO Address LSB */
#define ee_IO0Mask   0x /*...*/
#define ee_IO1       15 /* IO MSB */

/* EEPROM Word 1: */
#define ee_IntSel    0   /* Interrupt */
#define ee_IntMask   0x7
#define ee_LI        3   /* Link Integrity 0= enabled */
#define ee_PC        4   /* Polarity Correction 0= enabled */
#define ee_TPE_AUI   5   /* PortSelection 1=TPE */
#define ee_Jabber    6   /* Jabber prevention 0= enabled */
#define ee_AutoPort  7   /* Auto Port Selection 1= Disabled */
#define ee_SMOUT     8   /* SMout Pin Control 0= Input */
#define ee_PROM      9   /* Flash EPROM / PROM 0=Flash */
#define ee_reserved1 10  /* .. 12 =0! */
#define ee_AltReady  13  /* Alternate Ready, 0=normal */
#define ee_reserved2 14  /* =0! */
#define ee_Duplex    15

/* Word2,3,4: */
#define ee_IA5       0 /*bit start for individual Addr Byte 5 */
#define ee_IA4       8 /*bit start for individual Addr Byte 5 */
#define ee_IA3       0 /*bit start for individual Addr Byte 5 */
#define ee_IA2       8 /*bit start for individual Addr Byte 5 */
#define ee_IA1       0 /*bit start for individual Addr Byte 5 */
#define ee_IA0       8 /*bit start for individual Addr Byte 5 */

/* Word 5: */
#define ee_BNC_TPE   0 /* 0=TPE */
#define ee_BootType  1 /* 00=None, 01=IPX, 10=ODI, 11=NDIS */
#define ee_BootTypeMask 0x3 
#define ee_NumConn   3  /* Number of Connections 0= One or Two */
#define ee_FlashSock 4  /* Presence of Flash Socket 0= Present */
#define ee_PortTPE   5
#define ee_PortBNC   6
#define ee_PortAUI   7
#define ee_PowerMgt  10 /* 0= disabled */
#define ee_CP        13 /* Concurrent Processing */
#define ee_CPMask    0x7

/* Word 6: */
#define ee_Stepping  0 /* Stepping info */
#define ee_StepMask  0x0F
#define ee_BoardID   4 /* Manucaturer Board ID, reserved */
#define ee_BoardMask 0x0FFF

/* Word 7: */
#define ee_INT_TO_IRQ 0 /* int to IRQ Mapping  = 0x1EB8 for Pro/10+ */
#define ee_FX_INT2IRQ 0x1EB8 /* the _only_ mapping allowed for FX chips */

/*..*/
#define ee_SIZE 0x40 /* total EEprom Size */
#define ee_Checksum 0xBABA /* initial and final value for adding checksum */


/* Card identification via EEprom:   */
#define ee_addr_vendor 0x10  /* Word offset for EISA Vendor ID */
#define ee_addr_id 0x11      /* Word offset for Card ID */
#define ee_addr_SN 0x12      /* Serial Number */
#define ee_addr_CRC_8 0x14   /* CRC over last thee Bytes */


#define ee_vendor_intel0 0x25  /* Vendor ID Intel */
#define ee_vendor_intel1 0xD4
#define ee_id_eepro10p0 0x10   /* ID for eepro/10+ */
#define ee_id_eepro10p1 0x31

/* now this section could be used by both boards: the oldies and the ee10:
 * ee10 uses tx buffer before of rx buffer and the oldies the inverse.
 * (aris)
 */
#define	RAM_SIZE	0x8000

#define	RCV_HEADER	8
#define RCV_DEFAULT_RAM	0x6000
#define RCV_RAM 	rcv_ram

static unsigned rcv_ram = RCV_DEFAULT_RAM;

#define XMT_HEADER	8
#define XMT_RAM		(RAM_SIZE - RCV_RAM)

#define XMT_START	((rcv_start + RCV_RAM) % RAM_SIZE)

#define RCV_LOWER_LIMIT	(rcv_start >> 8)
#define RCV_UPPER_LIMIT	(((rcv_start + RCV_RAM) - 2) >> 8)
#define XMT_LOWER_LIMIT	(XMT_START >> 8)
#define XMT_UPPER_LIMIT	(((XMT_START + XMT_RAM) - 2) >> 8)

#define RCV_START_PRO	0x00
#define RCV_START_10	XMT_RAM
					/* by default the old driver */
static unsigned rcv_start = RCV_START_PRO;

#define	RCV_DONE	0x0008
#define	RX_OK		0x2000
#define	RX_ERROR	0x0d81

#define	TX_DONE_BIT	0x0080
#define	CHAIN_BIT	0x8000
#define	XMT_STATUS	0x02
#define	XMT_CHAIN	0x04
#define	XMT_COUNT	0x06

#define	BANK0_SELECT	0x00		
#define	BANK1_SELECT	0x40		
#define	BANK2_SELECT	0x80		

/* Bank 0 registers */
#define	COMMAND_REG	0x00	/* Register 0 */
#define	MC_SETUP	0x03
#define	XMT_CMD		0x04
#define	DIAGNOSE_CMD	0x07
#define	RCV_ENABLE_CMD	0x08
#define	RCV_DISABLE_CMD	0x0a
#define	STOP_RCV_CMD	0x0b
#define	RESET_CMD	0x0e
#define	POWER_DOWN_CMD	0x18
#define	RESUME_XMT_CMD	0x1c
#define	SEL_RESET_CMD	0x1e
#define	STATUS_REG	0x01	/* Register 1 */
#define	RX_INT		0x02
#define	TX_INT		0x04
#define	EXEC_STATUS	0x30
#define	ID_REG		0x02	/* Register 2	*/
#define	R_ROBIN_BITS	0xc0	/* round robin counter */
#define	ID_REG_MASK	0x2c
#define	ID_REG_SIG	0x24
#define	AUTO_ENABLE	0x10
#define	INT_MASK_REG	0x03	/* Register 3	*/
#define	RX_STOP_MASK	0x01
#define	RX_MASK		0x02
#define	TX_MASK		0x04
#define	EXEC_MASK	0x08
#define	ALL_MASK	0x0f
#define	IO_32_BIT	0x10
#define	RCV_BAR		0x04	/* The following are word (16-bit) registers */
#define	RCV_STOP	0x06

#define	XMT_BAR_PRO	0x0a
#define	XMT_BAR_10	0x0b
static unsigned xmt_bar = XMT_BAR_PRO;

#define	HOST_ADDRESS_REG	0x0c
#define	IO_PORT		0x0e
#define	IO_PORT_32_BIT	0x0c

/* Bank 1 registers */
#define	REG1	0x01
#define	WORD_WIDTH	0x02
#define	INT_ENABLE	0x80
#define INT_NO_REG	0x02
#define	RCV_LOWER_LIMIT_REG	0x08
#define	RCV_UPPER_LIMIT_REG	0x09

#define	XMT_LOWER_LIMIT_REG_PRO	0x0a
#define	XMT_UPPER_LIMIT_REG_PRO	0x0b
#define	XMT_LOWER_LIMIT_REG_10	0x0b
#define	XMT_UPPER_LIMIT_REG_10	0x0a
static unsigned xmt_lower_limit_reg = XMT_LOWER_LIMIT_REG_PRO;
static unsigned xmt_upper_limit_reg = XMT_UPPER_LIMIT_REG_PRO;

/* Bank 2 registers */
#define	XMT_Chain_Int	0x20	/* Interrupt at the end of the transmit chain */
#define	XMT_Chain_ErrStop	0x40 /* Interrupt at the end of the chain even if there are errors */
#define	RCV_Discard_BadFrame	0x80 /* Throw bad frames away, and continue to receive others */
#define	REG2		0x02
#define	PRMSC_Mode	0x01
#define	Multi_IA	0x20
#define	REG3		0x03
#define	TPE_BIT		0x04
#define	BNC_BIT		0x20
#define	REG13		0x0d
#define	FDX		0x00
#define	A_N_ENABLE	0x02
	
#define	I_ADD_REG0	0x04
#define	I_ADD_REG1	0x05
#define	I_ADD_REG2	0x06
#define	I_ADD_REG3	0x07
#define	I_ADD_REG4	0x08
#define	I_ADD_REG5	0x09

#define EEPROM_REG_PRO	0x0a
#define EEPROM_REG_10	0x0b
static unsigned eeprom_reg = EEPROM_REG_PRO;

#define EESK 0x01
#define EECS 0x02
#define EEDI 0x04
#define EEDO 0x08

/* The horrible routine to read a word from the serial EEPROM. */
/* IMPORTANT - the 82595 will be set to Bank 0 after the eeprom is read */

/* The delay between EEPROM clock transitions. */
#define eeprom_delay() { udelay(40); }
#define EE_READ_CMD (6 << 6)

/* do a full reset; data sheet asks for 250us delay */
#define eepro_full_reset(ioaddr)	outb(RESET_CMD, ioaddr); udelay(255);

/* do a nice reset */
#define eepro_sel_reset(ioaddr) \
  do {  \
    outb ( SEL_RESET_CMD, ioaddr ); \
    (void) SLOW_DOWN; \
    (void) SLOW_DOWN; \
  } while (0)

/* clear all interrupts */
#define	eepro_clear_int(ioaddr)	outb(ALL_MASK, ioaddr + STATUS_REG)

/* enable rx */
#define	eepro_en_rx(ioaddr)	outb(RCV_ENABLE_CMD, ioaddr)

/* disable rx */
#define	eepro_dis_rx(ioaddr)	outb(RCV_DISABLE_CMD, ioaddr)

/* switch bank */
#define eepro_sw2bank0(ioaddr) outb(BANK0_SELECT, ioaddr)
#define eepro_sw2bank1(ioaddr) outb(BANK1_SELECT, ioaddr)
#define eepro_sw2bank2(ioaddr) outb(BANK2_SELECT, ioaddr)

static unsigned int	rx_start, tx_start;
static int		tx_last;
static unsigned	int	tx_end;
static int		eepro = 0;
static unsigned int	mem_start, mem_end = RCV_DEFAULT_RAM / 1024;

/**************************************************************************
RESET - Reset adapter
***************************************************************************/
static void eepro_reset(struct nic *nic)
{
	int		temp_reg, i;

	/* put the card in its initial state */
	eepro_sw2bank2(nic->ioaddr);	/* be careful, bank2 now */
	temp_reg = inb(nic->ioaddr + eeprom_reg);
	DBG("Stepping %d\n", temp_reg >> 5);
	if (temp_reg & 0x10)	/* check the TurnOff Enable bit */
		outb(temp_reg & 0xEF, nic->ioaddr + eeprom_reg);
	for (i = 0; i < ETH_ALEN; i++)	/* fill the MAC address */
		outb(nic->node_addr[i], nic->ioaddr + I_ADD_REG0 + i);
	temp_reg = inb(nic->ioaddr + REG1);
	/* setup Transmit Chaining and discard bad RCV frames */
	outb(temp_reg | XMT_Chain_Int | XMT_Chain_ErrStop
		| RCV_Discard_BadFrame, nic->ioaddr + REG1);
	temp_reg = inb(nic->ioaddr + REG2);		/* match broadcast */
	outb(temp_reg | 0x14, nic->ioaddr + REG2);
	temp_reg = inb(nic->ioaddr + REG3);
	outb(temp_reg & 0x3F, nic->ioaddr + REG3);	/* clear test mode */
	/* set the receiving mode */
	eepro_sw2bank1(nic->ioaddr);	/* be careful, bank1 now */
	/* initialise the RCV and XMT upper and lower limits */
	outb(RCV_LOWER_LIMIT, nic->ioaddr + RCV_LOWER_LIMIT_REG);
	outb(RCV_UPPER_LIMIT, nic->ioaddr + RCV_UPPER_LIMIT_REG);
	outb(XMT_LOWER_LIMIT, nic->ioaddr + xmt_lower_limit_reg);
	outb(XMT_UPPER_LIMIT, nic->ioaddr + xmt_upper_limit_reg);
	eepro_sw2bank0(nic->ioaddr);	/* Switch back to bank 0 */
	eepro_clear_int(nic->ioaddr);
	/* Initialise RCV */
	outw(rx_start = (RCV_LOWER_LIMIT << 8), nic->ioaddr + RCV_BAR);
	outw(((RCV_UPPER_LIMIT << 8) | 0xFE), nic->ioaddr + RCV_STOP);
 	/* Make sure 1st poll won't find a valid packet header */
 	outw((RCV_LOWER_LIMIT << 8), nic->ioaddr + HOST_ADDRESS_REG);
 	outw(0,                      nic->ioaddr + IO_PORT);
	/* Intialise XMT */
	outw((XMT_LOWER_LIMIT << 8), nic->ioaddr + xmt_bar);
	eepro_sel_reset(nic->ioaddr);
	tx_start = tx_end = (unsigned int) (XMT_LOWER_LIMIT << 8);
	tx_last = 0;
	eepro_en_rx(nic->ioaddr);
}

/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static int eepro_poll(struct nic *nic, int retrieve)
{
	unsigned int	rcv_car = rx_start;
	unsigned int	rcv_event, rcv_status, rcv_next_frame, rcv_size;

	/* return true if there's an ethernet packet ready to read */
	/* nic->packet should contain data on return */
	/* nic->packetlen should contain length of data */
#if	0
	if ((inb(nic->ioaddr + STATUS_REG) & 0x40) == 0)
		return (0);
	outb(0x40, nic->ioaddr + STATUS_REG);
#endif
	outw(rcv_car, nic->ioaddr + HOST_ADDRESS_REG);
	rcv_event = inw(nic->ioaddr + IO_PORT);
	if (rcv_event != RCV_DONE)
		return (0);

	/* FIXME: I'm guessing this might not work with this card, since
	   it looks like once a rcv_event is started it must be completed.
	   maybe there's another way. */
	if ( ! retrieve ) return 1;

	rcv_status = inw(nic->ioaddr + IO_PORT);
	rcv_next_frame = inw(nic->ioaddr + IO_PORT);
	rcv_size = inw(nic->ioaddr + IO_PORT);
#if	0
	printf("%hX %hX %d %hhX\n", rcv_status, rcv_next_frame, rcv_size,
		inb(nic->ioaddr + STATUS_REG));
#endif
	if ((rcv_status & (RX_OK|RX_ERROR)) != RX_OK) {
		printf("Receive error %hX\n", rcv_status);
		return (0);
	}
	rcv_size &= 0x3FFF;
	insw(nic->ioaddr + IO_PORT, nic->packet, ((rcv_size + 3) >> 1));
#if	0
{
	int i;
	for (i = 0; i < 48; i++) {
		printf("%hhX", nic->packet[i]);
		putchar(i % 16 == 15 ? '\n' : ' ');
	}
}
#endif
	nic->packetlen = rcv_size;
	rcv_car  = (rx_start + RCV_HEADER + rcv_size);
	rx_start = rcv_next_frame;
/* 
	hex_dump(rcv_car, nic->packetlen); 
*/

	if (rcv_car == 0)
		rcv_car = ((RCV_UPPER_LIMIT << 8) | 0xff);
	outw(rcv_car - 1, nic->ioaddr + RCV_STOP);
	return (1);
}

/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static void eepro_transmit(
	struct nic *nic,
	const char *d,			/* Destination */
	unsigned int t,			/* Type */
	unsigned int s,			/* size */
	const char *p)			/* Packet */
{
	unsigned int	status, tx_available, last, end, length;
	unsigned short	type;
	int		boguscount = 20;

	length = s + ETH_HLEN;
	if (tx_end > tx_start)
		tx_available = XMT_RAM - (tx_end - tx_start);
	else if (tx_end < tx_start)
		tx_available = tx_start - tx_end;
	else
		tx_available = XMT_RAM;
	assert ( length <= tx_available );
	last = tx_end;
	end = last + (((length + 3) >> 1) << 1) + XMT_HEADER;
	if (end >= (XMT_UPPER_LIMIT << 8)) {
		last = (XMT_LOWER_LIMIT << 8);
		end = last + (((length + 3) >> 1) << 1) + XMT_HEADER;
	}
	outw(last, nic->ioaddr + HOST_ADDRESS_REG);
	outw(XMT_CMD, nic->ioaddr + IO_PORT);
	outw(0, nic->ioaddr + IO_PORT);
	outw(end, nic->ioaddr + IO_PORT);
	outw(length, nic->ioaddr + IO_PORT);
	outsw(nic->ioaddr + IO_PORT, d, ETH_ALEN / 2);
	outsw(nic->ioaddr + IO_PORT, nic->node_addr, ETH_ALEN / 2);
	type = htons(t);
	outsw(nic->ioaddr + IO_PORT, &type, sizeof(type) / 2);
	outsw(nic->ioaddr + IO_PORT, p, (s + 3) >> 1);
	/* A dummy read to flush the DRAM write pipeline */
	status = inw(nic->ioaddr + IO_PORT);
	outw(last, nic->ioaddr + xmt_bar);
	outb(XMT_CMD, nic->ioaddr);
	tx_start = last;
	tx_last = last;
	tx_end = end;
#if	0
	printf("%d %d\n", tx_start, tx_end);
#endif
	while (boguscount > 0) {
		if (((status = inw(nic->ioaddr + IO_PORT)) & TX_DONE_BIT) == 0) {
			udelay(40);
			boguscount--;
			continue;
		}
		if ((status & 0x2000) == 0) {
			DBG("Transmit status %hX\n", status);
		}
	}
}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void eepro_disable ( struct nic *nic, struct isa_device *isa __unused ) {
	eepro_sw2bank0(nic->ioaddr);	/* Switch to bank 0 */
	/* Flush the Tx and disable Rx */
	outb(STOP_RCV_CMD, nic->ioaddr);
	tx_start = tx_end = (XMT_LOWER_LIMIT << 8);
	tx_last = 0;
	/* Reset the 82595 */
	eepro_full_reset(nic->ioaddr);
}

/**************************************************************************
DISABLE - Enable, Disable, or Force interrupts
***************************************************************************/
static void eepro_irq(struct nic *nic __unused, irq_action_t action __unused)
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

static int read_eeprom(uint16_t ioaddr, int location)
{
	int		i;
	unsigned short	retval = 0;
	int		ee_addr = ioaddr + eeprom_reg;
	int		read_cmd = location | EE_READ_CMD;
	int		ctrl_val = EECS;

	if (eepro == LAN595FX_10ISA) {
		eepro_sw2bank1(ioaddr);
		outb(0x00, ioaddr + STATUS_REG);
	}
	eepro_sw2bank2(ioaddr);
	outb(ctrl_val, ee_addr);
	/* shift the read command bits out */
	for (i = 8; i >= 0; i--) {
		short outval = (read_cmd & (1 << i)) ? ctrl_val | EEDI : ctrl_val;
		outb(outval, ee_addr);
		outb(outval | EESK, ee_addr);	/* EEPROM clock tick */
		eeprom_delay();
		outb(outval, ee_addr);		/* finish EEPROM clock tick */
		eeprom_delay();
	}
	outb(ctrl_val, ee_addr);
	for (i = 16; i > 0; i--) {
		outb(ctrl_val | EESK, ee_addr);
		eeprom_delay();
		retval = (retval << 1) | ((inb(ee_addr) & EEDO) ? 1 : 0);
		outb(ctrl_val, ee_addr);
		eeprom_delay();
	}
	/* terminate the EEPROM access */
	ctrl_val &= ~EECS;
	outb(ctrl_val | EESK, ee_addr);
	eeprom_delay();
	outb(ctrl_val, ee_addr);
	eeprom_delay();
	eepro_sw2bank0(ioaddr);
	return (retval);
}

static int eepro_probe1 ( isa_probe_addr_t ioaddr ) {
	int		id, counter;

	id = inb(ioaddr + ID_REG);
	if ((id & ID_REG_MASK) != ID_REG_SIG)
		return (0);
	counter = id & R_ROBIN_BITS;
	if (((id = inb(ioaddr + ID_REG)) & R_ROBIN_BITS) != (counter + 0x40))
		return (0);
	/* yes the 82595 has been found */
	return (1);
}

static struct nic_operations eepro_operations = {
	.connect	= dummy_connect,
	.poll		= eepro_poll,
	.transmit	= eepro_transmit,
	.irq		= eepro_irq,

};

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
***************************************************************************/
static int eepro_probe ( struct nic *nic, struct isa_device *isa ) {

	int		i, l_eepro = 0;
	union {
		unsigned char	caddr[ETH_ALEN];
		unsigned short	saddr[ETH_ALEN/2];
	} station_addr;
	const char *name;

	nic->irqno  = 0;
	nic->ioaddr = isa->ioaddr;

	station_addr.saddr[2] = read_eeprom(nic->ioaddr,2);
	if ( ( station_addr.saddr[2] == 0x0000 ) ||
	     ( station_addr.saddr[2] == 0xFFFF ) ) {
		l_eepro = 3;
		eepro = LAN595FX_10ISA;
		eeprom_reg= EEPROM_REG_10;
		rcv_start = RCV_START_10;
		xmt_lower_limit_reg = XMT_LOWER_LIMIT_REG_10;
		xmt_upper_limit_reg = XMT_UPPER_LIMIT_REG_10;
		station_addr.saddr[2] = read_eeprom(nic->ioaddr,2);
	}
	station_addr.saddr[1] = read_eeprom(nic->ioaddr,3);
	station_addr.saddr[0] = read_eeprom(nic->ioaddr,4);
	if (l_eepro)
		name = "Intel EtherExpress 10 ISA";
	else if (read_eeprom(nic->ioaddr,7) == ee_FX_INT2IRQ) {
		name = "Intel EtherExpress Pro/10+ ISA";
		l_eepro = 2;
	} else if (station_addr.saddr[0] == SA_ADDR1) {
		name = "Intel EtherExpress Pro/10 ISA";
		l_eepro = 1;
	} else {
		l_eepro = 0;
		name = "Intel 82595-based LAN card";
	}
	station_addr.saddr[0] = bswap_16(station_addr.saddr[0]);
	station_addr.saddr[1] = bswap_16(station_addr.saddr[1]);
	station_addr.saddr[2] = bswap_16(station_addr.saddr[2]);
	for (i = 0; i < ETH_ALEN; i++) {
		nic->node_addr[i] = station_addr.caddr[i];
	}

	DBG ( "%s ioaddr %#hX, addr %s", name, nic->ioaddr, eth_ntoa ( nic->node_addr ) );

	mem_start = RCV_LOWER_LIMIT << 8;
	if ((mem_end & 0x3F) < 3 || (mem_end & 0x3F) > 29)
		mem_end = RCV_UPPER_LIMIT << 8;
	else {
		mem_end = mem_end * 1024 + (RCV_LOWER_LIMIT << 8);
		rcv_ram = mem_end - (RCV_LOWER_LIMIT << 8);
	}
	printf(", Rx mem %dK, if %s\n", (mem_end - mem_start) >> 10,
		GetBit(read_eeprom(nic->ioaddr,5), ee_BNC_TPE) ? "BNC" : "TP");

	eepro_reset(nic);

	/* point to NIC specific routines */
	nic->nic_op	= &eepro_operations;
	return 1;
}

static isa_probe_addr_t eepro_probe_addrs[] = {
	0x300, 0x210, 0x240, 0x280, 0x2C0, 0x200, 0x320, 0x340, 0x360,
};

ISA_DRIVER ( eepro_driver, eepro_probe_addrs, eepro_probe1,
		     GENERIC_ISAPNP_VENDOR, 0x828a );

DRIVER ( "eepro", nic_driver, isa_driver, eepro_driver,
	 eepro_probe, eepro_disable );

ISA_ROM ( "eepro", "Intel Etherexpress Pro/10" );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
