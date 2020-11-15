
/* epic100.c: A SMC 83c170 EPIC/100 fast ethernet driver for Etherboot */

FILE_LICENCE ( GPL2_OR_LATER );

/* 05/06/2003	timlegge	Fixed relocation and implemented Multicast */
#define LINUX_OUT_MACROS

#include "etherboot.h"
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>
#include "nic.h"
#include "epic100.h"

/* Condensed operations for readability */
#define virt_to_le32desc(addr)	cpu_to_le32(virt_to_bus(addr))
#define le32desc_to_virt(addr)	bus_to_virt(le32_to_cpu(addr))

#define TX_RING_SIZE	2	/* use at least 2 buffers for TX */
#define RX_RING_SIZE	2

#define PKT_BUF_SZ	1536	/* Size of each temporary Tx/Rx buffer.*/

/*
#define DEBUG_RX
#define DEBUG_TX
#define DEBUG_EEPROM
*/

#define EPIC_DEBUG 0	/* debug level */

/* The EPIC100 Rx and Tx buffer descriptors. */
struct epic_rx_desc {
    unsigned long status;
    unsigned long bufaddr;
    unsigned long buflength;
    unsigned long next;
};
/* description of the tx descriptors control bits commonly used */
#define TD_STDFLAGS	TD_LASTDESC

struct epic_tx_desc {
    unsigned long status;
    unsigned long bufaddr;
    unsigned long buflength;
    unsigned long  next;
};

#define delay(nanosec)   do { int _i = 3; while (--_i > 0) \
                                     { __SLOW_DOWN_IO; }} while (0)

static void	epic100_open(void);
static void	epic100_init_ring(void);
static void	epic100_disable(struct nic *nic);
static int	epic100_poll(struct nic *nic, int retrieve);
static void	epic100_transmit(struct nic *nic, const char *destaddr,
				 unsigned int type, unsigned int len, const char *data);
#ifdef	DEBUG_EEPROM
static int	read_eeprom(int location);
#endif
static int	mii_read(int phy_id, int location);
static void     epic100_irq(struct nic *nic, irq_action_t action);

static struct nic_operations epic100_operations;

static int	ioaddr;

static int	command;
static int	intstat;
static int	intmask;
static int	genctl ;
static int	eectl  ;
static int	test   ;
static int	mmctl  ;
static int	mmdata ;
static int	lan0   ;
static int	mc0    ;
static int	rxcon  ;
static int	txcon  ;
static int	prcdar ;
static int	ptcdar ;
static int	eththr ;

static unsigned int	cur_rx, cur_tx;		/* The next free ring entry */
#ifdef	DEBUG_EEPROM
static unsigned short	eeprom[64];
#endif
static signed char	phys[4];		/* MII device addresses. */
struct {
	struct epic_rx_desc	rx_ring[RX_RING_SIZE]
	__attribute__ ((aligned(4)));
	struct epic_tx_desc	tx_ring[TX_RING_SIZE]
	__attribute__ ((aligned(4)));
	unsigned char	 	rx_packet[PKT_BUF_SZ * RX_RING_SIZE];
	unsigned char		tx_packet[PKT_BUF_SZ * TX_RING_SIZE];
} epic100_bufs __shared;
#define rx_ring epic100_bufs.rx_ring
#define tx_ring epic100_bufs.tx_ring
#define rx_packet epic100_bufs.rx_packet
#define tx_packet epic100_bufs.tx_packet

/***********************************************************************/
/*                    Externally visible functions                     */
/***********************************************************************/


static int
epic100_probe ( struct nic *nic, struct pci_device *pci ) {

    int i;
    unsigned short* ap;
    unsigned int phy, phy_idx;

    if (pci->ioaddr == 0)
	return 0;

    /* Ideally we would detect all network cards in slot order.  That would
       be best done a central PCI probe dispatch, which wouldn't work
       well with the current structure.  So instead we detect just the
       Epic cards in slot order. */

    ioaddr = pci->ioaddr;

    nic->irqno  = 0;
    nic->ioaddr = pci->ioaddr & ~3;

    /* compute all used static epic100 registers address */
    command = ioaddr + COMMAND;		/* Control Register */
    intstat = ioaddr + INTSTAT;		/* Interrupt Status */
    intmask = ioaddr + INTMASK;		/* Interrupt Mask */
    genctl  = ioaddr + GENCTL;		/* General Control */
    eectl   = ioaddr + EECTL;		/* EEPROM Control  */
    test    = ioaddr + TEST;		/* Test register (clocks) */
    mmctl   = ioaddr + MMCTL;		/* MII Management Interface Control */
    mmdata  = ioaddr + MMDATA;		/* MII Management Interface Data */
    lan0    = ioaddr + LAN0;		/* MAC address. (0x40-0x48) */
    mc0     = ioaddr + MC0; 		/* Multicast Control */
    rxcon   = ioaddr + RXCON;		/* Receive Control */
    txcon   = ioaddr + TXCON;		/* Transmit Control */
    prcdar  = ioaddr + PRCDAR;		/* PCI Receive Current Descr Address */
    ptcdar  = ioaddr + PTCDAR;		/* PCI Transmit Current Descr Address */
    eththr  = ioaddr + ETHTHR;		/* Early Transmit Threshold */

    /* Reset the chip & bring it out of low-power mode. */
    outl(GC_SOFT_RESET, genctl);

    /* Disable ALL interrupts by setting the interrupt mask. */
    outl(INTR_DISABLE, intmask);

    /*
     * set the internal clocks:
     * Application Note 7.15 says:
     *    In order to set the CLOCK TEST bit in the TEST register,
     *	  perform the following:
     *
     *        Write 0x0008 to the test register at least sixteen
     *        consecutive times.
     *
     * The CLOCK TEST bit is Write-Only. Writing it several times
     * consecutively insures a successful write to the bit...
     */

    for (i = 0; i < 16; i++) {
	outl(0x00000008, test);
    }

#ifdef	DEBUG_EEPROM
{
    unsigned short sum = 0;
    unsigned short value;
    for (i = 0; i < 64; i++) {
	value = read_eeprom(i);
	eeprom[i] = value;
	sum += value;
    }
}

#if	(EPIC_DEBUG > 1)
    printf("EEPROM contents\n");
    for (i = 0; i < 64; i++) {
	printf(" %hhX%s", eeprom[i], i % 16 == 15 ? "\n" : "");
    }
#endif
#endif

    /* This could also be read from the EEPROM. */
    ap = (unsigned short*)nic->node_addr;
    for (i = 0; i < 3; i++)
	*ap++ = inw(lan0 + i*4);

    DBG ( " I/O %4.4x %s ", ioaddr, eth_ntoa ( nic->node_addr ) );

    /* Find the connected MII xcvrs. */
    for (phy = 0, phy_idx = 0; phy < 32 && phy_idx < sizeof(phys); phy++) {
	int mii_status = mii_read(phy, 0);

	if (mii_status != 0xffff  && mii_status != 0x0000) {
	    phys[phy_idx++] = phy;
#if	(EPIC_DEBUG > 1)
	    printf("MII transceiver found at address %d.\n", phy);
#endif
	}
    }
    if (phy_idx == 0) {
#if	(EPIC_DEBUG > 1)
	printf("***WARNING***: No MII transceiver found!\n");
#endif
	/* Use the known PHY address of the EPII. */
	phys[0] = 3;
    }

    epic100_open();
    nic->nic_op	= &epic100_operations;

    return 1;
}

static void set_rx_mode(void)
{
	unsigned char mc_filter[8];
	int i;
	memset(mc_filter, 0xff, sizeof(mc_filter));
	outl(0x0C, rxcon);
	for(i = 0; i < 4; i++)
		outw(((unsigned short *)mc_filter)[i], mc0 + i*4);
	return;
}
	
   static void
epic100_open(void)
{
    int mii_reg5;
    unsigned long tmp;

    epic100_init_ring();

    /* Pull the chip out of low-power mode, and set for PCI read multiple. */
    outl(GC_RX_FIFO_THR_64 | GC_MRC_READ_MULT | GC_ONE_COPY, genctl);

    outl(TX_FIFO_THRESH, eththr);

    tmp = TC_EARLY_TX_ENABLE | TX_SLOT_TIME;

    mii_reg5 = mii_read(phys[0], 5);
    if (mii_reg5 != 0xffff && (mii_reg5 & 0x0100)) {
	printf(" full-duplex mode");
	tmp |= TC_LM_FULL_DPX;
    } else
	tmp |= TC_LM_NORMAL;

    outl(tmp, txcon);

    /* Give address of RX and TX ring to the chip */
    outl(virt_to_le32desc(&rx_ring), prcdar);
    outl(virt_to_le32desc(&tx_ring), ptcdar);

    /* Start the chip's Rx process: receive unicast and broadcast */
    set_rx_mode();
    outl(CR_START_RX | CR_QUEUE_RX, command);

    putchar('\n');
}

/* Initialize the Rx and Tx rings. */
    static void
epic100_init_ring(void)
{
    int i;

    cur_rx = cur_tx = 0;

    for (i = 0; i < RX_RING_SIZE; i++) {
	rx_ring[i].status    = cpu_to_le32(RRING_OWN);	/* Owned by Epic chip */
	rx_ring[i].buflength = cpu_to_le32(PKT_BUF_SZ);
	rx_ring[i].bufaddr   = virt_to_bus(&rx_packet[i * PKT_BUF_SZ]);
	rx_ring[i].next      = virt_to_le32desc(&rx_ring[i + 1]) ;
    }
    /* Mark the last entry as wrapping the ring. */
    rx_ring[i-1].next = virt_to_le32desc(&rx_ring[0]);

    /*
     *The Tx buffer descriptor is filled in as needed,
     * but we do need to clear the ownership bit.
     */

    for (i = 0; i < TX_RING_SIZE; i++) {
	tx_ring[i].status  = 0x0000;			/* Owned by CPU */
    	tx_ring[i].buflength = 0x0000 | cpu_to_le32(TD_STDFLAGS << 16);
	tx_ring[i].bufaddr = virt_to_bus(&tx_packet[i * PKT_BUF_SZ]);
	tx_ring[i].next    = virt_to_le32desc(&tx_ring[i + 1]);
    }
	tx_ring[i-1].next    = virt_to_le32desc(&tx_ring[0]);
}

/* function: epic100_transmit
 * This transmits a packet.
 *
 * Arguments: char d[6]:          destination ethernet address.
 *            unsigned short t:   ethernet protocol type.
 *            unsigned short s:   size of the data-part of the packet.
 *            char *p:            the data for the packet.
 * returns:   void.
 */
    static void
epic100_transmit(struct nic *nic, const char *destaddr, unsigned int type,
		 unsigned int len, const char *data)
{
    unsigned short nstype;
    unsigned char *txp;
    int entry;
    unsigned long ct;

    /* Calculate the next Tx descriptor entry. */
    entry = cur_tx % TX_RING_SIZE;

    if ((tx_ring[entry].status & TRING_OWN) == TRING_OWN) {
	printf("eth_transmit: Unable to transmit. status=%4.4lx. Resetting...\n",
	       tx_ring[entry].status);

	epic100_open();
	return;
    }

    txp = tx_packet + (entry * PKT_BUF_SZ);

    memcpy(txp, destaddr, ETH_ALEN);
    memcpy(txp + ETH_ALEN, nic->node_addr, ETH_ALEN);
    nstype = htons(type);
    memcpy(txp + 12, (char*)&nstype, 2);
    memcpy(txp + ETH_HLEN, data, len);

    len += ETH_HLEN;
	len &= 0x0FFF;
	while(len < ETH_ZLEN)
		txp[len++] = '\0';
    /*
     * Caution: the write order is important here,
     * set the base address with the "ownership"
     * bits last.
     */
   
    tx_ring[entry].buflength |= cpu_to_le32(len);
    tx_ring[entry].status = cpu_to_le32(len << 16) |
	    cpu_to_le32(TRING_OWN);	/* Pass ownership to the chip. */

    cur_tx++;

    /* Trigger an immediate transmit demand. */
    outl(CR_QUEUE_TX, command);

    ct = currticks();
    /* timeout 10 ms for transmit */
    while ((le32_to_cpu(tx_ring[entry].status) & (TRING_OWN)) &&
		ct + 10*1000 < currticks())
	/* Wait */;

    if ((le32_to_cpu(tx_ring[entry].status) & TRING_OWN) != 0)
	printf("Oops, transmitter timeout, status=%4.4lX\n",
	    tx_ring[entry].status);
}

/* function: epic100_poll / eth_poll
 * This receives a packet from the network.
 *
 * Arguments: none
 *
 * returns:   1 if a packet was received.
 *            0 if no packet was received.
 * side effects:
 *            returns the packet in the array nic->packet.
 *            returns the length of the packet in nic->packetlen.
 */

    static int
epic100_poll(struct nic *nic, int retrieve)
{
    int entry;
    int retcode;
    unsigned long status;
    entry = cur_rx % RX_RING_SIZE;

    if ((rx_ring[entry].status & cpu_to_le32(RRING_OWN)) == RRING_OWN)
	return (0);

    if ( ! retrieve ) return 1;

    status = le32_to_cpu(rx_ring[entry].status);
    /* We own the next entry, it's a new packet. Send it up. */

#if	(EPIC_DEBUG > 4)
    printf("epic_poll: entry %d status %hX\n", entry, status);
#endif

    cur_rx++;
    if (status & 0x2000) {
	printf("epic_poll: Giant packet\n");
	retcode = 0;
    } else if (status & 0x0006) {
	/* Rx Frame errors are counted in hardware. */
	printf("epic_poll: Frame received with errors\n");
	retcode = 0;
    } else {
	/* Omit the four octet CRC from the length. */
	nic->packetlen = (status >> 16) - 4;
	memcpy(nic->packet, &rx_packet[entry * PKT_BUF_SZ], nic->packetlen);
	retcode = 1;
    }

    /* Clear all error sources. */
    outl(status & INTR_CLEARERRS, intstat);

    /* Give the descriptor back to the chip */
    rx_ring[entry].status = RRING_OWN;

    /* Restart Receiver */
    outl(CR_START_RX | CR_QUEUE_RX, command); 

    return retcode;
}


static void epic100_disable ( struct nic *nic __unused ) {
	/* Soft reset the chip. */
	outl(GC_SOFT_RESET, genctl);
}

static void epic100_irq(struct nic *nic __unused, irq_action_t action __unused)
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

#ifdef	DEBUG_EEPROM
/* Serial EEPROM section. */

/*  EEPROM_Ctrl bits. */
#define EE_SHIFT_CLK	0x04	/* EEPROM shift clock. */
#define EE_CS		0x02	/* EEPROM chip select. */
#define EE_DATA_WRITE	0x08	/* EEPROM chip data in. */
#define EE_WRITE_0	0x01
#define EE_WRITE_1	0x09
#define EE_DATA_READ	0x10	/* EEPROM chip data out. */
#define EE_ENB		(0x0001 | EE_CS)

/* The EEPROM commands include the alway-set leading bit. */
#define EE_WRITE_CMD	(5 << 6)
#define EE_READ_CMD	(6 << 6)
#define EE_ERASE_CMD	(7 << 6)

#define eeprom_delay(n)	delay(n)

    static int
read_eeprom(int location)
{
    int i;
    int retval = 0;
    int read_cmd = location | EE_READ_CMD;

    outl(EE_ENB & ~EE_CS, eectl);
    outl(EE_ENB, eectl);

    /* Shift the read command bits out. */
    for (i = 10; i >= 0; i--) {
	short dataval = (read_cmd & (1 << i)) ? EE_DATA_WRITE : 0;
	outl(EE_ENB | dataval, eectl);
	eeprom_delay(100);
	outl(EE_ENB | dataval | EE_SHIFT_CLK, eectl);
	eeprom_delay(150);
	outl(EE_ENB | dataval, eectl);	/* Finish EEPROM a clock tick. */
	eeprom_delay(250);
    }
    outl(EE_ENB, eectl);

    for (i = 16; i > 0; i--) {
	outl(EE_ENB | EE_SHIFT_CLK, eectl);
	eeprom_delay(100);
	retval = (retval << 1) | ((inl(eectl) & EE_DATA_READ) ? 1 : 0);
	outl(EE_ENB, eectl);
	eeprom_delay(100);
    }

    /* Terminate the EEPROM access. */
    outl(EE_ENB & ~EE_CS, eectl);
    return retval;
}
#endif


#define MII_READOP	1
#define MII_WRITEOP	2

    static int
mii_read(int phy_id, int location)
{
    int i;

    outl((phy_id << 9) | (location << 4) | MII_READOP, mmctl);
    /* Typical operation takes < 50 ticks. */

    for (i = 4000; i > 0; i--)
	if ((inl(mmctl) & MII_READOP) == 0)
	    break;
    return inw(mmdata);
}

static struct nic_operations epic100_operations = {
	.connect	= dummy_connect,
	.poll		= epic100_poll,
	.transmit	= epic100_transmit,
	.irq		= epic100_irq,

};

static struct pci_device_id epic100_nics[] = {
PCI_ROM(0x10b8, 0x0005, "epic100",    "SMC EtherPowerII", 0),		/* SMC 83c170 EPIC/100 */
PCI_ROM(0x10b8, 0x0006, "smc-83c175", "SMC EPIC/C 83c175", 0),
};

PCI_DRIVER ( epic100_driver, epic100_nics, PCI_NO_CLASS );

DRIVER ( "EPIC100", nic_driver, pci_driver, epic100_driver,
	 epic100_probe, epic100_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
