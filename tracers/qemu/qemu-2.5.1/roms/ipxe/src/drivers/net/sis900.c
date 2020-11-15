/* -*- Mode:C; c-basic-offset:4; -*- */

/* 
   sis900.c: An SiS 900/7016 PCI Fast Ethernet driver for Etherboot
   Copyright (C) 2001 Entity Cyber, Inc.

   Revision:	1.0	March 1, 2001
   
   Author: Marty Connor (mdc@etherboot.org)

   Adapted from a Linux driver which was written by Donald Becker
   and modified by Ollie Lho and Chin-Shan Li of SiS Corporation.
   Rewritten for Etherboot by Marty Connor.
   
   This software may be used and distributed according to the terms
   of the GNU Public License (GPL), incorporated herein by reference.
   
   References:
   SiS 7016 Fast Ethernet PCI Bus 10/100 Mbps LAN Controller with OnNow Support,
   preliminary Rev. 1.0 Jan. 14, 1998
   SiS 900 Fast Ethernet PCI Bus 10/100 Mbps LAN Single Chip with OnNow Support,
   preliminary Rev. 1.0 Nov. 10, 1998
   SiS 7014 Single Chip 100BASE-TX/10BASE-T Physical Layer Solution,
   preliminary Rev. 1.0 Jan. 18, 1998
   http://www.sis.com.tw/support/databook.htm */

FILE_LICENCE ( GPL_ANY );

/* Revision History */

/*
  07 Dec 2003  timlegge - Enabled Multicast Support
  06 Dec 2003  timlegge - Fixed relocation issue in 5.2
  04 Jan 2002  Chien-Yu Chen, Doug Ambrisko, Marty Connor  Patch to Etherboot 5.0.5
     Added support for the SiS 630ET plus various bug fixes from linux kernel
     source 2.4.17.
  01 March 2001  mdc     1.0
     Initial Release.  Tested with PCI based sis900 card and ThinkNIC
     computer.
  20 March 2001 P.Koegel
     added support for sis630e and PHY ICS1893 and RTL8201
     Testet with SIS730S chipset + ICS1893
*/


/* Includes */

#include "etherboot.h"
#include <ipxe/pci.h>
#include "nic.h"

#include "sis900.h"

/* Globals */

static struct nic_operations sis900_operations;

static int sis900_debug = 0;

static unsigned short vendor, dev_id;
static unsigned long ioaddr;
static u8 pci_revision;

static unsigned int cur_phy;

static unsigned int cur_rx;

struct {
    BufferDesc txd;
    BufferDesc rxd[NUM_RX_DESC];
    unsigned char txb[TX_BUF_SIZE];
    unsigned char rxb[NUM_RX_DESC * RX_BUF_SIZE];
} sis900_bufs __shared;
#define txd sis900_bufs.txd
#define rxd sis900_bufs.rxd
#define txb sis900_bufs.txb
#define rxb sis900_bufs.rxb

#if 0
static struct mac_chip_info {
    const char *name;
    u16 vendor_id, device_id, flags;
    int io_size;
} mac_chip_table[] = {
    { "SiS 900 PCI Fast Ethernet", PCI_VENDOR_ID_SIS, PCI_DEVICE_ID_SIS900,
      PCI_COMMAND_IO|PCI_COMMAND_MASTER, SIS900_TOTAL_SIZE},
    { "SiS 7016 PCI Fast Ethernet",PCI_VENDOR_ID_SIS, PCI_DEVICE_ID_SIS7016,
      PCI_COMMAND_IO|PCI_COMMAND_MASTER, SIS900_TOTAL_SIZE},
    {0,0,0,0,0} /* 0 terminated list. */
};
#endif

static void sis900_read_mode(struct nic *nic, int phy_addr, int *speed, int *duplex);
static void amd79c901_read_mode(struct nic *nic, int phy_addr, int *speed, int *duplex);
static void ics1893_read_mode(struct nic *nic, int phy_addr, int *speed, int *duplex);
static void rtl8201_read_mode(struct nic *nic, int phy_addr, int *speed, int *duplex);
static void vt6103_read_mode(struct nic *nic, int phy_addr, int *speed, int *duplex);

static struct mii_chip_info {
    const char * name;
    u16 phy_id0;
    u16 phy_id1;
    void (*read_mode) (struct nic *nic, int phy_addr, int *speed, int *duplex);
} mii_chip_table[] = {
    {"SiS 900 Internal MII PHY", 0x001d, 0x8000, sis900_read_mode},
    {"SiS 7014 Physical Layer Solution", 0x0016, 0xf830,sis900_read_mode},
    {"SiS 900 on Foxconn 661 7MI", 0x0143, 0xBC70, sis900_read_mode},
    {"AMD 79C901 10BASE-T PHY",  0x0000, 0x6B70, amd79c901_read_mode},
    {"AMD 79C901 HomePNA PHY",   0x0000, 0x6B90, amd79c901_read_mode},
    {"ICS 1893 Integrated PHYceiver"   , 0x0015, 0xf440,ics1893_read_mode},
//  {"NS 83851 PHY",0x2000, 0x5C20, MIX },
    {"RTL 8201 10/100Mbps Phyceiver"   , 0x0000, 0x8200,rtl8201_read_mode},
    {"VIA 6103 10/100Mbps Phyceiver", 0x0101, 0x8f20,vt6103_read_mode},
    {NULL,0,0,NULL}
};

static struct mii_phy {
    struct mii_phy * next;
    struct mii_chip_info * chip_info;
    int phy_addr;
    u16 status;
} mii;



#if 0
// PCI to ISA bridge for SIS640E access
static struct pci_device_id pci_isa_bridge_list[] = {
	{ .vendor = 0x1039, .device = 0x0008,
		.name = "SIS 85C503/5513 PCI to ISA bridge"},
};

PCI_DRIVER( sis_bridge_pci_driver, pci_isa_bridge_list, PCI_NO_CLASS );

static struct device_driver sis_bridge_driver = {
    .name = "SIS ISA bridge",
    .bus_driver = &pci_driver,
    .bus_driver_info = ( struct bus_driver_info * ) &sis_bridge_pci_driver,
};
#endif

/* Function Prototypes */

static int sis900_probe(struct nic *nic,struct pci_device *pci);

static u16  sis900_read_eeprom(int location);
static void sis900_mdio_reset(long mdio_addr);
static void sis900_mdio_idle(long mdio_addr);
static u16  sis900_mdio_read(int phy_id, int location);
#if 0
static void sis900_mdio_write(int phy_id, int location, int val);
#endif
static void sis900_init(struct nic *nic);

static void sis900_reset(struct nic *nic);

static void sis900_init_rxfilter(struct nic *nic);
static void sis900_init_txd(struct nic *nic);
static void sis900_init_rxd(struct nic *nic);
static void sis900_set_rx_mode(struct nic *nic);
static void sis900_check_mode(struct nic *nic);

static void sis900_transmit(struct nic *nic, const char *d, 
                            unsigned int t, unsigned int s, const char *p);
static int  sis900_poll(struct nic *nic, int retrieve);

static void sis900_disable(struct nic *nic);

static void sis900_irq(struct nic *nic, irq_action_t action);

/**
 *	sis900_get_mac_addr: - Get MAC address for stand alone SiS900 model
 *	@pci_dev: the sis900 pci device
 *	@net_dev: the net device to get address for
 *
 *	Older SiS900 and friends, use EEPROM to store MAC address.
 *	MAC address is read from read_eeprom() into @net_dev->dev_addr.
 */

static int sis900_get_mac_addr(struct pci_device * pci_dev __unused, struct nic *nic)
{
	u16 signature;
	int i;

	/* check to see if we have sane EEPROM */
	signature = (u16) sis900_read_eeprom( EEPROMSignature);
	if (signature == 0xffff || signature == 0x0000) {
		printf ("sis900_probe: Error EERPOM read %hX\n", signature);
		return 0;
	}

	/* get MAC address from EEPROM */
	for (i = 0; i < 3; i++)
			((u16 *)(nic->node_addr))[i] = sis900_read_eeprom(i+EEPROMMACAddr);
	return 1;
}

/**
 *	sis96x_get_mac_addr: - Get MAC address for SiS962 or SiS963 model
 *	@pci_dev: the sis900 pci device
 *	@net_dev: the net device to get address for 
 *
 *	SiS962 or SiS963 model, use EEPROM to store MAC address. And EEPROM 
 *	is shared by
 *	LAN and 1394. When access EEPROM, send EEREQ signal to hardware first 
 *	and wait for EEGNT. If EEGNT is ON, EEPROM is permitted to be access 
 *	by LAN, otherwise is not. After MAC address is read from EEPROM, send
 *	EEDONE signal to refuse EEPROM access by LAN. 
 *	The EEPROM map of SiS962 or SiS963 is different to SiS900. 
 *	The signature field in SiS962 or SiS963 spec is meaningless. 
 *	MAC address is read into @net_dev->dev_addr.
 */

static int sis96x_get_mac_addr(struct pci_device * pci_dev __unused, struct nic *nic)
{
/* 	long ioaddr = net_dev->base_addr; */
	long ee_addr = ioaddr + mear;
	u32 waittime = 0;
	int i;
	
	printf("Alternate function\n");

	outl(EEREQ, ee_addr);
	while(waittime < 2000) {
		if(inl(ee_addr) & EEGNT) {

			/* get MAC address from EEPROM */
			for (i = 0; i < 3; i++)
			        ((u16 *)(nic->node_addr))[i] = sis900_read_eeprom(i+EEPROMMACAddr);

			outl(EEDONE, ee_addr);
			return 1;
		} else {
			udelay(1);	
			waittime ++;
		}
	}
	outl(EEDONE, ee_addr);
	return 0;
}

/**
 *	sis630e_get_mac_addr: - Get MAC address for SiS630E model
 *	@pci_dev: the sis900 pci device
 *	@net_dev: the net device to get address for
 *
 *	SiS630E model, use APC CMOS RAM to store MAC address.
 *	APC CMOS RAM is accessed through ISA bridge.
 *	MAC address is read into @net_dev->dev_addr.
 */

static int sis630e_get_mac_addr(struct pci_device * pci_dev __unused, struct nic *nic)
{
#if 0
	u8 reg;
	int i;
	struct bus_loc bus_loc;
	union {
	    struct bus_dev bus_dev;
	    struct pci_device isa_bridge;
	} u;

	/* find PCI to ISA bridge */
	memset(&bus_loc, 0, sizeof(bus_loc));
	if ( ! find_by_driver ( &bus_loc, &u.bus_dev, &sis_bridge_driver, 0 ) )
	    return 0;

	pci_read_config_byte(&u.isa_bridge, 0x48, &reg);
	pci_write_config_byte(&u.isa_bridge, 0x48, reg | 0x40);

	for (i = 0; i < ETH_ALEN; i++)
	{
		outb(0x09 + i, 0x70);
		((u8 *)(nic->node_addr))[i] = inb(0x71);
	}
	pci_write_config_byte(&u.isa_bridge, 0x48, reg & ~0x40);

	return 1;
#endif

	/* Does not work with current bus/device model */
	memset ( nic->node_addr, 0, sizeof ( nic->node_addr ) );
	return 0;
}

/**
 *      sis630e_get_mac_addr: - Get MAC address for SiS630E model
 *      @pci_dev: the sis900 pci device
 *      @net_dev: the net device to get address for
 *
 *      SiS630E model, use APC CMOS RAM to store MAC address.
 *      APC CMOS RAM is accessed through ISA bridge.
 *      MAC address is read into @net_dev->dev_addr.
 */

static int sis635_get_mac_addr(struct pci_device * pci_dev __unused, struct nic *nic)
{
        u32 rfcrSave;
        u32 i;
	
	
        rfcrSave = inl(rfcr + ioaddr);

        outl(rfcrSave | RELOAD, ioaddr + cr);
        outl(0, ioaddr + cr);

        /* disable packet filtering before setting filter */
        outl(rfcrSave & ~RFEN, rfcr + ioaddr);

        /* load MAC addr to filter data register */
        for (i = 0 ; i < 3 ; i++) {
                outl((i << RFADDR_shift), ioaddr + rfcr);
                *( ((u16 *)nic->node_addr) + i) = inw(ioaddr + rfdr);
        }

        /* enable packet filitering */
        outl(rfcrSave | RFEN, rfcr + ioaddr);

        return 1;
}

/* 
 * Function: sis900_probe
 *
 * Description: initializes initializes the NIC, retrieves the
 *    MAC address of the card, and sets up some globals required by 
 *    other routines.
 *
 * Side effects:
 *            leaves the ioaddress of the sis900 chip in the variable ioaddr.
 *            leaves the sis900 initialized, and ready to receive packets.
 *
 * Returns:   struct nic *:          pointer to NIC data structure
 */

static int sis900_probe ( struct nic *nic, struct pci_device *pci ) {

    int i;
    int found=0;
    int phy_addr;
    u8 revision;
    int ret;

    if (pci->ioaddr == 0)
        return 0;

    nic->irqno  = 0;
    nic->ioaddr = pci->ioaddr;

    ioaddr  = pci->ioaddr;
    vendor  = pci->vendor;
    dev_id  = pci->device;

    /* wakeup chip */
    pci_write_config_dword(pci, 0x40, 0x00000000);

    adjust_pci_device(pci);

    /* get MAC address */
    ret = 0;
    pci_read_config_byte(pci, PCI_REVISION, &revision);
    
    /* save for use later in sis900_reset() */
    pci_revision = revision; 

    if (revision == SIS630E_900_REV)
        ret = sis630e_get_mac_addr(pci, nic);
    else if ((revision > 0x81) && (revision <= 0x90))
        ret = sis635_get_mac_addr(pci, nic);
    else if (revision == SIS96x_900_REV)
	ret = sis96x_get_mac_addr(pci, nic);
    else
        ret = sis900_get_mac_addr(pci, nic);

    if (ret == 0)
    {
        printf ("sis900_probe: Error MAC address not found\n");
        return 0;
    }

    /* 630ET : set the mii access mode as software-mode */
    if (revision == SIS630ET_900_REV)
	outl(ACCESSMODE | inl(ioaddr + cr), ioaddr + cr);

    DBG( "sis900_probe: Vendor:%#hX Device:%#hX\n", vendor, dev_id );

    /* probe for mii transceiver */
    /* search for total of 32 possible mii phy addresses */

    found = 0;
    for (phy_addr = 0; phy_addr < 32; phy_addr++) {
        u16 mii_status;
        u16 phy_id0, phy_id1;

        mii_status = sis900_mdio_read(phy_addr, MII_STATUS);
        if (mii_status == 0xffff || mii_status == 0x0000)
            /* the mii is not accessible, try next one */
            continue;
                
        phy_id0 = sis900_mdio_read(phy_addr, MII_PHY_ID0);
        phy_id1 = sis900_mdio_read(phy_addr, MII_PHY_ID1);

        /* search our mii table for the current mii */ 
        for (i = 0; mii_chip_table[i].phy_id1; i++) {

            if ((phy_id0 == mii_chip_table[i].phy_id0) &&
                ((phy_id1 & 0xFFF0) == mii_chip_table[i].phy_id1)){

                printf("sis900_probe: %s transceiver found at address %d.\n",
                       mii_chip_table[i].name, phy_addr);

                mii.chip_info = &mii_chip_table[i];
                mii.phy_addr  = phy_addr;
                mii.status    = sis900_mdio_read(phy_addr, MII_STATUS);
                mii.next      = NULL;

                found=1;
                break;
            }
        }
    }
        
    if (found == 0) {
        printf("sis900_probe: No MII transceivers found!\n");
        return 0;
    }

    /* Arbitrarily select the last PHY found as current PHY */
    cur_phy = mii.phy_addr;
    printf("sis900_probe: Using %s as default\n",  mii.chip_info->name);

    /* initialize device */
    sis900_init(nic);
    nic->nic_op	= &sis900_operations;

    return 1;
}




/* 
 * EEPROM Routines:  These functions read and write to EEPROM for 
 *    retrieving the MAC address and other configuration information about 
 *    the card.
 */

/* Delay between EEPROM clock transitions. */
#define eeprom_delay()  inl(ee_addr)


/* Function: sis900_read_eeprom
 *
 * Description: reads and returns a given location from EEPROM
 *
 * Arguments: int location:       requested EEPROM location
 *
 * Returns:   u16:                contents of requested EEPROM location
 *
 */

/* Read Serial EEPROM through EEPROM Access Register, Note that location is 
   in word (16 bits) unit */
static u16 sis900_read_eeprom(int location)
{
    int i;
    u16 retval = 0;
    long ee_addr = ioaddr + mear;
    u32 read_cmd = location | EEread;

    outl(0, ee_addr);
    eeprom_delay();
    outl(EECS, ee_addr);
    eeprom_delay();

    /* Shift the read command (9) bits out. */
    for (i = 8; i >= 0; i--) {
        u32 dataval = (read_cmd & (1 << i)) ? EEDI | EECS : EECS;
        outl(dataval, ee_addr);
        eeprom_delay();
        outl(dataval | EECLK, ee_addr);
        eeprom_delay();
    }
    outl(EECS, ee_addr);
    eeprom_delay();

    /* read the 16-bits data in */
    for (i = 16; i > 0; i--) {
        outl(EECS, ee_addr);
        eeprom_delay();
        outl(EECS | EECLK, ee_addr);
        eeprom_delay();
        retval = (retval << 1) | ((inl(ee_addr) & EEDO) ? 1 : 0);
        eeprom_delay();
    }
                
    /* Terminate the EEPROM access. */
    outl(0, ee_addr);
    eeprom_delay();
//  outl(EECLK, ee_addr);

    return (retval);
}

#define sis900_mdio_delay()    inl(mdio_addr)


/* 
   Read and write the MII management registers using software-generated
   serial MDIO protocol. Note that the command bits and data bits are
   sent out separately
*/

static void sis900_mdio_idle(long mdio_addr)
{
    outl(MDIO | MDDIR, mdio_addr);
    sis900_mdio_delay();
    outl(MDIO | MDDIR | MDC, mdio_addr);
}

/* Syncronize the MII management interface by shifting 32 one bits out. */
static void sis900_mdio_reset(long mdio_addr)
{
    int i;

    for (i = 31; i >= 0; i--) {
        outl(MDDIR | MDIO, mdio_addr);
        sis900_mdio_delay();
        outl(MDDIR | MDIO | MDC, mdio_addr);
        sis900_mdio_delay();
    }
    return;
}

static u16 sis900_mdio_read(int phy_id, int location)
{
    long mdio_addr = ioaddr + mear;
    int mii_cmd = MIIread|(phy_id<<MIIpmdShift)|(location<<MIIregShift);
    u16 retval = 0;
    int i;

    sis900_mdio_reset(mdio_addr);
    sis900_mdio_idle(mdio_addr);

    for (i = 15; i >= 0; i--) {
        int dataval = (mii_cmd & (1 << i)) ? MDDIR | MDIO : MDDIR;
        outl(dataval, mdio_addr);
        sis900_mdio_delay();
        outl(dataval | MDC, mdio_addr);
        sis900_mdio_delay();
    }

    /* Read the 16 data bits. */
    for (i = 16; i > 0; i--) {
        outl(0, mdio_addr);
        sis900_mdio_delay();
        retval = (retval << 1) | ((inl(mdio_addr) & MDIO) ? 1 : 0);
        outl(MDC, mdio_addr);
        sis900_mdio_delay();
    }
    outl(0x00, mdio_addr);
    return retval;
}

#if 0
static void sis900_mdio_write(int phy_id, int location, int value)
{
    long mdio_addr = ioaddr + mear;
    int mii_cmd = MIIwrite|(phy_id<<MIIpmdShift)|(location<<MIIregShift);
    int i;

    sis900_mdio_reset(mdio_addr);
    sis900_mdio_idle(mdio_addr);

    /* Shift the command bits out. */
    for (i = 15; i >= 0; i--) {
        int dataval = (mii_cmd & (1 << i)) ? MDDIR | MDIO : MDDIR;
        outb(dataval, mdio_addr);
        sis900_mdio_delay();
        outb(dataval | MDC, mdio_addr);
        sis900_mdio_delay();
    }
    sis900_mdio_delay();

    /* Shift the value bits out. */
    for (i = 15; i >= 0; i--) {
        int dataval = (value & (1 << i)) ? MDDIR | MDIO : MDDIR;
        outl(dataval, mdio_addr);
        sis900_mdio_delay();
        outl(dataval | MDC, mdio_addr);
        sis900_mdio_delay();
    }
    sis900_mdio_delay();
        
    /* Clear out extra bits. */
    for (i = 2; i > 0; i--) {
        outb(0, mdio_addr);
        sis900_mdio_delay();
        outb(MDC, mdio_addr);
        sis900_mdio_delay();
    }
    outl(0x00, mdio_addr);
    return;
}
#endif


/* Function: sis900_init
 *
 * Description: resets the ethernet controller chip and various
 *    data structures required for sending and receiving packets.
 *    
 * Arguments: struct nic *nic:          NIC data structure
 *
 * returns:   void.
 */

static void
sis900_init(struct nic *nic)
{
    /* Soft reset the chip. */
    sis900_reset(nic);

    sis900_init_rxfilter(nic);

    sis900_init_txd(nic);
    sis900_init_rxd(nic);

    sis900_set_rx_mode(nic);

    sis900_check_mode(nic);

    outl(RxENA| inl(ioaddr + cr), ioaddr + cr);
}


/* 
 * Function: sis900_reset
 *
 * Description: disables interrupts and soft resets the controller chip
 *
 * Arguments: struct nic *nic:          NIC data structure
 *
 * Returns:   void.
 */

static void 
sis900_reset(struct nic *nic __unused)
{
    int i = 0;
    u32 status = TxRCMP | RxRCMP;

    outl(0, ioaddr + ier);
    outl(0, ioaddr + imr);
    outl(0, ioaddr + rfcr);

    outl(RxRESET | TxRESET | RESET | inl(ioaddr + cr), ioaddr + cr);

    /* Check that the chip has finished the reset. */
    while (status && (i++ < 1000)) {
        status ^= (inl(isr + ioaddr) & status);
    }

    if( (pci_revision >= SIS635A_900_REV) || (pci_revision == SIS900B_900_REV) )
            outl(PESEL | RND_CNT, ioaddr + cfg);
    else
            outl(PESEL, ioaddr + cfg);
}


/* Function: sis_init_rxfilter
 *
 * Description: sets receive filter address to our MAC address
 *
 * Arguments: struct nic *nic:          NIC data structure
 *
 * returns:   void.
 */

static void
sis900_init_rxfilter(struct nic *nic)
{
    u32 rfcrSave;
    int i;
        
    rfcrSave = inl(rfcr + ioaddr);

    /* disable packet filtering before setting filter */
    outl(rfcrSave & ~RFEN, rfcr + ioaddr);

    /* load MAC addr to filter data register */
    for (i = 0 ; i < 3 ; i++) {
        u32 w;

        w = (u32) *((u16 *)(nic->node_addr)+i);
        outl((i << RFADDR_shift), ioaddr + rfcr);
        outl(w, ioaddr + rfdr);

        if (sis900_debug > 0)
            printf("sis900_init_rxfilter: Receive Filter Addrss[%d]=%X\n",
                   i, inl(ioaddr + rfdr));
    }

    /* enable packet filitering */
    outl(rfcrSave | RFEN, rfcr + ioaddr);
}


/* 
 * Function: sis_init_txd
 *
 * Description: initializes the Tx descriptor
 *
 * Arguments: struct nic *nic:          NIC data structure
 *
 * returns:   void.
 */

static void
sis900_init_txd(struct nic *nic __unused)
{
    txd.link   = (u32) 0;
    txd.cmdsts = (u32) 0;
    txd.bufptr = virt_to_bus(&txb[0]);

    /* load Transmit Descriptor Register */
    outl(virt_to_bus(&txd), ioaddr + txdp); 
    if (sis900_debug > 0)
        printf("sis900_init_txd: TX descriptor register loaded with: %X\n", 
               inl(ioaddr + txdp));
}


/* Function: sis_init_rxd
 *
 * Description: initializes the Rx descriptor ring
 *    
 * Arguments: struct nic *nic:          NIC data structure
 *
 * Returns:   void.
 */

static void 
sis900_init_rxd(struct nic *nic __unused) 
{ 
    int i;

    cur_rx = 0; 

    /* init RX descriptor */
    for (i = 0; i < NUM_RX_DESC; i++) {
        rxd[i].link   = virt_to_bus((i+1 < NUM_RX_DESC) ? &rxd[i+1] : &rxd[0]);
        rxd[i].cmdsts = (u32) RX_BUF_SIZE;
        rxd[i].bufptr = virt_to_bus(&rxb[i*RX_BUF_SIZE]);
        if (sis900_debug > 0)
            printf("sis900_init_rxd: rxd[%d]=%p link=%X cmdsts=%X bufptr=%X\n", 
                   i, &rxd[i], (unsigned int) rxd[i].link, (unsigned int) rxd[i].cmdsts,
		   (unsigned int) rxd[i].bufptr);
    }

    /* load Receive Descriptor Register */
    outl(virt_to_bus(&rxd[0]), ioaddr + rxdp);

    if (sis900_debug > 0)
        printf("sis900_init_rxd: RX descriptor register loaded with: %X\n", 
               inl(ioaddr + rxdp));

}


/* Function: sis_init_rxd
 *
 * Description: 
 *    sets the receive mode to accept all broadcast packets and packets
 *    with our MAC address, and reject all multicast packets.      
 *    
 * Arguments: struct nic *nic:          NIC data structure
 *
 * Returns:   void.
 */

static void sis900_set_rx_mode(struct nic *nic __unused)
{
    int i, table_entries;
    u32 rx_mode; 
    u16 mc_filter[16] = {0};	/* 256/128 bits multicast hash table */
    	
    if((pci_revision == SIS635A_900_REV) || (pci_revision == SIS900B_900_REV))
	table_entries = 16;
    else
	table_entries = 8;

    /* accept all multicast packet */
    rx_mode = RFAAB | RFAAM;
    for (i = 0; i < table_entries; i++)
		mc_filter[i] = 0xffff;
					
    /* update Multicast Hash Table in Receive Filter */
    for (i = 0; i < table_entries; i++) {
        /* why plus 0x04? That makes the correct value for hash table. */
        outl((u32)(0x00000004+i) << RFADDR_shift, ioaddr + rfcr);
        outl(mc_filter[i], ioaddr + rfdr);
    }

    /* Accept Broadcast and multicast packets, destination addresses that match 
       our MAC address */
    outl(RFEN | rx_mode, ioaddr + rfcr);

    return;
}


/* Function: sis900_check_mode
 *
 * Description: checks the state of transmit and receive
 *    parameters on the NIC, and updates NIC registers to match
 *    
 * Arguments: struct nic *nic:          NIC data structure
 *
 * Returns:   void.
 */

static void
sis900_check_mode(struct nic *nic)
{
    int speed, duplex;
    u32 tx_flags = 0, rx_flags = 0;

    mii.chip_info->read_mode(nic, cur_phy, &speed, &duplex);

    if( inl(ioaddr + cfg) & EDB_MASTER_EN ) {
        tx_flags = TxATP | (DMA_BURST_64 << TxMXDMA_shift) | (TX_FILL_THRESH << TxFILLT_shift);
	rx_flags = DMA_BURST_64 << RxMXDMA_shift;
    }
    else {
            tx_flags = TxATP | (DMA_BURST_512 << TxMXDMA_shift) | (TX_FILL_THRESH << TxFILLT_shift);
            rx_flags = DMA_BURST_512 << RxMXDMA_shift;
    }

    if (speed == HW_SPEED_HOME || speed == HW_SPEED_10_MBPS) {
        rx_flags |= (RxDRNT_10 << RxDRNT_shift);
        tx_flags |= (TxDRNT_10 << TxDRNT_shift);
    }
    else {
        rx_flags |= (RxDRNT_100 << RxDRNT_shift);
        tx_flags |= (TxDRNT_100 << TxDRNT_shift);
    }

    if (duplex == FDX_CAPABLE_FULL_SELECTED) {
        tx_flags |= (TxCSI | TxHBI);
        rx_flags |= RxATX;
    }

    outl (tx_flags, ioaddr + txcfg);
    outl (rx_flags, ioaddr + rxcfg);
}


/* Function: sis900_read_mode
 *
 * Description: retrieves and displays speed and duplex
 *    parameters from the NIC
 *    
 * Arguments: struct nic *nic:          NIC data structure
 *
 * Returns:   void.
 */

static void
sis900_read_mode(struct nic *nic __unused, int phy_addr, int *speed, int *duplex)
{
    int i = 0;
    u32 status;
    u16 phy_id0, phy_id1;
        
    /* STSOUT register is Latched on Transition, read operation updates it */
    do {
        status = sis900_mdio_read(phy_addr, MII_STSOUT);
    } while (i++ < 2);

    *speed = HW_SPEED_10_MBPS;
    *duplex = FDX_CAPABLE_HALF_SELECTED;
    
    if (status & (MII_NWAY_TX | MII_NWAY_TX_FDX))
	*speed = HW_SPEED_100_MBPS;
    if (status & ( MII_NWAY_TX_FDX | MII_NWAY_T_FDX))
	*duplex = FDX_CAPABLE_FULL_SELECTED;
	
    /* Workaround for Realtek RTL8201 PHY issue */
    phy_id0 = sis900_mdio_read(phy_addr, MII_PHY_ID0);
    phy_id1 = sis900_mdio_read(phy_addr, MII_PHY_ID1);
    if((phy_id0 == 0x0000) && ((phy_id1 & 0xFFF0) == 0x8200)){
	if(sis900_mdio_read(phy_addr, MII_CONTROL) & MII_CNTL_FDX)
	    *duplex = FDX_CAPABLE_FULL_SELECTED;
	if(sis900_mdio_read(phy_addr, 0x0019) & 0x01)
	    *speed = HW_SPEED_100_MBPS;
    }

    if (status & MII_STSOUT_LINK_FAIL)
        printf("sis900_read_mode: Media Link Off\n");
    else
        printf("sis900_read_mode: Media Link On %s %s-duplex \n", 
               *speed == HW_SPEED_100_MBPS ? 
               "100mbps" : "10mbps",
               *duplex == FDX_CAPABLE_FULL_SELECTED ?
               "full" : "half");
}


/* Function: amd79c901_read_mode
 *
 * Description: retrieves and displays speed and duplex
 *    parameters from the NIC
 *    
 * Arguments: struct nic *nic:          NIC data structure
 *
 * Returns:   void.
 */

static void
amd79c901_read_mode(struct nic *nic __unused, int phy_addr, int *speed, int *duplex)
{
    int i;
    u16 status;
        
    for (i = 0; i < 2; i++)
        status = sis900_mdio_read(phy_addr, MII_STATUS);

    if (status & MII_STAT_CAN_AUTO) {
        /* 10BASE-T PHY */
        for (i = 0; i < 2; i++)
            status = sis900_mdio_read(phy_addr, MII_STATUS_SUMMARY);
        if (status & MII_STSSUM_SPD)
            *speed = HW_SPEED_100_MBPS;
        else
            *speed = HW_SPEED_10_MBPS;
        if (status & MII_STSSUM_DPLX)
            *duplex = FDX_CAPABLE_FULL_SELECTED;
        else
            *duplex = FDX_CAPABLE_HALF_SELECTED;

        if (status & MII_STSSUM_LINK)
            printf("amd79c901_read_mode: Media Link On %s %s-duplex \n", 
                   *speed == HW_SPEED_100_MBPS ? 
                   "100mbps" : "10mbps",
                   *duplex == FDX_CAPABLE_FULL_SELECTED ?
                   "full" : "half");
        else
            printf("amd79c901_read_mode: Media Link Off\n");
    }
    else {
        /* HomePNA */
        *speed = HW_SPEED_HOME;
        *duplex = FDX_CAPABLE_HALF_SELECTED;
        if (status & MII_STAT_LINK)
            printf("amd79c901_read_mode:Media Link On 1mbps half-duplex \n");
        else
            printf("amd79c901_read_mode: Media Link Off\n");
    }
}


/**
 *	ics1893_read_mode: - read media mode for ICS1893 PHY
 *	@net_dev: the net device to read mode for
 *	@phy_addr: mii phy address
 *	@speed: the transmit speed to be determined
 *	@duplex: the duplex mode to be determined
 *
 *	ICS1893 PHY use Quick Poll Detailed Status register
 *	to determine the speed and duplex mode for sis900
 */

static void ics1893_read_mode(struct nic *nic __unused, int phy_addr, int *speed, int *duplex)
{
	int i = 0;
	u32 status;

	/* MII_QPDSTS is Latched, read twice in succession will reflect the current state */
	for (i = 0; i < 2; i++)
		status = sis900_mdio_read(phy_addr, MII_QPDSTS);

	if (status & MII_STSICS_SPD)
		*speed = HW_SPEED_100_MBPS;
	else
		*speed = HW_SPEED_10_MBPS;

	if (status & MII_STSICS_DPLX)
		*duplex = FDX_CAPABLE_FULL_SELECTED;
	else
		*duplex = FDX_CAPABLE_HALF_SELECTED;

	if (status & MII_STSICS_LINKSTS)
		printf("ics1893_read_mode: Media Link On %s %s-duplex \n",
		       *speed == HW_SPEED_100_MBPS ?
		       "100mbps" : "10mbps",
		       *duplex == FDX_CAPABLE_FULL_SELECTED ?
		       "full" : "half");
	else
		printf("ics1893_read_mode: Media Link Off\n");
}

/**
 *	rtl8201_read_mode: - read media mode for rtl8201 phy
 *	@nic: the net device to read mode for
 *	@phy_addr: mii phy address
 *	@speed: the transmit speed to be determined
 *	@duplex: the duplex mode to be determined
 *
 *	read MII_STATUS register from rtl8201 phy
 *	to determine the speed and duplex mode for sis900
 */

static void rtl8201_read_mode(struct nic *nic __unused, int phy_addr, int *speed, int *duplex)
{
	u32 status;

	status = sis900_mdio_read(phy_addr, MII_STATUS);

	if (status & MII_STAT_CAN_TX_FDX) {
		*speed = HW_SPEED_100_MBPS;
		*duplex = FDX_CAPABLE_FULL_SELECTED;
	}
	else if (status & MII_STAT_CAN_TX) {
		*speed = HW_SPEED_100_MBPS;
		*duplex = FDX_CAPABLE_HALF_SELECTED;
	}
	else if (status & MII_STAT_CAN_T_FDX) {
		*speed = HW_SPEED_10_MBPS;
		*duplex = FDX_CAPABLE_FULL_SELECTED;
	}
	else if (status & MII_STAT_CAN_T) {
		*speed = HW_SPEED_10_MBPS;
		*duplex = FDX_CAPABLE_HALF_SELECTED;
	}

	if (status & MII_STAT_LINK)
		printf("rtl8201_read_mode: Media Link On %s %s-duplex \n",
		       *speed == HW_SPEED_100_MBPS ?
		       "100mbps" : "10mbps",
		       *duplex == FDX_CAPABLE_FULL_SELECTED ?
		       "full" : "half");
	else
		printf("rtl8201_read_config_mode: Media Link Off\n");
}

/**
 *	vt6103_read_mode: - read media mode for vt6103 phy
 *	@nic: the net device to read mode for
 *	@phy_addr: mii phy address
 *	@speed: the transmit speed to be determined
 *	@duplex: the duplex mode to be determined
 *
 *	read MII_STATUS register from rtl8201 phy
 *	to determine the speed and duplex mode for sis900
 */

static void vt6103_read_mode(struct nic *nic __unused, int phy_addr, int *speed, int *duplex)
{
	u32 status;

	status = sis900_mdio_read(phy_addr, MII_STATUS);

	if (status & MII_STAT_CAN_TX_FDX) {
		*speed = HW_SPEED_100_MBPS;
		*duplex = FDX_CAPABLE_FULL_SELECTED;
	}
	else if (status & MII_STAT_CAN_TX) {
		*speed = HW_SPEED_100_MBPS;
		*duplex = FDX_CAPABLE_HALF_SELECTED;
	}
	else if (status & MII_STAT_CAN_T_FDX) {
		*speed = HW_SPEED_10_MBPS;
		*duplex = FDX_CAPABLE_FULL_SELECTED;
	}
	else if (status & MII_STAT_CAN_T) {
		*speed = HW_SPEED_10_MBPS;
		*duplex = FDX_CAPABLE_HALF_SELECTED;
	}

	if (status & MII_STAT_LINK)
		printf("vt6103_read_mode: Media Link On %s %s-duplex \n",
		       *speed == HW_SPEED_100_MBPS ?
		       "100mbps" : "10mbps",
		       *duplex == FDX_CAPABLE_FULL_SELECTED ?
		       "full" : "half");
	else
		printf("vt6103_read_config_mode: Media Link Off\n");
}

/* Function: sis900_transmit
 *
 * Description: transmits a packet and waits for completion or timeout.
 *
 * Arguments: char d[6]:          destination ethernet address.
 *            unsigned short t:   ethernet protocol type.
 *            unsigned short s:   size of the data-part of the packet.
 *            char *p:            the data for the packet.
 *    
 * Returns:   void.
 */

static void
sis900_transmit(struct nic  *nic,
                const char  *d,     /* Destination */
                unsigned int t,     /* Type */
                unsigned int s,     /* size */
                const char  *p)     /* Packet */
{
    u32 to, nstype;
    volatile u32 tx_status;
    
    /* Stop the transmitter */
    outl(TxDIS | inl(ioaddr + cr), ioaddr + cr);

    /* load Transmit Descriptor Register */
    outl(virt_to_bus(&txd), ioaddr + txdp); 
    if (sis900_debug > 1)
        printf("sis900_transmit: TX descriptor register loaded with: %X\n", 
               inl(ioaddr + txdp));

    memcpy(txb, d, ETH_ALEN);
    memcpy(txb + ETH_ALEN, nic->node_addr, ETH_ALEN);
    nstype = htons(t);
    memcpy(txb + 2 * ETH_ALEN, (char*)&nstype, 2);
    memcpy(txb + ETH_HLEN, p, s);

    s += ETH_HLEN;
    s &= DSIZE;

    if (sis900_debug > 1)
        printf("sis900_transmit: sending %d bytes ethtype %hX\n", (int) s, t);

    /* pad to minimum packet size */
    while (s < ETH_ZLEN)  
        txb[s++] = '\0';

    /* set the transmit buffer descriptor and enable Transmit State Machine */
    txd.bufptr = virt_to_bus(&txb[0]);
    txd.cmdsts = (u32) OWN | s;

    /* restart the transmitter */
    outl(TxENA | inl(ioaddr + cr), ioaddr + cr);

    if (sis900_debug > 1)
        printf("sis900_transmit: Queued Tx packet size %d.\n", (int) s);

    to = currticks() + TX_TIMEOUT;

    while (((tx_status=txd.cmdsts) & OWN) && (currticks() < to))
        /* wait */ ;

    if (currticks() >= to) {
        printf("sis900_transmit: TX Timeout! Tx status %X.\n", 
	       (unsigned int) tx_status);
    }
    
    if (tx_status & (ABORT | UNDERRUN | OWCOLL)) {
        /* packet unsuccessfully transmited */
        printf("sis900_transmit: Transmit error, Tx status %X.\n", 
	       (unsigned int) tx_status);
    }
    /* Disable interrupts by clearing the interrupt mask. */
    outl(0, ioaddr + imr);
}


/* Function: sis900_poll
 *
 * Description: checks for a received packet and returns it if found.
 *
 * Arguments: struct nic *nic:          NIC data structure
 *
 * Returns:   1 if a packet was received.
 *            0 if no packet was received.
 *
 * Side effects:
 *            Returns (copies) the packet to the array nic->packet.
 *            Returns the length of the packet in nic->packetlen.
 */

static int
sis900_poll(struct nic *nic, int retrieve)
{
    u32 rx_status = rxd[cur_rx].cmdsts;
    int retstat = 0;

     /* acknowledge interrupts by reading interrupt status register */
    inl(ioaddr + isr);

    if (sis900_debug > 2)
        printf("sis900_poll: cur_rx:%d, status:%X\n", cur_rx, 
	       (unsigned int) rx_status);

    if (!(rx_status & OWN))
        return retstat;

    if (sis900_debug > 1)
        printf("sis900_poll: got a packet: cur_rx:%d, status:%X\n",
               cur_rx, (unsigned int) rx_status);

    if ( ! retrieve ) return 1;
    
    nic->packetlen = (rx_status & DSIZE) - CRC_SIZE;

    if (rx_status & (ABORT|OVERRUN|TOOLONG|RUNT|RXISERR|CRCERR|FAERR)) {
        /* corrupted packet received */
        printf("sis900_poll: Corrupted packet received, buffer status = %X\n",
               (unsigned int) rx_status);
        retstat = 0;
    } else {
        /* give packet to higher level routine */
        memcpy(nic->packet, (rxb + cur_rx*RX_BUF_SIZE), nic->packetlen);
        retstat = 1;
    }

    /* return the descriptor and buffer to receive ring */
    rxd[cur_rx].cmdsts = RX_BUF_SIZE;
    rxd[cur_rx].bufptr = virt_to_bus(&rxb[cur_rx*RX_BUF_SIZE]);
        
    if (++cur_rx == NUM_RX_DESC)
        cur_rx = 0;

    /* re-enable the potentially idle receive state machine */
    outl(RxENA | inl(ioaddr + cr), ioaddr + cr);

    return retstat;

}


/* Function: sis900_disable
 *
 * Description: Turns off interrupts and stops Tx and Rx engines
 *    
 * Arguments: struct nic *nic:          NIC data structure
 *
 * Returns:   void.
 */

static void
sis900_disable ( struct nic *nic ) {

    sis900_init(nic);

    /* Disable interrupts by clearing the interrupt mask. */
    outl(0, ioaddr + imr);
    outl(0, ioaddr + ier);
    
    /* Stop the chip's Tx and Rx Status Machine */
    outl(RxDIS | TxDIS | inl(ioaddr + cr), ioaddr + cr);
}


/* Function: sis900_irq
 *
 * Description: Enable, Disable, or Force, interrupts
 *    
 * Arguments: struct nic *nic:          NIC data structure
 *            irq_action_t action:      Requested action       
 *
 * Returns:   void.
 */

static void
sis900_irq(struct nic *nic __unused, irq_action_t action __unused)
{
  switch ( action ) {
  case DISABLE :
    outl(0, ioaddr + imr);
    break;
  case ENABLE :
    outl((RxSOVR|RxORN|RxERR|RxOK|TxURN|TxERR|TxIDLE), ioaddr + imr);
    break;
  case FORCE :
    break;
  }
}

static struct nic_operations sis900_operations = {
	.connect	= dummy_connect,
	.poll		= sis900_poll,
	.transmit	= sis900_transmit,
	.irq		= sis900_irq,
};

static struct pci_device_id sis900_nics[] = {
PCI_ROM(0x1039, 0x0900, "sis900",  "SIS900", 0),
PCI_ROM(0x1039, 0x7016, "sis7016", "SIS7016", 0),
};

PCI_DRIVER ( sis900_driver, sis900_nics, PCI_NO_CLASS );

DRIVER ( "SIS900", nic_driver, pci_driver, sis900_driver,
	 sis900_probe, sis900_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
