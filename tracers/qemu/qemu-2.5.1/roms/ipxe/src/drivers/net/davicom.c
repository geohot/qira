#ifdef ALLMULTI
#error multicast support is not yet implemented
#endif
/*  
    DAVICOM DM9009/DM9102/DM9102A Etherboot Driver	V1.00

    This driver was ported from Marty Connor's Tulip Etherboot driver. 
    Thanks Marty Connor (mdc@etherboot.org) 

    This davicom etherboot driver supports DM9009/DM9102/DM9102A/
    DM9102A+DM9801/DM9102A+DM9802 NICs.

    This software may be used and distributed according to the terms
    of the GNU Public License, incorporated herein by reference.

*/

FILE_LICENCE ( GPL_ANY );

/*********************************************************************/
/* Revision History                                                  */
/*********************************************************************/

/*
  19 OCT 2000  Sten     1.00
			Different half and full duplex mode
			Do the different programming for DM9801/DM9802

  12 OCT 2000  Sten     0.90
			This driver was ported from tulip driver and it 
			has the following difference.
			Changed symbol tulip/TULIP to davicom/DAVICOM
			Deleted some code that did not use in this driver.
			Used chain-strcture to replace ring structure
			for both TX/RX descriptor.
			Allocated two tx descriptor.
			According current media mode to set operating 
			register(CR6)
*/


/*********************************************************************/
/* Declarations                                                      */
/*********************************************************************/

#include "etherboot.h"
#include "nic.h"
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>

#define TX_TIME_OUT       2*TICKS_PER_SEC

/* Register offsets for davicom device */
enum davicom_offsets {
   CSR0=0,     CSR1=0x08,  CSR2=0x10,  CSR3=0x18,  CSR4=0x20,  CSR5=0x28,
   CSR6=0x30,  CSR7=0x38,  CSR8=0x40,  CSR9=0x48, CSR10=0x50, CSR11=0x58,
  CSR12=0x60, CSR13=0x68, CSR14=0x70, CSR15=0x78, CSR16=0x80, CSR20=0xA0
};

/* EEPROM Address width definitions */
#define EEPROM_ADDRLEN 6
#define EEPROM_SIZE    32              /* 1 << EEPROM_ADDRLEN */
/* Used to be 128, but we only need to read enough to get the MAC
   address at bytes 20..25 */

/* Data Read from the EEPROM */
static unsigned char ee_data[EEPROM_SIZE];

/* The EEPROM commands include the alway-set leading bit. */
#define EE_WRITE_CMD    (5 << addr_len)
#define EE_READ_CMD     (6 << addr_len)
#define EE_ERASE_CMD    (7 << addr_len)

/* EEPROM_Ctrl bits. */
#define EE_SHIFT_CLK    0x02    /* EEPROM shift clock. */
#define EE_CS           0x01    /* EEPROM chip select. */
#define EE_DATA_WRITE   0x04    /* EEPROM chip data in. */
#define EE_WRITE_0      0x01
#define EE_WRITE_1      0x05
#define EE_DATA_READ    0x08    /* EEPROM chip data out. */
#define EE_ENB          (0x4800 | EE_CS)

/* Sten 10/11 for phyxcer */
#define PHY_DATA_0	0x0
#define PHY_DATA_1	0x20000
#define MDCLKH		0x10000

/* Delay between EEPROM clock transitions.  Even at 33Mhz current PCI
   implementations don't overrun the EEPROM clock.  We add a bus
   turn-around to insure that this remains true.  */
#define eeprom_delay()  inl(ee_addr)

/* helpful macro if on a big_endian machine for changing byte order.
   not strictly needed on Intel
   Already defined in Etherboot includes
#define le16_to_cpu(val) (val)
*/

/* transmit and receive descriptor format */
struct txdesc {
  volatile unsigned long   status;         /* owner, status */
  unsigned long   buf1sz:11,      /* size of buffer 1 */
    buf2sz:11,                    /* size of buffer 2 */
    control:10;                   /* control bits */
  const unsigned char *buf1addr;  /* buffer 1 address */
  const unsigned char *buf2addr;  /* buffer 2 address */
};

struct rxdesc {
  volatile unsigned long   status;         /* owner, status */
  unsigned long   buf1sz:11,      /* size of buffer 1 */
    buf2sz:11,                    /* size of buffer 2 */
    control:10;                   /* control bits */
  unsigned char   *buf1addr;      /* buffer 1 address */
  unsigned char   *buf2addr;      /* buffer 2 address */
};

/* Size of transmit and receive buffers */
#define BUFLEN 1536

/*********************************************************************/
/* Global Storage                                                    */
/*********************************************************************/

static struct nic_operations davicom_operations;

/* PCI Bus parameters */
static unsigned short vendor, dev_id;
static unsigned long ioaddr;

/* Note: transmit and receive buffers must be longword aligned and
   longword divisable */

/* transmit descriptor and buffer */
#define NTXD 2
#define NRXD 4
struct {
	struct txdesc txd[NTXD] __attribute__ ((aligned(4)));
	unsigned char txb[BUFLEN] __attribute__ ((aligned(4)));
	struct rxdesc rxd[NRXD] __attribute__ ((aligned(4)));
	unsigned char rxb[NRXD * BUFLEN] __attribute__ ((aligned(4)));
} davicom_bufs __shared;
#define txd davicom_bufs.txd
#define txb davicom_bufs.txb
#define rxd davicom_bufs.rxd
#define rxb davicom_bufs.rxb
static int rxd_tail;
static int TxPtr;


/*********************************************************************/
/* Function Prototypes                                               */
/*********************************************************************/
static void whereami(const char *str);
static int read_eeprom(unsigned long ioaddr, int location, int addr_len);
static int davicom_probe(struct nic *nic,struct pci_device *pci);
static void davicom_init_chain(struct nic *nic);	/* Sten 10/9 */
static void davicom_reset(struct nic *nic);
static void davicom_transmit(struct nic *nic, const char *d, unsigned int t,
			   unsigned int s, const char *p);
static int davicom_poll(struct nic *nic, int retrieve);
static void davicom_disable(struct nic *nic);
static void davicom_wait(unsigned int nticks);
static int phy_read(int);
static void phy_write(int, u16);
static void phy_write_1bit(u32, u32);
static int phy_read_1bit(u32);
static void davicom_media_chk(struct nic *);


/*********************************************************************/
/* Utility Routines                                                  */
/*********************************************************************/
static inline void whereami(const char *str)
{
  DBGP("%s\n", str);
  /* sleep(2); */
}

static void davicom_wait(unsigned int nticks)
{
  unsigned int to = currticks() + nticks;
  while (currticks() < to)
    /* wait */ ;
}


/*********************************************************************/
/* For DAVICOM phyxcer register by MII interface		     */
/*********************************************************************/
/*
  Read a word data from phy register
*/
static int phy_read(int location)
{
 int i, phy_addr=1;
 u16 phy_data;
 u32 io_dcr9;

 whereami("phy_read\n");

 io_dcr9 = ioaddr + CSR9;

 /* Send 33 synchronization clock to Phy controller */
 for (i=0; i<34; i++)
     phy_write_1bit(io_dcr9, PHY_DATA_1);

 /* Send start command(01) to Phy */
 phy_write_1bit(io_dcr9, PHY_DATA_0);
 phy_write_1bit(io_dcr9, PHY_DATA_1);

 /* Send read command(10) to Phy */
 phy_write_1bit(io_dcr9, PHY_DATA_1);
 phy_write_1bit(io_dcr9, PHY_DATA_0);

 /* Send Phy address */
 for (i=0x10; i>0; i=i>>1)
     phy_write_1bit(io_dcr9, phy_addr&i ? PHY_DATA_1: PHY_DATA_0);
   
 /* Send register address */
 for (i=0x10; i>0; i=i>>1)
     phy_write_1bit(io_dcr9, location&i ? PHY_DATA_1: PHY_DATA_0);

 /* Skip transition state */
 phy_read_1bit(io_dcr9);

 /* read 16bit data */
 for (phy_data=0, i=0; i<16; i++) {
   phy_data<<=1;
   phy_data|=phy_read_1bit(io_dcr9);
 }

 return phy_data;
}

/*
  Write a word to Phy register
*/
static void phy_write(int location, u16 phy_data)
{
 u16 i, phy_addr=1;
 u32 io_dcr9; 

 whereami("phy_write\n");

 io_dcr9 = ioaddr + CSR9;

 /* Send 33 synchronization clock to Phy controller */
 for (i=0; i<34; i++)
   phy_write_1bit(io_dcr9, PHY_DATA_1);

 /* Send start command(01) to Phy */
 phy_write_1bit(io_dcr9, PHY_DATA_0);
 phy_write_1bit(io_dcr9, PHY_DATA_1);

 /* Send write command(01) to Phy */
 phy_write_1bit(io_dcr9, PHY_DATA_0);
 phy_write_1bit(io_dcr9, PHY_DATA_1);

 /* Send Phy address */
 for (i=0x10; i>0; i=i>>1)
   phy_write_1bit(io_dcr9, phy_addr&i ? PHY_DATA_1: PHY_DATA_0);

 /* Send register address */
 for (i=0x10; i>0; i=i>>1)
   phy_write_1bit(io_dcr9, location&i ? PHY_DATA_1: PHY_DATA_0);

 /* written trasnition */
 phy_write_1bit(io_dcr9, PHY_DATA_1);
 phy_write_1bit(io_dcr9, PHY_DATA_0);

 /* Write a word data to PHY controller */
 for (i=0x8000; i>0; i>>=1)
   phy_write_1bit(io_dcr9, phy_data&i ? PHY_DATA_1: PHY_DATA_0);
}

/*
  Write one bit data to Phy Controller
*/
static void phy_write_1bit(u32 ee_addr, u32 phy_data)
{
 whereami("phy_write_1bit\n");
 outl(phy_data, ee_addr);                        /* MII Clock Low */
 eeprom_delay();
 outl(phy_data|MDCLKH, ee_addr);                 /* MII Clock High */
 eeprom_delay();
 outl(phy_data, ee_addr);                        /* MII Clock Low */
 eeprom_delay();
}

/*
  Read one bit phy data from PHY controller
*/
static int phy_read_1bit(u32 ee_addr)
{
 int phy_data;

 whereami("phy_read_1bit\n");

 outl(0x50000, ee_addr);
 eeprom_delay();

 phy_data=(inl(ee_addr)>>19) & 0x1;

 outl(0x40000, ee_addr);
 eeprom_delay();

 return phy_data;
}

/*
  DM9801/DM9802 present check and program 
*/
static void HPNA_process(void)
{

 if ( (phy_read(3) & 0xfff0) == 0xb900 ) {
   if ( phy_read(31) == 0x4404 ) {
     /* DM9801 present */
     if (phy_read(3) == 0xb901)
       phy_write(16, 0x5);	/* DM9801 E4 */
     else
       phy_write(16, 0x1005); /* DM9801 E3 and others */
     phy_write(25, ((phy_read(24) + 3) & 0xff) | 0xf000);
   } else {
     /* DM9802 present */
     phy_write(16, 0x5);
     phy_write(25, (phy_read(25) & 0xff00) + 2);
   }
 }
}

/*
  Sense media mode and set CR6
*/
static void davicom_media_chk(struct nic * nic __unused)
{
  unsigned long to, csr6;

  csr6 = 0x00200000;	/* SF */
  outl(csr6, ioaddr + CSR6);

#define PCI_VENDOR_ID_DAVICOM		0x1282
#define	PCI_DEVICE_ID_DM9009		0x9009
  if (vendor == PCI_VENDOR_ID_DAVICOM && dev_id == PCI_DEVICE_ID_DM9009) {
    /* Set to 10BaseT mode for DM9009 */
    phy_write(0, 0);
  } else {
    /* For DM9102/DM9102A */
    to = currticks() + 2 * TICKS_PER_SEC;
    while ( ((phy_read(1) & 0x24)!=0x24) && (currticks() < to))
      /* wait */ ;

    if ( (phy_read(1) & 0x24) == 0x24 ) {
      if (phy_read(17) & 0xa000)  
        csr6 |= 0x00000200;	/* Full Duplex mode */
    } else
      csr6 |= 0x00040000; /* Select DM9801/DM9802 when Ethernet link failed */
  }

  /* set the chip's operating mode */
  outl(csr6, ioaddr + CSR6);

  /* DM9801/DM9802 present check & program */
  if (csr6 & 0x40000)
    HPNA_process();
}


/*********************************************************************/
/* EEPROM Reading Code                                               */
/*********************************************************************/
/* EEPROM routines adapted from the Linux Tulip Code */
/* Reading a serial EEPROM is a "bit" grungy, but we work our way
   through:->.
*/
static int read_eeprom(unsigned long ioaddr, int location, int addr_len)
{
  int i;
  unsigned short retval = 0;
  long ee_addr = ioaddr + CSR9;
  int read_cmd = location | EE_READ_CMD;

  whereami("read_eeprom\n");

  outl(EE_ENB & ~EE_CS, ee_addr);
  outl(EE_ENB, ee_addr);

  /* Shift the read command bits out. */
  for (i = 4 + addr_len; i >= 0; i--) {
    short dataval = (read_cmd & (1 << i)) ? EE_DATA_WRITE : 0;
    outl(EE_ENB | dataval, ee_addr);
    eeprom_delay();
    outl(EE_ENB | dataval | EE_SHIFT_CLK, ee_addr);
    eeprom_delay();
  }
  outl(EE_ENB, ee_addr);

  for (i = 16; i > 0; i--) {
    outl(EE_ENB | EE_SHIFT_CLK, ee_addr);
    eeprom_delay();
    retval = (retval << 1) | ((inl(ee_addr) & EE_DATA_READ) ? 1 : 0);
    outl(EE_ENB, ee_addr);
    eeprom_delay();
  }

  /* Terminate the EEPROM access. */
  outl(EE_ENB & ~EE_CS, ee_addr);
  return retval;
}

/*********************************************************************/
/* davicom_init_chain - setup the tx and rx descriptors                */
/* Sten 10/9							     */
/*********************************************************************/
static void davicom_init_chain(struct nic *nic)
{
  int i;

  /* setup the transmit descriptor */
  /* Sten: Set 2 TX descriptor but use one TX buffer because
	   it transmit a packet and wait complete every time. */
  for (i=0; i<NTXD; i++) {
    txd[i].buf1addr = (void *)virt_to_bus(&txb[0]);	/* Used same TX buffer */
    txd[i].buf2addr = (void *)virt_to_bus(&txd[i+1]);	/*  Point to Next TX desc */
    txd[i].buf1sz   = 0;
    txd[i].buf2sz   = 0;
    txd[i].control  = 0x184;           /* Begin/End/Chain */
    txd[i].status   = 0x00000000;      /* give ownership to Host */
  }

  /* construct perfect filter frame with mac address as first match
     and broadcast address for all others */
  for (i=0; i<192; i++) txb[i] = 0xFF;
  txb[0] = nic->node_addr[0];
  txb[1] = nic->node_addr[1];
  txb[4] = nic->node_addr[2];
  txb[5] = nic->node_addr[3];
  txb[8] = nic->node_addr[4];
  txb[9] = nic->node_addr[5];

  /* setup receive descriptor */
  for (i=0; i<NRXD; i++) {
    rxd[i].buf1addr = (void *)virt_to_bus(&rxb[i * BUFLEN]);
    rxd[i].buf2addr = (void *)virt_to_bus(&rxd[i+1]); /* Point to Next RX desc */
    rxd[i].buf1sz   = BUFLEN;
    rxd[i].buf2sz   = 0;        /* not used */
    rxd[i].control  = 0x4;		/* Chain Structure */
    rxd[i].status   = 0x80000000;   /* give ownership to device */
  }

  /* Chain the last descriptor to first */
  txd[NTXD - 1].buf2addr = (void *)virt_to_bus(&txd[0]);
  rxd[NRXD - 1].buf2addr = (void *)virt_to_bus(&rxd[0]);
  TxPtr = 0;
  rxd_tail = 0;
}


/*********************************************************************/
/* davicom_reset - Reset adapter                                         */
/*********************************************************************/
static void davicom_reset(struct nic *nic)
{
  unsigned long to;

  whereami("davicom_reset\n");

  /* Stop Tx and RX */
  outl(inl(ioaddr + CSR6) & ~0x00002002, ioaddr + CSR6);

  /* Reset the chip, holding bit 0 set at least 50 PCI cycles. */
  outl(0x00000001, ioaddr + CSR0);

  davicom_wait(TICKS_PER_SEC);

  /* TX/RX descriptor burst */
  outl(0x0C00000, ioaddr + CSR0);	/* Sten 10/9 */

  /* set up transmit and receive descriptors */
  davicom_init_chain(nic);	/* Sten 10/9 */

  /* Point to receive descriptor */
  outl(virt_to_bus(&rxd[0]), ioaddr + CSR3);
  outl(virt_to_bus(&txd[0]), ioaddr + CSR4);	/* Sten 10/9 */

  /* According phyxcer media mode to set CR6,
     DM9102/A phyxcer can auto-detect media mode */
  davicom_media_chk(nic);

  /* Prepare Setup Frame Sten 10/9 */
  txd[TxPtr].buf1sz = 192;
  txd[TxPtr].control = 0x024;		/* SF/CE */
  txd[TxPtr].status = 0x80000000;	/* Give ownership to device */

  /* Start Tx */
  outl(inl(ioaddr + CSR6) | 0x00002000, ioaddr + CSR6);
  /* immediate transmit demand */
  outl(0, ioaddr + CSR1);

  to = currticks() + TX_TIME_OUT;
  while ((txd[TxPtr].status & 0x80000000) && (currticks() < to)) /* Sten 10/9 */
    /* wait */ ;

  if (currticks() >= to) {
    DBG ("TX Setup Timeout!\n");
  }
  /* Point to next TX descriptor */
 TxPtr = (++TxPtr >= NTXD) ? 0:TxPtr;	/* Sten 10/9 */

  DBG("txd.status = %lX\n", txd[TxPtr].status);
  DBG("ticks = %ld\n", currticks() - (to - TX_TIME_OUT));
  DBG_MORE();

  /* enable RX */
  outl(inl(ioaddr + CSR6) | 0x00000002, ioaddr + CSR6);
  /* immediate poll demand */
  outl(0, ioaddr + CSR2);
}


/*********************************************************************/
/* eth_transmit - Transmit a frame                                   */
/*********************************************************************/
static void davicom_transmit(struct nic *nic, const char *d, unsigned int t,
                           unsigned int s, const char *p)
{
  unsigned long to;

  whereami("davicom_transmit\n");

  /* Stop Tx */
  /* outl(inl(ioaddr + CSR6) & ~0x00002000, ioaddr + CSR6); */

  /* setup ethernet header */
  memcpy(&txb[0], d, ETH_ALEN);	/* DA 6byte */
  memcpy(&txb[ETH_ALEN], nic->node_addr, ETH_ALEN); /* SA 6byte*/
  txb[ETH_ALEN*2] = (t >> 8) & 0xFF; /* Frame type: 2byte */
  txb[ETH_ALEN*2+1] = t & 0xFF;
  memcpy(&txb[ETH_HLEN], p, s); /* Frame data */

  /* setup the transmit descriptor */
  txd[TxPtr].buf1sz   = ETH_HLEN+s;
  txd[TxPtr].control  = 0x00000184;      /* LS+FS+CE */
  txd[TxPtr].status   = 0x80000000;      /* give ownership to device */

  /* immediate transmit demand */
  outl(0, ioaddr + CSR1);

  to = currticks() + TX_TIME_OUT;
  while ((txd[TxPtr].status & 0x80000000) && (currticks() < to))
    /* wait */ ;

  if (currticks() >= to) {
    DBG ("TX Timeout!\n");
  }
 
  /* Point to next TX descriptor */
  TxPtr = (++TxPtr >= NTXD) ? 0:TxPtr;	/* Sten 10/9 */

}

/*********************************************************************/
/* eth_poll - Wait for a frame                                       */
/*********************************************************************/
static int davicom_poll(struct nic *nic, int retrieve)
{
  whereami("davicom_poll\n");

  if (rxd[rxd_tail].status & 0x80000000)
    return 0;

  if ( ! retrieve ) return 1;

  whereami("davicom_poll got one\n");

  nic->packetlen = (rxd[rxd_tail].status & 0x3FFF0000) >> 16;

  if( rxd[rxd_tail].status & 0x00008000){
      rxd[rxd_tail].status = 0x80000000;
      rxd_tail++;
      if (rxd_tail == NRXD) rxd_tail = 0;
      return 0;
  }

  /* copy packet to working buffer */
  /* XXX - this copy could be avoided with a little more work
     but for now we are content with it because the optimised
     memcpy is quite fast */

  memcpy(nic->packet, rxb + rxd_tail * BUFLEN, nic->packetlen);

  /* return the descriptor and buffer to receive ring */
  rxd[rxd_tail].status = 0x80000000;
  rxd_tail++;
  if (rxd_tail == NRXD) rxd_tail = 0;

  return 1;
}

/*********************************************************************/
/* eth_disable - Disable the interface                               */
/*********************************************************************/
static void davicom_disable ( struct nic *nic ) {

  whereami("davicom_disable\n");

  davicom_reset(nic);

  /* disable interrupts */
  outl(0x00000000, ioaddr + CSR7);

  /* Stop the chip's Tx and Rx processes. */
  outl(inl(ioaddr + CSR6) & ~0x00002002, ioaddr + CSR6);

  /* Clear the missed-packet counter. */
  inl(ioaddr + CSR8);
}


/*********************************************************************/
/* eth_irq - enable, disable and force interrupts                    */
/*********************************************************************/
static void davicom_irq(struct nic *nic __unused, irq_action_t action __unused)
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


/*********************************************************************/
/* eth_probe - Look for an adapter                                   */
/*********************************************************************/
static int davicom_probe ( struct nic *nic, struct pci_device *pci ) {

  unsigned int i;

  whereami("davicom_probe\n");

  if (pci->ioaddr == 0)
    return 0;

  vendor  = pci->vendor;
  dev_id  = pci->device;
  ioaddr  = pci->ioaddr;

  nic->ioaddr = pci->ioaddr;
  nic->irqno = 0;

  /* wakeup chip */
  pci_write_config_dword(pci, 0x40, 0x00000000);

  /* Stop the chip's Tx and Rx processes. */
  outl(inl(ioaddr + CSR6) & ~0x00002002, ioaddr + CSR6);

  /* Clear the missed-packet counter. */
  inl(ioaddr + CSR8);

  /* Get MAC Address */
  /* read EEPROM data */
  for (i = 0; i < sizeof(ee_data)/2; i++)
    ((unsigned short *)ee_data)[i] =
        le16_to_cpu(read_eeprom(ioaddr, i, EEPROM_ADDRLEN));

  /* extract MAC address from EEPROM buffer */
  for (i=0; i<ETH_ALEN; i++)
    nic->node_addr[i] = ee_data[20+i];

  DBG ( "Davicom %s at IOADDR %4.4lx\n", eth_ntoa ( nic->node_addr ), ioaddr );

  /* initialize device */
  davicom_reset(nic);
  nic->nic_op	= &davicom_operations;
  return 1;
}

static struct nic_operations davicom_operations = {
	.connect	= dummy_connect,
	.poll		= davicom_poll,
	.transmit	= davicom_transmit,
	.irq		= davicom_irq,

};

static struct pci_device_id davicom_nics[] = {
PCI_ROM(0x1282, 0x9100, "davicom9100", "Davicom 9100", 0),
PCI_ROM(0x1282, 0x9102, "davicom9102", "Davicom 9102", 0),
PCI_ROM(0x1282, 0x9009, "davicom9009", "Davicom 9009", 0),
PCI_ROM(0x1282, 0x9132, "davicom9132", "Davicom 9132", 0),	/* Needs probably some fixing */
};

PCI_DRIVER ( davicom_driver, davicom_nics, PCI_NO_CLASS );

DRIVER ( "DAVICOM", nic_driver, pci_driver, davicom_driver,
	 davicom_probe, davicom_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
