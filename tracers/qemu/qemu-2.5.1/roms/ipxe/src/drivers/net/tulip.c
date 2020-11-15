/* -*- Mode:C; c-basic-offset:4; -*- */

/*
  Tulip and clone Etherboot Driver

  By Marty Connor (mdc@etherboot.org)
  Copyright (C) 2001 Entity Cyber, Inc.

  This software may be used and distributed according to the terms
  of the GNU Public License, incorporated herein by reference.

  As of April 2001 this driver should support most tulip cards that 
  the Linux tulip driver supports because Donald Becker's Linux media 
  detection code is now included.

  Based on Ken Yap's Tulip Etherboot Driver and Donald Becker's
  Linux Tulip Driver. Supports N-Way speed auto-configuration on
  MX98715, MX98715A and MX98725. Support inexpensive PCI 10/100 cards
  based on the Macronix MX987x5 chip, such as the SOHOware Fast
  model SFA110A, and the LinkSYS model LNE100TX. The NetGear
  model FA310X, based on the LC82C168 chip is supported.
  The TRENDnet TE100-PCIA NIC which uses a genuine Intel 21143-PD
  chipset is supported. Also, Davicom DM9102's.

  Documentation and source code used:
  Source for Etherboot driver at
  http://etherboot.sourceforge.net/
  MX98715A Data Sheet and MX98715A Application Note
  on http://www.macronix.com/  (PDF format files)
  Source for Linux tulip driver at
  http://cesdis.gsfc.nasa.gov/linux/drivers/tulip.html

  Adapted by Ken Yap from
  FreeBSD netboot DEC 21143 driver
  Author: David Sharp
  date: Nov/98

  Some code fragments were taken from verious places, Ken Yap's
  etherboot, FreeBSD's if_de.c, and various Linux related files.
  DEC's manuals for the 21143 and SROM format were very helpful.
  The Linux de driver development page has a number of links to
  useful related information.  Have a look at:
  ftp://cesdis.gsfc.nasa.gov/pub/linux/drivers/tulip-devel.html
*/

FILE_LICENCE ( GPL_ANY );

/*********************************************************************/
/* Revision History                                                  */
/*********************************************************************/

/*
  08 Feb 2005  Ramesh Chander chhabaramesh at yahoo.co.in added table entries
               for SGThomson STE10/100A
  07 Sep 2003  timlegge	Multicast Support Added
  11 Apr 2001  mdc     [patch to etherboot 4.7.24]
     Major rewrite to include Linux tulip driver media detection
     code.  This driver should support a lot more cards now.
  16 Jul 2000  mdc     0.75b11
     Added support for ADMtek 0985 Centaur-P, a "Comet" tulip clone
     which is used on the LinkSYS LNE100TX v4.x cards.  We already
     support LNE100TX v2.0 cards, which use a different controller.
  04 Jul 2000   jam     ?
     Added test of status after receiving a packet from the card.
     Also uncommented the tulip_disable routine.  Stray packets
     seemed to be causing problems.
  27 Apr 2000   njl     ?
  29 Feb 2000   mdc     0.75b7
     Increased reset delay to 3 seconds because Macronix cards seem to
     need more reset time before card comes back to a usable state.
  26 Feb 2000   mdc     0.75b6
     Added a 1 second delay after initializing the transmitter because
     some cards seem to need the time or they drop the first packet 
     transmitted.
  23 Feb 2000   mdc     0.75b5
     removed udelay code and used currticks() for more reliable delay
     code in reset pause and sanity timeouts.  Added function prototypes
     and TX debugging code.
  21 Feb 2000   mdc     patch to Etherboot 4.4.3
     Incorporated patches from Bob Edwards and Paul Mackerras of 
     Linuxcare's OZLabs to deal with inefficiencies in tulip_transmit
     and udelay.  We now wait for packet transmission to complete
     (or sanity timeout).
  04 Feb 2000   Robert.Edwards@anu.edu.au patch to Etherboot 4.4.2
     patch to tulip.c that implements the automatic selection of the MII
     interface on cards using the Intel/DEC 21143 reference design, in
     particular, the TRENDnet TE100-PCIA NIC which uses a genuine Intel
     21143-PD chipset.
  11 Jan 2000   mdc     0.75b4
     Added support for NetGear FA310TX card based on the LC82C168
     chip.  This should also support Lite-On LC82C168 boards.
     Added simple MII support. Re-arranged code to better modularize
     initializations.
  04 Dec 1999   mdc     0.75b3
     Added preliminary support for LNE100TX PCI cards.  Should work for
     PNIC2 cards. No MII support, but single interface (RJ45) tulip
     cards seem to not care.
  03 Dec 1999   mdc     0.75b2
     Renamed from mx987x5 to tulip, merged in original tulip init code
     from tulip.c to support other tulip compatible cards.
  02 Dec 1999   mdc     0.75b1
     Released Beta MX987x5 Driver for code review and testing to netboot
     and thinguin mailing lists.
*/


/*********************************************************************/
/* Declarations                                                      */
/*********************************************************************/

#include "etherboot.h"
#include "nic.h"

#include <ipxe/ethernet.h>
#include <ipxe/pci.h>

/* User settable parameters */

#define TX_TIME_OUT       2*TICKS_PER_SEC

/* helpful macros if on a big_endian machine for changing byte order.
   not strictly needed on Intel */
#define get_unaligned(ptr) (*(ptr))
#define put_unaligned(val, ptr) ((void)( *(ptr) = (val) ))
#define get_u16(ptr) (*(u16 *)(ptr))
#define virt_to_le32desc(addr)  virt_to_bus(addr)

#define TULIP_IOTYPE  PCI_USES_MASTER | PCI_USES_IO | PCI_ADDR0
#define TULIP_SIZE 0x80

/* This is a mysterious value that can be written to CSR11 in the 21040 (only)
   to support a pre-NWay full-duplex signaling mechanism using short frames.
   No one knows what it should be, but if left at its default value some
   10base2(!) packets trigger a full-duplex-request interrupt. */
#define FULL_DUPLEX_MAGIC       0x6969

static const int csr0 = 0x01A00000 | 0x8000;

/*  The possible media types that can be set in options[] are: */
#define MEDIA_MASK 31
static const char * const medianame[32] = {
    "10baseT", "10base2", "AUI", "100baseTx",
    "10baseT-FDX", "100baseTx-FDX", "100baseT4", "100baseFx",
    "100baseFx-FDX", "MII 10baseT", "MII 10baseT-FDX", "MII",
    "10baseT(forced)", "MII 100baseTx", "MII 100baseTx-FDX", "MII 100baseT4",
    "MII 100baseFx-HDX", "MII 100baseFx-FDX", "Home-PNA 1Mbps", "Invalid-19",
};

/* This much match tulip_tbl[]!  Note 21142 == 21143. */
enum tulip_chips {
    DC21040=0, DC21041=1, DC21140=2, DC21142=3, DC21143=3,
    LC82C168, MX98713, MX98715, MX98725, AX88141, AX88140, PNIC2, COMET,
    COMPEX9881, I21145, XIRCOM, SGThomson,	/*Ramesh Chander*/
};

enum pci_id_flags_bits {
    /* Set PCI command register bits before calling probe1(). */
    PCI_USES_IO=1, PCI_USES_MEM=2, PCI_USES_MASTER=4,
    /* Read and map the single following PCI BAR. */
    PCI_ADDR0=0<<4, PCI_ADDR1=1<<4, PCI_ADDR2=2<<4, PCI_ADDR3=3<<4,
    PCI_ADDR_64BITS=0x100, PCI_NO_ACPI_WAKE=0x200, PCI_NO_MIN_LATENCY=0x400,
    PCI_UNUSED_IRQ=0x800,
};

struct pci_id_info {
    char *name;
    struct match_info {
        u32 pci, pci_mask, subsystem, subsystem_mask;
        u32 revision, revision_mask;                            /* Only 8 bits. */
    } id;
    enum pci_id_flags_bits pci_flags;
    int io_size;                                /* Needed for I/O region check or ioremap(). */
    int drv_flags;                              /* Driver use, intended as capability flags. */
};

static const struct pci_id_info pci_id_tbl[] = {
    { "Digital DC21040 Tulip", { 0x00021011, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 0x80, DC21040 },
    { "Digital DC21041 Tulip", { 0x00141011, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 0x80, DC21041 },
    { "Digital DS21140A Tulip", { 0x00091011, 0xffffffff, 0,0, 0x20,0xf0 },
      TULIP_IOTYPE, 0x80, DC21140 },
    { "Digital DS21140 Tulip", { 0x00091011, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 0x80, DC21140 },
    { "Digital DS21143 Tulip", { 0x00191011, 0xffffffff, 0,0, 65,0xff },
      TULIP_IOTYPE, TULIP_SIZE, DC21142 },
    { "Digital DS21142 Tulip", { 0x00191011, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, TULIP_SIZE, DC21142 },
    { "Kingston KNE110tx (PNIC)", { 0x000211AD, 0xffffffff, 0xf0022646, 0xffffffff, 0, 0 },
      TULIP_IOTYPE, 256, LC82C168 },
    { "Lite-On 82c168 PNIC", { 0x000211AD, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, LC82C168 },
    { "Macronix 98713 PMAC", { 0x051210d9, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, MX98713 },
    { "Macronix 98715 PMAC", { 0x053110d9, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, MX98715 },
    { "Macronix 98725 PMAC", { 0x053110d9, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, MX98725 },
    { "ASIX AX88141", { 0x1400125B, 0xffffffff, 0,0, 0x10, 0xf0 },
      TULIP_IOTYPE, 128, AX88141 },
    { "ASIX AX88140", { 0x1400125B, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 128, AX88140 },
    { "Lite-On LC82C115 PNIC-II", { 0xc11511AD, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, PNIC2 },
    { "ADMtek AN981 Comet", { 0x09811317, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, COMET },
    { "ADMTek AN983 Comet", { 0x12161113, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, COMET },
    { "ADMTek Comet AN983b", { 0x95111317, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, COMET },
    { "ADMtek Centaur-P", { 0x09851317, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, COMET },
    { "ADMtek Centaur-C", { 0x19851317, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, COMET },
    { "Compex RL100-TX", { 0x988111F6, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 128, COMPEX9881 },
    { "Intel 21145 Tulip", { 0x00398086, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 128, I21145 },
    { "Xircom Tulip clone", { 0x0003115d, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 128, XIRCOM },
    { "Davicom DM9102", { 0x91021282, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 0x80, DC21140 },
    { "Davicom DM9100", { 0x91001282, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 0x80, DC21140 },
    { "Macronix mxic-98715 (EN1217)", { 0x12171113, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, MX98715 },
    { "3Com 3cSOHO100B-TX (ADMtek Centuar)", { 0x930010b7, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, TULIP_SIZE, COMET },
    { "SG Thomson STE10/100A", { 0x2774104a, 0xffffffff, 0, 0, 0, 0 },
      TULIP_IOTYPE, 256, COMET },	/*Ramesh Chander*/
    { NULL, { 0, 0, 0, 0, 0, 0 }, 0, 0, 0 },
};

enum tbl_flag {
    HAS_MII=1, HAS_MEDIA_TABLE=2, CSR12_IN_SROM=4, ALWAYS_CHECK_MII=8,
    HAS_PWRDWN=0x10, MC_HASH_ONLY=0x20, /* Hash-only multicast filter. */
    HAS_PNICNWAY=0x80, HAS_NWAY=0x40,   /* Uses internal NWay xcvr. */
    HAS_INTR_MITIGATION=0x100, IS_ASIX=0x200, HAS_8023X=0x400,
};

/* Note: this table must match  enum tulip_chips  above. */
static struct tulip_chip_table {
    char *chip_name;
    int flags;
} tulip_tbl[] = {
    { "Digital DC21040 Tulip", 0},
    { "Digital DC21041 Tulip", HAS_MEDIA_TABLE | HAS_NWAY },
    { "Digital DS21140 Tulip", HAS_MII | HAS_MEDIA_TABLE | CSR12_IN_SROM },
    { "Digital DS21143 Tulip", HAS_MII | HAS_MEDIA_TABLE | ALWAYS_CHECK_MII 
      | HAS_PWRDWN | HAS_NWAY   | HAS_INTR_MITIGATION },
    { "Lite-On 82c168 PNIC", HAS_MII | HAS_PNICNWAY },
    { "Macronix 98713 PMAC", HAS_MII | HAS_MEDIA_TABLE | CSR12_IN_SROM },
    { "Macronix 98715 PMAC", HAS_MEDIA_TABLE },
    { "Macronix 98725 PMAC", HAS_MEDIA_TABLE },
    { "ASIX AX88140", HAS_MII | HAS_MEDIA_TABLE | CSR12_IN_SROM 
      | MC_HASH_ONLY | IS_ASIX },
    { "ASIX AX88141", HAS_MII | HAS_MEDIA_TABLE | CSR12_IN_SROM | MC_HASH_ONLY 
      | IS_ASIX },
    { "Lite-On PNIC-II", HAS_MII | HAS_NWAY | HAS_8023X },
    { "ADMtek Comet", HAS_MII | MC_HASH_ONLY },
    { "Compex 9881 PMAC",       HAS_MII | HAS_MEDIA_TABLE | CSR12_IN_SROM },
    { "Intel DS21145 Tulip", HAS_MII | HAS_MEDIA_TABLE | ALWAYS_CHECK_MII 
      | HAS_PWRDWN | HAS_NWAY },
    { "Xircom tulip work-alike", HAS_MII | HAS_MEDIA_TABLE | ALWAYS_CHECK_MII 
      | HAS_PWRDWN | HAS_NWAY },
    { "SGThomson STE10/100A", HAS_MII | MC_HASH_ONLY },	/*Ramesh Chander*/   
    { NULL, 0 },
};

/* A full-duplex map for media types. */
enum MediaIs {
    MediaIsFD = 1, MediaAlwaysFD=2, MediaIsMII=4, MediaIsFx=8,
    MediaIs100=16};

static const char media_cap[32] =
{0,0,0,16,  3,19,16,24,  27,4,7,5, 0,20,23,20, 20,31,0,0, };
static u8 t21040_csr13[] = {2,0x0C,8,4,  4,0,0,0, 0,0,0,0, 4,0,0,0};

/* 21041 transceiver register settings: 10-T, 10-2, AUI, 10-T, 10T-FD */
static u16 t21041_csr13[] = { 0xEF01, 0xEF09, 0xEF09, 0xEF01, 0xEF09, };
static u16 t21041_csr14[] = { 0xFFFF, 0xF7FD, 0xF7FD, 0x7F3F, 0x7F3D, };
static u16 t21041_csr15[] = { 0x0008, 0x0006, 0x000E, 0x0008, 0x0008, };

/* not used
static u16 t21142_csr13[] = { 0x0001, 0x0009, 0x0009, 0x0000, 0x0001, };
*/
static u16 t21142_csr14[] = { 0xFFFF, 0x0705, 0x0705, 0x0000, 0x7F3D, };
/* not used
static u16 t21142_csr15[] = { 0x0008, 0x0006, 0x000E, 0x0008, 0x0008, };
*/

/* Offsets to the Command and Status Registers, "CSRs".  All accesses
   must be longword instructions and quadword aligned. */
enum tulip_offsets {
    CSR0=0,     CSR1=0x08,  CSR2=0x10,  CSR3=0x18,  CSR4=0x20,  CSR5=0x28,
    CSR6=0x30,  CSR7=0x38,  CSR8=0x40,  CSR9=0x48, CSR10=0x50, CSR11=0x58,
    CSR12=0x60, CSR13=0x68, CSR14=0x70, CSR15=0x78, CSR16=0x80, CSR20=0xA0
};

/* The bits in the CSR5 status registers, mostly interrupt sources. */
enum status_bits {
    TimerInt=0x800, TPLnkFail=0x1000, TPLnkPass=0x10,
    NormalIntr=0x10000, AbnormalIntr=0x8000,
    RxJabber=0x200, RxDied=0x100, RxNoBuf=0x80, RxIntr=0x40,
    TxFIFOUnderflow=0x20, TxJabber=0x08, TxNoBuf=0x04, TxDied=0x02, TxIntr=0x01,
};

/* The configuration bits in CSR6. */
enum csr6_mode_bits {
	TxOn=0x2000, RxOn=0x0002, FullDuplex=0x0200,
	AcceptBroadcast=0x0100, AcceptAllMulticast=0x0080,
	AcceptAllPhys=0x0040, AcceptRunt=0x0008,
};


enum desc_status_bits {
    DescOwnded=0x80000000, RxDescFatalErr=0x8000, RxWholePkt=0x0300,
};

struct medialeaf {
    u8 type;
    u8 media;
    unsigned char *leafdata;
};

struct mediatable {
    u16 defaultmedia;
    u8 leafcount, csr12dir;                             /* General purpose pin directions. */
    unsigned has_mii:1, has_nonmii:1, has_reset:6;
    u32 csr15dir, csr15val;                             /* 21143 NWay setting. */
    struct medialeaf mleaf[0];
};

struct mediainfo {
    struct mediainfo *next;
    int info_type;
    int index;
    unsigned char *info;
};

/* EEPROM Address width definitions */
#define EEPROM_ADDRLEN 6
#define EEPROM_SIZE    128              /* 2 << EEPROM_ADDRLEN */

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

/* Delay between EEPROM clock transitions.  Even at 33Mhz current PCI
   implementations don't overrun the EEPROM clock.  We add a bus
   turn-around to insure that this remains true.  */
#define eeprom_delay()  inl(ee_addr)

/* Size of transmit and receive buffers */
#define BUFLEN 1536

/* Ring-wrap flag in length field, use for last ring entry.
   0x01000000 means chain on buffer2 address,
   0x02000000 means use the ring start address in CSR2/3.
   Note: Some work-alike chips do not function correctly in chained mode.
   The ASIX chip works only in chained mode.
   Thus we indicate ring mode, but always write the 'next' field for
   chained mode as well. */
#define DESC_RING_WRAP 0x02000000

/* transmit and receive descriptor format */
struct tulip_rx_desc {
    volatile u32 status;
    u32 length;
    u32 buffer1, buffer2;
};

struct tulip_tx_desc {
    volatile u32 status;
    u32 length;
    u32 buffer1, buffer2;
};

/*********************************************************************/
/* Global Storage                                                    */
/*********************************************************************/

static u32 ioaddr;

struct tulip_private {
    int cur_rx;
    int chip_id;                        /* index into tulip_tbl[]  */
    int pci_id_idx;                     /* index into pci_id_tbl[] */
    int revision;
    int flags;
    unsigned short vendor_id;           /* PCI card vendor code */
    unsigned short dev_id;              /* PCI card device code */
    unsigned char ehdr[ETH_HLEN];       /* buffer for ethernet header */
    const char *nic_name;
    unsigned int csr0, csr6;            /* Current CSR0, CSR6 settings. */
    unsigned int if_port;
    unsigned int full_duplex;         /* Full-duplex operation requested. */
    unsigned int full_duplex_lock;
    unsigned int medialock;           /* Do not sense media type. */
    unsigned int mediasense;          /* Media sensing in progress. */
    unsigned int nway, nwayset;     /* 21143 internal NWay. */
    unsigned int default_port;
    unsigned char eeprom[EEPROM_SIZE];  /* Serial EEPROM contents. */
    u8 media_table_storage[(sizeof(struct mediatable) + 32*sizeof(struct medialeaf))];
    u16 sym_advertise, mii_advertise;   /* NWay to-advertise. */
    struct mediatable *mtable;
    u16 lpar;                           /* 21143 Link partner ability. */
    u16 advertising[4];                 /* MII advertise, from SROM table. */
    signed char phys[4], mii_cnt;       /* MII device addresses. */
    int cur_index;                      /* Current media index. */
    int saved_if_port;
};

/* Note: transmit and receive buffers must be longword aligned and
   longword divisable */

#define TX_RING_SIZE	2
#define RX_RING_SIZE	4
struct {
    struct tulip_tx_desc tx_ring[TX_RING_SIZE];
    unsigned char txb[BUFLEN];
    struct tulip_rx_desc rx_ring[RX_RING_SIZE];
    unsigned char rxb[RX_RING_SIZE * BUFLEN];
    struct tulip_private tpx;
} tulip_bss __shared __attribute__ ((aligned(4)));
#define tx_ring tulip_bss.tx_ring
#define txb tulip_bss.txb
#define rx_ring tulip_bss.rx_ring
#define rxb tulip_bss.rxb

static struct tulip_private *tp;

/* Known cards that have old-style EEPROMs.
   Writing this table is described at
   http://cesdis.gsfc.nasa.gov/linux/drivers/tulip-drivers/tulip-media.html */
static struct fixups {
    char *name;
    unsigned char addr0, addr1, addr2;
    u16 newtable[32];                           /* Max length below. */
} eeprom_fixups[] = {
    {"Asante", 0, 0, 0x94, {0x1e00, 0x0000, 0x0800, 0x0100, 0x018c,
                            0x0000, 0x0000, 0xe078, 0x0001, 0x0050, 0x0018 }},
    {"SMC9332DST", 0, 0, 0xC0, { 0x1e00, 0x0000, 0x0800, 0x041f,
                                 0x0000, 0x009E, /* 10baseT */
                                 0x0004, 0x009E, /* 10baseT-FD */
                                 0x0903, 0x006D, /* 100baseTx */
                                 0x0905, 0x006D, /* 100baseTx-FD */ }},
    {"Cogent EM100", 0, 0, 0x92, { 0x1e00, 0x0000, 0x0800, 0x063f,
                                   0x0107, 0x8021, /* 100baseFx */
                                   0x0108, 0x8021, /* 100baseFx-FD */
                                   0x0100, 0x009E, /* 10baseT */
                                   0x0104, 0x009E, /* 10baseT-FD */
                                   0x0103, 0x006D, /* 100baseTx */
                                   0x0105, 0x006D, /* 100baseTx-FD */ }},
    {"Maxtech NX-110", 0, 0, 0xE8, { 0x1e00, 0x0000, 0x0800, 0x0513,
                                     0x1001, 0x009E, /* 10base2, CSR12 0x10*/
                                     0x0000, 0x009E, /* 10baseT */
                                     0x0004, 0x009E, /* 10baseT-FD */
                                     0x0303, 0x006D, /* 100baseTx, CSR12 0x03 */
                                     0x0305, 0x006D, /* 100baseTx-FD CSR12 0x03 */}},
    {"Accton EN1207", 0, 0, 0xE8, { 0x1e00, 0x0000, 0x0800, 0x051F,
                                    0x1B01, 0x0000, /* 10base2,   CSR12 0x1B */
                                    0x0B00, 0x009E, /* 10baseT,   CSR12 0x0B */
                                    0x0B04, 0x009E, /* 10baseT-FD,CSR12 0x0B */
                                    0x1B03, 0x006D, /* 100baseTx, CSR12 0x1B */
                                    0x1B05, 0x006D, /* 100baseTx-FD CSR12 0x1B */
    }},
    {NULL, 0, 0, 0, {}}};

static const char * block_name[] = {"21140 non-MII", "21140 MII PHY",
                                    "21142 Serial PHY", "21142 MII PHY", "21143 SYM PHY", "21143 reset method"};


/*********************************************************************/
/* Function Prototypes                                               */
/*********************************************************************/
static int mdio_read(struct nic *nic, int phy_id, int location);
static void mdio_write(struct nic *nic, int phy_id, int location, int value);
static int read_eeprom(unsigned long ioaddr, int location, int addr_len);
static void parse_eeprom(struct nic *nic);
static int tulip_probe(struct nic *nic,struct pci_device *pci);
static void tulip_init_ring(struct nic *nic);
static void tulip_reset(struct nic *nic);
static void tulip_transmit(struct nic *nic, const char *d, unsigned int t,
                           unsigned int s, const char *p);
static int tulip_poll(struct nic *nic, int retrieve);
static void tulip_disable(struct nic *nic);
static void nway_start(struct nic *nic);
static void pnic_do_nway(struct nic *nic);
static void select_media(struct nic *nic, int startup);
static void init_media(struct nic *nic);
static void start_link(struct nic *nic);
static int tulip_check_duplex(struct nic *nic);

static void tulip_wait(unsigned int nticks);


/*********************************************************************/
/* Utility Routines                                                  */
/*********************************************************************/

static void whereami (const char *str)
{
    DBGP("%s\n", str);
    /* sleep(2); */
}

static void tulip_wait(unsigned int nticks)
{
    unsigned int to = currticks() + nticks;
    while (currticks() < to)
        /* wait */ ;
}


/*********************************************************************/
/* Media Descriptor Code                                             */
/*********************************************************************/

/* MII transceiver control section.
   Read and write the MII registers using software-generated serial
   MDIO protocol.  See the MII specifications or DP83840A data sheet
   for details. */

/* The maximum data clock rate is 2.5 Mhz.  The minimum timing is usually
   met by back-to-back PCI I/O cycles, but we insert a delay to avoid
   "overclocking" issues or future 66Mhz PCI. */
#define mdio_delay() inl(mdio_addr)

/* Read and write the MII registers using software-generated serial
   MDIO protocol.  It is just different enough from the EEPROM protocol
   to not share code.  The maxium data clock rate is 2.5 Mhz. */
#define MDIO_SHIFT_CLK  0x10000
#define MDIO_DATA_WRITE0 0x00000
#define MDIO_DATA_WRITE1 0x20000
#define MDIO_ENB                0x00000         /* Ignore the 0x02000 databook setting. */
#define MDIO_ENB_IN             0x40000
#define MDIO_DATA_READ  0x80000

/* MII transceiver control section.
   Read and write the MII registers using software-generated serial
   MDIO protocol.  See the MII specifications or DP83840A data sheet
   for details. */

int mdio_read(struct nic *nic __unused, int phy_id, int location)
{
    int i;
    int read_cmd = (0xf6 << 10) | (phy_id << 5) | location;
    int retval = 0;
    long mdio_addr = ioaddr + CSR9;

    whereami("mdio_read\n");

    if (tp->chip_id == LC82C168) {
	int i = 1000;
	outl(0x60020000 + (phy_id<<23) + (location<<18), ioaddr + 0xA0);
	inl(ioaddr + 0xA0);
	inl(ioaddr + 0xA0);
	while (--i > 0)
	    if ( ! ((retval = inl(ioaddr + 0xA0)) & 0x80000000))
		return retval & 0xffff;
	return 0xffff;
    }

    if (tp->chip_id == COMET) {
	if (phy_id == 1) {
	    if (location < 7)
		return inl(ioaddr + 0xB4 + (location<<2));
	    else if (location == 17)
		return inl(ioaddr + 0xD0);
	    else if (location >= 29 && location <= 31)
		return inl(ioaddr + 0xD4 + ((location-29)<<2));
	}
	return 0xffff;
    }

    /* Establish sync by sending at least 32 logic ones. */
    for (i = 32; i >= 0; i--) {
	outl(MDIO_ENB | MDIO_DATA_WRITE1, mdio_addr);
	mdio_delay();
	outl(MDIO_ENB | MDIO_DATA_WRITE1 | MDIO_SHIFT_CLK, mdio_addr);
	mdio_delay();
    }
    /* Shift the read command bits out. */
    for (i = 15; i >= 0; i--) {
	int dataval = (read_cmd & (1 << i)) ? MDIO_DATA_WRITE1 : 0;

	outl(MDIO_ENB | dataval, mdio_addr);
	mdio_delay();
	outl(MDIO_ENB | dataval | MDIO_SHIFT_CLK, mdio_addr);
	mdio_delay();
    }
    /* Read the two transition, 16 data, and wire-idle bits. */
    for (i = 19; i > 0; i--) {
	outl(MDIO_ENB_IN, mdio_addr);
	mdio_delay();
	retval = (retval << 1) | ((inl(mdio_addr) & MDIO_DATA_READ) ? 1 : 0);
	outl(MDIO_ENB_IN | MDIO_SHIFT_CLK, mdio_addr);
	mdio_delay();
    }
    return (retval>>1) & 0xffff;
}

void mdio_write(struct nic *nic __unused, int phy_id, int location, int value)
{
    int i;
    int cmd = (0x5002 << 16) | (phy_id << 23) | (location<<18) | value;
    long mdio_addr = ioaddr + CSR9;

    whereami("mdio_write\n");

    if (tp->chip_id == LC82C168) {
	int i = 1000;
	outl(cmd, ioaddr + 0xA0);
	do
	    if ( ! (inl(ioaddr + 0xA0) & 0x80000000))
		break;
	while (--i > 0);
	return;
    }

    if (tp->chip_id == COMET) {
	if (phy_id != 1)
	    return;
	if (location < 7)
	    outl(value, ioaddr + 0xB4 + (location<<2));
	else if (location == 17)
	    outl(value, ioaddr + 0xD0);
	else if (location >= 29 && location <= 31)
	    outl(value, ioaddr + 0xD4 + ((location-29)<<2));
	return;
    }

    /* Establish sync by sending 32 logic ones. */
    for (i = 32; i >= 0; i--) {
	outl(MDIO_ENB | MDIO_DATA_WRITE1, mdio_addr);
	mdio_delay();
	outl(MDIO_ENB | MDIO_DATA_WRITE1 | MDIO_SHIFT_CLK, mdio_addr);
	mdio_delay();
    }
    /* Shift the command bits out. */
    for (i = 31; i >= 0; i--) {
	int dataval = (cmd & (1 << i)) ? MDIO_DATA_WRITE1 : 0;
	outl(MDIO_ENB | dataval, mdio_addr);
	mdio_delay();
	outl(MDIO_ENB | dataval | MDIO_SHIFT_CLK, mdio_addr);
	mdio_delay();
    }
    /* Clear out extra bits. */
    for (i = 2; i > 0; i--) {
	outl(MDIO_ENB_IN, mdio_addr);
	mdio_delay();
	outl(MDIO_ENB_IN | MDIO_SHIFT_CLK, mdio_addr);
	mdio_delay();
    }
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
/* EEPROM Parsing Code                                               */
/*********************************************************************/
static void parse_eeprom(struct nic *nic)
{
    unsigned char *p, *ee_data = tp->eeprom;
    int new_advertise = 0;
    int i;

    whereami("parse_eeprom\n");

    tp->mtable = NULL;
    /* Detect an old-style (SA only) EEPROM layout:
       memcmp(ee_data, ee_data+16, 8). */
    for (i = 0; i < 8; i ++)
        if (ee_data[i] != ee_data[16+i])
            break;
    if (i >= 8) {
        /* Do a fix-up based on the vendor half of the station address. */
        for (i = 0; eeprom_fixups[i].name; i++) {
            if (nic->node_addr[0] == eeprom_fixups[i].addr0
                &&  nic->node_addr[1] == eeprom_fixups[i].addr1
                &&  nic->node_addr[2] == eeprom_fixups[i].addr2) {
                if (nic->node_addr[2] == 0xE8  &&  ee_data[0x1a] == 0x55)
                    i++;                /* An Accton EN1207, not an outlaw Maxtech. */
                memcpy(ee_data + 26, eeprom_fixups[i].newtable,
                       sizeof(eeprom_fixups[i].newtable));
                DBG("%s: Old format EEPROM on '%s' board.\n%s: Using substitute media control info.\n",
                       tp->nic_name, eeprom_fixups[i].name, tp->nic_name);
                break;
            }
        }
        if (eeprom_fixups[i].name == NULL) { /* No fixup found. */
            DBG("%s: Old style EEPROM with no media selection information.\n",
                   tp->nic_name);
            return;
        }
    }

    if (ee_data[19] > 1) {
        DBG("%s:  Multiport cards (%d ports) may not work correctly.\n",
               tp->nic_name, ee_data[19]);
    }

    p = (void *)ee_data + ee_data[27];

    if (ee_data[27] == 0) {             /* No valid media table. */
            DBG2("%s:  No Valid Media Table. ee_data[27] = %hhX\n",
		 tp->nic_name, ee_data[27]);
    } else if (tp->chip_id == DC21041) {
        int media = get_u16(p);
        int count = p[2];
        p += 3;

        DBG("%s: 21041 Media table, default media %hX (%s).\n",
               tp->nic_name, media,
               media & 0x0800 ? "Autosense" : medianame[media & 15]);
        for (i = 0; i < count; i++) {
            unsigned char media_block = *p++;
            int media_code = media_block & MEDIA_MASK;
            if (media_block & 0x40)
                p += 6;
            switch(media_code) {
            case 0: new_advertise |= 0x0020; break;
            case 4: new_advertise |= 0x0040; break;
            }
            DBG("%s:  21041 media #%d, %s.\n",
                   tp->nic_name, media_code, medianame[media_code]);
        }
    } else {
        unsigned char csr12dir = 0;
        int count;
        struct mediatable *mtable;
        u16 media = get_u16(p);

        p += 2;
        if (tp->flags & CSR12_IN_SROM)
            csr12dir = *p++;
        count = *p++;

        tp->mtable = mtable = (struct mediatable *)&tp->media_table_storage[0];

        mtable->defaultmedia = media;
        mtable->leafcount = count;
        mtable->csr12dir = csr12dir;
        mtable->has_nonmii = mtable->has_mii = mtable->has_reset = 0;
        mtable->csr15dir = mtable->csr15val = 0;

        DBG("%s:  EEPROM default media type %s.\n", tp->nic_name,
               media & 0x0800 ? "Autosense" : medianame[media & MEDIA_MASK]);

        for (i = 0; i < count; i++) {
            struct medialeaf *leaf = &mtable->mleaf[i];

            if ((p[0] & 0x80) == 0) { /* 21140 Compact block. */
                leaf->type = 0;
                leaf->media = p[0] & 0x3f;
                leaf->leafdata = p;
                if ((p[2] & 0x61) == 0x01)      /* Bogus, but Znyx boards do it. */
                    mtable->has_mii = 1;
                p += 4;
            } else {
                switch(leaf->type = p[1]) {
                case 5:
                    mtable->has_reset = i;
                    leaf->media = p[2] & 0x0f;
                    break;
                case 1: case 3:
                    mtable->has_mii = 1;
                    leaf->media = 11;
                    break;
                case 2:
                    if ((p[2] & 0x3f) == 0) {
                        u32 base15 = (p[2] & 0x40) ? get_u16(p + 7) : 0x0008;
                        u16 *p1 = (u16 *)(p + (p[2] & 0x40 ? 9 : 3));
                        mtable->csr15dir = (get_unaligned(p1 + 0)<<16) + base15;
                        mtable->csr15val = (get_unaligned(p1 + 1)<<16) + base15;
                    }
                    /* Fall through. */
                case 0: case 4:
                    mtable->has_nonmii = 1;
                    leaf->media = p[2] & MEDIA_MASK;
                    switch (leaf->media) {
                    case 0: new_advertise |= 0x0020; break;
                    case 4: new_advertise |= 0x0040; break;
                    case 3: new_advertise |= 0x0080; break;
                    case 5: new_advertise |= 0x0100; break;
                    case 6: new_advertise |= 0x0200; break;
                    }
                    break;
                default:
                    leaf->media = 19;
                }
                leaf->leafdata = p + 2;
                p += (p[0] & 0x3f) + 1;
            }
            if (leaf->media == 11) {
                unsigned char *bp = leaf->leafdata;
                DBG2("%s:  MII interface PHY %d, setup/reset sequences %d/%d long, capabilities %hhX %hhX.\n",
		     tp->nic_name, bp[0], bp[1], bp[2 + bp[1]*2],
		     bp[5 + bp[2 + bp[1]*2]*2], bp[4 + bp[2 + bp[1]*2]*2]);
            }
            DBG("%s:  Index #%d - Media %s (#%d) described "
                   "by a %s (%d) block.\n",
                   tp->nic_name, i, medianame[leaf->media], leaf->media,
                   leaf->type < 6 ? block_name[leaf->type] : "UNKNOWN",
                   leaf->type);
        }
        if (new_advertise)
            tp->sym_advertise = new_advertise;
    }
}


/*********************************************************************/
/* tulip_init_ring - setup the tx and rx descriptors                */
/*********************************************************************/
static void tulip_init_ring(struct nic *nic __unused)
{
    int i;

    whereami("tulip_init_ring\n");

    tp->cur_rx = 0;

    for (i = 0; i < RX_RING_SIZE; i++) {
	rx_ring[i].status  = cpu_to_le32(0x80000000);
	rx_ring[i].length  = cpu_to_le32(BUFLEN);
	rx_ring[i].buffer1 = virt_to_le32desc(&rxb[i * BUFLEN]);
	rx_ring[i].buffer2 = virt_to_le32desc(&rx_ring[i+1]);
    }
    /* Mark the last entry as wrapping the ring. */
    rx_ring[i-1].length    = cpu_to_le32(DESC_RING_WRAP | BUFLEN);
    rx_ring[i-1].buffer2   = virt_to_le32desc(&rx_ring[0]);

    /* We only use 1 transmit buffer, but we use 2 descriptors so
       transmit engines have somewhere to point to if they feel the need */

    tx_ring[0].status  = 0x00000000;
    tx_ring[0].buffer1 = virt_to_le32desc(&txb[0]);
    tx_ring[0].buffer2 = virt_to_le32desc(&tx_ring[1]);

    /* this descriptor should never get used, since it will never be owned
       by the machine (status will always == 0) */
    tx_ring[1].status  = 0x00000000;
    tx_ring[1].buffer1 = virt_to_le32desc(&txb[0]);
    tx_ring[1].buffer2 = virt_to_le32desc(&tx_ring[0]);

    /* Mark the last entry as wrapping the ring, though this should never happen */
    tx_ring[1].length  = cpu_to_le32(DESC_RING_WRAP | BUFLEN);
}


static void set_rx_mode(struct nic *nic __unused) {
	int csr6 = inl(ioaddr + CSR6) & ~0x00D5;

	tp->csr6 &= ~0x00D5;
 
	/* !IFF_PROMISC */
	tp->csr6 |= AcceptAllMulticast;
	csr6 |= AcceptAllMulticast;

	outl(csr6, ioaddr + CSR6);

	
	
}

/*********************************************************************/
/* eth_reset - Reset adapter                                         */
/*********************************************************************/
static void tulip_reset(struct nic *nic)
{
    int i;
    unsigned long to;

    whereami("tulip_reset\n");

    /* Stop Tx and RX */
    outl(inl(ioaddr + CSR6) & ~0x00002002, ioaddr + CSR6);

    /* On some chip revs we must set the MII/SYM port before the reset!? */
    if (tp->mii_cnt  ||  (tp->mtable  &&  tp->mtable->has_mii)) {
	outl(0x814C0000, ioaddr + CSR6);
    }
 
    /* Reset the chip, holding bit 0 set at least 50 PCI cycles. */
    outl(0x00000001, ioaddr + CSR0);
    tulip_wait(1);

    /* turn off reset and set cache align=16lword, burst=unlimit */
    outl(tp->csr0, ioaddr + CSR0);

    /*  Wait the specified 50 PCI cycles after a reset */
    tulip_wait(1);

    /* set up transmit and receive descriptors */
    tulip_init_ring(nic);

    if (tp->chip_id == PNIC2) {
        u32 addr_high = (nic->node_addr[1]<<8) + (nic->node_addr[0]<<0);
        /* This address setting does not appear to impact chip operation?? */
        outl((nic->node_addr[5]<<8) + nic->node_addr[4] +
             (nic->node_addr[3]<<24) + (nic->node_addr[2]<<16),
             ioaddr + 0xB0);
        outl(addr_high + (addr_high<<16), ioaddr + 0xB8);
    }

    /* MC_HASH_ONLY boards don't support setup packets */
    if (tp->flags & MC_HASH_ONLY) {
        u32 addr_low = cpu_to_le32(get_unaligned((u32 *)nic->node_addr));
        u32 addr_high = cpu_to_le32(get_unaligned((u16 *)(nic->node_addr+4)));

	/* clear multicast hash filters and setup MAC address filters */
	if (tp->flags & IS_ASIX) {
            outl(0, ioaddr + CSR13);
            outl(addr_low,  ioaddr + CSR14);
            outl(1, ioaddr + CSR13);
            outl(addr_high, ioaddr + CSR14);
	    outl(2, ioaddr + CSR13);
	    outl(0, ioaddr + CSR14);
	    outl(3, ioaddr + CSR13);
	    outl(0, ioaddr + CSR14);
	} else if (tp->chip_id == COMET) {
            outl(addr_low,  ioaddr + 0xA4);
            outl(addr_high, ioaddr + 0xA8);
            outl(0, ioaddr + 0xAC);
            outl(0, ioaddr + 0xB0);
	}
    } else {
	/* for other boards we send a setup packet to initialize
	   the filters */
	u32 tx_flags = 0x08000000 | 192;

	/* construct perfect filter frame with mac address as first match
	   and broadcast address for all others */
	for (i=0; i<192; i++) 
	    txb[i] = 0xFF;
	txb[0] = nic->node_addr[0];
	txb[1] = nic->node_addr[1];
	txb[4] = nic->node_addr[2];
	txb[5] = nic->node_addr[3];
	txb[8] = nic->node_addr[4];
	txb[9] = nic->node_addr[5];

	tx_ring[0].length  = cpu_to_le32(tx_flags);
	tx_ring[0].buffer1 = virt_to_le32desc(&txb[0]);
	tx_ring[0].status  = cpu_to_le32(0x80000000);
    }

    /* Point to rx and tx descriptors */
    outl(virt_to_le32desc(&rx_ring[0]), ioaddr + CSR3);
    outl(virt_to_le32desc(&tx_ring[0]), ioaddr + CSR4);

    init_media(nic);

    /* set the chip's operating mode (but don't turn on xmit and recv yet) */
    outl((tp->csr6 & ~0x00002002), ioaddr + CSR6);

    /* send setup packet for cards that support it */
    if (!(tp->flags & MC_HASH_ONLY)) {
	/* enable transmit  wait for completion */
	outl(tp->csr6 | 0x00002000, ioaddr + CSR6);
	/* immediate transmit demand */
	outl(0, ioaddr + CSR1);

	to = currticks() + TX_TIME_OUT;
	while ((tx_ring[0].status & 0x80000000) && (currticks() < to))
	    /* wait */ ;

	if (currticks() >= to) {
	    DBG ("%s: TX Setup Timeout.\n", tp->nic_name);
	}
    }

    if (tp->chip_id == LC82C168)
	tulip_check_duplex(nic);

    set_rx_mode(nic); 	
        
    /* enable transmit and receive */
    outl(tp->csr6 | 0x00002002, ioaddr + CSR6);
}


/*********************************************************************/
/* eth_transmit - Transmit a frame                                   */
/*********************************************************************/
static void tulip_transmit(struct nic *nic, const char *d, unsigned int t,
                           unsigned int s, const char *p)
{
    u16 nstype;
    u32 to;
    u32 csr6 = inl(ioaddr + CSR6);

    whereami("tulip_transmit\n");

    /* Disable Tx */
    outl(csr6 & ~0x00002000, ioaddr + CSR6);

    memcpy(txb, d, ETH_ALEN);
    memcpy(txb + ETH_ALEN, nic->node_addr, ETH_ALEN);
    nstype = htons((u16) t);
    memcpy(txb + 2 * ETH_ALEN, (u8 *)&nstype, 2);
    memcpy(txb + ETH_HLEN, p, s);

    s += ETH_HLEN;
    s &= 0x0FFF;

    /* pad to minimum packet size */
    while (s < ETH_ZLEN)  
        txb[s++] = '\0';

    DBG2("%s: sending %d bytes ethtype %hX\n", tp->nic_name, s, t);
        
    /* setup the transmit descriptor */
    /* 0x60000000 = no interrupt on completion */
    tx_ring[0].length = cpu_to_le32(0x60000000 | s);
    tx_ring[0].status = cpu_to_le32(0x80000000);

    /* Point to transmit descriptor */
    outl(virt_to_le32desc(&tx_ring[0]), ioaddr + CSR4);

    /* Enable Tx */
    outl(csr6 | 0x00002000, ioaddr + CSR6);
    /* immediate transmit demand */
    outl(0, ioaddr + CSR1);

    to = currticks() + TX_TIME_OUT;
    while ((tx_ring[0].status & 0x80000000) && (currticks() < to))
        /* wait */ ;

    if (currticks() >= to) {
        DBG ("TX Timeout!\n");
    }

    /* Disable Tx */
    outl(csr6 & ~0x00002000, ioaddr + CSR6);
}

/*********************************************************************/
/* eth_poll - Wait for a frame                                       */
/*********************************************************************/
static int tulip_poll(struct nic *nic, int retrieve)
{

    whereami("tulip_poll\n");

    /* no packet waiting. packet still owned by NIC */
    if (rx_ring[tp->cur_rx].status & 0x80000000)
        return 0;

    if ( ! retrieve ) return 1;

    whereami("tulip_poll got one\n");

    nic->packetlen = (rx_ring[tp->cur_rx].status & 0x3FFF0000) >> 16;

    /* if we get a corrupted packet. throw it away and move on */
    if (rx_ring[tp->cur_rx].status & 0x00008000) {
	/* return the descriptor and buffer to receive ring */
        rx_ring[tp->cur_rx].status = 0x80000000;
	tp->cur_rx = (tp->cur_rx + 1) % RX_RING_SIZE;
        return 0;
    }

    /* copy packet to working buffer */
    memcpy(nic->packet, rxb + tp->cur_rx * BUFLEN, nic->packetlen);

    /* return the descriptor and buffer to receive ring */
    rx_ring[tp->cur_rx].status = 0x80000000;
    tp->cur_rx = (tp->cur_rx + 1) % RX_RING_SIZE;

    return 1;
}

/*********************************************************************/
/* eth_disable - Disable the interface                               */
/*********************************************************************/
static void tulip_disable ( struct nic *nic ) {

    whereami("tulip_disable\n");

    tulip_reset(nic);

    /* disable interrupts */
    outl(0x00000000, ioaddr + CSR7);

    /* Stop the chip's Tx and Rx processes. */
    outl(inl(ioaddr + CSR6) & ~0x00002002, ioaddr + CSR6);

    /* Clear the missed-packet counter. */
    inl(ioaddr + CSR8);
}

/*********************************************************************/
/*IRQ - Enable, Disable, or Force interrupts                         */
/*********************************************************************/
static void tulip_irq(struct nic *nic __unused, irq_action_t action __unused)
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

static struct nic_operations tulip_operations = {
	.connect	= dummy_connect,
	.poll		= tulip_poll,
	.transmit	= tulip_transmit,
	.irq		= tulip_irq,

};

/*********************************************************************/
/* eth_probe - Look for an adapter                                   */
/*********************************************************************/
static int tulip_probe ( struct nic *nic, struct pci_device *pci ) {

    u32 i;
    u8  chip_rev;
    u8 ee_data[EEPROM_SIZE];
    unsigned short sum;
    int chip_idx;
    static unsigned char last_phys_addr[ETH_ALEN] = {0x00, 'L', 'i', 'n', 'u', 'x'};

    if (pci->ioaddr == 0)
        return 0;

    ioaddr         = pci->ioaddr;
    nic->ioaddr    = pci->ioaddr & ~3;
    nic->irqno     = 0;

    /* point to private storage */
    tp = &tulip_bss.tpx;

    tp->vendor_id  = pci->vendor;
    tp->dev_id     = pci->device;
    tp->nic_name   = pci->id->name;

    tp->if_port = 0;
    tp->default_port = 0;

    adjust_pci_device(pci);

    /* disable interrupts */
    outl(0x00000000, ioaddr + CSR7);

    /* Stop the chip's Tx and Rx processes. */
    outl(inl(ioaddr + CSR6) & ~0x00002002, ioaddr + CSR6);

    /* Clear the missed-packet counter. */
    inl(ioaddr + CSR8);

    DBG("\n");                /* so we start on a fresh line */
    whereami("tulip_probe\n");

    DBG2 ("%s: Looking for Tulip Chip: Vendor=%hX  Device=%hX\n", tp->nic_name,
	  tp->vendor_id, tp->dev_id);

    /* Figure out which chip we're dealing with */
    i = 0;
    chip_idx = -1;
  
    while (pci_id_tbl[i].name) {
        if ( (((u32) tp->dev_id << 16) | tp->vendor_id) == 
             (pci_id_tbl[i].id.pci & pci_id_tbl[i].id.pci_mask) ) {
            chip_idx = pci_id_tbl[i].drv_flags;
            break;
        }
        i++;
    }

    if (chip_idx == -1) {
        DBG ("%s: Unknown Tulip Chip: Vendor=%hX  Device=%hX\n", tp->nic_name,
                tp->vendor_id, tp->dev_id);
        return 0;
    }

    tp->pci_id_idx = i;
    tp->flags = tulip_tbl[chip_idx].flags;

    DBG2 ("%s: tp->pci_id_idx == %d,  name == %s\n", tp->nic_name,
	  tp->pci_id_idx, pci_id_tbl[tp->pci_id_idx].name);
    DBG2 ("%s: chip_idx == %d, name == %s\n", tp->nic_name, chip_idx,
	  tulip_tbl[chip_idx].chip_name);
  
    /* Bring the 21041/21143 out of sleep mode.
       Caution: Snooze mode does not work with some boards! */
    if (tp->flags & HAS_PWRDWN)
        pci_write_config_dword(pci, 0x40, 0x00000000);

    if (inl(ioaddr + CSR5) == 0xFFFFFFFF) {
        DBG("%s: The Tulip chip at %X is not functioning.\n",
               tp->nic_name, (unsigned int) ioaddr);
        return 0;
    }
   
    pci_read_config_byte(pci, PCI_REVISION, &chip_rev);

    DBG("%s: [chip: %s] rev %d at %hX\n", tp->nic_name,
           tulip_tbl[chip_idx].chip_name, chip_rev, (unsigned int) ioaddr);
    DBG("%s: Vendor=%hX  Device=%hX", tp->nic_name, tp->vendor_id, tp->dev_id);

    if (chip_idx == DC21041  &&  inl(ioaddr + CSR9) & 0x8000) {
        DBG(" 21040 compatible mode.");
        chip_idx = DC21040;
    }

    DBG("\n");

    /* The SROM/EEPROM interface varies dramatically. */
    sum = 0;
    if (chip_idx == DC21040) {
        outl(0, ioaddr + CSR9);         /* Reset the pointer with a dummy write. */
        for (i = 0; i < ETH_ALEN; i++) {
            int value, boguscnt = 100000;
            do
                value = inl(ioaddr + CSR9);
            while (value < 0  && --boguscnt > 0);
            nic->node_addr[i] = value;
            sum += value & 0xff;
        }
    } else if (chip_idx == LC82C168) {
        for (i = 0; i < 3; i++) {
            int value, boguscnt = 100000;
            outl(0x600 | i, ioaddr + 0x98);
            do
                value = inl(ioaddr + CSR9);
            while (value < 0  && --boguscnt > 0);
            put_unaligned(le16_to_cpu(value), ((u16*)nic->node_addr) + i);
            sum += value & 0xffff;
        }
    } else if (chip_idx == COMET) {
        /* No need to read the EEPROM. */
        put_unaligned(inl(ioaddr + 0xA4), (u32 *)nic->node_addr);
        put_unaligned(inl(ioaddr + 0xA8), (u16 *)(nic->node_addr + 4));
        for (i = 0; i < ETH_ALEN; i ++)
            sum += nic->node_addr[i];
    } else {
        /* A serial EEPROM interface, we read now and sort it out later. */
        int sa_offset = 0;
        int ee_addr_size = read_eeprom(ioaddr, 0xff, 8) & 0x40000 ? 8 : 6;

        for (i = 0; i < sizeof(ee_data)/2; i++)
            ((u16 *)ee_data)[i] =
                le16_to_cpu(read_eeprom(ioaddr, i, ee_addr_size));

        /* DEC now has a specification (see Notes) but early board makers
           just put the address in the first EEPROM locations. */
        /* This does  memcmp(eedata, eedata+16, 8) */
        for (i = 0; i < 8; i ++)
            if (ee_data[i] != ee_data[16+i])
                sa_offset = 20;
        if (ee_data[0] == 0xff  &&  ee_data[1] == 0xff &&  ee_data[2] == 0) {
            sa_offset = 2;              /* Grrr, damn Matrox boards. */
        }
        for (i = 0; i < ETH_ALEN; i ++) {
            nic->node_addr[i] = ee_data[i + sa_offset];
            sum += ee_data[i + sa_offset];
        }
    }
    /* Lite-On boards have the address byte-swapped. */
    if ((nic->node_addr[0] == 0xA0  ||  nic->node_addr[0] == 0xC0)
        &&  nic->node_addr[1] == 0x00)
        for (i = 0; i < ETH_ALEN; i+=2) {
            char tmp = nic->node_addr[i];
            nic->node_addr[i] = nic->node_addr[i+1];
            nic->node_addr[i+1] = tmp;
        }

    if (sum == 0  || sum == ETH_ALEN*0xff) {
        DBG("%s: EEPROM not present!\n", tp->nic_name);
        for (i = 0; i < ETH_ALEN-1; i++)
            nic->node_addr[i] = last_phys_addr[i];
        nic->node_addr[i] = last_phys_addr[i] + 1;
    }

    for (i = 0; i < ETH_ALEN; i++)
        last_phys_addr[i] = nic->node_addr[i];

    DBG ( "%s: %s at ioaddr %hX\n", tp->nic_name, eth_ntoa ( nic->node_addr ), 
	  (unsigned int) ioaddr );

    tp->chip_id = chip_idx;
    tp->revision = chip_rev;
    tp->csr0 = csr0;

    /* BugFixes: The 21143-TD hangs with PCI Write-and-Invalidate cycles.
       And the ASIX must have a burst limit or horrible things happen. */
    if (chip_idx == DC21143  &&  chip_rev == 65)
        tp->csr0 &= ~0x01000000;
    else if (tp->flags & IS_ASIX)
        tp->csr0 |= 0x2000;

    if (media_cap[tp->default_port] & MediaIsMII) {
        static const u16 media2advert[] = { 0x20, 0x40, 0x03e0, 0x60,
					    0x80, 0x100, 0x200 };
        tp->mii_advertise = media2advert[tp->default_port - 9];
        tp->mii_advertise |= (tp->flags & HAS_8023X); /* Matching bits! */
    }

    /* This is logically part of the probe routine, but too complex
       to write inline. */
    if (tp->flags & HAS_MEDIA_TABLE) {
        memcpy(tp->eeprom, ee_data, sizeof(tp->eeprom));
        parse_eeprom(nic);
    }

    start_link(nic);

    /* reset the device and make ready for tx and rx of packets */
    tulip_reset(nic);
    nic->nic_op	= &tulip_operations;

    /* give the board a chance to reset before returning */
    tulip_wait(4*TICKS_PER_SEC);

    return 1;
}

static void start_link(struct nic *nic)
{
    int i;

    whereami("start_link\n");

    if ((tp->flags & ALWAYS_CHECK_MII) ||
        (tp->mtable  &&  tp->mtable->has_mii) ||
        ( ! tp->mtable  &&  (tp->flags & HAS_MII))) {
        unsigned int phy, phy_idx;
        if (tp->mtable  &&  tp->mtable->has_mii) {
            for (i = 0; i < tp->mtable->leafcount; i++)
                if (tp->mtable->mleaf[i].media == 11) {
                    tp->cur_index = i;
                    tp->saved_if_port = tp->if_port;
                    select_media(nic, 2);
                    tp->if_port = tp->saved_if_port;
                    break;
                }
        }

        /* Find the connected MII xcvrs. */
        for (phy = 0, phy_idx = 0; phy < 32 && phy_idx < sizeof(tp->phys);
             phy++) {
            int mii_status = mdio_read(nic, phy, 1);
            if ((mii_status & 0x8301) == 0x8001 ||
                ((mii_status & 0x8000) == 0  && (mii_status & 0x7800) != 0)) {
                int mii_reg0 = mdio_read(nic, phy, 0);
                int mii_advert = mdio_read(nic, phy, 4);
                int to_advert;

                if (tp->mii_advertise)
                    to_advert = tp->mii_advertise;
                else if (tp->advertising[phy_idx])
                    to_advert = tp->advertising[phy_idx];
                else                    /* Leave unchanged. */
                    tp->mii_advertise = to_advert = mii_advert;

                tp->phys[phy_idx++] = phy;
                DBG("%s:  MII transceiver %d config %hX status %hX advertising %hX.\n",
                       tp->nic_name, phy, mii_reg0, mii_status, mii_advert);
                                /* Fixup for DLink with miswired PHY. */
                if (mii_advert != to_advert) {
                    DBG("%s:  Advertising %hX on PHY %d previously advertising %hX.\n",
                           tp->nic_name, to_advert, phy, mii_advert);
                    mdio_write(nic, phy, 4, to_advert);
                }
                                /* Enable autonegotiation: some boards default to off. */
                mdio_write(nic, phy, 0, mii_reg0 |
                           (tp->full_duplex ? 0x1100 : 0x1000) |
                           (media_cap[tp->default_port]&MediaIs100 ? 0x2000:0));
            }
        }
        tp->mii_cnt = phy_idx;
        if (tp->mtable  &&  tp->mtable->has_mii  &&  phy_idx == 0) {
            DBG("%s: ***WARNING***: No MII transceiver found!\n",
                   tp->nic_name);
            tp->phys[0] = 1;
        }
    }

    /* Reset the xcvr interface and turn on heartbeat. */
    switch (tp->chip_id) {
    case DC21040:
        outl(0x00000000, ioaddr + CSR13);
        outl(0x00000004, ioaddr + CSR13);
        break;
    case DC21041:
        /* This is nway_start(). */
        if (tp->sym_advertise == 0)
            tp->sym_advertise = 0x0061;
        outl(0x00000000, ioaddr + CSR13);
        outl(0xFFFFFFFF, ioaddr + CSR14);
        outl(0x00000008, ioaddr + CSR15); /* Listen on AUI also. */
        outl(inl(ioaddr + CSR6) | 0x0200, ioaddr + CSR6);
        outl(0x0000EF01, ioaddr + CSR13);
        break;
    case DC21140: default:
        if (tp->mtable)
            outl(tp->mtable->csr12dir | 0x100, ioaddr + CSR12);
        break;
    case DC21142:
    case PNIC2:
        if (tp->mii_cnt  ||  media_cap[tp->if_port] & MediaIsMII) {
            outl(0x82020000, ioaddr + CSR6);
            outl(0x0000, ioaddr + CSR13);
            outl(0x0000, ioaddr + CSR14);
            outl(0x820E0000, ioaddr + CSR6);
        } else
            nway_start(nic);
        break;
    case LC82C168:
        if ( ! tp->mii_cnt) {
            tp->nway = 1;
            tp->nwayset = 0;
            outl(0x00420000, ioaddr + CSR6);
            outl(0x30, ioaddr + CSR12);
            outl(0x0001F078, ioaddr + 0xB8);
            outl(0x0201F078, ioaddr + 0xB8); /* Turn on autonegotiation. */
        }
        break;
    case MX98713: case COMPEX9881:
        outl(0x00000000, ioaddr + CSR6);
        outl(0x000711C0, ioaddr + CSR14); /* Turn on NWay. */
        outl(0x00000001, ioaddr + CSR13);
        break;
    case MX98715: case MX98725:
        outl(0x01a80000, ioaddr + CSR6);
        outl(0xFFFFFFFF, ioaddr + CSR14);
        outl(0x00001000, ioaddr + CSR12);
        break;
    case COMET:
        /* No initialization necessary. */
        break;
    }
}

static void nway_start(struct nic *nic __unused)
{
    int csr14 = ((tp->sym_advertise & 0x0780) << 9)  |
        ((tp->sym_advertise&0x0020)<<1) | 0xffbf;

    whereami("nway_start\n");

    tp->if_port = 0;
    tp->nway = tp->mediasense = 1;
    tp->nwayset = tp->lpar = 0;
    if (tp->chip_id == PNIC2) {
        tp->csr6 = 0x01000000 | (tp->sym_advertise & 0x0040 ? 0x0200 : 0);
        return;
    }
    DBG2("%s: Restarting internal NWay autonegotiation, %X.\n",
	 tp->nic_name, csr14);
    outl(0x0001, ioaddr + CSR13);
    outl(csr14, ioaddr + CSR14);
    tp->csr6 = 0x82420000 | (tp->sym_advertise & 0x0040 ? 0x0200 : 0);
    outl(tp->csr6, ioaddr + CSR6);
    if (tp->mtable  &&  tp->mtable->csr15dir) {
        outl(tp->mtable->csr15dir, ioaddr + CSR15);
        outl(tp->mtable->csr15val, ioaddr + CSR15);
    } else if (tp->chip_id != PNIC2)
        outw(0x0008, ioaddr + CSR15);
    if (tp->chip_id == DC21041)                 /* Trigger NWAY. */
        outl(0xEF01, ioaddr + CSR12);
    else
        outl(0x1301, ioaddr + CSR12);
}

static void init_media(struct nic *nic)
{
    int i;

    whereami("init_media\n");

    tp->saved_if_port = tp->if_port;
    if (tp->if_port == 0)
        tp->if_port = tp->default_port;

    /* Allow selecting a default media. */
    i = 0;
    if (tp->mtable == NULL)
        goto media_picked;
    if (tp->if_port) {
        int looking_for = media_cap[tp->if_port] & MediaIsMII ? 11 :
            (tp->if_port == 12 ? 0 : tp->if_port);
        for (i = 0; i < tp->mtable->leafcount; i++)
            if (tp->mtable->mleaf[i].media == looking_for) {
                DBG("%s: Using user-specified media %s.\n",
                       tp->nic_name, medianame[tp->if_port]);
                goto media_picked;
            }
    }
    if ((tp->mtable->defaultmedia & 0x0800) == 0) {
        int looking_for = tp->mtable->defaultmedia & 15;
        for (i = 0; i < tp->mtable->leafcount; i++)
            if (tp->mtable->mleaf[i].media == looking_for) {
                DBG("%s: Using EEPROM-set media %s.\n",
                       tp->nic_name, medianame[looking_for]);
                goto media_picked;
            }
    }
    /* Start sensing first non-full-duplex media. */
    for (i = tp->mtable->leafcount - 1;
         (media_cap[tp->mtable->mleaf[i].media] & MediaAlwaysFD) && i > 0; i--)
        ;
 media_picked:

    tp->csr6 = 0;
    tp->cur_index = i;
    tp->nwayset = 0;

    if (tp->if_port) {
        if (tp->chip_id == DC21143  &&  media_cap[tp->if_port] & MediaIsMII) {
            /* We must reset the media CSRs when we force-select MII mode. */
            outl(0x0000, ioaddr + CSR13);
            outl(0x0000, ioaddr + CSR14);
            outl(0x0008, ioaddr + CSR15);
        }
        select_media(nic, 1);
        return;
    }
    switch(tp->chip_id) {
    case DC21041:
        /* tp->nway = 1;*/
        nway_start(nic);
        break;
    case DC21142:
        if (tp->mii_cnt) {
            select_media(nic, 1);
	    DBG2("%s: Using MII transceiver %d, status %hX.\n",
		 tp->nic_name, tp->phys[0], mdio_read(nic, tp->phys[0], 1));
            outl(0x82020000, ioaddr + CSR6);
            tp->csr6 = 0x820E0000;
            tp->if_port = 11;
            outl(0x0000, ioaddr + CSR13);
            outl(0x0000, ioaddr + CSR14);
        } else
            nway_start(nic);
        break;
    case PNIC2:
        nway_start(nic);
        break;
    case LC82C168:
        if (tp->mii_cnt) {
            tp->if_port = 11;
            tp->csr6 = 0x814C0000 | (tp->full_duplex ? 0x0200 : 0);
            outl(0x0001, ioaddr + CSR15);
        } else if (inl(ioaddr + CSR5) & TPLnkPass)
            pnic_do_nway(nic);
        else {
            /* Start with 10mbps to do autonegotiation. */
            outl(0x32, ioaddr + CSR12);
            tp->csr6 = 0x00420000;
            outl(0x0001B078, ioaddr + 0xB8);
            outl(0x0201B078, ioaddr + 0xB8);
        }
        break;
    case MX98713: case COMPEX9881:
        tp->if_port = 0;
        tp->csr6 = 0x01880000 | (tp->full_duplex ? 0x0200 : 0);
        outl(0x0f370000 | inw(ioaddr + 0x80), ioaddr + 0x80);
        break;
    case MX98715: case MX98725:
        /* Provided by BOLO, Macronix - 12/10/1998. */
        tp->if_port = 0;
        tp->csr6 = 0x01a80200;
        outl(0x0f370000 | inw(ioaddr + 0x80), ioaddr + 0x80);
        outl(0x11000 | inw(ioaddr + 0xa0), ioaddr + 0xa0);
        break;
    case COMET:
        /* Enable automatic Tx underrun recovery */
        outl(inl(ioaddr + 0x88) | 1, ioaddr + 0x88);
        tp->if_port = 0;
	tp->csr6 = 0x00040000;
        break;
    case AX88140: case AX88141:
        tp->csr6 = tp->mii_cnt ? 0x00040100 : 0x00000100;
        break;
    default:
        select_media(nic, 1);
    }
}

static void pnic_do_nway(struct nic *nic __unused)
{
    u32 phy_reg = inl(ioaddr + 0xB8);
    u32 new_csr6 = tp->csr6 & ~0x40C40200;

    whereami("pnic_do_nway\n");

    if (phy_reg & 0x78000000) { /* Ignore baseT4 */
        if (phy_reg & 0x20000000)               tp->if_port = 5;
        else if (phy_reg & 0x40000000)  tp->if_port = 3;
        else if (phy_reg & 0x10000000)  tp->if_port = 4;
        else if (phy_reg & 0x08000000)  tp->if_port = 0;
        tp->nwayset = 1;
        new_csr6 = (tp->if_port & 1) ? 0x01860000 : 0x00420000;
        outl(0x32 | (tp->if_port & 1), ioaddr + CSR12);
        if (tp->if_port & 1)
            outl(0x1F868, ioaddr + 0xB8);
        if (phy_reg & 0x30000000) {
            tp->full_duplex = 1;
            new_csr6 |= 0x00000200;
        }
	DBG2("%s: PNIC autonegotiated status %X, %s.\n",
	     tp->nic_name, phy_reg, medianame[tp->if_port]);
        if (tp->csr6 != new_csr6) {
            tp->csr6 = new_csr6;
            outl(tp->csr6 | 0x0002, ioaddr + CSR6);     /* Restart Tx */
            outl(tp->csr6 | 0x2002, ioaddr + CSR6);
        }
    }
}

/* Set up the transceiver control registers for the selected media type. */
static void select_media(struct nic *nic, int startup)
{
    struct mediatable *mtable = tp->mtable;
    u32 new_csr6;
    int i;

    whereami("select_media\n");

    if (mtable) {
        struct medialeaf *mleaf = &mtable->mleaf[tp->cur_index];
        unsigned char *p = mleaf->leafdata;
        switch (mleaf->type) {
        case 0:                                 /* 21140 non-MII xcvr. */
            DBG2("%s: Using a 21140 non-MII transceiver"
		 " with control setting %hhX.\n",
		 tp->nic_name, p[1]);
            tp->if_port = p[0];
            if (startup)
                outl(mtable->csr12dir | 0x100, ioaddr + CSR12);
            outl(p[1], ioaddr + CSR12);
            new_csr6 = 0x02000000 | ((p[2] & 0x71) << 18);
            break;
        case 2: case 4: {
            u16 setup[5];
            u32 csr13val, csr14val, csr15dir, csr15val;
            for (i = 0; i < 5; i++)
                setup[i] = get_u16(&p[i*2 + 1]);

            tp->if_port = p[0] & 15;
            if (media_cap[tp->if_port] & MediaAlwaysFD)
                tp->full_duplex = 1;

            if (startup && mtable->has_reset) {
                struct medialeaf *rleaf = &mtable->mleaf[mtable->has_reset];
                unsigned char *rst = rleaf->leafdata;
		DBG2("%s: Resetting the transceiver.\n",
		     tp->nic_name);
                for (i = 0; i < rst[0]; i++)
                    outl(get_u16(rst + 1 + (i<<1)) << 16, ioaddr + CSR15);
            }
	    DBG2("%s: 21143 non-MII %s transceiver control %hX/%hX.\n",
		 tp->nic_name, medianame[tp->if_port], setup[0], setup[1]);
            if (p[0] & 0x40) {  /* SIA (CSR13-15) setup values are provided. */
                csr13val = setup[0];
                csr14val = setup[1];
                csr15dir = (setup[3]<<16) | setup[2];
                csr15val = (setup[4]<<16) | setup[2];
                outl(0, ioaddr + CSR13);
                outl(csr14val, ioaddr + CSR14);
                outl(csr15dir, ioaddr + CSR15); /* Direction */
                outl(csr15val, ioaddr + CSR15); /* Data */
                outl(csr13val, ioaddr + CSR13);
            } else {
                csr13val = 1;
                csr14val = 0x0003FF7F;
                csr15dir = (setup[0]<<16) | 0x0008;
                csr15val = (setup[1]<<16) | 0x0008;
                if (tp->if_port <= 4)
                    csr14val = t21142_csr14[tp->if_port];
                if (startup) {
                    outl(0, ioaddr + CSR13);
                    outl(csr14val, ioaddr + CSR14);
                }
                outl(csr15dir, ioaddr + CSR15); /* Direction */
                outl(csr15val, ioaddr + CSR15); /* Data */
                if (startup) outl(csr13val, ioaddr + CSR13);
            }
	    DBG2("%s:  Setting CSR15 to %X/%X.\n",
		 tp->nic_name, csr15dir, csr15val);
            if (mleaf->type == 4)
                new_csr6 = 0x82020000 | ((setup[2] & 0x71) << 18);
            else
                new_csr6 = 0x82420000;
            break;
        }
        case 1: case 3: {
            int phy_num = p[0];
            int init_length = p[1];
            u16 *misc_info;

            tp->if_port = 11;
            new_csr6 = 0x020E0000;
            if (mleaf->type == 3) {     /* 21142 */
                u16 *init_sequence = (u16*)(p+2);
                u16 *reset_sequence = &((u16*)(p+3))[init_length];
                int reset_length = p[2 + init_length*2];
                misc_info = reset_sequence + reset_length;
                if (startup)
                    for (i = 0; i < reset_length; i++)
                        outl(get_u16(&reset_sequence[i]) << 16, ioaddr + CSR15);
                for (i = 0; i < init_length; i++)
                    outl(get_u16(&init_sequence[i]) << 16, ioaddr + CSR15);
            } else {
                u8 *init_sequence = p + 2;
                u8 *reset_sequence = p + 3 + init_length;
                int reset_length = p[2 + init_length];
                misc_info = (u16*)(reset_sequence + reset_length);
                if (startup) {
                    outl(mtable->csr12dir | 0x100, ioaddr + CSR12);
                    for (i = 0; i < reset_length; i++)
                        outl(reset_sequence[i], ioaddr + CSR12);
                }
                for (i = 0; i < init_length; i++)
                    outl(init_sequence[i], ioaddr + CSR12);
            }
            tp->advertising[phy_num] = get_u16(&misc_info[1]) | 1;
            if (startup < 2) {
                if (tp->mii_advertise == 0)
                    tp->mii_advertise = tp->advertising[phy_num];
		DBG2("%s:  Advertising %hX on MII %d.\n",
		     tp->nic_name, tp->mii_advertise, tp->phys[phy_num]);
                mdio_write(nic, tp->phys[phy_num], 4, tp->mii_advertise);
            }
            break;
        }
        default:
            DBG("%s:  Invalid media table selection %d.\n",
                   tp->nic_name, mleaf->type);
            new_csr6 = 0x020E0000;
        }
	DBG2("%s: Using media type %s, CSR12 is %hhX.\n",
	     tp->nic_name, medianame[tp->if_port],
	     inl(ioaddr + CSR12) & 0xff);
    } else if (tp->chip_id == DC21041) {
        int port = tp->if_port <= 4 ? tp->if_port : 0;
	DBG2("%s: 21041 using media %s, CSR12 is %hX.\n",
	     tp->nic_name, medianame[port == 3 ? 12: port],
	     inl(ioaddr + CSR12));
        outl(0x00000000, ioaddr + CSR13); /* Reset the serial interface */
        outl(t21041_csr14[port], ioaddr + CSR14);
        outl(t21041_csr15[port], ioaddr + CSR15);
        outl(t21041_csr13[port], ioaddr + CSR13);
        new_csr6 = 0x80020000;
    } else if (tp->chip_id == LC82C168) {
        if (startup && ! tp->medialock)
            tp->if_port = tp->mii_cnt ? 11 : 0;
	DBG2("%s: PNIC PHY status is %hX, media %s.\n",
	     tp->nic_name, inl(ioaddr + 0xB8), medianame[tp->if_port]);
        if (tp->mii_cnt) {
            new_csr6 = 0x810C0000;
            outl(0x0001, ioaddr + CSR15);
            outl(0x0201B07A, ioaddr + 0xB8);
        } else if (startup) {
            /* Start with 10mbps to do autonegotiation. */
            outl(0x32, ioaddr + CSR12);
            new_csr6 = 0x00420000;
            outl(0x0001B078, ioaddr + 0xB8);
            outl(0x0201B078, ioaddr + 0xB8);
        } else if (tp->if_port == 3  ||  tp->if_port == 5) {
            outl(0x33, ioaddr + CSR12);
            new_csr6 = 0x01860000;
            /* Trigger autonegotiation. */
            outl(startup ? 0x0201F868 : 0x0001F868, ioaddr + 0xB8);
        } else {
            outl(0x32, ioaddr + CSR12);
            new_csr6 = 0x00420000;
            outl(0x1F078, ioaddr + 0xB8);
        }
    } else if (tp->chip_id == DC21040) {                                        /* 21040 */
        /* Turn on the xcvr interface. */
        int csr12 = inl(ioaddr + CSR12);
	DBG2("%s: 21040 media type is %s, CSR12 is %hhX.\n",
	     tp->nic_name, medianame[tp->if_port], csr12);
        if (media_cap[tp->if_port] & MediaAlwaysFD)
            tp->full_duplex = 1;
        new_csr6 = 0x20000;
        /* Set the full duplux match frame. */
        outl(FULL_DUPLEX_MAGIC, ioaddr + CSR11);
        outl(0x00000000, ioaddr + CSR13); /* Reset the serial interface */
        if (t21040_csr13[tp->if_port] & 8) {
            outl(0x0705, ioaddr + CSR14);
            outl(0x0006, ioaddr + CSR15);
        } else {
            outl(0xffff, ioaddr + CSR14);
            outl(0x0000, ioaddr + CSR15);
        }
        outl(0x8f01 | t21040_csr13[tp->if_port], ioaddr + CSR13);
    } else {                                    /* Unknown chip type with no media table. */
        if (tp->default_port == 0)
            tp->if_port = tp->mii_cnt ? 11 : 3;
        if (media_cap[tp->if_port] & MediaIsMII) {
            new_csr6 = 0x020E0000;
        } else if (media_cap[tp->if_port] & MediaIsFx) {
            new_csr6 = 0x028600000;
        } else
            new_csr6 = 0x038600000;
	DBG2("%s: No media description table, assuming "
	     "%s transceiver, CSR12 %hhX.\n",
	     tp->nic_name, medianame[tp->if_port],
	     inl(ioaddr + CSR12));
    }

    tp->csr6 = new_csr6 | (tp->csr6 & 0xfdff) | (tp->full_duplex ? 0x0200 : 0);
    return;
}

/*
  Check the MII negotiated duplex and change the CSR6 setting if
  required.
  Return 0 if everything is OK.
  Return < 0 if the transceiver is missing or has no link beat.
*/
static int tulip_check_duplex(struct nic *nic)
{
        unsigned int bmsr, lpa, negotiated, new_csr6;

        bmsr = mdio_read(nic, tp->phys[0], 1);
        lpa = mdio_read(nic, tp->phys[0], 5);

	DBG2("%s: MII status %#x, Link partner report %#x.\n",
	     tp->nic_name, bmsr, lpa);

        if (bmsr == 0xffff)
                return -2;
        if ((bmsr & 4) == 0) { 
                int new_bmsr = mdio_read(nic, tp->phys[0], 1); 
                if ((new_bmsr & 4) == 0) { 
			DBG2("%s: No link beat on the MII interface,"
			     " status %#x.\n", tp->nic_name,
			     new_bmsr);
                        return -1;
                }
        }
        tp->full_duplex = lpa & 0x140;

        new_csr6 = tp->csr6;
        negotiated = lpa & tp->advertising[0];

        if(negotiated & 0x380) new_csr6 &= ~0x400000; 
        else                   new_csr6 |= 0x400000;
        if (tp->full_duplex)   new_csr6 |= 0x200; 
        else                   new_csr6 &= ~0x200;

        if (new_csr6 != tp->csr6) {
                tp->csr6 = new_csr6;

		DBG("%s: Setting %s-duplex based on MII"
		    "#%d link partner capability of %#x.\n",
		    tp->nic_name,
		    tp->full_duplex ? "full" : "half",
		    tp->phys[0], lpa);
                return 1;
        }

        return 0;
}

static struct pci_device_id tulip_nics[] = {
PCI_ROM(0x1011, 0x0002, "dc21040",     "Digital Tulip", 0),
PCI_ROM(0x1011, 0x0009, "ds21140",     "Digital Tulip Fast", 0),
PCI_ROM(0x1011, 0x0014, "dc21041",     "Digital Tulip+", 0),
PCI_ROM(0x1011, 0x0019, "ds21142",     "Digital Tulip 21142", 0),
PCI_ROM(0x10b7, 0x9300, "3csoho100b-tx","3ComSOHO100B-TX", 0),
PCI_ROM(0x10b9, 0x5261, "ali1563",     "ALi 1563 integrated ethernet", 0),
PCI_ROM(0x10d9, 0x0512, "mx98713",     "Macronix MX987x3", 0),
PCI_ROM(0x10d9, 0x0531, "mx98715",     "Macronix MX987x5", 0),
PCI_ROM(0x1113, 0x1217, "mxic-98715",  "Macronix MX987x5", 0),
PCI_ROM(0x11ad, 0xc115, "lc82c115",    "LinkSys LNE100TX", 0),
PCI_ROM(0x11ad, 0x0002, "82c168",      "Netgear FA310TX", 0),
PCI_ROM(0x1282, 0x9100, "dm9100",      "Davicom 9100", 0),
PCI_ROM(0x1282, 0x9102, "dm9102",      "Davicom 9102", 0),
PCI_ROM(0x1282, 0x9009, "dm9009",      "Davicom 9009", 0),
PCI_ROM(0x1282, 0x9132, "dm9132",      "Davicom 9132", 0),
PCI_ROM(0x1317, 0x0985, "centaur-p",   "ADMtek Centaur-P", 0),
PCI_ROM(0x1317, 0x0981, "an981",       "ADMtek AN981 Comet", 0),		/* ADMTek Centaur-P (stmicro) */
PCI_ROM(0x1113, 0x1216, "an983",       "ADMTek AN983 Comet", 0),
PCI_ROM(0x1317, 0x9511, "an983b",      "ADMTek Comet 983b", 0),
PCI_ROM(0x1317, 0x1985, "centaur-c",   "ADMTek Centaur-C", 0),
PCI_ROM(0x8086, 0x0039, "intel21145",  "Intel Tulip", 0),
PCI_ROM(0x125b, 0x1400, "ax88140",     "ASIX AX88140", 0),
PCI_ROM(0x11f6, 0x9881, "rl100tx",     "Compex RL100-TX", 0),
PCI_ROM(0x115d, 0x0003, "xircomtulip", "Xircom Tulip", 0),
PCI_ROM(0x104a, 0x0981, "tulip-0981",  "Tulip 0x104a 0x0981", 0),
PCI_ROM(0x104a, 0x2774, "SGThomson-STE10100A", "Tulip 0x104a 0x2774", 0),	/*Modified by Ramesh Chander*/
PCI_ROM(0x1113, 0x9511, "tulip-9511",  "Tulip 0x1113 0x9511", 0),
PCI_ROM(0x1186, 0x1561, "tulip-1561",  "Tulip 0x1186 0x1561", 0),
PCI_ROM(0x1259, 0xa120, "tulip-a120",  "Tulip 0x1259 0xa120", 0),
PCI_ROM(0x13d1, 0xab02, "tulip-ab02",  "Tulip 0x13d1 0xab02", 0),
PCI_ROM(0x13d1, 0xab03, "tulip-ab03",  "Tulip 0x13d1 0xab03", 0),
PCI_ROM(0x13d1, 0xab08, "tulip-ab08",  "Tulip 0x13d1 0xab08", 0),
PCI_ROM(0x14f1, 0x1803, "lanfinity",   "Conexant LANfinity", 0),
PCI_ROM(0x1626, 0x8410, "tulip-8410",  "Tulip 0x1626 0x8410", 0),
PCI_ROM(0x1737, 0xab08, "tulip-1737-ab08","Tulip 0x1737 0xab08", 0),
PCI_ROM(0x1737, 0xab09, "tulip-ab09",  "Tulip 0x1737 0xab09", 0),
};

PCI_DRIVER ( tulip_driver, tulip_nics, PCI_NO_CLASS );

DRIVER ( "Tulip", nic_driver, pci_driver, tulip_driver,
	 tulip_probe, tulip_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
