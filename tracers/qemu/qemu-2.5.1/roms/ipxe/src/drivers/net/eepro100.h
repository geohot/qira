
#ifndef __EEPRO100_H_
#define __EEPRO100_H_

FILE_LICENCE ( GPL2_OR_LATER );

#define CONGENB         0	/* Enable congestion control in the DP83840. */
#define TX_FIFO         8	/* Tx FIFO threshold in 4 byte units, 0-15 */
#define RX_FIFO         8	/* Rx FIFO threshold, default 32 bytes. */
#define TX_DMA_COUNT    0	/* Tx DMA burst length, 0-127, default 0. */
#define RX_DMA_COUNT    0	/* Rx DMA length, 0 means no preemption. */
#define CU_CMD_TIMEOUT  1000	/* CU command accept timeout in microseconds */
#define LINK_CHECK_PERIOD 1000	/* # of poll() calls between link checks */

#define RFD_PACKET_LEN  1518
#define RFD_IOB_LEN     1536
#define RFD_HEADER_LEN  16
#define CB_ALIGN        2	/* Alignment of command blocks */

#define RFD_COUNT       4
#define TCB_COUNT       4
#define RX_RING_BYTES   ( RFD_COUNT * sizeof ( struct ifec_rfd ) )
#define TX_RING_BYTES   ( TCB_COUNT * sizeof ( struct ifec_tcb ) )

/* some EEPROM addresses */
#define EEPROM_ADDR_MAC_0		0
#define EEPROM_ADDR_MDIO_REGISTER	6

/* Control / Status Register byte offsets - SDM Table 11 */
enum CSROffsets {
	SCBStatus=0,             SCBCmd=2,              SCBPointer = 4,
	CSRPort=8,               CSRFlash=12,           CSREeprom = 14,
	CSRCtrlMDI=16,           CSREarlyRx=20
};

/* System Control Block Command Word - SDM Table 12 */
enum SCBCmdBits {
	/* SCB Interrupt Masks - SDM Table 14 */
	SCBMaskCmdDone=0x8000,   SCBMaskRxDone=0x4000,  SCBMaskCmdIdle=0x2000,
	SCBMaskRxSuspend=0x1000, SCBMaskEarlyRx=0x0800, SCBMaskFlowCtl=0x0400,
	SCBTriggerIntr=0x0200,   SCBMaskAll=0x0100,
	/* SCB Control Commands - SDM Table 14-16 */
	CUStart=0x0010,          CUResume=0x0020,       CUStatsAddr=0x0040,
	CUShowStats=0x0050,      CUCmdBase=0x0060,      CUDumpStats=0x0070,
	RUStart=0x0001,          RUResume=0x0002,       RUAbort=0x0004,
	RUAddrLoad=0x0006,       RUResumeNoResources=0x0007
};

enum SCBPortCmds {
	PortReset=0, PortSelfTest=1, PortPartialReset=2, PortDump=3
};

/* Action Commands - SDM Table 14,37 */
enum ActionCommands {
	CmdNOp = 0,              CmdIASetup = 1,        CmdConfigure = 2,
	CmdMulticastList = 3,    CmdTx = 4,             CmdTDR = 5,
	CmdDump = 6,             CmdDiagnose = 7,
	/* And some extra flags: */
	CmdEndOfList = 0x8000,
	CmdSuspend = 0x4000,     CmdIntr = 0x2000,      CmdTxFlex = 0x0008
};

enum TCBBits {
	TCB_C=0x8000,            TCB_OK=0x2000,         TCB_U=0x1000
};

enum RFDBits {
	/* Status Word Bits */
	RFDRxCol=0x0001,         RFDIAMatch=0x0002,     RFDNoMatch=0x0004,
	RFDReserved3=0x0008,     RFDRxErr=0x0010,       RFDEthType=0x0020,
	RFDReserved6=0x0040,     RFDShort=0x0080,       RFDDMAOverrun=0x0100,
	RFDNoBufs=0x0200,        RFDCRCAlign=0x0400,    RFDCRCError=0x0800,
	RFDReserved12=0x1000,    RFD_OK=0x2000,         RFDComplete=0x8000,
	/* Command Word Bits */
	//RFD_SF=0x0008,           RFDSuspend=0x4000,     RFDEndOfList=0x8000,
	/* Other */
	RFDMaskCount=0x3FFF
};

enum phy_chips {
	NonSuchPhy=0,            I82553AB,              I82553C,
	I82503,                  DP83840,               S80C240,
	S80C24,                  PhyUndefined,          DP83840A=10
};

/* Serial EEPROM section.
   A "bit" grungy, but we work our way through bit-by-bit :->. */
/*  EEPROM_Ctrl bits. */
#define EE_SHIFT_CLK    0x01    /* EEPROM shift clock. */
#define EE_CS           0x02    /* EEPROM chip select. */
#define EE_DATA_WRITE   0x04    /* EEPROM chip data in. */
#define EE_DATA_READ    0x08    /* EEPROM chip data out. */
#define EE_ENB          ( 0x4800 | EE_CS )

/* Elements of the dump_statistics block. This block must be lword aligned. */
struct ifec_stats {
	u32
	tx_good_frames,          tx_coll16_errs,        tx_late_colls,
	tx_underruns,            tx_lost_carrier,       tx_deferred,
	tx_one_colls,            tx_multi_colls,        tx_total_colls,
	rx_good_frames,          rx_crc_errs,           rx_align_errs,
	rx_resource_errs,        rx_overrun_errs,       rx_colls_errs,
	rx_runt_errs,            done_marker;
};

struct ifec_tcb {                  /* A Transmit Command Block & TBD. Must be */
	volatile s16 status;       /*             word (even address) aligned */
	u16          command;
	u32          link;         /* PHYSICAL next ifec_tcb, doesn't change */
	u32          tbda_addr;    /* TBD Array, points to TBD below */
	s32          count;        /* # of TBD, Tx start thresh., etc. */
	/* The following constitutes a Transmit Buffer Descriptor (TBD).
	 * TBDs must be aligned on an even address (word-aligned). */
	u32          tbd_addr0;    /* PHYSICAL ptr to Tx data */
	s32          tbd_size0;    /* Length of Tx data */
	/* Driver-specific data; not part of TCB format. */
	struct io_buffer *iob;     /* Exists from tx() to completion poll() */
	struct ifec_tcb  *next;    /* VIRTUAL next ifec_tcb, doesn't change */
};

struct ifec_rfd {              /* A Receive Frame Descriptor. Must be aligned */
	volatile s16 status;   /*           on a physical word (even address) */
	s16          command;
	u32          link;          /* PHYSICAL next ifec_rfd, doesn't change */
	u32          rx_buf_addr;   /* Unused. Flex rx mode is not documented */
	u16          count;         /*                  and may be impossible */
	u16          size;
	char         packet[RFD_PACKET_LEN];
};

struct ifec_ias {              /* Individual Address Setup command block. */
	volatile s16 status;   /* Must be word (even address) aligned. */
	u16          command;
	u32          link;     /* PHYSICAL next command block to process */
	u8           ia[6];
};

struct ifec_cfg {                   /* The configure command format. */
	volatile s16 status;
	u16          command;
	u32          link;          /* PHYSICAL next command block to process */
	u8           byte[22];      /* 22 configuration bytes */
};

struct ifec_private {
	unsigned long         ioaddr;
	struct ifec_stats     stats;
	unsigned short        mdio_register;

	struct ifec_tcb      *tcbs;
	struct ifec_rfd      *rfds[RFD_COUNT];
	struct ifec_tcb      *tcb_head, *tcb_tail;
	struct io_buffer     *tx_iobs[TCB_COUNT];
	struct io_buffer     *rx_iobs[RFD_COUNT];
	int		      cur_rx;
	int		      tx_curr;
	int		      tx_tail;
	int		      tx_cnt;
	/*
	 * The configured flag indicates if a Config command was last issued.
	 * The following attempt to issue a command (in ifec_tx_wake) will
	 * use a START rather than RESUME SCB command. It seems the card won't
	 * RESUME after a configure command.
	 */
	int                   configured;
	struct spi_bit_basher spi;
	struct spi_device     eeprom;
	
};

/**************************** Function prototypes ****************************/

/* PCI device API prototypes */
static int  ifec_pci_probe  ( struct pci_device *pci );
static void ifec_pci_remove ( struct pci_device *pci );

/* Network device API prototypes */
static void ifec_net_close    ( struct net_device* );
static void ifec_net_irq      ( struct net_device*, int enable );
static int  ifec_net_open     ( struct net_device* );
static void ifec_net_poll     ( struct net_device* );
static int  ifec_net_transmit ( struct net_device*, struct io_buffer *iobuf );

/* Local function prototypes */
static void ifec_init_eeprom     ( struct net_device * );
static int  ifec_mdio_read       ( struct net_device *, int phy, int location );
static void ifec_mdio_setup      ( struct net_device *, int options );
static int  ifec_mdio_write      ( struct net_device *, int phy, int loc, int val);
static void ifec_reset           ( struct net_device * );
static void ifec_free            ( struct net_device * );
static void ifec_rfd_init        ( struct ifec_rfd *rfd, s16 command, u32 link );
static void  ifec_rx_process     ( struct net_device * );
static void ifec_reprime_ru      ( struct net_device * );
static void ifec_check_ru_status ( struct net_device *, unsigned short );
static int  ifec_get_rx_desc     ( struct net_device *, int ,int ,int );
static void ifec_refill_rx_ring  ( struct net_device * );
static int  ifec_rx_setup        ( struct net_device * );
static int  ifec_scb_cmd         ( struct net_device *, u32 ptr, u8 cmd );
static int  ifec_scb_cmd_wait    ( struct net_device * );
static void ifec_tx_process      ( struct net_device * );
static int  ifec_tx_setup        ( struct net_device * );
static void ifec_tx_wake         ( struct net_device * );

#endif
