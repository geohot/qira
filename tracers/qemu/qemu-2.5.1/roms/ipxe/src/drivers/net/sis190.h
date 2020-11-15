#ifndef __SIS190_H__
#define __SIS190_H__

FILE_LICENCE ( GPL_ANY );

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <mii.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/io.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/netdevice.h>
#include <ipxe/pci.h>
#include <ipxe/timer.h>

#define PCI_VENDOR_ID_SI	0x1039

#define PHY_MAX_ADDR		32
#define PHY_ID_ANY		0x1f
#define MII_REG_ANY		0x1f

#define DRV_VERSION		"1.3"
#define DRV_NAME		"sis190"
#define SIS190_DRIVER_NAME	DRV_NAME " Gigabit Ethernet driver " DRV_VERSION
#define PFX DRV_NAME ": "

#define sis190_rx_quota(count, quota)	count

#define NUM_TX_DESC		8	/* [8..1024] */
#define NUM_RX_DESC		8	/* [8..8192] */
#define TX_RING_BYTES		(NUM_TX_DESC * sizeof(struct TxDesc))
#define RX_RING_BYTES		(NUM_RX_DESC * sizeof(struct RxDesc))
#define RX_BUF_SIZE		1536
#define RX_BUF_MASK		0xfff8

#define RING_ALIGNMENT		256

#define SIS190_REGS_SIZE	0x80

/* Enhanced PHY access register bit definitions */
#define EhnMIIread		0x0000
#define EhnMIIwrite		0x0020
#define EhnMIIdataShift		16
#define EhnMIIpmdShift		6	/* 7016 only */
#define EhnMIIregShift		11
#define EhnMIIreq		0x0010
#define EhnMIInotDone		0x0010

/* Write/read MMIO register */
#define SIS_W8(reg, val)	writeb ((val), ioaddr + (reg))
#define SIS_W16(reg, val)	writew ((val), ioaddr + (reg))
#define SIS_W32(reg, val)	writel ((val), ioaddr + (reg))
#define SIS_R8(reg)		readb (ioaddr + (reg))
#define SIS_R16(reg)		readw (ioaddr + (reg))
#define SIS_R32(reg)		readl (ioaddr + (reg))

#define SIS_PCI_COMMIT()	SIS_R32(IntrControl)

enum sis190_registers {
	TxControl		= 0x00,
	TxDescStartAddr		= 0x04,
	rsv0			= 0x08,	// reserved
	TxSts			= 0x0c,	// unused (Control/Status)
	RxControl		= 0x10,
	RxDescStartAddr		= 0x14,
	rsv1			= 0x18,	// reserved
	RxSts			= 0x1c,	// unused
	IntrStatus		= 0x20,
	IntrMask		= 0x24,
	IntrControl		= 0x28,
	IntrTimer		= 0x2c,	// unused (Interrupt Timer)
	PMControl		= 0x30,	// unused (Power Mgmt Control/Status)
	rsv2			= 0x34,	// reserved
	ROMControl		= 0x38,
	ROMInterface		= 0x3c,
	StationControl		= 0x40,
	GMIIControl		= 0x44,
	GIoCR			= 0x48, // unused (GMAC IO Compensation)
	GIoCtrl			= 0x4c, // unused (GMAC IO Control)
	TxMacControl		= 0x50,
	TxLimit			= 0x54, // unused (Tx MAC Timer/TryLimit)
	RGDelay			= 0x58, // unused (RGMII Tx Internal Delay)
	rsv3			= 0x5c, // reserved
	RxMacControl		= 0x60,
	RxMacAddr		= 0x62,
	RxHashTable		= 0x68,
	// Undocumented		= 0x6c,
	RxWolCtrl		= 0x70,
	RxWolData		= 0x74, // unused (Rx WOL Data Access)
	RxMPSControl		= 0x78,	// unused (Rx MPS Control)
	rsv4			= 0x7c, // reserved
};

enum sis190_register_content {
	/* IntrStatus */
	SoftInt			= 0x40000000,	// unused
	Timeup			= 0x20000000,	// unused
	PauseFrame		= 0x00080000,	// unused
	MagicPacket		= 0x00040000,	// unused
	WakeupFrame		= 0x00020000,	// unused
	LinkChange		= 0x00010000,
	RxQEmpty		= 0x00000080,
	RxQInt			= 0x00000040,
	TxQ1Empty		= 0x00000020,	// unused
	TxQ1Int			= 0x00000010,
	TxQ0Empty		= 0x00000008,	// unused
	TxQ0Int			= 0x00000004,
	RxHalt			= 0x00000002,
	TxHalt			= 0x00000001,

	/* {Rx/Tx}CmdBits */
	CmdReset		= 0x10,
	CmdRxEnb		= 0x08,		// unused
	CmdTxEnb		= 0x01,
	RxBufEmpty		= 0x01,		// unused

	/* Cfg9346Bits */
	Cfg9346_Lock		= 0x00,		// unused
	Cfg9346_Unlock		= 0xc0,		// unused

	/* RxMacControl */
	AcceptErr		= 0x20,		// unused
	AcceptRunt		= 0x10,		// unused
	AcceptBroadcast		= 0x0800,
	AcceptMulticast		= 0x0400,
	AcceptMyPhys		= 0x0200,
	AcceptAllPhys		= 0x0100,

	/* RxConfigBits */
	RxCfgFIFOShift		= 13,
	RxCfgDMAShift		= 8,		// 0x1a in RxControl ?

	/* TxConfigBits */
	TxInterFrameGapShift	= 24,
	TxDMAShift		= 8, /* DMA burst value (0-7) is shift this many bits */

	LinkStatus		= 0x02,		// unused
	FullDup			= 0x01,		// unused

	/* TBICSRBit */
	TBILinkOK		= 0x02000000,	// unused
};

struct TxDesc {
	volatile u32 PSize;
	volatile u32 status;
	volatile u32 addr;
	volatile u32 size;
};

struct RxDesc {
	volatile u32 PSize;
	volatile u32 status;
	volatile u32 addr;
	volatile u32 size;
};

enum _DescStatusBit {
	/* _Desc.status */
	OWNbit		= 0x80000000, // RXOWN/TXOWN
	INTbit		= 0x40000000, // RXINT/TXINT
	CRCbit		= 0x00020000, // CRCOFF/CRCEN
	PADbit		= 0x00010000, // PREADD/PADEN
	/* _Desc.size */
	RingEnd		= 0x80000000,
	/* TxDesc.status */
	LSEN		= 0x08000000, // TSO ? -- FR
	IPCS		= 0x04000000,
	TCPCS		= 0x02000000,
	UDPCS		= 0x01000000,
	BSTEN		= 0x00800000,
	EXTEN		= 0x00400000,
	DEFEN		= 0x00200000,
	BKFEN		= 0x00100000,
	CRSEN		= 0x00080000,
	COLEN		= 0x00040000,
	THOL3		= 0x30000000,
	THOL2		= 0x20000000,
	THOL1		= 0x10000000,
	THOL0		= 0x00000000,

	WND		= 0x00080000,
	TABRT		= 0x00040000,
	FIFO		= 0x00020000,
	LINK		= 0x00010000,
	ColCountMask	= 0x0000ffff,
	/* RxDesc.status */
	IPON		= 0x20000000,
	TCPON		= 0x10000000,
	UDPON		= 0x08000000,
	Wakup		= 0x00400000,
	Magic		= 0x00200000,
	Pause		= 0x00100000,
	DEFbit		= 0x00200000,
	BCAST		= 0x000c0000,
	MCAST		= 0x00080000,
	UCAST		= 0x00040000,
	/* RxDesc.PSize */
	TAGON		= 0x80000000,
	RxDescCountMask	= 0x7f000000, // multi-desc pkt when > 1 ? -- FR
	ABORT		= 0x00800000,
	SHORT		= 0x00400000,
	LIMIT		= 0x00200000,
	MIIER		= 0x00100000,
	OVRUN		= 0x00080000,
	NIBON		= 0x00040000,
	COLON		= 0x00020000,
	CRCOK		= 0x00010000,
	RxSizeMask	= 0x0000ffff
	/*
	* The asic could apparently do vlan, TSO, jumbo (sis191 only) and
	* provide two (unused with Linux) Tx queues. No publicly
	* available documentation alas.
	*/
};

enum sis190_eeprom_access_register_bits {
	EECS	= 0x00000001,	// unused
	EECLK	= 0x00000002,	// unused
	EEDO	= 0x00000008,	// unused
	EEDI	= 0x00000004,	// unused
	EEREQ	= 0x00000080,
	EEROP	= 0x00000200,
	EEWOP	= 0x00000100	// unused
};

/* EEPROM Addresses */
enum sis190_eeprom_address {
	EEPROMSignature	= 0x00,
	EEPROMCLK	= 0x01,	// unused
	EEPROMInfo	= 0x02,
	EEPROMMACAddr	= 0x03
};

enum sis190_feature {
	F_HAS_RGMII	= 1,
	F_PHY_88E1111	= 2,
	F_PHY_BCM5461	= 4
};

struct sis190_private {
	void *mmio_addr;
	struct pci_device *pci_device;
	struct net_device *dev;
	u32 cur_rx;
	u32 cur_tx;
	u32 dirty_rx;
	u32 dirty_tx;
	u32 rx_dma;
	u32 tx_dma;
	struct RxDesc *RxDescRing;
	struct TxDesc *TxDescRing;
	struct io_buffer *Rx_iobuf[NUM_RX_DESC];
	struct io_buffer *Tx_iobuf[NUM_TX_DESC];
	struct mii_if_info mii_if;
	struct list_head first_phy;
	u32 features;
};

struct sis190_phy {
	struct list_head list;
	int phy_id;
	u16 id[2];
	u16 status;
	u8  type;
};

enum sis190_phy_type {
	UNKNOWN	= 0x00,
	HOME	= 0x01,
	LAN	= 0x02,
	MIX	= 0x03
};

static struct mii_chip_info {
	const char *name;
	u16 id[2];
	unsigned int type;
	u32 feature;
} mii_chip_table[] = {
	{ "Atheros PHY",          { 0x004d, 0xd010 }, LAN, 0 },
	{ "Atheros PHY AR8012",   { 0x004d, 0xd020 }, LAN, 0 },
	{ "Broadcom PHY BCM5461", { 0x0020, 0x60c0 }, LAN, F_PHY_BCM5461 },
	{ "Broadcom PHY AC131",   { 0x0143, 0xbc70 }, LAN, 0 },
	{ "Agere PHY ET1101B",    { 0x0282, 0xf010 }, LAN, 0 },
	{ "Marvell PHY 88E1111",  { 0x0141, 0x0cc0 }, LAN, F_PHY_88E1111 },
	{ "Realtek PHY RTL8201",  { 0x0000, 0x8200 }, LAN, 0 },
	{ NULL, { 0x00, 0x00 }, 0, 0 }
};

static const struct {
	const char *name;
} sis_chip_info[] = {
	{ "SiS 190 PCI Fast Ethernet adapter" },
	{ "SiS 191 PCI Gigabit Ethernet adapter" },
};

static void sis190_phy_task(struct sis190_private *tp);
static void sis190_free(struct net_device *dev);
static inline void sis190_init_rxfilter(struct net_device *dev);

#endif
