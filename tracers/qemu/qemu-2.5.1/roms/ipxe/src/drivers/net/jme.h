/*
 * JMicron JMC2x0 series PCIe Ethernet gPXE Device Driver
 *
 * Copyright 2010 Guo-Fu Tseng <cooldavid@cooldavid.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */
FILE_LICENCE ( GPL2_OR_LATER );

#ifndef __JME_H_INCLUDED__
#define __JME_H_INCLUDED__

#define PCI_VENDOR_ID_JMICRON		0x197b
#define PCI_DEVICE_ID_JMICRON_JMC250	0x0250
#define PCI_DEVICE_ID_JMICRON_JMC260	0x0260

/*
 * Extra PCI Configuration space interface
 */
#define PCI_DCSR_MRRS		0x59
#define PCI_DCSR_MRRS_MASK	0x70

enum pci_dcsr_mrrs_vals {
	MRRS_128B	= 0x00,
	MRRS_256B	= 0x10,
	MRRS_512B	= 0x20,
	MRRS_1024B	= 0x30,
	MRRS_2048B	= 0x40,
	MRRS_4096B	= 0x50,
};

/*
 * TX/RX Descriptors
 *
 * TX/RX Ring DESC Count Must be multiple of 16 and <= 1024
 */
#define RING_DESC_ALIGN		16	/* Descriptor alignment */
#define TX_DESC_SIZE		16

struct txdesc {
	union {
		uint8_t		all[16];
		uint32_t	dw[4];
		struct {
			/* DW0 */
			uint16_t	vlan;
			uint8_t		rsv1;
			uint8_t		flags;

			/* DW1 */
			uint16_t	datalen;
			uint16_t	mss;

			/* DW2 */
			uint16_t	pktsize;
			uint16_t	rsv2;

			/* DW3 */
			uint32_t	bufaddr;
		} desc1;
		struct {
			/* DW0 */
			uint16_t	rsv1;
			uint8_t		rsv2;
			uint8_t		flags;

			/* DW1 */
			uint16_t	datalen;
			uint16_t	rsv3;

			/* DW2 */
			uint32_t	bufaddrh;

			/* DW3 */
			uint32_t	bufaddrl;
		} desc2;
		struct {
			/* DW0 */
			uint8_t		ehdrsz;
			uint8_t		rsv1;
			uint8_t		rsv2;
			uint8_t		flags;

			/* DW1 */
			uint16_t	trycnt;
			uint16_t	segcnt;

			/* DW2 */
			uint16_t	pktsz;
			uint16_t	rsv3;

			/* DW3 */
			uint32_t	bufaddrl;
		} descwb;
	};
};

enum jme_txdesc_flags_bits {
	TXFLAG_OWN	= 0x80,
	TXFLAG_INT	= 0x40,
	TXFLAG_64BIT	= 0x20,
	TXFLAG_TCPCS	= 0x10,
	TXFLAG_UDPCS	= 0x08,
	TXFLAG_IPCS	= 0x04,
	TXFLAG_LSEN	= 0x02,
	TXFLAG_TAGON	= 0x01,
};

#define TXDESC_MSS_SHIFT	2
enum jme_txwbdesc_flags_bits {
	TXWBFLAG_OWN	= 0x80,
	TXWBFLAG_INT	= 0x40,
	TXWBFLAG_TMOUT	= 0x20,
	TXWBFLAG_TRYOUT	= 0x10,
	TXWBFLAG_COL	= 0x08,

	TXWBFLAG_ALLERR	= TXWBFLAG_TMOUT |
			  TXWBFLAG_TRYOUT |
			  TXWBFLAG_COL,
};

#define RX_DESC_SIZE		16
#define RX_BUF_DMA_ALIGN	8
#define RX_PREPAD_SIZE		10
#define ETH_CRC_LEN		2
#define RX_VLANHDR_LEN		2
#define RX_EXTRA_LEN		(ETH_HLEN + \
				ETH_CRC_LEN + \
				RX_VLANHDR_LEN + \
				RX_BUF_DMA_ALIGN)
#define FIXED_MTU		1500
#define RX_ALLOC_LEN		(FIXED_MTU + RX_EXTRA_LEN)

struct rxdesc {
	union {
		uint8_t		all[16];
		uint32_t	dw[4];
		struct {
			/* DW0 */
			uint16_t	rsv2;
			uint8_t		rsv1;
			uint8_t		flags;

			/* DW1 */
			uint16_t	datalen;
			uint16_t	wbcpl;

			/* DW2 */
			uint32_t	bufaddrh;

			/* DW3 */
			uint32_t	bufaddrl;
		} desc1;
		struct {
			/* DW0 */
			uint16_t	vlan;
			uint16_t	flags;

			/* DW1 */
			uint16_t	framesize;
			uint8_t		errstat;
			uint8_t		desccnt;

			/* DW2 */
			uint32_t	rsshash;

			/* DW3 */
			uint8_t		hashfun;
			uint8_t		hashtype;
			uint16_t	resrv;
		} descwb;
	};
};

enum jme_rxdesc_flags_bits {
	RXFLAG_OWN	= 0x80,
	RXFLAG_INT	= 0x40,
	RXFLAG_64BIT	= 0x20,
};

enum jme_rxwbdesc_flags_bits {
	RXWBFLAG_OWN		= 0x8000,
	RXWBFLAG_INT		= 0x4000,
	RXWBFLAG_MF		= 0x2000,
	RXWBFLAG_64BIT		= 0x2000,
	RXWBFLAG_TCPON		= 0x1000,
	RXWBFLAG_UDPON		= 0x0800,
	RXWBFLAG_IPCS		= 0x0400,
	RXWBFLAG_TCPCS		= 0x0200,
	RXWBFLAG_UDPCS		= 0x0100,
	RXWBFLAG_TAGON		= 0x0080,
	RXWBFLAG_IPV4		= 0x0040,
	RXWBFLAG_IPV6		= 0x0020,
	RXWBFLAG_PAUSE		= 0x0010,
	RXWBFLAG_MAGIC		= 0x0008,
	RXWBFLAG_WAKEUP		= 0x0004,
	RXWBFLAG_DEST		= 0x0003,
	RXWBFLAG_DEST_UNI	= 0x0001,
	RXWBFLAG_DEST_MUL	= 0x0002,
	RXWBFLAG_DEST_BRO	= 0x0003,
};

enum jme_rxwbdesc_desccnt_mask {
	RXWBDCNT_WBCPL	= 0x80,
	RXWBDCNT_DCNT	= 0x7F,
};

enum jme_rxwbdesc_errstat_bits {
	RXWBERR_LIMIT	= 0x80,
	RXWBERR_MIIER	= 0x40,
	RXWBERR_NIBON	= 0x20,
	RXWBERR_COLON	= 0x10,
	RXWBERR_ABORT	= 0x08,
	RXWBERR_SHORT	= 0x04,
	RXWBERR_OVERUN	= 0x02,
	RXWBERR_CRCERR	= 0x01,
	RXWBERR_ALLERR	= 0xFF,
};

/*
 * The structure holding buffer information and ring descriptors all together.
 */
struct jme_ring {
	void *desc;		/* pointer to ring memory  */
	unsigned long dma;	/* phys address for ring dma */

	/* Buffer information corresponding to each descriptor */
	struct io_buffer **bufinf;

	int next_to_clean;
	int next_to_fill;
	int next_to_use;
	int nr_free;
};

/*
 * Jmac Adapter Private data
 */
struct jme_adapter {
	void			*regs;
	struct mii_if_info	mii_if;
	struct pci_device	*pdev;
	unsigned int		fpgaver;
	unsigned int		chiprev;
	uint32_t		reg_ghc;
	uint32_t		reg_txcs;
	uint32_t		reg_rxcs;
	uint32_t		reg_rxmcs;
	uint32_t		phylink;
	struct jme_ring		rxring;
	uint32_t		rx_ring_size;
	uint32_t		rx_ring_mask;
	struct jme_ring		txring;
	uint32_t		tx_ring_size;
	uint32_t		tx_ring_mask;
};

/*
 * I/O Resters
 */
enum jme_iomap_regs_value {
	JME_REGS_SIZE	= 0x1000,
};

enum jme_iomap_offsets {
	JME_MAC		= 0x0000,
	JME_PHY		= 0x0400,
	JME_MISC	= 0x0800,
	JME_RSS		= 0x0C00,
};

enum jme_iomap_lens {
	JME_MAC_LEN	= 0x80,
	JME_PHY_LEN	= 0x58,
	JME_MISC_LEN	= 0x98,
	JME_RSS_LEN	= 0xFF,
};

enum jme_iomap_regs {
	JME_TXCS	= JME_MAC | 0x00, /* Transmit Control and Status */
	JME_TXDBA_LO	= JME_MAC | 0x04, /* Transmit Queue Desc Base Addr */
	JME_TXDBA_HI	= JME_MAC | 0x08, /* Transmit Queue Desc Base Addr */
	JME_TXQDC	= JME_MAC | 0x0C, /* Transmit Queue Desc Count */
	JME_TXNDA	= JME_MAC | 0x10, /* Transmit Queue Next Desc Addr */
	JME_TXMCS	= JME_MAC | 0x14, /* Transmit MAC Control Status */
	JME_TXPFC	= JME_MAC | 0x18, /* Transmit Pause Frame Control */
	JME_TXTRHD	= JME_MAC | 0x1C, /* Transmit Timer/Retry@Half-Dup */

	JME_RXCS	= JME_MAC | 0x20, /* Receive Control and Status */
	JME_RXDBA_LO	= JME_MAC | 0x24, /* Receive Queue Desc Base Addr */
	JME_RXDBA_HI	= JME_MAC | 0x28, /* Receive Queue Desc Base Addr */
	JME_RXQDC	= JME_MAC | 0x2C, /* Receive Queue Desc Count */
	JME_RXNDA	= JME_MAC | 0x30, /* Receive Queue Next Desc Addr */
	JME_RXMCS	= JME_MAC | 0x34, /* Receive MAC Control Status */
	JME_RXUMA_LO	= JME_MAC | 0x38, /* Receive Unicast MAC Address */
	JME_RXUMA_HI	= JME_MAC | 0x3C, /* Receive Unicast MAC Address */
	JME_RXMCHT_LO	= JME_MAC | 0x40, /* Recv Multicast Addr HashTable */
	JME_RXMCHT_HI	= JME_MAC | 0x44, /* Recv Multicast Addr HashTable */
	JME_WFODP	= JME_MAC | 0x48, /* Wakeup Frame Output Data Port */
	JME_WFOI	= JME_MAC | 0x4C, /* Wakeup Frame Output Interface */

	JME_SMI		= JME_MAC | 0x50, /* Station Management Interface */
	JME_GHC		= JME_MAC | 0x54, /* Global Host Control */
	JME_PMCS	= JME_MAC | 0x60, /* Power Management Control/Stat */


	JME_PHY_CS	= JME_PHY | 0x28, /* PHY Ctrl and Status Register */
	JME_PHY_LINK	= JME_PHY | 0x30, /* PHY Link Status Register */
	JME_SMBCSR	= JME_PHY | 0x40, /* SMB Control and Status */
	JME_SMBINTF	= JME_PHY | 0x44, /* SMB Interface */


	JME_TMCSR	= JME_MISC | 0x00, /* Timer Control/Status Register */
	JME_GPREG0	= JME_MISC | 0x08, /* General purpose REG-0 */
	JME_GPREG1	= JME_MISC | 0x0C, /* General purpose REG-1 */
	JME_IEVE	= JME_MISC | 0x20, /* Interrupt Event Status */
	JME_IREQ	= JME_MISC | 0x24, /* Intr Req Status(For Debug) */
	JME_IENS	= JME_MISC | 0x28, /* Intr Enable - Setting Port */
	JME_IENC	= JME_MISC | 0x2C, /* Interrupt Enable - Clear Port */
	JME_PCCRX0	= JME_MISC | 0x30, /* PCC Control for RX Queue 0 */
	JME_PCCTX	= JME_MISC | 0x40, /* PCC Control for TX Queues */
	JME_CHIPMODE	= JME_MISC | 0x44, /* Identify FPGA Version */
	JME_SHBA_HI	= JME_MISC | 0x48, /* Shadow Register Base HI */
	JME_SHBA_LO	= JME_MISC | 0x4C, /* Shadow Register Base LO */
	JME_TIMER1	= JME_MISC | 0x70, /* Timer1 */
	JME_TIMER2	= JME_MISC | 0x74, /* Timer2 */
	JME_APMC	= JME_MISC | 0x7C, /* Aggressive Power Mode Control */
	JME_PCCSRX0	= JME_MISC | 0x80, /* PCC Status of RX0 */
};

/*
 * TX Control/Status Bits
 */
enum jme_txcs_bits {
	TXCS_QUEUE7S	= 0x00008000,
	TXCS_QUEUE6S	= 0x00004000,
	TXCS_QUEUE5S	= 0x00002000,
	TXCS_QUEUE4S	= 0x00001000,
	TXCS_QUEUE3S	= 0x00000800,
	TXCS_QUEUE2S	= 0x00000400,
	TXCS_QUEUE1S	= 0x00000200,
	TXCS_QUEUE0S	= 0x00000100,
	TXCS_FIFOTH	= 0x000000C0,
	TXCS_DMASIZE	= 0x00000030,
	TXCS_BURST	= 0x00000004,
	TXCS_ENABLE	= 0x00000001,
};

enum jme_txcs_value {
	TXCS_FIFOTH_16QW	= 0x000000C0,
	TXCS_FIFOTH_12QW	= 0x00000080,
	TXCS_FIFOTH_8QW		= 0x00000040,
	TXCS_FIFOTH_4QW		= 0x00000000,

	TXCS_DMASIZE_64B	= 0x00000000,
	TXCS_DMASIZE_128B	= 0x00000010,
	TXCS_DMASIZE_256B	= 0x00000020,
	TXCS_DMASIZE_512B	= 0x00000030,

	TXCS_SELECT_QUEUE0	= 0x00000000,
	TXCS_SELECT_QUEUE1	= 0x00010000,
	TXCS_SELECT_QUEUE2	= 0x00020000,
	TXCS_SELECT_QUEUE3	= 0x00030000,
	TXCS_SELECT_QUEUE4	= 0x00040000,
	TXCS_SELECT_QUEUE5	= 0x00050000,
	TXCS_SELECT_QUEUE6	= 0x00060000,
	TXCS_SELECT_QUEUE7	= 0x00070000,

	TXCS_DEFAULT		= TXCS_FIFOTH_4QW |
				  TXCS_BURST,
};

#define JME_TX_DISABLE_TIMEOUT 10 /* 10 msec */

/*
 * TX MAC Control/Status Bits
 */
enum jme_txmcs_bit_masks {
	TXMCS_IFG2		= 0xC0000000,
	TXMCS_IFG1		= 0x30000000,
	TXMCS_TTHOLD		= 0x00000300,
	TXMCS_FBURST		= 0x00000080,
	TXMCS_CARRIEREXT	= 0x00000040,
	TXMCS_DEFER		= 0x00000020,
	TXMCS_BACKOFF		= 0x00000010,
	TXMCS_CARRIERSENSE	= 0x00000008,
	TXMCS_COLLISION		= 0x00000004,
	TXMCS_CRC		= 0x00000002,
	TXMCS_PADDING		= 0x00000001,
};

enum jme_txmcs_values {
	TXMCS_IFG2_6_4		= 0x00000000,
	TXMCS_IFG2_8_5		= 0x40000000,
	TXMCS_IFG2_10_6		= 0x80000000,
	TXMCS_IFG2_12_7		= 0xC0000000,

	TXMCS_IFG1_8_4		= 0x00000000,
	TXMCS_IFG1_12_6		= 0x10000000,
	TXMCS_IFG1_16_8		= 0x20000000,
	TXMCS_IFG1_20_10	= 0x30000000,

	TXMCS_TTHOLD_1_8	= 0x00000000,
	TXMCS_TTHOLD_1_4	= 0x00000100,
	TXMCS_TTHOLD_1_2	= 0x00000200,
	TXMCS_TTHOLD_FULL	= 0x00000300,

	TXMCS_DEFAULT		= TXMCS_IFG2_8_5 |
				  TXMCS_IFG1_16_8 |
				  TXMCS_TTHOLD_FULL |
				  TXMCS_DEFER |
				  TXMCS_CRC |
				  TXMCS_PADDING,
};

enum jme_txpfc_bits_masks {
	TXPFC_VLAN_TAG		= 0xFFFF0000,
	TXPFC_VLAN_EN		= 0x00008000,
	TXPFC_PF_EN		= 0x00000001,
};

enum jme_txtrhd_bits_masks {
	TXTRHD_TXPEN		= 0x80000000,
	TXTRHD_TXP		= 0x7FFFFF00,
	TXTRHD_TXREN		= 0x00000080,
	TXTRHD_TXRL		= 0x0000007F,
};

enum jme_txtrhd_shifts {
	TXTRHD_TXP_SHIFT	= 8,
	TXTRHD_TXRL_SHIFT	= 0,
};

/*
 * RX Control/Status Bits
 */
enum jme_rxcs_bit_masks {
	/* FIFO full threshold for transmitting Tx Pause Packet */
	RXCS_FIFOTHTP	= 0x30000000,
	/* FIFO threshold for processing next packet */
	RXCS_FIFOTHNP	= 0x0C000000,
	RXCS_DMAREQSZ	= 0x03000000, /* DMA Request Size */
	RXCS_QUEUESEL	= 0x00030000, /* Queue selection */
	RXCS_RETRYGAP	= 0x0000F000, /* RX Desc full retry gap */
	RXCS_RETRYCNT	= 0x00000F00, /* RX Desc full retry counter */
	RXCS_WAKEUP	= 0x00000040, /* Enable receive wakeup packet */
	RXCS_MAGIC	= 0x00000020, /* Enable receive magic packet */
	RXCS_SHORT	= 0x00000010, /* Enable receive short packet */
	RXCS_ABORT	= 0x00000008, /* Enable receive errorr packet */
	RXCS_QST	= 0x00000004, /* Receive queue start */
	RXCS_SUSPEND	= 0x00000002,
	RXCS_ENABLE	= 0x00000001,
};

enum jme_rxcs_values {
	RXCS_FIFOTHTP_16T	= 0x00000000,
	RXCS_FIFOTHTP_32T	= 0x10000000,
	RXCS_FIFOTHTP_64T	= 0x20000000,
	RXCS_FIFOTHTP_128T	= 0x30000000,

	RXCS_FIFOTHNP_16QW	= 0x00000000,
	RXCS_FIFOTHNP_32QW	= 0x04000000,
	RXCS_FIFOTHNP_64QW	= 0x08000000,
	RXCS_FIFOTHNP_128QW	= 0x0C000000,

	RXCS_DMAREQSZ_16B	= 0x00000000,
	RXCS_DMAREQSZ_32B	= 0x01000000,
	RXCS_DMAREQSZ_64B	= 0x02000000,
	RXCS_DMAREQSZ_128B	= 0x03000000,

	RXCS_QUEUESEL_Q0	= 0x00000000,
	RXCS_QUEUESEL_Q1	= 0x00010000,
	RXCS_QUEUESEL_Q2	= 0x00020000,
	RXCS_QUEUESEL_Q3	= 0x00030000,

	RXCS_RETRYGAP_256ns	= 0x00000000,
	RXCS_RETRYGAP_512ns	= 0x00001000,
	RXCS_RETRYGAP_1024ns	= 0x00002000,
	RXCS_RETRYGAP_2048ns	= 0x00003000,
	RXCS_RETRYGAP_4096ns	= 0x00004000,
	RXCS_RETRYGAP_8192ns	= 0x00005000,
	RXCS_RETRYGAP_16384ns	= 0x00006000,
	RXCS_RETRYGAP_32768ns	= 0x00007000,

	RXCS_RETRYCNT_0		= 0x00000000,
	RXCS_RETRYCNT_4		= 0x00000100,
	RXCS_RETRYCNT_8		= 0x00000200,
	RXCS_RETRYCNT_12	= 0x00000300,
	RXCS_RETRYCNT_16	= 0x00000400,
	RXCS_RETRYCNT_20	= 0x00000500,
	RXCS_RETRYCNT_24	= 0x00000600,
	RXCS_RETRYCNT_28	= 0x00000700,
	RXCS_RETRYCNT_32	= 0x00000800,
	RXCS_RETRYCNT_36	= 0x00000900,
	RXCS_RETRYCNT_40	= 0x00000A00,
	RXCS_RETRYCNT_44	= 0x00000B00,
	RXCS_RETRYCNT_48	= 0x00000C00,
	RXCS_RETRYCNT_52	= 0x00000D00,
	RXCS_RETRYCNT_56	= 0x00000E00,
	RXCS_RETRYCNT_60	= 0x00000F00,

	RXCS_DEFAULT		= RXCS_FIFOTHTP_128T |
				  RXCS_FIFOTHNP_128QW |
				  RXCS_DMAREQSZ_128B |
				  RXCS_RETRYGAP_256ns |
				  RXCS_RETRYCNT_32,
};

#define JME_RX_DISABLE_TIMEOUT 10 /* 10 msec */

/*
 * RX MAC Control/Status Bits
 */
enum jme_rxmcs_bits {
	RXMCS_ALLFRAME		= 0x00000800,
	RXMCS_BRDFRAME		= 0x00000400,
	RXMCS_MULFRAME		= 0x00000200,
	RXMCS_UNIFRAME		= 0x00000100,
	RXMCS_ALLMULFRAME	= 0x00000080,
	RXMCS_MULFILTERED	= 0x00000040,
	RXMCS_RXCOLLDEC		= 0x00000020,
	RXMCS_FLOWCTRL		= 0x00000008,
	RXMCS_VTAGRM		= 0x00000004,
	RXMCS_PREPAD		= 0x00000002,
	RXMCS_CHECKSUM		= 0x00000001,

	RXMCS_DEFAULT		= RXMCS_VTAGRM |
				  RXMCS_FLOWCTRL |
				  RXMCS_CHECKSUM,
};

/*
 * Wakeup Frame setup interface registers
 */
#define WAKEUP_FRAME_NR	8
#define WAKEUP_FRAME_MASK_DWNR	4

enum jme_wfoi_bit_masks {
	WFOI_MASK_SEL		= 0x00000070,
	WFOI_CRC_SEL		= 0x00000008,
	WFOI_FRAME_SEL		= 0x00000007,
};

enum jme_wfoi_shifts {
	WFOI_MASK_SHIFT		= 4,
};

/*
 * SMI Related definitions
 */
enum jme_smi_bit_mask {
	SMI_DATA_MASK		= 0xFFFF0000,
	SMI_REG_ADDR_MASK	= 0x0000F800,
	SMI_PHY_ADDR_MASK	= 0x000007C0,
	SMI_OP_WRITE		= 0x00000020,
	/* Set to 1, after req done it'll be cleared to 0 */
	SMI_OP_REQ		= 0x00000010,
	SMI_OP_MDIO		= 0x00000008, /* Software assess In/Out */
	SMI_OP_MDOE		= 0x00000004, /* Software Output Enable */
	SMI_OP_MDC		= 0x00000002, /* Software CLK Control */
	SMI_OP_MDEN		= 0x00000001, /* Software access Enable */
};

enum jme_smi_bit_shift {
	SMI_DATA_SHIFT		= 16,
	SMI_REG_ADDR_SHIFT	= 11,
	SMI_PHY_ADDR_SHIFT	= 6,
};

static inline uint32_t smi_reg_addr(int x)
{
	return (x << SMI_REG_ADDR_SHIFT) & SMI_REG_ADDR_MASK;
}

static inline uint32_t smi_phy_addr(int x)
{
	return (x << SMI_PHY_ADDR_SHIFT) & SMI_PHY_ADDR_MASK;
}

#define JME_PHY_TIMEOUT 100 /* 100 msec */
#define JME_PHY_REG_NR 32

/*
 * Global Host Control
 */
enum jme_ghc_bit_mask {
	GHC_SWRST		= 0x40000000,
	GHC_DPX			= 0x00000040,
	GHC_SPEED		= 0x00000030,
	GHC_LINK_POLL		= 0x00000001,
};

enum jme_ghc_speed_val {
	GHC_SPEED_10M		= 0x00000010,
	GHC_SPEED_100M		= 0x00000020,
	GHC_SPEED_1000M		= 0x00000030,
};

enum jme_ghc_to_clk {
	GHC_TO_CLK_OFF		= 0x00000000,
	GHC_TO_CLK_GPHY		= 0x00400000,
	GHC_TO_CLK_PCIE		= 0x00800000,
	GHC_TO_CLK_INVALID	= 0x00C00000,
};

enum jme_ghc_txmac_clk {
	GHC_TXMAC_CLK_OFF	= 0x00000000,
	GHC_TXMAC_CLK_GPHY	= 0x00100000,
	GHC_TXMAC_CLK_PCIE	= 0x00200000,
	GHC_TXMAC_CLK_INVALID	= 0x00300000,
};

/*
 * Power management control and status register
 */
enum jme_pmcs_bit_masks {
	PMCS_WF7DET	= 0x80000000,
	PMCS_WF6DET	= 0x40000000,
	PMCS_WF5DET	= 0x20000000,
	PMCS_WF4DET	= 0x10000000,
	PMCS_WF3DET	= 0x08000000,
	PMCS_WF2DET	= 0x04000000,
	PMCS_WF1DET	= 0x02000000,
	PMCS_WF0DET	= 0x01000000,
	PMCS_LFDET	= 0x00040000,
	PMCS_LRDET	= 0x00020000,
	PMCS_MFDET	= 0x00010000,
	PMCS_WF7EN	= 0x00008000,
	PMCS_WF6EN	= 0x00004000,
	PMCS_WF5EN	= 0x00002000,
	PMCS_WF4EN	= 0x00001000,
	PMCS_WF3EN	= 0x00000800,
	PMCS_WF2EN	= 0x00000400,
	PMCS_WF1EN	= 0x00000200,
	PMCS_WF0EN	= 0x00000100,
	PMCS_LFEN	= 0x00000004,
	PMCS_LREN	= 0x00000002,
	PMCS_MFEN	= 0x00000001,
};

/*
 * Giga PHY Status Registers
 */
enum jme_phy_link_bit_mask {
	PHY_LINK_SPEED_MASK		= 0x0000C000,
	PHY_LINK_DUPLEX			= 0x00002000,
	PHY_LINK_SPEEDDPU_RESOLVED	= 0x00000800,
	PHY_LINK_UP			= 0x00000400,
	PHY_LINK_AUTONEG_COMPLETE	= 0x00000200,
	PHY_LINK_MDI_STAT		= 0x00000040,
};

enum jme_phy_link_speed_val {
	PHY_LINK_SPEED_10M		= 0x00000000,
	PHY_LINK_SPEED_100M		= 0x00004000,
	PHY_LINK_SPEED_1000M		= 0x00008000,
};

#define JME_SPDRSV_TIMEOUT	500	/* 500 us */

/*
 * SMB Control and Status
 */
enum jme_smbcsr_bit_mask {
	SMBCSR_CNACK	= 0x00020000,
	SMBCSR_RELOAD	= 0x00010000,
	SMBCSR_EEPROMD	= 0x00000020,
	SMBCSR_INITDONE	= 0x00000010,
	SMBCSR_BUSY	= 0x0000000F,
};

enum jme_smbintf_bit_mask {
	SMBINTF_HWDATR	= 0xFF000000,
	SMBINTF_HWDATW	= 0x00FF0000,
	SMBINTF_HWADDR	= 0x0000FF00,
	SMBINTF_HWRWN	= 0x00000020,
	SMBINTF_HWCMD	= 0x00000010,
	SMBINTF_FASTM	= 0x00000008,
	SMBINTF_GPIOSCL	= 0x00000004,
	SMBINTF_GPIOSDA	= 0x00000002,
	SMBINTF_GPIOEN	= 0x00000001,
};

enum jme_smbintf_vals {
	SMBINTF_HWRWN_READ	= 0x00000020,
	SMBINTF_HWRWN_WRITE	= 0x00000000,
};

enum jme_smbintf_shifts {
	SMBINTF_HWDATR_SHIFT	= 24,
	SMBINTF_HWDATW_SHIFT	= 16,
	SMBINTF_HWADDR_SHIFT	= 8,
};

#define JME_EEPROM_RELOAD_TIMEOUT 2000 /* 2000 msec */
#define JME_SMB_BUSY_TIMEOUT 20 /* 20 msec */
#define JME_SMB_LEN 256
#define JME_EEPROM_MAGIC 0x250

/*
 * Timer Control/Status Register
 */
enum jme_tmcsr_bit_masks {
	TMCSR_SWIT	= 0x80000000,
	TMCSR_EN	= 0x01000000,
	TMCSR_CNT	= 0x00FFFFFF,
};

/*
 * General Purpose REG-0
 */
enum jme_gpreg0_masks {
	GPREG0_DISSH		= 0xFF000000,
	GPREG0_PCIRLMT		= 0x00300000,
	GPREG0_PCCNOMUTCLR	= 0x00040000,
	GPREG0_LNKINTPOLL	= 0x00001000,
	GPREG0_PCCTMR		= 0x00000300,
	GPREG0_PHYADDR		= 0x0000001F,
};

enum jme_gpreg0_vals {
	GPREG0_DISSH_DW7	= 0x80000000,
	GPREG0_DISSH_DW6	= 0x40000000,
	GPREG0_DISSH_DW5	= 0x20000000,
	GPREG0_DISSH_DW4	= 0x10000000,
	GPREG0_DISSH_DW3	= 0x08000000,
	GPREG0_DISSH_DW2	= 0x04000000,
	GPREG0_DISSH_DW1	= 0x02000000,
	GPREG0_DISSH_DW0	= 0x01000000,
	GPREG0_DISSH_ALL	= 0xFF000000,

	GPREG0_PCIRLMT_8	= 0x00000000,
	GPREG0_PCIRLMT_6	= 0x00100000,
	GPREG0_PCIRLMT_5	= 0x00200000,
	GPREG0_PCIRLMT_4	= 0x00300000,

	GPREG0_PCCTMR_16ns	= 0x00000000,
	GPREG0_PCCTMR_256ns	= 0x00000100,
	GPREG0_PCCTMR_1us	= 0x00000200,
	GPREG0_PCCTMR_1ms	= 0x00000300,

	GPREG0_PHYADDR_1	= 0x00000001,

	GPREG0_DEFAULT		= GPREG0_DISSH_ALL |
				  GPREG0_PCIRLMT_4 |
				  GPREG0_PCCTMR_1us |
				  GPREG0_PHYADDR_1,
};

/*
 * General Purpose REG-1
 * Note: All theses bits defined here are for
 *       Chip mode revision 0x11 only
 */
enum jme_gpreg1_masks {
	GPREG1_INTRDELAYUNIT	= 0x00000018,
	GPREG1_INTRDELAYENABLE	= 0x00000007,
};

enum jme_gpreg1_vals {
	GPREG1_RSSPATCH		= 0x00000040,
	GPREG1_HALFMODEPATCH	= 0x00000020,

	GPREG1_INTDLYUNIT_16NS	= 0x00000000,
	GPREG1_INTDLYUNIT_256NS	= 0x00000008,
	GPREG1_INTDLYUNIT_1US	= 0x00000010,
	GPREG1_INTDLYUNIT_16US	= 0x00000018,

	GPREG1_INTDLYEN_1U	= 0x00000001,
	GPREG1_INTDLYEN_2U	= 0x00000002,
	GPREG1_INTDLYEN_3U	= 0x00000003,
	GPREG1_INTDLYEN_4U	= 0x00000004,
	GPREG1_INTDLYEN_5U	= 0x00000005,
	GPREG1_INTDLYEN_6U	= 0x00000006,
	GPREG1_INTDLYEN_7U	= 0x00000007,

	GPREG1_DEFAULT		= 0x00000000,
};

/*
 * Interrupt Status Bits
 */
enum jme_interrupt_bits {
	INTR_SWINTR	= 0x80000000,
	INTR_TMINTR	= 0x40000000,
	INTR_LINKCH	= 0x20000000,
	INTR_PAUSERCV	= 0x10000000,
	INTR_MAGICRCV	= 0x08000000,
	INTR_WAKERCV	= 0x04000000,
	INTR_PCCRX0TO	= 0x02000000,
	INTR_PCCRX1TO	= 0x01000000,
	INTR_PCCRX2TO	= 0x00800000,
	INTR_PCCRX3TO	= 0x00400000,
	INTR_PCCTXTO	= 0x00200000,
	INTR_PCCRX0	= 0x00100000,
	INTR_PCCRX1	= 0x00080000,
	INTR_PCCRX2	= 0x00040000,
	INTR_PCCRX3	= 0x00020000,
	INTR_PCCTX	= 0x00010000,
	INTR_RX3EMP	= 0x00008000,
	INTR_RX2EMP	= 0x00004000,
	INTR_RX1EMP	= 0x00002000,
	INTR_RX0EMP	= 0x00001000,
	INTR_RX3	= 0x00000800,
	INTR_RX2	= 0x00000400,
	INTR_RX1	= 0x00000200,
	INTR_RX0	= 0x00000100,
	INTR_TX7	= 0x00000080,
	INTR_TX6	= 0x00000040,
	INTR_TX5	= 0x00000020,
	INTR_TX4	= 0x00000010,
	INTR_TX3	= 0x00000008,
	INTR_TX2	= 0x00000004,
	INTR_TX1	= 0x00000002,
	INTR_TX0	= 0x00000001,
};

static const uint32_t INTR_ENABLE = INTR_LINKCH |
				    INTR_RX0EMP |
				    INTR_RX0 |
				    INTR_TX0;

/*
 * PCC Control Registers
 */
enum jme_pccrx_masks {
	PCCRXTO_MASK	= 0xFFFF0000,
	PCCRX_MASK	= 0x0000FF00,
};

enum jme_pcctx_masks {
	PCCTXTO_MASK	= 0xFFFF0000,
	PCCTX_MASK	= 0x0000FF00,
	PCCTX_QS_MASK	= 0x000000FF,
};

enum jme_pccrx_shifts {
	PCCRXTO_SHIFT	= 16,
	PCCRX_SHIFT	= 8,
};

enum jme_pcctx_shifts {
	PCCTXTO_SHIFT	= 16,
	PCCTX_SHIFT	= 8,
};

enum jme_pcctx_bits {
	PCCTXQ0_EN	= 0x00000001,
	PCCTXQ1_EN	= 0x00000002,
	PCCTXQ2_EN	= 0x00000004,
	PCCTXQ3_EN	= 0x00000008,
	PCCTXQ4_EN	= 0x00000010,
	PCCTXQ5_EN	= 0x00000020,
	PCCTXQ6_EN	= 0x00000040,
	PCCTXQ7_EN	= 0x00000080,
};

/*
 * Chip Mode Register
 */
enum jme_chipmode_bit_masks {
	CM_FPGAVER_MASK		= 0xFFFF0000,
	CM_CHIPREV_MASK		= 0x0000FF00,
	CM_CHIPMODE_MASK	= 0x0000000F,
};

enum jme_chipmode_shifts {
	CM_FPGAVER_SHIFT	= 16,
	CM_CHIPREV_SHIFT	= 8,
};

/*
 * Workaround
 */
static inline int is_buggy250(unsigned short device, unsigned int chiprev)
{
	return device == PCI_DEVICE_ID_JMICRON_JMC250 && chiprev == 0x11;
}

/*
 * Read/Write I/O Registers
 */
static inline uint32_t jread32(struct jme_adapter *jme, uint32_t reg)
{
	return readl(jme->regs + reg);
}

static inline void jwrite32(struct jme_adapter *jme, uint32_t reg, uint32_t val)
{
	writel(val, jme->regs + reg);
}

static void jwrite32f(struct jme_adapter *jme, uint32_t reg, uint32_t val)
{
	/*
	 * Read after write should cause flush
	 */
	writel(val, jme->regs + reg);
	readl(jme->regs + reg);
}

#endif
