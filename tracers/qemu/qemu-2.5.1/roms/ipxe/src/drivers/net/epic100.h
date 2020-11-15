#ifndef	_EPIC100_H_
# define _EPIC100_H_

FILE_LICENCE ( GPL2_OR_LATER );

#ifndef	PCI_VENDOR_SMC
# define PCI_VENDOR_SMC		0x10B8
#endif

#ifndef	PCI_DEVICE_SMC_EPIC100
# define PCI_DEVICE_SMC_EPIC100	0x0005
#endif

#define PCI_DEVICE_ID_NONE	0xFFFF

/* Offsets to registers (using SMC names). */
enum epic100_registers {
    COMMAND= 0,		/* Control Register */
    INTSTAT= 4,		/* Interrupt Status */
    INTMASK= 8,		/* Interrupt Mask */
    GENCTL = 0x0C,	/* General Control */
    NVCTL  = 0x10,	/* Non Volatile Control */
    EECTL  = 0x14,	/* EEPROM Control  */
    TEST   = 0x1C,	/* Test register: marked as reserved (see in source code) */
    CRCCNT = 0x20,	/* CRC Error Counter */
    ALICNT = 0x24,	/* Frame Alignment Error Counter */
    MPCNT  = 0x28,	/* Missed Packet Counter */
    MMCTL  = 0x30,	/* MII Management Interface Control */
    MMDATA = 0x34,	/* MII Management Interface Data */
    MIICFG = 0x38,	/* MII Configuration */
    IPG    = 0x3C,	/* InterPacket Gap */
    LAN0   = 0x40,	/* MAC address. (0x40-0x48) */
    IDCHK  = 0x4C,	/* BoardID/ Checksum */
    MC0    = 0x50,	/* Multicast filter table. (0x50-0x5c) */
    RXCON  = 0x60,	/* Receive Control */
    TXCON  = 0x70,	/* Transmit Control */
    TXSTAT = 0x74,	/* Transmit Status */
    PRCDAR = 0x84,	/* PCI Receive Current Descriptor Address */
    PRSTAT = 0xA4,	/* PCI Receive DMA Status */
    PRCPTHR= 0xB0,	/* PCI Receive Copy Threshold */
    PTCDAR = 0xC4,	/* PCI Transmit Current Descriptor Address */
    ETHTHR = 0xDC	/* Early Transmit Threshold */
};

/* Command register (CR_) bits */
#define CR_STOP_RX		(0x00000001)
#define CR_START_RX		(0x00000002)
#define CR_QUEUE_TX		(0x00000004)
#define CR_QUEUE_RX		(0x00000008)
#define CR_NEXTFRAME		(0x00000010)
#define CR_STOP_TX_DMA		(0x00000020)
#define CR_STOP_RX_DMA		(0x00000040)
#define CR_TX_UGO		(0x00000080)

/* Interrupt register bits. NI means No Interrupt generated */

#define	INTR_RX_THR_STA		(0x00400000)	/* rx copy threshold status NI */
#define	INTR_RX_BUFF_EMPTY	(0x00200000)	/* rx buffers empty. NI */
#define	INTR_TX_IN_PROG		(0x00100000)	/* tx copy in progess. NI */
#define	INTR_RX_IN_PROG		(0x00080000)	/* rx copy in progress. NI */
#define	INTR_TXIDLE		(0x00040000)	/* tx idle. NI */
#define INTR_RXIDLE		(0x00020000)	/* rx idle. NI */
#define INTR_INTR_ACTIVE	(0x00010000)	/* Interrupt active. NI */
#define INTR_RX_STATUS_OK	(0x00008000)	/* rx status valid. NI */
#define INTR_PCI_TGT_ABT	(0x00004000)	/* PCI Target abort */
#define INTR_PCI_MASTER_ABT	(0x00002000)	/* PCI Master abort */
#define INTR_PCI_PARITY_ERR	(0x00001000)	/* PCI address parity error */
#define INTR_PCI_DATA_ERR	(0x00000800)	/* PCI data parity error */
#define INTR_RX_THR_CROSSED	(0x00000400)	/* rx copy threshold crossed */
#define INTR_CNTFULL		(0x00000200)	/* Counter overflow */
#define INTR_TXUNDERRUN		(0x00000100)	/* tx underrun. */
#define INTR_TXEMPTY		(0x00000080)	/* tx queue empty */
#define INTR_TX_CH_COMPLETE	(0x00000040)	/* tx chain complete */
#define INTR_TXDONE		(0x00000020)	/* tx complete (w or w/o err) */
#define INTR_RXERROR		(0x00000010)	/* rx error (CRC) */
#define INTR_RXOVERFLOW		(0x00000008)	/* rx buffer overflow */
#define INTR_RX_QUEUE_EMPTY	(0x00000004)	/* rx queue empty. */
#define INTR_RXHEADER		(0x00000002)	/* header copy complete */
#define INTR_RXDONE		(0x00000001)	/* Receive copy complete */

#define INTR_CLEARINTR		(0x00007FFF)
#define INTR_VALIDBITS		(0x007FFFFF)
#define INTR_DISABLE		(0x00000000)
#define INTR_CLEARERRS		(0x00007F18)
#define INTR_ABNINTR		(INTR_CNTFULL | INTR_TXUNDERRUN | INTR_RXOVERFLOW)

/* General Control (GC_) bits */

#define GC_SOFT_RESET		(0x00000001)
#define GC_INTR_ENABLE		(0x00000002)
#define GC_SOFT_INTR		(0x00000004)
#define GC_POWER_DOWN		(0x00000008)
#define GC_ONE_COPY		(0x00000010)
#define GC_BIG_ENDIAN		(0x00000020)
#define GC_RX_PREEMPT_TX	(0x00000040)
#define GC_TX_PREEMPT_RX	(0x00000080)

/*
 * Receive FIFO Threshold values
 * Control the level at which the  PCI burst state machine
 * begins to empty the receive FIFO. Possible values: 0-3
 *
 * 0 => 32, 1 => 64, 2 => 96 3 => 128 bytes.
 */
#define GC_RX_FIFO_THR_32	(0x00000000)
#define GC_RX_FIFO_THR_64	(0x00000100)
#define GC_RX_FIFO_THR_96	(0x00000200)
#define GC_RX_FIFO_THR_128	(0x00000300)

/* Memory Read Control (MRC_) values */
#define GC_MRC_MEM_READ		(0x00000000)
#define GC_MRC_READ_MULT	(0x00000400)
#define GC_MRC_READ_LINE	(0x00000800)

#define GC_SOFTBIT0		(0x00001000)
#define GC_SOFTBIT1		(0x00002000)
#define GC_RESET_PHY		(0x00004000)

/* Definitions of the Receive Control (RC_) register bits */

#define RC_SAVE_ERRORED_PKT	(0x00000001)
#define RC_SAVE_RUNT_FRAMES	(0x00000002)
#define RC_RCV_BROADCAST	(0x00000004)
#define RC_RCV_MULTICAST	(0x00000008)
#define RC_RCV_INVERSE_PKT	(0x00000010)
#define RC_PROMISCUOUS_MODE	(0x00000020)
#define RC_MONITOR_MODE		(0x00000040)
#define RC_EARLY_RCV_ENABLE	(0x00000080)

/* description of the rx descriptors control bits */
#define RD_FRAGLIST		(0x0001)	/* Desc points to a fragment list */
#define RD_LLFORM		(0x0002)	/* Frag list format */
#define RD_HDR_CPY		(0x0004)	/* Desc used for header copy */

/* Definition of the Transmit CONTROL (TC) register bits */

#define TC_EARLY_TX_ENABLE	(0x00000001)

/* Loopback Mode (LM_) Select valuesbits */
#define TC_LM_NORMAL		(0x00000000)
#define TC_LM_INTERNAL		(0x00000002)
#define TC_LM_EXTERNAL		(0x00000004)
#define TC_LM_FULL_DPX		(0x00000006)

#define TX_SLOT_TIME		(0x00000078)

/* Bytes transferred to chip before transmission starts. */
#define TX_FIFO_THRESH		128	/* Rounded down to 4 byte units. */

/* description of rx descriptors status bits */
#define RRING_PKT_INTACT	(0x0001)
#define RRING_ALIGN_ERR		(0x0002)
#define RRING_CRC_ERR		(0x0004)
#define RRING_MISSED_PKT	(0x0008)
#define RRING_MULTICAST		(0x0010)
#define RRING_BROADCAST		(0x0020)
#define RRING_RECEIVER_DISABLE	(0x0040)
#define RRING_STATUS_VALID	(0x1000)
#define RRING_FRAGLIST_ERR	(0x2000)
#define RRING_HDR_COPIED	(0x4000)
#define RRING_OWN		(0x8000)

/* error summary */
#define RRING_ERROR		(RRING_ALIGN_ERR|RRING_CRC_ERR)

/* description of tx descriptors status bits */
#define TRING_PKT_INTACT	(0x0001)	/* pkt transmitted. */
#define TRING_PKT_NONDEFER	(0x0002)	/* pkt xmitted w/o deferring */
#define TRING_COLL		(0x0004)	/* pkt xmitted w collisions */
#define TRING_CARR		(0x0008)	/* carrier sense lost */
#define TRING_UNDERRUN		(0x0010)	/* DMA underrun */
#define TRING_HB_COLL		(0x0020)	/* Collision detect Heartbeat */
#define TRING_WIN_COLL		(0x0040)	/* out of window collision */
#define TRING_DEFERRED		(0x0080)	/* Deferring */
#define TRING_COLL_COUNT	(0x0F00)	/* collision counter (mask) */
#define TRING_COLL_EXCESS	(0x1000)	/* tx aborted: excessive colls */
#define TRING_OWN		(0x8000)	/* desc ownership bit */

/* error summary */
#define TRING_ABORT	(TRING_COLL_EXCESS|TRING_WIN_COLL|TRING_UNDERRUN)
#define TRING_ERROR	(TRING_DEFERRED|TRING_WIN_COLL|TRING_UNDERRUN|TRING_CARR/*|TRING_COLL*/ )

/* description of the tx descriptors control bits */
#define TD_FRAGLIST		(0x0001)	/* Desc points to a fragment list */
#define TD_LLFORM		(0x0002)	/* Frag list format */
#define TD_IAF			(0x0004)	/* Generate Interrupt after tx */
#define TD_NOCRC		(0x0008)	/* No CRC generated */
#define TD_LASTDESC		(0x0010)	/* Last desc for this frame */

#endif	/* _EPIC100_H_ */
