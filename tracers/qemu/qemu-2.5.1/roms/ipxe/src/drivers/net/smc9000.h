/*------------------------------------------------------------------------
 * smc9000.h
 *
 * Copyright (C) 1998 by Daniel Engström
 * Copyright (C) 1996 by Erik Stahlman
 *
 * This software may be used and distributed according to the terms
 * of the GNU Public License, incorporated herein by reference.
 *
 * This file contains register information and access macros for
 * the SMC91xxx chipset.
 *
 * Information contained in this file was obtained from the SMC91C94
 * manual from SMC.  To get a copy, if you really want one, you can find
 * information under www.smsc.com in the components division.
 * ( this thanks to advice from Donald Becker ).
 *
 * Authors
 *      Daniel Engström                         <daniel.engstrom@riksnett.no>
 *	Erik Stahlman				<erik@vt.edu>
 *
 * History
 * 96-01-06		 Erik Stahlman   moved definitions here from main .c
 *                                       file
 * 96-01-19		 Erik Stahlman	 polished this up some, and added
 *                                       better error handling
 * 98-09-25              Daniel Engström adjusted for Etherboot
 * 98-09-27              Daniel Engström moved some static strings back to the
 *                                       main .c file
 * --------------------------------------------------------------------------*/

FILE_LICENCE ( GPL_ANY );

#ifndef	_SMC9000_H_
# define _SMC9000_H_

/* I want some simple types */
typedef unsigned char			byte;
typedef unsigned short			word;
typedef unsigned long int		dword;

/*---------------------------------------------------------------
 *
 * A description of the SMC registers is probably in order here,
 * although for details, the SMC datasheet is invaluable.
 *
 * Basically, the chip has 4 banks of registers ( 0 to 3 ), which
 * are accessed by writing a number into the BANK_SELECT register
 * ( I also use a SMC_SELECT_BANK macro for this ).
 *
 * The banks are configured so that for most purposes, bank 2 is all
 * that is needed for simple run time tasks.
 * ----------------------------------------------------------------------*/

/*
 * Bank Select Register:
 *
 *		yyyy yyyy 0000 00xx
 *		xx		= bank number
 *		yyyy yyyy	= 0x33, for identification purposes.
 */
#define	BANK_SELECT		14

/* BANK 0  */

#define	TCR		0	/* transmit control register */
#define TCR_ENABLE	0x0001	/* if this is 1, we can transmit */
#define TCR_FDUPLX	0x0800	/* receive packets sent out */
#define TCR_STP_SQET	0x1000	/* stop transmitting if Signal quality error */
#define	TCR_MON_CNS	0x0400	/* monitors the carrier status */
#define	TCR_PAD_ENABLE	0x0080	/* pads short packets to 64 bytes */

#define	TCR_CLEAR	0	/* do NOTHING */
/* the normal settings for the TCR register : */
#define	TCR_NORMAL	(TCR_ENABLE | TCR_PAD_ENABLE)


#define EPH_STATUS	2
#define ES_LINK_OK	0x4000	/* is the link integrity ok ? */

#define	RCR		4
#define RCR_SOFTRESET	0x8000	/* resets the chip */
#define	RCR_STRIP_CRC	0x200	/* strips CRC */
#define RCR_ENABLE	0x100	/* IFF this is set, we can receive packets */
#define RCR_ALMUL	0x4	/* receive all multicast packets */
#define	RCR_PROMISC	0x2	/* enable promiscuous mode */

/* the normal settings for the RCR register : */
#define	RCR_NORMAL	(RCR_STRIP_CRC | RCR_ENABLE)
#define RCR_CLEAR	0x0		/* set it to a base state */

#define	COUNTER		6
#define	MIR		8
#define	MCR		10
/* 12 is reserved */

// Receive/Phy Control Register
/* BANK 0  */
#define RPC_REG         0x000A
#define RPC_SPEED       0x2000  // When 1 PHY is in 100Mbps mode.
#define RPC_DPLX        0x1000  // When 1 PHY is in Full-Duplex Mode
#define RPC_ANEG        0x0800  // When 1 PHY is in Auto-Negotiate Mode
#define RPC_LSXA_SHFT   5       // Bits to shift LS2A,LS1A,LS0A to lsb
#define RPC_LSXB_SHFT   2       // Bits to get LS2B,LS1B,LS0B to lsb
#define RPC_LED_100_10  (0x00)  // LED = 100Mbps OR's with 10Mbps link detect
#define RPC_LED_RES     (0x01)  // LED = Reserved
#define RPC_LED_10      (0x02)  // LED = 10Mbps link detect
#define RPC_LED_FD      (0x03)  // LED = Full Duplex Mode
#define RPC_LED_TX_RX   (0x04)  // LED = TX or RX packet occurred
#define RPC_LED_100     (0x05)  // LED = 100Mbps link detect
#define RPC_LED_TX      (0x06)  // LED = TX packet occurred
#define RPC_LED_RX      (0x07)  // LED = RX packet occurred
#define RPC_DEFAULT (RPC_ANEG | (RPC_LED_100 << RPC_LSXA_SHFT) | (RPC_LED_FD << RPC_LSXB_SHFT) | RPC_SPEED | RPC_DPLX)

// Receive/Phy Control Register
/* BANK 0  */
#define RPC_REG         0x000A
#define RPC_SPEED       0x2000  // When 1 PHY is in 100Mbps mode.
#define RPC_DPLX        0x1000  // When 1 PHY is in Full-Duplex Mode
#define RPC_ANEG        0x0800  // When 1 PHY is in Auto-Negotiate Mode
#define RPC_LSXA_SHFT   5       // Bits to shift LS2A,LS1A,LS0A to lsb
#define RPC_LSXB_SHFT   2       // Bits to get LS2B,LS1B,LS0B to lsb
#define RPC_LED_100_10  (0x00)  // LED = 100Mbps OR's with 10Mbps link detect
#define RPC_LED_RES     (0x01)  // LED = Reserved
#define RPC_LED_10      (0x02)  // LED = 10Mbps link detect
#define RPC_LED_FD      (0x03)  // LED = Full Duplex Mode
#define RPC_LED_TX_RX   (0x04)  // LED = TX or RX packet occurred
#define RPC_LED_100     (0x05)  // LED = 100Mbps link detect
#define RPC_LED_TX      (0x06)  // LED = TX packet occurred
#define RPC_LED_RX      (0x07)  // LED = RX packet occurred
#define RPC_DEFAULT (RPC_ANEG | (RPC_LED_100 << RPC_LSXA_SHFT) | (RPC_LED_FD << RPC_LSXB_SHFT) | RPC_SPEED | RPC_DPLX)

/* BANK 1 */
#define CFG			0
#define CFG_AUI_SELECT		0x100
#define	BASE			2
#define	ADDR0			4
#define	ADDR1			6
#define	ADDR2			8
#define	GENERAL			10
#define	CONTROL			12
#define	CTL_POWERDOWN		0x2000
#define	CTL_LE_ENABLE		0x80
#define	CTL_CR_ENABLE		0x40
#define	CTL_TE_ENABLE		0x0020
#define CTL_AUTO_RELEASE	0x0800
#define	CTL_EPROM_ACCESS	0x0003 /* high if Eprom is being read */

/* BANK 2 */
#define MMU_CMD		0
#define MC_BUSY		1	/* only readable bit in the register */
#define MC_NOP		0
#define	MC_ALLOC	0x20	/* or with number of 256 byte packets */
#define	MC_RESET	0x40
#define	MC_REMOVE	0x60	/* remove the current rx packet */
#define MC_RELEASE	0x80	/* remove and release the current rx packet */
#define MC_FREEPKT	0xA0	/* Release packet in PNR register */
#define MC_ENQUEUE	0xC0	/* Enqueue the packet for transmit */

#define	PNR_ARR		2
#define FIFO_PORTS	4

#define FP_RXEMPTY	0x8000
#define FP_TXEMPTY	0x80

#define	POINTER		6
#define PTR_READ	0x2000
#define	PTR_RCV		0x8000
#define	PTR_AUTOINC	0x4000
#define PTR_AUTO_INC	0x0040

#define	DATA_1		8
#define	DATA_2		10
#define	INTERRUPT	12

#define INT_MASK	13
#define IM_RCV_INT	0x1
#define	IM_TX_INT	0x2
#define	IM_TX_EMPTY_INT	0x4
#define	IM_ALLOC_INT	0x8
#define	IM_RX_OVRN_INT	0x10
#define	IM_EPH_INT	0x20
#define	IM_ERCV_INT	0x40 /* not on SMC9192 */

/* BANK 3 */
#define	MULTICAST1	0
#define	MULTICAST2	2
#define	MULTICAST3	4
#define	MULTICAST4	6
#define	MGMT		8
#define	REVISION	10 /* ( hi: chip id   low: rev # ) */

// Management Interface Register (MII)
#define MII_REG         0x0008
#define MII_MSK_CRS100  0x4000 // Disables CRS100 detection during tx half dup
#define MII_MDOE        0x0008 // MII Output Enable
#define MII_MCLK        0x0004 // MII Clock, pin MDCLK
#define MII_MDI         0x0002 // MII Input, pin MDI
#define MII_MDO         0x0001 // MII Output, pin MDO

/* this is NOT on SMC9192 */
#define	ERCV		12

/* Note that 9194 and 9196 have the smame chip id,
 * the 9196 will have revisions starting at 6 */
#define CHIP_9190	3
#define CHIP_9194	4
#define CHIP_9195	5
#define CHIP_9196	4
#define CHIP_91100	7
#define CHIP_91100FD	8

#define REV_9196	6

/*
 * Transmit status bits
 */
#define TS_SUCCESS	0x0001
#define TS_LOSTCAR	0x0400
#define TS_LATCOL	0x0200
#define TS_16COL	0x0010

/*
 * Receive status bits
 */
#define RS_ALGNERR	0x8000
#define RS_BADCRC	0x2000
#define RS_ODDFRAME	0x1000
#define RS_TOOLONG	0x0800
#define RS_TOOSHORT	0x0400
#define RS_MULTICAST	0x0001
#define RS_ERRORS	(RS_ALGNERR | RS_BADCRC | RS_TOOLONG | RS_TOOSHORT)

// PHY Register Addresses (LAN91C111 Internal PHY)

// PHY Control Register
#define PHY_CNTL_REG            0x00
#define PHY_CNTL_RST            0x8000  // 1=PHY Reset
#define PHY_CNTL_LPBK           0x4000  // 1=PHY Loopback
#define PHY_CNTL_SPEED          0x2000  // 1=100Mbps, 0=10Mpbs
#define PHY_CNTL_ANEG_EN        0x1000 // 1=Enable Auto negotiation
#define PHY_CNTL_PDN            0x0800  // 1=PHY Power Down mode
#define PHY_CNTL_MII_DIS        0x0400  // 1=MII 4 bit interface disabled
#define PHY_CNTL_ANEG_RST       0x0200 // 1=Reset Auto negotiate
#define PHY_CNTL_DPLX           0x0100  // 1=Full Duplex, 0=Half Duplex
#define PHY_CNTL_COLTST         0x0080  // 1= MII Colision Test

// PHY Status Register
#define PHY_STAT_REG            0x01
#define PHY_STAT_CAP_T4         0x8000  // 1=100Base-T4 capable
#define PHY_STAT_CAP_TXF        0x4000  // 1=100Base-X full duplex capable
#define PHY_STAT_CAP_TXH        0x2000  // 1=100Base-X half duplex capable
#define PHY_STAT_CAP_TF         0x1000  // 1=10Mbps full duplex capable
#define PHY_STAT_CAP_TH         0x0800  // 1=10Mbps half duplex capable
#define PHY_STAT_CAP_SUPR       0x0040  // 1=recv mgmt frames with not preamble
#define PHY_STAT_ANEG_ACK       0x0020  // 1=ANEG has completed
#define PHY_STAT_REM_FLT        0x0010  // 1=Remote Fault detected
#define PHY_STAT_CAP_ANEG       0x0008  // 1=Auto negotiate capable
#define PHY_STAT_LINK           0x0004  // 1=valid link
#define PHY_STAT_JAB            0x0002  // 1=10Mbps jabber condition
#define PHY_STAT_EXREG          0x0001  // 1=extended registers implemented

// PHY Identifier Registers
#define PHY_ID1_REG             0x02    // PHY Identifier 1
#define PHY_ID2_REG             0x03    // PHY Identifier 2

// PHY Auto-Negotiation Advertisement Register
#define PHY_AD_REG              0x04
#define PHY_AD_NP               0x8000  // 1=PHY requests exchange of Next Page
#define PHY_AD_ACK              0x4000  // 1=got link code word from remote
#define PHY_AD_RF               0x2000  // 1=advertise remote fault
#define PHY_AD_T4               0x0200  // 1=PHY is capable of 100Base-T4
#define PHY_AD_TX_FDX           0x0100  // 1=PHY is capable of 100Base-TX FDPLX
#define PHY_AD_TX_HDX           0x0080  // 1=PHY is capable of 100Base-TX HDPLX
#define PHY_AD_10_FDX           0x0040  // 1=PHY is capable of 10Base-T FDPLX
#define PHY_AD_10_HDX           0x0020  // 1=PHY is capable of 10Base-T HDPLX
#define PHY_AD_CSMA             0x0001  // 1=PHY is capable of 802.3 CMSA

// PHY Auto-negotiation Remote End Capability Register
#define PHY_RMT_REG             0x05
// Uses same bit definitions as PHY_AD_REG

// PHY Configuration Register 1
#define PHY_CFG1_REG            0x10
#define PHY_CFG1_LNKDIS         0x8000  // 1=Rx Link Detect Function disabled
#define PHY_CFG1_XMTDIS         0x4000  // 1=TP Transmitter Disabled
#define PHY_CFG1_XMTPDN         0x2000  // 1=TP Transmitter Powered Down
#define PHY_CFG1_BYPSCR         0x0400  // 1=Bypass scrambler/descrambler
#define PHY_CFG1_UNSCDS         0x0200  // 1=Unscramble Idle Reception Disable
#define PHY_CFG1_EQLZR          0x0100  // 1=Rx Equalizer Disabled
#define PHY_CFG1_CABLE          0x0080  // 1=STP(150ohm), 0=UTP(100ohm)
#define PHY_CFG1_RLVL0          0x0040  // 1=Rx Squelch level reduced by 4.5db
#define PHY_CFG1_TLVL_SHIFT     2       // Transmit Output Level Adjust
#define PHY_CFG1_TLVL_MASK      0x003C
#define PHY_CFG1_TRF_MASK       0x0003  // Transmitter Rise/Fall time


// PHY Configuration Register 2
#define PHY_CFG2_REG            0x11
#define PHY_CFG2_APOLDIS        0x0020  // 1=Auto Polarity Correction disabled
#define PHY_CFG2_JABDIS         0x0010  // 1=Jabber disabled
#define PHY_CFG2_MREG           0x0008  // 1=Multiple register access (MII mgt)
#define PHY_CFG2_INTMDIO        0x0004  // 1=Interrupt signaled with MDIO pulseo

// PHY Status Output (and Interrupt status) Register
#define PHY_INT_REG             0x12    // Status Output (Interrupt Status)
#define PHY_INT_INT             0x8000  // 1=bits have changed since last read
#define PHY_INT_LNKFAIL         0x4000  // 1=Link Not detected
#define PHY_INT_LOSSSYNC        0x2000  // 1=Descrambler has lost sync
#define PHY_INT_CWRD            0x1000  // 1=Invalid 4B5B code detected on rx
#define PHY_INT_SSD             0x0800  // 1=No Start Of Stream detected on rx
#define PHY_INT_ESD             0x0400  // 1=No End Of Stream detected on rx
#define PHY_INT_RPOL            0x0200  // 1=Reverse Polarity detected
#define PHY_INT_JAB             0x0100  // 1=Jabber detected
#define PHY_INT_SPDDET          0x0080  // 1=100Base-TX mode, 0=10Base-T mode
#define PHY_INT_DPLXDET         0x0040  // 1=Device in Full Duplex

// PHY Interrupt/Status Mask Register
#define PHY_MASK_REG            0x13    // Interrupt Mask
// Uses the same bit definitions as PHY_INT_REG


// PHY Register Addresses (LAN91C111 Internal PHY)

// PHY Control Register
#define PHY_CNTL_REG            0x00
#define PHY_CNTL_RST            0x8000  // 1=PHY Reset
#define PHY_CNTL_LPBK           0x4000  // 1=PHY Loopback
#define PHY_CNTL_SPEED          0x2000  // 1=100Mbps, 0=10Mpbs
#define PHY_CNTL_ANEG_EN        0x1000 // 1=Enable Auto negotiation
#define PHY_CNTL_PDN            0x0800  // 1=PHY Power Down mode
#define PHY_CNTL_MII_DIS        0x0400  // 1=MII 4 bit interface disabled
#define PHY_CNTL_ANEG_RST       0x0200 // 1=Reset Auto negotiate
#define PHY_CNTL_DPLX           0x0100  // 1=Full Duplex, 0=Half Duplex
#define PHY_CNTL_COLTST         0x0080  // 1= MII Colision Test

// PHY Status Register
#define PHY_STAT_REG            0x01
#define PHY_STAT_CAP_T4         0x8000  // 1=100Base-T4 capable
#define PHY_STAT_CAP_TXF        0x4000  // 1=100Base-X full duplex capable
#define PHY_STAT_CAP_TXH        0x2000  // 1=100Base-X half duplex capable
#define PHY_STAT_CAP_TF         0x1000  // 1=10Mbps full duplex capable
#define PHY_STAT_CAP_TH         0x0800  // 1=10Mbps half duplex capable
#define PHY_STAT_CAP_SUPR       0x0040  // 1=recv mgmt frames with not preamble
#define PHY_STAT_ANEG_ACK       0x0020  // 1=ANEG has completed
#define PHY_STAT_REM_FLT        0x0010  // 1=Remote Fault detected
#define PHY_STAT_CAP_ANEG       0x0008  // 1=Auto negotiate capable
#define PHY_STAT_LINK           0x0004  // 1=valid link
#define PHY_STAT_JAB            0x0002  // 1=10Mbps jabber condition
#define PHY_STAT_EXREG          0x0001  // 1=extended registers implemented

// PHY Identifier Registers
#define PHY_ID1_REG             0x02    // PHY Identifier 1
#define PHY_ID2_REG             0x03    // PHY Identifier 2

// PHY Auto-Negotiation Advertisement Register
#define PHY_AD_REG              0x04
#define PHY_AD_NP               0x8000  // 1=PHY requests exchange of Next Page
#define PHY_AD_ACK              0x4000  // 1=got link code word from remote
#define PHY_AD_RF               0x2000  // 1=advertise remote fault
#define PHY_AD_T4               0x0200  // 1=PHY is capable of 100Base-T4
#define PHY_AD_TX_FDX           0x0100  // 1=PHY is capable of 100Base-TX FDPLX
#define PHY_AD_TX_HDX           0x0080  // 1=PHY is capable of 100Base-TX HDPLX
#define PHY_AD_10_FDX           0x0040  // 1=PHY is capable of 10Base-T FDPLX
#define PHY_AD_10_HDX           0x0020  // 1=PHY is capable of 10Base-T HDPLX
#define PHY_AD_CSMA             0x0001  // 1=PHY is capable of 802.3 CMSA

// PHY Auto-negotiation Remote End Capability Register
#define PHY_RMT_REG             0x05
// Uses same bit definitions as PHY_AD_REG

// PHY Configuration Register 1
#define PHY_CFG1_REG            0x10
#define PHY_CFG1_LNKDIS         0x8000  // 1=Rx Link Detect Function disabled
#define PHY_CFG1_XMTDIS         0x4000  // 1=TP Transmitter Disabled
#define PHY_CFG1_XMTPDN         0x2000  // 1=TP Transmitter Powered Down
#define PHY_CFG1_BYPSCR         0x0400  // 1=Bypass scrambler/descrambler
#define PHY_CFG1_UNSCDS         0x0200  // 1=Unscramble Idle Reception Disable
#define PHY_CFG1_EQLZR          0x0100  // 1=Rx Equalizer Disabled
#define PHY_CFG1_CABLE          0x0080  // 1=STP(150ohm), 0=UTP(100ohm)
#define PHY_CFG1_RLVL0          0x0040  // 1=Rx Squelch level reduced by 4.5db
#define PHY_CFG1_TLVL_SHIFT     2       // Transmit Output Level Adjust
#define PHY_CFG1_TLVL_MASK      0x003C
#define PHY_CFG1_TRF_MASK       0x0003  // Transmitter Rise/Fall time


// PHY Configuration Register 2
#define PHY_CFG2_REG            0x11
#define PHY_CFG2_APOLDIS        0x0020  // 1=Auto Polarity Correction disabled
#define PHY_CFG2_JABDIS         0x0010  // 1=Jabber disabled
#define PHY_CFG2_MREG           0x0008  // 1=Multiple register access (MII mgt)
#define PHY_CFG2_INTMDIO        0x0004  // 1=Interrupt signaled with MDIO pulseo

// PHY Status Output (and Interrupt status) Register
#define PHY_INT_REG             0x12    // Status Output (Interrupt Status)
#define PHY_INT_INT             0x8000  // 1=bits have changed since last read
#define PHY_INT_LNKFAIL         0x4000  // 1=Link Not detected
#define PHY_INT_LOSSSYNC        0x2000  // 1=Descrambler has lost sync
#define PHY_INT_CWRD            0x1000  // 1=Invalid 4B5B code detected on rx
#define PHY_INT_SSD             0x0800  // 1=No Start Of Stream detected on rx
#define PHY_INT_ESD             0x0400  // 1=No End Of Stream detected on rx
#define PHY_INT_RPOL            0x0200  // 1=Reverse Polarity detected
#define PHY_INT_JAB             0x0100  // 1=Jabber detected
#define PHY_INT_SPDDET          0x0080  // 1=100Base-TX mode, 0=10Base-T mode
#define PHY_INT_DPLXDET         0x0040  // 1=Device in Full Duplex

// PHY Interrupt/Status Mask Register
#define PHY_MASK_REG            0x13    // Interrupt Mask
// Uses the same bit definitions as PHY_INT_REG


/*-------------------------------------------------------------------------
 *  I define some macros to make it easier to do somewhat common
 * or slightly complicated, repeated tasks.
 --------------------------------------------------------------------------*/

/* select a register bank, 0 to 3  */

#define SMC_SELECT_BANK(x, y) { _outw( y, x + BANK_SELECT ); }

/* define a small delay for the reset */
#define SMC_DELAY(x) { inw( x + RCR );\
			inw( x + RCR );\
			inw( x + RCR ); }


#endif	/* _SMC_9000_H_ */

