/*
 * 3c90x.c -- This file implements the 3c90x driver for etherboot.  Written
 * by Greg Beeley, Greg.Beeley@LightSys.org.  Modified by Steve Smith,
 * Steve.Smith@Juno.Com. Alignment bug fix Neil Newell (nn@icenoir.net).
 *
 * Port from etherboot to iPXE API, implementation of tx/rx ring support
 * by Thomas Miletich, thomas.miletich@gmail.com
 * Thanks to Marty Connor and Stefan Hajnoczi for their help and feedback.
 *
 * This program Copyright (C) 1999 LightSys Technology Services, Inc.
 * Portions Copyright (C) 1999 Steve Smith
 *
 * This program may be re-distributed in source or binary form, modified,
 * sold, or copied for any purpose, provided that the above copyright message
 * and this text are included with all source copies or derivative works, and
 * provided that the above copyright message and this text are included in the
 * documentation of any binary-only distributions.  This program is distributed
 * WITHOUT ANY WARRANTY, without even the warranty of FITNESS FOR A PARTICULAR
 * PURPOSE or MERCHANTABILITY.  Please read the associated documentation
 * "3c90x.txt" before compiling and using this driver.
 *
 * --------
 *
 * Program written with the assistance of the 3com documentation for
 * the 3c905B-TX card, as well as with some assistance from the 3c59x
 * driver Donald Becker wrote for the Linux kernel, and with some assistance
 * from the remainder of the Etherboot distribution.
 *
 * REVISION HISTORY:
 *
 * v0.10	1-26-1998	GRB	Initial implementation.
 * v0.90	1-27-1998	GRB	System works.
 * v1.00pre1	2-11-1998	GRB	Got prom boot issue fixed.
 * v2.0		9-24-1999	SCS	Modified for 3c905 (from 3c905b code)
 *					Re-wrote poll and transmit for
 *					better error recovery and heavy
 *					network traffic operation
 * v2.01    5-26-2003 NN Fixed driver alignment issue which
 *                  caused system lockups if driver structures
 *                  not 8-byte aligned.
 * v2.02   11-28-2007 GSt Got polling working again by replacing
 * 			"for(i=0;i<40000;i++);" with "mdelay(1);"
 *
 *
 * indent options: indent -kr -i8 3c90x.c
 */

FILE_LICENCE ( BSD2 );

#ifndef __3C90X_H_
#define __3C90X_H_

static struct net_device_operations a3c90x_operations;

#define	XCVR_MAGIC	(0x5A00)

/* Register definitions for the 3c905 */
enum Registers {
	regPowerMgmtCtrl_w = 0x7c,	/* 905B Revision Only                 */
	regUpMaxBurst_w = 0x7a,	/* 905B Revision Only                 */
	regDnMaxBurst_w = 0x78,	/* 905B Revision Only                 */
	regDebugControl_w = 0x74,	/* 905B Revision Only                 */
	regDebugData_l = 0x70,	/* 905B Revision Only                 */
	regRealTimeCnt_l = 0x40,	/* Universal                          */
	regUpBurstThresh_b = 0x3e,	/* 905B Revision Only                 */
	regUpPoll_b = 0x3d,	/* 905B Revision Only                 */
	regUpPriorityThresh_b = 0x3c,	/* 905B Revision Only                 */
	regUpListPtr_l = 0x38,	/* Universal                          */
	regCountdown_w = 0x36,	/* Universal                          */
	regFreeTimer_w = 0x34,	/* Universal                          */
	regUpPktStatus_l = 0x30,	/* Universal with Exception, pg 130   */
	regTxFreeThresh_b = 0x2f,	/* 90X Revision Only                  */
	regDnPoll_b = 0x2d,	/* 905B Revision Only                 */
	regDnPriorityThresh_b = 0x2c,	/* 905B Revision Only                 */
	regDnBurstThresh_b = 0x2a,	/* 905B Revision Only                 */
	regDnListPtr_l = 0x24,	/* Universal with Exception, pg 107   */
	regDmaCtrl_l = 0x20,	/* Universal with Exception, pg 106   */
	/*                                    */
	regIntStatusAuto_w = 0x1e,	/* 905B Revision Only                 */
	regTxStatus_b = 0x1b,	/* Universal with Exception, pg 113   */
	regTimer_b = 0x1a,	/* Universal                          */
	regTxPktId_b = 0x18,	/* 905B Revision Only                 */
	regCommandIntStatus_w = 0x0e,	/* Universal (Command Variations)     */
};

/* following are windowed registers */
enum Registers7 {
	regPowerMgmtEvent_7_w = 0x0c,	/* 905B Revision Only                 */
	regVlanEtherType_7_w = 0x04,	/* 905B Revision Only                 */
	regVlanMask_7_w = 0x00,	/* 905B Revision Only                 */
};

enum Registers6 {
	regBytesXmittedOk_6_w = 0x0c,	/* Universal                          */
	regBytesRcvdOk_6_w = 0x0a,	/* Universal                          */
	regUpperFramesOk_6_b = 0x09,	/* Universal                          */
	regFramesDeferred_6_b = 0x08,	/* Universal                          */
	regFramesRecdOk_6_b = 0x07,	/* Universal with Exceptions, pg 142  */
	regFramesXmittedOk_6_b = 0x06,	/* Universal                          */
	regRxOverruns_6_b = 0x05,	/* Universal                          */
	regLateCollisions_6_b = 0x04,	/* Universal                          */
	regSingleCollisions_6_b = 0x03,	/* Universal                          */
	regMultipleCollisions_6_b = 0x02,	/* Universal                          */
	regSqeErrors_6_b = 0x01,	/* Universal                          */
	regCarrierLost_6_b = 0x00,	/* Universal                          */
};

enum Registers5 {
	regIndicationEnable_5_w = 0x0c,	/* Universal                          */
	regInterruptEnable_5_w = 0x0a,	/* Universal                          */
	regTxReclaimThresh_5_b = 0x09,	/* 905B Revision Only                 */
	regRxFilter_5_b = 0x08,	/* Universal                          */
	regRxEarlyThresh_5_w = 0x06,	/* Universal                          */
	regTxStartThresh_5_w = 0x00,	/* Universal                          */
};

enum Registers4 {
	regUpperBytesOk_4_b = 0x0d,	/* Universal                          */
	regBadSSD_4_b = 0x0c,	/* Universal                          */
	regMediaStatus_4_w = 0x0a,	/* Universal with Exceptions, pg 201  */
	regPhysicalMgmt_4_w = 0x08,	/* Universal                          */
	regNetworkDiagnostic_4_w = 0x06,	/* Universal with Exceptions, pg 203  */
	regFifoDiagnostic_4_w = 0x04,	/* Universal with Exceptions, pg 196  */
	regVcoDiagnostic_4_w = 0x02,	/* Undocumented?                      */
};

enum Registers3 {
	regTxFree_3_w = 0x0c,	/* Universal                          */
	regRxFree_3_w = 0x0a,	/* Universal with Exceptions, pg 125  */
	regResetMediaOptions_3_w = 0x08,	/* Media Options on B Revision,       */
	/* Reset Options on Non-B Revision    */
	regMacControl_3_w = 0x06,	/* Universal with Exceptions, pg 199  */
	regMaxPktSize_3_w = 0x04,	/* 905B Revision Only                 */
	regInternalConfig_3_l = 0x00,	/* Universal, different bit           */
	/* definitions, pg 59                 */
};

enum Registers2 {
	regResetOptions_2_w = 0x0c,	/* 905B Revision Only                 */
	regStationMask_2_3w = 0x06,	/* Universal with Exceptions, pg 127  */
	regStationAddress_2_3w = 0x00,	/* Universal with Exceptions, pg 127  */
};

enum Registers1 {
	regRxStatus_1_w = 0x0a,	/* 90X Revision Only, Pg 126          */
};

enum Registers0 {
	regEepromData_0_w = 0x0c,	/* Universal                          */
	regEepromCommand_0_w = 0x0a,	/* Universal                          */
	regBiosRomData_0_b = 0x08,	/* 905B Revision Only                 */
	regBiosRomAddr_0_l = 0x04,	/* 905B Revision Only                 */
};


/* The names for the eight register windows */
enum Windows {
	winNone = 0xff,
	winPowerVlan7 = 0x07,
	winStatistics6 = 0x06,
	winTxRxControl5 = 0x05,
	winDiagnostics4 = 0x04,
	winTxRxOptions3 = 0x03,
	winAddressing2 = 0x02,
	winUnused1 = 0x01,
	winEepromBios0 = 0x00,
};


/* Command definitions for the 3c90X */
enum Commands {
	cmdGlobalReset = 0x00,	/* Universal with Exceptions, pg 151 */
	cmdSelectRegisterWindow = 0x01,	/* Universal                         */
	cmdEnableDcConverter = 0x02,	/*                                   */
	cmdRxDisable = 0x03,	/*                                   */
	cmdRxEnable = 0x04,	/* Universal                         */
	cmdRxReset = 0x05,	/* Universal                         */
	cmdStallCtl = 0x06,	/* Universal                         */
	cmdTxEnable = 0x09,	/* Universal                         */
	cmdTxDisable = 0x0A,	/*                                   */
	cmdTxReset = 0x0B,	/* Universal                         */
	cmdRequestInterrupt = 0x0C,	/*                                   */
	cmdAcknowledgeInterrupt = 0x0D,	/* Universal                         */
	cmdSetInterruptEnable = 0x0E,	/* Universal                         */
	cmdSetIndicationEnable = 0x0F,	/* Universal                         */
	cmdSetRxFilter = 0x10,	/* Universal                         */
	cmdSetRxEarlyThresh = 0x11,	/*                                   */
	cmdSetTxStartThresh = 0x13,	/*                                   */
	cmdStatisticsEnable = 0x15,	/*                                   */
	cmdStatisticsDisable = 0x16,	/*                                   */
	cmdDisableDcConverter = 0x17,	/*                                   */
	cmdSetTxReclaimThresh = 0x18,	/*                                   */
	cmdSetHashFilterBit = 0x19,	/*                                   */
};

enum GlobalResetParams {
	globalResetAll = 0,
	globalResetMaskNetwork = (1<<2),
	globalResetMaskAll = 0x1ff,
};

enum FrameStartHeader {
	fshTxIndicate = 0x8000,
	fshDnComplete = 0x10000,
	fshRndupDefeat = 0x10000000,
};

enum UpDownDesc {
	upLastFrag = (1 << 31),
	downLastFrag = (1 << 31),
};

enum UpPktStatus {
	upComplete = (1 << 15),
	upError = (1 << 14),
};

enum Stalls {
	upStall = 0x00,
	upUnStall = 0x01,

	dnStall = 0x02,
	dnUnStall = 0x03,
};

enum Resources {
	resRxRing = 0x00,
	resTxRing = 0x02,
	resRxIOBuf = 0x04
};

enum eeprom {
	eepromBusy = (1 << 15),
	eepromRead = ((0x02) << 6),
	eepromRead_556 = 0x230,
	eepromHwAddrOffset = 0x0a,
};

/* Bit 4 is only used in revison B and upwards */
enum linktype {
	link10BaseT = 0x00,
	linkAUI = 0x01,
	link10Base2 = 0x03,
	link100BaseFX = 0x05,
	linkMII = 0x06,
	linkAutoneg = 0x08,
	linkExternalMII = 0x09,
};

/* Values for int status register bitmask */
#define	INT_INTERRUPTLATCH	(1<<0)
#define INT_HOSTERROR		(1<<1)
#define INT_TXCOMPLETE		(1<<2)
#define INT_RXCOMPLETE		(1<<4)
#define INT_RXEARLY		(1<<5)
#define INT_INTREQUESTED	(1<<6)
#define INT_UPDATESTATS		(1<<7)
#define INT_LINKEVENT		(1<<8)
#define INT_DNCOMPLETE		(1<<9)
#define INT_UPCOMPLETE		(1<<10)
#define INT_CMDINPROGRESS	(1<<12)
#define INT_WINDOWNUMBER	(7<<13)

/* Buffer sizes */
#define TX_RING_SIZE 8
#define RX_RING_SIZE 8
#define TX_RING_ALIGN 16
#define RX_RING_ALIGN 16
#define RX_BUF_SIZE 1536

/* Timeouts for eeprom and command completion */
/* Timeout 1 second, to be save */
#define EEPROM_TIMEOUT		1 * 1000 * 1000

/* TX descriptor */
struct TXD {
	volatile unsigned int DnNextPtr;
	volatile unsigned int FrameStartHeader;
	volatile unsigned int DataAddr;
	volatile unsigned int DataLength;
} __attribute__ ((aligned(8)));	/* 64-bit aligned for bus mastering */

/* RX descriptor */
struct RXD {
	volatile unsigned int UpNextPtr;
	volatile unsigned int UpPktStatus;
	volatile unsigned int DataAddr;
	volatile unsigned int DataLength;
} __attribute__ ((aligned(8)));	/* 64-bit aligned for bus mastering */

/* Private NIC dats */
struct INF_3C90X {
	unsigned int is3c556;
	unsigned char isBrev;
	unsigned char CurrentWindow;
	unsigned int IOAddr;
	unsigned short eeprom[0x21];
	unsigned int tx_cur;	/* current entry in tx_ring */
	unsigned int tx_cnt;	/* current number of used tx descriptors */
	unsigned int tx_tail;	/* entry of last finished packet */
	unsigned int rx_cur;
	struct TXD *tx_ring;
	struct RXD *rx_ring;
	struct io_buffer *tx_iobuf[TX_RING_SIZE];
	struct io_buffer *rx_iobuf[RX_RING_SIZE];
	struct nvs_device nvs;
};

#endif
