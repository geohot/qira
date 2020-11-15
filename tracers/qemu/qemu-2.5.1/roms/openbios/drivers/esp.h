/* $Id: esp.h,v 1.28 2000/03/30 01:33:17 davem Exp $
 * esp.h:  Defines and structures for the Sparc ESP (Enhanced SCSI
 *         Processor) driver under Linux.
 *
 * Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
 */

#ifndef _SPARC_ESP_H
#define _SPARC_ESP_H

/* For dvma controller register definitions. */
#include "asm/dma.h"

/* The ESP SCSI controllers have their register sets in three
 * "classes":
 *
 * 1) Registers which are both read and write.
 * 2) Registers which are read only.
 * 3) Registers which are write only.
 *
 * Yet, they all live within the same IO space.
 */

/* All the ESP registers are one byte each and are accessed longwords
 * apart with a big-endian ordering to the bytes.
 */
					/* Access    Description              Offset */
#define ESP_TCLOW	0x00UL		/* rw  Low bits of the transfer count 0x00   */
#define ESP_TCMED	0x04UL		/* rw  Mid bits of the transfer count 0x04   */
#define ESP_FDATA	0x08UL		/* rw  FIFO data bits                 0x08   */
#define ESP_CMD		0x0cUL		/* rw  SCSI command bits              0x0c   */
#define ESP_STATUS	0x10UL		/* ro  ESP status register            0x10   */
#define ESP_BUSID	ESP_STATUS	/* wo  Bus ID for select/reselect     0x10   */
#define ESP_INTRPT	0x14UL		/* ro  Kind of interrupt              0x14   */
#define ESP_TIMEO	ESP_INTRPT	/* wo  Timeout value for select/resel 0x14   */
#define ESP_SSTEP	0x18UL		/* ro  Sequence step register         0x18   */
#define ESP_STP		ESP_SSTEP	/* wo  Transfer period per sync       0x18   */
#define ESP_FFLAGS	0x1cUL		/* ro  Bits of current FIFO info      0x1c   */
#define ESP_SOFF	ESP_FFLAGS	/* wo  Sync offset                    0x1c   */
#define ESP_CFG1	0x20UL		/* rw  First configuration register   0x20   */
#define ESP_CFACT	0x24UL		/* wo  Clock conversion factor        0x24   */
#define ESP_STATUS2	ESP_CFACT	/* ro  HME status2 register           0x24   */
#define ESP_CTEST	0x28UL		/* wo  Chip test register             0x28   */
#define ESP_CFG2	0x2cUL		/* rw  Second configuration register  0x2c   */
#define ESP_CFG3	0x30UL		/* rw  Third configuration register   0x30   */
#define ESP_TCHI	0x38UL		/* rw  High bits of transfer count    0x38   */
#define ESP_UID		ESP_TCHI	/* ro  Unique ID code                 0x38   */
#define FAS_RLO		ESP_TCHI	/* rw  HME extended counter           0x38   */
#define ESP_FGRND	0x3cUL		/* rw  Data base for fifo             0x3c   */
#define FAS_RHI		ESP_FGRND	/* rw  HME extended counter           0x3c   */
#define ESP_REG_SIZE	0x40UL

/* Various revisions of the ESP board. */
enum esp_rev {
	esp100     = 0x00,  /* NCR53C90 - very broken */
	esp100a    = 0x01,  /* NCR53C90A */
	esp236     = 0x02,
	fas236     = 0x03,
	fas100a    = 0x04,
	fast       = 0x05,
	fashme     = 0x06,
	espunknown = 0x07
};

/* Bitfield meanings for the above registers. */

/* ESP config reg 1, read-write, found on all ESP chips */
#define ESP_CONFIG1_ID        0x07             /* My BUS ID bits */
#define ESP_CONFIG1_CHTEST    0x08             /* Enable ESP chip tests */
#define ESP_CONFIG1_PENABLE   0x10             /* Enable parity checks */
#define ESP_CONFIG1_PARTEST   0x20             /* Parity test mode enabled? */
#define ESP_CONFIG1_SRRDISAB  0x40             /* Disable SCSI reset reports */
#define ESP_CONFIG1_SLCABLE   0x80             /* Enable slow cable mode */

/* ESP config reg 2, read-write, found only on esp100a+esp200+esp236 chips */
#define ESP_CONFIG2_DMAPARITY 0x01             /* enable DMA Parity (200,236) */
#define ESP_CONFIG2_REGPARITY 0x02             /* enable reg Parity (200,236) */
#define ESP_CONFIG2_BADPARITY 0x04             /* Bad parity target abort  */
#define ESP_CONFIG2_SCSI2ENAB 0x08             /* Enable SCSI-2 features (tmode only) */
#define ESP_CONFIG2_HI        0x10             /* High Impedance DREQ ???  */
#define ESP_CONFIG2_HMEFENAB  0x10             /* HME features enable */
#define ESP_CONFIG2_BCM       0x20             /* Enable byte-ctrl (236)   */
#define ESP_CONFIG2_DISPINT   0x20             /* Disable pause irq (hme) */
#define ESP_CONFIG2_FENAB     0x40             /* Enable features (fas100,esp216)      */
#define ESP_CONFIG2_SPL       0x40             /* Enable status-phase latch (esp236)   */
#define ESP_CONFIG2_MKDONE    0x40             /* HME magic feature */
#define ESP_CONFIG2_HME32     0x80             /* HME 32 extended */
#define ESP_CONFIG2_MAGIC     0xe0             /* Invalid bits... */

/* ESP config register 3 read-write, found only esp236+fas236+fas100a+hme chips */
#define ESP_CONFIG3_FCLOCK    0x01             /* FAST SCSI clock rate (esp100a/hme) */
#define ESP_CONFIG3_TEM       0x01             /* Enable thresh-8 mode (esp/fas236)  */
#define ESP_CONFIG3_FAST      0x02             /* Enable FAST SCSI     (esp100a/hme) */
#define ESP_CONFIG3_ADMA      0x02             /* Enable alternate-dma (esp/fas236)  */
#define ESP_CONFIG3_TENB      0x04             /* group2 SCSI2 support (esp100a/hme) */
#define ESP_CONFIG3_SRB       0x04             /* Save residual byte   (esp/fas236)  */
#define ESP_CONFIG3_TMS       0x08             /* Three-byte msg's ok  (esp100a/hme) */
#define ESP_CONFIG3_FCLK      0x08             /* Fast SCSI clock rate (esp/fas236)  */
#define ESP_CONFIG3_IDMSG     0x10             /* ID message checking  (esp100a/hme) */
#define ESP_CONFIG3_FSCSI     0x10             /* Enable FAST SCSI     (esp/fas236)  */
#define ESP_CONFIG3_GTM       0x20             /* group2 SCSI2 support (esp/fas236)  */
#define ESP_CONFIG3_IDBIT3    0x20             /* Bit 3 of HME SCSI-ID (hme)         */
#define ESP_CONFIG3_TBMS      0x40             /* Three-byte msg's ok  (esp/fas236)  */
#define ESP_CONFIG3_EWIDE     0x40             /* Enable Wide-SCSI     (hme)         */
#define ESP_CONFIG3_IMS       0x80             /* ID msg chk'ng        (esp/fas236)  */
#define ESP_CONFIG3_OBPUSH    0x80             /* Push odd-byte to dma (hme)         */

/* ESP command register read-write */
/* Group 1 commands:  These may be sent at any point in time to the ESP
 *                    chip.  None of them can generate interrupts 'cept
 *                    the "SCSI bus reset" command if you have not disabled
 *                    SCSI reset interrupts in the config1 ESP register.
 */
#define ESP_CMD_NULL          0x00             /* Null command, ie. a nop */
#define ESP_CMD_FLUSH         0x01             /* FIFO Flush */
#define ESP_CMD_RC            0x02             /* Chip reset */
#define ESP_CMD_RS            0x03             /* SCSI bus reset */

/* Group 2 commands:  ESP must be an initiator and connected to a target
 *                    for these commands to work.
 */
#define ESP_CMD_TI            0x10             /* Transfer Information */
#define ESP_CMD_ICCSEQ        0x11             /* Initiator cmd complete sequence */
#define ESP_CMD_MOK           0x12             /* Message okie-dokie */
#define ESP_CMD_TPAD          0x18             /* Transfer Pad */
#define ESP_CMD_SATN          0x1a             /* Set ATN */
#define ESP_CMD_RATN          0x1b             /* De-assert ATN */

/* Group 3 commands:  ESP must be in the MSGOUT or MSGIN state and be connected
 *                    to a target as the initiator for these commands to work.
 */
#define ESP_CMD_SMSG          0x20             /* Send message */
#define ESP_CMD_SSTAT         0x21             /* Send status */
#define ESP_CMD_SDATA         0x22             /* Send data */
#define ESP_CMD_DSEQ          0x23             /* Discontinue Sequence */
#define ESP_CMD_TSEQ          0x24             /* Terminate Sequence */
#define ESP_CMD_TCCSEQ        0x25             /* Target cmd cmplt sequence */
#define ESP_CMD_DCNCT         0x27             /* Disconnect */
#define ESP_CMD_RMSG          0x28             /* Receive Message */
#define ESP_CMD_RCMD          0x29             /* Receive Command */
#define ESP_CMD_RDATA         0x2a             /* Receive Data */
#define ESP_CMD_RCSEQ         0x2b             /* Receive cmd sequence */

/* Group 4 commands:  The ESP must be in the disconnected state and must
 *                    not be connected to any targets as initiator for
 *                    these commands to work.
 */
#define ESP_CMD_RSEL          0x40             /* Reselect */
#define ESP_CMD_SEL           0x41             /* Select w/o ATN */
#define ESP_CMD_SELA          0x42             /* Select w/ATN */
#define ESP_CMD_SELAS         0x43             /* Select w/ATN & STOP */
#define ESP_CMD_ESEL          0x44             /* Enable selection */
#define ESP_CMD_DSEL          0x45             /* Disable selections */
#define ESP_CMD_SA3           0x46             /* Select w/ATN3 */
#define ESP_CMD_RSEL3         0x47             /* Reselect3 */

/* This bit enables the ESP's DMA on the SBus */
#define ESP_CMD_DMA           0x80             /* Do DMA? */


/* ESP status register read-only */
#define ESP_STAT_PIO          0x01             /* IO phase bit */
#define ESP_STAT_PCD          0x02             /* CD phase bit */
#define ESP_STAT_PMSG         0x04             /* MSG phase bit */
#define ESP_STAT_PMASK        0x07             /* Mask of phase bits */
#define ESP_STAT_TDONE        0x08             /* Transfer Completed */
#define ESP_STAT_TCNT         0x10             /* Transfer Counter Is Zero */
#define ESP_STAT_PERR         0x20             /* Parity error */
#define ESP_STAT_SPAM         0x40             /* Real bad error */
/* This indicates the 'interrupt pending' condition on esp236, it is a reserved
 * bit on other revs of the ESP.
 */
#define ESP_STAT_INTR         0x80             /* Interrupt */

/* HME only: status 2 register */
#define ESP_STAT2_SCHBIT      0x01 /* Upper bits 3-7 of sstep enabled */
#define ESP_STAT2_FFLAGS      0x02 /* The fifo flags are now latched */
#define ESP_STAT2_XCNT        0x04 /* The transfer counter is latched */
#define ESP_STAT2_CREGA       0x08 /* The command reg is active now */
#define ESP_STAT2_WIDE        0x10 /* Interface on this adapter is wide */
#define ESP_STAT2_F1BYTE      0x20 /* There is one byte at top of fifo */
#define ESP_STAT2_FMSB        0x40 /* Next byte in fifo is most significant */
#define ESP_STAT2_FEMPTY      0x80 /* FIFO is empty */

/* The status register can be masked with ESP_STAT_PMASK and compared
 * with the following values to determine the current phase the ESP
 * (at least thinks it) is in.  For our purposes we also add our own
 * software 'done' bit for our phase management engine.
 */
#define ESP_DOP   (0)                                       /* Data Out  */
#define ESP_DIP   (ESP_STAT_PIO)                            /* Data In   */
#define ESP_CMDP  (ESP_STAT_PCD)                            /* Command   */
#define ESP_STATP (ESP_STAT_PCD|ESP_STAT_PIO)               /* Status    */
#define ESP_MOP   (ESP_STAT_PMSG|ESP_STAT_PCD)              /* Message Out */
#define ESP_MIP   (ESP_STAT_PMSG|ESP_STAT_PCD|ESP_STAT_PIO) /* Message In */

/* ESP interrupt register read-only */
#define ESP_INTR_S            0x01             /* Select w/o ATN */
#define ESP_INTR_SATN         0x02             /* Select w/ATN */
#define ESP_INTR_RSEL         0x04             /* Reselected */
#define ESP_INTR_FDONE        0x08             /* Function done */
#define ESP_INTR_BSERV        0x10             /* Bus service */
#define ESP_INTR_DC           0x20             /* Disconnect */
#define ESP_INTR_IC           0x40             /* Illegal command given */
#define ESP_INTR_SR           0x80             /* SCSI bus reset detected */

/* Interrupt status macros */
#define ESP_SRESET_IRQ(esp)  ((esp)->intreg & (ESP_INTR_SR))
#define ESP_ILLCMD_IRQ(esp)  ((esp)->intreg & (ESP_INTR_IC))
#define ESP_SELECT_WITH_ATN_IRQ(esp)     ((esp)->intreg & (ESP_INTR_SATN))
#define ESP_SELECT_WITHOUT_ATN_IRQ(esp)  ((esp)->intreg & (ESP_INTR_S))
#define ESP_SELECTION_IRQ(esp)  ((ESP_SELECT_WITH_ATN_IRQ(esp)) ||         \
				 (ESP_SELECT_WITHOUT_ATN_IRQ(esp)))
#define ESP_RESELECTION_IRQ(esp)         ((esp)->intreg & (ESP_INTR_RSEL))

/* ESP sequence step register read-only */
#define ESP_STEP_VBITS        0x07             /* Valid bits */
#define ESP_STEP_ASEL         0x00             /* Selection&Arbitrate cmplt */
#define ESP_STEP_SID          0x01             /* One msg byte sent */
#define ESP_STEP_NCMD         0x02             /* Was not in command phase */
#define ESP_STEP_PPC          0x03             /* Early phase chg caused cmnd
                                                * bytes to be lost
                                                */
#define ESP_STEP_FINI4        0x04             /* Command was sent ok */

/* Ho hum, some ESP's set the step register to this as well... */
#define ESP_STEP_FINI5        0x05
#define ESP_STEP_FINI6        0x06
#define ESP_STEP_FINI7        0x07

/* ESP chip-test register read-write */
#define ESP_TEST_TARG         0x01             /* Target test mode */
#define ESP_TEST_INI          0x02             /* Initiator test mode */
#define ESP_TEST_TS           0x04             /* Tristate test mode */

/* ESP unique ID register read-only, found on fas236+fas100a only */
#define ESP_UID_F100A         0x00             /* ESP FAS100A  */
#define ESP_UID_F236          0x02             /* ESP FAS236   */
#define ESP_UID_REV           0x07             /* ESP revision */
#define ESP_UID_FAM           0xf8             /* ESP family   */

/* ESP fifo flags register read-only */
/* Note that the following implies a 16 byte FIFO on the ESP. */
#define ESP_FF_FBYTES         0x1f             /* Num bytes in FIFO */
#define ESP_FF_ONOTZERO       0x20             /* offset ctr not zero (esp100) */
#define ESP_FF_SSTEP          0xe0             /* Sequence step */

/* ESP clock conversion factor register write-only */
#define ESP_CCF_F0            0x00             /* 35.01MHz - 40MHz */
#define ESP_CCF_NEVER         0x01             /* Set it to this and die */
#define ESP_CCF_F2            0x02             /* 10MHz */
#define ESP_CCF_F3            0x03             /* 10.01MHz - 15MHz */
#define ESP_CCF_F4            0x04             /* 15.01MHz - 20MHz */
#define ESP_CCF_F5            0x05             /* 20.01MHz - 25MHz */
#define ESP_CCF_F6            0x06             /* 25.01MHz - 30MHz */
#define ESP_CCF_F7            0x07             /* 30.01MHz - 35MHz */

/* HME only... */
#define ESP_BUSID_RESELID     0x10
#define ESP_BUSID_CTR32BIT    0x40

#define ESP_BUS_TIMEOUT        275             /* In milli-seconds */
#define ESP_TIMEO_CONST       8192
#define ESP_NEG_DEFP(mhz, cfact) \
        ((ESP_BUS_TIMEOUT * ((mhz) / 1000)) / (8192 * (cfact)))
#define ESP_MHZ_TO_CYCLE(mhertz)  ((1000000000) / ((mhertz) / 1000))
#define ESP_TICK(ccf, cycle)  ((7682 * (ccf) * (cycle) / 1000))

#endif /* !(_SPARC_ESP_H) */
