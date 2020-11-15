/*
 * i82365.h 1.15 1999/10/25 20:03:34
 *
 * The contents of this file may be used under the
 * terms of the GNU General Public License version 2 (the "GPL").
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and
 * limitations under the License. 
 *
 * The initial developer of the original code is David A. Hinds
 * <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 * are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 */

FILE_LICENCE ( GPL2_ONLY );

#ifndef _LINUX_I82365_H
#define _LINUX_I82365_H

/* register definitions for the Intel 82365SL PCMCIA controller */

/* Offsets for PCIC registers */
#define I365_IDENT	0x00	/* Identification and revision */
#define I365_STATUS	0x01	/* Interface status */
#define I365_POWER	0x02	/* Power and RESETDRV control */
#define I365_INTCTL	0x03	/* Interrupt and general control */
#define I365_CSC	0x04	/* Card status change */
#define I365_CSCINT	0x05	/* Card status change interrupt control */
#define I365_ADDRWIN	0x06	/* Address window enable */
#define I365_IOCTL	0x07	/* I/O control */
#define I365_GENCTL	0x16	/* Card detect and general control */
#define I365_GBLCTL	0x1E	/* Global control register */

/* Offsets for I/O and memory window registers */
#define I365_IO(map)	(0x08+((map)<<2))
#define I365_MEM(map)	(0x10+((map)<<3))
#define I365_W_START	0
#define I365_W_STOP	2
#define I365_W_OFF	4

/* Flags for I365_STATUS */
#define I365_CS_BVD1	0x01
#define I365_CS_STSCHG	0x01
#define I365_CS_BVD2	0x02
#define I365_CS_SPKR	0x02
#define I365_CS_DETECT	0x0C
#define I365_CS_WRPROT	0x10
#define I365_CS_READY	0x20	/* Inverted */
#define I365_CS_POWERON	0x40
#define I365_CS_GPI	0x80

/* Flags for I365_POWER */
#define I365_PWR_OFF	0x00	/* Turn off the socket */
#define I365_PWR_OUT	0x80	/* Output enable */
#define I365_PWR_NORESET 0x40	/* Disable RESETDRV on resume */
#define I365_PWR_AUTO	0x20	/* Auto pwr switch enable */
#define I365_VCC_MASK	0x18	/* Mask for turning off Vcc */
/* There are different layouts for B-step and DF-step chips: the B
   step has independent Vpp1/Vpp2 control, and the DF step has only
   Vpp1 control, plus 3V control */
#define I365_VCC_5V	0x10	/* Vcc = 5.0v */
#define I365_VCC_3V	0x18	/* Vcc = 3.3v */
#define I365_VPP2_MASK	0x0c	/* Mask for turning off Vpp2 */
#define I365_VPP2_5V	0x04	/* Vpp2 = 5.0v */
#define I365_VPP2_12V	0x08	/* Vpp2 = 12.0v */
#define I365_VPP1_MASK	0x03	/* Mask for turning off Vpp1 */
#define I365_VPP1_5V	0x01	/* Vpp2 = 5.0v */
#define I365_VPP1_12V	0x02	/* Vpp2 = 12.0v */

/* Flags for I365_INTCTL */
#define I365_RING_ENA	0x80
#define I365_PC_RESET	0x40
#define I365_PC_IOCARD	0x20
#define I365_INTR_ENA	0x10
#define I365_IRQ_MASK	0x0F

/* Flags for I365_CSC and I365_CSCINT*/
#define I365_CSC_BVD1	0x01
#define I365_CSC_STSCHG	0x01
#define I365_CSC_BVD2	0x02
#define I365_CSC_READY	0x04
#define I365_CSC_DETECT	0x08
#define I365_CSC_ANY	0x0F
#define I365_CSC_GPI	0x10

/* Flags for I365_ADDRWIN */
#define I365_ENA_IO(map)	(0x40 << (map))
#define I365_ENA_MEM(map)	(0x01 << (map))

/* Flags for I365_IOCTL */
#define I365_IOCTL_MASK(map)	(0x0F << (map<<2))
#define I365_IOCTL_WAIT(map)	(0x08 << (map<<2))
#define I365_IOCTL_0WS(map)	(0x04 << (map<<2))
#define I365_IOCTL_IOCS16(map)	(0x02 << (map<<2))
#define I365_IOCTL_16BIT(map)	(0x01 << (map<<2))

/* Flags for I365_GENCTL */
#define I365_CTL_16DELAY	0x01
#define I365_CTL_RESET		0x02
#define I365_CTL_GPI_ENA	0x04
#define I365_CTL_GPI_CTL	0x08
#define I365_CTL_RESUME		0x10
#define I365_CTL_SW_IRQ		0x20

/* Flags for I365_GBLCTL */
#define I365_GBL_PWRDOWN	0x01
#define I365_GBL_CSC_LEV	0x02
#define I365_GBL_WRBACK		0x04
#define I365_GBL_IRQ_0_LEV	0x08
#define I365_GBL_IRQ_1_LEV	0x10

/* Flags for memory window registers */
#define I365_MEM_16BIT	0x8000	/* In memory start high byte */
#define I365_MEM_0WS	0x4000
#define I365_MEM_WS1	0x8000	/* In memory stop high byte */
#define I365_MEM_WS0	0x4000
#define I365_MEM_WRPROT	0x8000	/* In offset high byte */
#define I365_MEM_REG	0x4000

#define I365_REG(slot, reg)	(((slot) << 6) + reg)

#endif /* _LINUX_I82365_H */

//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
// Beginning vg468.h (for VADEM chipset)

#ifndef _LINUX_VG468_H
#define _LINUX_VG468_H

/* Special bit in I365_IDENT used for Vadem chip detection */
#define I365_IDENT_VADEM        0x08

/* Special definitions in I365_POWER */
#define VG468_VPP2_MASK         0x0c
#define VG468_VPP2_5V           0x04
#define VG468_VPP2_12V          0x08

/* Unique Vadem registers */
#define VG469_VSENSE            0x1f    /* Card voltage sense */
#define VG469_VSELECT           0x2f    /* Card voltage select */
#define VG468_CTL               0x38    /* Control register */
#define VG468_TIMER             0x39    /* Timer control */
#define VG468_MISC              0x3a    /* Miscellaneous */
#define VG468_GPIO_CFG          0x3b    /* GPIO configuration */
#define VG469_EXT_MODE          0x3c    /* Extended mode register */
#define VG468_SELECT            0x3d    /* Programmable chip select */
#define VG468_SELECT_CFG        0x3e    /* Chip select configuration */
#define VG468_ATA               0x3f    /* ATA control */

/* Flags for VG469_VSENSE */
#define VG469_VSENSE_A_VS1      0x01
#define VG469_VSENSE_A_VS2      0x02
#define VG469_VSENSE_B_VS1      0x04
#define VG469_VSENSE_B_VS2      0x08

/* Flags for VG469_VSELECT */
#define VG469_VSEL_VCC          0x03
#define VG469_VSEL_5V           0x00
#define VG469_VSEL_3V           0x03
#define VG469_VSEL_MAX          0x0c
#define VG469_VSEL_EXT_STAT     0x10
#define VG469_VSEL_EXT_BUS      0x20
#define VG469_VSEL_MIXED        0x40
#define VG469_VSEL_ISA          0x80

/* Flags for VG468_CTL */
#define VG468_CTL_SLOW          0x01    /* 600ns memory timing */
#define VG468_CTL_ASYNC         0x02    /* Asynchronous bus clocking */
#define VG468_CTL_TSSI          0x08    /* Tri-state some outputs */
#define VG468_CTL_DELAY         0x10    /* Card detect debounce */
#define VG468_CTL_INPACK        0x20    /* Obey INPACK signal? */
#define VG468_CTL_POLARITY      0x40    /* VCCEN polarity */
#define VG468_CTL_COMPAT        0x80    /* Compatibility stuff */

#define VG469_CTL_WS_COMPAT     0x04    /* Wait state compatibility */
#define VG469_CTL_STRETCH       0x10    /* LED stretch */

/* Flags for VG468_TIMER */
#define VG468_TIMER_ZEROPWR     0x10    /* Zero power control */
#define VG468_TIMER_SIGEN       0x20    /* Power up */
#define VG468_TIMER_STATUS      0x40    /* Activity timer status */
#define VG468_TIMER_RES         0x80    /* Timer resolution */
#define VG468_TIMER_MASK        0x0f    /* Activity timer timeout */

/* Flags for VG468_MISC */
#define VG468_MISC_GPIO         0x04    /* General-purpose IO */
#define VG468_MISC_DMAWSB       0x08    /* DMA wait state control */
#define VG469_MISC_LEDENA       0x10    /* LED enable */
#define VG468_MISC_VADEMREV     0x40    /* Vadem revision control */
#define VG468_MISC_UNLOCK       0x80    /* Unique register lock */

/* Flags for VG469_EXT_MODE_A */
#define VG469_MODE_VPPST        0x03    /* Vpp steering control */
#define VG469_MODE_INT_SENSE    0x04    /* Internal voltage sense */
#define VG469_MODE_CABLE        0x08
#define VG469_MODE_COMPAT       0x10    /* i82365sl B or DF step */
#define VG469_MODE_TEST         0x20
#define VG469_MODE_RIO          0x40    /* Steer RIO to INTR? */

/* Flags for VG469_EXT_MODE_B */
#define VG469_MODE_B_3V         0x01    /* 3.3v for socket B */

#endif /* _LINUX_VG468_H */


//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
// Beginning ricoh.h (RICOH chipsets)

#ifndef _LINUX_RICOH_H
#define _LINUX_RICOH_H


#define RF5C_MODE_CTL           0x1f    /* Mode control */
#define RF5C_PWR_CTL            0x2f    /* Mixed voltage control */
#define RF5C_CHIP_ID            0x3a    /* Chip identification */
#define RF5C_MODE_CTL_3         0x3b    /* Mode control 3 */

/* I/O window address offset */
#define RF5C_IO_OFF(w)          (0x36+((w)<<1))

/* Flags for RF5C_MODE_CTL */
#define RF5C_MODE_ATA           0x01    /* ATA mode */
#define RF5C_MODE_LED_ENA       0x02    /* IRQ 12 is LED */
#define RF5C_MODE_CA21          0x04
#define RF5C_MODE_CA22          0x08
#define RF5C_MODE_CA23          0x10
#define RF5C_MODE_CA24          0x20
#define RF5C_MODE_CA25          0x40
#define RF5C_MODE_3STATE_BIT7   0x80

/* Flags for RF5C_PWR_CTL */
#define RF5C_PWR_VCC_3V         0x01
#define RF5C_PWR_IREQ_HIGH      0x02
#define RF5C_PWR_INPACK_ENA     0x04
#define RF5C_PWR_5V_DET         0x08
#define RF5C_PWR_TC_SEL         0x10    /* Terminal Count: irq 11 or 15 */
#define RF5C_PWR_DREQ_LOW       0x20
#define RF5C_PWR_DREQ_OFF       0x00    /* DREQ steering control */
#define RF5C_PWR_DREQ_INPACK    0x40
#define RF5C_PWR_DREQ_SPKR      0x80
#define RF5C_PWR_DREQ_IOIS16    0xc0

/* Values for RF5C_CHIP_ID */
#define RF5C_CHIP_RF5C296       0x32
#define RF5C_CHIP_RF5C396       0xb2

/* Flags for RF5C_MODE_CTL_3 */
#define RF5C_MCTL3_DISABLE      0x01    /* Disable PCMCIA interface */
#define RF5C_MCTL3_DMA_ENA      0x02

/* Register definitions for Ricoh PCI-to-CardBus bridges */

/* Extra bits in CB_BRIDGE_CONTROL */
#define RL5C46X_BCR_3E0_ENA             0x0800
#define RL5C46X_BCR_3E2_ENA             0x1000

/* Bridge Configuration Register */
#define RL5C4XX_CONFIG                  0x80    /* 16 bit */
#define  RL5C4XX_CONFIG_IO_1_MODE       0x0200
#define  RL5C4XX_CONFIG_IO_0_MODE       0x0100
#define  RL5C4XX_CONFIG_PREFETCH        0x0001


/* Misc Control Register */
#define RL5C4XX_MISC                    0x0082  /* 16 bit */
#define  RL5C4XX_MISC_HW_SUSPEND_ENA    0x0002
#define  RL5C4XX_MISC_VCCEN_POL         0x0100
#define  RL5C4XX_MISC_VPPEN_POL         0x0200
#define  RL5C46X_MISC_SUSPEND           0x0001
#define  RL5C46X_MISC_PWR_SAVE_2        0x0004
#define  RL5C46X_MISC_IFACE_BUSY        0x0008
#define  RL5C46X_MISC_B_LOCK            0x0010
#define  RL5C46X_MISC_A_LOCK            0x0020
#define  RL5C46X_MISC_PCI_LOCK          0x0040
#define  RL5C47X_MISC_IFACE_BUSY        0x0004
#define  RL5C47X_MISC_PCI_INT_MASK      0x0018
#define  RL5C47X_MISC_PCI_INT_DIS       0x0020
#define  RL5C47X_MISC_SUBSYS_WR         0x0040
#define  RL5C47X_MISC_SRIRQ_ENA         0x0080
#define  RL5C47X_MISC_5V_DISABLE        0x0400
#define  RL5C47X_MISC_LED_POL           0x0800

/* 16-bit Interface Control Register */
#define RL5C4XX_16BIT_CTL               0x0084  /* 16 bit */
#define  RL5C4XX_16CTL_IO_TIMING        0x0100
#define  RL5C4XX_16CTL_MEM_TIMING       0x0200
#define  RL5C46X_16CTL_LEVEL_1          0x0010
#define  RL5C46X_16CTL_LEVEL_2          0x0020

/* 16-bit IO and memory timing registers */
#define RL5C4XX_16BIT_IO_0              0x0088  /* 16 bit */
#define RL5C4XX_16BIT_MEM_0             0x0088  /* 16 bit */
#define  RL5C4XX_SETUP_MASK             0x0007
#define  RL5C4XX_SETUP_SHIFT            0
#define  RL5C4XX_CMD_MASK               0x01f0
#define  RL5C4XX_CMD_SHIFT              4
#define  RL5C4XX_HOLD_MASK              0x1c00
#define  RL5C4XX_HOLD_SHIFT             10
#define  RL5C4XX_MISC_CONTROL           0x2F /* 8 bit */
#define  RL5C4XX_ZV_ENABLE              0x08

#endif /* _LINUX_RICOH_H */


//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
//*****************************************************************************
// Beginning cirrus.h (CIRRUS chipsets)

#ifndef _LINUX_CIRRUS_H
#define _LINUX_CIRRUS_H

#ifndef PCI_VENDOR_ID_CIRRUS
#define PCI_VENDOR_ID_CIRRUS            0x1013
#endif
#ifndef PCI_DEVICE_ID_CIRRUS_6729
#define PCI_DEVICE_ID_CIRRUS_6729       0x1100
#endif
#ifndef PCI_DEVICE_ID_CIRRUS_6832
#define PCI_DEVICE_ID_CIRRUS_6832       0x1110
#endif

#define PD67_MISC_CTL_1         0x16    /* Misc control 1 */
#define PD67_FIFO_CTL           0x17    /* FIFO control */
#define PD67_MISC_CTL_2         0x1E    /* Misc control 2 */
#define PD67_CHIP_INFO          0x1f    /* Chip information */
#define PD67_ATA_CTL            0x026   /* 6730: ATA control */
#define PD67_EXT_INDEX          0x2e    /* Extension index */
#define PD67_EXT_DATA           0x2f    /* Extension data */

/* PD6722 extension registers -- indexed in PD67_EXT_INDEX */
#define PD67_DATA_MASK0         0x01    /* Data mask 0 */
#define PD67_DATA_MASK1         0x02    /* Data mask 1 */
#define PD67_DMA_CTL            0x03    /* DMA control */

/* PD6730 extension registers -- indexed in PD67_EXT_INDEX */
#define PD67_EXT_CTL_1          0x03    /* Extension control 1 */
#define PD67_MEM_PAGE(n)        ((n)+5) /* PCI window bits 31:24 */
#define PD67_EXTERN_DATA        0x0a
#define PD67_MISC_CTL_3         0x25
#define PD67_SMB_PWR_CTL        0x26

/* I/O window address offset */
#define PD67_IO_OFF(w)          (0x36+((w)<<1))

/* Timing register sets */
#define PD67_TIME_SETUP(n)      (0x3a + 3*(n))
#define PD67_TIME_CMD(n)        (0x3b + 3*(n))
#define PD67_TIME_RECOV(n)      (0x3c + 3*(n))

/* Flags for PD67_MISC_CTL_1 */
#define PD67_MC1_5V_DET         0x01    /* 5v detect */
#define PD67_MC1_MEDIA_ENA      0x01    /* 6730: Multimedia enable */
#define PD67_MC1_VCC_3V         0x02    /* 3.3v Vcc */
#define PD67_MC1_PULSE_MGMT     0x04
#define PD67_MC1_PULSE_IRQ      0x08
#define PD67_MC1_SPKR_ENA       0x10
#define PD67_MC1_INPACK_ENA     0x80

/* Flags for PD67_FIFO_CTL */
#define PD67_FIFO_EMPTY         0x80

/* Flags for PD67_MISC_CTL_2 */
#define PD67_MC2_FREQ_BYPASS    0x01
#define PD67_MC2_DYNAMIC_MODE   0x02
#define PD67_MC2_SUSPEND        0x04
#define PD67_MC2_5V_CORE        0x08
#define PD67_MC2_LED_ENA        0x10    /* IRQ 12 is LED enable */
#define PD67_MC2_FAST_PCI       0x10    /* 6729: PCI bus > 25 MHz */
#define PD67_MC2_3STATE_BIT7    0x20    /* Floppy change bit */
#define PD67_MC2_DMA_MODE       0x40
#define PD67_MC2_IRQ15_RI       0x80    /* IRQ 15 is ring enable */

/* Flags for PD67_CHIP_INFO */
#define PD67_INFO_SLOTS         0x20    /* 0 = 1 slot, 1 = 2 slots */
#define PD67_INFO_CHIP_ID       0xc0
#define PD67_INFO_REV           0x1c

/* Fields in PD67_TIME_* registers */
#define PD67_TIME_SCALE         0xc0
#define PD67_TIME_SCALE_1       0x00
#define PD67_TIME_SCALE_16      0x40
#define PD67_TIME_SCALE_256     0x80
#define PD67_TIME_SCALE_4096    0xc0
#define PD67_TIME_MULT          0x3f

/* Fields in PD67_DMA_CTL */
#define PD67_DMA_MODE           0xc0
#define PD67_DMA_OFF            0x00
#define PD67_DMA_DREQ_INPACK    0x40
#define PD67_DMA_DREQ_WP        0x80
#define PD67_DMA_DREQ_BVD2      0xc0
#define PD67_DMA_PULLUP         0x20    /* Disable socket pullups? */

/* Fields in PD67_EXT_CTL_1 */
#define PD67_EC1_VCC_PWR_LOCK   0x01
#define PD67_EC1_AUTO_PWR_CLEAR 0x02
#define PD67_EC1_LED_ENA        0x04
#define PD67_EC1_INV_CARD_IRQ   0x08
#define PD67_EC1_INV_MGMT_IRQ   0x10
#define PD67_EC1_PULLUP_CTL     0x20

/* Fields in PD67_MISC_CTL_3 */
#define PD67_MC3_IRQ_MASK       0x03
#define PD67_MC3_IRQ_PCPCI      0x00
#define PD67_MC3_IRQ_EXTERN     0x01
#define PD67_MC3_IRQ_PCIWAY     0x02
#define PD67_MC3_IRQ_PCI        0x03
#define PD67_MC3_PWR_MASK       0x0c
#define PD67_MC3_PWR_SERIAL     0x00
#define PD67_MC3_PWR_TI2202     0x08
#define PD67_MC3_PWR_SMB        0x0c

/* Register definitions for Cirrus PD6832 PCI-to-CardBus bridge */

/* PD6832 extension registers -- indexed in PD67_EXT_INDEX */
#define PD68_EXT_CTL_2                  0x0b
#define PD68_PCI_SPACE                  0x22
#define PD68_PCCARD_SPACE               0x23
#define PD68_WINDOW_TYPE                0x24
#define PD68_EXT_CSC                    0x2e
#define PD68_MISC_CTL_4                 0x2f
#define PD68_MISC_CTL_5                 0x30
#define PD68_MISC_CTL_6                 0x31

/* Extra flags in PD67_MISC_CTL_3 */
#define PD68_MC3_HW_SUSP                0x10
#define PD68_MC3_MM_EXPAND              0x40
#define PD68_MC3_MM_ARM                 0x80

/* Bridge Control Register */
#define  PD6832_BCR_MGMT_IRQ_ENA        0x0800

/* Socket Number Register */
#define PD6832_SOCKET_NUMBER            0x004c  /* 8 bit */

#endif /* _LINUX_CIRRUS_H */



