#ifndef _VELOCITY_H
#define _VELOCITY_H

/** @file
 *
 * VIA Velocity network driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

/** Skeleton BAR size */
#define	VELOCITY_BAR_SIZE 	256

/** Default timeout */
#define	VELOCITY_TIMEOUT_US	10 * 1000

struct velocity_frag {
	uint32_t	addr;
	uint32_t	des2;
} __attribute__ ((packed));

/** Velocity descriptor format */
struct velocity_tx_descriptor {
	uint32_t	des0;
	uint32_t	des1;
	/* We only use the first fragment, the HW requires us to have 7 */
	struct velocity_frag frags[7];
} __attribute__ ((packed));

struct velocity_rx_descriptor {
	uint32_t	des0;
	uint32_t	des1;
	uint32_t	addr;
	uint32_t	des2;
} __attribute__ ((packed));

#define	VELOCITY_DES0_RMBC(_n)	(((_n) >> 16) & 0x1fff)
#define	VELOCITY_DES0_OWN	(1 << 31)
#define	VELOCITY_DES0_TERR	(1 << 15)
#define	VELOCITY_DES0_RXOK	(1 << 15)
#define	VELOCITY_DES0_FDX	(1 << 14)
#define	VELOCITY_DES0_GMII	(1 << 13)
#define	VELOCITY_DES0_LNKFL	(1 << 12)
#define	VELOCITY_DES0_SHDN	(1 << 10)
#define	VELOCITY_DES0_CRS	(1 << 9)
#define	VELOCITY_DES0_CDH	(1 << 8)
#define	VELOCITY_DES0_ABT	(1 << 7)
#define	VELOCITY_DES0_OWT	(1 << 6)
#define	VELOCITY_DES0_OWC	(1 << 5)
#define	VELOCITY_DES0_COLS	(1 << 4)

#define VELOCITY_DES0_RXSHDN	(1 << 30)
#define VELOCITY_DES0_RXER	(1 << 5)
#define VELOCITY_DES0_RLE	(1 << 4)
#define VELOCITY_DES0_CE	(1 << 3)
#define VELOCITY_DES0_FAE	(1 << 2)
#define VELOCITY_DES0_CRC	(1 << 1)
#define VELOCITY_DES0_RX_ERR	( VELOCITY_DES0_RXER | \
                                  VELOCITY_DES0_RLE | \
                                  VELOCITY_DES0_CE | \
                                  VELOCITY_DES0_FAE | \
                                  VELOCITY_DES0_CRC )

/** TX descriptor fragment number */
#define	VELOCITY_DES1_FRAG(_n)	(((_n + 1) & 0xf) << 28)
#define	VELOCITY_DES1_TCPLS	((1 << 24) | (1 << 25))
#define	VELOCITY_DES1_INTR	(1 << 23)
#define	VELOCITY_DES1_PIC	(1 << 22)
#define	VELOCITY_DES1_VETAG	(1 << 21)
#define	VELOCITY_DES1_IPCK	(1 << 20)
#define	VELOCITY_DES1_UDPCK	(1 << 19)
#define VELOCITY_DES1_TCPCK	(1 << 18)
#define	VELOCITY_DES1_JMBO	(1 << 17)
#define	VELOCITY_DES1_CRC	(1 << 16)

#define	VELOCITY_DES2_IC	(1 << 31)
#define	VELOCITY_DES2_SIZE(_n)	(((_n) & 0x1fff) << 16)

/** Number of receive descriptors
 *
 * Must be a multiple of 4 (hardware requirement).
 */
#define	VELOCITY_RXDESC_NUM	8
#define	VELOCITY_RXDESC_SIZE	\
    ( VELOCITY_RXDESC_NUM * sizeof ( struct velocity_rx_descriptor ) )

/** Number of transmit descriptors */
#define	VELOCITY_TXDESC_NUM	8
#define	VELOCITY_TXDESC_SIZE	\
    ( VELOCITY_TXDESC_NUM * sizeof ( struct velocity_tx_descriptor ) )

/** Descriptor alignment */
#define	VELOCITY_RING_ALIGN	64

/** Receive buffer length */
#define VELOCITY_RX_MAX_LEN 1536

/** MAC address registers */
#define VELOCITY_MAC0		0x00
#define VELOCITY_MAC1		0x01
#define	VELOCITY_MAC2		0x02
#define VELOCITY_MAC3		0x03
#define	VELOCITY_MAC4		0x04
#define	VELOCITY_MAC5		0x05

/** Receive control register */
#define VELOCITY_RCR		0x06
#define	RHINE_RCR_SYMERR_ACCEPT	(1 << 7)	/*< Accept symbol error */
#define	RHINE_RCR_FILTER_ACCEPT	(1 << 6)	/*< Accept based on filter */
#define	RHINE_RCR_LONG_ACCEPT	(1 << 5)	/*< Accept long packets */
#define	RHINE_RCR_PROMISC	(1 << 4)	/*< Promiscuous mode */
#define	RHINE_RCR_BCAST_ACCEPT	(1 << 3)	/*< Accept broadcast */
#define	RHINE_RCR_MCAST_ACCEPT	(1 << 2)	/*< Accept multicast */
#define	RHINE_RCR_RUNT_ACCEPT	(1 << 1)	/*< Accept runt frames */
#define	RHINE_RCR_ERR_ACCEPT	(1 << 0)	/*< Accept erroneous frames */

/** Transmit control register */
#define VELOCITY_TCR			0x07
#define	VELOCITY_TCR_LB0	(1 << 0)	/*< Loopback control */
#define	VELOCITY_TCR_LB1	(1 << 1)	/*< Loopback control */
#define	VELOCITY_TCR_COLTMC0	(1 << 2)	/*< Collision retry control */
#define	VELOCITY_TCR_COLTMC1	(1 << 3)	/*< Collision retry control */

/** Command register 0 (set) */
#define VELOCITY_CRS0			0x08
#define	VELOCITY_CR0_TXON	(1 << 3)	/*< Transmit enable */
#define	VELOCITY_CR0_RXON	(1 << 2)	/*< Receive enable */
#define	VELOCITY_CR0_STOP	(1 << 1)	/*< Stop NIC */
#define	VELOCITY_CR0_START	(1 << 0)	/*< Start NIC */

/** Command register 1 (set) */
#define VELOCITY_CRS1			0x09
#define	VELOCITY_CR1_SFRST	(1 << 7)	/*< Software reset */
#define	VELOCITY_CR1_TM1EN	(1 << 6)	/*< Perioding software counting */
#define	VELOCITY_CR1_TM0EN	(1 << 5)	/*< Single-shot software counting */
#define	VELOCITY_CR1_DPOLL	(1 << 3)	/*< Disable auto polling */
#define	VELOCITY_CR1_DISAU	(1 << 0)	/*< Unicast reception disable */

/** Command register 2 (set) */
#define VELOCITY_CRS2			0x0A
#define	VELOCITY_CR2_XONEN	(1 << 7)	/*< XON/XOFF mode enable */
#define	VELOCITY_CR2_FDXTFCEN	(1 << 6)	/*< FDX flow control TX */
#define	VELOCITY_CR2_FDXRFCEN	(1 << 5)
#define	VELOCITY_CR2_HDXFCEN	(1 << 4)

/** Command register 3 (set) */
#define VELOCITY_CRS3			0x0B
#define	VELOCITY_CR3_FOSRST		(1 << 6)
#define	VELOCITY_CR3_FPHYRST		(1 << 5)
#define	VELOCITY_CR3_DIAG		(1 << 4)
#define	VELOCITY_CR3_INTPCTL		(1 << 2)
#define	VELOCITY_CR3_GINTMSK1		(1 << 1)
#define	VELOCITY_CR3_SWPEND		(1 << 0)

/** Command register 0 (clear) */
#define VELOCITY_CRC0			0x0C

/** Command register 1 (clear) */
#define VELOCITY_CRC1			0x0D

/** Command register 2 (clear */
#define VELOCITY_CRC2			0x0E

/** Command register 3 (clear */
#define VELOCITY_CRC3			0x0F
#define VELOCITY_CAM0			0x10
#define VELOCITY_CAM1			0x11
#define VELOCITY_CAM2			0x12
#define VELOCITY_CAM3			0x13
#define VELOCITY_CAM4			0x14
#define VELOCITY_CAM5			0x15
#define VELOCITY_CAM6			0x16
#define VELOCITY_CAM7			0x17
#define VELOCITY_TXDESC_HI		0x18    /* Hi part of 64bit txdesc base addr */
#define VELOCITY_DATABUF_HI		0x1D    /* Hi part of 64bit data buffer addr */
#define VELOCITY_INTCTL0		0x20    /* interrupt control register */
#define VELOCITY_RXSUPPTHR		0x20
#define VELOCITY_TXSUPPTHR		0x20
#define VELOCITY_INTHOLDOFF		0x20
#define VELOCITY_INTCTL1		0x21    /* interrupt control register */
#define VELOCITY_TXHOSTERR		0x22    /* TX host error status */
#define VELOCITY_RXHOSTERR		0x23    /* RX host error status */

/** Interrupt status register 0 */
#define VELOCITY_ISR0			0x24
#define	VELOCITY_ISR0_PTX3		(1 << 7)
#define	VELOCITY_ISR0_PTX2		(1 << 6)
#define VELOCITY_ISR0_PTX1		(1 << 5)
#define VELOCITY_ISR0_PTX0		(1 << 4)
#define VELOCITY_ISR0_PTXI		(1 << 3)
#define VELOCITY_ISR0_PRXI		(1 << 2)
#define VELOCITY_ISR0_PPTXI		(1 << 1)
#define VELOCITY_ISR0_PPRXI		(1 << 0)

/** Interrupt status register 1 */
#define VELOCITY_ISR1			0x25
#define VELOCITY_ISR1_SRCI		(1 << 7)
#define VELOCITY_ISR1_LSTPEI		(1 << 6)
#define VELOCITY_ISR1_LSTEI		(1 << 5)
#define VELOCITY_ISR1_OVFL		(1 << 4)
#define VELOCITY_ISR1_FLONI		(1 << 3)
#define VELOCITY_ISR1_RACEI		(1 << 2)

/** Interrupt status register 2 */
#define VELOCITY_ISR2			0x26
#define VELOCITY_ISR2_HFLD		(1 << 7)
#define VELOCITY_ISR2_UDPI		(1 << 6)
#define VELOCITY_ISR2_MIBFI		(1 << 5)
#define VELOCITY_ISR2_SHDNII		(1 << 4)
#define VELOCITY_ISR2_PHYI		(1 << 3)
#define VELOCITY_ISR2_PWEI		(1 << 2)
#define VELOCITY_ISR2_TMR1I		(1 << 1)
#define VELOCITY_ISR2_TMR0I		(1 << 0)

/** Interrupt status register 3 */
#define VELOCITY_ISR3			0x27

/** Interrupt mask register 0 */
#define VELOCITY_IMR0			0x28

/** Interrupt mask register 1 */
#define VELOCITY_IMR1			0x29

/** Interrupt mask register 2 */
#define VELOCITY_IMR2			0x2a

/** Interrupt mask register 3 */
#define VELOCITY_IMR3			0x2b

#define VELOCITY_TXSTS_PORT		0x2C    /* Transmit status port (???) */
#define VELOCITY_TXQCSRS		0x30    /* TX queue ctl/status set */

#define	VELOCITY_TXQCSRS_DEAD3		(1 << 15)
#define	VELOCITY_TXQCSRS_WAK3		(1 << 14)
#define	VELOCITY_TXQCSRS_ACT3		(1 << 13)
#define	VELOCITY_TXQCSRS_RUN3		(1 << 12)
#define	VELOCITY_TXQCSRS_DEAD2		(1 << 11)
#define	VELOCITY_TXQCSRS_WAK2		(1 << 10)
#define	VELOCITY_TXQCSRS_ACT2		(1 << 9)
#define	VELOCITY_TXQCSRS_RUN2		(1 << 8)
#define VELOCITY_TXQCSRS_DEAD1		(1 << 7)
#define	VELOCITY_TXQCSRS_WAK1		(1 << 6)
#define	VELOCITY_TXQCSRS_ACT1		(1 << 5)
#define VELOCITY_TXQCSRS_RUN1		(1 << 4)
#define	VELOCITY_TXQCSRS_DEAD0		(1 << 3)
#define	VELOCITY_TXQCSRS_WAK0		(1 << 2)
#define	VELOCITY_TXQCSRS_ACT0		(1 << 1)
#define	VELOCITY_TXQCSRS_RUN0		(1 << 0)

#define VELOCITY_RXQCSRS		0x32    /* RX queue ctl/status set */
#define VELOCITY_RXQCSRC		0x36

#define	VELOCITY_RXQCSR_DEAD		(1 << 3)
#define	VELOCITY_RXQCSR_WAK		(1 << 2)
#define	VELOCITY_RXQCSR_ACT		(1 << 1)
#define	VELOCITY_RXQCSR_RUN		(1 << 0)

#define VELOCITY_TXQCSRC		0x34    /* TX queue ctl/status clear */
#define VELOCITY_RXQCSRC		0x36    /* RX queue ctl/status clear */
#define VELOCITY_RXDESC_ADDR_LO		0x38    /* RX desc base addr (lo 32 bits) */
#define VELOCITY_RXDESC_CONSIDX		0x3C    /* Current RX descriptor index */
#define VELOCITY_TXQTIMER		0x3E    /* TX queue timer pend register */
#define VELOCITY_RXQTIMER		0x3F    /* RX queue timer pend register */
#define VELOCITY_TXDESC_ADDR_LO0	0x40    /* TX desc0 base addr (lo 32 bits) */
#define VELOCITY_TXDESC_ADDR_LO1	0x44    /* TX desc1 base addr (lo 32 bits) */
#define VELOCITY_TXDESC_ADDR_LO2	0x48    /* TX desc2 base addr (lo 32 bits) */
#define VELOCITY_TXDESC_ADDR_LO3	0x4C    /* TX desc3 base addr (lo 32 bits) */
#define VELOCITY_RXDESCNUM		0x50    /* Size of RX desc ring */
#define VELOCITY_TXDESCNUM		0x52    /* Size of TX desc ring */
#define VELOCITY_TXDESC_CONSIDX0	0x54    /* Current TX descriptor index */
#define VELOCITY_TXDESC_CONSIDX1	0x56    /* Current TX descriptor index */
#define VELOCITY_TXDESC_CONSIDX2	0x58    /* Current TX descriptor index */
#define VELOCITY_TXDESC_CONSIDX3	0x5A    /* Current TX descriptor index */
#define VELOCITY_TX_PAUSE_TIMER		0x5C    /* TX pause frame timer */
#define VELOCITY_RXDESC_RESIDUECNT	0x5E    /* RX descriptor residue count */
#define VELOCITY_FIFOTEST0		0x60    /* FIFO test register */
#define VELOCITY_FIFOTEST1		0x64    /* FIFO test register */
#define VELOCITY_CAMADDR		0x68    /* CAM address register */
#define VELOCITY_CAMCTL			0x69    /* CAM control register */
#define VELOCITY_MIICFG			0x6C    /* MII port config register */
#define VELOCITY_MIISR			0x6D    /* MII port status register */
#define	VELOCITY_MIISR_IDLE		(1 << 7)
#define VELOCITY_PHYSTS0		0x6E    /* PHY status register */
#define	VELOCITY_PHYSTS0_LINK		(1 << 6)
#define VELOCITY_PHYSTS1		0x6F    /* PHY status register */
#define VELOCITY_MIICR			0x70    /* MII command register */
#define VELOCITY_MIICR_MAUTO		(1 << 7)
#define VELOCITY_MIICR_RCMD		(1 << 6)
#define VELOCITY_MIICR_WCMD		(1 << 5)
#define VELOCITY_MIICR_MDPM		(1 << 4)
#define VELOCITY_MIICR_MOUT		(1 << 3)
#define VELOCITY_MIICR_MDO		(1 << 2)
#define VELOCITY_MIICR_MDI		(1 << 1)
#define VELOCITY_MIICR_MDC		(1 << 0)

#define VELOCITY_MIIADDR		0x71    /* MII address register */
#define VELOCITY_MIIDATA		0x72    /* MII data register */
#define VELOCITY_SSTIMER		0x74    /* single-shot timer */
#define VELOCITY_PTIMER			0x76    /* periodic timer */
#define VELOCITY_DMACFG0		0x7C    /* DMA config 0 */
#define VELOCITY_DMACFG1		0x7D    /* DMA config 1 */
#define VELOCITY_RXCFG			0x7E    /* MAC RX config */
#define VELOCITY_TXCFG			0x7F    /* MAC TX config */
#define VELOCITY_SWEEDATA		0x85    /* EEPROM software loaded data */

/** Chip Configuration Register A */
#define VELOCITY_CFGA			0x78
#define VELOCITY_CFGA_PACPI		(1 << 0)

/** Power Management Sticky Register */
#define VELOCITY_STICKY			0x83
#define VELOCITY_STICKY_DS0		(1 << 0)
#define VELOCITY_STICKY_DS1		(1 << 1)

#define VELOCITY_EEWRDAT		0x8C    /* EEPROM embedded write */
#define VELOCITY_EECSUM			0x92    /* EEPROM checksum */
#define VELOCITY_EECSR			0x93    /* EEPROM control/status */
#define	VELOCITY_EECSR_RELOAD		(1 << 5)
#define VELOCITY_EERDDAT		0x94    /* EEPROM embedded read */
#define VELOCITY_EEADDR			0x96    /* EEPROM address */
#define VELOCITY_EECMD			0x97    /* EEPROM embedded command */

/** A Velocity network card */
struct velocity_nic {
	/** Registers */
	void *regs;
	/** MII interface */
	struct mii_interface mii;
	/** Netdev */
	struct net_device *netdev;

	/** Receive descriptor ring */
	struct velocity_rx_descriptor *rx_ring;
	/** Receive I/O buffers */
	struct io_buffer *rx_buffs[VELOCITY_RXDESC_NUM];
	/** Receive producer index */
	unsigned int rx_prod;
	/** Receive consumer index */
	unsigned int rx_cons;
	/** Receive commit number
	  *
	  * Used to fullfill the hardware requirement of returning receive buffers
	  * to the hardware only in blocks of 4.
	  */
	unsigned int rx_commit;

	/** Transmit descriptor ring */
	struct velocity_tx_descriptor *tx_ring;
	/** Transmit producer index */
	unsigned int tx_prod;
	/** Transmit consumer index */
	unsigned int tx_cons;
};

#endif /* _VELOCITY_H */
