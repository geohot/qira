#ifndef _RHINE_H
#define _RHINE_H

/** @file
 *
 * VIA Rhine network driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

/** Rhine BAR size */
#define RHINE_BAR_SIZE		256

/** Default timeout */
#define	RHINE_TIMEOUT_US	10000

/** Rhine descriptor format */
struct rhine_descriptor {
	uint32_t	des0;
	uint32_t	des1;
	uint32_t	buffer;
	uint32_t	next;
} __attribute__ (( packed ));

#define	RHINE_DES0_OWN		(1 << 31)	/*< Owned descriptor */
#define RHINE_DES1_IC		(1 << 23)	/*< Generate interrupt */
#define	RHINE_TDES1_EDP		(1 << 22)	/*< End of packet */
#define	RHINE_TDES1_STP		(1 << 21)	/*< Start of packet */
#define	RHINE_TDES1_TCPCK	(1 << 20)	/*< HW TCP checksum */
#define	RHINE_TDES1_UDPCK	(1 << 19)	/*< HW UDP checksum */
#define	RHINE_TDES1_IPCK	(1 << 18)	/*< HW IP checksum */
#define	RHINE_TDES1_TAG		(1 << 17)	/*< Tagged frame */
#define	RHINE_TDES1_CRC		(1 << 16)	/*< No CRC */
#define	RHINE_DES1_CHAIN	(1 << 15)	/*< Chained descriptor */
#define	RHINE_DES1_SIZE(_x)	((_x) & 0x7ff)	/*< Frame size */
#define	RHINE_DES0_GETSIZE(_x)	(((_x) >> 16) & 0x7ff)

#define	RHINE_RDES0_RXOK	(1 << 15)
#define	RHINE_RDES0_VIDHIT	(1 << 14)
#define	RHINE_RDES0_MAR		(1 << 13)
#define	RHINE_RDES0_BAR		(1 << 12)
#define	RHINE_RDES0_PHY		(1 << 11)
#define	RHINE_RDES0_CHN		(1 << 10)
#define	RHINE_RDES0_STP		(1 << 9)
#define	RHINE_RDES0_EDP		(1 << 8)
#define	RHINE_RDES0_BUFF	(1 << 7)
#define	RHINE_RDES0_FRAG	(1 << 6)
#define	RHINE_RDES0_RUNT	(1 << 5)
#define	RHINE_RDES0_LONG	(1 << 4)
#define	RHINE_RDES0_FOV		(1 << 3)
#define	RHINE_RDES0_FAE		(1 << 2)
#define	RHINE_RDES0_CRCE	(1 << 1)
#define	RHINE_RDES0_RERR	(1 << 0)

#define	RHINE_TDES0_TERR	(1 << 15)
#define	RHINE_TDES0_UDF		(1 << 11)
#define	RHINE_TDES0_CRS		(1 << 10)
#define	RHINE_TDES0_OWC		(1 << 9)
#define	RHINE_TDES0_ABT		(1 << 8)
#define	RHINE_TDES0_CDH		(1 << 7)
#define	RHINE_TDES0_COLS	(1 << 4)
#define	RHINE_TDES0_NCR(_x)	((_x) & 0xf)

#define	RHINE_RING_ALIGN	4

/** Rhine descriptor rings sizes */
#define	RHINE_RXDESC_NUM	4
#define	RHINE_TXDESC_NUM	8
#define	RHINE_RX_MAX_LEN	1536

/** Rhine MAC address registers */
#define	RHINE_MAC		0x00

/** Receive control register */
#define	RHINE_RCR		0x06
#define	RHINE_RCR_FIFO_TRSH(_x)	(((_x) & 0x7) << 5) /*< RX FIFO threshold */
#define	RHINE_RCR_PHYS_ACCEPT	(1 << 4)	/*< Accept matching PA */
#define	RHINE_RCR_BCAST_ACCEPT	(1 << 3)	/*< Accept broadcast */
#define	RHINE_RCR_MCAST_ACCEPT	(1 << 2)	/*< Accept multicast */
#define	RHINE_RCR_RUNT_ACCEPT	(1 << 1)	/*< Accept runt frames */
#define	RHINE_RCR_ERR_ACCEPT	(1 << 0)	/*< Accept erroneous frames */

/** Transmit control register */
#define	RHINE_TCR		0x07
#define	RHINE_TCR_LOOPBACK(_x)	(((_x) & 0x3) << 1) /*< Transmit loop mode */
#define	RHINE_TCR_TAGGING	(1 << 0)	/*< 802.1P/Q packet tagging */

/** Command 0 register */
#define	RHINE_CR0		0x08
#define	RHINE_CR0_RXSTART	(1 << 6)
#define	RHINE_CR0_TXSTART	(1 << 5)
#define	RHINE_CR0_TXEN		(1 << 4)	/*< Transmit enable */
#define	RHINE_CR0_RXEN		(1 << 3)	/*< Receive enable */
#define	RHINE_CR0_STOPNIC	(1 << 2)	/*< Stop NIC */
#define	RHINE_CR0_STARTNIC	(1 << 1)	/*< Start NIC */

/** Command 1 register */
#define	RHINE_CR1		0x09
#define	RHINE_CR1_RESET		(1 << 7)	/*< Software reset */
#define	RHINE_CR1_RXPOLL	(1 << 6)	/*< Receive poll demand */
#define	RHINE_CR1_TXPOLL	(1 << 5)	/*< Xmit poll demand */
#define	RHINE_CR1_AUTOPOLL	(1 << 3)	/*< Disable autopoll */
#define	RHINE_CR1_FDX		(1 << 2)	/*< Full duplex */
#define	RIHNE_CR1_ACCUNI	(1 << 1)	/*< Disable accept unicast */

/** Transmit queue wake register */
#define	RHINE_TXQUEUE_WAKE	0x0a

/** Interrupt service 0 */
#define	RHINE_ISR0		0x0c
#define	RHINE_ISR0_MIBOVFL	(1 << 7)
#define	RHINE_ISR0_PCIERR	(1 << 6)
#define	RHINE_ISR0_RXRINGERR	(1 << 5)
#define	RHINE_ISR0_TXRINGERR	(1 << 4)
#define	RHINE_ISR0_TXERR	(1 << 3)
#define	RHINE_ISR0_RXERR	(1 << 2)
#define	RHINE_ISR0_TXDONE	(1 << 1)
#define	RHINE_ISR0_RXDONE	(1 << 0)

/** Interrupt service 1 */
#define	RHINE_ISR1		0x0d
#define	RHINE_ISR1_GPI		(1 << 7)
#define	RHINE_ISR1_PORTSTATE	(1 << 6)
#define	RHINE_ISR1_TXABORT	(1 << 5)
#define	RHINE_ISR1_RXNOBUF	(1 << 4)
#define	RHINE_ISR1_RXFIFOOVFL	(1 << 3)
#define	RHINE_ISR1_RXFIFOUNFL	(1 << 2)
#define	RHINE_ISR1_TXFIFOUNFL	(1 << 1)
#define	RHINE_ISR1_EARLYRX	(1 << 0)

/** Interrupt enable mask register 0 */
#define	RHINE_IMR0		0x0e

/** Interrupt enable mask register 1 */
#define	RHINE_IMR1		0x0f

/** RX queue descriptor base address */
#define	RHINE_RXQUEUE_BASE	0x18

/** TX queue 0 descriptor base address */
#define	RHINE_TXQUEUE_BASE	0x1c

/** MII configuration */
#define	RHINE_MII_CFG		0x6c

/** MII status register */
#define	RHINE_MII_SR		0x6d
#define	RHINE_MII_SR_PHYRST	(1 << 7)	/*< PHY reset */
#define	RHINE_MII_SR_LINKNWAY	(1 << 4)	/*< Link status after N-Way */
#define	RHINE_MII_SR_PHYERR	(1 << 3)	/*< PHY device error */
#define	RHINE_MII_SR_DUPLEX	(1 << 2)	/*< Duplex mode after N-Way */
#define	RHINE_MII_SR_LINKPOLL	(1 << 1)	/*< Link status after poll */
#define	RHINE_MII_SR_LINKSPD	(1 << 0)	/*< Link speed after N-Way */

/** MII bus control 0 register */
#define	RHINE_MII_BCR0		0x6e

/** MII bus control 1 register */
#define	RHINE_MII_BCR1		0x6f

/** MII control register */
#define	RHINE_MII_CR		0x70
#define	RHINE_MII_CR_AUTOPOLL	(1 << 7)	/*< MII auto polling */
#define	RHINE_MII_CR_RDEN	(1 << 6)	/*< PHY read enable */
#define	RHINE_MII_CR_WREN	(1 << 5)	/*< PHY write enable */
#define	RHINE_MII_CR_DIRECT	(1 << 4)	/*< Direct programming mode */
#define	RHINE_MII_CR_MDIOOUT	(1 << 3)	/*< MDIO output enable */

/** MII port address */
#define	RHINE_MII_ADDR		0x71
#define	RHINE_MII_ADDR_MSRCEN	(1 << 6)
#define	RHINE_MII_ADDR_MDONE	(1 << 5)

/** MII read/write data */
#define	RHINE_MII_RDWR		0x72

/** EERPOM control/status register */
#define	RHINE_EEPROM_CTRL	0x74
#define	RHINE_EEPROM_CTRL_STATUS	(1 << 7) /*< EEPROM status */
#define	RHINE_EEPROM_CTRL_RELOAD	(1 << 5) /*< EEPROM reload */

/** Chip configuration A */
#define	RHINE_CHIPCFG_A		0x78
/* MMIO enable. Only valid for Rhine I. Reserved on later boards */
#define RHINE_CHIPCFG_A_MMIO	(1 << 5)

/** Chip configuration B */
#define	RHINE_CHIPCFG_B		0x79

/** Chip configuation C */
#define	RHINE_CHIPCFG_C		0x7a

/** Chip configuration D */
#define	RHINE_CHIPCFG_D		0x7b
/* MMIO enable. Only valid on Rhine II and later. GPIOEN on Rhine I */
#define RHINE_CHIPCFG_D_MMIO	(1 << 7)

#define RHINE_REVISION_OLD	0x20

/** A VIA Rhine descriptor ring */
struct rhine_ring {
	/** Descriptors */
	struct rhine_descriptor *desc;
	/** Producer index */
	unsigned int prod;
	/** Consumer index */
	unsigned int cons;

	/** Number of descriptors */
	unsigned int count;
	/** Register address */
	unsigned int reg;
};

/**
 * Initialise descriptor ring
 *
 * @v ring		Descriptor ring
 * @v count		Number of descriptors (must be a power of 2)
 * @v reg		Register address
 */
static inline __attribute__ (( always_inline)) void
rhine_init_ring ( struct rhine_ring *ring, unsigned int count,
		  unsigned int reg ) {
	ring->count = count;
	ring->reg = reg;
}

/** A VIA Rhine network card */
struct rhine_nic {
	/** I/O address (some PIO access is always required) */
	unsigned long ioaddr;
	/** Registers */
	void *regs;
	/** Cached value of CR1 (to avoid read-modify-write on fast path) */
	uint8_t cr1;

	/** MII interface */
	struct mii_interface mii;

	/** Transmit descriptor ring */
	struct rhine_ring tx;
	/** Receive descriptor ring */
	struct rhine_ring rx;
	/** Receive I/O buffers */
	struct io_buffer *rx_iobuf[RHINE_RXDESC_NUM];
};

#endif /* _RHINE_H */
