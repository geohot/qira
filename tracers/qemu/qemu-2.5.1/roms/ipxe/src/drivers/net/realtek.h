#ifndef _REALTEK_H
#define _REALTEK_H

/** @file
 *
 * Realtek 10/100/1000 network card driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/spi.h>
#include <ipxe/spi_bit.h>
#include <ipxe/nvo.h>
#include <ipxe/if_ether.h>

/** PCI memory BAR size */
#define RTL_BAR_SIZE 0x100

/** A packet descriptor */
struct realtek_descriptor {
	/** Buffer size */
	uint16_t length;
	/** Flags */
	uint16_t flags;
	/** Reserved */
	uint32_t reserved;
	/** Buffer address */
	uint64_t address;
} __attribute__ (( packed ));

/** Descriptor buffer size mask */
#define RTL_DESC_SIZE_MASK 0x3fff

/** Packet descriptor flags */
enum realtek_descriptor_flags {
	/** Descriptor is owned by NIC */
	RTL_DESC_OWN = 0x8000,
	/** End of descriptor ring */
	RTL_DESC_EOR = 0x4000,
	/** First segment descriptor */
	RTL_DESC_FS = 0x2000,
	/** Last segment descriptor */
	RTL_DESC_LS = 0x1000,
	/** Receive error summary */
	RTL_DESC_RES = 0x0020,
};

/** Descriptor ring alignment */
#define RTL_RING_ALIGN 256

/** A legacy mode receive packet header */
struct realtek_legacy_header {
	/** Status */
	uint16_t status;
	/** Length */
	uint16_t length;
	/** Packet data */
	uint8_t data[0];
} __attribute__ (( packed ));

/** Legacy mode status bits */
enum realtek_legacy_status {
	/** Received OK */
	RTL_STAT_ROK = 0x0001,
};

/** ID Register 0 (6 bytes) */
#define RTL_IDR0 0x00

/** Multicast Register 0 (dword) */
#define RTL_MAR0 0x08

/** Multicast Register 4 (dword) */
#define RTL_MAR4 0x0c

/** Transmit Status of Descriptor N (dword, 8139 only) */
#define RTL_TSD(n) ( 0x10 + 4 * (n) )
#define RTL_TSD_ERTXTH(x)	( (x) << 16 ) /**< Early TX threshold */
#define RTL_TSD_ERTXTH_DEFAULT RTL_TSD_ERTXTH ( 256 / 32 )
#define RTL_TSD_OWN		0x00002000UL /**< Ownership */

/** Transmit Start Address of Descriptor N (dword, 8139 only) */
#define RTL_TSAD(n) ( 0x20 + 4 * (n) )

/** Transmit Normal Priority Descriptors (qword) */
#define RTL_TNPDS 0x20

/** Number of transmit descriptors
 *
 * This is a hardware limit when using legacy mode.
 */
#define RTL_NUM_TX_DESC 4

/** Receive Buffer Start Address (dword, 8139 only) */
#define RTL_RBSTART 0x30

/** Receive buffer length */
#define RTL_RXBUF_LEN 8192

/** Receive buffer padding */
#define RTL_RXBUF_PAD 2038 /* Allow space for WRAP */

/** Receive buffer alignment */
#define RTL_RXBUF_ALIGN 16

/** Command Register (byte) */
#define RTL_CR 0x37
#define RTL_CR_RST		0x10	/**< Reset */
#define RTL_CR_RE		0x08	/**< Receiver Enable */
#define RTL_CR_TE		0x04	/**< Transmit Enable */
#define RTL_CR_BUFE		0x01	/**< Receive buffer empty */

/** Maximum time to wait for a reset, in milliseconds */
#define RTL_RESET_MAX_WAIT_MS 100

/** Current Address of Packet Read (word, 8139 only) */
#define RTL_CAPR 0x38

/** Transmit Priority Polling Register (byte, 8169 only) */
#define RTL_TPPOLL_8169 0x38
#define RTL_TPPOLL_NPQ		0x40	/**< Normal Priority Queue Polling */

/** Interrupt Mask Register (word) */
#define RTL_IMR 0x3c
#define RTL_IRQ_PUN_LINKCHG	0x0020	/**< Packet underrun / link change */
#define RTL_IRQ_TER		0x0008	/**< Transmit error */
#define RTL_IRQ_TOK		0x0004	/**< Transmit OK */
#define RTL_IRQ_RER		0x0002	/**< Receive error */
#define RTL_IRQ_ROK		0x0001	/**< Receive OK */

/** Interrupt Status Register (word) */
#define RTL_ISR 0x3e

/** Transmit (Tx) Configuration Register (dword) */
#define RTL_TCR 0x40
#define RTL_TCR_MXDMA(x)	( (x) << 8 ) /**< Max DMA burst size */
#define RTL_TCR_MXDMA_MASK	RTL_TCR_MXDMA ( 0x7 )
#define RTL_TCR_MXDMA_DEFAULT	RTL_TCR_MXDMA ( 0x7 /* Unlimited */ )

/** Receive (Rx) Configuration Register (dword) */
#define RTL_RCR 0x44
#define RTL_RCR_STOP_WORKING	0x01000000UL /**< Here be dragons */
#define RTL_RCR_RXFTH(x)	( (x) << 13 ) /**< Receive FIFO threshold */
#define RTL_RCR_RXFTH_MASK	RTL_RCR_RXFTH ( 0x7 )
#define RTL_RCR_RXFTH_DEFAULT	RTL_RCR_RXFTH ( 0x7 /* Whole packet */ )
#define RTL_RCR_RBLEN(x)	( (x) << 11 ) /**< Receive buffer length */
#define RTL_RCR_RBLEN_MASK	RTL_RCR_RBLEN ( 0x3 )
#define RTL_RCR_RBLEN_DEFAULT	RTL_RCR_RBLEN ( 0 /* 8kB */ )
#define RTL_RCR_MXDMA(x)	( (x) << 8 ) /**< Max DMA burst size */
#define RTL_RCR_MXDMA_MASK	RTL_RCR_MXDMA ( 0x7 )
#define RTL_RCR_MXDMA_DEFAULT	RTL_RCR_MXDMA ( 0x7 /* Unlimited */ )
#define RTL_RCR_WRAP		0x00000080UL /**< Overrun receive buffer */
#define RTL_RCR_9356SEL		0x00000040UL /**< EEPROM is a 93C56 */
#define RTL_RCR_AB		0x00000008UL /**< Accept broadcast packets */
#define RTL_RCR_AM		0x00000004UL /**< Accept multicast packets */
#define RTL_RCR_APM		0x00000002UL /**< Accept physical match */
#define RTL_RCR_AAP		0x00000001UL /**< Accept all packets */

/** 93C46 (93C56) Command Register (byte) */
#define RTL_9346CR 0x50
#define RTL_9346CR_EEM(x)	( (x) << 6 ) /**< Mode select */
#define RTL_9346CR_EEM_EEPROM	RTL_9346CR_EEM ( 0x2 ) /**< EEPROM mode */
#define RTL_9346CR_EEM_NORMAL	RTL_9346CR_EEM ( 0x0 ) /**< Normal mode */
#define RTL_9346CR_EECS		0x08	/**< Chip select */
#define RTL_9346CR_EESK		0x04	/**< Clock */
#define RTL_9346CR_EEDI		0x02	/**< Data in */
#define RTL_9346CR_EEDO		0x01	/**< Data out */

/** Word offset of ID code word within EEPROM */
#define RTL_EEPROM_ID ( 0x00 / 2 )

/** EEPROM code word magic value */
#define RTL_EEPROM_ID_MAGIC 0x8129

/** Word offset of MAC address within EEPROM */
#define RTL_EEPROM_MAC ( 0x0e / 2 )

/** Word offset of VPD / non-volatile options within EEPROM */
#define RTL_EEPROM_VPD ( 0x40 / 2 )

/** Length of VPD / non-volatile options within EEPROM */
#define RTL_EEPROM_VPD_LEN 0x40

/** Configuration Register 1 (byte) */
#define RTL_CONFIG1 0x52
#define RTL_CONFIG1_VPD		0x02	/**< Vital Product Data enabled */

/** Media Status Register (byte, 8139 only) */
#define RTL_MSR 0x58
#define RTL_MSR_TXFCE		0x80	/**< TX flow control enabled */
#define RTL_MSR_RXFCE		0x40	/**< RX flow control enabled */
#define RTL_MSR_AUX_STATUS	0x10	/**< Aux power present */
#define RTL_MSR_SPEED_10	0x08	/**< 10Mbps */
#define RTL_MSR_LINKB		0x04	/**< Inverse of link status */
#define RTL_MSR_TXPF		0x02	/**< TX pause flag */
#define RTL_MSR_RXPF		0x01	/**< RX pause flag */

/** PHY Access Register (dword, 8169 only) */
#define RTL_PHYAR 0x60
#define RTL_PHYAR_FLAG		0x80000000UL /**< Read/write flag */

/** Construct PHY Access Register value */
#define RTL_PHYAR_VALUE( flag, reg, data ) ( (flag) | ( (reg) << 16 ) | (data) )

/** Extract PHY Access Register data */
#define RTL_PHYAR_DATA( value ) ( (value) & 0xffff )

/** Maximum time to wait for PHY access, in microseconds */
#define RTL_MII_MAX_WAIT_US 500

/** PHY (GMII, MII, or TBI) Status Register (byte, 8169 only) */
#define RTL_PHYSTATUS 0x6c
#define RTL_PHYSTATUS_ENTBI	0x80	/**< TBI / GMII mode */
#define RTL_PHYSTATUS_TXFLOW	0x40	/**< TX flow control enabled */
#define RTL_PHYSTATUS_RXFLOW	0x20	/**< RX flow control enabled */
#define RTL_PHYSTATUS_1000MF	0x10	/**< 1000Mbps full-duplex */
#define RTL_PHYSTATUS_100M	0x08	/**< 100Mbps */
#define RTL_PHYSTATUS_10M	0x04	/**< 10Mbps */
#define RTL_PHYSTATUS_LINKSTS	0x02	/**< Link ok */
#define RTL_PHYSTATUS_FULLDUP	0x01	/**< Full duplex */

/** Transmit Priority Polling Register (byte, 8139C+ only) */
#define RTL_TPPOLL_8139CP 0xd9

/** RX Packet Maximum Size Register (word) */
#define RTL_RMS 0xda

/** C+ Command Register (word) */
#define RTL_CPCR 0xe0
#define RTL_CPCR_DAC		0x0010	/**< PCI Dual Address Cycle Enable */
#define RTL_CPCR_MULRW		0x0008	/**< PCI Multiple Read/Write Enable */
#define RTL_CPCR_CPRX		0x0002	/**< C+ receive enable */
#define RTL_CPCR_CPTX		0x0001	/**< C+ transmit enable */

/** Receive Descriptor Start Address Register (qword) */
#define RTL_RDSAR 0xe4

/** Number of receive descriptors */
#define RTL_NUM_RX_DESC 4

/** Receive buffer length */
#define RTL_RX_MAX_LEN \
	( ETH_FRAME_LEN + 4 /* VLAN */ + 4 /* CRC */ + 4 /* extra space */ )

/** A Realtek descriptor ring */
struct realtek_ring {
	/** Descriptors */
	struct realtek_descriptor *desc;
	/** Producer index */
	unsigned int prod;
	/** Consumer index */
	unsigned int cons;

	/** Descriptor start address register */
	unsigned int reg;
	/** Length (in bytes) */
	size_t len;
};

/**
 * Initialise descriptor ring
 *
 * @v ring		Descriptor ring
 * @v count		Number of descriptors
 * @v reg		Descriptor start address register
 */
static inline __attribute__ (( always_inline)) void
realtek_init_ring ( struct realtek_ring *ring, unsigned int count,
		    unsigned int reg ) {
	ring->len = ( count * sizeof ( ring->desc[0] ) );
	ring->reg = reg;
}

/** A Realtek network card */
struct realtek_nic {
	/** Registers */
	void *regs;
	/** SPI bit-bashing interface */
	struct spi_bit_basher spibit;
	/** EEPROM */
	struct spi_device eeprom;
	/** Non-volatile options */
	struct nvo_block nvo;
	/** MII interface */
	struct mii_interface mii;

	/** Legacy datapath mode */
	int legacy;
	/** PHYAR and PHYSTATUS registers are present */
	int have_phy_regs;
	/** TPPoll register offset */
	unsigned int tppoll;

	/** Transmit descriptor ring */
	struct realtek_ring tx;
	/** Receive descriptor ring */
	struct realtek_ring rx;
	/** Receive I/O buffers */
	struct io_buffer *rx_iobuf[RTL_NUM_RX_DESC];
	/** Receive buffer (legacy mode) */
	void *rx_buffer;
	/** Offset within receive buffer (legacy mode) */
	unsigned int rx_offset;
};

#endif /* _REALTEK_H */
