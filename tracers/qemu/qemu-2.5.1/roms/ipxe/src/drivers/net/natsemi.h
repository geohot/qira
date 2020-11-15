#ifndef _NATSEMI_H
#define _NATSEMI_H

/** @file
 *
 * National Semiconductor "MacPhyter" network card driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <ipxe/spi.h>
#include <ipxe/spi_bit.h>

/** BAR size */
#define NATSEMI_BAR_SIZE 0x100

/** A 32-bit packet descriptor */
struct natsemi_descriptor_32 {
	/** Link to next descriptor */
	uint32_t link;
	/** Command / status */
	uint32_t cmdsts;
	/** Buffer pointer */
	uint32_t bufptr;
} __attribute__ (( packed ));

/** A 64-bit packet descriptor */
struct natsemi_descriptor_64 {
	/** Link to next descriptor */
	uint64_t link;
	/** Buffer pointer */
	uint64_t bufptr;
	/** Command / status */
	uint32_t cmdsts;
	/** Extended status */
	uint32_t extsts;
} __attribute__ (( packed ));

/** A packet descriptor
 *
 * The 32-bit and 64-bit variants are overlaid such that "cmdsts" can
 * be accessed as a common field, and the overall size is a power of
 * two (to allow the descriptor ring length to be used as an
 * alignment).
 */
union natsemi_descriptor {
	/** Common fields */
	struct {
		/** Reserved */
		uint8_t reserved_a[16];
		/** Command / status */
		uint32_t cmdsts;
		/** Reserved */
		uint8_t reserved_b[12];
	} __attribute__ (( packed )) common;
	/** 64-bit descriptor */
	struct natsemi_descriptor_64 d64;
	/** 32-bit descriptor */
	struct {
		/** Reserved */
		uint8_t reserved[12];
		/** Descriptor */
		struct natsemi_descriptor_32 d32;
	} __attribute__ (( packed )) d32pad;
};

/** Descriptor buffer size mask */
#define NATSEMI_DESC_SIZE_MASK 0xfff

/** Packet descriptor flags */
enum natsemi_descriptor_flags {
	/** Descriptor is owned by NIC */
	NATSEMI_DESC_OWN = 0x80000000UL,
	/** Request descriptor interrupt */
	NATSEMI_DESC_INTR = 0x20000000UL,
	/** Packet OK */
	NATSEMI_DESC_OK = 0x08000000UL,
};

/** Command Register */
#define NATSEMI_CR 0x0000
#define NATSEMI_CR_RST		0x00000100UL	/**< Reset */
#define NATSEMI_CR_RXR		0x00000020UL	/**< Receiver reset */
#define NATSEMI_CR_TXR		0x00000010UL	/**< Transmit reset */
#define NATSEMI_CR_RXE		0x00000004UL	/**< Receiver enable */
#define NATSEMI_CR_TXE		0x00000001UL	/**< Transmit enable */

/** Maximum time to wait for a reset, in milliseconds */
#define NATSEMI_RESET_MAX_WAIT_MS 100

/** Configuration and Media Status Register */
#define NATSEMI_CFG 0x0004
#define NATSEMI_CFG_LNKSTS	0x80000000UL	/**< Link status */
#define NATSEMI_CFG_SPDSTS1	0x40000000UL	/**< Speed status bit 1 */
#define NATSEMI_CFG_MODE_1000	0x00400000UL	/**< 1000 Mb/s mode control */
#define NATSEMI_CFG_PCI64_DET	0x00002000UL	/**< PCI 64-bit bus detected */
#define NATSEMI_CFG_DATA64_EN	0x00001000UL	/**< 64-bit data enable */
#define NATSEMI_CFG_M64ADDR	0x00000800UL	/**< 64-bit address enable */
#define NATSEMI_CFG_EXTSTS_EN	0x00000100UL	/**< Extended status enable */

/** EEPROM Access Register */
#define NATSEMI_MEAR 0x0008
#define NATSEMI_MEAR_EESEL	0x00000008UL	/**< EEPROM chip select */
#define NATSEMI_MEAR_EECLK	0x00000004UL	/**< EEPROM serial clock */
#define NATSEMI_MEAR_EEDO	0x00000002UL	/**< EEPROM data out */
#define NATSEMI_MEAR_EEDI	0x00000001UL	/**< EEPROM data in */

/** Size of EEPROM (in bytes) */
#define NATSEMI_EEPROM_SIZE 32

/** Word offset of MAC address within sane EEPROM layout */
#define NATSEMI_EEPROM_MAC_SANE 0x0a

/** Word offset of MAC address within insane EEPROM layout */
#define NATSEMI_EEPROM_MAC_INSANE 0x06

/** PCI Test Control Register */
#define NATSEMI_PTSCR 0x000c
#define NATSEMI_PTSCR_EELOAD_EN	0x00000004UL	/**< Enable EEPROM load */

/** Maximum time to wait for a configuration reload, in milliseconds */
#define NATSEMI_EELOAD_MAX_WAIT_MS 100

/** Interrupt Status Register */
#define NATSEMI_ISR 0x0010
#define NATSEMI_IRQ_TXDESC	0x00000080UL	/**< TX descriptor */
#define NATSEMI_IRQ_RXDESC	0x00000002UL	/**< RX descriptor */

/** Interrupt Mask Register */
#define NATSEMI_IMR 0x0014

/** Interrupt Enable Register */
#define NATSEMI_IER 0x0018
#define NATSEMI_IER_IE		0x00000001UL	/**< Interrupt enable */

/** Transmit Descriptor Pointer */
#define NATSEMI_TXDP 0x0020

/** Transmit Descriptor Pointer High Dword (64-bit) */
#define NATSEMI_TXDP_HI_64 0x0024

/** Number of transmit descriptors */
#define NATSEMI_NUM_TX_DESC 4

/** Transmit configuration register (32-bit) */
#define NATSEMI_TXCFG_32 0x24

/** Transmit configuration register (64-bit) */
#define NATSEMI_TXCFG_64 0x28
#define NATSEMI_TXCFG_CSI	0x80000000UL	/**< Carrier sense ignore */
#define NATSEMI_TXCFG_HBI	0x40000000UL	/**< Heartbeat ignore */
#define NATSEMI_TXCFG_ATP	0x10000000UL	/**< Automatic padding */
#define NATSEMI_TXCFG_ECRETRY	0x00800000UL	/**< Excess collision retry */
#define NATSEMI_TXCFG_MXDMA(x)	( (x) << 20 )	/**< Max DMA burst size */
#define NATSEMI_TXCFG_FLTH(x)	( (x) << 8 )	/**< Fill threshold */
#define NATSEMI_TXCFG_DRTH(x)	( (x) << 0 )	/**< Drain threshold */

/** Max DMA burst size (encoded value)
 *
 * This represents 256-byte bursts on 83815 controllers and 512-byte
 * bursts on 83820 controllers.
 */
#define NATSEMI_TXCFG_MXDMA_DEFAULT NATSEMI_TXCFG_MXDMA ( 0x7 )

/** Fill threshold (in units of 32 bytes)
 *
 * Must be at least as large as the max DMA burst size, so use a value
 * of 512 bytes.
 */
#define NATSEMI_TXCFG_FLTH_DEFAULT NATSEMI_TXCFG_FLTH ( 512 / 32 )

/** Drain threshold (in units of 32 bytes)
 *
 * Start transmission once we receive a conservative 1024 bytes, to
 * avoid FIFO underrun errors.  (83815 does not allow us to specify a
 * value of 0 for "wait until whole packet is present".)
 *
 * Fill threshold plus drain threshold must be less than the transmit
 * FIFO size, which is 2kB on 83815 and 8kB on 83820.
 */
#define NATSEMI_TXCFG_DRTH_DEFAULT NATSEMI_TXCFG_DRTH ( 1024 / 32 )

/** Receive Descriptor Pointer */
#define NATSEMI_RXDP 0x0030

/** Receive Descriptor Pointer High Dword (64-bit) */
#define NATSEMI_RXDP_HI_64 0x0034

/** Number of receive descriptors */
#define NATSEMI_NUM_RX_DESC 4

/** Receive buffer length */
#define NATSEMI_RX_MAX_LEN ( ETH_FRAME_LEN + 4 /* VLAN */ + 4 /* CRC */ )

/** Receive configuration register (32-bit) */
#define NATSEMI_RXCFG_32 0x34

/** Receive configuration register (64-bit) */
#define NATSEMI_RXCFG_64 0x38
#define NATSEMI_RXCFG_ARP	0x40000000UL	/**< Accept runt packets */
#define NATSEMI_RXCFG_ATX	0x10000000UL	/**< Accept transmit packets */
#define NATSEMI_RXCFG_ALP	0x08000000UL	/**< Accept long packets */
#define NATSEMI_RXCFG_MXDMA(x)	( (x) << 20 )	/**< Max DMA burst size */
#define NATSEMI_RXCFG_DRTH(x)	( (x) << 1 )	/**< Drain threshold */

/** Max DMA burst size (encoded value)
 *
 * This represents 256-byte bursts on 83815 controllers and 512-byte
 * bursts on 83820 controllers.
 */
#define NATSEMI_RXCFG_MXDMA_DEFAULT NATSEMI_RXCFG_MXDMA ( 0x7 )

/** Drain threshold (in units of 8 bytes)
 *
 * Start draining after 64 bytes.
 *
 * Must be large enough to allow packet's accept/reject status to be
 * determined before draining begins.
 */
#define NATSEMI_RXCFG_DRTH_DEFAULT NATSEMI_RXCFG_DRTH ( 64 / 8 )

/** Receive Filter/Match Control Register */
#define NATSEMI_RFCR 0x0048
#define NATSEMI_RFCR_RFEN	0x80000000UL	/**< RX filter enable */
#define NATSEMI_RFCR_AAB	0x40000000UL	/**< Accept all broadcast */
#define NATSEMI_RFCR_AAM	0x20000000UL	/**< Accept all multicast */
#define NATSEMI_RFCR_AAU	0x10000000UL	/**< Accept all unicast */
#define NATSEMI_RFCR_RFADDR( addr ) ( (addr) << 0 ) /**< Extended address */
#define NATSEMI_RFCR_RFADDR_MASK NATSEMI_RFCR_RFADDR ( 0x3ff )

/** Perfect match filter address base */
#define NATSEMI_RFADDR_PMATCH_BASE 0x000

/** Receive Filter/Match Data Register */
#define NATSEMI_RFDR 0x004c
#define NATSEMI_RFDR_BMASK	0x00030000UL	/**< Byte mask */
#define NATSEMI_RFDR_DATA( value ) ( (value) & 0xffff ) /**< Filter data */

/** National Semiconductor network card flags */
enum natsemi_nic_flags {
	/** EEPROM is little-endian */
	NATSEMI_EEPROM_LITTLE_ENDIAN = 0x0001,
	/** EEPROM layout is insane */
	NATSEMI_EEPROM_INSANE = 0x0002,
	/** Card supports 64-bit operation */
	NATSEMI_64BIT = 0x0004,
	/** Card supports 1000Mbps link */
	NATSEMI_1000 = 0x0008,
};

/** A National Semiconductor descriptor ring */
struct natsemi_ring {
	/** Descriptors */
	union natsemi_descriptor *desc;
	/** Producer index */
	unsigned int prod;
	/** Consumer index */
	unsigned int cons;

	/** Number of descriptors */
	unsigned int count;
	/** Descriptor start address register */
	unsigned int reg;
};

/**
 * Initialise descriptor ring
 *
 * @v ring		Descriptor ring
 * @v count		Number of descriptors
 * @v reg		Descriptor start address register
 */
static inline __attribute__ (( always_inline)) void
natsemi_init_ring ( struct natsemi_ring *ring, unsigned int count,
		    unsigned int reg ) {
	ring->count = count;
	ring->reg = reg;
}

/** A National Semiconductor network card */
struct natsemi_nic {
	/** Flags */
	unsigned int flags;
	/** Registers */
	void *regs;
	/** SPI bit-bashing interface */
	struct spi_bit_basher spibit;
	/** EEPROM */
	struct spi_device eeprom;

	/** Transmit descriptor ring */
	struct natsemi_ring tx;
	/** Receive descriptor ring */
	struct natsemi_ring rx;
	/** Receive I/O buffers */
	struct io_buffer *rx_iobuf[NATSEMI_NUM_RX_DESC];

	/** Link status (cache) */
	uint32_t cfg;
};

/**
 * Check if card can access physical address
 *
 * @v natsemi		National Semiconductor device
 * @v address		Physical address
 * @v address_ok	Card can access physical address
 */
static inline __attribute__ (( always_inline )) int
natsemi_address_ok ( struct natsemi_nic *natsemi, physaddr_t address ) {

	/* In a 32-bit build, all addresses can be accessed */
	if ( sizeof ( physaddr_t ) <= sizeof ( uint32_t ) )
		return 1;

	/* A 64-bit card can access all addresses */
	if ( natsemi->flags & NATSEMI_64BIT )
		return 1;

	/* A 32-bit card can access all addresses below 4GB */
	if ( ( address & ~0xffffffffULL ) == 0 )
		return 1;

	return 0;
}

#endif /* _NATSEMI_H */
