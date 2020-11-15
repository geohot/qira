#ifndef _MYSON_H
#define _MYSON_H

/** @file
 *
 * Myson Technology network card driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/if_ether.h>

/** BAR size */
#define MYSON_BAR_SIZE 256

/** A packet descriptor */
struct myson_descriptor {
	/** Status */
	uint32_t status;
	/** Control */
	uint32_t control;
	/** Buffer start address */
	uint32_t address;
	/** Next descriptor address */
	uint32_t next;
} __attribute__ (( packed ));

/* Transmit status */
#define MYSON_TX_STAT_OWN	0x80000000UL	/**< Owner */
#define MYSON_TX_STAT_ABORT	0x00002000UL	/**< Abort */
#define MYSON_TX_STAT_CSL	0x00001000UL	/**< Carrier sense lost */

/* Transmit control */
#define MYSON_TX_CTRL_IC	0x80000000UL	/**< Interrupt control */
#define MYSON_TX_CTRL_LD	0x20000000UL	/**< Last descriptor */
#define MYSON_TX_CTRL_FD	0x10000000UL	/**< First descriptor */
#define MYSON_TX_CTRL_CRC	0x08000000UL	/**< CRC append */
#define MYSON_TX_CTRL_PAD	0x04000000UL	/**< Pad control */
#define MYSON_TX_CTRL_RTLC	0x02000000UL	/**< Retry late collision */
#define MYSON_TX_CTRL_PKTS(x)	( (x) << 11 )	/**< Packet size */
#define MYSON_TX_CTRL_TBS(x)	( (x) << 0 )	/**< Transmit buffer size */

/* Receive status */
#define MYSON_RX_STAT_OWN	0x80000000UL	/**< Owner */
#define MYSON_RX_STAT_FLNG(status) ( ( (status) >> 16 ) & 0xfff )
#define MYSON_RX_STAT_ES	0x00000080UL	/**< Error summary */

/* Receive control */
#define MYSON_RX_CTRL_RBS(x)	( (x) << 0 )	/**< Receive buffer size */

/** Descriptor ring alignment */
#define MYSON_RING_ALIGN 4

/** Physical Address Register 0 */
#define MYSON_PAR0 0x00

/** Physical Address Register 4 */
#define MYSON_PAR4 0x04

/** Physical address */
union myson_physical_address {
	struct {
		uint32_t low;
		uint32_t high;
	} __attribute__ (( packed )) reg;
	uint8_t raw[ETH_ALEN];
};

/** Transmit and Receive Configuration Register */
#define MYSON_TCR_RCR 0x18
#define MYSON_TCR_TXS		0x80000000UL	/**< Transmit status */
#define MYSON_TCR_TE		0x00040000UL	/**< Transmit enable */
#define MYSON_RCR_RXS		0x00008000UL	/**< Receive status */
#define MYSON_RCR_PROM		0x00000080UL	/**< Promiscuous mode */
#define MYSON_RCR_AB		0x00000040UL	/**< Accept broadcast */
#define MYSON_RCR_AM		0x00000020UL	/**< Accept multicast */
#define MYSON_RCR_ARP		0x00000008UL	/**< Accept runt packet */
#define MYSON_RCR_ALP		0x00000004UL	/**< Accept long packet */
#define MYSON_RCR_RE		0x00000001UL	/**< Receive enable */

/** Maximum time to wait for transmit and receive to be idle, in milliseconds */
#define MYSON_IDLE_MAX_WAIT_MS 100

/** Bus Command Register */
#define MYSON_BCR 0x1c
#define MYSON_BCR_RLE		0x00000100UL	/**< Read line enable */
#define MYSON_BCR_RME		0x00000080UL	/**< Read multiple enable */
#define MYSON_BCR_WIE		0x00000040UL	/**< Write and invalidate */
#define MYSON_BCR_PBL(x)	( (x) << 3 )	/**< Burst length */
#define MYSON_BCR_PBL_MASK	MYSON_BCR_PBL ( 0x7 )
#define MYSON_BCR_PBL_DEFAULT	MYSON_BCR_PBL ( 0x6 )
#define MYSON_BCR_SWR		0x00000001UL	/**< Software reset */

/** Maximum time to wait for a reset, in milliseconds */
#define MYSON_RESET_MAX_WAIT_MS 100

/** Transmit Poll Demand Register */
#define MYSON_TXPDR 0x20

/** Receive Poll Demand Register */
#define MYSON_RXPDR 0x24

/** Transmit List Base Address */
#define MYSON_TXLBA 0x2c

/** Number of transmit descriptors */
#define MYSON_NUM_TX_DESC 4

/** Receive List Base Address */
#define MYSON_RXLBA 0x30

/** Number of receive descriptors */
#define MYSON_NUM_RX_DESC 4

/** Receive buffer length */
#define MYSON_RX_MAX_LEN ( ETH_FRAME_LEN + 4 /* VLAN */ + 4 /* CRC */ )

/** Interrupt Status Register */
#define MYSON_ISR 0x34
#define MYSON_IRQ_TI		0x00000008UL	/**< Transmit interrupt */
#define MYSON_IRQ_RI		0x00000004UL	/**< Receive interrupt */

/** Number of I/O delays between ISR reads */
#define MYSON_ISR_IODELAY_COUNT 4

/** Interrupt Mask Register */
#define MYSON_IMR 0x38

/** Boot ROM / EEPROM / MII Management Register */
#define MYSON_ROM_MII 0x40
#define MYSON_ROM_AUTOLD	0x00100000UL	/**< Auto load */

/** Maximum time to wait for a configuration reload, in milliseconds */
#define MYSON_AUTOLD_MAX_WAIT_MS 100

/** A Myson descriptor ring */
struct myson_ring {
	/** Descriptors */
	struct myson_descriptor *desc;
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
 * @v reg		Descriptor base address register
 */
static inline __attribute__ (( always_inline)) void
myson_init_ring ( struct myson_ring *ring, unsigned int count,
		  unsigned int reg ) {
	ring->count = count;
	ring->reg = reg;
}

/** A myson network card */
struct myson_nic {
	/** Registers */
	void *regs;

	/** Transmit descriptor ring */
	struct myson_ring tx;
	/** Receive descriptor ring */
	struct myson_ring rx;
	/** Receive I/O buffers */
	struct io_buffer *rx_iobuf[MYSON_NUM_RX_DESC];
};

/**
 * Check if card can access physical address
 *
 * @v address		Physical address
 * @v address_ok	Card can access physical address
 */
static inline __attribute__ (( always_inline )) int
myson_address_ok ( physaddr_t address ) {

	/* In a 32-bit build, all addresses can be accessed */
	if ( sizeof ( physaddr_t ) <= sizeof ( uint32_t ) )
		return 1;

	/* Card can access all addresses below 4GB */
	if ( ( address & ~0xffffffffULL ) == 0 )
		return 1;

	return 0;
}

#endif /* _MYSON_H */
