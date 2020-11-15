#ifndef _INTEL_H
#define _INTEL_H

/** @file
 *
 * Intel 10/100/1000 network card driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/if_ether.h>
#include <ipxe/nvs.h>

/** Intel BAR size */
#define INTEL_BAR_SIZE ( 128 * 1024 )

/** A packet descriptor */
struct intel_descriptor {
	/** Buffer address */
	uint64_t address;
	/** Length */
	uint16_t length;
	/** Flags */
	uint8_t flags;
	/** Command */
	uint8_t command;
	/** Status */
	uint32_t status;
} __attribute__ (( packed ));

/** Descriptor type */
#define INTEL_DESC_FL_DTYP( dtyp ) ( (dtyp) << 4 )
#define INTEL_DESC_FL_DTYP_DATA INTEL_DESC_FL_DTYP ( 0x03 )

/** Descriptor extension */
#define INTEL_DESC_CMD_DEXT 0x20

/** Report status */
#define INTEL_DESC_CMD_RS 0x08

/** Insert frame checksum (CRC) */
#define INTEL_DESC_CMD_IFCS 0x02

/** End of packet */
#define INTEL_DESC_CMD_EOP 0x01

/** Descriptor done */
#define INTEL_DESC_STATUS_DD 0x00000001UL

/** Receive error */
#define INTEL_DESC_STATUS_RXE 0x00000100UL

/** Payload length */
#define INTEL_DESC_STATUS_PAYLEN( len ) ( (len) << 14 )

/** Device Control Register */
#define INTEL_CTRL 0x00000UL
#define INTEL_CTRL_LRST		0x00000008UL	/**< Link reset */
#define INTEL_CTRL_ASDE		0x00000020UL	/**< Auto-speed detection */
#define INTEL_CTRL_SLU		0x00000040UL	/**< Set link up */
#define INTEL_CTRL_FRCSPD	0x00000800UL	/**< Force speed */
#define INTEL_CTRL_FRCDPLX	0x00001000UL	/**< Force duplex */
#define INTEL_CTRL_RST		0x04000000UL	/**< Device reset */
#define INTEL_CTRL_PHY_RST	0x80000000UL	/**< PHY reset */

/** Time to delay for device reset, in milliseconds */
#define INTEL_RESET_DELAY_MS 20

/** Device Status Register */
#define INTEL_STATUS 0x00008UL
#define INTEL_STATUS_LU		0x00000002UL	/**< Link up */

/** EEPROM Read Register */
#define INTEL_EERD 0x00014UL
#define INTEL_EERD_START	0x00000001UL	/**< Start read */
#define INTEL_EERD_DONE_SMALL	0x00000010UL	/**< Read done (small EERD) */
#define INTEL_EERD_DONE_LARGE	0x00000002UL	/**< Read done (large EERD) */
#define INTEL_EERD_ADDR_SHIFT_SMALL 8		/**< Address shift (small) */
#define INTEL_EERD_ADDR_SHIFT_LARGE 2		/**< Address shift (large) */
#define INTEL_EERD_DATA(value)	( (value) >> 16 ) /**< Read data */

/** Maximum time to wait for EEPROM read, in milliseconds */
#define INTEL_EEPROM_MAX_WAIT_MS 100

/** EEPROM word length */
#define INTEL_EEPROM_WORD_LEN_LOG2 1

/** Minimum EEPROM size, in words */
#define INTEL_EEPROM_MIN_SIZE_WORDS 64

/** Offset of MAC address within EEPROM */
#define INTEL_EEPROM_MAC 0x00

/** Interrupt Cause Read Register */
#define INTEL_ICR 0x000c0UL
#define INTEL_IRQ_TXDW		0x00000001UL	/**< Transmit descriptor done */
#define INTEL_IRQ_TXQE		0x00000002UL	/**< Transmit queue empty */
#define INTEL_IRQ_LSC		0x00000004UL	/**< Link status change */
#define INTEL_IRQ_RXDMT0	0x00000010UL	/**< Receive queue low */
#define INTEL_IRQ_RXT0		0x00000080UL	/**< Receive timer */
#define INTEL_IRQ_RXO		0x00000400UL	/**< Receive overrun */

/** Interrupt Mask Set/Read Register */
#define INTEL_IMS 0x000d0UL

/** Interrupt Mask Clear Register */
#define INTEL_IMC 0x000d8UL

/** Receive Control Register */
#define INTEL_RCTL 0x00100UL
#define INTEL_RCTL_EN		0x00000002UL	/**< Receive enable */
#define INTEL_RCTL_UPE		0x00000008UL	/**< Unicast promiscuous mode */
#define INTEL_RCTL_MPE		0x00000010UL	/**< Multicast promiscuous */
#define INTEL_RCTL_BAM		0x00008000UL	/**< Broadcast accept mode */
#define INTEL_RCTL_BSIZE_BSEX(bsex,bsize) \
	( ( (bsize) << 16 ) | ( (bsex) << 25 ) ) /**< Buffer size */
#define INTEL_RCTL_BSIZE_2048	INTEL_RCTL_BSIZE_BSEX ( 0, 0 )
#define INTEL_RCTL_BSIZE_BSEX_MASK INTEL_RCTL_BSIZE_BSEX ( 1, 3 )
#define INTEL_RCTL_SECRC	0x04000000UL	/**< Strip CRC */

/** Transmit Control Register */
#define INTEL_TCTL 0x00400UL
#define INTEL_TCTL_EN		0x00000002UL	/**< Transmit enable */
#define INTEL_TCTL_PSP		0x00000008UL	/**< Pad short packets */
#define INTEL_TCTL_CT(x)	( (x) << 4 )	/**< Collision threshold */
#define INTEL_TCTL_CT_DEFAULT	INTEL_TCTL_CT ( 0x0f )
#define INTEL_TCTL_CT_MASK	INTEL_TCTL_CT ( 0xff )
#define INTEL_TCTL_COLD(x)	( (x) << 12 )	/**< Collision distance */
#define INTEL_TCTL_COLD_DEFAULT	INTEL_TCTL_COLD ( 0x040 )
#define INTEL_TCTL_COLD_MASK	INTEL_TCTL_COLD ( 0x3ff )

/** Packet Buffer Allocation */
#define INTEL_PBA 0x01000UL

/** Packet Buffer Size */
#define INTEL_PBS 0x01008UL

/** Receive Descriptor register block */
#define INTEL_RD 0x02800UL

/** Number of receive descriptors
 *
 * Minimum value is 8, since the descriptor ring length must be a
 * multiple of 128.
 */
#define INTEL_NUM_RX_DESC 16

/** Receive descriptor ring fill level */
#define INTEL_RX_FILL 8

/** Receive buffer length */
#define INTEL_RX_MAX_LEN 2048

/** Transmit Descriptor register block */
#define INTEL_TD 0x03800UL

/** Number of transmit descriptors
 *
 * Descriptor ring length must be a multiple of 16.  ICH8/9/10
 * requires a minimum of 16 TX descriptors.
 */
#define INTEL_NUM_TX_DESC 16

/** Transmit descriptor ring maximum fill level */
#define INTEL_TX_FILL ( INTEL_NUM_TX_DESC - 1 )

/** Receive/Transmit Descriptor Base Address Low (offset) */
#define INTEL_xDBAL 0x00

/** Receive/Transmit Descriptor Base Address High (offset) */
#define INTEL_xDBAH 0x04

/** Receive/Transmit Descriptor Length (offset) */
#define INTEL_xDLEN 0x08

/** Receive/Transmit Descriptor Head (offset) */
#define INTEL_xDH 0x10

/** Receive/Transmit Descriptor Tail (offset) */
#define INTEL_xDT 0x18

/** Receive/Transmit Descriptor Control (offset) */
#define INTEL_xDCTL 0x28
#define INTEL_xDCTL_ENABLE	0x02000000UL	/**< Queue enable */

/** Receive Address Low */
#define INTEL_RAL0 0x05400UL

/** Receive Address High */
#define INTEL_RAH0 0x05404UL
#define INTEL_RAH0_AV		0x80000000UL	/**< Address valid */

/** Receive address */
union intel_receive_address {
	struct {
		uint32_t low;
		uint32_t high;
	} __attribute__ (( packed )) reg;
	uint8_t raw[ETH_ALEN];
};

/** An Intel descriptor ring */
struct intel_ring {
	/** Descriptors */
	struct intel_descriptor *desc;
	/** Producer index */
	unsigned int prod;
	/** Consumer index */
	unsigned int cons;

	/** Register block */
	unsigned int reg;
	/** Length (in bytes) */
	size_t len;

	/** Populate descriptor
	 *
	 * @v desc		Descriptor
	 * @v addr		Data buffer address
	 * @v len		Length of data
	 */
	void ( * describe ) ( struct intel_descriptor *desc, physaddr_t addr,
			      size_t len );
};

/**
 * Initialise descriptor ring
 *
 * @v ring		Descriptor ring
 * @v count		Number of descriptors
 * @v reg		Descriptor register block
 * @v describe		Method to populate descriptor
 */
static inline __attribute__ (( always_inline)) void
intel_init_ring ( struct intel_ring *ring, unsigned int count, unsigned int reg,
		  void ( * describe ) ( struct intel_descriptor *desc,
					physaddr_t addr, size_t len ) ) {

	ring->len = ( count * sizeof ( ring->desc[0] ) );
	ring->reg = reg;
	ring->describe = describe;
}

/** An Intel virtual function mailbox */
struct intel_mailbox {
	/** Mailbox control register */
	unsigned int ctrl;
	/** Mailbox memory base */
	unsigned int mem;
};

/**
 * Initialise mailbox
 *
 * @v mbox		Mailbox
 * @v ctrl		Mailbox control register
 * @v mem		Mailbox memory register base
 */
static inline __attribute__ (( always_inline )) void
intel_init_mbox ( struct intel_mailbox *mbox, unsigned int ctrl,
		  unsigned int mem ) {

	mbox->ctrl = ctrl;
	mbox->mem = mem;
}

/** An Intel network card */
struct intel_nic {
	/** Registers */
	void *regs;
	/** Port number (for multi-port devices) */
	unsigned int port;
	/** Flags */
	unsigned int flags;
	/** Forced interrupts */
	unsigned int force_icr;

	/** EEPROM */
	struct nvs_device eeprom;
	/** EEPROM done flag */
	uint32_t eerd_done;
	/** EEPROM address shift */
	unsigned int eerd_addr_shift;

	/** Mailbox */
	struct intel_mailbox mbox;

	/** Transmit descriptor ring */
	struct intel_ring tx;
	/** Receive descriptor ring */
	struct intel_ring rx;
	/** Receive I/O buffers */
	struct io_buffer *rx_iobuf[INTEL_NUM_RX_DESC];
};

/** Driver flags */
enum intel_flags {
	/** PBS/PBA errata workaround required */
	INTEL_PBS_ERRATA = 0x0001,
	/** VMware missing interrupt workaround required */
	INTEL_VMWARE = 0x0002,
};

/**
 * Dump diagnostic information
 *
 * @v intel		Intel device
 */
static inline void intel_diag ( struct intel_nic *intel ) {

	DBGC ( intel, "INTEL %p TX %04x(%02x)/%04x(%02x) "
	       "RX %04x(%02x)/%04x(%02x)\n", intel,
	       ( intel->tx.cons & 0xffff ),
	       readl ( intel->regs + intel->tx.reg + INTEL_xDH ),
	       ( intel->tx.prod & 0xffff ),
	       readl ( intel->regs + intel->tx.reg + INTEL_xDT ),
	       ( intel->rx.cons & 0xffff ),
	       readl ( intel->regs + intel->rx.reg + INTEL_xDH ),
	       ( intel->rx.prod & 0xffff ),
	       readl ( intel->regs + intel->rx.reg + INTEL_xDT ) );
}

extern void intel_describe_tx ( struct intel_descriptor *tx,
				physaddr_t addr, size_t len );
extern void intel_describe_tx_adv ( struct intel_descriptor *tx,
				    physaddr_t addr, size_t len );
extern void intel_describe_rx ( struct intel_descriptor *rx,
				physaddr_t addr, size_t len );
extern int intel_create_ring ( struct intel_nic *intel,
			       struct intel_ring *ring );
extern void intel_destroy_ring ( struct intel_nic *intel,
				 struct intel_ring *ring );
extern void intel_refill_rx ( struct intel_nic *intel );
extern void intel_empty_rx ( struct intel_nic *intel );
extern int intel_transmit ( struct net_device *netdev,
			    struct io_buffer *iobuf );
extern void intel_poll_tx ( struct net_device *netdev );
extern void intel_poll_rx ( struct net_device *netdev );

#endif /* _INTEL_H */
