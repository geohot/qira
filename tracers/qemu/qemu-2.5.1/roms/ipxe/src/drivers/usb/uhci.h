#ifndef _IPXE_UHCI_H
#define _IPXE_UHCI_H

/** @file
 *
 * USB Universal Host Controller Interface (UHCI) driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <assert.h>
#include <ipxe/pci.h>
#include <ipxe/usb.h>

/** Minimum alignment required for data structures
 *
 * With the exception of the frame list (which is page-aligned), data
 * structures used by UHCI generally require 16-byte alignment.
 */
#define UHCI_ALIGN 16

/** Number of ports */
#define UHCI_PORTS 2

/** Maximum transfer size */
#define UHCI_MTU 1280

/** I/O BAR size */
#define UHCI_BAR_SIZE 0x14

/** USB command register */
#define UHCI_USBCMD 0x00

/** Max packet is 64 bytes */
#define UHCI_USBCMD_MAX64 0x0080

/** Host controller reset */
#define UHCI_USBCMD_HCRESET 0x0002

/** Run/stop */
#define UHCI_USBCMD_RUN 0x0001

/** USB status register */
#define UHCI_USBSTS 0x02

/** Host controller halted */
#define UHCI_USBSTS_HCHALTED 0x0020

/** USB interrupt */
#define UHCI_USBSTS_USBINT 0x0001

/** Frame list base address register */
#define UHCI_FLBASEADD 0x08

/** Port status and control register */
#define UHCI_PORTSC(port) ( 0x0e + ( (port) << 1 ) )

/** Port reset */
#define UHCI_PORTSC_PR 0x0200

/** Low-speed device attached */
#define UHCI_PORTSC_LS 0x0100

/** Port enabled/disabled change */
#define UHCI_PORTSC_PEC 0x0008

/** Port enabled */
#define UHCI_PORTSC_PED 0x0004

/** Connect status change */
#define UHCI_PORTSC_CSC 0x0002

/** Current connect status */
#define UHCI_PORTSC_CCS 0x0001

/** Port status change mask */
#define UHCI_PORTSC_CHANGE ( UHCI_PORTSC_CSC | UHCI_PORTSC_PEC )

/** Depth-first processing */
#define UHCI_LINK_DEPTH_FIRST 0x00000004UL

/** Queue head type */
#define UHCI_LINK_TYPE_QH 0x00000002UL

/** List terminator */
#define UHCI_LINK_TERMINATE 0x00000001UL

/** Number of frames in frame list */
#define UHCI_FRAMES 1024

/** A frame list */
struct uhci_frame_list {
	/** Link pointer */
	uint32_t link[UHCI_FRAMES];
} __attribute__ (( packed ));

/** A transfer descriptor */
struct uhci_transfer_descriptor {
	/** Link pointer */
	uint32_t link;
	/** Actual length */
	uint16_t actual;
	/** Status */
	uint8_t status;
	/** Flags */
	uint8_t flags;
	/** Control */
	uint32_t control;
	/** Buffer pointer */
	uint32_t data;
} __attribute__ (( packed ));

/** Length mask */
#define UHCI_LEN_MASK 0x7ff

/** Actual length */
#define UHCI_ACTUAL_LEN( actual ) ( ( (actual) + 1 ) & UHCI_LEN_MASK )

/** Active */
#define UHCI_STATUS_ACTIVE 0x80

/** Stalled */
#define UHCI_STATUS_STALLED 0x40

/** Data buffer error */
#define UHCI_STATUS_BUFFER 0x20

/** Babble detected */
#define UHCI_STATUS_BABBLE 0x10

/** NAK received */
#define UHCI_STATUS_NAK 0x08

/** CRC/timeout error */
#define UHCI_STATUS_CRC_TIMEOUT 0x04

/** Bitstuff error */
#define UHCI_STATUS_BITSTUFF 0x02

/** Short packet detect */
#define UHCI_FL_SPD 0x20

/** Error counter */
#define UHCI_FL_CERR( count ) ( (count) << 3 )

/** Error counter maximum value */
#define UHCI_FL_CERR_MAX UHCI_FL_CERR ( 3 )

/** Low speed device */
#define UHCI_FL_LS 0x04

/** Interrupt on completion */
#define UHCI_FL_IOC 0x01

/** Packet ID */
#define UHCI_CONTROL_PID( pid ) ( (pid) << 0 )

/** Packet ID mask */
#define UHCI_CONTROL_PID_MASK UHCI_CONTROL_PID ( 0xff )

/** Device address */
#define UHCI_CONTROL_DEVICE( address ) ( (address) << 8 )

/** Endpoint address */
#define UHCI_CONTROL_ENDPOINT( address ) ( (address) << 15 )

/** Data toggle */
#define UHCI_CONTROL_TOGGLE ( 1 << 19 )

/** Data length */
#define UHCI_CONTROL_LEN( len ) ( ( ( (len) - 1 ) & UHCI_LEN_MASK ) << 21 )

/** Check for data packet
 *
 * This check is based on the fact that only USB_PID_SETUP has bit 2
 * set.
 */
#define UHCI_DATA_PACKET( control ) ( ! ( control & 0x04 ) )

/** Check for short packet */
#define UHCI_SHORT_PACKET( control, actual ) \
	( ( ( (control) >> 21 ) ^ (actual) ) & UHCI_LEN_MASK )

/** USB legacy support register (in PCI configuration space) */
#define UHCI_USBLEGSUP 0xc0

/** USB legacy support default value */
#define UHCI_USBLEGSUP_DEFAULT 0x2000

/** A queue head */
struct uhci_queue_head {
	/** Horizontal link pointer */
	uint32_t link;
	/** Current transfer descriptor */
	uint32_t current;
} __attribute__ (( packed ));

/** A single UHCI transfer
 *
 * UHCI hardware is extremely simple, and requires software to build
 * the entire packet schedule (including manually handling all of the
 * data toggles).  The hardware requires at least 16 bytes of transfer
 * descriptors per 64 bytes of transmitted/received data.  We allocate
 * the transfer descriptors at the time that the transfer is enqueued,
 * to avoid the need to allocate unreasonably large blocks when the
 * endpoint is opened.
 */
struct uhci_transfer {
	/** Producer counter */
	unsigned int prod;
	/** Consumer counter */
	unsigned int cons;
	/** Completed data length */
	size_t len;

	/** Transfer descriptors */
	struct uhci_transfer_descriptor *desc;

	/** I/O buffer */
	struct io_buffer *iobuf;
};

/** Number of transfer descriptors in a ring
 *
 * This is a policy decision.
 */
#define UHCI_RING_COUNT 16

/** A transfer ring */
struct uhci_ring {
	/** Producer counter */
	unsigned int prod;
	/** Consumer counter */
	unsigned int cons;

	/** Maximum packet length */
	size_t mtu;
	/** Base flags
	 *
	 * This incorporates the CERR and LS bits
	 */
	uint8_t flags;
	/** Base control word
	 *
	 * This incorporates the device address, the endpoint address,
	 * and the data toggle for the next descriptor to be enqueued.
	 */
	uint32_t control;

	/** Transfers */
	struct uhci_transfer *xfer[UHCI_RING_COUNT];
	/** End of transfer ring (if non-empty) */
	struct uhci_transfer *end;

	/** Queue head */
	struct uhci_queue_head *head;
};

/**
 * Calculate space used in transfer ring
 *
 * @v ring		Transfer ring
 * @ret fill		Number of entries used
 */
static inline __attribute__ (( always_inline )) unsigned int
uhci_ring_fill ( struct uhci_ring *ring ) {
	unsigned int fill;

	fill = ( ring->prod - ring->cons );
	assert ( fill <= UHCI_RING_COUNT );
	return fill;
}

/**
 * Calculate space remaining in transfer ring
 *
 * @v ring		Transfer ring
 * @ret remaining	Number of entries remaining
 */
static inline __attribute__ (( always_inline )) unsigned int
uhci_ring_remaining ( struct uhci_ring *ring ) {
	unsigned int fill = uhci_ring_fill ( ring );

	return ( UHCI_RING_COUNT - fill );
}

/** Maximum time to wait for host controller to stop
 *
 * This is a policy decision.
 */
#define UHCI_STOP_MAX_WAIT_MS 100

/** Maximum time to wait for reset to complete
 *
 * This is a policy decision.
 */
#define UHCI_RESET_MAX_WAIT_MS 500

/** Maximum time to wait for a port to be enabled
 *
 * This is a policy decision.
 */
#define UHCI_PORT_ENABLE_MAX_WAIT_MS 500

/** A UHCI device */
struct uhci_device {
	/** Registers */
	unsigned long regs;
	/** Name */
	const char *name;

	/** EHCI companion controller bus:dev.fn address (if any) */
	unsigned int companion;

	/** Asynchronous queue head */
	struct uhci_queue_head *head;
	/** Frame list */
	struct uhci_frame_list *frame;

	/** List of all endpoints */
	struct list_head endpoints;
	/** Asynchronous schedule */
	struct list_head async;
	/** Periodic schedule
	 *
	 * Listed in decreasing order of endpoint interval.
	 */
	struct list_head periodic;

	/** USB bus */
	struct usb_bus *bus;
};

/** A UHCI endpoint */
struct uhci_endpoint {
	/** UHCI device */
	struct uhci_device *uhci;
	/** USB endpoint */
	struct usb_endpoint *ep;
	/** List of all endpoints */
	struct list_head list;
	/** Endpoint schedule */
	struct list_head schedule;

	/** Transfer ring */
	struct uhci_ring ring;
};

#endif /* _IPXE_UHCI_H */
