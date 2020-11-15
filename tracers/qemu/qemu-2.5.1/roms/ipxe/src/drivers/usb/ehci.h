#ifndef _IPXE_EHCI_H
#define _IPXE_EHCI_H

/** @file
 *
 * USB Enhanced Host Controller Interface (EHCI) driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/pci.h>
#include <ipxe/usb.h>

/** Minimum alignment required for data structures
 *
 * With the exception of the periodic frame list (which is
 * page-aligned), data structures used by EHCI generally require
 * 32-byte alignment and must not cross a 4kB page boundary.  We
 * simplify this requirement by aligning each structure on its own
 * size, with a minimum of a 32 byte alignment.
 */
#define EHCI_MIN_ALIGN 32

/** Maximum transfer size
 *
 * EHCI allows for transfers of up to 20kB with page-alignment, or
 * 16kB with arbitrary alignment.
 */
#define EHCI_MTU 16384

/** Page-alignment required for some data structures */
#define EHCI_PAGE_ALIGN 4096

/** EHCI PCI BAR */
#define EHCI_BAR PCI_BASE_ADDRESS_0

/** Capability register length */
#define EHCI_CAP_CAPLENGTH 0x00

/** Host controller interface version number */
#define EHCI_CAP_HCIVERSION 0x02

/** Structural parameters */
#define EHCI_CAP_HCSPARAMS 0x04

/** Number of ports */
#define EHCI_HCSPARAMS_PORTS(params) ( ( (params) >> 0 ) & 0x0f )

/** Capability parameters */
#define EHCI_CAP_HCCPARAMS 0x08

/** 64-bit addressing capability */
#define EHCI_HCCPARAMS_ADDR64(params) ( ( (params) >> 0 ) & 0x1 )

/** Programmable frame list flag */
#define EHCI_HCCPARAMS_FLSIZE(params) ( ( (params) >> 1 ) & 0x1 )

/** EHCI extended capabilities pointer */
#define EHCI_HCCPARAMS_EECP(params) ( ( ( (params) >> 8 ) & 0xff ) )

/** EHCI extended capability ID */
#define EHCI_EECP_ID(eecp) ( ( (eecp) >> 0 ) & 0xff )

/** Next EHCI extended capability pointer */
#define EHCI_EECP_NEXT(eecp) ( ( ( (eecp) >> 8 ) & 0xff ) )

/** USB legacy support extended capability */
#define EHCI_EECP_ID_LEGACY 1

/** USB legacy support BIOS owned semaphore */
#define EHCI_USBLEGSUP_BIOS 0x02

/** USB legacy support BIOS ownership flag */
#define EHCI_USBLEGSUP_BIOS_OWNED 0x01

/** USB legacy support OS owned semaphore */
#define EHCI_USBLEGSUP_OS 0x03

/** USB legacy support OS ownership flag */
#define EHCI_USBLEGSUP_OS_OWNED 0x01

/** USB legacy support control/status */
#define EHCI_USBLEGSUP_CTLSTS 0x04

/** USB command register */
#define EHCI_OP_USBCMD 0x00

/** Run/stop */
#define EHCI_USBCMD_RUN 0x00000001UL

/** Host controller reset */
#define EHCI_USBCMD_HCRST 0x00000002UL

/** Frame list size */
#define EHCI_USBCMD_FLSIZE(flsize) ( (flsize) << 2 )

/** Frame list size mask */
#define EHCI_USBCMD_FLSIZE_MASK EHCI_USBCMD_FLSIZE ( 3 )

/** Default frame list size */
#define EHCI_FLSIZE_DEFAULT 0

/** Smallest allowed frame list size */
#define EHCI_FLSIZE_SMALL 2

/** Number of elements in frame list */
#define EHCI_PERIODIC_FRAMES(flsize) ( 1024 >> (flsize) )

/** Periodic schedule enable */
#define EHCI_USBCMD_PERIODIC 0x00000010UL

/** Asynchronous schedule enable */
#define EHCI_USBCMD_ASYNC 0x00000020UL

/** Asyncchronous schedule advance doorbell */
#define EHCI_USBCMD_ASYNC_ADVANCE 0x000040UL

/** USB status register */
#define EHCI_OP_USBSTS 0x04

/** USB interrupt */
#define EHCI_USBSTS_USBINT 0x00000001UL

/** USB error interrupt */
#define EHCI_USBSTS_USBERRINT 0x00000002UL

/** Port change detect */
#define EHCI_USBSTS_PORT 0x00000004UL

/** Frame list rollover */
#define EHCI_USBSTS_ROLLOVER 0x00000008UL

/** Host system error */
#define EHCI_USBSTS_SYSERR 0x00000010UL

/** Asynchronous schedule advanced */
#define EHCI_USBSTS_ASYNC_ADVANCE 0x00000020UL

/** Periodic schedule enabled */
#define EHCI_USBSTS_PERIODIC 0x00004000UL

/** Asynchronous schedule enabled */
#define EHCI_USBSTS_ASYNC 0x00008000UL

/** Host controller halted */
#define EHCI_USBSTS_HCH 0x00001000UL

/** USB status change mask */
#define EHCI_USBSTS_CHANGE						\
	( EHCI_USBSTS_USBINT | EHCI_USBSTS_USBERRINT |			\
	  EHCI_USBSTS_PORT | EHCI_USBSTS_ROLLOVER |			\
	  EHCI_USBSTS_SYSERR | EHCI_USBSTS_ASYNC_ADVANCE )

/** USB interrupt enable register */
#define EHCI_OP_USBINTR 0x08

/** Frame index register */
#define EHCI_OP_FRINDEX 0x0c

/** Control data structure segment register */
#define EHCI_OP_CTRLDSSEGMENT 0x10

/** Periodic frame list base address register */
#define EHCI_OP_PERIODICLISTBASE 0x14

/** Current asynchronous list address register */
#define EHCI_OP_ASYNCLISTADDR 0x18

/** Configure flag register */
#define EHCI_OP_CONFIGFLAG 0x40

/** Configure flag */
#define EHCI_CONFIGFLAG_CF 0x00000001UL

/** Port status and control register */
#define EHCI_OP_PORTSC(port) ( 0x40 + ( (port) << 2 ) )

/** Current connect status */
#define EHCI_PORTSC_CCS 0x00000001UL

/** Connect status change */
#define EHCI_PORTSC_CSC 0x00000002UL

/** Port enabled */
#define EHCI_PORTSC_PED 0x00000004UL

/** Port enabled/disabled change */
#define EHCI_PORTSC_PEC 0x00000008UL

/** Over-current change */
#define EHCI_PORTSC_OCC 0x00000020UL

/** Port reset */
#define EHCI_PORTSC_PR 0x00000100UL

/** Line status */
#define EHCI_PORTSC_LINE_STATUS(portsc) ( ( (portsc) >> 10 ) & 0x3 )

/** Line status: low-speed device */
#define EHCI_PORTSC_LINE_STATUS_LOW 0x1

/** Port power */
#define EHCI_PORTSC_PP 0x00001000UL

/** Port owner */
#define EHCI_PORTSC_OWNER 0x00002000UL

/** Port status change mask */
#define EHCI_PORTSC_CHANGE \
	( EHCI_PORTSC_CSC | EHCI_PORTSC_PEC | EHCI_PORTSC_OCC )

/** List terminator */
#define EHCI_LINK_TERMINATE 0x00000001UL

/** Frame list type */
#define EHCI_LINK_TYPE(type) ( (type) << 1 )

/** Queue head type */
#define EHCI_LINK_TYPE_QH EHCI_LINK_TYPE ( 1 )

/** A periodic frame list entry */
struct ehci_periodic_frame {
	/** First queue head */
	uint32_t link;
} __attribute__ (( packed ));

/** A transfer descriptor */
struct ehci_transfer_descriptor {
	/** Next transfer descriptor */
	uint32_t next;
	/** Alternate next transfer descriptor */
	uint32_t alt;
	/** Status */
	uint8_t status;
	/** Flags */
	uint8_t flags;
	/** Transfer length */
	uint16_t len;
	/** Buffer pointers (low 32 bits) */
	uint32_t low[5];
	/** Extended buffer pointers (high 32 bits) */
	uint32_t high[5];
	/** Reserved */
	uint8_t reserved[12];
} __attribute__ (( packed ));

/** Transaction error */
#define EHCI_STATUS_XACT_ERR 0x08

/** Babble detected */
#define EHCI_STATUS_BABBLE 0x10

/** Data buffer error */
#define EHCI_STATUS_BUFFER 0x20

/** Halted */
#define EHCI_STATUS_HALTED 0x40

/** Active */
#define EHCI_STATUS_ACTIVE 0x80

/** PID code */
#define EHCI_FL_PID(code) ( (code) << 0 )

/** OUT token */
#define EHCI_FL_PID_OUT EHCI_FL_PID ( 0 )

/** IN token */
#define EHCI_FL_PID_IN EHCI_FL_PID ( 1 )

/** SETUP token */
#define EHCI_FL_PID_SETUP EHCI_FL_PID ( 2 )

/** Error counter */
#define EHCI_FL_CERR( count ) ( (count) << 2 )

/** Error counter maximum value */
#define EHCI_FL_CERR_MAX EHCI_FL_CERR ( 3 )

/** Interrupt on completion */
#define EHCI_FL_IOC 0x80

/** Length mask */
#define EHCI_LEN_MASK 0x7fff

/** Data toggle */
#define EHCI_LEN_TOGGLE 0x8000

/** A queue head */
struct ehci_queue_head {
	/** Horizontal link pointer */
	uint32_t link;
	/** Endpoint characteristics */
	uint32_t chr;
	/** Endpoint capabilities */
	uint32_t cap;
	/** Current transfer descriptor */
	uint32_t current;
	/** Transfer descriptor cache */
	struct ehci_transfer_descriptor cache;
} __attribute__ (( packed ));

/** Device address */
#define EHCI_CHR_ADDRESS( address ) ( (address) << 0 )

/** Endpoint number */
#define EHCI_CHR_ENDPOINT( address ) ( ( (address) & 0xf ) << 8 )

/** Endpoint speed */
#define EHCI_CHR_EPS( eps ) ( (eps) << 12 )

/** Full-speed endpoint */
#define EHCI_CHR_EPS_FULL EHCI_CHR_EPS ( 0 )

/** Low-speed endpoint */
#define EHCI_CHR_EPS_LOW EHCI_CHR_EPS ( 1 )

/** High-speed endpoint */
#define EHCI_CHR_EPS_HIGH EHCI_CHR_EPS ( 2 )

/** Explicit data toggles */
#define EHCI_CHR_TOGGLE 0x00004000UL

/** Head of reclamation list flag */
#define EHCI_CHR_HEAD 0x00008000UL

/** Maximum packet length */
#define EHCI_CHR_MAX_LEN( len ) ( (len) << 16 )

/** Control endpoint flag */
#define EHCI_CHR_CONTROL 0x08000000UL

/** Interrupt schedule mask */
#define EHCI_CAP_INTR_SCHED( uframe ) ( 1 << ( (uframe) + 0 ) )

/** Split completion schedule mask */
#define EHCI_CAP_SPLIT_SCHED( uframe ) ( 1 << ( (uframe) + 8 ) )

/** Default split completion schedule mask
 *
 * We schedule all split starts in microframe 0, on the assumption
 * that we will never have to deal with more than sixteen actively
 * interrupting devices via the same transaction translator.  We
 * schedule split completions for all remaining microframes after
 * microframe 1 (in which the low-speed or full-speed transaction is
 * assumed to execute).  This is a very crude approximation designed
 * to avoid the need for calculating exactly when low-speed and
 * full-speed transactions will execute.  Since we only ever deal with
 * interrupt endpoints (rather than isochronous endpoints), the volume
 * of periodic traffic is extremely low, and this approximation should
 * remain valid.
 */
#define EHCI_CAP_SPLIT_SCHED_DEFAULT					\
	( EHCI_CAP_SPLIT_SCHED ( 2 ) | EHCI_CAP_SPLIT_SCHED ( 3 ) |	\
	  EHCI_CAP_SPLIT_SCHED ( 4 ) | EHCI_CAP_SPLIT_SCHED ( 5 ) |	\
	  EHCI_CAP_SPLIT_SCHED ( 6 ) | EHCI_CAP_SPLIT_SCHED ( 7 ) )

/** Transaction translator hub address */
#define EHCI_CAP_TT_HUB( address ) ( (address) << 16 )

/** Transaction translator port number */
#define EHCI_CAP_TT_PORT( port ) ( (port) << 23 )

/** High-bandwidth pipe multiplier */
#define EHCI_CAP_MULT( mult ) ( (mult) << 30 )

/** A transfer descriptor ring */
struct ehci_ring {
	/** Producer counter */
	unsigned int prod;
	/** Consumer counter */
	unsigned int cons;

	/** Residual untransferred data */
	size_t residual;

	/** I/O buffers */
	struct io_buffer **iobuf;

	/** Queue head */
	struct ehci_queue_head *head;
	/** Transfer descriptors */
	struct ehci_transfer_descriptor *desc;
};

/** Number of transfer descriptors in a ring
 *
 * This is a policy decision.
 */
#define EHCI_RING_COUNT 64

/**
 * Calculate space used in transfer descriptor ring
 *
 * @v ring		Transfer descriptor ring
 * @ret fill		Number of entries used
 */
static inline __attribute__ (( always_inline )) unsigned int
ehci_ring_fill ( struct ehci_ring *ring ) {
	unsigned int fill;

	fill = ( ring->prod - ring->cons );
	assert ( fill <= EHCI_RING_COUNT );
	return fill;
}

/**
 * Calculate space remaining in transfer descriptor ring
 *
 * @v ring		Transfer descriptor ring
 * @ret remaining	Number of entries remaining
 */
static inline __attribute__ (( always_inline )) unsigned int
ehci_ring_remaining ( struct ehci_ring *ring ) {
	unsigned int fill = ehci_ring_fill ( ring );

	return ( EHCI_RING_COUNT - fill );
}

/** Time to delay after enabling power to a port
 *
 * This is not mandated by EHCI; we use the value given for xHCI.
 */
#define EHCI_PORT_POWER_DELAY_MS 20

/** Time to delay after releasing ownership of a port
 *
 * This is a policy decision.
 */
#define EHCI_DISOWN_DELAY_MS 100

/** Maximum time to wait for BIOS to release ownership
 *
 * This is a policy decision.
 */
#define EHCI_USBLEGSUP_MAX_WAIT_MS 100

/** Maximum time to wait for asynchronous schedule to advance
 *
 * This is a policy decision.
 */
#define EHCI_ASYNC_ADVANCE_MAX_WAIT_MS 100

/** Maximum time to wait for host controller to stop
 *
 * This is a policy decision.
 */
#define EHCI_STOP_MAX_WAIT_MS 100

/** Maximum time to wait for reset to complete
 *
 * This is a policy decision.
 */
#define EHCI_RESET_MAX_WAIT_MS 500

/** Maximum time to wait for a port reset to complete
 *
 * This is a policy decision.
 */
#define EHCI_PORT_RESET_MAX_WAIT_MS 500

/** An EHCI transfer */
struct ehci_transfer {
	/** Data buffer */
	void *data;
	/** Length */
	size_t len;
	/** Flags
	 *
	 * This is the bitwise OR of zero or more EHCI_FL_XXX values.
	 * The low 8 bits are copied to the flags byte within the
	 * transfer descriptor; the remaining bits hold flags
	 * meaningful only to our driver code.
	 */
	unsigned int flags;
};

/** Set initial data toggle */
#define EHCI_FL_TOGGLE 0x8000

/** An EHCI device */
struct ehci_device {
	/** Registers */
	void *regs;
	/** Name */
	const char *name;

	/** Capability registers */
	void *cap;
	/** Operational registers */
	void *op;

	/** Number of ports */
	unsigned int ports;
	/** 64-bit addressing capability */
	int addr64;
	/** Frame list size */
	unsigned int flsize;
	/** EHCI extended capabilities offset */
	unsigned int eecp;

	/** USB legacy support capability (if present and enabled) */
	unsigned int legacy;

	/** Control data structure segment */
	uint32_t ctrldssegment;
	/** Asynchronous queue head */
	struct ehci_queue_head *head;
	/** Periodic frame list */
	struct ehci_periodic_frame *frame;

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

/** An EHCI endpoint */
struct ehci_endpoint {
	/** EHCI device */
	struct ehci_device *ehci;
	/** USB endpoint */
	struct usb_endpoint *ep;
	/** List of all endpoints */
	struct list_head list;
	/** Endpoint schedule */
	struct list_head schedule;

	/** Transfer descriptor ring */
	struct ehci_ring ring;
};

extern unsigned int ehci_companion ( struct pci_device *pci );

#endif /* _IPXE_EHCI_H */
