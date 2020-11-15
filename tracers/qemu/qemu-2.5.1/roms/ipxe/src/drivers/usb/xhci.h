#ifndef _IPXE_XHCI_H
#define _IPXE_XHCI_H

/** @file
 *
 * USB eXtensible Host Controller Interface (xHCI) driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <assert.h>
#include <ipxe/pci.h>
#include <ipxe/uaccess.h>
#include <ipxe/usb.h>

/** Minimum alignment required for data structures
 *
 * With the exception of the scratchpad buffer pages (which are
 * page-aligned), data structures used by xHCI generally require from
 * 16 to 64 byte alignment and must not cross an (xHCI) page boundary.
 * We simplify this requirement by aligning each structure on its own
 * size, with a minimum of a 64 byte alignment.
 */
#define XHCI_MIN_ALIGN 64

/** Maximum transfer size */
#define XHCI_MTU 65536

/** xHCI PCI BAR */
#define XHCI_BAR PCI_BASE_ADDRESS_0

/** Capability register length */
#define XHCI_CAP_CAPLENGTH 0x00

/** Host controller interface version number */
#define XHCI_CAP_HCIVERSION 0x02

/** Structural parameters 1 */
#define XHCI_CAP_HCSPARAMS1 0x04

/** Number of device slots */
#define XHCI_HCSPARAMS1_SLOTS(params) ( ( (params) >> 0 ) & 0xff )

/** Number of interrupters */
#define XHCI_HCSPARAMS1_INTRS(params) ( ( (params) >> 8 ) & 0x3ff )

/** Number of ports */
#define XHCI_HCSPARAMS1_PORTS(params) ( ( (params) >> 24 ) & 0xff )

/** Structural parameters 2 */
#define XHCI_CAP_HCSPARAMS2 0x08

/** Number of page-sized scratchpad buffers */
#define XHCI_HCSPARAMS2_SCRATCHPADS(params) \
	( ( ( (params) >> 16 ) & 0x3e0 ) | ( ( (params) >> 27 ) & 0x1f ) )

/** Capability parameters */
#define XHCI_CAP_HCCPARAMS1 0x10

/** 64-bit addressing capability */
#define XHCI_HCCPARAMS1_ADDR64(params) ( ( (params) >> 0 ) & 0x1 )

/** Context size shift */
#define XHCI_HCCPARAMS1_CSZ_SHIFT(params) ( 5 + ( ( (params) >> 2 ) & 0x1 ) )

/** xHCI extended capabilities pointer */
#define XHCI_HCCPARAMS1_XECP(params) ( ( ( (params) >> 16 ) & 0xffff ) << 2 )

/** Doorbell offset */
#define XHCI_CAP_DBOFF 0x14

/** Runtime register space offset */
#define XHCI_CAP_RTSOFF 0x18

/** xHCI extended capability ID */
#define XHCI_XECP_ID(xecp) ( ( (xecp) >> 0 ) & 0xff )

/** Next xHCI extended capability pointer */
#define XHCI_XECP_NEXT(xecp) ( ( ( (xecp) >> 8 ) & 0xff ) << 2 )

/** USB legacy support extended capability */
#define XHCI_XECP_ID_LEGACY 1

/** USB legacy support BIOS owned semaphore */
#define XHCI_USBLEGSUP_BIOS 0x02

/** USB legacy support BIOS ownership flag */
#define XHCI_USBLEGSUP_BIOS_OWNED 0x01

/** USB legacy support OS owned semaphore */
#define XHCI_USBLEGSUP_OS 0x03

/** USB legacy support OS ownership flag */
#define XHCI_USBLEGSUP_OS_OWNED 0x01

/** USB legacy support control/status */
#define XHCI_USBLEGSUP_CTLSTS 0x04

/** Supported protocol extended capability */
#define XHCI_XECP_ID_SUPPORTED 2

/** Supported protocol revision */
#define XHCI_SUPPORTED_REVISION 0x00

/** Supported protocol minor revision */
#define XHCI_SUPPORTED_REVISION_VER(revision) ( ( (revision) >> 16 ) & 0xffff )

/** Supported protocol name */
#define XHCI_SUPPORTED_NAME 0x04

/** Supported protocol ports */
#define XHCI_SUPPORTED_PORTS 0x08

/** Supported protocol port offset */
#define XHCI_SUPPORTED_PORTS_OFFSET(ports) ( ( (ports) >> 0 ) & 0xff )

/** Supported protocol port count */
#define XHCI_SUPPORTED_PORTS_COUNT(ports) ( ( (ports) >> 8 ) & 0xff )

/** Supported protocol PSI count */
#define XHCI_SUPPORTED_PORTS_PSIC(ports) ( ( (ports) >> 28 ) & 0x0f )

/** Supported protocol slot */
#define XHCI_SUPPORTED_SLOT 0x0c

/** Supported protocol slot type */
#define XHCI_SUPPORTED_SLOT_TYPE(slot) ( ( (slot) >> 0 ) & 0x1f )

/** Supported protocol PSI */
#define XHCI_SUPPORTED_PSI(index) ( 0x10 + ( (index) * 4 ) )

/** Supported protocol PSI value */
#define XHCI_SUPPORTED_PSI_VALUE(psi) ( ( (psi) >> 0 ) & 0x0f )

/** Supported protocol PSI mantissa */
#define XHCI_SUPPORTED_PSI_MANTISSA(psi) ( ( (psi) >> 16 ) & 0xffff )

/** Supported protocol PSI exponent */
#define XHCI_SUPPORTED_PSI_EXPONENT(psi) ( ( (psi) >> 4 ) & 0x03 )

/** Default PSI values */
enum xhci_default_psi_value {
	/** Full speed (12Mbps) */
	XHCI_SPEED_FULL = 1,
	/** Low speed (1.5Mbps) */
	XHCI_SPEED_LOW = 2,
	/** High speed (480Mbps) */
	XHCI_SPEED_HIGH = 3,
	/** Super speed */
	XHCI_SPEED_SUPER = 4,
};

/** USB command register */
#define XHCI_OP_USBCMD 0x00

/** Run/stop */
#define XHCI_USBCMD_RUN 0x00000001UL

/** Host controller reset */
#define XHCI_USBCMD_HCRST 0x00000002UL

/** USB status register */
#define XHCI_OP_USBSTS 0x04

/** Host controller halted */
#define XHCI_USBSTS_HCH 0x00000001UL

/** Page size register */
#define XHCI_OP_PAGESIZE 0x08

/** Page size */
#define XHCI_PAGESIZE(pagesize) ( (pagesize) << 12 )

/** Device notifcation control register */
#define XHCI_OP_DNCTRL 0x14

/** Command ring control register */
#define XHCI_OP_CRCR 0x18

/** Command ring cycle state */
#define XHCI_CRCR_RCS 0x00000001UL

/** Command abort */
#define XHCI_CRCR_CA 0x00000004UL

/** Command ring running */
#define XHCI_CRCR_CRR 0x00000008UL

/** Device context base address array pointer */
#define XHCI_OP_DCBAAP 0x30

/** Configure register */
#define XHCI_OP_CONFIG 0x38

/** Maximum device slots enabled */
#define XHCI_CONFIG_MAX_SLOTS_EN(slots) ( (slots) << 0 )

/** Maximum device slots enabled mask */
#define XHCI_CONFIG_MAX_SLOTS_EN_MASK \
	XHCI_CONFIG_MAX_SLOTS_EN ( 0xff )

/** Port status and control register */
#define XHCI_OP_PORTSC(port) ( 0x400 - 0x10 + ( (port) << 4 ) )

/** Current connect status */
#define XHCI_PORTSC_CCS 0x00000001UL

/** Port enabled */
#define XHCI_PORTSC_PED 0x00000002UL

/** Port reset */
#define XHCI_PORTSC_PR 0x00000010UL

/** Port link state */
#define XHCI_PORTSC_PLS(pls) ( (pls) << 5 )

/** Disabled port link state */
#define XHCI_PORTSC_PLS_DISABLED XHCI_PORTSC_PLS ( 4 )

/** RxDetect port link state */
#define XHCI_PORTSC_PLS_RXDETECT XHCI_PORTSC_PLS ( 5 )

/** Port link state mask */
#define XHCI_PORTSC_PLS_MASK XHCI_PORTSC_PLS ( 0xf )

/** Port power */
#define XHCI_PORTSC_PP 0x00000200UL

/** Time to delay after enabling power to a port */
#define XHCI_PORT_POWER_DELAY_MS 20

/** Port speed ID value */
#define XHCI_PORTSC_PSIV(portsc) ( ( (portsc) >> 10 ) & 0xf )

/** Port indicator control */
#define XHCI_PORTSC_PIC(indicators) ( (indicators) << 14 )

/** Port indicator control mask */
#define XHCI_PORTSC_PIC_MASK XHCI_PORTSC_PIC ( 3 )

/** Port link state write strobe */
#define XHCI_PORTSC_LWS 0x00010000UL

/** Time to delay after writing the port link state */
#define XHCI_LINK_STATE_DELAY_MS 20

/** Connect status change */
#define XHCI_PORTSC_CSC 0x00020000UL

/** Port enabled/disabled change */
#define XHCI_PORTSC_PEC 0x00040000UL

/** Warm port reset change */
#define XHCI_PORTSC_WRC 0x00080000UL

/** Over-current change */
#define XHCI_PORTSC_OCC 0x00100000UL

/** Port reset change */
#define XHCI_PORTSC_PRC 0x00200000UL

/** Port link state change */
#define XHCI_PORTSC_PLC 0x00400000UL

/** Port config error change */
#define XHCI_PORTSC_CEC 0x00800000UL

/** Port status change mask */
#define XHCI_PORTSC_CHANGE					\
	( XHCI_PORTSC_CSC | XHCI_PORTSC_PEC | XHCI_PORTSC_WRC |	\
	  XHCI_PORTSC_OCC | XHCI_PORTSC_PRC | XHCI_PORTSC_PLC |	\
	  XHCI_PORTSC_CEC )

/** Port status and control bits which should be preserved
 *
 * The port status and control register is a horrendous mix of
 * differing semantics.  Some bits are written to only when a separate
 * write strobe bit is set.  Some bits should be preserved when
 * modifying other bits.  Some bits will be cleared if written back as
 * a one.  Most excitingly, the "port enabled" bit has the semantics
 * that 1=enabled, 0=disabled, yet writing a 1 will disable the port.
 */
#define XHCI_PORTSC_PRESERVE ( XHCI_PORTSC_PP | XHCI_PORTSC_PIC_MASK )

/** Port power management status and control register */
#define XHCI_OP_PORTPMSC(port) ( 0x404 - 0x10 + ( (port) << 4 ) )

/** Port link info register */
#define XHCI_OP_PORTLI(port) ( 0x408 - 0x10 + ( (port) << 4 ) )

/** Port hardware link power management control register */
#define XHCI_OP_PORTHLPMC(port) ( 0x40c - 0x10 + ( (port) << 4 ) )

/** Event ring segment table size register */
#define XHCI_RUN_ERSTSZ(intr) ( 0x28 + ( (intr) << 5 ) )

/** Event ring segment table base address register */
#define XHCI_RUN_ERSTBA(intr) ( 0x30 + ( (intr) << 5 ) )

/** Event ring dequeue pointer register */
#define XHCI_RUN_ERDP(intr) ( 0x38 + ( (intr) << 5 ) )

/** A transfer request block template */
struct xhci_trb_template {
	/** Parameter */
	uint64_t parameter;
	/** Status */
	uint32_t status;
	/** Control */
	uint32_t control;
};

/** A transfer request block */
struct xhci_trb_common {
	/** Reserved */
	uint64_t reserved_a;
	/** Reserved */
	uint32_t reserved_b;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Reserved */
	uint16_t reserved_c;
} __attribute__ (( packed ));

/** Transfer request block cycle bit flag */
#define XHCI_TRB_C 0x01

/** Transfer request block toggle cycle bit flag */
#define XHCI_TRB_TC 0x02

/** Transfer request block chain flag */
#define XHCI_TRB_CH 0x10

/** Transfer request block interrupt on completion flag */
#define XHCI_TRB_IOC 0x20

/** Transfer request block immediate data flag */
#define XHCI_TRB_IDT 0x40

/** Transfer request block type */
#define XHCI_TRB_TYPE(type) ( (type) << 2 )

/** Transfer request block type mask */
#define XHCI_TRB_TYPE_MASK XHCI_TRB_TYPE ( 0x3f )

/** A normal transfer request block */
struct xhci_trb_normal {
	/** Data buffer */
	uint64_t data;
	/** Length */
	uint32_t len;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Reserved */
	uint16_t reserved;
} __attribute__ (( packed ));

/** A normal transfer request block */
#define XHCI_TRB_NORMAL XHCI_TRB_TYPE ( 1 )

/** Construct TD size field */
#define XHCI_TD_SIZE(remaining) \
	( ( ( (remaining) <= 0xf ) ? remaining : 0xf ) << 17 )

/** A setup stage transfer request block */
struct xhci_trb_setup {
	/** Setup packet */
	struct usb_setup_packet packet;
	/** Length */
	uint32_t len;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Transfer direction */
	uint8_t direction;
	/** Reserved */
	uint8_t reserved;
} __attribute__ (( packed ));

/** A setup stage transfer request block */
#define XHCI_TRB_SETUP XHCI_TRB_TYPE ( 2 )

/** Setup stage input data direction */
#define XHCI_SETUP_IN 3

/** Setup stage output data direction */
#define XHCI_SETUP_OUT 2

/** A data stage transfer request block */
struct xhci_trb_data {
	/** Data buffer */
	uint64_t data;
	/** Length */
	uint32_t len;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Transfer direction */
	uint8_t direction;
	/** Reserved */
	uint8_t reserved;
} __attribute__ (( packed ));

/** A data stage transfer request block */
#define XHCI_TRB_DATA XHCI_TRB_TYPE ( 3 )

/** Input data direction */
#define XHCI_DATA_IN 0x01

/** Output data direction */
#define XHCI_DATA_OUT 0x00

/** A status stage transfer request block */
struct xhci_trb_status {
	/** Reserved */
	uint64_t reserved_a;
	/** Reserved */
	uint32_t reserved_b;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Direction */
	uint8_t direction;
	/** Reserved */
	uint8_t reserved_c;
} __attribute__ (( packed ));

/** A status stage transfer request block */
#define XHCI_TRB_STATUS XHCI_TRB_TYPE ( 4 )

/** Input status direction */
#define XHCI_STATUS_IN 0x01

/** Output status direction */
#define XHCI_STATUS_OUT 0x00

/** A link transfer request block */
struct xhci_trb_link {
	/** Next ring segment */
	uint64_t next;
	/** Reserved */
	uint32_t reserved_a;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Reserved */
	uint16_t reserved_c;
} __attribute__ (( packed ));

/** A link transfer request block */
#define XHCI_TRB_LINK XHCI_TRB_TYPE ( 6 )

/** A no-op transfer request block */
#define XHCI_TRB_NOP XHCI_TRB_TYPE ( 8 )

/** An enable slot transfer request block */
struct xhci_trb_enable_slot {
	/** Reserved */
	uint64_t reserved_a;
	/** Reserved */
	uint32_t reserved_b;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Slot type */
	uint8_t slot;
	/** Reserved */
	uint8_t reserved_c;
} __attribute__ (( packed ));

/** An enable slot transfer request block */
#define XHCI_TRB_ENABLE_SLOT XHCI_TRB_TYPE ( 9 )

/** A disable slot transfer request block */
struct xhci_trb_disable_slot {
	/** Reserved */
	uint64_t reserved_a;
	/** Reserved */
	uint32_t reserved_b;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Reserved */
	uint8_t reserved_c;
	/** Slot ID */
	uint8_t slot;
} __attribute__ (( packed ));

/** A disable slot transfer request block */
#define XHCI_TRB_DISABLE_SLOT XHCI_TRB_TYPE ( 10 )

/** A context transfer request block */
struct xhci_trb_context {
	/** Input context */
	uint64_t input;
	/** Reserved */
	uint32_t reserved_a;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Reserved */
	uint8_t reserved_b;
	/** Slot ID */
	uint8_t slot;
} __attribute__ (( packed ));

/** An address device transfer request block */
#define XHCI_TRB_ADDRESS_DEVICE XHCI_TRB_TYPE ( 11 )

/** A configure endpoint transfer request block */
#define XHCI_TRB_CONFIGURE_ENDPOINT XHCI_TRB_TYPE ( 12 )

/** An evaluate context transfer request block */
#define XHCI_TRB_EVALUATE_CONTEXT XHCI_TRB_TYPE ( 13 )

/** A reset endpoint transfer request block */
struct xhci_trb_reset_endpoint {
	/** Reserved */
	uint64_t reserved_a;
	/** Reserved */
	uint32_t reserved_b;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Endpoint ID */
	uint8_t endpoint;
	/** Slot ID */
	uint8_t slot;
} __attribute__ (( packed ));

/** A reset endpoint transfer request block */
#define XHCI_TRB_RESET_ENDPOINT XHCI_TRB_TYPE ( 14 )

/** A stop endpoint transfer request block */
struct xhci_trb_stop_endpoint {
	/** Reserved */
	uint64_t reserved_a;
	/** Reserved */
	uint32_t reserved_b;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Endpoint ID */
	uint8_t endpoint;
	/** Slot ID */
	uint8_t slot;
} __attribute__ (( packed ));

/** A stop endpoint transfer request block */
#define XHCI_TRB_STOP_ENDPOINT XHCI_TRB_TYPE ( 15 )

/** A set transfer ring dequeue pointer transfer request block */
struct xhci_trb_set_tr_dequeue_pointer {
	/** Dequeue pointer */
	uint64_t dequeue;
	/** Reserved */
	uint32_t reserved;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Endpoint ID */
	uint8_t endpoint;
	/** Slot ID */
	uint8_t slot;
} __attribute__ (( packed ));

/** A set transfer ring dequeue pointer transfer request block */
#define XHCI_TRB_SET_TR_DEQUEUE_POINTER XHCI_TRB_TYPE ( 16 )

/** A no-op command transfer request block */
#define XHCI_TRB_NOP_CMD XHCI_TRB_TYPE ( 23 )

/** A transfer event transfer request block */
struct xhci_trb_transfer {
	/** Transfer TRB pointer */
	uint64_t transfer;
	/** Residual transfer length */
	uint16_t residual;
	/** Reserved */
	uint8_t reserved;
	/** Completion code */
	uint8_t code;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Endpoint ID */
	uint8_t endpoint;
	/** Slot ID */
	uint8_t slot;
} __attribute__ (( packed ));

/** A transfer event transfer request block */
#define XHCI_TRB_TRANSFER XHCI_TRB_TYPE ( 32 )

/** A command completion event transfer request block */
struct xhci_trb_complete {
	/** Command TRB pointer */
	uint64_t command;
	/** Parameter */
	uint8_t parameter[3];
	/** Completion code */
	uint8_t code;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Virtual function ID */
	uint8_t vf;
	/** Slot ID */
	uint8_t slot;
} __attribute__ (( packed ));

/** A command completion event transfer request block */
#define XHCI_TRB_COMPLETE XHCI_TRB_TYPE ( 33 )

/** xHCI completion codes */
enum xhci_completion_code {
	/** Success */
	XHCI_CMPLT_SUCCESS = 1,
	/** Short packet */
	XHCI_CMPLT_SHORT = 13,
	/** Command ring stopped */
	XHCI_CMPLT_CMD_STOPPED = 24,
};

/** A port status change transfer request block */
struct xhci_trb_port_status {
	/** Reserved */
	uint8_t reserved_a[3];
	/** Port ID */
	uint8_t port;
	/** Reserved */
	uint8_t reserved_b[7];
	/** Completion code */
	uint8_t code;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Reserved */
	uint16_t reserved_c;
} __attribute__ (( packed ));

/** A port status change transfer request block */
#define XHCI_TRB_PORT_STATUS XHCI_TRB_TYPE ( 34 )

/** A port status change transfer request block */
struct xhci_trb_host_controller {
	/** Reserved */
	uint64_t reserved_a;
	/** Reserved */
	uint8_t reserved_b[3];
	/** Completion code */
	uint8_t code;
	/** Flags */
	uint8_t flags;
	/** Type */
	uint8_t type;
	/** Reserved */
	uint16_t reserved_c;
} __attribute__ (( packed ));

/** A port status change transfer request block */
#define XHCI_TRB_HOST_CONTROLLER XHCI_TRB_TYPE ( 37 )

/** A transfer request block */
union xhci_trb {
	/** Template */
	struct xhci_trb_template template;
	/** Common fields */
	struct xhci_trb_common common;
	/** Normal TRB */
	struct xhci_trb_normal normal;
	/** Setup stage TRB */
	struct xhci_trb_setup setup;
	/** Data stage TRB */
	struct xhci_trb_data data;
	/** Status stage TRB */
	struct xhci_trb_status status;
	/** Link TRB */
	struct xhci_trb_link link;
	/** Enable slot TRB */
	struct xhci_trb_enable_slot enable;
	/** Disable slot TRB */
	struct xhci_trb_disable_slot disable;
	/** Input context TRB */
	struct xhci_trb_context context;
	/** Reset endpoint TRB */
	struct xhci_trb_reset_endpoint reset;
	/** Stop endpoint TRB */
	struct xhci_trb_stop_endpoint stop;
	/** Set transfer ring dequeue pointer TRB */
	struct xhci_trb_set_tr_dequeue_pointer dequeue;
	/** Transfer event */
	struct xhci_trb_transfer transfer;
	/** Command completion event */
	struct xhci_trb_complete complete;
	/** Port status changed event */
	struct xhci_trb_port_status port;
	/** Host controller event */
	struct xhci_trb_host_controller host;
} __attribute__ (( packed ));

/** An input control context */
struct xhci_control_context {
	/** Drop context flags */
	uint32_t drop;
	/** Add context flags */
	uint32_t add;
	/** Reserved */
	uint32_t reserved_a[5];
	/** Configuration value */
	uint8_t config;
	/** Interface number */
	uint8_t intf;
	/** Alternate setting */
	uint8_t alt;
	/** Reserved */
	uint8_t reserved_b;
} __attribute__ (( packed ));

/** A slot context */
struct xhci_slot_context {
	/** Device info */
	uint32_t info;
	/** Maximum exit latency */
	uint16_t latency;
	/** Root hub port number */
	uint8_t port;
	/** Number of downstream ports */
	uint8_t ports;
	/** TT hub slot ID */
	uint8_t tt_id;
	/** TT port number */
	uint8_t tt_port;
	/** Interrupter target */
	uint16_t intr;
	/** USB address */
	uint8_t address;
	/** Reserved */
	uint16_t reserved_a;
	/** Slot state */
	uint8_t state;
	/** Reserved */
	uint32_t reserved_b[4];
} __attribute__ (( packed ));

/** Construct slot context device info */
#define XHCI_SLOT_INFO( entries, hub, speed, route ) \
	( ( (entries) << 27 ) | ( (hub) << 26 ) | ( (speed) << 20 ) | (route) )

/** An endpoint context */
struct xhci_endpoint_context {
	/** Endpoint state */
	uint8_t state;
	/** Stream configuration */
	uint8_t stream;
	/** Polling interval */
	uint8_t interval;
	/** Max ESIT payload high */
	uint8_t esit_high;
	/** Endpoint type */
	uint8_t type;
	/** Maximum burst size */
	uint8_t burst;
	/** Maximum packet size */
	uint16_t mtu;
	/** Transfer ring dequeue pointer */
	uint64_t dequeue;
	/** Average TRB length */
	uint16_t trb_len;
	/** Max ESIT payload low */
	uint16_t esit_low;
	/** Reserved */
	uint32_t reserved[3];
} __attribute__ (( packed ));

/** Endpoint states */
enum xhci_endpoint_state {
	/** Endpoint is disabled */
	XHCI_ENDPOINT_DISABLED = 0,
	/** Endpoint is running */
	XHCI_ENDPOINT_RUNNING = 1,
	/** Endpoint is halted due to a USB Halt condition */
	XHCI_ENDPOINT_HALTED = 2,
	/** Endpoint is stopped */
	XHCI_ENDPOINT_STOPPED = 3,
	/** Endpoint is halted due to a TRB error */
	XHCI_ENDPOINT_ERROR = 4,
};

/** Endpoint state mask */
#define XHCI_ENDPOINT_STATE_MASK 0x07

/** Endpoint type */
#define XHCI_EP_TYPE(type) ( (type) << 3 )

/** Control endpoint type */
#define XHCI_EP_TYPE_CONTROL XHCI_EP_TYPE ( 4 )

/** Input endpoint type */
#define XHCI_EP_TYPE_IN XHCI_EP_TYPE ( 4 )

/** Periodic endpoint type */
#define XHCI_EP_TYPE_PERIODIC XHCI_EP_TYPE ( 1 )

/** Endpoint dequeue cycle state */
#define XHCI_EP_DCS 0x00000001UL

/** Control endpoint average TRB length */
#define XHCI_EP0_TRB_LEN 8

/** An event ring segment */
struct xhci_event_ring_segment {
	/** Base address */
	uint64_t base;
	/** Number of TRBs */
	uint32_t count;
	/** Reserved */
	uint32_t reserved;
} __attribute__ (( packed ));

/** A transfer request block command/transfer ring */
struct xhci_trb_ring {
	/** Producer counter */
	unsigned int prod;
	/** Consumer counter */
	unsigned int cons;
	/** Ring size (log2) */
	unsigned int shift;
	/** Ring counter mask */
	unsigned int mask;

	/** I/O buffers */
	struct io_buffer **iobuf;

	/** Transfer request blocks */
	union xhci_trb *trb;
	/** Length of transfer request blocks */
	size_t len;
	/** Link TRB (if applicable) */
	struct xhci_trb_link *link;

	/** Doorbell register */
	void *db;
	/** Doorbell register value */
	uint32_t dbval;
};

/** An event ring */
struct xhci_event_ring {
	/** Consumer counter */
	unsigned int cons;
	/** Event ring segment table */
	struct xhci_event_ring_segment *segment;
	/** Transfer request blocks */
	union xhci_trb *trb;
};

/**
 * Calculate doorbell register value
 *
 * @v target		Doorbell target
 * @v stream		Doorbell stream ID
 * @ret dbval		Doorbell register value
 */
#define XHCI_DBVAL( target, stream ) ( (target) | ( (stream) << 16 ) )

/**
 * Calculate space used in TRB ring
 *
 * @v ring		TRB ring
 * @ret fill		Number of entries used
 */
static inline __attribute__ (( always_inline )) unsigned int
xhci_ring_fill ( struct xhci_trb_ring *ring ) {

	return ( ring->prod - ring->cons );
}

/**
 * Calculate space remaining in TRB ring
 *
 * @v ring		TRB ring
 * @ret remaining	Number of entries remaining
 *
 * xHCI does not allow us to completely fill a ring; there must be at
 * least one free entry (excluding the Link TRB).
 */
static inline __attribute__ (( always_inline )) unsigned int
xhci_ring_remaining ( struct xhci_trb_ring *ring ) {
	unsigned int fill = xhci_ring_fill ( ring );

	/* We choose to utilise rings with ( 2^n + 1 ) entries, with
	 * the final entry being a Link TRB.  The maximum fill level
	 * is therefore
	 *
	 *   ( ( 2^n + 1 ) - 1 (Link TRB) - 1 (one slot always empty)
	 *       == ( 2^n - 1 )
	 *
	 * which is therefore equal to the ring mask.
	 */
	assert ( fill <= ring->mask );
	return ( ring->mask - fill );
}

/**
 * Calculate physical address of most recently consumed TRB
 *
 * @v ring		TRB ring
 * @ret trb		TRB physical address
 */
static inline __attribute__ (( always_inline )) physaddr_t
xhci_ring_consumed ( struct xhci_trb_ring *ring ) {
	unsigned int index = ( ( ring->cons - 1 ) & ring->mask );

	return virt_to_phys ( &ring->trb[index] );
}

/** Slot context index */
#define XHCI_CTX_SLOT 0

/** Calculate context index from USB endpoint address */
#define XHCI_CTX(address)						\
	( (address) ? ( ( ( (address) & 0x0f ) << 1 ) |			\
			( ( (address) & 0x80 ) >> 7 ) ) : 1 )

/** Endpoint zero context index */
#define XHCI_CTX_EP0 XHCI_CTX ( 0x00 )

/** End of contexts */
#define XHCI_CTX_END 32

/** Device context index */
#define XHCI_DCI(ctx) ( (ctx) + 0 )

/** Input context index */
#define XHCI_ICI(ctx) ( (ctx) + 1 )

/** Number of TRBs (excluding Link TRB) in the command ring
 *
 * This is a policy decision.
 */
#define XHCI_CMD_TRBS_LOG2 2

/** Number of TRBs in the event ring
 *
 * This is a policy decision.
 */
#define XHCI_EVENT_TRBS_LOG2 6

/** Number of TRBs in a transfer ring
 *
 * This is a policy decision.
 */
#define XHCI_TRANSFER_TRBS_LOG2 6

/** Maximum time to wait for BIOS to release ownership
 *
 * This is a policy decision.
 */
#define XHCI_USBLEGSUP_MAX_WAIT_MS 100

/** Maximum time to wait for host controller to stop
 *
 * This is a policy decision.
 */
#define XHCI_STOP_MAX_WAIT_MS 100

/** Maximum time to wait for reset to complete
 *
 * This is a policy decision.
 */
#define XHCI_RESET_MAX_WAIT_MS 500

/** Maximum time to wait for a command to complete
 *
 * The "address device" command involves waiting for a response to a
 * USB control transaction, and so we must wait for up to the 5000ms
 * that USB allows for devices to respond to control transactions.
 */
#define XHCI_COMMAND_MAX_WAIT_MS USB_CONTROL_MAX_WAIT_MS

/** Time to delay after aborting a command
 *
 * This is a policy decision
 */
#define XHCI_COMMAND_ABORT_DELAY_MS 500

/** Maximum time to wait for a port reset to complete
 *
 * This is a policy decision.
 */
#define XHCI_PORT_RESET_MAX_WAIT_MS 500

/** Intel PCH quirk */
struct xhci_pch {
	/** USB2 port routing register original value */
	uint32_t xusb2pr;
	/** USB3 port SuperSpeed enable register original value */
	uint32_t usb3pssen;
};

/** Intel PCH quirk flag */
#define XHCI_PCH 0x0001

/** Intel PCH USB2 port routing register */
#define XHCI_PCH_XUSB2PR 0xd0

/** Intel PCH USB2 port routing mask register */
#define XHCI_PCH_XUSB2PRM 0xd4

/** Intel PCH SuperSpeed enable register */
#define XHCI_PCH_USB3PSSEN 0xd8

/** Intel PCH USB3 port routing mask register */
#define XHCI_PCH_USB3PRM 0xdc

/** Invalid protocol speed ID values quirk */
#define XHCI_BAD_PSIV 0x0002

/** An xHCI device */
struct xhci_device {
	/** Registers */
	void *regs;
	/** Name */
	const char *name;
	/** Quirks */
	unsigned int quirks;

	/** Capability registers */
	void *cap;
	/** Operational registers */
	void *op;
	/** Runtime registers */
	void *run;
	/** Doorbell registers */
	void *db;

	/** Number of device slots */
	unsigned int slots;
	/** Number of interrupters */
	unsigned int intrs;
	/** Number of ports */
	unsigned int ports;

	/** Number of page-sized scratchpad buffers */
	unsigned int scratchpads;

	/** 64-bit addressing capability */
	int addr64;
	/** Context size shift */
	unsigned int csz_shift;
	/** xHCI extended capabilities offset */
	unsigned int xecp;

	/** Page size */
	size_t pagesize;

	/** USB legacy support capability (if present and enabled) */
	unsigned int legacy;

	/** Device context base address array */
	uint64_t *dcbaa;

	/** Scratchpad buffer area */
	userptr_t scratchpad;
	/** Scratchpad buffer array */
	uint64_t *scratchpad_array;

	/** Command ring */
	struct xhci_trb_ring command;
	/** Event ring */
	struct xhci_event_ring event;
	/** Current command (if any) */
	union xhci_trb *pending;

	/** Device slots, indexed by slot ID */
	struct xhci_slot **slot;

	/** USB bus */
	struct usb_bus *bus;

	/** Intel PCH quirk */
	struct xhci_pch pch;
};

/** An xHCI device slot */
struct xhci_slot {
	/** xHCI device */
	struct xhci_device *xhci;
	/** USB device */
	struct usb_device *usb;
	/** Slot ID */
	unsigned int id;
	/** Slot context */
	struct xhci_slot_context *context;
	/** Route string */
	unsigned int route;
	/** Root hub port number */
	unsigned int port;
	/** Protocol speed ID */
	unsigned int psiv;
	/** Number of ports (if this device is a hub) */
	unsigned int ports;
	/** Transaction translator slot ID */
	unsigned int tt_id;
	/** Transaction translator port */
	unsigned int tt_port;
	/** Endpoints, indexed by context ID */
	struct xhci_endpoint *endpoint[XHCI_CTX_END];
};

/** An xHCI endpoint */
struct xhci_endpoint {
	/** xHCI device */
	struct xhci_device *xhci;
	/** xHCI slot */
	struct xhci_slot *slot;
	/** USB endpoint */
	struct usb_endpoint *ep;
	/** Context index */
	unsigned int ctx;
	/** Endpoint type */
	unsigned int type;
	/** Endpoint interval */
	unsigned int interval;
	/** Endpoint context */
	struct xhci_endpoint_context *context;
	/** Transfer ring */
	struct xhci_trb_ring ring;
};

#endif /* _IPXE_XHCI_H */
