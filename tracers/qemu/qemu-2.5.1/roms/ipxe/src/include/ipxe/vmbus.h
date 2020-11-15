#ifndef _IPXE_VMBUS_H
#define _IPXE_VMBUS_H

/** @file
 *
 * Hyper-V virtual machine bus
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <byteswap.h>
#include <ipxe/uuid.h>
#include <ipxe/device.h>
#include <ipxe/tables.h>
#include <ipxe/uaccess.h>
#include <ipxe/iobuf.h>
#include <ipxe/hyperv.h>

/** VMBus message connection ID */
#define VMBUS_MESSAGE_ID 1

/** VMBus event connection ID */
#define VMBUS_EVENT_ID 2

/** VMBus message type */
#define VMBUS_MESSAGE_TYPE 1

/** VMBus message synthetic interrupt */
#define VMBUS_MESSAGE_SINT 2

/** VMBus version number */
union vmbus_version {
	/** Raw version */
	uint32_t raw;
	/** Major/minor version */
	struct {
		/** Minor version */
		uint16_t minor;
		/** Major version */
		uint16_t major;
	};
} __attribute__ (( packed ));

/** Known VMBus protocol versions */
enum vmbus_raw_version {
	/** Windows Server 2008 */
	VMBUS_VERSION_WS2008 = ( ( 0 << 16 ) | ( 13 << 0 ) ),
	/** Windows 7 */
	VMBUS_VERSION_WIN7 = ( ( 1 << 16 ) | ( 1 << 0 ) ),
	/** Windows 8 */
	VMBUS_VERSION_WIN8 = ( ( 2 << 16 ) | ( 4 << 0 ) ),
	/** Windows 8.1 */
	VMBUS_VERSION_WIN8_1 = ( ( 3 << 16 ) | ( 0 << 0 ) ),
};

/** Guest physical address range descriptor */
struct vmbus_gpa_range {
	/** Byte count */
	uint32_t len;
	/** Starting byte offset */
	uint32_t offset;
	/** Page frame numbers
	 *
	 * The length of this array is implied by the byte count and
	 * starting offset.
	 */
	uint64_t pfn[0];
} __attribute__ (( packed ));

/** VMBus message header */
struct vmbus_message_header {
	/** Message type */
	uint32_t type;
	/** Reserved */
	uint32_t reserved;
} __attribute__ (( packed ));

/** VMBus message types */
enum vmbus_message_type {
	VMBUS_OFFER_CHANNEL = 1,
	VMBUS_REQUEST_OFFERS = 3,
	VMBUS_ALL_OFFERS_DELIVERED = 4,
	VMBUS_OPEN_CHANNEL = 5,
	VMBUS_OPEN_CHANNEL_RESULT = 6,
	VMBUS_CLOSE_CHANNEL = 7,
	VMBUS_GPADL_HEADER = 8,
	VMBUS_GPADL_CREATED = 10,
	VMBUS_GPADL_TEARDOWN = 11,
	VMBUS_GPADL_TORNDOWN = 12,
	VMBUS_INITIATE_CONTACT = 14,
	VMBUS_VERSION_RESPONSE = 15,
	VMBUS_UNLOAD = 16,
	VMBUS_UNLOAD_RESPONSE = 17,
};

/** VMBus "offer channel" message */
struct vmbus_offer_channel {
	/** Message header */
	struct vmbus_message_header header;
	/** Channel type */
	union uuid type;
	/** Channel instance */
	union uuid instance;
	/** Reserved */
	uint8_t reserved_a[16];
	/** Flags */
	uint16_t flags;
	/** Reserved */
	uint8_t reserved_b[2];
	/** User data */
	uint8_t data[120];
	/** Reserved */
	uint8_t reserved_c[4];
	/** Channel ID */
	uint32_t channel;
	/** Monitor ID */
	uint8_t monitor;
	/** Monitor exists */
	uint8_t monitored;
	/** Reserved */
	uint8_t reserved[2];
	/** Connection ID */
	uint32_t connection;
} __attribute__ (( packed ));

/** VMBus "open channel" message */
struct vmbus_open_channel {
	/** Message header */
	struct vmbus_message_header header;
	/** Channel ID */
	uint32_t channel;
	/** Open ID */
	uint32_t id;
	/** Ring buffer GPADL ID */
	uint32_t gpadl;
	/** Reserved */
	uint32_t reserved;
	/** Outbound ring buffer size (in pages) */
	uint32_t out_pages;
	/** User-specific data */
	uint8_t data[120];
} __attribute__ (( packed ));

/** VMBus "open channel result" message */
struct vmbus_open_channel_result {
	/** Message header */
	struct vmbus_message_header header;
	/** Channel ID */
	uint32_t channel;
	/** Open ID */
	uint32_t id;
	/** Status */
	uint32_t status;
} __attribute__ (( packed ));

/** VMBus "close channel" message */
struct vmbus_close_channel {
	/** Message header */
	struct vmbus_message_header header;
	/** Channel ID */
	uint32_t channel;
} __attribute__ (( packed ));

/** VMBus "GPADL header" message */
struct vmbus_gpadl_header {
	/** Message header */
	struct vmbus_message_header header;
	/** Channel ID */
	uint32_t channel;
	/** GPADL ID */
	uint32_t gpadl;
	/** Length of range descriptors */
	uint16_t range_len;
	/** Number of range descriptors */
	uint16_t range_count;
	/** Range descriptors */
	struct vmbus_gpa_range range[0];
} __attribute__ (( packed ));

/** VMBus "GPADL created" message */
struct vmbus_gpadl_created {
	/** Message header */
	struct vmbus_message_header header;
	/** Channel ID */
	uint32_t channel;
	/** GPADL ID */
	uint32_t gpadl;
	/** Creation status */
	uint32_t status;
} __attribute__ (( packed ));

/** VMBus "GPADL teardown" message */
struct vmbus_gpadl_teardown {
	/** Message header */
	struct vmbus_message_header header;
	/** Channel ID */
	uint32_t channel;
	/** GPADL ID */
	uint32_t gpadl;
} __attribute__ (( packed ));

/** VMBus "GPADL torndown" message */
struct vmbus_gpadl_torndown {
	/** Message header */
	struct vmbus_message_header header;
	/** GPADL ID */
	uint32_t gpadl;
} __attribute__ (( packed ));

/** VMBus "initiate contact" message */
struct vmbus_initiate_contact {
	/** Message header */
	struct vmbus_message_header header;
	/** Requested version */
	union vmbus_version version;
	/** Target virtual CPU */
	uint32_t vcpu;
	/** Interrupt page base address */
	uint64_t intr;
	/** Parent to child monitor page base address */
	uint64_t monitor_in;
	/** Child to parent monitor page base address */
	uint64_t monitor_out;
} __attribute__ (( packed ));

/** VMBus "version response" message */
struct vmbus_version_response {
	/** Message header */
	struct vmbus_message_header header;
	/** Version is supported */
	uint8_t supported;
	/** Reserved */
	uint8_t reserved[3];
	/** Version */
	union vmbus_version version;
} __attribute__ (( packed ));

/** VMBus message */
union vmbus_message {
	/** Common message header */
	struct vmbus_message_header header;
	/** "Offer channel" message */
	struct vmbus_offer_channel offer;
	/** "Open channel" message */
	struct vmbus_open_channel open;
	/** "Open channel result" message */
	struct vmbus_open_channel_result opened;
	/** "Close channel" message */
	struct vmbus_close_channel close;
	/** "GPADL header" message */
	struct vmbus_gpadl_header gpadlhdr;
	/** "GPADL created" message */
	struct vmbus_gpadl_created created;
	/** "GPADL teardown" message */
	struct vmbus_gpadl_teardown teardown;
	/** "GPADL torndown" message */
	struct vmbus_gpadl_torndown torndown;
	/** "Initiate contact" message */
	struct vmbus_initiate_contact initiate;
	/** "Version response" message */
	struct vmbus_version_response version;
};

/** VMBus packet header */
struct vmbus_packet_header {
	/** Type */
	uint16_t type;
	/** Length of packet header (in quadwords) */
	uint16_t hdr_qlen;
	/** Length of packet (in quadwords) */
	uint16_t qlen;
	/** Flags */
	uint16_t flags;
	/** Transaction ID
	 *
	 * This is an opaque token: we therefore treat it as
	 * native-endian and don't worry about byte-swapping.
	 */
	uint64_t xid;
} __attribute__ (( packed ));

/** VMBus packet types */
enum vmbus_packet_type {
	VMBUS_DATA_INBAND = 6,
	VMBUS_DATA_XFER_PAGES = 7,
	VMBUS_DATA_GPA_DIRECT = 9,
	VMBUS_CANCELLATION = 10,
	VMBUS_COMPLETION = 11,
};

/** VMBus packet flags */
enum vmbus_packet_flags {
	VMBUS_COMPLETION_REQUESTED = 0x0001,
};

/** VMBus GPA direct header */
struct vmbus_gpa_direct_header {
	/** Packet header */
	struct vmbus_packet_header header;
	/** Reserved */
	uint32_t reserved;
	/** Number of range descriptors */
	uint32_t range_count;
	/** Range descriptors */
	struct vmbus_gpa_range range[0];
} __attribute__ (( packed ));

/** VMBus transfer page range */
struct vmbus_xfer_page_range {
	/** Length */
	uint32_t len;
	/** Offset */
	uint32_t offset;
} __attribute__ (( packed ));

/** VMBus transfer page header */
struct vmbus_xfer_page_header {
	/** Packet header */
	struct vmbus_packet_header header;
	/** Page set ID */
	uint16_t pageset;
	/** Sender owns page set */
	uint8_t owner;
	/** Reserved */
	uint8_t reserved;
	/** Number of range descriptors */
	uint32_t range_count;
	/** Range descriptors */
	struct vmbus_xfer_page_range range[0];
} __attribute__ (( packed ));

/** Maximum expected size of VMBus packet header */
#define VMBUS_PACKET_MAX_HEADER_LEN 64

/** VMBus maximum-sized packet header */
union vmbus_packet_header_max {
	/** Common header */
	struct vmbus_packet_header header;
	/** GPA direct header */
	struct vmbus_gpa_direct_header gpa;
	/** Transfer page header */
	struct vmbus_xfer_page_header xfer;
	/** Padding to maximum supported size */
	uint8_t padding[VMBUS_PACKET_MAX_HEADER_LEN];
} __attribute__ (( packed ));

/** VMBus packet footer */
struct vmbus_packet_footer {
	/** Reserved */
	uint32_t reserved;
	/** Producer index of the first byte of the packet */
	uint32_t prod;
} __attribute__ (( packed ));

/** VMBus ring buffer
 *
 * This is the structure of the each of the ring buffers created when
 * a VMBus channel is opened.
 */
struct vmbus_ring {
	/** Producer index (modulo ring length) */
	uint32_t prod;
	/** Consumer index (modulo ring length) */
	uint32_t cons;
	/** Interrupt mask */
	uint32_t intr_mask;
	/** Reserved */
	uint8_t reserved[4084];
	/** Ring buffer contents */
	uint8_t data[0];
} __attribute__ (( packed ));

/** VMBus interrupt page */
struct vmbus_interrupt {
	/** Inbound interrupts */
	uint8_t in[ PAGE_SIZE / 2 ];
	/** Outbound interrupts */
	uint8_t out[ PAGE_SIZE / 2 ];
} __attribute__ (( packed ));

/** A virtual machine bus */
struct vmbus {
	/** Interrupt page */
	struct vmbus_interrupt *intr;
	/** Inbound notifications */
	struct hv_monitor *monitor_in;
	/** Outbound notifications */
	struct hv_monitor *monitor_out;
	/** Received message buffer */
	const union vmbus_message *message;
};

struct vmbus_device;

/** VMBus channel operations */
struct vmbus_channel_operations {
	/**
	 * Handle received control packet
	 *
	 * @v vmdev		VMBus device
	 * @v xid		Transaction ID
	 * @v data		Data
	 * @v len		Length of data
	 * @ret rc		Return status code
	 */
	int ( * recv_control ) ( struct vmbus_device *vmdev, uint64_t xid,
				 const void *data, size_t len );
	/**
	 * Handle received data packet
	 *
	 * @v vmdev		VMBus device
	 * @v xid		Transaction ID
	 * @v data		Data
	 * @v len		Length of data
	 * @v list		List of I/O buffers
	 * @ret rc		Return status code
	 *
	 * This function takes ownership of the I/O buffer.  It should
	 * eventually call vmbus_send_completion() to indicate to the
	 * host that the buffer can be reused.
	 */
	int ( * recv_data ) ( struct vmbus_device *vmdev, uint64_t xid,
			      const void *data, size_t len,
			      struct list_head *list );
	/**
	 * Handle received completion packet
	 *
	 * @v vmdev		VMBus device
	 * @v xid		Transaction ID
	 * @v data		Data
	 * @v len		Length of data
	 * @ret rc		Return status code
	 */
	int ( * recv_completion ) ( struct vmbus_device *vmdev, uint64_t xid,
				    const void *data, size_t len );
	/**
	 * Handle received cancellation packet
	 *
	 * @v vmdev		VMBus device
	 * @v xid		Transaction ID
	 * @ret rc		Return status code
	 */
	int ( * recv_cancellation ) ( struct vmbus_device *vmdev,
				      uint64_t xid );
};

struct vmbus_xfer_pages;

/** VMBus transfer page set operations */
struct vmbus_xfer_pages_operations {
	/**
	 * Copy data from transfer page
	 *
	 * @v pages		Transfer page set
	 * @v data		Data buffer
	 * @v offset		Offset within page set
	 * @v len		Length within page set
	 * @ret rc		Return status code
	 */
	int ( * copy ) ( struct vmbus_xfer_pages *pages, void *data,
			 size_t offset, size_t len );
};

/** VMBus transfer page set */
struct vmbus_xfer_pages {
	/** List of all transfer page sets */
	struct list_head list;
	/** Page set ID (in protocol byte order) */
	uint16_t pageset;
	/** Page set operations */
	struct vmbus_xfer_pages_operations *op;
};

/** A VMBus device */
struct vmbus_device {
	/** Generic iPXE device */
	struct device dev;
	/** Hyper-V hypervisor */
	struct hv_hypervisor *hv;

	/** Channel ID */
	unsigned int channel;
	/** Monitor ID */
	unsigned int monitor;
	/** Signal channel
	 *
	 * @v vmdev		VMBus device
	 */
	void ( * signal ) ( struct vmbus_device *vmdev );

	/** Outbound ring buffer length */
	uint32_t out_len;
	/** Inbound ring buffer length */
	uint32_t in_len;
	/** Outbound ring buffer */
	struct vmbus_ring *out;
	/** Inbound ring buffer */
	struct vmbus_ring *in;
	/** Ring buffer GPADL ID */
	unsigned int gpadl;

	/** Channel operations */
	struct vmbus_channel_operations *op;
	/** Maximum expected data packet length */
	size_t mtu;
	/** Packet buffer */
	void *packet;
	/** List of transfer page sets */
	struct list_head pages;

	/** Driver */
	struct vmbus_driver *driver;
	/** Driver-private data */
	void *priv;
};

/** A VMBus device driver */
struct vmbus_driver {
	/** Name */
	const char *name;
	/** Device type */
	union uuid type;
	/** Probe device
	 *
	 * @v vmdev		VMBus device
	 * @ret rc		Return status code
	 */
	int ( * probe ) ( struct vmbus_device *vmdev );
	/** Remove device
	 *
	 * @v vmdev		VMBus device
	 */
	void ( * remove ) ( struct vmbus_device *vmdev );
};

/** VMBus device driver table */
#define VMBUS_DRIVERS __table ( struct vmbus_driver, "vmbus_drivers" )

/** Declare a VMBus device driver */
#define __vmbus_driver __table_entry ( VMBUS_DRIVERS, 01 )

/**
 * Set VMBus device driver-private data
 *
 * @v vmdev		VMBus device
 * @v priv		Private data
 */
static inline void vmbus_set_drvdata ( struct vmbus_device *vmdev, void *priv ){
	vmdev->priv = priv;
}

/**
 * Get VMBus device driver-private data
 *
 * @v vmdev		VMBus device
 * @ret priv		Private data
 */
static inline void * vmbus_get_drvdata ( struct vmbus_device *vmdev ) {
	return vmdev->priv;
}

/** Construct VMBus type */
#define VMBUS_TYPE( a, b, c, d, e0, e1, e2, e3, e4, e5 ) {		\
	.canonical = {							\
		cpu_to_le32 ( a ), cpu_to_le16 ( b ),			\
		cpu_to_le16 ( c ), cpu_to_be16 ( d ),			\
		{ e0, e1, e2, e3, e4, e5 }				\
	 } }

/**
 * Check if data is present in ring buffer
 *
 * @v vmdev		VMBus device
 * @v has_data		Data is present
 */
static inline __attribute__ (( always_inline )) int
vmbus_has_data ( struct vmbus_device *vmdev ) {

	return ( vmdev->in->prod != vmdev->in->cons );
}

/**
 * Register transfer page set
 *
 * @v vmdev		VMBus device
 * @v pages		Transfer page set
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
vmbus_register_pages ( struct vmbus_device *vmdev,
		       struct vmbus_xfer_pages *pages ) {

	list_add ( &pages->list, &vmdev->pages );
	return 0;
}

/**
 * Unregister transfer page set
 *
 * @v vmdev		VMBus device
 * @v pages		Transfer page set
 */
static inline __attribute__ (( always_inline )) void
vmbus_unregister_pages ( struct vmbus_device *vmdev,
			 struct vmbus_xfer_pages *pages ) {

	list_check_contains_entry ( pages, &vmdev->pages, list );
	list_del ( &pages->list );
}

extern int vmbus_establish_gpadl ( struct vmbus_device *vmdev, userptr_t data,
				   size_t len );
extern int vmbus_gpadl_teardown ( struct vmbus_device *vmdev,
				  unsigned int gpadl );
extern int vmbus_open ( struct vmbus_device *vmdev,
			struct vmbus_channel_operations *op,
			size_t out_len, size_t in_len, size_t mtu );
extern void vmbus_close ( struct vmbus_device *vmdev );
extern int vmbus_send_control ( struct vmbus_device *vmdev, uint64_t xid,
				const void *data, size_t len );
extern int vmbus_send_data ( struct vmbus_device *vmdev, uint64_t xid,
			     const void *data, size_t len,
			     struct io_buffer *iobuf );
extern int vmbus_send_completion ( struct vmbus_device *vmdev, uint64_t xid,
				   const void *data, size_t len );
extern int vmbus_send_cancellation ( struct vmbus_device *vmdev, uint64_t xid );
extern int vmbus_poll ( struct vmbus_device *vmdev );
extern void vmbus_dump_channel ( struct vmbus_device *vmdev );

extern int vmbus_probe ( struct hv_hypervisor *hv, struct device *parent );
extern void vmbus_remove ( struct hv_hypervisor *hv, struct device *parent );

#endif /* _IPXE_VMBUS_H */
