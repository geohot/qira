#ifndef _NETVSC_H
#define _NETVSC_H

/** @file
 *
 * Hyper-V network virtual service client
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Maximum supported NetVSC message length */
#define NETVSC_MTU 512

/** Maximum time to wait for a transaction to complete
 *
 * This is a policy decision.
 */
#define NETVSC_MAX_WAIT_MS 1000

/** Number of transmit ring entries
 *
 * Must be a power of two.  This is a policy decision.  This value
 * must be sufficiently small to guarantee that we never run out of
 * space in the VMBus outbound ring buffer.
 */
#define NETVSC_TX_NUM_DESC 32

/** RX data buffer page set ID
 *
 * This is a policy decision.
 */
#define NETVSC_RX_BUF_PAGESET 0xbead

/** RX data buffer length
 *
 * This is a policy decision.
 */
#define NETVSC_RX_BUF_LEN ( 16 * PAGE_SIZE )

/** Base transaction ID
 *
 * This is a policy decision.
 */
#define NETVSC_BASE_XID 0x18ae0000UL

/** Relative transaction IDs */
enum netvsc_xrid {
	/** Transmit descriptors (one per transmit buffer ID) */
	NETVSC_TX_BASE_XRID = 0,
	/** Initialisation */
	NETVSC_INIT_XRID = ( NETVSC_TX_BASE_XRID + NETVSC_TX_NUM_DESC ),
	/** NDIS version */
	NETVSC_NDIS_VERSION_XRID,
	/** Establish receive buffer */
	NETVSC_RX_ESTABLISH_XRID,
	/** Revoke receive buffer */
	NETVSC_RX_REVOKE_XRID,
};

/** NetVSC status codes */
enum netvsc_status {
	NETVSC_NONE = 0,
	NETVSC_OK = 1,
	NETVSC_FAIL = 2,
	NETVSC_TOO_NEW = 3,
	NETVSC_TOO_OLD = 4,
	NETVSC_BAD_PACKET = 5,
	NETVSC_BUSY = 6,
	NETVSC_UNSUPPORTED = 7,
};

/** NetVSC message header */
struct netvsc_header {
	/** Type */
	uint32_t type;
} __attribute__ (( packed ));

/** NetVSC initialisation message */
#define NETVSC_INIT_MSG 1

/** NetVSC initialisation message */
struct netvsc_init_message {
	/** Message header */
	struct netvsc_header header;
	/** Minimum supported protocol version */
	uint32_t min;
	/** Maximum supported protocol version */
	uint32_t max;
	/** Reserved */
	uint8_t reserved[20];
} __attribute__ (( packed ));

/** Oldest known NetVSC protocol version */
#define NETVSC_VERSION_1 2 /* sic */

/** NetVSC initialisation completion */
#define NETVSC_INIT_CMPLT 2

/** NetVSC initialisation completion */
struct netvsc_init_completion {
	/** Message header */
	struct netvsc_header header;
	/** Protocol version */
	uint32_t version;
	/** Maximum memory descriptor list length */
	uint32_t max_mdl_len;
	/** Status */
	uint32_t status;
	/** Reserved */
	uint8_t reserved[16];
} __attribute__ (( packed ));

/** NetVSC NDIS version message */
#define NETVSC_NDIS_VERSION_MSG 100

/** NetVSC NDIS version message */
struct netvsc_ndis_version_message {
	/** Message header */
	struct netvsc_header header;
	/** Major version */
	uint32_t major;
	/** Minor version */
	uint32_t minor;
	/** Reserved */
	uint8_t reserved[20];
} __attribute__ (( packed ));

/** NetVSC NDIS major version */
#define NETVSC_NDIS_MAJOR 6

/** NetVSC NDIS minor version */
#define NETVSC_NDIS_MINOR 1

/** NetVSC establish receive data buffer message */
#define NETVSC_RX_ESTABLISH_MSG 101

/** NetVSC establish receive data buffer completion */
#define NETVSC_RX_ESTABLISH_CMPLT 102

/** NetVSC revoke receive data buffer message */
#define NETVSC_RX_REVOKE_MSG 103

/** NetVSC establish transmit data buffer message */
#define NETVSC_TX_ESTABLISH_MSG 104

/** NetVSC establish transmit data buffer completion */
#define NETVSC_TX_ESTABLISH_CMPLT 105

/** NetVSC revoke transmit data buffer message */
#define NETVSC_TX_REVOKE_MSG 106

/** NetVSC establish data buffer message */
struct netvsc_establish_buffer_message {
	/** Message header */
	struct netvsc_header header;
	/** GPADL ID */
	uint32_t gpadl;
	/** Page set ID */
	uint16_t pageset;
	/** Reserved */
	uint8_t reserved[22];
} __attribute__ (( packed ));

/** NetVSC receive data buffer section */
struct netvsc_rx_buffer_section {
	/** Starting offset */
	uint32_t start;
	/** Subsection length */
	uint32_t len;
	/** Number of subsections */
	uint32_t count;
	/** Ending offset */
	uint32_t end;
} __attribute__ (( packed ));

/** NetVSC establish receive data buffer completion */
struct netvsc_rx_establish_buffer_completion {
	/** Message header */
	struct netvsc_header header;
	/** Status */
	uint32_t status;
	/** Number of sections (must be 1) */
	uint32_t count;
	/** Section descriptors */
	struct netvsc_rx_buffer_section section[1];
} __attribute__ (( packed ));

/** NetVSC establish transmit data buffer completion */
struct netvsc_tx_establish_buffer_completion {
	/** Message header */
	struct netvsc_header header;
	/** Status */
	uint32_t status;
	/** Section length */
	uint32_t len;
} __attribute__ (( packed ));

/** NetVSC revoke data buffer message */
struct netvsc_revoke_buffer_message {
	/** Message header */
	struct netvsc_header header;
	/** Page set ID */
	uint16_t pageset;
	/** Reserved */
	uint8_t reserved[26];
} __attribute__ (( packed ));

/** NetVSC RNDIS message */
#define NETVSC_RNDIS_MSG 107

/** NetVSC RNDIS message */
struct netvsc_rndis_message {
	/** Message header */
	struct netvsc_header header;
	/** RNDIS channel */
	uint32_t channel;
	/** Buffer index (or NETVSC_RNDIS_NO_BUFFER) */
	uint32_t buffer;
	/** Buffer length */
	uint32_t len;
	/** Reserved */
	uint8_t reserved[16];
} __attribute__ (( packed ));

/** RNDIS data channel (for RNDIS_PACKET_MSG only) */
#define NETVSC_RNDIS_DATA 0

/** RNDIS control channel (for all other RNDIS messages) */
#define NETVSC_RNDIS_CONTROL 1

/** "No buffer used" index */
#define NETVSC_RNDIS_NO_BUFFER 0xffffffffUL

/** A NetVSC descriptor ring */
struct netvsc_ring {
	/** Number of descriptors */
	unsigned int count;
	/** I/O buffers, indexed by buffer ID */
	struct io_buffer **iobufs;
	/** Buffer ID ring */
	uint8_t *ids;
	/** Buffer ID producer counter */
	unsigned int id_prod;
	/** Buffer ID consumer counter */
	unsigned int id_cons;
};

/**
 * Initialise descriptor ring
 *
 * @v ring		Descriptor ring
 * @v count		Maximum number of used descriptors
 * @v iobufs		I/O buffers
 * @v ids		Buffer IDs
 */
static inline __attribute__ (( always_inline )) void
netvsc_init_ring ( struct netvsc_ring *ring, unsigned int count,
		   struct io_buffer **iobufs, uint8_t *ids ) {

	ring->count = count;
	ring->iobufs = iobufs;
	ring->ids = ids;
}

/**
 * Check whether or not descriptor ring is full
 *
 * @v ring		Descriptor ring
 * @v is_full		Ring is full
 */
static inline __attribute__ (( always_inline )) int
netvsc_ring_is_full ( struct netvsc_ring *ring ) {
	unsigned int fill_level;

	fill_level = ( ring->id_prod - ring->id_cons );
	assert ( fill_level <= ring->count );
	return ( fill_level >= ring->count );
}

/**
 * Check whether or not descriptor ring is empty
 *
 * @v ring		Descriptor ring
 * @v is_empty		Ring is empty
 */
static inline __attribute__ (( always_inline )) int
netvsc_ring_is_empty ( struct netvsc_ring *ring ) {

	return ( ring->id_prod == ring->id_cons );
}

/** A NetVSC data buffer */
struct netvsc_buffer {
	/** Transfer page set */
	struct vmbus_xfer_pages pages;
	/** Establish data buffer message type */
	uint8_t establish_type;
	/** Establish data buffer relative transaction ID */
	uint8_t establish_xrid;
	/** Revoke data buffer message type */
	uint8_t revoke_type;
	/** Revoke data buffer relative transaction ID */
	uint8_t revoke_xrid;
	/** Buffer length */
	size_t len;
	/** Buffer */
	userptr_t data;
	/** GPADL ID */
	unsigned int gpadl;
};

/**
 * Initialise data buffer
 *
 * @v buffer		Data buffer
 * @v pageset		Page set ID
 * @v op		Page set operations
 * @v establish_type	Establish data buffer message type
 * @v establish_xrid	Establish data buffer relative transaction ID
 * @v revoke_type	Revoke data buffer message type
 * @v revoke_type	Revoke data buffer relative transaction ID
 * @v len		Required length
 */
static inline __attribute__ (( always_inline )) void
netvsc_init_buffer ( struct netvsc_buffer *buffer, uint16_t pageset,
		     struct vmbus_xfer_pages_operations *op,
		     uint8_t establish_type, uint8_t establish_xrid,
		     uint8_t revoke_type, uint8_t revoke_xrid, size_t len ) {

	buffer->pages.pageset = cpu_to_le16 ( pageset );
	buffer->pages.op = op;
	buffer->establish_type = establish_type;
	buffer->establish_xrid = establish_xrid;
	buffer->revoke_type = revoke_type;
	buffer->revoke_xrid = revoke_xrid;
	buffer->len = len;
}

/** A NetVSC device */
struct netvsc_device {
	/** VMBus device */
	struct vmbus_device *vmdev;
	/** RNDIS device */
	struct rndis_device *rndis;
	/** Name */
	const char *name;

	/** Transmit ring */
	struct netvsc_ring tx;
	/** Transmit buffer IDs */
	uint8_t tx_ids[NETVSC_TX_NUM_DESC];
	/** Transmit I/O buffers */
	struct io_buffer *tx_iobufs[NETVSC_TX_NUM_DESC];

	/** Receive buffer */
	struct netvsc_buffer rx;

	/** Relative transaction ID for current blocking transaction */
	unsigned int wait_xrid;
	/** Return status code for current blocking transaction */
	int wait_rc;
};

#endif /* _NETVSC_H */
