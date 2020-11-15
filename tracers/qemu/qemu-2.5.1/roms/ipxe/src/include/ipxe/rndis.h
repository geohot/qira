#ifndef _IPXE_RNDIS_H
#define _IPXE_RNDIS_H

/** @file
 *
 * Remote Network Driver Interface Specification
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>

/** Maximum time to wait for a transaction to complete
 *
 * This is a policy decision.
 */
#define RNDIS_MAX_WAIT_MS 1000

/** RNDIS message header */
struct rndis_header {
	/** Message type */
	uint32_t type;
	/** Message length */
	uint32_t len;
} __attribute__ (( packed ));

/** RNDIS initialise message */
#define RNDIS_INITIALISE_MSG 0x00000002UL

/** RNDIS initialise message */
struct rndis_initialise_message {
	/** Request ID */
	uint32_t id;
	/** Major version */
	uint32_t major;
	/** Minor version */
	uint32_t minor;
	/** Maximum transfer size */
	uint32_t mtu;
} __attribute__ (( packed ));

/** Request ID used for initialisation
 *
 * This is a policy decision.
 */
#define RNDIS_INIT_ID 0xe110e110UL

/** RNDIS major version */
#define RNDIS_VERSION_MAJOR 1

/** RNDIS minor version */
#define RNDIS_VERSION_MINOR 0

/** RNDIS maximum transfer size
 *
 * This is a policy decision.
 */
#define RNDIS_MTU 2048

/** RNDIS initialise completion */
#define RNDIS_INITIALISE_CMPLT 0x80000002UL

/** RNDIS initialise completion */
struct rndis_initialise_completion {
	/** Request ID */
	uint32_t id;
	/** Status */
	uint32_t status;
	/** Major version */
	uint32_t major;
	/** Minor version */
	uint32_t minor;
	/** Device flags */
	uint32_t flags;
	/** Medium */
	uint32_t medium;
	/** Maximum packets per transfer */
	uint32_t max_pkts;
	/** Maximum transfer size */
	uint32_t mtu;
	/** Packet alignment factor */
	uint32_t align;
	/** Reserved */
	uint32_t reserved;
} __attribute__ (( packed ));

/** RNDIS halt message */
#define RNDIS_HALT_MSG 0x00000003UL

/** RNDIS halt message */
struct rndis_halt_message {
	/** Request ID */
	uint32_t id;
} __attribute__ (( packed ));

/** RNDIS query OID message */
#define RNDIS_QUERY_MSG 0x00000004UL

/** RNDIS set OID message */
#define RNDIS_SET_MSG 0x00000005UL

/** RNDIS query or set OID message */
struct rndis_oid_message {
	/** Request ID */
	uint32_t id;
	/** Object ID */
	uint32_t oid;
	/** Information buffer length */
	uint32_t len;
	/** Information buffer offset */
	uint32_t offset;
	/** Reserved */
	uint32_t reserved;
} __attribute__ (( packed ));

/** RNDIS query OID completion */
#define RNDIS_QUERY_CMPLT 0x80000004UL

/** RNDIS query OID completion */
struct rndis_query_completion {
	/** Request ID */
	uint32_t id;
	/** Status */
	uint32_t status;
	/** Information buffer length */
	uint32_t len;
	/** Information buffer offset */
	uint32_t offset;
} __attribute__ (( packed ));

/** RNDIS set OID completion */
#define RNDIS_SET_CMPLT 0x80000005UL

/** RNDIS set OID completion */
struct rndis_set_completion {
	/** Request ID */
	uint32_t id;
	/** Status */
	uint32_t status;
} __attribute__ (( packed ));

/** RNDIS reset message */
#define RNDIS_RESET_MSG 0x00000006UL

/** RNDIS reset message */
struct rndis_reset_message {
	/** Reserved */
	uint32_t reserved;
} __attribute__ (( packed ));

/** RNDIS reset completion */
#define RNDIS_RESET_CMPLT 0x80000006UL

/** RNDIS reset completion */
struct rndis_reset_completion {
	/** Status */
	uint32_t status;
	/** Addressing reset */
	uint32_t addr;
} __attribute__ (( packed ));

/** RNDIS indicate status message */
#define RNDIS_INDICATE_STATUS_MSG 0x00000007UL

/** RNDIS diagnostic information */
struct rndis_diagnostic_info {
	/** Status */
	uint32_t status;
	/** Error offset */
	uint32_t offset;
} __attribute__ (( packed ));

/** RNDIS indicate status message */
struct rndis_indicate_status_message {
	/** Status */
	uint32_t status;
	/** Status buffer length */
	uint32_t len;
	/** Status buffer offset */
	uint32_t offset;
	/** Diagnostic information (optional) */
	struct rndis_diagnostic_info diag[0];
} __attribute__ (( packed ));

/** RNDIS status codes */
enum rndis_status {
	/** Device is connected to a network medium */
	RNDIS_STATUS_MEDIA_CONNECT = 0x4001000bUL,
	/** Device is disconnected from the medium */
	RNDIS_STATUS_MEDIA_DISCONNECT = 0x4001000cUL,
	/** Unknown start-of-day status code */
	RNDIS_STATUS_WTF_WORLD = 0x40020006UL,
};

/** RNDIS keepalive message */
#define RNDIS_KEEPALIVE_MSG 0x00000008UL

/** RNDIS keepalive message */
struct rndis_keepalive_message {
	/** Request ID */
	uint32_t id;
} __attribute__ (( packed ));

/** RNDIS keepalive completion */
#define RNDIS_KEEPALIVE_CMPLT 0x80000008UL

/** RNDIS keepalive completion */
struct rndis_keepalive_completion {
	/** Request ID */
	uint32_t id;
	/** Status */
	uint32_t status;
} __attribute__ (( packed ));

/** RNDIS packet message */
#define RNDIS_PACKET_MSG 0x00000001UL

/** RNDIS packet field */
struct rndis_packet_field {
	/** Offset */
	uint32_t offset;
	/** Length */
	uint32_t len;
} __attribute__ (( packed ));

/** RNDIS packet message */
struct rndis_packet_message {
	/** Data */
	struct rndis_packet_field data;
	/** Out-of-band data records */
	struct rndis_packet_field oob;
	/** Number of out-of-band data records */
	uint32_t oob_count;
	/** Per-packet information record */
	struct rndis_packet_field ppi;
	/** Reserved */
	uint32_t reserved;
} __attribute__ (( packed ));

/** RNDIS packet record */
struct rndis_packet_record {
	/** Length */
	uint32_t len;
	/** Type */
	uint32_t type;
	/** Offset */
	uint32_t offset;
} __attribute__ (( packed ));

/** OID for packet filter */
#define RNDIS_OID_GEN_CURRENT_PACKET_FILTER 0x0001010eUL

/** Packet filter bits */
enum rndis_packet_filter {
	/** Unicast packets */
	RNDIS_FILTER_UNICAST = 0x00000001UL,
	/** Multicast packets */
	RNDIS_FILTER_MULTICAST = 0x00000002UL,
	/** All multicast packets */
	RNDIS_FILTER_ALL_MULTICAST = 0x00000004UL,
	/** Broadcast packets */
	RNDIS_FILTER_BROADCAST = 0x00000008UL,
	/** All packets */
	RNDIS_FILTER_PROMISCUOUS = 0x00000020UL
};

/** OID for media status */
#define RNDIS_OID_GEN_MEDIA_CONNECT_STATUS 0x00010114UL

/** OID for permanent MAC address */
#define RNDIS_OID_802_3_PERMANENT_ADDRESS 0x01010101UL

/** OID for current MAC address */
#define RNDIS_OID_802_3_CURRENT_ADDRESS	0x01010102UL

struct rndis_device;

/** RNDIS device operations */
struct rndis_operations {
	/**
	 * Open RNDIS device
	 *
	 * @v rndis		RNDIS device
	 * @ret rc		Return status code
	 */
	int ( * open ) ( struct rndis_device *rndis );
	/**
	 * Close RNDIS device
	 *
	 * @v rndis		RNDIS device
	 */
	void ( * close ) ( struct rndis_device *rndis );
	/**
	 * Transmit packet
	 *
	 * @v rndis		RNDIS device
	 * @v iobuf		I/O buffer
	 * @ret rc		Return status code
	 *
	 * If this method returns success then the RNDIS device must
	 * eventually report completion via rndis_tx_complete().
	 */
	int ( * transmit ) ( struct rndis_device *rndis,
			     struct io_buffer *iobuf );
	/**
	 * Poll for completed and received packets
	 *
	 * @v rndis		RNDIS device
	 */
	void ( * poll ) ( struct rndis_device *rndis );
};

/** An RNDIS device */
struct rndis_device {
	/** Network device */
	struct net_device *netdev;
	/** Device name */
	const char *name;
	/** RNDIS operations */
	struct rndis_operations *op;
	/** Driver private data */
	void *priv;

	/** Request ID for current blocking request */
	unsigned int wait_id;
	/** Return status code for current blocking request */
	int wait_rc;
};

/**
 * Initialise an RNDIS device
 *
 * @v rndis		RNDIS device
 * @v op		RNDIS device operations
 */
static inline void rndis_init ( struct rndis_device *rndis,
				struct rndis_operations *op ) {

	rndis->op = op;
}

extern void rndis_tx_complete_err ( struct rndis_device *rndis,
				    struct io_buffer *iobuf, int rc );
extern int rndis_tx_defer ( struct rndis_device *rndis,
			    struct io_buffer *iobuf );
extern void rndis_rx ( struct rndis_device *rndis, struct io_buffer *iobuf );
extern void rndis_rx_err ( struct rndis_device *rndis, struct io_buffer *iobuf,
			   int rc );

extern struct rndis_device * alloc_rndis ( size_t priv_len );
extern int register_rndis ( struct rndis_device *rndis );
extern void unregister_rndis ( struct rndis_device *rndis );
extern void free_rndis ( struct rndis_device *rndis );

/**
 * Complete message transmission
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 */
static inline void rndis_tx_complete ( struct rndis_device *rndis,
				       struct io_buffer *iobuf ) {

	rndis_tx_complete_err ( rndis, iobuf, 0 );
}

#endif /* _IPXE_RNDIS_H */
