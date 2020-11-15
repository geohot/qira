#ifndef _IPXE_INFINIBAND_H
#define _IPXE_INFINIBAND_H

/** @file
 *
 * Infiniband protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/refcnt.h>
#include <ipxe/device.h>
#include <ipxe/tables.h>
#include <ipxe/ib_packet.h>
#include <ipxe/ib_mad.h>

/** Subnet management interface QPN */
#define IB_QPN_SMI 0

/** Subnet management interface queue key */
#define IB_QKEY_SMI 0

/** General service interface QPN */
#define IB_QPN_GSI 1

/** General service interface queue key */
#define IB_QKEY_GSI 0x80010000UL

/** Broadcast QPN */
#define IB_QPN_BROADCAST 0xffffffUL

/** QPN mask */
#define IB_QPN_MASK 0xffffffUL

/** Default Infiniband partition key */
#define IB_PKEY_DEFAULT 0xffff

/** Infiniband partition key full membership flag */
#define IB_PKEY_FULL 0x8000

/**
 * Maximum payload size
 *
 * This is currently hard-coded in various places (drivers, subnet
 * management agent, etc.) to 2048.
 */
#define IB_MAX_PAYLOAD_SIZE 2048

struct ib_device;
struct ib_queue_pair;
struct ib_address_vector;
struct ib_completion_queue;
struct ib_mad_interface;

/** Infiniband transmission rates */
enum ib_rate {
	IB_RATE_2_5 = 2,
	IB_RATE_10 = 3,
	IB_RATE_30 = 4,
	IB_RATE_5 = 5,
	IB_RATE_20 = 6,
	IB_RATE_40 = 7,
	IB_RATE_60 = 8,
	IB_RATE_80 = 9,
	IB_RATE_120 = 10,
};

/** An Infiniband Address Vector */
struct ib_address_vector {
	/** Queue Pair Number */
	unsigned long qpn;
	/** Queue key
	 *
	 * Not specified for received packets.
	 */
	unsigned long qkey;
	/** Local ID */
	unsigned int lid;
	/** Rate
	 *
	 * Not specified for received packets.
	 */
	enum ib_rate rate;
	/** Service level */
	unsigned int sl;
	/** GID is present */
	unsigned int gid_present;
	/** GID, if present */
	union ib_gid gid;
	/** VLAN is present */
	unsigned int vlan_present;
	/** VLAN, if present */
	unsigned int vlan;
};

/** An Infiniband Work Queue */
struct ib_work_queue {
	/** Containing queue pair */
	struct ib_queue_pair *qp;
	/** "Is a send queue" flag */
	int is_send;
	/** Associated completion queue */
	struct ib_completion_queue *cq;
	/** List of work queues on this completion queue */
	struct list_head list;
	/** Packet sequence number */
	uint32_t psn;
	/** Number of work queue entries */
	unsigned int num_wqes;
	/** Number of occupied work queue entries */
	unsigned int fill;
	/** Next work queue entry index
	 *
	 * This is the index of the next entry to be filled (i.e. the
	 * first empty entry).  This value is not bounded by num_wqes;
	 * users must logical-AND with (num_wqes-1) to generate an
	 * array index.
	 */
	unsigned long next_idx;
	/** I/O buffers assigned to work queue */
	struct io_buffer **iobufs;
	/** Driver private data */
	void *drv_priv;
};

/** An Infiniband multicast GID */
struct ib_multicast_gid {
	/** List of multicast GIDs on this QP */
	struct list_head list;
	/** Multicast GID */
	union ib_gid gid;
};

/** An Infiniband queue pair type */
enum ib_queue_pair_type {
	IB_QPT_SMI,
	IB_QPT_GSI,
	IB_QPT_UD,
	IB_QPT_RC,
	IB_QPT_ETH,
};

/** Infiniband queue pair operations */
struct ib_queue_pair_operations {
	/** Allocate receive I/O buffer
	 *
	 * @v len		Maximum receive length
	 * @ret iobuf		I/O buffer (or NULL if out of memory)
	 */
	struct io_buffer * ( * alloc_iob ) ( size_t len );
};

/** An Infiniband Queue Pair */
struct ib_queue_pair {
	/** Containing Infiniband device */
	struct ib_device *ibdev;
	/** List of queue pairs on this Infiniband device */
	struct list_head list;
	/** Queue pair number */
	unsigned long qpn;
	/** Externally-visible queue pair number
	 *
	 * This may differ from the real queue pair number (e.g. when
	 * the HCA cannot use the management QPNs 0 and 1 as hardware
	 * QPNs and needs to remap them).
	 */
	unsigned long ext_qpn;
	/** Queue pair type */
	enum ib_queue_pair_type type;
	/** Queue key */
	unsigned long qkey;
	/** Send queue */
	struct ib_work_queue send;
	/** Receive queue */
	struct ib_work_queue recv;
	/** List of multicast GIDs */
	struct list_head mgids;
	/** Address vector */
	struct ib_address_vector av;
	/** Queue pair operations */
	struct ib_queue_pair_operations *op;
	/** Driver private data */
	void *drv_priv;
	/** Queue owner private data */
	void *owner_priv;
};

/** Infiniband completion queue operations */
struct ib_completion_queue_operations {
	/**
	 * Complete Send WQE
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @v iobuf		I/O buffer
	 * @v rc		Completion status code
	 */
	void ( * complete_send ) ( struct ib_device *ibdev,
				   struct ib_queue_pair *qp,
				   struct io_buffer *iobuf, int rc );
	/**
	 * Complete Receive WQE
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @v dest		Destination address vector, or NULL
	 * @v source		Source address vector, or NULL
	 * @v iobuf		I/O buffer
	 * @v rc		Completion status code
	 */
	void ( * complete_recv ) ( struct ib_device *ibdev,
				   struct ib_queue_pair *qp,
				   struct ib_address_vector *dest,
				   struct ib_address_vector *source,
				   struct io_buffer *iobuf, int rc );
};

/** An Infiniband Completion Queue */
struct ib_completion_queue {
	/** Containing Infiniband device */
	struct ib_device *ibdev;
	/** List of completion queues on this Infiniband device */
	struct list_head list;
	/** Completion queue number */
	unsigned long cqn;
	/** Number of completion queue entries */
	unsigned int num_cqes;
	/** Next completion queue entry index
	 *
	 * This is the index of the next entry to be filled (i.e. the
	 * first empty entry).  This value is not bounded by num_wqes;
	 * users must logical-AND with (num_wqes-1) to generate an
	 * array index.
	 */
	unsigned long next_idx;
	/** List of work queues completing to this queue */
	struct list_head work_queues;
	/** Completion queue operations */
	struct ib_completion_queue_operations *op;
	/** Driver private data */
	void *drv_priv;
};

/**
 * Infiniband device operations
 *
 * These represent a subset of the Infiniband Verbs.
 */
struct ib_device_operations {
	/** Create completion queue
	 *
	 * @v ibdev		Infiniband device
	 * @v cq		Completion queue
	 * @ret rc		Return status code
	 */
	int ( * create_cq ) ( struct ib_device *ibdev,
			      struct ib_completion_queue *cq );
	/** Destroy completion queue
	 *
	 * @v ibdev		Infiniband device
	 * @v cq		Completion queue
	 */
	void ( * destroy_cq ) ( struct ib_device *ibdev,
				struct ib_completion_queue *cq );
	/** Create queue pair
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @ret rc		Return status code
	 */
	int ( * create_qp ) ( struct ib_device *ibdev,
			      struct ib_queue_pair *qp );
	/** Modify queue pair
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @ret rc		Return status code
	 */
	int ( * modify_qp ) ( struct ib_device *ibdev,
			      struct ib_queue_pair *qp );
	/** Destroy queue pair
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 */
	void ( * destroy_qp ) ( struct ib_device *ibdev,
				struct ib_queue_pair *qp );
	/** Post send work queue entry
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @v dest		Destination address vector
	 * @v iobuf		I/O buffer
	 * @ret rc		Return status code
	 *
	 * If this method returns success, the I/O buffer remains
	 * owned by the queue pair.  If this method returns failure,
	 * the I/O buffer is immediately released; the failure is
	 * interpreted as "failure to enqueue buffer".
	 */
	int ( * post_send ) ( struct ib_device *ibdev,
			      struct ib_queue_pair *qp,
			      struct ib_address_vector *dest,
			      struct io_buffer *iobuf );
	/** Post receive work queue entry
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @v iobuf		I/O buffer
	 * @ret rc		Return status code
	 *
	 * If this method returns success, the I/O buffer remains
	 * owned by the queue pair.  If this method returns failure,
	 * the I/O buffer is immediately released; the failure is
	 * interpreted as "failure to enqueue buffer".
	 */
	int ( * post_recv ) ( struct ib_device *ibdev,
			      struct ib_queue_pair *qp,
			      struct io_buffer *iobuf );
	/** Poll completion queue
	 *
	 * @v ibdev		Infiniband device
	 * @v cq		Completion queue
	 *
	 * The relevant completion handler (specified at completion
	 * queue creation time) takes ownership of the I/O buffer.
	 */
	void ( * poll_cq ) ( struct ib_device *ibdev,
			     struct ib_completion_queue *cq );
	/**
	 * Poll event queue
	 *
	 * @v ibdev		Infiniband device
	 */
	void ( * poll_eq ) ( struct ib_device *ibdev );
	/**
	 * Open port
	 *
	 * @v ibdev		Infiniband device
	 * @ret rc		Return status code
	 */
	int ( * open ) ( struct ib_device *ibdev );
	/**
	 * Close port
	 *
	 * @v ibdev		Infiniband device
	 */
	void ( * close ) ( struct ib_device *ibdev );
	/** Attach to multicast group
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @v gid		Multicast GID
	 * @ret rc		Return status code
	 */
	int ( * mcast_attach ) ( struct ib_device *ibdev,
				 struct ib_queue_pair *qp,
				 union ib_gid *gid );
	/** Detach from multicast group
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @v gid		Multicast GID
	 */
	void ( * mcast_detach ) ( struct ib_device *ibdev,
				  struct ib_queue_pair *qp,
				  union ib_gid *gid );
	/** Set port information
	 *
	 * @v ibdev		Infiniband device
	 * @v mad		Set port information MAD
	 *
	 * This method is required only by adapters that do not have
	 * an embedded SMA.
	 */
	int ( * set_port_info ) ( struct ib_device *ibdev, union ib_mad *mad );
	/** Set partition key table
	 *
	 * @v ibdev		Infiniband device
	 * @v mad		Set partition key table MAD
	 *
	 * This method is required only by adapters that do not have
	 * an embedded SMA.
	 */
	int ( * set_pkey_table ) ( struct ib_device *ibdev,
				   union ib_mad *mad );
};

/** An Infiniband device */
struct ib_device {
	/** Reference counter */
	struct refcnt refcnt;
	/** List of Infiniband devices */
	struct list_head list;
	/** List of open Infiniband devices */
	struct list_head open_list;
	/** Underlying device */
	struct device *dev;
	/** List of completion queues */
	struct list_head cqs;
	/** List of queue pairs */
	struct list_head qps;
	/** Infiniband operations */
	struct ib_device_operations *op;
	/** Port number */
	unsigned int port;
	/** Port open request counter */
	unsigned int open_count;

	/** Port state */
	uint8_t port_state;
	/** Link width supported */
	uint8_t link_width_supported;
	/** Link width enabled */
	uint8_t link_width_enabled;
	/** Link width active */
	uint8_t link_width_active;
	/** Link speed supported */
	uint8_t link_speed_supported;
	/** Link speed enabled */
	uint8_t link_speed_enabled;
	/** Link speed active */
	uint8_t link_speed_active;
	/** Node GUID */
	union ib_guid node_guid;
	/** Port GID (comprising GID prefix and port GUID) */
	union ib_gid gid;
	/** Port LID */
	uint16_t lid;
	/** Subnet manager LID */
	uint16_t sm_lid;
	/** Subnet manager SL */
	uint8_t sm_sl;
	/** Partition key */
	uint16_t pkey;

	/** RDMA key
	 *
	 * This is a single key allowing unrestricted access to
	 * memory.
	 */
	uint32_t rdma_key;

	/** Subnet management interface */
	struct ib_mad_interface *smi;
	/** General services interface */
	struct ib_mad_interface *gsi;

	/** Driver private data */
	void *drv_priv;
	/** Owner private data */
	void *owner_priv;
};

/** An Infiniband upper-layer driver */
struct ib_driver {
	/** Name */
	const char *name;
	/** Probe device
	 *
	 * @v ibdev		Infiniband device
	 * @ret rc		Return status code
	 */
	int ( * probe ) ( struct ib_device *ibdev );
	/** Notify of device or link state change
	 *
	 * @v ibdev		Infiniband device
	 */
	void ( * notify ) ( struct ib_device *ibdev );
	/** Remove device
	 *
	 * @v ibdev		Infiniband device
	 */
	void ( * remove ) ( struct ib_device *ibdev );
};

/** Infiniband driver table */
#define IB_DRIVERS __table ( struct ib_driver, "ib_drivers" )

/** Declare an Infiniband driver */
#define __ib_driver __table_entry ( IB_DRIVERS, 01 )

extern struct ib_completion_queue *
ib_create_cq ( struct ib_device *ibdev, unsigned int num_cqes,
	       struct ib_completion_queue_operations *op );
extern void ib_destroy_cq ( struct ib_device *ibdev,
			    struct ib_completion_queue *cq );
extern void ib_poll_cq ( struct ib_device *ibdev,
			 struct ib_completion_queue *cq );
extern struct ib_queue_pair *
ib_create_qp ( struct ib_device *ibdev, enum ib_queue_pair_type type,
	       unsigned int num_send_wqes, struct ib_completion_queue *send_cq,
	       unsigned int num_recv_wqes, struct ib_completion_queue *recv_cq,
	       struct ib_queue_pair_operations *op );
extern int ib_modify_qp ( struct ib_device *ibdev, struct ib_queue_pair *qp );
extern void ib_destroy_qp ( struct ib_device *ibdev,
			    struct ib_queue_pair *qp );
extern struct ib_queue_pair * ib_find_qp_qpn ( struct ib_device *ibdev,
					       unsigned long qpn );
extern struct ib_queue_pair * ib_find_qp_mgid ( struct ib_device *ibdev,
						union ib_gid *gid );
extern struct ib_work_queue * ib_find_wq ( struct ib_completion_queue *cq,
					   unsigned long qpn, int is_send );
extern int ib_post_send ( struct ib_device *ibdev, struct ib_queue_pair *qp,
			  struct ib_address_vector *dest,
			  struct io_buffer *iobuf );
extern int ib_post_recv ( struct ib_device *ibdev, struct ib_queue_pair *qp,
			  struct io_buffer *iobuf );
extern void ib_complete_send ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp,
			       struct io_buffer *iobuf, int rc );
extern void ib_complete_recv ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp,
			       struct ib_address_vector *dest,
			       struct ib_address_vector *source,
			       struct io_buffer *iobuf, int rc );
extern void ib_refill_recv ( struct ib_device *ibdev,
			     struct ib_queue_pair *qp );
extern int ib_open ( struct ib_device *ibdev );
extern void ib_close ( struct ib_device *ibdev );
extern int ib_link_rc ( struct ib_device *ibdev );
extern int ib_mcast_attach ( struct ib_device *ibdev, struct ib_queue_pair *qp,
			     union ib_gid *gid );
extern void ib_mcast_detach ( struct ib_device *ibdev,
			      struct ib_queue_pair *qp, union ib_gid *gid );
extern int ib_count_ports ( struct ib_device *ibdev );
extern int ib_set_port_info ( struct ib_device *ibdev, union ib_mad *mad );
extern int ib_set_pkey_table ( struct ib_device *ibdev, union ib_mad *mad );
extern struct ib_device * alloc_ibdev ( size_t priv_size );
extern int register_ibdev ( struct ib_device *ibdev );
extern void unregister_ibdev ( struct ib_device *ibdev );
extern struct ib_device * find_ibdev ( union ib_gid *gid );
extern struct ib_device * last_opened_ibdev ( void );
extern void ib_link_state_changed ( struct ib_device *ibdev );
extern void ib_poll_eq ( struct ib_device *ibdev );
extern struct list_head ib_devices;

/** Iterate over all network devices */
#define for_each_ibdev( ibdev ) \
	list_for_each_entry ( (ibdev), &ib_devices, list )

/**
 * Check link state of Infiniband device
 *
 * @v ibdev		Infiniband device
 * @ret link_up		Link is up
 */
static inline __always_inline int
ib_link_ok ( struct ib_device *ibdev ) {
	return ( ibdev->port_state == IB_PORT_STATE_ACTIVE );
}

/**
 * Check whether or not Infiniband device is open
 *
 * @v ibdev		Infiniband device
 * @v is_open		Infiniband device is open
 */
static inline __attribute__ (( always_inline )) int
ib_is_open ( struct ib_device *ibdev ) {
	return ( ibdev->open_count > 0 );
}

/**
 * Get reference to Infiniband device
 *
 * @v ibdev		Infiniband device
 * @ret ibdev		Infiniband device
 */
static inline __always_inline struct ib_device *
ibdev_get ( struct ib_device *ibdev ) {
	ref_get ( &ibdev->refcnt );
	return ibdev;
}

/**
 * Drop reference to Infiniband device
 *
 * @v ibdev		Infiniband device
 */
static inline __always_inline void
ibdev_put ( struct ib_device *ibdev ) {
	ref_put ( &ibdev->refcnt );
}

/**
 * Set Infiniband work queue driver-private data
 *
 * @v wq		Work queue
 * @v priv		Private data
 */
static inline __always_inline void
ib_wq_set_drvdata ( struct ib_work_queue *wq, void *priv ) {
	wq->drv_priv = priv;
}

/**
 * Get Infiniband work queue driver-private data
 *
 * @v wq		Work queue
 * @ret priv		Private data
 */
static inline __always_inline void *
ib_wq_get_drvdata ( struct ib_work_queue *wq ) {
	return wq->drv_priv;
}

/**
 * Set Infiniband queue pair driver-private data
 *
 * @v qp		Queue pair
 * @v priv		Private data
 */
static inline __always_inline void
ib_qp_set_drvdata ( struct ib_queue_pair *qp, void *priv ) {
	qp->drv_priv = priv;
}

/**
 * Get Infiniband queue pair driver-private data
 *
 * @v qp		Queue pair
 * @ret priv		Private data
 */
static inline __always_inline void *
ib_qp_get_drvdata ( struct ib_queue_pair *qp ) {
	return qp->drv_priv;
}

/**
 * Set Infiniband queue pair owner-private data
 *
 * @v qp		Queue pair
 * @v priv		Private data
 */
static inline __always_inline void
ib_qp_set_ownerdata ( struct ib_queue_pair *qp, void *priv ) {
	qp->owner_priv = priv;
}

/**
 * Get Infiniband queue pair owner-private data
 *
 * @v qp		Queue pair
 * @ret priv		Private data
 */
static inline __always_inline void *
ib_qp_get_ownerdata ( struct ib_queue_pair *qp ) {
	return qp->owner_priv;
}

/**
 * Set Infiniband completion queue driver-private data
 *
 * @v cq		Completion queue
 * @v priv		Private data
 */
static inline __always_inline void
ib_cq_set_drvdata ( struct ib_completion_queue *cq, void *priv ) {
	cq->drv_priv = priv;
}

/**
 * Get Infiniband completion queue driver-private data
 *
 * @v cq		Completion queue
 * @ret priv		Private data
 */
static inline __always_inline void *
ib_cq_get_drvdata ( struct ib_completion_queue *cq ) {
	return cq->drv_priv;
}

/**
 * Set Infiniband device driver-private data
 *
 * @v ibdev		Infiniband device
 * @v priv		Private data
 */
static inline __always_inline void
ib_set_drvdata ( struct ib_device *ibdev, void *priv ) {
	ibdev->drv_priv = priv;
}

/**
 * Get Infiniband device driver-private data
 *
 * @v ibdev		Infiniband device
 * @ret priv		Private data
 */
static inline __always_inline void *
ib_get_drvdata ( struct ib_device *ibdev ) {
	return ibdev->drv_priv;
}

/**
 * Set Infiniband device owner-private data
 *
 * @v ibdev		Infiniband device
 * @v priv		Private data
 */
static inline __always_inline void
ib_set_ownerdata ( struct ib_device *ibdev, void *priv ) {
	ibdev->owner_priv = priv;
}

/**
 * Get Infiniband device owner-private data
 *
 * @v ibdev		Infiniband device
 * @ret priv		Private data
 */
static inline __always_inline void *
ib_get_ownerdata ( struct ib_device *ibdev ) {
	return ibdev->owner_priv;
}

#endif /* _IPXE_INFINIBAND_H */
