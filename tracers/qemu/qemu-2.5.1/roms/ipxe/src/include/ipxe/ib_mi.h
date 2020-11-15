#ifndef _IPXE_IB_MI_H
#define _IPXE_IB_MI_H

/** @file
 *
 * Infiniband management interfaces
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/list.h>
#include <ipxe/retry.h>
#include <ipxe/tables.h>
#include <ipxe/infiniband.h>

struct ib_mad_interface;
struct ib_mad_transaction;

/** An Infiniband management agent */
struct ib_mad_agent {
	/** Management class */
	uint8_t mgmt_class;
	/** Class version */
	uint8_t class_version;
	/** Attribute (in network byte order) */
	uint16_t attr_id;
	/** Handle MAD
	 *
	 * @v ibdev		Infiniband device
	 * @v mi		Management interface
	 * @v mad		Received MAD
	 * @v av		Source address vector
	 * @ret rc		Return status code
	 */
	void ( * handle ) ( struct ib_device *ibdev,
			    struct ib_mad_interface *mi,
			    union ib_mad *mad,
			    struct ib_address_vector *av );
};

/** Infiniband management agents */
#define IB_MAD_AGENTS __table ( struct ib_mad_agent, "ib_mad_agents" )

/** Declare an Infiniband management agent */
#define __ib_mad_agent __table_entry ( IB_MAD_AGENTS, 01 )

/** Infiniband management transaction operations */
struct ib_mad_transaction_operations {
	/** Handle transaction completion
	 *
	 * @v ibdev		Infiniband device
	 * @v mi		Management interface
	 * @v madx		Management transaction
	 * @v rc		Status code
	 * @v mad		Received MAD (or NULL on error)
	 * @v av		Source address vector (or NULL on error)
	 *
	 * The completion handler should in most cases call
	 * ib_destroy_madx() to free up the completed transaction.
	 */
	void ( * complete ) ( struct ib_device *ibdev,
			      struct ib_mad_interface *mi,
			      struct ib_mad_transaction *madx,
			      int rc, union ib_mad *mad,
			      struct ib_address_vector *av );
};

/** An Infiniband management transaction */
struct ib_mad_transaction {
	/** Associated management interface */
	struct ib_mad_interface *mi;
	/** List of transactions */
	struct list_head list;
	/** Retry timer */
	struct retry_timer timer;
	/** Destination address vector */
	struct ib_address_vector av;
	/** MAD being sent */
	union ib_mad mad;
	/** Transaction operations */
	struct ib_mad_transaction_operations *op;
	/** Owner private data */
	void *owner_priv;
};

/** An Infiniband management interface */
struct ib_mad_interface {
	/** Infiniband device */
	struct ib_device *ibdev;
	/** Completion queue */
	struct ib_completion_queue *cq;
	/** Queue pair */
	struct ib_queue_pair *qp;
	/** List of management transactions */
	struct list_head madx;
};

/**
 * Set Infiniband management transaction owner-private data
 *
 * @v madx		Management transaction
 * @v priv		Private data
 */
static inline __always_inline void
ib_madx_set_ownerdata ( struct ib_mad_transaction *madx, void *priv ) {
	madx->owner_priv = priv;
}

/**
 * Get Infiniband management transaction owner-private data
 *
 * @v madx		Management transaction
 * @ret priv		Private data
 */
static inline __always_inline void *
ib_madx_get_ownerdata ( struct ib_mad_transaction *madx ) {
	return madx->owner_priv;
}

extern int ib_mi_send ( struct ib_device *ibdev, struct ib_mad_interface *mi,
			union ib_mad *mad, struct ib_address_vector *av );
extern struct ib_mad_transaction *
ib_create_madx ( struct ib_device *ibdev, struct ib_mad_interface *mi,
		 union ib_mad *mad, struct ib_address_vector *av,
		 struct ib_mad_transaction_operations *op );
extern void ib_destroy_madx ( struct ib_device *ibdev,
			      struct ib_mad_interface *mi,
			      struct ib_mad_transaction *madx );
extern struct ib_mad_interface * ib_create_mi ( struct ib_device *ibdev,
						enum ib_queue_pair_type type );
extern void ib_destroy_mi ( struct ib_device *ibdev,
			    struct ib_mad_interface *mi );

#endif /* _IPXE_IB_MI_H */
