#ifndef _IPXE_IB_MCAST_H
#define _IPXE_IB_MCAST_H

/** @file
 *
 * Infiniband multicast groups
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/infiniband.h>

struct ib_mad_transaction;

/** An Infiniband multicast group membership */
struct ib_mc_membership {
	/** Queue pair */
	struct ib_queue_pair *qp;
	/** Multicast GID */
	union ib_gid gid;
	/** Multicast group join transaction */
	struct ib_mad_transaction *madx;
	/** Handle join success/failure
	 *
	 * @v ibdev		Infiniband device
	 * @v qp		Queue pair
	 * @v membership	Multicast group membership
	 * @v rc		Status code
	 * @v mad		Response MAD (or NULL on error)
	 */
	void ( * complete ) ( struct ib_device *ibdev, struct ib_queue_pair *qp,
			      struct ib_mc_membership *membership, int rc,
			      union ib_mad *mad );
};

extern int ib_mcast_join ( struct ib_device *ibdev, struct ib_queue_pair *qp,
			   struct ib_mc_membership *membership,
			   union ib_gid *gid,
			   void ( * joined ) ( struct ib_device *ibdev,
					       struct ib_queue_pair *qp,
					       struct ib_mc_membership *memb,
					       int rc, union ib_mad *mad ) );

extern void ib_mcast_leave ( struct ib_device *ibdev, struct ib_queue_pair *qp,
			     struct ib_mc_membership *membership );

#endif /* _IPXE_IB_MCAST_H */
