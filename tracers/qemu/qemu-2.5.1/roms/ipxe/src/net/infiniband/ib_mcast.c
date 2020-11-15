/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/list.h>
#include <ipxe/infiniband.h>
#include <ipxe/ib_mi.h>
#include <ipxe/ib_mcast.h>

/** @file
 *
 * Infiniband multicast groups
 *
 */

/**
 * Generate multicast membership MAD
 *
 * @v ibdev		Infiniband device
 * @v gid		Multicast GID
 * @v join		Join (rather than leave) group
 * @v mad		MAD to fill in
 */
static void ib_mcast_mad ( struct ib_device *ibdev, union ib_gid *gid,
			   int join, union ib_mad *mad ) {
	struct ib_mad_sa *sa = &mad->sa;

	/* Construct multicast membership record request */
	memset ( sa, 0, sizeof ( *sa ) );
	sa->mad_hdr.mgmt_class = IB_MGMT_CLASS_SUBN_ADM;
	sa->mad_hdr.class_version = IB_SA_CLASS_VERSION;
	sa->mad_hdr.method =
		( join ? IB_MGMT_METHOD_SET : IB_MGMT_METHOD_DELETE );
	sa->mad_hdr.attr_id = htons ( IB_SA_ATTR_MC_MEMBER_REC );
	sa->sa_hdr.comp_mask[1] =
		htonl ( IB_SA_MCMEMBER_REC_MGID | IB_SA_MCMEMBER_REC_PORT_GID |
			IB_SA_MCMEMBER_REC_JOIN_STATE );
	sa->sa_data.mc_member_record.scope__join_state = 1;
	memcpy ( &sa->sa_data.mc_member_record.mgid, gid,
		 sizeof ( sa->sa_data.mc_member_record.mgid ) );
	memcpy ( &sa->sa_data.mc_member_record.port_gid, &ibdev->gid,
		 sizeof ( sa->sa_data.mc_member_record.port_gid ) );
}

/**
 * Handle multicast membership record join response
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v madx		Management transaction
 * @v rc		Status code
 * @v mad		Received MAD (or NULL on error)
 * @v av		Source address vector (or NULL on error)
 */
static void ib_mcast_complete ( struct ib_device *ibdev,
				struct ib_mad_interface *mi __unused,
				struct ib_mad_transaction *madx,
				int rc, union ib_mad *mad,
				struct ib_address_vector *av __unused ) {
	struct ib_mc_membership *membership = ib_madx_get_ownerdata ( madx );
	struct ib_queue_pair *qp = membership->qp;
	union ib_gid *gid = &membership->gid;
	struct ib_mc_member_record *mc_member_record =
		&mad->sa.sa_data.mc_member_record;
	int joined;
	unsigned long qkey;

	/* Report failures */
	if ( ( rc == 0 ) && ( mad->hdr.status != htons ( IB_MGMT_STATUS_OK ) ))
		rc = -ENOTCONN;
	if ( rc != 0 ) {
		DBGC ( ibdev, "IBDEV %p QPN %lx join failed: %s\n",
		       ibdev, qp->qpn, strerror ( rc ) );
		goto out;
	}

	/* Extract values from MAD */
	joined = ( mad->hdr.method == IB_MGMT_METHOD_GET_RESP );
	qkey = ntohl ( mc_member_record->qkey );
	DBGC ( ibdev, "IBDEV %p QPN %lx %s " IB_GID_FMT " qkey %lx\n",
	       ibdev, qp->qpn, ( joined ? "joined" : "left" ),
	       IB_GID_ARGS ( gid ), qkey );

	/* Set queue key */
	qp->qkey = qkey;
	if ( ( rc = ib_modify_qp ( ibdev, qp ) ) != 0 ) {
		DBGC ( ibdev, "IBDEV %p QPN %lx could not modify qkey: %s\n",
		       ibdev, qp->qpn, strerror ( rc ) );
		goto out;
	}

 out:
	/* Destroy the completed transaction */
	ib_destroy_madx ( ibdev, mi, madx );
	membership->madx = NULL;

	/* Hand off to upper completion handler */
	membership->complete ( ibdev, qp, membership, rc, mad );
}

/** Multicast membership management transaction completion operations */
static struct ib_mad_transaction_operations ib_mcast_op = {
	.complete = ib_mcast_complete,
};

/**
 * Join multicast group
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v membership	Multicast group membership
 * @v gid		Multicast GID to join
 * @v joined		Join completion handler
 * @ret rc		Return status code
 */
int ib_mcast_join ( struct ib_device *ibdev, struct ib_queue_pair *qp,
		    struct ib_mc_membership *membership, union ib_gid *gid,
		    void ( * complete ) ( struct ib_device *ibdev,
					  struct ib_queue_pair *qp,
					  struct ib_mc_membership *membership,
					  int rc, union ib_mad *mad ) ) {
	union ib_mad mad;
	int rc;

	DBGC ( ibdev, "IBDEV %p QPN %lx joining " IB_GID_FMT "\n",
	       ibdev, qp->qpn, IB_GID_ARGS ( gid ) );

	/* Sanity check */
	assert ( qp != NULL );

	/* Initialise structure */
	membership->qp = qp;
	memcpy ( &membership->gid, gid, sizeof ( membership->gid ) );
	membership->complete = complete;

	/* Attach queue pair to multicast GID */
	if ( ( rc = ib_mcast_attach ( ibdev, qp, gid ) ) != 0 ) {
		DBGC ( ibdev, "IBDEV %p QPN %lx could not attach: %s\n",
		       ibdev, qp->qpn, strerror ( rc ) );
		goto err_mcast_attach;
	}

	/* Initiate multicast membership join */
	ib_mcast_mad ( ibdev, gid, 1, &mad );
	membership->madx = ib_create_madx ( ibdev, ibdev->gsi, &mad, NULL,
					    &ib_mcast_op );
	if ( ! membership->madx ) {
		DBGC ( ibdev, "IBDEV %p QPN %lx could not create join "
		       "transaction\n", ibdev, qp->qpn );
		rc = -ENOMEM;
		goto err_create_madx;
	}
	ib_madx_set_ownerdata ( membership->madx, membership );

	return 0;

	ib_destroy_madx ( ibdev, ibdev->gsi, membership->madx );
 err_create_madx:
	ib_mcast_detach ( ibdev, qp, gid );
 err_mcast_attach:
	return rc;
}

/**
 * Leave multicast group
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v membership	Multicast group membership
 */
void ib_mcast_leave ( struct ib_device *ibdev, struct ib_queue_pair *qp,
		      struct ib_mc_membership *membership ) {
	union ib_gid *gid = &membership->gid;
	union ib_mad mad;
	int rc;

	DBGC ( ibdev, "IBDEV %p QPN %lx leaving " IB_GID_FMT "\n",
	       ibdev, qp->qpn, IB_GID_ARGS ( gid ) );

	/* Sanity check */
	assert ( qp != NULL );

	/* Detach from multicast GID */
	ib_mcast_detach ( ibdev, qp, &membership->gid );

	/* Cancel multicast membership join, if applicable */
	if ( membership->madx ) {
		ib_destroy_madx ( ibdev, ibdev->gsi, membership->madx );
		membership->madx = NULL;
	}

	/* Send a single group leave MAD */
	ib_mcast_mad ( ibdev, &membership->gid, 0, &mad );
	if ( ( rc = ib_mi_send ( ibdev, ibdev->gsi, &mad, NULL ) ) != 0 ) {
		DBGC ( ibdev, "IBDEV %p QPN %lx could not send leave request: "
		       "%s\n", ibdev, qp->qpn, strerror ( rc ) );
	}
}
