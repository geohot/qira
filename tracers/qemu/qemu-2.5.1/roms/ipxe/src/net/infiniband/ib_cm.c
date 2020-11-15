/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/infiniband.h>
#include <ipxe/ib_mi.h>
#include <ipxe/ib_pathrec.h>
#include <ipxe/ib_cm.h>

/**
 * @file
 *
 * Infiniband communication management
 *
 */

/** List of connections */
static LIST_HEAD ( ib_cm_conns );

/**
 * Find connection by local communication ID
 *
 * @v local_id		Local communication ID
 * @ret conn		Connection, or NULL
 */
static struct ib_connection * ib_cm_find ( uint32_t local_id ) {
	struct ib_connection *conn;

	list_for_each_entry ( conn, &ib_cm_conns, list ) {
		if ( conn->local_id == local_id )
			return conn;
	}
	return NULL;
}

/**
 * Send "ready to use" response
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v av		Address vector
 * @v local_id		Local communication ID
 * @v remote_id		Remote communication ID
 * @ret rc		Return status code
 */
static int ib_cm_send_rtu ( struct ib_device *ibdev,
			    struct ib_mad_interface *mi,
			    struct ib_address_vector *av,
			    uint32_t local_id, uint32_t remote_id ) {
	union ib_mad mad;
	struct ib_cm_ready_to_use *rtu = &mad.cm.cm_data.ready_to_use;
	int rc;

	/* Construct "ready to use" response */
	memset ( &mad, 0, sizeof ( mad ) );
	mad.hdr.mgmt_class = IB_MGMT_CLASS_CM;
	mad.hdr.class_version = IB_CM_CLASS_VERSION;
	mad.hdr.method = IB_MGMT_METHOD_SEND;
	mad.hdr.attr_id = htons ( IB_CM_ATTR_READY_TO_USE );
	rtu->local_id = htonl ( local_id );
	rtu->remote_id = htonl ( remote_id );
	if ( ( rc = ib_mi_send ( ibdev, mi, &mad, av ) ) != 0 ){
		DBG ( "CM could not send RTU: %s\n", strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle duplicate connection replies
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @v av		Source address vector
 * @ret rc		Return status code
 *
 * If a "ready to use" MAD is lost, the peer may resend the connection
 * reply.  We have to respond to these with duplicate "ready to use"
 * MADs, otherwise the peer may time out and drop the connection.
 */
static void ib_cm_recv_rep ( struct ib_device *ibdev,
			     struct ib_mad_interface *mi,
			     union ib_mad *mad,
			     struct ib_address_vector *av ) {
	struct ib_cm_connect_reply *rep = &mad->cm.cm_data.connect_reply;
	struct ib_connection *conn;
	uint32_t local_id = ntohl ( rep->remote_id );
	int rc;

	/* Identify connection */
	conn = ib_cm_find ( local_id );
	if ( conn ) {
		/* Try to send "ready to use" reply */
		if ( ( rc = ib_cm_send_rtu ( ibdev, mi, av, conn->local_id,
					     conn->remote_id ) ) != 0 ) {
			/* Ignore errors; the remote end will retry */
		}
	} else {
		DBG ( "CM unidentified connection %08x\n", local_id );
	}
}

/**
 * Send reply to disconnection request
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v av		Address vector
 * @v local_id		Local communication ID
 * @v remote_id		Remote communication ID
 * @ret rc		Return status code
 */
static int ib_cm_send_drep ( struct ib_device *ibdev,
			     struct ib_mad_interface *mi,
			     struct ib_address_vector *av,
			     uint32_t local_id, uint32_t remote_id ) {
	union ib_mad mad;
	struct ib_cm_disconnect_reply *drep = &mad.cm.cm_data.disconnect_reply;
	int rc;

	/* Construct reply to disconnection request */
	memset ( &mad, 0, sizeof ( mad ) );
	mad.hdr.mgmt_class = IB_MGMT_CLASS_CM;
	mad.hdr.class_version = IB_CM_CLASS_VERSION;
	mad.hdr.method = IB_MGMT_METHOD_SEND;
	mad.hdr.attr_id = htons ( IB_CM_ATTR_DISCONNECT_REPLY );
	drep->local_id = htonl ( local_id );
	drep->remote_id = htonl ( remote_id );
	if ( ( rc = ib_mi_send ( ibdev, mi, &mad, av ) ) != 0 ){
		DBG ( "CM could not send DREP: %s\n", strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle disconnection requests
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @v av		Source address vector
 * @ret rc		Return status code
 */
static void ib_cm_recv_dreq ( struct ib_device *ibdev,
			      struct ib_mad_interface *mi,
			      union ib_mad *mad,
			      struct ib_address_vector *av ) {
	struct ib_cm_disconnect_request *dreq =
		&mad->cm.cm_data.disconnect_request;
	struct ib_connection *conn;
	uint32_t local_id = ntohl ( dreq->remote_id );
	uint32_t remote_id = ntohl ( dreq->local_id );
	int rc;

	/* Identify connection */
	conn = ib_cm_find ( local_id );
	if ( conn ) {
		/* Notify upper layer */
		conn->op->changed ( ibdev, conn->qp, conn, -ENOTCONN,
				    &dreq->private_data,
				    sizeof ( dreq->private_data ) );
	} else {
		DBG ( "CM unidentified connection %08x\n", local_id );
	}

	/* Send reply */
	if ( ( rc = ib_cm_send_drep ( ibdev, mi, av, local_id,
				      remote_id ) ) != 0 ) {
		/* Ignore errors; the remote end will retry */
	}
};

/** Communication management agents */
struct ib_mad_agent ib_cm_agent[] __ib_mad_agent = {
	{
		.mgmt_class = IB_MGMT_CLASS_CM,
		.class_version = IB_CM_CLASS_VERSION,
		.attr_id = htons ( IB_CM_ATTR_CONNECT_REPLY ),
		.handle = ib_cm_recv_rep,
	},
	{
		.mgmt_class = IB_MGMT_CLASS_CM,
		.class_version = IB_CM_CLASS_VERSION,
		.attr_id = htons ( IB_CM_ATTR_DISCONNECT_REQUEST ),
		.handle = ib_cm_recv_dreq,
	},
};

/**
 * Convert connection rejection reason to return status code
 *
 * @v reason		Rejection reason (in network byte order)
 * @ret rc		Return status code
 */
static int ib_cm_rejection_reason_to_rc ( uint16_t reason ) {
	switch ( reason ) {
	case htons ( IB_CM_REJECT_BAD_SERVICE_ID ) :
		return -ENODEV;
	case htons ( IB_CM_REJECT_STALE_CONN ) :
		return -EALREADY;
	case htons ( IB_CM_REJECT_CONSUMER ) :
		return -ENOTTY;
	default:
		return -EPERM;
	}
}

/**
 * Handle connection request transaction completion
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v madx		Management transaction
 * @v rc		Status code
 * @v mad		Received MAD (or NULL on error)
 * @v av		Source address vector (or NULL on error)
 */
static void ib_cm_req_complete ( struct ib_device *ibdev,
				 struct ib_mad_interface *mi,
				 struct ib_mad_transaction *madx,
				 int rc, union ib_mad *mad,
				 struct ib_address_vector *av ) {
	struct ib_connection *conn = ib_madx_get_ownerdata ( madx );
	struct ib_queue_pair *qp = conn->qp;
	struct ib_cm_common *common = &mad->cm.cm_data.common;
	struct ib_cm_connect_reply *rep = &mad->cm.cm_data.connect_reply;
	struct ib_cm_connect_reject *rej = &mad->cm.cm_data.connect_reject;
	void *private_data = NULL;
	size_t private_data_len = 0;

	/* Report failures */
	if ( ( rc == 0 ) && ( mad->hdr.status != htons ( IB_MGMT_STATUS_OK ) ))
		rc = -EIO;
	if ( rc != 0 ) {
		DBGC ( conn, "CM %p connection request failed: %s\n",
		       conn, strerror ( rc ) );
		goto out;
	}

	/* Record remote communication ID */
	conn->remote_id = ntohl ( common->local_id );

	/* Handle response */
	switch ( mad->hdr.attr_id ) {

	case htons ( IB_CM_ATTR_CONNECT_REPLY ) :
		/* Extract fields */
		qp->av.qpn = ( ntohl ( rep->local_qpn ) >> 8 );
		qp->send.psn = ( ntohl ( rep->starting_psn ) >> 8 );
		private_data = &rep->private_data;
		private_data_len = sizeof ( rep->private_data );
		DBGC ( conn, "CM %p connected to QPN %lx PSN %x\n",
		       conn, qp->av.qpn, qp->send.psn );

		/* Modify queue pair */
		if ( ( rc = ib_modify_qp ( ibdev, qp ) ) != 0 ) {
			DBGC ( conn, "CM %p could not modify queue pair: %s\n",
			       conn, strerror ( rc ) );
			goto out;
		}

		/* Send "ready to use" reply */
		if ( ( rc = ib_cm_send_rtu ( ibdev, mi, av, conn->local_id,
					     conn->remote_id ) ) != 0 ) {
			/* Treat as non-fatal */
			rc = 0;
		}
		break;

	case htons ( IB_CM_ATTR_CONNECT_REJECT ) :
		/* Extract fields */
		DBGC ( conn, "CM %p connection rejected (reason %d)\n",
		       conn, ntohs ( rej->reason ) );
		/* Private data is valid only for a Consumer Reject */
		if ( rej->reason == htons ( IB_CM_REJECT_CONSUMER ) ) {
			private_data = &rej->private_data;
			private_data_len = sizeof ( rej->private_data );
		}
		rc = ib_cm_rejection_reason_to_rc ( rej->reason );
		break;

	default:
		DBGC ( conn, "CM %p unexpected response (attribute %04x)\n",
		       conn, ntohs ( mad->hdr.attr_id ) );
		rc = -ENOTSUP;
		break;
	}

 out:
	/* Destroy the completed transaction */
	ib_destroy_madx ( ibdev, ibdev->gsi, madx );
	conn->madx = NULL;

	/* Hand off to the upper completion handler */
	conn->op->changed ( ibdev, qp, conn, rc, private_data,
			    private_data_len );
}

/** Connection request operations */
static struct ib_mad_transaction_operations ib_cm_req_op = {
	.complete = ib_cm_req_complete,
};

/**
 * Handle connection path transaction completion
 *
 * @v ibdev		Infiniband device
 * @v path		Path
 * @v rc		Status code
 * @v av		Address vector, or NULL on error
 */
static void ib_cm_path_complete ( struct ib_device *ibdev,
				  struct ib_path *path, int rc,
				  struct ib_address_vector *av ) {
	struct ib_connection *conn = ib_path_get_ownerdata ( path );
	struct ib_queue_pair *qp = conn->qp;
	union ib_mad mad;
	struct ib_cm_connect_request *req = &mad.cm.cm_data.connect_request;
	size_t private_data_len;

	/* Report failures */
	if ( rc != 0 ) {
		DBGC ( conn, "CM %p path lookup failed: %s\n",
		       conn, strerror ( rc ) );
		conn->op->changed ( ibdev, qp, conn, rc, NULL, 0 );
		goto out;
	}

	/* Update queue pair peer path */
	memcpy ( &qp->av, av, sizeof ( qp->av ) );

	/* Construct connection request */
	memset ( &mad, 0, sizeof ( mad ) );
	mad.hdr.mgmt_class = IB_MGMT_CLASS_CM;
	mad.hdr.class_version = IB_CM_CLASS_VERSION;
	mad.hdr.method = IB_MGMT_METHOD_SEND;
	mad.hdr.attr_id = htons ( IB_CM_ATTR_CONNECT_REQUEST );
	req->local_id = htonl ( conn->local_id );
	memcpy ( &req->service_id, &conn->service_id,
		 sizeof ( req->service_id ) );
	memcpy ( &req->local_ca, &ibdev->node_guid, sizeof ( req->local_ca ) );
	req->local_qpn__responder_resources = htonl ( ( qp->qpn << 8 ) | 1 );
	req->local_eecn__initiator_depth = htonl ( ( 0 << 8 ) | 1 );
	req->remote_eecn__remote_timeout__service_type__ee_flow_ctrl =
		htonl ( ( 0x14 << 3 ) | ( IB_CM_TRANSPORT_RC << 1 ) |
			( 0 << 0 ) );
	req->starting_psn__local_timeout__retry_count =
		htonl ( ( qp->recv.psn << 8 ) | ( 0x14 << 3 ) |
			( 0x07 << 0 ) );
	req->pkey = htons ( ibdev->pkey );
	req->payload_mtu__rdc_exists__rnr_retry =
		( ( IB_MTU_2048 << 4 ) | ( 1 << 3 ) | ( 0x07 << 0 ) );
	req->max_cm_retries__srq = ( ( 0x0f << 4 ) | ( 0 << 3 ) );
	req->primary.local_lid = htons ( ibdev->lid );
	req->primary.remote_lid = htons ( conn->qp->av.lid );
	memcpy ( &req->primary.local_gid, &ibdev->gid,
		 sizeof ( req->primary.local_gid ) );
	memcpy ( &req->primary.remote_gid, &conn->qp->av.gid,
		 sizeof ( req->primary.remote_gid ) );
	req->primary.flow_label__rate =
		htonl ( ( 0 << 12 ) | ( conn->qp->av.rate << 0 ) );
	req->primary.hop_limit = 0;
	req->primary.sl__subnet_local =
		( ( conn->qp->av.sl << 4 ) | ( 1 << 3 ) );
	req->primary.local_ack_timeout = ( 0x13 << 3 );
	private_data_len = conn->private_data_len;
	if ( private_data_len > sizeof ( req->private_data ) )
		private_data_len = sizeof ( req->private_data );
	memcpy ( &req->private_data, &conn->private_data, private_data_len );

	/* Create connection request */
	av->qpn = IB_QPN_GSI;
	av->qkey = IB_QKEY_GSI;
	conn->madx = ib_create_madx ( ibdev, ibdev->gsi, &mad, av,
				      &ib_cm_req_op );
	if ( ! conn->madx ) {
		DBGC ( conn, "CM %p could not create connection request\n",
		       conn );
		conn->op->changed ( ibdev, qp, conn, rc, NULL, 0 );
		goto out;
	}
	ib_madx_set_ownerdata ( conn->madx, conn );

 out:
	/* Destroy the completed transaction */
	ib_destroy_path ( ibdev, path );
	conn->path = NULL;
}

/** Connection path operations */
static struct ib_path_operations ib_cm_path_op = {
	.complete = ib_cm_path_complete,
};

/**
 * Create connection to remote QP
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dgid		Target GID
 * @v service_id	Target service ID
 * @v private_data	Connection request private data
 * @v private_data_len	Length of connection request private data
 * @v op		Connection operations
 * @ret conn		Connection
 */
struct ib_connection *
ib_create_conn ( struct ib_device *ibdev, struct ib_queue_pair *qp,
		 union ib_gid *dgid, union ib_guid *service_id,
		 void *private_data, size_t private_data_len,
		 struct ib_connection_operations *op ) {
	struct ib_connection *conn;

	/* Allocate and initialise request */
	conn = zalloc ( sizeof ( *conn ) + private_data_len );
	if ( ! conn )
		goto err_alloc_conn;
	conn->ibdev = ibdev;
	conn->qp = qp;
	memset ( &qp->av, 0, sizeof ( qp->av ) );
	qp->av.gid_present = 1;
	memcpy ( &qp->av.gid, dgid, sizeof ( qp->av.gid ) );
	conn->local_id = random();
	memcpy ( &conn->service_id, service_id, sizeof ( conn->service_id ) );
	conn->op = op;
	conn->private_data_len = private_data_len;
	memcpy ( &conn->private_data, private_data, private_data_len );

	/* Create path */
	conn->path = ib_create_path ( ibdev, &qp->av, &ib_cm_path_op );
	if ( ! conn->path )
		goto err_create_path;
	ib_path_set_ownerdata ( conn->path, conn );

	/* Add to list of connections */
	list_add ( &conn->list, &ib_cm_conns );

	DBGC ( conn, "CM %p created for IBDEV %p QPN %lx\n",
	       conn, ibdev, qp->qpn );
	DBGC ( conn, "CM %p connecting to " IB_GID_FMT " " IB_GUID_FMT "\n",
	       conn, IB_GID_ARGS ( dgid ), IB_GUID_ARGS ( service_id ) );

	return conn;

	ib_destroy_path ( ibdev, conn->path );
 err_create_path:
	free ( conn );
 err_alloc_conn:
	return NULL;
}

/**
 * Destroy connection to remote QP
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v conn		Connection
 */
void ib_destroy_conn ( struct ib_device *ibdev,
		       struct ib_queue_pair *qp __unused,
		       struct ib_connection *conn ) {

	list_del ( &conn->list );
	if ( conn->madx )
		ib_destroy_madx ( ibdev, ibdev->gsi, conn->madx );
	if ( conn->path )
		ib_destroy_path ( ibdev, conn->path );
	free ( conn );
}
