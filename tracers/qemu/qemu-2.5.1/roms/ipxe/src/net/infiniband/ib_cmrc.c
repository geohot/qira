/*
 * Copyright (C) 2009 Fen Systems Ltd <mbrown@fensystems.co.uk>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

FILE_LICENCE ( BSD2 );

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/process.h>
#include <ipxe/infiniband.h>
#include <ipxe/ib_cm.h>
#include <ipxe/ib_cmrc.h>

/**
 * @file
 *
 * Infiniband Communication-managed Reliable Connections
 *
 */

/** CMRC number of send WQEs
 *
 * This is a policy decision.
 */
#define IB_CMRC_NUM_SEND_WQES 4

/** CMRC number of receive WQEs
 *
 * This is a policy decision.
 */
#define IB_CMRC_NUM_RECV_WQES 2

/** CMRC number of completion queue entries
 *
 * This is a policy decision
 */
#define IB_CMRC_NUM_CQES 8

/** An Infiniband Communication-Managed Reliable Connection */
struct ib_cmrc_connection {
	/** Reference count */
	struct refcnt refcnt;
	/** Data transfer interface */
	struct interface xfer;
	/** Infiniband device */
	struct ib_device *ibdev;
	/** Completion queue */
	struct ib_completion_queue *cq;
	/** Queue pair */
	struct ib_queue_pair *qp;
	/** Connection */
	struct ib_connection *conn;
	/** Destination GID */
	union ib_gid dgid;
	/** Service ID */
	union ib_guid service_id;
	/** QP is connected */
	int connected;
	/** Shutdown process */
	struct process shutdown;
};

/**
 * Shut down CMRC connection gracefully
 *
 * @v cmrc		Communication-Managed Reliable Connection
 *
 * The Infiniband data structures are not reference-counted or
 * guarded.  It is therefore unsafe to shut them down while we may be
 * in the middle of a callback from the Infiniband stack (e.g. in a
 * receive completion handler).
 *
 * This shutdown process will run some time after the call to
 * ib_cmrc_close(), after control has returned out of the Infiniband
 * core, and will shut down the Infiniband interfaces cleanly.
 *
 * The shutdown process holds an implicit reference on the CMRC
 * connection, ensuring that the structure is not freed before the
 * shutdown process has run.
 */
static void ib_cmrc_shutdown ( struct ib_cmrc_connection *cmrc ) {

	DBGC ( cmrc, "CMRC %p shutting down\n", cmrc );

	/* Shut down Infiniband interface */
	ib_destroy_conn ( cmrc->ibdev, cmrc->qp, cmrc->conn );
	ib_destroy_qp ( cmrc->ibdev, cmrc->qp );
	ib_destroy_cq ( cmrc->ibdev, cmrc->cq );
	ib_close ( cmrc->ibdev );

	/* Drop the remaining reference */
	ref_put ( &cmrc->refcnt );
}

/**
 * Close CMRC connection
 *
 * @v cmrc		Communication-Managed Reliable Connection
 * @v rc		Reason for close
 */
static void ib_cmrc_close ( struct ib_cmrc_connection *cmrc, int rc ) {

	/* Close data transfer interface */
	intf_shutdown ( &cmrc->xfer, rc );

	/* Schedule shutdown process */
	process_add ( &cmrc->shutdown );
}

/**
 * Handle change of CMRC connection status
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v conn		Connection
 * @v rc_cm		Connection status code
 * @v private_data	Private data, if available
 * @v private_data_len	Length of private data
 */
static void ib_cmrc_changed ( struct ib_device *ibdev __unused,
			      struct ib_queue_pair *qp,
			      struct ib_connection *conn __unused, int rc_cm,
			      void *private_data, size_t private_data_len ) {
	struct ib_cmrc_connection *cmrc = ib_qp_get_ownerdata ( qp );
	int rc_xfer;

	/* Record connection status */
	if ( rc_cm == 0 ) {
		DBGC ( cmrc, "CMRC %p connected\n", cmrc );
		cmrc->connected = 1;
	} else {
		DBGC ( cmrc, "CMRC %p disconnected: %s\n",
		       cmrc, strerror ( rc_cm ) );
		cmrc->connected = 0;
	}

	/* Pass up any private data */
	DBGC2 ( cmrc, "CMRC %p received private data:\n", cmrc );
	DBGC2_HDA ( cmrc, 0, private_data, private_data_len );
	if ( private_data &&
	     ( rc_xfer = xfer_deliver_raw ( &cmrc->xfer, private_data,
					    private_data_len ) ) != 0 ) {
		DBGC ( cmrc, "CMRC %p could not deliver private data: %s\n",
		       cmrc, strerror ( rc_xfer ) );
		ib_cmrc_close ( cmrc, rc_xfer );
		return;
	}

	/* Notify upper connection of window change */
	xfer_window_changed ( &cmrc->xfer );

	/* If we are disconnected, close the upper connection */
	if ( rc_cm != 0 ) {
		ib_cmrc_close ( cmrc, rc_cm );
		return;
	}
}

/** CMRC connection operations */
static struct ib_connection_operations ib_cmrc_conn_op = {
	.changed = ib_cmrc_changed,
};

/**
 * Handle CMRC send completion
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ib_cmrc_complete_send ( struct ib_device *ibdev __unused,
				    struct ib_queue_pair *qp,
				    struct io_buffer *iobuf, int rc ) {
	struct ib_cmrc_connection *cmrc = ib_qp_get_ownerdata ( qp );

	/* Free the completed I/O buffer */
	free_iob ( iobuf );

	/* Close the connection on any send errors */
	if ( rc != 0 ) {
		DBGC ( cmrc, "CMRC %p send error: %s\n",
		       cmrc, strerror ( rc ) );
		ib_cmrc_close ( cmrc, rc );
		return;
	}
}

/**
 * Handle CMRC receive completion
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dest		Destination address vector, or NULL
 * @v source		Source address vector, or NULL
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ib_cmrc_complete_recv ( struct ib_device *ibdev __unused,
				    struct ib_queue_pair *qp,
				    struct ib_address_vector *dest __unused,
				    struct ib_address_vector *source __unused,
				    struct io_buffer *iobuf, int rc ) {
	struct ib_cmrc_connection *cmrc = ib_qp_get_ownerdata ( qp );

	/* Close the connection on any receive errors */
	if ( rc != 0 ) {
		DBGC ( cmrc, "CMRC %p receive error: %s\n",
		       cmrc, strerror ( rc ) );
		free_iob ( iobuf );
		ib_cmrc_close ( cmrc, rc );
		return;
	}

	DBGC2 ( cmrc, "CMRC %p received:\n", cmrc );
	DBGC2_HDA ( cmrc, 0, iobuf->data, iob_len ( iobuf ) );

	/* Pass up data */
	if ( ( rc = xfer_deliver_iob ( &cmrc->xfer, iobuf ) ) != 0 ) {
		DBGC ( cmrc, "CMRC %p could not deliver data: %s\n",
		       cmrc, strerror ( rc ) );
		ib_cmrc_close ( cmrc, rc );
		return;
	}
}

/** Infiniband CMRC completion operations */
static struct ib_completion_queue_operations ib_cmrc_completion_ops = {
	.complete_send = ib_cmrc_complete_send,
	.complete_recv = ib_cmrc_complete_recv,
};

/** Infiniband CMRC queue pair operations */
static struct ib_queue_pair_operations ib_cmrc_queue_pair_ops = {
	.alloc_iob = alloc_iob,
};

/**
 * Send data via CMRC
 *
 * @v cmrc		CMRC connection
 * @v iobuf		Datagram I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int ib_cmrc_xfer_deliver ( struct ib_cmrc_connection *cmrc,
				  struct io_buffer *iobuf,
				  struct xfer_metadata *meta __unused ) {
	int rc;

	/* If no connection has yet been attempted, send this datagram
	 * as the CM REQ private data.  Otherwise, send it via the QP.
	 */
	if ( ! cmrc->connected ) {

		/* Abort if we have already sent a CM connection request */
		if ( cmrc->conn ) {
			DBGC ( cmrc, "CMRC %p attempt to send before "
			       "connection is complete\n", cmrc );
			rc = -EIO;
			goto out;
		}

		/* Send via CM connection request */
		cmrc->conn = ib_create_conn ( cmrc->ibdev, cmrc->qp,
					      &cmrc->dgid, &cmrc->service_id,
					      iobuf->data, iob_len ( iobuf ),
					      &ib_cmrc_conn_op );
		if ( ! cmrc->conn ) {
			DBGC ( cmrc, "CMRC %p could not connect\n", cmrc );
			rc = -ENOMEM;
			goto out;
		}

	} else {

		/* Send via QP */
		if ( ( rc = ib_post_send ( cmrc->ibdev, cmrc->qp, NULL,
					   iob_disown ( iobuf ) ) ) != 0 ) {
			DBGC ( cmrc, "CMRC %p could not send: %s\n",
			       cmrc, strerror ( rc ) );
			goto out;
		}

	}
	return 0;

 out:
	/* Free the I/O buffer if necessary */
	free_iob ( iobuf );

	/* Close the connection on any errors */
	if ( rc != 0 )
		ib_cmrc_close ( cmrc, rc );

	return rc;
}

/**
 * Check CMRC flow control window
 *
 * @v cmrc		CMRC connection
 * @ret len		Length of window
 */
static size_t ib_cmrc_xfer_window ( struct ib_cmrc_connection *cmrc ) {

	/* We indicate a window only when we are successfully
	 * connected.
	 */
	return ( cmrc->connected ? IB_MAX_PAYLOAD_SIZE : 0 );
}

/**
 * Identify device underlying CMRC connection
 *
 * @v cmrc		CMRC connection
 * @ret device		Underlying device
 */
static struct device *
ib_cmrc_identify_device ( struct ib_cmrc_connection *cmrc ) {
	return cmrc->ibdev->dev;
}

/** CMRC data transfer interface operations */
static struct interface_operation ib_cmrc_xfer_operations[] = {
	INTF_OP ( xfer_deliver, struct ib_cmrc_connection *,
		  ib_cmrc_xfer_deliver ),
	INTF_OP ( xfer_window, struct ib_cmrc_connection *,
		  ib_cmrc_xfer_window ),
	INTF_OP ( intf_close, struct ib_cmrc_connection *, ib_cmrc_close ),
	INTF_OP ( identify_device, struct ib_cmrc_connection *,
		  ib_cmrc_identify_device ),
};

/** CMRC data transfer interface descriptor */
static struct interface_descriptor ib_cmrc_xfer_desc =
	INTF_DESC ( struct ib_cmrc_connection, xfer, ib_cmrc_xfer_operations );

/** CMRC shutdown process descriptor */
static struct process_descriptor ib_cmrc_shutdown_desc =
	PROC_DESC_ONCE ( struct ib_cmrc_connection, shutdown,
			 ib_cmrc_shutdown );

/**
 * Open CMRC connection
 *
 * @v xfer		Data transfer interface
 * @v ibdev		Infiniband device
 * @v dgid		Destination GID
 * @v service_id	Service ID
 * @ret rc		Returns status code
 */
int ib_cmrc_open ( struct interface *xfer, struct ib_device *ibdev,
		   union ib_gid *dgid, union ib_guid *service_id ) {
	struct ib_cmrc_connection *cmrc;
	int rc;

	/* Allocate and initialise structure */
	cmrc = zalloc ( sizeof ( *cmrc ) );
	if ( ! cmrc ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	ref_init ( &cmrc->refcnt, NULL );
	intf_init ( &cmrc->xfer, &ib_cmrc_xfer_desc, &cmrc->refcnt );
	cmrc->ibdev = ibdev;
	memcpy ( &cmrc->dgid, dgid, sizeof ( cmrc->dgid ) );
	memcpy ( &cmrc->service_id, service_id, sizeof ( cmrc->service_id ) );
	process_init_stopped ( &cmrc->shutdown, &ib_cmrc_shutdown_desc,
			       &cmrc->refcnt );

	/* Open Infiniband device */
	if ( ( rc = ib_open ( ibdev ) ) != 0 ) {
		DBGC ( cmrc, "CMRC %p could not open device: %s\n",
		       cmrc, strerror ( rc ) );
		goto err_open;
	}

	/* Create completion queue */
	cmrc->cq = ib_create_cq ( ibdev, IB_CMRC_NUM_CQES,
				  &ib_cmrc_completion_ops );
	if ( ! cmrc->cq ) {
		DBGC ( cmrc, "CMRC %p could not create completion queue\n",
		       cmrc );
		rc = -ENOMEM;
		goto err_create_cq;
	}

	/* Create queue pair */
	cmrc->qp = ib_create_qp ( ibdev, IB_QPT_RC, IB_CMRC_NUM_SEND_WQES,
				  cmrc->cq, IB_CMRC_NUM_RECV_WQES, cmrc->cq,
				  &ib_cmrc_queue_pair_ops );
	if ( ! cmrc->qp ) {
		DBGC ( cmrc, "CMRC %p could not create queue pair\n", cmrc );
		rc = -ENOMEM;
		goto err_create_qp;
	}
	ib_qp_set_ownerdata ( cmrc->qp, cmrc );
	DBGC ( cmrc, "CMRC %p using QPN %lx\n", cmrc, cmrc->qp->qpn );

	/* Attach to parent interface, transfer reference (implicitly)
	 * to our shutdown process, and return.
	 */
	intf_plug_plug ( &cmrc->xfer, xfer );
	return 0;

	ib_destroy_qp ( ibdev, cmrc->qp );
 err_create_qp:
	ib_destroy_cq ( ibdev, cmrc->cq );
 err_create_cq:
	ib_close ( ibdev );
 err_open:
	ref_put ( &cmrc->refcnt );
 err_alloc:
	return rc;
}
