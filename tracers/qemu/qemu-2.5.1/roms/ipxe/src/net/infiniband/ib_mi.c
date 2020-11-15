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
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/infiniband.h>
#include <ipxe/iobuf.h>
#include <ipxe/ib_mi.h>

/**
 * @file
 *
 * Infiniband management interfaces
 *
 */

/** Management interface number of send WQEs
 *
 * This is a policy decision.
 */
#define IB_MI_NUM_SEND_WQES 4

/** Management interface number of receive WQEs
 *
 * This is a policy decision.
 */
#define IB_MI_NUM_RECV_WQES 2

/** Management interface number of completion queue entries
 *
 * This is a policy decision
 */
#define IB_MI_NUM_CQES 8

/** TID magic signature */
#define IB_MI_TID_MAGIC ( ( 'i' << 24 ) | ( 'P' << 16 ) | ( 'X' << 8 ) | 'E' )

/** TID to use for next MAD */
static unsigned int next_tid;

/**
 * Handle received MAD
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @v av		Source address vector
 * @ret rc		Return status code
 */
static int ib_mi_handle ( struct ib_device *ibdev,
			  struct ib_mad_interface *mi,
			  union ib_mad *mad,
			  struct ib_address_vector *av ) {
	struct ib_mad_hdr *hdr = &mad->hdr;
	struct ib_mad_transaction *madx;
	struct ib_mad_agent *agent;

	/* Look for a matching transaction by TID */
	list_for_each_entry ( madx, &mi->madx, list ) {
		if ( memcmp ( &hdr->tid, &madx->mad.hdr.tid,
			      sizeof ( hdr->tid ) ) != 0 )
			continue;
		/* Found a matching transaction */
		madx->op->complete ( ibdev, mi, madx, 0, mad, av );
		return 0;
	}

	/* If there is no matching transaction, look for a listening agent */
	for_each_table_entry ( agent, IB_MAD_AGENTS ) {
		if ( ( ( agent->mgmt_class & IB_MGMT_CLASS_MASK ) !=
		       ( hdr->mgmt_class & IB_MGMT_CLASS_MASK ) ) ||
		     ( agent->class_version != hdr->class_version ) ||
		     ( agent->attr_id != hdr->attr_id ) )
			continue;
		/* Found a matching agent */
		agent->handle ( ibdev, mi, mad, av );
		return 0;
	}

	/* Otherwise, ignore it */
	DBGC ( mi, "MI %p RX TID %08x%08x ignored\n",
	       mi, ntohl ( hdr->tid[0] ), ntohl ( hdr->tid[1] ) );
	return -ENOTSUP;
}

/**
 * Complete receive via management interface
 *
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dest		Destination address vector
 * @v source		Source address vector
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ib_mi_complete_recv ( struct ib_device *ibdev,
				  struct ib_queue_pair *qp,
				  struct ib_address_vector *dest __unused,
				  struct ib_address_vector *source,
				  struct io_buffer *iobuf, int rc ) {
	struct ib_mad_interface *mi = ib_qp_get_ownerdata ( qp );
	union ib_mad *mad;
	struct ib_mad_hdr *hdr;

	/* Ignore errors */
	if ( rc != 0 ) {
		DBGC ( mi, "MI %p RX error: %s\n", mi, strerror ( rc ) );
		goto out;
	}

	/* Sanity checks */
	if ( iob_len ( iobuf ) != sizeof ( *mad ) ) {
		DBGC ( mi, "MI %p RX bad size (%zd bytes)\n",
		       mi, iob_len ( iobuf ) );
		DBGC_HDA ( mi, 0, iobuf->data, iob_len ( iobuf ) );
		goto out;
	}
	mad = iobuf->data;
	hdr = &mad->hdr;
	if ( hdr->base_version != IB_MGMT_BASE_VERSION ) {
		DBGC ( mi, "MI %p RX unsupported base version %x\n",
		       mi, hdr->base_version );
		DBGC_HDA ( mi, 0, mad, sizeof ( *mad ) );
		goto out;
	}
	DBGC ( mi, "MI %p RX TID %08x%08x (%02x,%02x,%02x,%04x) status "
	       "%04x\n", mi, ntohl ( hdr->tid[0] ), ntohl ( hdr->tid[1] ),
	       hdr->mgmt_class, hdr->class_version, hdr->method,
	       ntohs ( hdr->attr_id ), ntohs ( hdr->status ) );
	DBGC2_HDA ( mi, 0, mad, sizeof ( *mad ) );

	/* Handle MAD */
	if ( ( rc = ib_mi_handle ( ibdev, mi, mad, source ) ) != 0 )
		goto out;

 out:
	free_iob ( iobuf );
}

/** Management interface completion operations */
static struct ib_completion_queue_operations ib_mi_completion_ops = {
	.complete_recv = ib_mi_complete_recv,
};

/** Management interface queue pair operations */
static struct ib_queue_pair_operations ib_mi_queue_pair_ops = {
	.alloc_iob = alloc_iob,
};

/**
 * Transmit MAD
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		MAD
 * @v av		Destination address vector
 * @ret rc		Return status code
 */
int ib_mi_send ( struct ib_device *ibdev, struct ib_mad_interface *mi,
		 union ib_mad *mad, struct ib_address_vector *av ) {
	struct ib_mad_hdr *hdr = &mad->hdr;
	struct io_buffer *iobuf;
	int rc;

	/* Set common fields */
	hdr->base_version = IB_MGMT_BASE_VERSION;
	if ( ( hdr->tid[0] == 0 ) && ( hdr->tid[1] == 0 ) ) {
		hdr->tid[0] = htonl ( IB_MI_TID_MAGIC );
		hdr->tid[1] = htonl ( ++next_tid );
	}
	DBGC ( mi, "MI %p TX TID %08x%08x (%02x,%02x,%02x,%04x) status "
	       "%04x\n", mi, ntohl ( hdr->tid[0] ), ntohl ( hdr->tid[1] ),
	       hdr->mgmt_class, hdr->class_version, hdr->method,
	       ntohs ( hdr->attr_id ), ntohs ( hdr->status ) );
	DBGC2_HDA ( mi, 0, mad, sizeof ( *mad ) );

	/* Construct directed route portion of response, if necessary */
	if ( hdr->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE ) {
		struct ib_mad_smp *smp = &mad->smp;
		unsigned int hop_pointer;
		unsigned int hop_count;

		smp->mad_hdr.status |= htons ( IB_SMP_STATUS_D_INBOUND );
		hop_pointer = smp->mad_hdr.class_specific.smp.hop_pointer;
		hop_count = smp->mad_hdr.class_specific.smp.hop_count;
		assert ( hop_count == hop_pointer );
		if ( hop_pointer < ( sizeof ( smp->return_path.hops ) /
				     sizeof ( smp->return_path.hops[0] ) ) ) {
			smp->return_path.hops[hop_pointer] = ibdev->port;
		} else {
			DBGC ( mi, "MI %p TX TID %08x%08x invalid hop pointer "
			       "%d\n", mi, ntohl ( hdr->tid[0] ),
			       ntohl ( hdr->tid[1] ), hop_pointer );
			return -EINVAL;
		}
	}

	/* Construct I/O buffer */
	iobuf = alloc_iob ( sizeof ( *mad ) );
	if ( ! iobuf ) {
		DBGC ( mi, "MI %p could not allocate buffer for TID "
		       "%08x%08x\n",
		       mi, ntohl ( hdr->tid[0] ), ntohl ( hdr->tid[1] ) );
		return -ENOMEM;
	}
	memcpy ( iob_put ( iobuf, sizeof ( *mad ) ), mad, sizeof ( *mad ) );

	/* Send I/O buffer */
	if ( ( rc = ib_post_send ( ibdev, mi->qp, av, iobuf ) ) != 0 ) {
		DBGC ( mi, "MI %p TX TID %08x%08x failed: %s\n",
		       mi,  ntohl ( hdr->tid[0] ), ntohl ( hdr->tid[1] ),
		       strerror ( rc ) );
		free_iob ( iobuf );
		return rc;
	}

	return 0;
}

/**
 * Handle management transaction timer expiry
 *
 * @v timer		Retry timer
 * @v expired		Failure indicator
 */
static void ib_mi_timer_expired ( struct retry_timer *timer, int expired ) {
	struct ib_mad_transaction *madx =
		container_of ( timer, struct ib_mad_transaction, timer );
	struct ib_mad_interface *mi = madx->mi;
	struct ib_device *ibdev = mi->ibdev;
	struct ib_mad_hdr *hdr = &madx->mad.hdr;

	/* Abandon transaction if we have tried too many times */
	if ( expired ) {
		DBGC ( mi, "MI %p abandoning TID %08x%08x\n",
		       mi, ntohl ( hdr->tid[0] ), ntohl ( hdr->tid[1] ) );
		madx->op->complete ( ibdev, mi, madx, -ETIMEDOUT, NULL, NULL );
		return;
	}

	/* Restart retransmission timer */
	start_timer ( timer );

	/* Resend MAD */
	ib_mi_send ( ibdev, mi, &madx->mad, &madx->av );
}

/**
 * Create management transaction
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		MAD to send
 * @v av		Destination address, or NULL to use SM's GSI
 * @v op		Management transaction operations
 * @ret madx		Management transaction, or NULL
 */
struct ib_mad_transaction *
ib_create_madx ( struct ib_device *ibdev, struct ib_mad_interface *mi,
		 union ib_mad *mad, struct ib_address_vector *av,
		 struct ib_mad_transaction_operations *op ) {
	struct ib_mad_transaction *madx;

	/* Allocate and initialise structure */
	madx = zalloc ( sizeof ( *madx ) );
	if ( ! madx )
		return NULL;
	timer_init ( &madx->timer, ib_mi_timer_expired, NULL );
	madx->mi = mi;
	madx->op = op;

	/* Determine address vector */
	if ( av ) {
		memcpy ( &madx->av, av, sizeof ( madx->av ) );
	} else {
		madx->av.lid = ibdev->sm_lid;
		madx->av.sl = ibdev->sm_sl;
		madx->av.qpn = IB_QPN_GSI;
		madx->av.qkey = IB_QKEY_GSI;
	}

	/* Copy MAD */
	memcpy ( &madx->mad, mad, sizeof ( madx->mad ) );

	/* Add to list and start timer to send initial MAD */
	list_add ( &madx->list, &mi->madx );
	start_timer_nodelay ( &madx->timer );

	return madx;
}

/**
 * Destroy management transaction
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v madx		Management transaction
 */
void ib_destroy_madx ( struct ib_device *ibdev __unused,
		       struct ib_mad_interface *mi __unused,
		       struct ib_mad_transaction *madx ) {

	/* Stop timer and remove from list */
	stop_timer ( &madx->timer );
	list_del ( &madx->list );

	/* Free transaction */
	free ( madx );
}

/**
 * Create management interface
 *
 * @v ibdev		Infiniband device
 * @v type		Queue pair type
 * @ret mi		Management agent, or NULL
 */
struct ib_mad_interface * ib_create_mi ( struct ib_device *ibdev,
					 enum ib_queue_pair_type type ) {
	struct ib_mad_interface *mi;
	int rc;

	/* Allocate and initialise fields */
	mi = zalloc ( sizeof ( *mi ) );
	if ( ! mi )
		goto err_alloc;
	mi->ibdev = ibdev;
	INIT_LIST_HEAD ( &mi->madx );

	/* Create completion queue */
	mi->cq = ib_create_cq ( ibdev, IB_MI_NUM_CQES, &ib_mi_completion_ops );
	if ( ! mi->cq ) {
		DBGC ( mi, "MI %p could not allocate completion queue\n", mi );
		goto err_create_cq;
	}

	/* Create queue pair */
	mi->qp = ib_create_qp ( ibdev, type, IB_MI_NUM_SEND_WQES, mi->cq,
				IB_MI_NUM_RECV_WQES, mi->cq,
				&ib_mi_queue_pair_ops );
	if ( ! mi->qp ) {
		DBGC ( mi, "MI %p could not allocate queue pair\n", mi );
		goto err_create_qp;
	}
	ib_qp_set_ownerdata ( mi->qp, mi );
	DBGC ( mi, "MI %p (%s) running on QPN %#lx\n",
	       mi, ( ( type == IB_QPT_SMI ) ? "SMI" : "GSI" ), mi->qp->qpn );

	/* Set queue key */
	mi->qp->qkey = ( ( type == IB_QPT_SMI ) ? IB_QKEY_SMI : IB_QKEY_GSI );
	if ( ( rc = ib_modify_qp ( ibdev, mi->qp ) ) != 0 ) {
		DBGC ( mi, "MI %p could not set queue key: %s\n",
		       mi, strerror ( rc ) );
		goto err_modify_qp;
	}

	/* Fill receive ring */
	ib_refill_recv ( ibdev, mi->qp );
	return mi;

 err_modify_qp:
	ib_destroy_qp ( ibdev, mi->qp );
 err_create_qp:
	ib_destroy_cq ( ibdev, mi->cq );
 err_create_cq:
	free ( mi );
 err_alloc:
	return NULL;
}

/**
 * Destroy management interface
 *
 * @v mi		Management interface
 */
void ib_destroy_mi ( struct ib_device *ibdev, struct ib_mad_interface *mi ) {
	struct ib_mad_transaction *madx;
	struct ib_mad_transaction *tmp;

	/* Flush any outstanding requests */
	list_for_each_entry_safe ( madx, tmp, &mi->madx, list ) {
		DBGC ( mi, "MI %p destroyed while TID %08x%08x in progress\n",
		       mi, ntohl ( madx->mad.hdr.tid[0] ),
		       ntohl ( madx->mad.hdr.tid[1] ) );
		madx->op->complete ( ibdev, mi, madx, -ECANCELED, NULL, NULL );
	}

	ib_destroy_qp ( ibdev, mi->qp );
	ib_destroy_cq ( ibdev, mi->cq );
	free ( mi );
}
