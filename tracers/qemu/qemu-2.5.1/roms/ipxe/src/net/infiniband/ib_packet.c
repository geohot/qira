/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/infiniband.h>
#include <ipxe/ib_packet.h>

/**
 * @file
 *
 * Infiniband Packet Formats
 *
 */

/**
 * Add IB headers
 *
 * @v ibdev		Infiniband device
 * @v iobuf		I/O buffer to contain headers
 * @v qp		Queue pair
 * @v payload_len	Payload length
 * @v dest		Destination address vector
 * @ret rc		Return status code
 */
int ib_push ( struct ib_device *ibdev, struct io_buffer *iobuf,
	      struct ib_queue_pair *qp, size_t payload_len,
	      const struct ib_address_vector *dest ) {
	struct ib_local_route_header *lrh;
	struct ib_global_route_header *grh;
	struct ib_base_transport_header *bth;
	struct ib_datagram_extended_transport_header *deth;
	size_t orig_iob_len = iob_len ( iobuf );
	size_t pad_len;
	size_t lrh_len;
	size_t grh_len;
	unsigned int vl;
	unsigned int lnh;

	DBGC2 ( ibdev, "IBDEV %p TX %04x:%08lx => %04x:%08lx (key %08lx)\n",
		ibdev, ibdev->lid, qp->ext_qpn, dest->lid, dest->qpn,
		dest->qkey );

	/* Calculate packet length */
	pad_len = ( (-payload_len) & 0x3 );
	payload_len += pad_len;
	payload_len += 4; /* ICRC */

	/* Reserve space for headers */
	orig_iob_len = iob_len ( iobuf );
	deth = iob_push ( iobuf, sizeof ( *deth ) );
	bth = iob_push ( iobuf, sizeof ( *bth ) );
	grh_len = ( payload_len + iob_len ( iobuf ) - orig_iob_len );
	grh = ( dest->gid_present ?
		iob_push ( iobuf, sizeof ( *grh ) ) : NULL );
	lrh = iob_push ( iobuf, sizeof ( *lrh ) );
	lrh_len = ( payload_len + iob_len ( iobuf ) - orig_iob_len );

	/* Construct LRH */
	vl = ( ( qp->ext_qpn == IB_QPN_SMI ) ? IB_VL_SMP : IB_VL_DEFAULT );
	lrh->vl__lver = ( vl << 4 );
	lnh = ( grh ? IB_LNH_GRH : IB_LNH_BTH );
	lrh->sl__lnh = ( ( dest->sl << 4 ) | lnh );
	lrh->dlid = htons ( dest->lid );
	lrh->length = htons ( lrh_len >> 2 );
	lrh->slid = htons ( ibdev->lid );

	/* Construct GRH, if required */
	if ( grh ) {
		grh->ipver__tclass__flowlabel =
			htonl ( IB_GRH_IPVER_IPv6 << 28 );
		grh->paylen = htons ( grh_len );
		grh->nxthdr = IB_GRH_NXTHDR_IBA;
		grh->hoplmt = 0;
		memcpy ( &grh->sgid, &ibdev->gid, sizeof ( grh->sgid ) );
		memcpy ( &grh->dgid, &dest->gid, sizeof ( grh->dgid ) );
	}

	/* Construct BTH */
	bth->opcode = BTH_OPCODE_UD_SEND;
	bth->se__m__padcnt__tver = ( pad_len << 4 );
	bth->pkey = htons ( ibdev->pkey );
	bth->dest_qp = htonl ( dest->qpn );
	bth->ack__psn = htonl ( ( qp->send.psn++ ) & 0xffffffUL );

	/* Construct DETH */
	deth->qkey = htonl ( dest->qkey );
	deth->src_qp = htonl ( qp->ext_qpn );

	DBGCP_HDA ( ibdev, 0, iobuf->data,
		    ( iob_len ( iobuf ) - orig_iob_len ) );

	return 0;
}

/**
 * Remove IB headers
 *
 * @v ibdev		Infiniband device
 * @v iobuf		I/O buffer containing headers
 * @v qp		Queue pair to fill in, or NULL
 * @v payload_len	Payload length to fill in, or NULL
 * @v dest		Destination address vector to fill in
 * @v source		Source address vector to fill in
 * @ret rc		Return status code
 */
int ib_pull ( struct ib_device *ibdev, struct io_buffer *iobuf,
	      struct ib_queue_pair **qp, size_t *payload_len,
	      struct ib_address_vector *dest,
	      struct ib_address_vector *source ) {
	struct ib_local_route_header *lrh;
	struct ib_global_route_header *grh;
	struct ib_base_transport_header *bth;
	struct ib_datagram_extended_transport_header *deth;
	size_t orig_iob_len = iob_len ( iobuf );
	unsigned int lnh;
	size_t pad_len;

	/* Clear return values */
	if ( qp )
		*qp = NULL;
	if ( payload_len )
		*payload_len = 0;
	memset ( dest, 0, sizeof ( *dest ) );
	memset ( source, 0, sizeof ( *source ) );

	/* Extract LRH */
	if ( iob_len ( iobuf ) < sizeof ( *lrh ) ) {
		DBGC ( ibdev, "IBDEV %p RX too short (%zd bytes) for LRH\n",
		       ibdev, iob_len ( iobuf ) );
		return -EINVAL;
	}
	lrh = iobuf->data;
	iob_pull ( iobuf, sizeof ( *lrh ) );
	dest->lid = ntohs ( lrh->dlid );
	dest->sl = ( lrh->sl__lnh >> 4 );
	source->lid = ntohs ( lrh->slid );
	source->sl = ( lrh->sl__lnh >> 4 );
	lnh = ( lrh->sl__lnh & 0x3 );

	/* Reject unsupported packets */
	if ( ! ( ( lnh == IB_LNH_BTH ) || ( lnh == IB_LNH_GRH ) ) ) {
		DBGC ( ibdev, "IBDEV %p RX unsupported LNH %x\n",
		       ibdev, lnh );
		return -ENOTSUP;
	}

	/* Extract GRH, if present */
	if ( lnh == IB_LNH_GRH ) {
		if ( iob_len ( iobuf ) < sizeof ( *grh ) ) {
			DBGC ( ibdev, "IBDEV %p RX too short (%zd bytes) "
			       "for GRH\n", ibdev, iob_len ( iobuf ) );
			return -EINVAL;
		}
		grh = iobuf->data;
		iob_pull ( iobuf, sizeof ( *grh ) );
		dest->gid_present = 1;
		memcpy ( &dest->gid, &grh->dgid, sizeof ( dest->gid ) );
		source->gid_present = 1;
		memcpy ( &source->gid, &grh->sgid, sizeof ( source->gid ) );
	} else {
		grh = NULL;
	}

	/* Extract BTH */
	if ( iob_len ( iobuf ) < sizeof ( *bth ) ) {
		DBGC ( ibdev, "IBDEV %p RX too short (%zd bytes) for BTH\n",
		       ibdev, iob_len ( iobuf ) );
		return -EINVAL;
	}
	bth = iobuf->data;
	iob_pull ( iobuf, sizeof ( *bth ) );
	if ( bth->opcode != BTH_OPCODE_UD_SEND ) {
		DBGC ( ibdev, "IBDEV %p unsupported BTH opcode %x\n",
		       ibdev, bth->opcode );
		return -ENOTSUP;
	}
	dest->qpn = ntohl ( bth->dest_qp );

	/* Extract DETH */
	if ( iob_len ( iobuf ) < sizeof ( *deth ) ) {
		DBGC ( ibdev, "IBDEV %p RX too short (%zd bytes) for DETH\n",
		       ibdev, iob_len ( iobuf ) );
		return -EINVAL;
	}
	deth = iobuf->data;
	iob_pull ( iobuf, sizeof ( *deth ) );
	source->qpn = ntohl ( deth->src_qp );
	source->qkey = ntohl ( deth->qkey );

	/* Calculate payload length, if applicable */
	if ( payload_len ) {
		pad_len = ( ( bth->se__m__padcnt__tver >> 4 ) & 0x3 );
		*payload_len = ( ( ntohs ( lrh->length ) << 2 )
				 - ( orig_iob_len - iob_len ( iobuf ) )
				 - pad_len - 4 /* ICRC */ );
	}

	/* Determine destination QP, if applicable */
	if ( qp ) {
		if ( IB_LID_MULTICAST ( dest->lid ) && grh ) {
			if ( ! ( *qp = ib_find_qp_mgid ( ibdev, &grh->dgid ))){
				DBGC ( ibdev, "IBDEV %p RX for unknown MGID "
				       IB_GID_FMT "\n",
				       ibdev, IB_GID_ARGS ( &grh->dgid ) );
				return -ENODEV;
			}
		} else {
			if ( ! ( *qp = ib_find_qp_qpn ( ibdev, dest->qpn ) ) ) {
				DBGC ( ibdev, "IBDEV %p RX for nonexistent "
				       "QPN %lx\n", ibdev, dest->qpn );
				return -ENODEV;
			}
		}
		assert ( *qp );
	}

	DBGC2 ( ibdev, "IBDEV %p RX %04x:%08lx <= %04x:%08lx (key %08x)\n",
		ibdev, dest->lid, ( IB_LID_MULTICAST ( dest->lid ) ?
			      ( qp ? (*qp)->ext_qpn : -1UL ) : dest->qpn ),
		source->lid, source->qpn, ntohl ( deth->qkey ) );
	DBGCP_HDA ( ibdev, 0,
		    ( iobuf->data - ( orig_iob_len - iob_len ( iobuf ) ) ),
		    ( orig_iob_len - iob_len ( iobuf ) ) );

	return 0;
}
