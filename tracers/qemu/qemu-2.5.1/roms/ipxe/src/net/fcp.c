/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/iobuf.h>
#include <ipxe/open.h>
#include <ipxe/process.h>
#include <ipxe/uri.h>
#include <ipxe/acpi.h>
#include <ipxe/scsi.h>
#include <ipxe/device.h>
#include <ipxe/edd.h>
#include <ipxe/fc.h>
#include <ipxe/fcels.h>
#include <ipxe/fcp.h>

/** @file
 *
 * Fibre Channel Protocol
 *
 */

/* Disambiguate the various error causes */
#define ERANGE_READ_DATA_ORDERING \
	__einfo_error ( EINFO_ERANGE_READ_DATA_ORDERING )
#define EINFO_ERANGE_READ_DATA_ORDERING \
	__einfo_uniqify ( EINFO_ERANGE, 0x01, "Read data out of order" )
#define ERANGE_READ_DATA_OVERRUN \
	__einfo_error ( EINFO_ERANGE_READ_DATA_OVERRUN )
#define EINFO_ERANGE_READ_DATA_OVERRUN \
	__einfo_uniqify ( EINFO_ERANGE, 0x02, "Read data overrun" )
#define ERANGE_WRITE_DATA_STUCK \
	__einfo_error ( EINFO_ERANGE_WRITE_DATA_STUCK )
#define EINFO_ERANGE_WRITE_DATA_STUCK \
	__einfo_uniqify ( EINFO_ERANGE, 0x03, "Write data stuck" )
#define ERANGE_WRITE_DATA_OVERRUN \
	__einfo_error ( EINFO_ERANGE_WRITE_DATA_OVERRUN )
#define EINFO_ERANGE_WRITE_DATA_OVERRUN \
	__einfo_uniqify ( EINFO_ERANGE, 0x04, "Write data overrun" )
#define ERANGE_DATA_UNDERRUN \
	__einfo_error ( EINFO_ERANGE_DATA_UNDERRUN )
#define EINFO_ERANGE_DATA_UNDERRUN \
	__einfo_uniqify ( EINFO_ERANGE, 0x05, "Data underrun" )

/******************************************************************************
 *
 * PRLI
 *
 ******************************************************************************
 */

struct fc_els_prli_descriptor fcp_prli_descriptor __fc_els_prli_descriptor;

/**
 * Transmit FCP PRLI
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fcp_prli_tx ( struct fc_els *els ) {
	struct fcp_prli_service_parameters param;

	/* Build service parameter page */
	memset ( &param, 0, sizeof ( param ) );
	param.flags = htonl ( FCP_PRLI_NO_READ_RDY | FCP_PRLI_INITIATOR );

	return fc_els_prli_tx ( els, &fcp_prli_descriptor, &param );
}

/**
 * Receive FCP PRLI
 *
 * @v els		Fibre Channel ELS transaction
 * @v frame		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fcp_prli_rx ( struct fc_els *els, void *data, size_t len ) {
	return fc_els_prli_rx ( els, &fcp_prli_descriptor, data, len );
}

/**
 * Detect FCP PRLI
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fcp_prli_detect ( struct fc_els *els, const void *data,
			     size_t len ) {
	return fc_els_prli_detect ( els, &fcp_prli_descriptor, data, len );
}

/** FCP PRLI ELS handler */
struct fc_els_handler fcp_prli_handler __fc_els_handler = {
	.name		= "PRLI-FCP",
	.tx		= fcp_prli_tx,
	.rx		= fcp_prli_rx,
	.detect		= fcp_prli_detect,
};

/** FCP PRLI descriptor */
struct fc_els_prli_descriptor fcp_prli_descriptor __fc_els_prli_descriptor = {
	.type		= FC_TYPE_FCP,
	.param_len	= sizeof ( struct fcp_prli_service_parameters ),
	.handler	= &fcp_prli_handler,
};

/******************************************************************************
 *
 * FCP devices and commands
 *
 ******************************************************************************
 */

/** An FCP device */
struct fcp_device {
	/** Reference count */
	struct refcnt refcnt;
	/** Fibre Channel upper-layer protocol user */
	struct fc_ulp_user user;
	/** SCSI command issuing interface */
	struct interface scsi;
	/** List of active commands */
	struct list_head fcpcmds;

	/** Fibre Channel WWN (for boot firmware table) */
	struct fc_name wwn;
	/** SCSI LUN (for boot firmware table) */
	struct scsi_lun lun;
};

/** An FCP command */
struct fcp_command {
	/** Reference count */
	struct refcnt refcnt;
	/** FCP SCSI device */
	struct fcp_device *fcpdev;
	/** List of active commands */
	struct list_head list;
	/** SCSI command interface */
	struct interface scsi;
	/** Fibre Channel exchange interface */
	struct interface xchg;
	/** Send process */
	struct process process;
	/** Send current IU
	 *
	 * @v fcpcmd	FCP command
	 * @ret rc	Return status code
	 */
	int ( * send ) ( struct fcp_command *fcpcmd );
	/** SCSI command */
	struct scsi_cmd command;
	/** Data offset within command */
	size_t offset;
	/** Length of data remaining to be sent within this IU */
	size_t remaining;
	/** Exchange ID */
	uint16_t xchg_id;
};

/**
 * Get reference to FCP device
 *
 * @v fcpdev		FCP device
 * @ret fcpdev		FCP device
 */
static inline __attribute__ (( always_inline )) struct fcp_device *
fcpdev_get ( struct fcp_device *fcpdev ) {
	ref_get ( &fcpdev->refcnt );
	return fcpdev;
}

/**
 * Drop reference to FCP device
 *
 * @v fcpdev		FCP device
 */
static inline __attribute__ (( always_inline )) void
fcpdev_put ( struct fcp_device *fcpdev ) {
	ref_put ( &fcpdev->refcnt );
}

/**
 * Get reference to FCP command
 *
 * @v fcpcmd		FCP command
 * @ret fcpcmd		FCP command
 */
static inline __attribute__ (( always_inline )) struct fcp_command *
fcpcmd_get ( struct fcp_command *fcpcmd ) {
	ref_get ( &fcpcmd->refcnt );
	return fcpcmd;
}

/**
 * Drop reference to FCP command
 *
 * @v fcpcmd		FCP command
 */
static inline __attribute__ (( always_inline )) void
fcpcmd_put ( struct fcp_command *fcpcmd ) {
	ref_put ( &fcpcmd->refcnt );
}

/**
 * Start FCP command sending
 *
 * @v fcpcmd		FCP command
 * @v send		Send method
 */
static inline __attribute__ (( always_inline )) void
fcpcmd_start_send ( struct fcp_command *fcpcmd,
		    int ( * send ) ( struct fcp_command *fcpcmd ) ) {
	fcpcmd->send = send;
	process_add ( &fcpcmd->process );
}

/**
 * Stop FCP command sending
 *
 * @v fcpcmd		FCP command
 */
static inline __attribute__ (( always_inline )) void
fcpcmd_stop_send ( struct fcp_command *fcpcmd ) {
	process_del ( &fcpcmd->process );
}

/**
 * Free FCP command
 *
 * @v refcnt		Reference count
 */
static void fcpcmd_free ( struct refcnt *refcnt ) {
	struct fcp_command *fcpcmd =
		container_of ( refcnt, struct fcp_command, refcnt );

	/* Remove from list of commands */
	list_del ( &fcpcmd->list );
	fcpdev_put ( fcpcmd->fcpdev );

	/* Free command */
	free ( fcpcmd );
}

/**
 * Close FCP command
 *
 * @v fcpcmd		FCP command
 * @v rc		Reason for close
 */
static void fcpcmd_close ( struct fcp_command *fcpcmd, int rc ) {
	struct fcp_device *fcpdev = fcpcmd->fcpdev;

	if ( rc != 0 ) {
		DBGC ( fcpdev, "FCP %p xchg %04x closed: %s\n",
		       fcpdev, fcpcmd->xchg_id, strerror ( rc ) );
	}

	/* Stop sending */
	fcpcmd_stop_send ( fcpcmd );

	/* Shut down interfaces */
	intf_shutdown ( &fcpcmd->scsi, rc );
	intf_shutdown ( &fcpcmd->xchg, rc );
}

/**
 * Close FCP command in error
 *
 * @v fcpcmd		FCP command
 * @v rc		Reason for close
 */
static void fcpcmd_close_err ( struct fcp_command *fcpcmd, int rc ) {
	if ( rc == 0 )
		rc = -EPIPE;
	fcpcmd_close ( fcpcmd, rc );
}

/**
 * Send FCP command IU
 *
 * @v fcpcmd		FCP command
 * @ret rc		Return status code
 */
static int fcpcmd_send_cmnd ( struct fcp_command *fcpcmd ) {
	struct fcp_device *fcpdev = fcpcmd->fcpdev;
	struct scsi_cmd *command = &fcpcmd->command;
	struct io_buffer *iobuf;
	struct fcp_cmnd *cmnd;
	struct xfer_metadata meta;
	int rc;

	/* Sanity check */
	if ( command->data_in_len && command->data_out_len ) {
		DBGC ( fcpdev, "FCP %p xchg %04x cannot handle bidirectional "
		       "command\n", fcpdev, fcpcmd->xchg_id );
		return -ENOTSUP;
	}

	/* Allocate I/O buffer */
	iobuf = xfer_alloc_iob ( &fcpcmd->xchg, sizeof ( *cmnd ) );
	if ( ! iobuf ) {
		DBGC ( fcpdev, "FCP %p xchg %04x cannot allocate command IU\n",
		       fcpdev, fcpcmd->xchg_id );
		return -ENOMEM;
	}

	/* Construct command IU frame */
	cmnd = iob_put ( iobuf, sizeof ( *cmnd ) );
	memset ( cmnd, 0, sizeof ( *cmnd ) );
	memcpy ( &cmnd->lun, &command->lun, sizeof ( cmnd->lun ) );
	assert ( ! ( command->data_in_len && command->data_out_len ) );
	if ( command->data_in_len )
		cmnd->dirn |= FCP_CMND_RDDATA;
	if ( command->data_out_len )
		cmnd->dirn |= FCP_CMND_WRDATA;
	memcpy ( &cmnd->cdb, &fcpcmd->command.cdb, sizeof ( cmnd->cdb ) );
	cmnd->len = htonl ( command->data_in_len + command->data_out_len );
	memset ( &meta, 0, sizeof ( meta ) );
	meta.flags = ( XFER_FL_CMD_STAT | XFER_FL_OVER );
	DBGC2 ( fcpdev, "FCP %p xchg %04x CMND " SCSI_CDB_FORMAT " %04x\n",
		fcpdev, fcpcmd->xchg_id, SCSI_CDB_DATA ( cmnd->cdb ),
		ntohl ( cmnd->len ) );

	/* No further data to send within this IU */
	fcpcmd_stop_send ( fcpcmd );

	/* Send command IU frame */
	if ( ( rc = xfer_deliver ( &fcpcmd->xchg, iob_disown ( iobuf ),
				   &meta ) ) != 0 ) {
		DBGC ( fcpdev, "FCP %p xchg %04x cannot deliver command IU: "
		       "%s\n", fcpdev, fcpcmd->xchg_id, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle FCP read data IU
 *
 * @v fcpcmd		FCP command
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fcpcmd_recv_rddata ( struct fcp_command *fcpcmd,
				struct io_buffer *iobuf,
				struct xfer_metadata *meta ) {
	struct fcp_device *fcpdev = fcpcmd->fcpdev;
	struct scsi_cmd *command = &fcpcmd->command;
	size_t offset = meta->offset;
	size_t len = iob_len ( iobuf );
	int rc;

	/* Sanity checks */
	if ( ! ( meta->flags & XFER_FL_ABS_OFFSET ) ) {
		DBGC ( fcpdev, "FCP %p xchg %04x read data missing offset\n",
		       fcpdev, fcpcmd->xchg_id );
		rc = -ERANGE_READ_DATA_ORDERING;
		goto done;
	}
	if ( offset != fcpcmd->offset ) {
		DBGC ( fcpdev, "FCP %p xchg %04x read data out of order "
		       "(expected %zd, received %zd)\n",
		       fcpdev, fcpcmd->xchg_id, fcpcmd->offset, offset );
		rc = -ERANGE_READ_DATA_ORDERING;
		goto done;
	}
	if ( ( offset + len ) > command->data_in_len ) {
		DBGC ( fcpdev, "FCP %p xchg %04x read data overrun (max %zd, "
		       "received %zd)\n", fcpdev, fcpcmd->xchg_id,
		       command->data_in_len, ( offset + len ) );
		rc = -ERANGE_READ_DATA_OVERRUN;
		goto done;
	}
	DBGC2 ( fcpdev, "FCP %p xchg %04x RDDATA [%08zx,%08zx)\n",
		fcpdev, fcpcmd->xchg_id, offset, ( offset + len ) );

	/* Copy to user buffer */
	copy_to_user ( command->data_in, offset, iobuf->data, len );
	fcpcmd->offset += len;
	assert ( fcpcmd->offset <= command->data_in_len );

	rc = 0;
 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Send FCP write data IU
 *
 * @v fcpcmd		FCP command
 * @ret rc		Return status code
 */
static int fcpcmd_send_wrdata ( struct fcp_command *fcpcmd ) {
	struct fcp_device *fcpdev = fcpcmd->fcpdev;
	struct scsi_cmd *command = &fcpcmd->command;
	struct io_buffer *iobuf;
	struct xfer_metadata meta;
	size_t len;
	int rc;

	/* Calculate length to be sent */
	len = xfer_window ( &fcpcmd->xchg );
	if ( len > fcpcmd->remaining )
		len = fcpcmd->remaining;

	/* Sanity checks */
	if ( len == 0 ) {
		DBGC ( fcpdev, "FCP %p xchg %04x write data stuck\n",
		       fcpdev, fcpcmd->xchg_id );
		return -ERANGE_WRITE_DATA_STUCK;
	}
	if ( ( fcpcmd->offset + len ) > command->data_out_len ) {
		DBGC ( fcpdev, "FCP %p xchg %04x write data overrun (max %zd, "
		       "requested %zd)\n", fcpdev, fcpcmd->xchg_id,
		       command->data_out_len, ( fcpcmd->offset + len ) );
		return -ERANGE_WRITE_DATA_OVERRUN;
	}

	/* Allocate I/O buffer */
	iobuf = xfer_alloc_iob ( &fcpcmd->xchg, len );
	if ( ! iobuf ) {
		DBGC ( fcpdev, "FCP %p xchg %04x cannot allocate write data "
		       "IU for %zd bytes\n", fcpdev, fcpcmd->xchg_id, len );
		return -ENOMEM;
	}

	/* Construct data IU frame */
	copy_from_user ( iob_put ( iobuf, len ), command->data_out,
			 fcpcmd->offset, len );
	memset ( &meta, 0, sizeof ( meta ) );
	meta.flags = ( XFER_FL_RESPONSE | XFER_FL_ABS_OFFSET );
	meta.offset = fcpcmd->offset;
	DBGC2 ( fcpdev, "FCP %p xchg %04x WRDATA [%08zx,%04zx)\n",
		fcpdev, fcpcmd->xchg_id, fcpcmd->offset,
		( fcpcmd->offset + iob_len ( iobuf ) ) );

	/* Calculate amount of data remaining to be sent within this IU */
	assert ( len <= fcpcmd->remaining );
	fcpcmd->offset += len;
	fcpcmd->remaining -= len;
	assert ( fcpcmd->offset <= command->data_out_len );
	if ( fcpcmd->remaining == 0 ) {
		fcpcmd_stop_send ( fcpcmd );
		meta.flags |= XFER_FL_OVER;
	}

	/* Send data IU frame */
	if ( ( rc = xfer_deliver ( &fcpcmd->xchg, iob_disown ( iobuf ),
				   &meta ) ) != 0 ) {
		DBGC ( fcpdev, "FCP %p xchg %04x cannot deliver write data "
		       "IU: %s\n", fcpdev, fcpcmd->xchg_id, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle FCP transfer ready IU
 *
 * @v fcpcmd		FCP command
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fcpcmd_recv_xfer_rdy ( struct fcp_command *fcpcmd,
				  struct io_buffer *iobuf,
				  struct xfer_metadata *meta __unused ) {
	struct fcp_device *fcpdev = fcpcmd->fcpdev;
	struct fcp_xfer_rdy *xfer_rdy = iobuf->data;
	int rc;

	/* Sanity checks */
	if ( iob_len ( iobuf ) != sizeof ( *xfer_rdy ) ) {
		DBGC ( fcpdev, "FCP %p xchg %04x received invalid transfer "
		       "ready IU:\n", fcpdev, fcpcmd->xchg_id );
		DBGC_HDA ( fcpdev, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EPROTO;
		goto done;
	}
	if ( ntohl ( xfer_rdy->offset ) != fcpcmd->offset ) {
		/* We do not advertise out-of-order delivery */
		DBGC ( fcpdev, "FCP %p xchg %04x cannot support out-of-order "
		       "delivery (expected %zd, requested %d)\n",
		       fcpdev, fcpcmd->xchg_id, fcpcmd->offset,
		       ntohl ( xfer_rdy->offset ) );
		rc = -EPROTO;
		goto done;
	}
	DBGC2 ( fcpdev, "FCP %p xchg %04x XFER_RDY [%08x,%08x)\n",
		fcpdev, fcpcmd->xchg_id, ntohl ( xfer_rdy->offset ),
		( ntohl ( xfer_rdy->offset ) + ntohl ( xfer_rdy->len ) ) );

	/* Start sending requested data */
	fcpcmd->remaining = ntohl ( xfer_rdy->len );
	fcpcmd_start_send ( fcpcmd, fcpcmd_send_wrdata );

	rc = 0;
 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Handle FCP response IU
 *
 * @v fcpcmd		FCP command
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fcpcmd_recv_rsp ( struct fcp_command *fcpcmd,
			     struct io_buffer *iobuf,
			     struct xfer_metadata *meta __unused ) {
	struct fcp_device *fcpdev = fcpcmd->fcpdev;
	struct scsi_cmd *command = &fcpcmd->command;
	struct fcp_rsp *rsp = iobuf->data;
	struct scsi_rsp response;
	int rc;

	/* Sanity check */
	if ( ( iob_len ( iobuf ) < sizeof ( *rsp ) ) ||
	     ( iob_len ( iobuf ) < ( sizeof ( *rsp ) +
				     fcp_rsp_response_data_len ( rsp ) +
				     fcp_rsp_sense_data_len ( rsp ) ) ) ) {
		DBGC ( fcpdev, "FCP %p xchg %04x received invalid response "
		       "IU:\n", fcpdev, fcpcmd->xchg_id );
		DBGC_HDA ( fcpdev, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EPROTO;
		goto done;
	}
	DBGC2 ( fcpdev, "FCP %p xchg %04x RSP stat %02x resid %08x flags %02x"
		"%s%s%s%s\n", fcpdev, fcpcmd->xchg_id, rsp->status,
		ntohl ( rsp->residual ), rsp->flags,
		( ( rsp->flags & FCP_RSP_RESPONSE_LEN_VALID ) ? " resp" : "" ),
		( ( rsp->flags & FCP_RSP_SENSE_LEN_VALID ) ? " sense" : "" ),
		( ( rsp->flags & FCP_RSP_RESIDUAL_OVERRUN ) ? " over" : "" ),
		( ( rsp->flags & FCP_RSP_RESIDUAL_UNDERRUN ) ? " under" : "" ));
	if ( fcp_rsp_response_data ( rsp ) ) {
		DBGC2 ( fcpdev, "FCP %p xchg %04x response data:\n",
			fcpdev, fcpcmd->xchg_id );
		DBGC2_HDA ( fcpdev, 0, fcp_rsp_response_data ( rsp ),
			    fcp_rsp_response_data_len ( rsp ) );
	}
	if ( fcp_rsp_sense_data ( rsp ) ) {
		DBGC2 ( fcpdev, "FCP %p xchg %04x sense data:\n",
			fcpdev, fcpcmd->xchg_id );
		DBGC2_HDA ( fcpdev, 0, fcp_rsp_sense_data ( rsp ),
			    fcp_rsp_sense_data_len ( rsp ) );
	}

	/* Check for locally-detected command underrun */
	if ( ( rsp->status == 0 ) &&
	     ( fcpcmd->offset != ( command->data_in_len +
				   command->data_out_len ) ) ) {
		DBGC ( fcpdev, "FCP %p xchg %04x data underrun (expected %zd, "
		       "got %zd)\n", fcpdev, fcpcmd->xchg_id,
		       ( command->data_in_len + command->data_out_len ),
		       fcpcmd->offset );
		rc = -ERANGE_DATA_UNDERRUN;
		goto done;
	}

	/* Build SCSI response */
	memset ( &response, 0, sizeof ( response ) );
	response.status = rsp->status;
	if ( rsp->flags & ( FCP_RSP_RESIDUAL_OVERRUN |
			    FCP_RSP_RESIDUAL_UNDERRUN ) ) {
		response.overrun = ntohl ( rsp->residual );
		if ( rsp->flags & FCP_RSP_RESIDUAL_UNDERRUN )
			response.overrun = -response.overrun;
	}
	scsi_parse_sense ( fcp_rsp_sense_data ( rsp ),
			   fcp_rsp_sense_data_len ( rsp ), &response.sense );

	/* Free buffer before sending response, to minimise
	 * out-of-memory errors.
	 */
	free_iob ( iob_disown ( iobuf ) );

	/* Send SCSI response */
	scsi_response ( &fcpcmd->scsi, &response );

	/* Terminate command */
	fcpcmd_close ( fcpcmd, 0 );

	rc = 0;
 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Handle unknown FCP IU
 *
 * @v fcpcmd		FCP command
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fcpcmd_recv_unknown ( struct fcp_command *fcpcmd,
				 struct io_buffer *iobuf,
				 struct xfer_metadata *meta __unused ) {
	struct fcp_device *fcpdev = fcpcmd->fcpdev;

	DBGC ( fcpdev, "FCP %p xchg %04x received unknown IU:\n",
	       fcpdev, fcpcmd->xchg_id );
	DBGC_HDA ( fcpdev, 0, iobuf->data, iob_len ( iobuf ) );
	free_iob ( iobuf );
	return -EPROTO;
}

/**
 * Transmit FCP frame
 *
 * @v fcpcmd		FCP command
 */
static void fcpcmd_step ( struct fcp_command *fcpcmd ) {
	int rc;

	/* Send the current IU */
	if ( ( rc = fcpcmd->send ( fcpcmd ) ) != 0 ) {
		/* Treat failure as a fatal error */
		fcpcmd_close ( fcpcmd, rc );
	}
}

/**
 * Receive FCP frame
 *
 * @v fcpcmd		FCP command
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fcpcmd_deliver ( struct fcp_command *fcpcmd,
			    struct io_buffer *iobuf,
			    struct xfer_metadata *meta ) {
	int ( * fcpcmd_recv ) ( struct fcp_command *fcpcmd,
				struct io_buffer *iobuf,
				struct xfer_metadata *meta );
	int rc;

	/* Determine handler */
	switch ( meta->flags & ( XFER_FL_CMD_STAT | XFER_FL_RESPONSE ) ) {
	case ( XFER_FL_RESPONSE ) :
		fcpcmd_recv = fcpcmd_recv_rddata;
		break;
	case ( XFER_FL_CMD_STAT ) :
		fcpcmd_recv = fcpcmd_recv_xfer_rdy;
		break;
	case ( XFER_FL_CMD_STAT | XFER_FL_RESPONSE ) :
		fcpcmd_recv = fcpcmd_recv_rsp;
		break;
	default:
		fcpcmd_recv = fcpcmd_recv_unknown;
		break;
	}

	/* Handle IU */
	if ( ( rc = fcpcmd_recv ( fcpcmd, iob_disown ( iobuf ), meta ) ) != 0 ){
		/* Treat any error as fatal to the command */
		fcpcmd_close ( fcpcmd, rc );
	}

	return rc;
}

/** FCP command SCSI interface operations */
static struct interface_operation fcpcmd_scsi_op[] = {
	INTF_OP ( intf_close, struct fcp_command *, fcpcmd_close ),
};

/** FCP command SCSI interface descriptor */
static struct interface_descriptor fcpcmd_scsi_desc =
	INTF_DESC_PASSTHRU ( struct fcp_command, scsi, fcpcmd_scsi_op, xchg );

/** FCP command Fibre Channel exchange interface operations */
static struct interface_operation fcpcmd_xchg_op[] = {
	INTF_OP ( xfer_deliver, struct fcp_command *, fcpcmd_deliver ),
	INTF_OP ( intf_close, struct fcp_command *, fcpcmd_close_err ),
};

/** FCP command Fibre Channel exchange interface descriptor */
static struct interface_descriptor fcpcmd_xchg_desc =
	INTF_DESC_PASSTHRU ( struct fcp_command, xchg, fcpcmd_xchg_op, scsi );

/** FCP command process descriptor */
static struct process_descriptor fcpcmd_process_desc =
	PROC_DESC ( struct fcp_command, process, fcpcmd_step );

/**
 * Issue FCP SCSI command
 *
 * @v fcpdev		FCP device
 * @v parent		Parent interface
 * @v command		SCSI command
 * @ret tag		Command tag, or negative error
 */
static int fcpdev_scsi_command ( struct fcp_device *fcpdev,
				 struct interface *parent,
				 struct scsi_cmd *command ) {
	struct fcp_prli_service_parameters *param = fcpdev->user.ulp->param;
	struct fcp_command *fcpcmd;
	int xchg_id;
	int rc;

	/* Check link */
	if ( ( rc = fcpdev->user.ulp->link.rc ) != 0 ) {
		DBGC ( fcpdev, "FCP %p could not issue command while link is "
		       "down: %s\n", fcpdev, strerror ( rc ) );
		goto err_link;
	}

	/* Check target capability */
	assert ( param != NULL );
	assert ( fcpdev->user.ulp->param_len >= sizeof ( *param ) );
	if ( ! ( param->flags & htonl ( FCP_PRLI_TARGET ) ) ) {
		DBGC ( fcpdev, "FCP %p could not issue command: not a target\n",
		       fcpdev );
		rc = -ENOTTY;
		goto err_target;
	}

	/* Allocate and initialise structure */
	fcpcmd = zalloc ( sizeof ( *fcpcmd ) );
	if ( ! fcpcmd ) {
		rc = -ENOMEM;
		goto err_zalloc;
	}
	ref_init ( &fcpcmd->refcnt, fcpcmd_free );
	intf_init ( &fcpcmd->scsi, &fcpcmd_scsi_desc, &fcpcmd->refcnt );
	intf_init ( &fcpcmd->xchg, &fcpcmd_xchg_desc, &fcpcmd->refcnt );
	process_init_stopped ( &fcpcmd->process, &fcpcmd_process_desc,
			       &fcpcmd->refcnt );
	fcpcmd->fcpdev = fcpdev_get ( fcpdev );
	list_add ( &fcpcmd->list, &fcpdev->fcpcmds );
	memcpy ( &fcpcmd->command, command, sizeof ( fcpcmd->command ) );

	/* Create new exchange */
	if ( ( xchg_id = fc_xchg_originate ( &fcpcmd->xchg,
					     fcpdev->user.ulp->peer->port,
					     &fcpdev->user.ulp->peer->port_id,
					     FC_TYPE_FCP ) ) < 0 ) {
		rc = xchg_id;
		DBGC ( fcpdev, "FCP %p could not create exchange: %s\n",
		       fcpdev, strerror ( rc ) );
		goto err_xchg_originate;
	}
	fcpcmd->xchg_id = xchg_id;

	/* Start sending command IU */
	fcpcmd_start_send ( fcpcmd, fcpcmd_send_cmnd );

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( &fcpcmd->scsi, parent );
	ref_put ( &fcpcmd->refcnt );
	return ( FCP_TAG_MAGIC | fcpcmd->xchg_id );

 err_xchg_originate:
	fcpcmd_close ( fcpcmd, rc );
	ref_put ( &fcpcmd->refcnt );
 err_zalloc:
 err_target:
 err_link:
	return rc;
}

/**
 * Close FCP device
 *
 * @v fcpdev		FCP device
 * @v rc		Reason for close
 */
static void fcpdev_close ( struct fcp_device *fcpdev, int rc ) {
	struct fcp_command *fcpcmd;
	struct fcp_command *tmp;

	DBGC ( fcpdev, "FCP %p closed: %s\n", fcpdev, strerror ( rc ) );

	/* Shut down interfaces */
	intf_shutdown ( &fcpdev->scsi, rc );

	/* Shut down any active commands */
	list_for_each_entry_safe ( fcpcmd, tmp, &fcpdev->fcpcmds, list ) {
		fcpcmd_get ( fcpcmd );
		fcpcmd_close ( fcpcmd, rc );
		fcpcmd_put ( fcpcmd );
	}

	/* Drop reference to ULP */
	fc_ulp_detach ( &fcpdev->user );
}

/**
 * Check FCP device flow-control window
 *
 * @v fcpdev		FCP device
 * @ret len		Length of window
 */
static size_t fcpdev_window ( struct fcp_device *fcpdev ) {
	return ( fc_link_ok ( &fcpdev->user.ulp->link ) ?
		 ~( ( size_t ) 0 ) : 0 );
}

/**
 * Describe FCP device in an ACPI table
 *
 * @v fcpdev		FCP device
 * @v acpi		ACPI table
 * @v len		Length of ACPI table
 * @ret rc		Return status code
 */
static int fcpdev_acpi_describe ( struct fcp_device *fcpdev,
				  struct acpi_description_header *acpi,
				  size_t len ) {

	DBGC ( fcpdev, "FCP %p cannot yet describe device in an ACPI table\n",
	       fcpdev );
	( void ) acpi;
	( void ) len;
	return 0;
}

/**
 * Describe FCP device using EDD
 *
 * @v fcpdev		FCP device
 * @v type		EDD interface type
 * @v path		EDD device path
 * @ret rc		Return status code
 */
static int fcpdev_edd_describe ( struct fcp_device *fcpdev,
				 struct edd_interface_type *type,
				 union edd_device_path *path ) {
	union {
		struct fc_name fc;
		uint64_t u64;
	} wwn;
	union {
		struct scsi_lun scsi;
		uint64_t u64;
	} lun;

	type->type = cpu_to_le64 ( EDD_INTF_TYPE_FIBRE );
	memcpy ( &wwn.fc, &fcpdev->wwn, sizeof ( wwn.fc ) );
	path->fibre.wwn = be64_to_cpu ( wwn.u64 );
	memcpy ( &lun.scsi, &fcpdev->lun, sizeof ( lun.scsi ) );
	path->fibre.lun = be64_to_cpu ( lun.u64 );
	return 0;
}

/**
 * Identify device underlying FCP device
 *
 * @v fcpdev		FCP device
 * @ret device		Underlying device
 */
static struct device * fcpdev_identify_device ( struct fcp_device *fcpdev ) {

	/* We know the underlying device only if the link is up;
	 * otherwise we don't have a port to examine.
	 */
	if ( ! fc_link_ok ( &fcpdev->user.ulp->link ) ) {
		DBGC ( fcpdev, "FCP %p doesn't know underlying device "
		       "until link is up\n", fcpdev );
		return NULL;
	}

	/* Hand off to port's transport interface */
	assert ( fcpdev->user.ulp->peer->port != NULL );
	return identify_device ( &fcpdev->user.ulp->peer->port->transport );
}

/** FCP device SCSI interface operations */
static struct interface_operation fcpdev_scsi_op[] = {
	INTF_OP ( scsi_command, struct fcp_device *, fcpdev_scsi_command ),
	INTF_OP ( xfer_window, struct fcp_device *, fcpdev_window ),
	INTF_OP ( intf_close, struct fcp_device *, fcpdev_close ),
	INTF_OP ( acpi_describe, struct fcp_device *, fcpdev_acpi_describe ),
	INTF_OP ( edd_describe, struct fcp_device *, fcpdev_edd_describe ),
	INTF_OP ( identify_device, struct fcp_device *,
		  fcpdev_identify_device ),
};

/** FCP device SCSI interface descriptor */
static struct interface_descriptor fcpdev_scsi_desc =
	INTF_DESC ( struct fcp_device, scsi, fcpdev_scsi_op );

/**
 * Examine FCP ULP link state
 *
 * @v user		Fibre Channel upper-layer protocol user
 */
static void fcpdev_examine ( struct fc_ulp_user *user ) {
	struct fcp_device *fcpdev =
		container_of ( user, struct fcp_device, user );

	if ( fc_link_ok ( &fcpdev->user.ulp->link ) ) {
		DBGC ( fcpdev, "FCP %p link is up\n", fcpdev );
	} else {
		DBGC ( fcpdev, "FCP %p link is down: %s\n",
		       fcpdev, strerror ( fcpdev->user.ulp->link.rc ) );
	}

	/* Notify SCSI layer of window change */
	xfer_window_changed ( &fcpdev->scsi );
}

/**
 * Open FCP device
 *
 * @v parent		Parent interface
 * @v wwn		Fibre Channel WWN
 * @v lun		SCSI LUN
 * @ret rc		Return status code
 */
static int fcpdev_open ( struct interface *parent, struct fc_name *wwn,
			 struct scsi_lun *lun ) {
	struct fc_ulp *ulp;
	struct fcp_device *fcpdev;
	int rc;

	/* Get Fibre Channel ULP interface */
	ulp = fc_ulp_get_wwn_type ( wwn, FC_TYPE_FCP );
	if ( ! ulp ) {
		rc = -ENOMEM;
		goto err_ulp_get;
	}

	/* Allocate and initialise structure */
	fcpdev = zalloc ( sizeof ( *fcpdev ) );
	if ( ! fcpdev ) {
		rc = -ENOMEM;
		goto err_zalloc;
	}
	ref_init ( &fcpdev->refcnt, NULL );
	intf_init ( &fcpdev->scsi, &fcpdev_scsi_desc, &fcpdev->refcnt );
	INIT_LIST_HEAD ( &fcpdev->fcpcmds );
	fc_ulp_user_init ( &fcpdev->user, fcpdev_examine, &fcpdev->refcnt );

	DBGC ( fcpdev, "FCP %p opened for %s\n", fcpdev, fc_ntoa ( wwn ) );

	/* Attach to Fibre Channel ULP */
	fc_ulp_attach ( ulp, &fcpdev->user );

	/* Preserve parameters required for boot firmware table */
	memcpy ( &fcpdev->wwn, wwn, sizeof ( fcpdev->wwn ) );
	memcpy ( &fcpdev->lun, lun, sizeof ( fcpdev->lun ) );

	/* Attach SCSI device to parent interface */
	if ( ( rc = scsi_open ( parent, &fcpdev->scsi, lun ) ) != 0 ) {
		DBGC ( fcpdev, "FCP %p could not create SCSI device: %s\n",
		       fcpdev, strerror ( rc ) );
		goto err_scsi_open;
	}

	/* Drop temporary reference to ULP */
	fc_ulp_put ( ulp );

	/* Mortalise self and return */
	ref_put ( &fcpdev->refcnt );
	return 0;

 err_scsi_open:
	fcpdev_close ( fcpdev, rc );
	ref_put ( &fcpdev->refcnt );
 err_zalloc:
	fc_ulp_put ( ulp );
 err_ulp_get:
	return rc;
}

/******************************************************************************
 *
 * FCP URIs
 *
 ******************************************************************************
 */

/**
 * Parse FCP URI
 *
 * @v uri		URI
 * @ret wwn		Fibre Channel WWN
 * @ret lun		SCSI LUN
 * @ret rc		Return status code
 *
 * An FCP URI has the form "fcp:<wwn>:<lun>" or "fcp://<wwn>/<lun>"
 */
static int fcp_parse_uri ( struct uri *uri, struct fc_name *wwn,
			   struct scsi_lun *lun ) {
	char wwn_buf[ FC_NAME_STRLEN + 1 /* NUL */ ];
	const char *wwn_text;
	const char *lun_text;
	int rc;

	/* Extract WWN and LUN texts from URI */
	if ( uri->opaque ) {
		/* "fcp:<wwn>:<lun>" */
		if ( snprintf ( wwn_buf, sizeof ( wwn_buf ), "%s",
				uri->opaque ) < ( FC_NAME_STRLEN + 1 /* : */ ) )
			return -EINVAL;
		if ( uri->opaque[FC_NAME_STRLEN] != ':' )
			return -EINVAL;
		wwn_text = wwn_buf;
		lun_text = &uri->opaque[FC_NAME_STRLEN + 1];
	} else {
		/* If host exists, path must also exist */
		if ( ! ( uri->host && uri->path ) )
			return -EINVAL;
		if ( uri->path[0] != '/' )
			return -EINVAL;
		wwn_text = uri->host;
		lun_text = ( uri->path + 1 );
	}

	/* Parse WWN */
	if ( ( rc = fc_aton ( wwn_text, wwn ) ) != 0 )
		return rc;

	/* Parse LUN */
	if ( ( rc = scsi_parse_lun ( lun_text, lun ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Open FCP URI
 *
 * @v parent		Parent interface
 * @v uri		URI
 * @ret rc		Return status code
 */
static int fcp_open ( struct interface *parent, struct uri *uri ) {
	struct fc_name wwn;
	struct scsi_lun lun;
	int rc;

	/* Parse URI */
	if ( ( rc = fcp_parse_uri ( uri, &wwn, &lun ) ) != 0 )
		return rc;

	/* Open FCP device */
	if ( ( rc = fcpdev_open ( parent, &wwn, &lun ) ) != 0 )
		return rc;

	return 0;
}

/** FCP URI opener */
struct uri_opener fcp_uri_opener __uri_opener = {
	.scheme = "fcp",
	.open = fcp_open,
};
