#ifndef _IPXE_FCP_H
#define _IPXE_FCP_H

/**
 * @file
 *
 * Fibre Channel Protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/fc.h>
#include <ipxe/fcels.h>
#include <ipxe/scsi.h>

/** An FCP command IU */
struct fcp_cmnd {
	/** SCSI LUN */
	struct scsi_lun lun;
	/** Command reference number */
	uint8_t ref;
	/** Priority and task attributes */
	uint8_t priority;
	/** Task management flags */
	uint8_t flags;
	/** Direction */
	uint8_t dirn;
	/** SCSI CDB */
	union scsi_cdb cdb;
	/** Data length */
	uint32_t len;
} __attribute__ (( packed ));

/** Command includes data-out */
#define FCP_CMND_WRDATA 0x01

/** Command includes data-in */
#define FCP_CMND_RDDATA 0x02

/** FCP tag magic marker */
#define FCP_TAG_MAGIC 0x18ae0000

/** An FCP transfer ready IU */
struct fcp_xfer_rdy {
	/** Relative offset of data */
	uint32_t offset;
	/** Burst length */
	uint32_t len;
	/** Reserved */
	uint32_t reserved;
} __attribute__ (( packed ));

/** An FCP response IU */
struct fcp_rsp {
	/** Reserved */
	uint8_t reserved[8];
	/** Retry delay timer */
	uint16_t retry_delay;
	/** Flags */
	uint8_t flags;
	/** SCSI status code */
	uint8_t status;
	/** Residual data count */
	uint32_t residual;
	/** Sense data length */
	uint32_t sense_len;
	/** Response data length */
	uint32_t response_len;
} __attribute__ (( packed ));

/** Response length field is valid */
#define FCP_RSP_RESPONSE_LEN_VALID 0x01

/** Sense length field is valid */
#define FCP_RSP_SENSE_LEN_VALID 0x02

/** Residual represents overrun */
#define FCP_RSP_RESIDUAL_OVERRUN 0x04

/** Residual represents underrun */
#define FCP_RSP_RESIDUAL_UNDERRUN 0x08

/**
 * Get response data portion of FCP response
 *
 * @v rsp			FCP response
 * @ret response_data		Response data, or NULL if not present
 */
static inline void * fcp_rsp_response_data ( struct fcp_rsp *rsp ) {
	return ( ( rsp->flags & FCP_RSP_RESPONSE_LEN_VALID ) ?
		 ( ( ( void * ) rsp ) + sizeof ( *rsp ) ) : NULL );
}

/**
 * Get length of response data portion of FCP response
 *
 * @v rsp			FCP response
 * @ret response_data_len	Response data length
 */
static inline size_t fcp_rsp_response_data_len ( struct fcp_rsp *rsp ) {
	return ( ( rsp->flags & FCP_RSP_RESPONSE_LEN_VALID ) ?
		 ntohl ( rsp->response_len ) : 0 );
}

/**
 * Get sense data portion of FCP response
 *
 * @v rsp			FCP response
 * @ret sense_data		Sense data, or NULL if not present
 */
static inline void * fcp_rsp_sense_data ( struct fcp_rsp *rsp ) {
	return ( ( rsp->flags & FCP_RSP_SENSE_LEN_VALID ) ?
		 ( ( ( void * ) rsp ) + sizeof ( *rsp ) +
		   fcp_rsp_response_data_len ( rsp ) ) : NULL );
}

/**
 * Get length of sense data portion of FCP response
 *
 * @v rsp			FCP response
 * @ret sense_data_len		Sense data length
 */
static inline size_t fcp_rsp_sense_data_len ( struct fcp_rsp *rsp ) {
	return ( ( rsp->flags & FCP_RSP_SENSE_LEN_VALID ) ?
		 ntohl ( rsp->sense_len ) : 0 );
}

/** An FCP PRLI service parameter page */
struct fcp_prli_service_parameters {
	/** Flags */
	uint32_t flags;
} __attribute__ (( packed ));

/** Write FCP_XFER_RDY disabled */
#define FCP_PRLI_NO_WRITE_RDY 0x0001

/** Read FCP_XFER_RDY disabled */
#define FCP_PRLI_NO_READ_RDY 0x0002

/** Has target functionality */
#define FCP_PRLI_TARGET 0x0010

/** Has initiator functionality */
#define FCP_PRLI_INITIATOR 0x0020

/** Data overlay allowed */
#define FCP_PRLI_OVERLAY 0x0040

/** Confirm completion allowed */
#define FCP_PRLI_CONF 0x0080

/** Retransmission supported */
#define FCP_PRLI_RETRY 0x0100

/** Task retry identification */
#define FCP_PRLI_TASK_RETRY 0x0200

/** REC ELS supported */
#define FCP_PRLI_REC 0x0400

/** Enhanced discovery supported */
#define FCP_PRLI_ENH_DISC 0x0800

#endif /* _IPXE_FCP_H */
