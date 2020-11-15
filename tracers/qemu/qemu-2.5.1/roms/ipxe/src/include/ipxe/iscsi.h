#ifndef _IPXE_ISCSI_H
#define _IPXE_ISCSI_H

/** @file
 *
 * iSCSI protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/socket.h>
#include <ipxe/scsi.h>
#include <ipxe/chap.h>
#include <ipxe/refcnt.h>
#include <ipxe/xfer.h>
#include <ipxe/process.h>

/** Default iSCSI port */
#define ISCSI_PORT 3260

/**
 * iSCSI segment lengths
 *
 * iSCSI uses an icky structure with one one-byte field (a dword
 * count) and one three-byte field (a byte count).  This structure,
 * and the accompanying macros, relieve some of the pain.
 */
union iscsi_segment_lengths {
	struct {
		/** The AHS length (measured in dwords) */
		uint8_t ahs_len;
		/** The data length (measured in bytes), in network
		 * byte order
		 */
		uint8_t data_len[3];
	} bytes;
	/** The data length (measured in bytes), in network byte
	 * order, with ahs_len as the first byte.
	 */
	uint32_t ahs_and_data_len;
};

/** The length of the additional header segment, in dwords */
#define ISCSI_AHS_LEN( segment_lengths ) \
	( (segment_lengths).bytes.ahs_len )

/** The length of the data segment, in bytes, excluding any padding */
#define ISCSI_DATA_LEN( segment_lengths ) \
	( ntohl ( (segment_lengths).ahs_and_data_len ) & 0xffffff )

/** The padding of the data segment, in bytes */
#define ISCSI_DATA_PAD_LEN( segment_lengths ) \
	( ( 0 - (segment_lengths).bytes.data_len[2] ) & 0x03 )

/** Set additional header and data segment lengths */
#define ISCSI_SET_LENGTHS( segment_lengths, ahs_len, data_len ) do {	\
	(segment_lengths).ahs_and_data_len =				\
		htonl ( data_len | ( ahs_len << 24 ) );			\
	} while ( 0 )

/**
 * iSCSI basic header segment common fields
 *
 */
struct iscsi_bhs_common {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Fields specific to the PDU type */
	uint8_t other_a[2];
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Fields specific to the PDU type */
	uint8_t other_b[8];
	/** Initiator Task Tag */
	uint32_t itt;
	/** Fields specific to the PDU type */
	uint8_t other_c[28];
};

/** Opcode mask */
#define ISCSI_OPCODE_MASK 0x3f

/** Immediate delivery */
#define ISCSI_FLAG_IMMEDIATE 0x40

/** Final PDU of a sequence */
#define ISCSI_FLAG_FINAL 0x80

/** iSCSI tag magic marker */
#define ISCSI_TAG_MAGIC 0x18ae0000

/** iSCSI reserved tag value */
#define ISCSI_TAG_RESERVED 0xffffffff

/**
 * iSCSI basic header segment common request fields
 *
 */
struct iscsi_bhs_common_response {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Fields specific to the PDU type */
	uint8_t other_a[2];
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Fields specific to the PDU type */
	uint8_t other_b[8];
	/** Initiator Task Tag */
	uint32_t itt;
	/** Fields specific to the PDU type */
	uint8_t other_c[4];
	/** Status sequence number */
	uint32_t statsn;
	/** Expected command sequence number */
	uint32_t expcmdsn;
	/** Fields specific to the PDU type */
	uint8_t other_d[16];
};

/**
 * iSCSI login request basic header segment
 *
 */
struct iscsi_bhs_login_request {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Maximum supported version number */
	uint8_t version_max;
	/** Minimum supported version number */
	uint8_t version_min;
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Initiator session ID (IANA format) enterprise number and flags */
	uint32_t isid_iana_en;
	/** Initiator session ID (IANA format) qualifier */
	uint16_t isid_iana_qual;
	/** Target session identifying handle */
	uint16_t tsih;
	/** Initiator Task Tag */
	uint32_t itt;
	/** Connection ID */
	uint16_t cid;
	/** Reserved */
	uint16_t reserved_a;
	/** Command sequence number */
	uint32_t cmdsn;
	/** Expected status sequence number */
	uint32_t expstatsn;
	/** Reserved */
	uint8_t reserved_b[16];
};

/** Login request opcode */
#define ISCSI_OPCODE_LOGIN_REQUEST 0x03

/** Willingness to transition to next stage */
#define ISCSI_LOGIN_FLAG_TRANSITION 0x80

/** Key=value pairs continued in subsequent request */
#define ISCSI_LOGIN_FLAG_CONTINUE 0x40

/* Current stage values and mask */
#define ISCSI_LOGIN_CSG_MASK 0x0c
#define ISCSI_LOGIN_CSG_SECURITY_NEGOTIATION 0x00
#define ISCSI_LOGIN_CSG_OPERATIONAL_NEGOTIATION 0x04
#define ISCSI_LOGIN_CSG_FULL_FEATURE_PHASE 0x0c

/* Next stage values and mask */
#define ISCSI_LOGIN_NSG_MASK 0x03
#define ISCSI_LOGIN_NSG_SECURITY_NEGOTIATION 0x00
#define ISCSI_LOGIN_NSG_OPERATIONAL_NEGOTIATION 0x01
#define ISCSI_LOGIN_NSG_FULL_FEATURE_PHASE 0x03

/** ISID IANA format marker */
#define ISCSI_ISID_IANA 0x40000000

/** Fen Systems Ltd. IANA enterprise number
 *
 * Permission is hereby granted to use Fen Systems Ltd.'s IANA
 * enterprise number with this iSCSI implementation.
 */
#define IANA_EN_FEN_SYSTEMS 10019

/**
 * iSCSI login response basic header segment
 *
 */
struct iscsi_bhs_login_response {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Maximum supported version number */
	uint8_t version_max;
	/** Minimum supported version number */
	uint8_t version_min;
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Initiator session ID (IANA format) enterprise number and flags */
	uint32_t isid_iana_en;
	/** Initiator session ID (IANA format) qualifier */
	uint16_t isid_iana_qual;
	/** Target session identifying handle */
	uint16_t tsih;
	/** Initiator Task Tag */
	uint32_t itt;
	/** Reserved */
	uint32_t reserved_a;
	/** Status sequence number */
	uint32_t statsn;
	/** Expected command sequence number */
	uint32_t expcmdsn;
	/** Maximum command sequence number */
	uint32_t maxcmdsn;
	/** Status class */
	uint8_t status_class;
	/** Status detail */
	uint8_t status_detail;
	/** Reserved */
	uint8_t reserved_b[10];
};

/** Login response opcode */
#define ISCSI_OPCODE_LOGIN_RESPONSE 0x23

/* Login response status codes */
#define ISCSI_STATUS_SUCCESS			0x00
#define ISCSI_STATUS_REDIRECT			0x01
#define ISCSI_STATUS_INITIATOR_ERROR		0x02
#define ISCSI_STATUS_INITIATOR_ERROR_AUTHENTICATION	0x01
#define ISCSI_STATUS_INITIATOR_ERROR_AUTHORISATION	0x02
#define ISCSI_STATUS_INITIATOR_ERROR_NOT_FOUND		0x03
#define ISCSI_STATUS_INITIATOR_ERROR_REMOVED		0x04
#define ISCSI_STATUS_TARGET_ERROR		0x03
#define ISCSI_STATUS_TARGET_ERROR_UNAVAILABLE		0x01
#define ISCSI_STATUS_TARGET_ERROR_NO_RESOURCES		0x02

/**
 * iSCSI SCSI command basic header segment
 *
 */
struct iscsi_bhs_scsi_command {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Reserved */
	uint16_t reserved_a;
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** SCSI Logical Unit Number */
	struct scsi_lun lun;
	/** Initiator Task Tag */
	uint32_t itt;
	/** Expected data transfer length */
	uint32_t exp_len;
	/** Command sequence number */
	uint32_t cmdsn;
	/** Expected status sequence number */
	uint32_t expstatsn;
	/** SCSI Command Descriptor Block (CDB) */
	union scsi_cdb cdb;
};

/** SCSI command opcode */
#define ISCSI_OPCODE_SCSI_COMMAND 0x01

/** Command will read data */
#define ISCSI_COMMAND_FLAG_READ 0x40

/** Command will write data */
#define ISCSI_COMMAND_FLAG_WRITE 0x20

/* Task attributes */
#define ISCSI_COMMAND_ATTR_UNTAGGED 0x00
#define ISCSI_COMMAND_ATTR_SIMPLE 0x01
#define ISCSI_COMMAND_ATTR_ORDERED 0x02
#define ISCSI_COMMAND_ATTR_HEAD_OF_QUEUE 0x03
#define ISCSI_COMMAND_ATTR_ACA 0x04

/**
 * iSCSI SCSI response basic header segment
 *
 */
struct iscsi_bhs_scsi_response {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Response code */
	uint8_t response;
	/** SCSI status code */
	uint8_t status;
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Reserved */
	uint8_t reserved_a[8];
	/** Initiator Task Tag */
	uint32_t itt;
	/** SNACK tag */
	uint32_t snack;
	/** Status sequence number */
	uint32_t statsn;
	/** Expected command sequence number */
	uint32_t expcmdsn;
	/** Maximum command sequence number */
	uint32_t maxcmdsn;
	/** Expected data sequence number */
	uint32_t expdatasn;
	/** Bidirectional read residual count */
	uint32_t bidi_residual_count;
	/** Residual count */
	uint32_t residual_count;
};

/** SCSI response opcode */
#define ISCSI_OPCODE_SCSI_RESPONSE 0x21

/** SCSI command completed at target */
#define ISCSI_RESPONSE_COMMAND_COMPLETE 0x00

/** SCSI target failure */
#define ISCSI_RESPONSE_TARGET_FAILURE 0x01

/** Data overflow occurred */
#define ISCSI_RESPONSE_FLAG_OVERFLOW 0x20

/** Data underflow occurred */
#define ISCSI_RESPONSE_FLAG_UNDERFLOW 0x40

/**
 * iSCSI data-in basic header segment
 *
 */
struct iscsi_bhs_data_in {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Reserved */
	uint8_t reserved_a;
	/** SCSI status code */
	uint8_t status;
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Logical Unit Number */
	struct scsi_lun lun;
	/** Initiator Task Tag */
	uint32_t itt;
	/** Target Transfer Tag */
	uint32_t ttt;
	/** Status sequence number */
	uint32_t statsn;
	/** Expected command sequence number */
	uint32_t expcmdsn;
	/** Maximum command sequence number */
	uint32_t maxcmdsn;
	/** Data sequence number */
	uint32_t datasn;
	/** Buffer offset */
	uint32_t offset;
	/** Residual count */
	uint32_t residual_count;
};

/** Data-in opcode */
#define ISCSI_OPCODE_DATA_IN 0x25

/** Data requires acknowledgement */
#define ISCSI_DATA_FLAG_ACKNOWLEDGE 0x40

/** Data overflow occurred */
#define ISCSI_DATA_FLAG_OVERFLOW 0x04

/** Data underflow occurred */
#define ISCSI_DATA_FLAG_UNDERFLOW 0x02

/** SCSI status code and overflow/underflow flags are valid */
#define ISCSI_DATA_FLAG_STATUS 0x01

/**
 * iSCSI data-out basic header segment
 *
 */
struct iscsi_bhs_data_out {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Reserved */
	uint16_t reserved_a;
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Logical Unit Number */
	struct scsi_lun lun;
	/** Initiator Task Tag */
	uint32_t itt;
	/** Target Transfer Tag */
	uint32_t ttt;
	/** Reserved */
	uint32_t reserved_b;
	/** Expected status sequence number */
	uint32_t expstatsn;
	/** Reserved */
	uint32_t reserved_c;
	/** Data sequence number */
	uint32_t datasn;
	/** Buffer offset */
	uint32_t offset;
	/** Reserved */
	uint32_t reserved_d;
};

/** Data-out opcode */
#define ISCSI_OPCODE_DATA_OUT 0x05

/**
 * iSCSI request to transfer basic header segment
 *
 */
struct iscsi_bhs_r2t {
	/** Opcode */
	uint8_t opcode;
	/** Flags */
	uint8_t flags;
	/** Reserved */
	uint16_t reserved_a;
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Logical Unit Number */
	struct scsi_lun lun;
	/** Initiator Task Tag */
	uint32_t itt;
	/** Target Transfer Tag */
	uint32_t ttt;
	/** Status sequence number */
	uint32_t statsn;
	/** Expected command sequence number */
	uint32_t expcmdsn;
	/** Maximum command sequence number */
	uint32_t maxcmdsn;
	/** R2T sequence number */
	uint32_t r2tsn;
	/** Buffer offset */
	uint32_t offset;
	/** Desired data transfer length */
	uint32_t len;
};

/** R2T opcode */
#define ISCSI_OPCODE_R2T 0x31

/**
 * iSCSI NOP-In basic header segment
 *
 */
struct iscsi_nop_in {
	/** Opcode */
	uint8_t opcode;
	/** Reserved */
	uint8_t reserved_a[3];
	/** Segment lengths */
	union iscsi_segment_lengths lengths;
	/** Logical Unit Number */
	struct scsi_lun lun;
	/** Initiator Task Tag */
	uint32_t itt;
	/** Target Transfer Tag */
	uint32_t ttt;
	/** Status sequence number */
	uint32_t statsn;
	/** Expected command sequence number */
	uint32_t expcmdsn;
	/** Maximum command sequence number */
	uint32_t maxcmdsn;
	/** Reserved */
	uint8_t reserved_b[12];
};

/** NOP-In opcode */
#define ISCSI_OPCODE_NOP_IN 0x20

/**
 * An iSCSI basic header segment
 */
union iscsi_bhs {
	struct iscsi_bhs_common common;
	struct iscsi_bhs_common_response common_response;
	struct iscsi_bhs_login_request login_request;
	struct iscsi_bhs_login_response login_response;
	struct iscsi_bhs_scsi_command scsi_command;
	struct iscsi_bhs_scsi_response scsi_response;
	struct iscsi_bhs_data_in data_in;
	struct iscsi_bhs_data_out data_out;
	struct iscsi_bhs_r2t r2t;
	struct iscsi_nop_in nop_in;
	unsigned char bytes[ sizeof ( struct iscsi_bhs_common ) ];
};

/** State of an iSCSI TX engine */
enum iscsi_tx_state {
	/** Nothing to send */
	ISCSI_TX_IDLE = 0,
	/** Sending the basic header segment */
	ISCSI_TX_BHS,
	/** Sending the additional header segment */
	ISCSI_TX_AHS,
	/** Sending the data segment */
	ISCSI_TX_DATA,
};

/** State of an iSCSI RX engine */
enum iscsi_rx_state {
	/** Receiving the basic header segment */
	ISCSI_RX_BHS = 0,
	/** Receiving the additional header segment */
	ISCSI_RX_AHS,
	/** Receiving the data segment */
	ISCSI_RX_DATA,
	/** Receiving the data segment padding */
	ISCSI_RX_DATA_PADDING,
};

/** An iSCSI session */
struct iscsi_session {
	/** Reference counter */
	struct refcnt refcnt;

	/** SCSI command-issuing interface */
	struct interface control;
	/** SCSI command interface */
	struct interface data;
	/** Transport-layer socket */
	struct interface socket;

	/** Initiator IQN */
	char *initiator_iqn;
	/** Target address */
	char *target_address;
	/** Target port */
	unsigned int target_port;
	/** Target IQN */
	char *target_iqn;

	/** Session status
	 *
	 * This is the bitwise-OR of zero or more ISCSI_STATUS_XXX
	 * constants.
	 */
	int status;

	/** Initiator username (if any) */
	char *initiator_username;
	/** Initiator password (if any) */
	char *initiator_password;
	/** Target username (if any) */
	char *target_username;
	/** Target password (if any) */
	char *target_password;
	/** CHAP challenge (for target auth only)
	 *
	 * This is a block of random data; the first byte is used as
	 * the CHAP identifier (CHAP_I) and the remainder as the CHAP
	 * challenge (CHAP_C).
	 */
	unsigned char chap_challenge[17];
	/** CHAP response (used for both initiator and target auth) */
	struct chap_response chap;

	/** Initiator session ID (IANA format) qualifier
	 *
	 * This is part of the ISID.  It is generated randomly
	 * whenever a new connection is opened.
	 */
	uint16_t isid_iana_qual;
	/** Initiator task tag
	 *
	 * This is the tag of the current command.  It is incremented
	 * whenever a new command is started.
	 */
	uint32_t itt;
	/** Target transfer tag
	 *
	 * This is the tag attached to a sequence of data-out PDUs in
	 * response to an R2T.
	 */
	uint32_t ttt;
	/** Transfer offset
	 *
	 * This is the offset for an in-progress sequence of data-out
	 * PDUs in response to an R2T.
	 */
	uint32_t transfer_offset;
	/** Transfer length
	 *
	 * This is the length for an in-progress sequence of data-out
	 * PDUs in response to an R2T.
	 */
	uint32_t transfer_len;
	/** Command sequence number
	 *
	 * This is the sequence number of the current command, used to
	 * fill out the CmdSN field in iSCSI request PDUs.  It is
	 * updated with the value of the ExpCmdSN field whenever we
	 * receive an iSCSI response PDU containing such a field.
	 */
	uint32_t cmdsn;
	/** Status sequence number
	 *
	 * This is the most recent status sequence number present in
	 * the StatSN field of an iSCSI response PDU containing such a
	 * field.  Whenever we send an iSCSI request PDU, we fill out
	 * the ExpStatSN field with this value plus one.
	 */
	uint32_t statsn;
	
	/** Basic header segment for current TX PDU */
	union iscsi_bhs tx_bhs;
	/** State of the TX engine */
	enum iscsi_tx_state tx_state;
	/** TX process */
	struct process process;

	/** Basic header segment for current RX PDU */
	union iscsi_bhs rx_bhs;
	/** State of the RX engine */
	enum iscsi_rx_state rx_state;
	/** Byte offset within the current RX state */
	size_t rx_offset;
	/** Length of the current RX state */
	size_t rx_len;
	/** Buffer for received data (not always used) */
	void *rx_buffer;

	/** Current SCSI command, if any */
	struct scsi_cmd *command;

	/** Target socket address (for boot firmware table) */
	struct sockaddr target_sockaddr;
	/** SCSI LUN (for boot firmware table) */
	struct scsi_lun lun;
};

/** iSCSI session is currently in the security negotiation phase */
#define ISCSI_STATUS_SECURITY_NEGOTIATION_PHASE		\
	( ISCSI_LOGIN_CSG_SECURITY_NEGOTIATION |	\
	  ISCSI_LOGIN_NSG_OPERATIONAL_NEGOTIATION )

/** iSCSI session is currently in the operational parameter
 * negotiation phase
 */
#define ISCSI_STATUS_OPERATIONAL_NEGOTIATION_PHASE	\
	( ISCSI_LOGIN_CSG_OPERATIONAL_NEGOTIATION |	\
	  ISCSI_LOGIN_NSG_FULL_FEATURE_PHASE )

/** iSCSI session is currently in the full feature phase */
#define ISCSI_STATUS_FULL_FEATURE_PHASE	ISCSI_LOGIN_CSG_FULL_FEATURE_PHASE

/** Mask for all iSCSI session phases */
#define ISCSI_STATUS_PHASE_MASK ( ISCSI_LOGIN_CSG_MASK | ISCSI_LOGIN_NSG_MASK )

/** iSCSI session needs to send the initial security negotiation strings */
#define ISCSI_STATUS_STRINGS_SECURITY 0x0100

/** iSCSI session needs to send the CHAP_A string */
#define ISCSI_STATUS_STRINGS_CHAP_ALGORITHM 0x0200

/** iSCSI session needs to send the CHAP response */
#define ISCSI_STATUS_STRINGS_CHAP_RESPONSE 0x0400

/** iSCSI session needs to send the mutual CHAP challenge */
#define ISCSI_STATUS_STRINGS_CHAP_CHALLENGE 0x0800

/** iSCSI session needs to send the operational negotiation strings */
#define ISCSI_STATUS_STRINGS_OPERATIONAL 0x1000

/** Mask for all iSCSI "needs to send" flags */
#define ISCSI_STATUS_STRINGS_MASK 0xff00

/** Target has requested forward (initiator) authentication */
#define ISCSI_STATUS_AUTH_FORWARD_REQUIRED 0x00010000

/** Initiator requires target (reverse) authentication */
#define ISCSI_STATUS_AUTH_REVERSE_REQUIRED 0x00020000

/** Target authenticated itself correctly */
#define ISCSI_STATUS_AUTH_REVERSE_OK 0x00040000

/** Default initiator IQN prefix */
#define ISCSI_DEFAULT_IQN_PREFIX "iqn.2010-04.org.ipxe"

#endif /* _IPXE_ISCSI_H */
