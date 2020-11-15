#ifndef _IPXE_FCELS_H
#define _IPXE_FCELS_H

/**
 * @file
 *
 * Fibre Channel Extended Link Services
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/fc.h>
#include <ipxe/tables.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/process.h>
#include <ipxe/interface.h>

/** Fibre Channel ELS frame common parameters */
struct fc_els_frame_common {
	/** ELS command code */
	uint8_t command;
	/** Reserved */
	uint8_t reserved[3];
} __attribute__ (( packed ));

/** Fibre Channel ELS command codes */
enum fc_els_command_code {
	FC_ELS_LS_RJT = 0x01,		/**< Link Service Reject */
	FC_ELS_LS_ACC = 0x02,		/**< Link Service Accept */
	FC_ELS_PLOGI = 0x03,		/**< Port Login */
	FC_ELS_FLOGI = 0x04,		/**< Fabric Login */
	FC_ELS_LOGO = 0x05,		/**< Logout */
	FC_ELS_RTV = 0x0e,		/**< Read Timeout Value */
	FC_ELS_ECHO = 0x10,		/**< Echo */
	FC_ELS_PRLI = 0x20,		/**< Process Login */
	FC_ELS_PRLO = 0x21,		/**< Process Logout */
};

/** A Fibre Channel LS_RJT frame */
struct fc_ls_rjt_frame {
	/** ELS command code */
	uint8_t command;
	/** Reserved */
	uint8_t reserved[4];
	/** Reason code */
	uint8_t reason;
	/** Reason code explanation */
	uint8_t explanation;
	/** Vendor unique */
	uint8_t vendor;
} __attribute__ (( packed ));

/** Fibre Channel ELS rejection reason codes */
enum fc_els_reject_reason {
	/** Invalid ELS command code */
	FC_ELS_RJT_INVALID_COMMAND = 0x01,
	/** Logical error */
	FC_ELS_RJT_ILLOGICAL = 0x03,
	/** Logical busy */
	FC_ELS_RJT_BUSY = 0x05,
	/** Protocol error */
	FC_ELS_RJT_PROTOCOL = 0x07,
	/** Unable to perform command request */
	FC_ELS_RJT_UNABLE = 0x09,
	/** Command not supported */
	FC_ELS_RJT_UNSUPPORTED = 0x0b,
	/** Command already in progress */
	FC_ELS_RJT_IN_PROGRESS = 0x0e,
};

/** Fibre Channel "common" service parameters */
struct fc_login_common {
	/** Login version */
	uint16_t version;
	/** Buffer-to-buffer credit */
	uint16_t credit;
	/** Flags */
	uint16_t flags;
	/** Receive size */
	uint16_t mtu;
	/** "Common"?! */
	union {
		struct {
			/** Maximum number of concurrent sequences */
			uint16_t max_seq;
			/** Relative offset by info category */
			uint16_t rel_offs;
		} plogi;
		struct {
			/** Resource allocation timeout value */
			uint32_t r_a_tov;
		} flogi;
	} u;
	/** Error detection timeout value */
	uint32_t e_d_tov;
} __attribute__ (( packed ));

/** Fibre Channel default login version */
#define FC_LOGIN_VERSION 0x2020

/** Fibre Channel default buffer-to-buffer credit */
#define FC_LOGIN_DEFAULT_B2B 10

/** Continuously increasing relative offset */
#define FC_LOGIN_CONTINUOUS_OFFSET 0x8000

/** Clean address */
#define FC_LOGIN_CLEAN 0x8000

/** Multiple N_Port_ID support */
#define FC_LOGIN_MULTI_N 0x8000

/** Random relative offset */
#define FC_LOGIN_RANDOM_OFFSET 0x4000

/** Virtual fabrics */
#define FC_LOGIN_VIRTUAL 0x4000

/** Vendor version level */
#define FC_LOGIN_VENDOR 0x2000

/** Multiple N_Port_ID support */
#define FC_LOGIN_MULTI_F 0x2000

/** Forwarder port */
#define FC_LOGIN_F_PORT 0x1000

/** Alternative credit management */
#define FC_LOGIN_ALT_CREDIT 0x0800

/** Name server session started */
#define FC_LOGIN_NSS_STARTED 0x0800

/** Begin name server session */
#define FC_LOGIN_NSS_BEGIN 0x0400

/** 1ns error detection timer resolution */
#define FC_LOGIN_HIRES_E_D_TOV 0x0400

/** Broadcast supported */
#define FC_LOGIN_BROADCAST 0x0100

/** Query buffer conditions */
#define FC_LOGIN_QUERY_BUF 0x0040

/** Security */
#define FC_LOGIN_SECURITY 0x0020

/** Clock sync primitive capable */
#define FC_LOGIN_CLOCK_SYNC 0x0010

/** Short R_T timeout */
#define FC_LOGIN_SHORT_R_T_TOV 0x0008

/** Dynamic half duplex */
#define FC_LOGIN_DHD 0x0004

/** Continuously increasing sequence count */
#define FC_LOGIN_CONTINUOUS_SEQ 0x0002

/** Payload */
#define FC_LOGIN_PAYLOAD 0x0001

/** Fibre Channel default MTU */
#define FC_LOGIN_DEFAULT_MTU 1452

/** Default maximum number of concurrent sequences */
#define FC_LOGIN_DEFAULT_MAX_SEQ 255

/** Default relative offset by info category */
#define FC_LOGIN_DEFAULT_REL_OFFS 0x1f

/** Default E_D timeout value */
#define FC_LOGIN_DEFAULT_E_D_TOV 2000

/** Fibre Channel class-specific login parameters */
struct fc_login_class {
	/** Flags */
	uint16_t flags;
	/** Initiator flags */
	uint16_t init_flags;
	/** Recipient flags */
	uint16_t recip_flags;
	/** Receive data field size */
	uint16_t mtu;
	/** Maximum number of concurrent sequences */
	uint16_t max_seq;
	/** End-to-end credit */
	uint16_t credit;
	/** Reserved */
	uint8_t reserved0;
	/** Maximum number of open sequences per exchange */
	uint8_t max_seq_per_xchg;
	/** Reserved */
	uint8_t reserved1[2];
} __attribute__ (( packed ));

/** Class valid */
#define FC_LOGIN_CLASS_VALID 0x8000

/** Sequential delivery requested */
#define FC_LOGIN_CLASS_SEQUENTIAL 0x0800

/** A Fibre Channel FLOGI/PLOGI frame */
struct fc_login_frame {
	/** ELS command code */
	uint8_t command;
	/** Reserved */
	uint8_t reserved[3];
	/** Common service parameters */
	struct fc_login_common common;
	/** Port name */
	struct fc_name port_wwn;
	/** Node name */
	struct fc_name node_wwn;
	/** Class 1 service parameters */
	struct fc_login_class class1;
	/** Class 2 service parameters */
	struct fc_login_class class2;
	/** Class 3 service parameters */
	struct fc_login_class class3;
	/** Class 4 service parameters */
	struct fc_login_class class4;
	/** Vendor version level */
	uint8_t vendor_version[16];
} __attribute__ (( packed ));

/** A Fibre Channel LOGO request frame */
struct fc_logout_request_frame {
	/** ELS command code */
	uint8_t command;
	/** Reserved */
	uint8_t reserved[4];
	/** Port ID */
	struct fc_port_id port_id;
	/** Port name */
	struct fc_name port_wwn;
} __attribute__ (( packed ));

/** A Fibre Channel LOGO response frame */
struct fc_logout_response_frame {
	/** ELS command code */
	uint8_t command;
	/** Reserved */
	uint8_t reserved[3];
} __attribute__ (( packed ));

/** A Fibre Channel PRLI service parameter page */
struct fc_prli_page {
	/** Type code */
	uint8_t type;
	/** Type code extension */
	uint8_t type_ext;
	/** Flags and response code */
	uint16_t flags;
	/** Reserved */
	uint32_t reserved[2];
} __attribute__ (( packed ));

/** Establish image pair */
#define FC_PRLI_ESTABLISH 0x2000

/** Response code mask */
#define FC_PRLI_RESPONSE_MASK 0x0f00

/** Request was executed successfully */
#define FC_PRLI_RESPONSE_SUCCESS 0x0100

/** A Fibre Channel PRLI frame */
struct fc_prli_frame {
	/** ELS command code */
	uint8_t command;
	/** Page length */
	uint8_t page_len;
	/** Payload length */
	uint16_t len;
	/** Service parameter page */
	struct fc_prli_page page;
} __attribute__ (( packed ));

/** A Fibre Channel RTV request frame */
struct fc_rtv_request_frame {
	/** ELS command code */
	uint8_t command;
	/** Reserved */
	uint8_t reserved[3];
} __attribute__ (( packed ));

/** A Fibre Channel RTV response frame */
struct fc_rtv_response_frame {
	/** ELS command code */
	uint8_t command;
	/** Reserved */
	uint8_t reserved0[3];
	/** Resource allocation timeout value */
	uint32_t r_a_tov;
	/** Error detection timeout value */
	uint32_t e_d_tov;
	/** Timeout qualifier */
	uint16_t flags;
	/** Reserved */
	uint16_t reserved1;
} __attribute__ (( packed ));

/** 1ns error detection timer resolution */
#define FC_RTV_HIRES_E_D_TOV 0x0400

/** Short R_T timeout */
#define FC_RTV_SHORT_R_T_TOV 0x0008

/** A Fibre Channel ECHO frame */
struct fc_echo_frame_header {
	/** ELS command code */
	uint8_t command;
	/** Reserved */
	uint8_t reserved[3];
} __attribute__ (( packed ));

/** A Fibre Channel extended link services transaction */
struct fc_els {
	/** Reference count */
	struct refcnt refcnt;
	/** Job control interface */
	struct interface job;
	/** Fibre Channel exchange */
	struct interface xchg;
	/** Request sending process */
	struct process process;

	/** Fibre Channel port */
	struct fc_port *port;
	/** Local port ID */
	struct fc_port_id port_id;
	/** Peer port ID */
	struct fc_port_id peer_port_id;
	/** ELS handler, if known */
	struct fc_els_handler *handler;
	/** Flags */
	unsigned int flags;
};

/** Fibre Channel extended link services transaction flags */
enum fc_els_flags {
	/** ELS transaction is a request */
	FC_ELS_REQUEST = 0x0001,
};

/** A Fibre Channel extended link services handler */
struct fc_els_handler {
	/** Name */
	const char *name;
	/** Transmit ELS frame
	 *
	 * @v els		Fibre Channel ELS transaction
	 * @ret rc		Return status code
	 */
	int ( * tx ) ( struct fc_els *els );
	/** Receive ELS frame
	 *
	 * @v els		Fibre Channel ELS transaction
	 * @v data		ELS frame
	 * @v len		Length of ELS frame
	 * @ret rc		Return status code
	 */
	int ( * rx ) ( struct fc_els *els, void *data, size_t len );
	/** Detect ELS frame
	 *
	 * @v els		Fibre Channel ELS transaction
	 * @v data		ELS frame
	 * @v len		Length of ELS frame
	 * @ret rc		Return status code
	 */
	int ( * detect ) ( struct fc_els *els, const void *data, size_t len );
};

/** Fibre Channel ELS handler table */
#define FC_ELS_HANDLERS __table ( struct fc_els_handler, "fc_els_handlers" )

/** Declare a Fibre Channel ELS handler */
#define __fc_els_handler __table_entry ( FC_ELS_HANDLERS, 01 )

/** A Fibre Channel ELS PRLI descriptor */
struct fc_els_prli_descriptor {
	/** Upper-layer protocol type */
	unsigned int type;
	/** Service parameter length */
	size_t param_len;
	/** Fibre Channel ELS handler */
	struct fc_els_handler *handler;
};

/** Fibre Channel ELS PRLI descriptor table */
#define FC_ELS_PRLI_DESCRIPTORS \
	__table ( struct fc_els_prli_descriptor, "fc_els_prli_descriptors" )

/** Declare a Fibre Channel ELS PRLI descriptor */
#define __fc_els_prli_descriptor __table_entry ( FC_ELS_PRLI_DESCRIPTORS, 01 )

/**
 * Check if Fibre Channel ELS transaction is a request
 *
 * @v els		Fibre Channel ELS transaction
 * @ret is_request	ELS transaction is a request
 */
static inline int fc_els_is_request ( struct fc_els *els ) {
	return ( els->flags & FC_ELS_REQUEST );
}

/**
 * Calculate ELS command to transmit
 *
 * @v els		Fibre Channel ELS transaction
 * @v request_command	Command for requests
 * @v command		Command to transmit
 */
static inline unsigned int fc_els_tx_command ( struct fc_els *els,
					       unsigned int request_command ) {
	return ( fc_els_is_request ( els ) ? request_command : FC_ELS_LS_ACC );
}

extern int fc_els_tx ( struct fc_els *els, const void *data, size_t len );
extern int fc_els_request ( struct interface *job, struct fc_port *port,
			    struct fc_port_id *peer_port_id,
			    struct fc_els_handler *handler );
extern int fc_els_flogi ( struct interface *parent, struct fc_port *port );
extern int fc_els_plogi ( struct interface *parent, struct fc_port *port,
			  struct fc_port_id *peer_port_id );
extern int fc_els_logo ( struct interface *parent, struct fc_port *port,
			 struct fc_port_id *peer_port_id );
extern int fc_els_prli ( struct interface *parent, struct fc_port *port,
			 struct fc_port_id *peer_port_id, unsigned int type );
extern int fc_els_prli_tx ( struct fc_els *els,
			    struct fc_els_prli_descriptor *descriptor,
			    void *param );
extern int fc_els_prli_rx ( struct fc_els *els,
			    struct fc_els_prli_descriptor *descriptor,
			    void *data, size_t len );
extern int fc_els_prli_detect ( struct fc_els *els __unused,
				struct fc_els_prli_descriptor *descriptor,
				const void *data, size_t len );

#endif /* _IPXE_FCELS_H */
