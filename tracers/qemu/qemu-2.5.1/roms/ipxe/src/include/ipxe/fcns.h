#ifndef _IPXE_FCNS_H
#define _IPXE_FCNS_H

/**
 * @file
 *
 * Fibre Channel name server lookups
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/fc.h>

/** A Fibre Channel Common Transport header */
struct fc_ct_header {
	/** Revision */
	uint8_t revision;
	/** Original requestor ID */
	struct fc_port_id in_id;
	/** Generic service type */
	uint8_t type;
	/** Generic service subtype */
	uint8_t subtype;
	/** Options */
	uint8_t options;
	/** Reserved */
	uint8_t reserved;
	/** Command/response code */
	uint16_t code;
	/** Maximum/residual size */
	uint16_t size;
	/** Fragment ID */
	uint8_t fragment;
	/** Reason code */
	uint8_t reason;
	/** Reason code explanation */
	uint8_t explanation;
	/** Vendor specific */
	uint8_t vendor;
} __attribute__ (( packed ));

/** Fibre Channel Common Transport revision */
#define FC_CT_REVISION 1

/** Fibre Channel generic service type */
enum fc_gs_type {
	/** Directory service */
	FC_GS_TYPE_DS = 0xfc,
};

/** Fibre Channel generic service response codes */
enum fc_gs_response_code {
	/** Accepted */
	FC_GS_ACCEPT = 0x8002,
	/** Rejected */
	FC_GS_REJECT = 0x8001,
};

/** Fibre Channel generic service rejection reason codes */
enum fc_gs_reason_code {
	/** Invalid command code */
	FC_GS_BAD_COMMAND = 0x01,
	/** Invalid version level */
	FC_GS_BAD_VERSION = 0x02,
	/** Logical error */
	FC_GS_ERROR = 0x03,
	/** Invalid CT_IU size */
	FC_GS_BAD_SIZE = 0x04,
	/** Logical busy */
	FC_GS_BUSY = 0x05,
	/** Protocol error */
	FC_GS_EPROTO = 0x07,
	/** Unable to perform command request */
	FC_GS_UNABLE = 0x09,
	/** Command not supported */
	FC_GS_ENOTSUP = 0x0b,
	/** Server not available */
	FC_GS_UNAVAILABLE = 0x0d,
	/** Session could not be established */
	FC_GS_SESSION = 0x0e,
};

/** Fibre Channel directory service subtype */
enum fc_ds_subtype {
	/** Name server */
	FC_DS_SUBTYPE_NAME = 0x02,
};

/** Fibre Channel name server commands */
enum fc_ns_command_nibble {
	/** Get */
	FC_NS_GET = 0x1,
	/** Register */
	FC_NS_REGISTER = 0x2,
	/** De-register */
	FC_NS_DEREGISTER = 0x3,
};

/** Fibre Channel name server objects */
enum fc_ns_object_nibble {
	/** Port ID */
	FC_NS_PORT_ID = 0x1,
	/** Port name */
	FC_NS_PORT_NAME = 0x2,
	/** Node name */
	FC_NS_NODE_NAME = 0x3,
	/** FC-4 types */
	FC_NS_FC4_TYPES = 0x7,
	/** Symbolic port name */
	FC_NS_SYM_PORT_NAME = 0x8,
	/** Symbolic node name */
	FC_NS_SYM_NODE_NAME = 0x9,
	/** FC-4 features */
	FC_NS_FC4_FEATURES = 0xf,
};

/** Construct Fibre Channel name server command code
 *
 * @v command		Name server command
 * @v key		Name server key
 * @v value		Name server value
 * @ret code		Name server command code
 */
#define FC_NS_CODE( command, key, value )				\
	( ( (command) << 8 ) | ( (key) << 4 ) | ( (value) << 0 ) )

/** Construct Fibre Channel name server "get" command code
 *
 * @v key		Name server key
 * @v value		Name server value to get
 * @ret code		Name server command code
 */
#define FC_NS_GET( key, value ) FC_NS_CODE ( FC_NS_GET, key, value )

/** Construct Fibre Channel name server "register" command code
 *
 * @v key		Name server key
 * @v value		Name server value to register
 * @ret code		Name server command code
 */
#define FC_NS_REGISTER( key, value ) FC_NS_CODE ( FC_NS_REGISTER, key, value )

/** Extract Fibre Channel name server command
 *
 * @v code		Name server command code
 * @ret command		Name server command
 */
#define FC_NS_COMMAND( code ) ( ( (code) >> 8 ) & 0xf )

/** Extract Fibre Channel name server key
 *
 * @v code		Name server command code
 * @ret key		Name server key
 */
#define FC_NS_KEY( code ) ( ( (code) >> 4 ) & 0xf )

/** Extract Fibre Channel name server value
 *
 * @v code		Name server command code
 * @ret value		NAme server value
 */
#define FC_NS_VALUE( code ) ( ( (code) >> 0 ) & 0xf )

/** A Fibre Channel name server port ID */
struct fc_ns_port_id {
	/** Reserved */
	uint8_t reserved;
	/** Port ID */
	struct fc_port_id port_id;
} __attribute__ (( packed ));

/** A Fibre Channel name server GID_PN request */
struct fc_ns_gid_pn_request {
	/** Common Transport header */
	struct fc_ct_header ct;
	/** Port name */
	struct fc_name port_wwn;
} __attribute__ (( packed ));

/** A Fibre Channel name server request */
union fc_ns_request {
	/** Get ID by port name */
	struct fc_ns_gid_pn_request gid_pn;
};

/** A Fibre Channel name server rejection response */
struct fc_ns_reject_response {
	/** Common Transport header */
	struct fc_ct_header ct;
} __attribute__ (( packed ));

/** A Fibre Channel name server GID_PN response */
struct fc_ns_gid_pn_response {
	/** Common Transport header */
	struct fc_ct_header ct;
	/** Port ID */
	struct fc_ns_port_id port_id;
} __attribute__ (( packed ));

/** A Fibre Channel name server response */
union fc_ns_response {
	/** Common Transport header */
	struct fc_ct_header ct;
	/** Rejection */
	struct fc_ns_reject_response reject;
	/** Get ID by port name */
	struct fc_ns_gid_pn_response gid_pn;
};

extern int fc_ns_query ( struct fc_peer *peer, struct fc_port *port,
			 int ( * done ) ( struct fc_peer *peer,
					  struct fc_port *port,
					  struct fc_port_id *peer_port_id ) );

#endif /* _IPXE_FCNS_H */
