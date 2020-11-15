#ifndef _IPXE_FC_H
#define _IPXE_FC_H

/**
 * @file
 *
 * Fibre Channel
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/tables.h>
#include <ipxe/interface.h>
#include <ipxe/retry.h>
#include <ipxe/socket.h>

/******************************************************************************
 *
 * Fibre Channel Names and identifiers
 *
 ******************************************************************************
 */

/** A Fibre Channel name */
struct fc_name {
	uint8_t bytes[8];
} __attribute__ (( packed ));

/** Length of Fibre Channel name text */
#define FC_NAME_STRLEN 23 /* "xx:xx:xx:xx:xx:xx:xx:xx" */

/** A Fibre Channel port identifier */
struct fc_port_id {
	uint8_t bytes[3];
} __attribute__ (( packed ));

/** Length of Fibre Channel port identifier next */
#define FC_PORT_ID_STRLEN 9 /* "xx.xx.xx" */

/**
 * Fibre Channel socket address
 */
struct sockaddr_fc {
	/** Socket address family (part of struct @c sockaddr)
	 *
	 * Always set to @c AF_FC for Fibre Channel addresses
	 */
	sa_family_t sfc_family;
	/** Port ID */
	struct fc_port_id sfc_port_id;
	/** Padding
	 *
	 * This ensures that a struct @c sockaddr_tcpip is large
	 * enough to hold a socket address for any TCP/IP address
	 * family.
	 */
	char pad[ sizeof ( struct sockaddr ) - sizeof ( sa_family_t )
					     - sizeof ( struct fc_port_id ) ];
} __attribute__ (( packed, may_alias ));

extern struct fc_port_id fc_empty_port_id;
extern struct fc_port_id fc_f_port_id;
extern struct fc_port_id fc_gs_port_id;
extern struct fc_port_id fc_ptp_low_port_id;
extern struct fc_port_id fc_ptp_high_port_id;

extern const char * fc_id_ntoa ( const struct fc_port_id *id );
extern int fc_id_aton ( const char *id_text, struct fc_port_id *id );
extern const char * fc_ntoa ( const struct fc_name *wwn );
extern int fc_aton ( const char *wwn_text, struct fc_name *wwn );
extern struct sockaddr * fc_fill_sockaddr ( struct sockaddr_fc *sa_fc,
					    struct fc_port_id *id );

/******************************************************************************
 *
 * Fibre Channel link state
 *
 ******************************************************************************
 */

/** Delay between failed link-up attempts */
#define FC_LINK_RETRY_DELAY ( 2 * TICKS_PER_SEC )

/** A Fibre Channel link state nonitor */
struct fc_link_state {
	/** Retry timer */
	struct retry_timer timer;
	/** Link state */
	int rc;
	/** Examine link state
	 *
	 * @v link		Fibre Channel link state monitor
	 */
	void ( * examine ) ( struct fc_link_state *link );
};

/**
 * Check Fibre Channel link state
 *
 * @v link		Fibre Channel link state monitor
 * @ret link_up		Link is up
 */
static inline __attribute__ (( always_inline )) int
fc_link_ok ( struct fc_link_state *link ) {
	return ( link->rc == 0 );
}

/******************************************************************************
 *
 * Fibre Channel packet formats and exchanges
 *
 ******************************************************************************
 */

/** A Fibre Channel Frame Header */
struct fc_frame_header {
	/** Routing control
	 *
	 * This is the bitwise OR of one @c fc_r_ctl_routing value and
	 * one @c fc_r_ctl_info value.
	 */
	uint8_t r_ctl;
	/** Destination ID */
	struct fc_port_id d_id;
	/** Class-specific control / Priority */
	uint8_t cs_ctl_prio;
	/** Source ID */
	struct fc_port_id s_id;
	/** Data structure type */
	uint8_t type;
	/** Frame control - exchange and sequence */
	uint8_t f_ctl_es;
	/** Frame control - acknowledgements  */
	uint8_t f_ctl_ack;
	/** Frame control - miscellaneous */
	uint8_t f_ctl_misc;
	/** Sequence ID */
	uint8_t seq_id;
	/** Data field control */
	uint8_t df_ctl;
	/** Sequence count */
	uint16_t seq_cnt;
	/** Originator exchange ID */
	uint16_t ox_id;
	/** Responder exchange ID */
	uint16_t rx_id;
	/** Parameter
	 *
	 * Contains the relative offset when @c FC_F_CTL_MISC_REL_OFF
	 * is set.
	 */
	uint32_t parameter;
} __attribute__ (( packed ));

/** Fibre Channel Routing Control Routing */
enum fc_r_ctl_routing {
	FC_R_CTL_DATA = 0x00,		/**< Device Data */
	FC_R_CTL_ELS = 0x20,		/**< Extended Link Services */
	FC_R_CTL_FC4_LINK = 0x30,	/**< FC-4 Link Data */
	FC_R_CTL_VIDEO = 0x40,		/**< Video Data */
	FC_R_CTL_EH = 0x50,		/**< Extended Headers */
	FC_R_CTL_BLS = 0x80,		/**< Basic Link Services */
	FC_R_CTL_LINK_CTRL = 0xc0,	/**< Link Control */
	FC_R_CTL_EXT_ROUTE = 0xf0,	/**< Extended Routing */
};

/** Fibre Channel Routing Control Routing mask */
#define FC_R_CTL_ROUTING_MASK 0xf0

/** Fibre Channel Routing Control Information */
enum fc_r_ctl_info {
	FC_R_CTL_UNCAT = 0x00,		/**< Uncategorized */
	FC_R_CTL_SOL_DATA = 0x01,	/**< Solicited Data */
	FC_R_CTL_UNSOL_CTRL = 0x02,	/**< Unsolicited Control */
	FC_R_CTL_SOL_CTRL = 0x03,	/**< Solicited Control */
	FC_R_CTL_UNSOL_DATA = 0x04,	/**< Unsolicited Data */
	FC_R_CTL_DATA_DESC = 0x05,	/**< Data Descriptor */
	FC_R_CTL_UNSOL_CMD = 0x06,	/**< Unsolicited Command */
	FC_R_CTL_CMD_STAT = 0x07,	/**< Command Status */
};

/** Fibre Channel Routing Control Information mask */
#define FC_R_CTL_INFO_MASK 0x07

/** Fibre Channel Data Structure Type */
enum fc_type {
	FC_TYPE_BLS = 0x00,		/**< Basic Link Service */
	FC_TYPE_ELS = 0x01,		/**< Extended Link Service */
	FC_TYPE_FCP = 0x08,		/**< Fibre Channel Protocol */
	FC_TYPE_CT  = 0x20,		/**< Common Transport */
};

/** Fibre Channel Frame Control - Exchange and Sequence */
enum fc_f_ctl_es {
	FC_F_CTL_ES_RESPONDER = 0x80,	/**< Responder of Exchange */
	FC_F_CTL_ES_RECIPIENT = 0x40,	/**< Sequence Recipient */
	FC_F_CTL_ES_FIRST = 0x20,	/**< First Sequence of Exchange */
	FC_F_CTL_ES_LAST = 0x10,	/**< Last Sequence of Exchange */
	FC_F_CTL_ES_END = 0x08,		/**< Last Data Frame of Sequence */
	FC_F_CTL_ES_TRANSFER = 0x01,	/**< Transfer Sequence Initiative */
};

/** Fibre Channel Frame Control - Miscellaneous */
enum fc_f_ctl_misc {
	FC_F_CTL_MISC_REL_OFF = 0x08,	/**< Relative Offset Present */
};

/** Responder exchange identifier used before first response */
#define FC_RX_ID_UNKNOWN 0xffff

struct fc_port;

extern int fc_xchg_originate ( struct interface *parent, struct fc_port *port,
			       struct fc_port_id *peer_port_id,
			       unsigned int type );

/** A Fibre Channel responder */
struct fc_responder {
	/** Type */
	unsigned int type;
	/** Respond to exchange
	 *
	 * @v xchg		Exchange interface
	 * @v port		Fibre Channel port
	 * @v port_id		Local port ID
	 * @v peer_port_id	Peer port ID
	 * @ret rc		Return status code
	 */
	int ( * respond ) ( struct interface *xchg, struct fc_port *port,
			    struct fc_port_id *port_id,
			    struct fc_port_id *peer_port_id );
};

/** Fibre Channel responder table */
#define FC_RESPONDERS __table ( struct fc_responder, "fc_responders" )

/** Declare a Fibre Channel responder */
#define __fc_responder __table_entry ( FC_RESPONDERS, 01 )

/******************************************************************************
 *
 * Fibre Channel ports
 *
 ******************************************************************************
 */

/** A Fibre Channel port */
struct fc_port {
	/** Reference count */
	struct refcnt refcnt;
	/** List of all ports */
	struct list_head list;
	/** Name of this port */
	char name[8];

	/** Transport interface */
	struct interface transport;
	/** Node name */
	struct fc_name node_wwn;
	/** Port name */
	struct fc_name port_wwn;
	/** Local port ID */
	struct fc_port_id port_id;
	/** Flags */
	unsigned int flags;

	/** Link state monitor */
	struct fc_link_state link;
	/** FLOGI interface */
	struct interface flogi;
	/** Link node name */
	struct fc_name link_node_wwn;
	/** Link port name */
	struct fc_name link_port_wwn;
	/** Link port ID (for point-to-point links only) */
	struct fc_port_id ptp_link_port_id;

	/** Name server PLOGI interface */
	struct interface ns_plogi;

	/** List of active exchanges */
	struct list_head xchgs;
};

/** Fibre Channel port flags */
enum fc_port_flags {
	/** Port is attached to a fabric */
	FC_PORT_HAS_FABRIC = 0x0001,
	/** Port is logged in to a name server */
	FC_PORT_HAS_NS = 0x0002,
};

/**
 * Get reference to Fibre Channel port
 *
 * @v port		Fibre Channel port
 * @ret port		Fibre Channel port
 */
static inline __attribute__ (( always_inline )) struct fc_port *
fc_port_get ( struct fc_port *port ) {
	ref_get ( &port->refcnt );
	return port;
}

/**
 * Drop reference to Fibre Channel port
 *
 * @v port		Fibre Channel port
 */
static inline __attribute__ (( always_inline )) void
fc_port_put ( struct fc_port *port ) {
	ref_put ( &port->refcnt );
}

extern struct list_head fc_ports;

extern int fc_port_login ( struct fc_port *port, struct fc_port_id *port_id,
			   const struct fc_name *link_node_wwn,
			   const struct fc_name *link_port_wwn,
			   int has_fabric );
extern void fc_port_logout ( struct fc_port *port, int rc );
extern int fc_port_open ( struct interface *transport,
			  const struct fc_name *node_wwn,
			  const struct fc_name *port_wwn,
			  const char *name );
extern struct fc_port * fc_port_find ( const char *name );

/******************************************************************************
 *
 * Fibre Channel peers
 *
 ******************************************************************************
 */

/** A Fibre Channel peer */
struct fc_peer {
	/** Reference count */
	struct refcnt refcnt;
	/** List of all peers */
	struct list_head list;

	/** Port name */
	struct fc_name port_wwn;

	/** Link state monitor */
	struct fc_link_state link;
	/** PLOGI interface */
	struct interface plogi;
	/** Fibre Channel port, if known */
	struct fc_port *port;
	/** Peer port ID, if known */
	struct fc_port_id port_id;

	/** List of upper-layer protocols */
	struct list_head ulps;
	/** Active usage count
	 *
	 * A peer (and attached ULPs) may be created in response to
	 * unsolicited login requests received via the fabric.  We
	 * track our own active usage count independently of the
	 * existence of the peer, so that if the peer becomes logged
	 * out (e.g. due to a link failure) then we know whether or
	 * not we should attempt to relogin.
	 */
	unsigned int usage;
};

/**
 * Get reference to Fibre Channel peer
 *
 * @v peer		Fibre Channel peer
 * @ret peer		Fibre Channel peer
 */
static inline __attribute__ (( always_inline )) struct fc_peer *
fc_peer_get ( struct fc_peer *peer ) {
	ref_get ( &peer->refcnt );
	return peer;
}

/**
 * Drop reference to Fibre Channel peer
 *
 * @v peer		Fibre Channel peer
 */
static inline __attribute__ (( always_inline )) void
fc_peer_put ( struct fc_peer *peer ) {
	ref_put ( &peer->refcnt );
}

extern struct list_head fc_peers;

extern struct fc_peer * fc_peer_get_wwn ( const struct fc_name *port_wwn );
extern struct fc_peer *
fc_peer_get_port_id ( struct fc_port *port,
		      const struct fc_port_id *peer_port_id );
extern int fc_peer_login ( struct fc_peer *peer,
			   struct fc_port *port,
			   struct fc_port_id *port_id );
extern void fc_peer_logout ( struct fc_peer *peer, int rc );

/******************************************************************************
 *
 * Fibre Channel upper-layer protocols
 *
 ******************************************************************************
 */

/** A Fibre Channel upper-layer protocol */
struct fc_ulp {
	/** Reference count */
	struct refcnt refcnt;
	/** Fibre Channel peer */
	struct fc_peer *peer;
	/** List of upper-layer protocols */
	struct list_head list;

	/** Type */
	unsigned int type;
	/** Flags */
	unsigned int flags;

	/** Link state monitor */
	struct fc_link_state link;
	/** PRLI interface */
	struct interface prli;
	/** Service parameters, if any */
	void *param;
	/** Service parameter length */
	size_t param_len;

	/** Active users of this upper-layer protocol
	 *
	 * As with peers, an upper-layer protocol may be created in
	 * response to an unsolicited login request received via the
	 * fabric.  This list records the number of active users of
	 * the ULP; the number of entries in the list is equivalent to
	 * the peer usage count.
	 */
	struct list_head users;
};

/** Fibre Channel upper-layer protocol flags */
enum fc_ulp_flags {
	/** A login originated by us has succeeded */
	FC_ULP_ORIGINATED_LOGIN_OK = 0x0001,
};

/** A Fibre Channel upper-layer protocol user */
struct fc_ulp_user {
	/** Fibre Channel upper layer protocol */
	struct fc_ulp *ulp;
	/** List of users */
	struct list_head list;
	/** Containing object reference count, or NULL */
	struct refcnt *refcnt;
	/** Examine link state
	 *
	 * @v user		Fibre Channel upper-layer-protocol user
	 */
	void ( * examine ) ( struct fc_ulp_user *user );
};

/**
 * Get reference to Fibre Channel upper-layer protocol
 *
 * @v ulp		Fibre Channel upper-layer protocol
 * @ret ulp		Fibre Channel upper-layer protocol
 */
static inline __attribute__ (( always_inline )) struct fc_ulp *
fc_ulp_get ( struct fc_ulp *ulp ) {
	ref_get ( &ulp->refcnt );
	return ulp;
}

/**
 * Drop reference to Fibre Channel upper-layer protocol
 *
 * @v ulp		Fibre Channel upper-layer protocol
 */
static inline __attribute__ (( always_inline )) void
fc_ulp_put ( struct fc_ulp *ulp ) {
	ref_put ( &ulp->refcnt );
}

/**
 * Get reference to Fibre Channel upper-layer protocol user
 *
 * @v user		Fibre Channel upper-layer protocol user
 * @ret user		Fibre Channel upper-layer protocol user
 */
static inline __attribute__ (( always_inline )) struct fc_ulp_user *
fc_ulp_user_get ( struct fc_ulp_user *user ) {
	ref_get ( user->refcnt );
	return user;
}

/**
 * Drop reference to Fibre Channel upper-layer protocol user
 *
 * @v user		Fibre Channel upper-layer protocol user
 */
static inline __attribute__ (( always_inline )) void
fc_ulp_user_put ( struct fc_ulp_user *user ) {
	ref_put ( user->refcnt );
}

/**
 * Initialise Fibre Channel upper-layer protocol user
 *
 * @v user		Fibre Channel upper-layer protocol user
 * @v examine		Examine link state method
 * @v refcnt		Containing object reference count, or NULL
 */
static inline __attribute__ (( always_inline )) void
fc_ulp_user_init ( struct fc_ulp_user *user,
		   void ( * examine ) ( struct fc_ulp_user *user ),
		   struct refcnt *refcnt ) {
	user->examine = examine;
	user->refcnt = refcnt;
}

extern struct fc_ulp * fc_ulp_get_wwn_type ( const struct fc_name *port_wwn,
					     unsigned int type );
extern struct fc_ulp *
fc_ulp_get_port_id_type ( struct fc_port *port,
			  const struct fc_port_id *peer_port_id,
			  unsigned int type );
extern void fc_ulp_attach ( struct fc_ulp *ulp, struct fc_ulp_user *user );
extern void fc_ulp_detach ( struct fc_ulp_user *user );
extern int fc_ulp_login ( struct fc_ulp *ulp, const void *param,
			  size_t param_len, int originated );
extern void fc_ulp_logout ( struct fc_ulp *ulp, int rc );

#endif /* _IPXE_FC_H */
