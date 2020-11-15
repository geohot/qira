#ifndef _IPXE_ETH_SLOW_H
#define _IPXE_ETH_SLOW_H

/** @file
 *
 * Ethernet slow protocols
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Slow protocols header */
struct eth_slow_header {
	/** Slow protocols subtype */
	uint8_t subtype;
	/** Subtype version number */
	uint8_t version;
} __attribute__ (( packed ));

/** LACP subtype */
#define ETH_SLOW_SUBTYPE_LACP 1

/** LACP version number */
#define ETH_SLOW_LACP_VERSION 1

/** Marker subtype */
#define ETH_SLOW_SUBTYPE_MARKER 2

/** Marker version number */
#define ETH_SLOW_MARKER_VERSION 1

/** TLV (type, length, value) header */
struct eth_slow_tlv_header {
	/** Type
	 *
	 * This is an ETH_SLOW_TLV_XXX constant.
	 */
	uint8_t type;
	/** Length
	 *
	 * The length includes the TLV header (except for a TLV
	 * terminator, which has a length of zero).
	 */
	uint8_t length;
} __attribute__ (( packed ));

/** Terminator type */
#define ETH_SLOW_TLV_TERMINATOR 0

/** Terminator length */
#define ETH_SLOW_TLV_TERMINATOR_LEN 0

/** LACP actor type */
#define ETH_SLOW_TLV_LACP_ACTOR 1

/** LACP actor length */
#define ETH_SLOW_TLV_LACP_ACTOR_LEN \
	( sizeof ( struct eth_slow_lacp_entity_tlv ) )

/** LACP partner type */
#define ETH_SLOW_TLV_LACP_PARTNER 2

/** LACP partner length */
#define ETH_SLOW_TLV_LACP_PARTNER_LEN \
	( sizeof ( struct eth_slow_lacp_entity_tlv ) )

/** LACP collector type */
#define ETH_SLOW_TLV_LACP_COLLECTOR 3

/** LACP collector length */
#define ETH_SLOW_TLV_LACP_COLLECTOR_LEN \
	( sizeof ( struct eth_slow_lacp_collector_tlv ) )

/** Marker request type */
#define ETH_SLOW_TLV_MARKER_REQUEST 1

/** Marker request length */
#define ETH_SLOW_TLV_MARKER_REQUEST_LEN \
	( sizeof ( struct eth_slow_marker_tlv ) )

/** Marker response type */
#define ETH_SLOW_TLV_MARKER_RESPONSE 2

/** Marker response length */
#define ETH_SLOW_TLV_MARKER_RESPONSE_LEN \
	( sizeof ( struct eth_slow_marker_tlv ) )

/** Terminator TLV */
struct eth_slow_terminator_tlv {
	/** TLV header */
	struct eth_slow_tlv_header tlv;
} __attribute__ (( packed ));

/** LACP entity (actor or partner) TLV */
struct eth_slow_lacp_entity_tlv {
	/** TLV header */
	struct eth_slow_tlv_header tlv;
	/** System priority
	 *
	 * Used to determine the order in which ports are selected for
	 * aggregation.
	 */
	uint16_t system_priority;
	/** System identifier
	 *
	 * Used to uniquely identify the system (i.e. the entity with
	 * potentially multiple ports).
	 */
	uint8_t system[ETH_ALEN];
	/** Key
	 *
	 * Used to uniquely identify a group of aggregatable ports
	 * within a system.
	 */
	uint16_t key;
	/** Port priority
	 *
	 * Used to determine the order in which ports are selected for
	 * aggregation.
	 */
	uint16_t port_priority;
	/** Port identifier
	 *
	 * Used to uniquely identify a port within a system.
	 */
	uint16_t port;
	/** State
	 *
	 * This is the bitwise OR of zero or more LACP_STATE_XXX
	 * constants.
	 */
	uint8_t state;
	/** Reserved */
	uint8_t reserved[3];
} __attribute__ (( packed ));

/** Maximum system priority */
#define LACP_SYSTEM_PRIORITY_MAX 0xffff

/** Maximum port priority */
#define LACP_PORT_PRIORITY_MAX 0xff

/** LACP entity is active
 *
 * Represented by the state character "A"/"a"
 */
#define LACP_STATE_ACTIVE 0x01

/** LACP timeout is short
 *
 * Short timeout is one second, long timeout is 30s
 *
 * Represented by the state character "F"/"f"
 */
#define LACP_STATE_FAST 0x02

/** LACP link is aggregateable
 *
 * Represented by the state characters "G"/"g"
 */
#define LACP_STATE_AGGREGATABLE 0x04

/** LACP link is in synchronisation
 *
 * Represented by the state characters "S"/"s"
 */
#define LACP_STATE_IN_SYNC 0x08

/** LACP link is collecting (receiving)
 *
 * Represented by the state characters "C"/"c"
 */
#define LACP_STATE_COLLECTING 0x10

/** LACP link is distributing (transmitting)
 *
 * Represented by the state characters "D"/"d"
 */
#define LACP_STATE_DISTRIBUTING 0x20

/** LACP entity is using defaulted partner information
 *
 * Represented by the state characters "L"/"l"
 */
#define LACP_STATE_DEFAULTED 0x40

/** LACP entity receive state machine is in EXPIRED
 *
 * Represented by the state characters "X"/"x"
 */
#define LACP_STATE_EXPIRED 0x80

/** LACP collector TLV */
struct eth_slow_lacp_collector_tlv {
	/** TLV header */
	struct eth_slow_tlv_header tlv;
	/** Maximum delay (in 10us increments) */
	uint16_t max_delay;
	/** Reserved */
	uint8_t reserved[12];
} __attribute__ (( packed ));

/** Marker TLV */
struct eth_slow_marker_tlv {
	/** TLV header */
	struct eth_slow_tlv_header tlv;
	/** Requester port */
	uint16_t port;
	/** Requester system */
	uint8_t system[ETH_ALEN];
	/** Requester transaction ID */
	uint32_t xact;
	/** Padding */
	uint16_t pad;
} __attribute__ (( packed ));

/** LACP packet */
struct eth_slow_lacp {
	/** Slow protocols header */
	struct eth_slow_header header;
	/** Actor information */
	struct eth_slow_lacp_entity_tlv actor;
	/** Partner information */
	struct eth_slow_lacp_entity_tlv partner;
	/** Collector information */
	struct eth_slow_lacp_collector_tlv collector;
	/** Terminator */
	struct eth_slow_terminator_tlv terminator;
	/** Reserved */
	uint8_t reserved[50];
} __attribute__ (( packed ));

/** Marker packet */
struct eth_slow_marker {
	/** Slow protocols header */
	struct eth_slow_header header;
	/** Marker information */
	struct eth_slow_marker_tlv marker;
	/** Terminator */
	struct eth_slow_terminator_tlv terminator;
	/** Reserved */
	uint8_t reserved[90];
} __attribute__ (( packed ));

/** Slow protocols packet */
union eth_slow_packet {
	/** Slow protocols header */
	struct eth_slow_header header;
	/** LACP packet */
	struct eth_slow_lacp lacp;
	/** Marker packet */
	struct eth_slow_marker marker;
} __attribute__ (( packed ));

#endif /* _IPXE_ETH_SLOW_H */
