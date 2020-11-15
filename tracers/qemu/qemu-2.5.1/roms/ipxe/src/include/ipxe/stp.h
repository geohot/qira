#ifndef _IPXE_STP_H
#define _IPXE_STP_H

/** @file
 *
 * Spanning Tree Protocol (STP)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/if_ether.h>

/** "Protocol" value for STP
 *
 * This is the concatenated {DSAP,SSAP} value used internally by iPXE
 * as the network-layer protocol for LLC frames.
 */
#define ETH_P_STP 0x4242

/** A switch identifier */
struct stp_switch {
	/** Priotity */
	uint16_t priority;
	/** MAC address */
	uint8_t mac[ETH_ALEN];
} __attribute__ (( packed ));

/** A Spanning Tree bridge protocol data unit */
struct stp_bpdu {
	/** LLC DSAP */
	uint8_t dsap;
	/** LLC SSAP */
	uint8_t ssap;
	/** LLC control field */
	uint8_t control;
	/** Protocol ID */
	uint16_t protocol;
	/** Protocol version */
	uint8_t version;
	/** Message type */
	uint8_t type;
	/** Flags */
	uint8_t flags;
	/** Root switch */
	struct stp_switch root;
	/** Root path cost */
	uint32_t cost;
	/** Sender switch */
	struct stp_switch sender;
	/** Port */
	uint16_t port;
	/** Message age */
	uint16_t age;
	/** Maximum age */
	uint16_t max;
	/** Hello time */
	uint16_t hello;
	/** Forward delay */
	uint16_t delay;
} __attribute__ (( packed ));

/** Spanning Tree protocol ID */
#define STP_PROTOCOL 0x0000

/** Rapid Spanning Tree protocol version */
#define STP_VERSION_RSTP 0x02

/** Rapid Spanning Tree bridge PDU type */
#define STP_TYPE_RSTP 0x02

/** Port is forwarding */
#define STP_FL_FORWARDING 0x20

#endif /* _IPXE_STP_H */
