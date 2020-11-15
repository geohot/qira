#ifndef _IPXE_DHCPPKT_H
#define _IPXE_DHCPPKT_H

/** @file
 *
 * DHCP packets
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/dhcp.h>
#include <ipxe/dhcpopts.h>
#include <ipxe/refcnt.h>

/**
 * A DHCP packet
 *
 */
struct dhcp_packet {
	/** Reference counter */
	struct refcnt refcnt;
	/** The DHCP packet contents */
	struct dhcphdr *dhcphdr;
	/** DHCP options */
	struct dhcp_options options;
	/** Settings interface */
	struct settings settings;
};

/**
 * Increment reference count on DHCP packet
 *
 * @v dhcppkt		DHCP packet
 * @ret dhcppkt		DHCP packet
 */
static inline __attribute__ (( always_inline )) struct dhcp_packet *
dhcppkt_get ( struct dhcp_packet *dhcppkt ) {
	ref_get ( &dhcppkt->refcnt );
	return dhcppkt;
}

/**
 * Decrement reference count on DHCP packet
 *
 * @v dhcppkt		DHCP packet
 */
static inline __attribute__ (( always_inline )) void
dhcppkt_put ( struct dhcp_packet *dhcppkt ) {
	ref_put ( &dhcppkt->refcnt );
}

/**
 * Get used length of DHCP packet
 *
 * @v dhcppkt		DHCP packet
 * @ret len		Used length
 */
static inline int dhcppkt_len ( struct dhcp_packet *dhcppkt ) {
	return ( offsetof ( struct dhcphdr, options ) +
		 dhcppkt->options.used_len );
}

extern int dhcppkt_store ( struct dhcp_packet *dhcppkt, unsigned int tag,
			   const void *data, size_t len );
extern int dhcppkt_fetch ( struct dhcp_packet *dhcppkt, unsigned int tag,
			   void *data, size_t len );
extern void dhcppkt_init ( struct dhcp_packet *dhcppkt, 
			   struct dhcphdr *data, size_t len );

#endif /* _IPXE_DHCPPKT_H */
