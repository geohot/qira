#ifndef _IPXE_IPSTATS_H
#define _IPXE_IPSTATS_H

/** @file
 *
 * IP statistics
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/tables.h>

struct io_buffer;

/** IP system statistics
 *
 * Definitions are taken from the RFC4293 section 5
 * "ipSystemStatsEntry" table.
 *
 * To minimise code size, we use "unsigned long" as the counter
 * variable type regardless of whether this type is 32-bit or 64-bit.
 * On a 32-bit build (e.g. the standard BIOS build), this means that
 * we omit the "high capacity" 64-bit counters (prefixed with "HC").
 * This reduces the code size required to maintain the counter values,
 * and avoids the need to support the "%lld" format in vsprintf.c
 * (which would require dragging in the 64-bit division library on a
 * standard 32-bit build).  Since total available memory in a 32-bit
 * environment is limited to 4GB, it is unlikely that we will overflow
 * even the 32-bit octet counters under normal operation.
 *
 * Counters relating to packet forwarding are omitted, since iPXE
 * includes no functionality for acting as a router.
 *
 * Counters related to output fragmentation are omitted, since iPXE
 * has no support for fragmenting transmitted packets.
 *
 * The ipSystemStatsInDiscards and ipSystemStatsOutDiscards counters
 * are omitted, since they will always be zero.
 *
 * Separate octet counters for multicast packets are omitted to save
 * code size.
 */
struct ip_statistics {
	/** ipSystemStatsInReceives
	 *
	 * The total number of input IP datagrams received, including
	 * those received in error.
	 */
	unsigned long in_receives;
	/** ipSystemStatsInOctets
	 *
	 * The total number of octets received in input IP datagrams,
	 * including those received in error.  Octets from datagrams
	 * counted in ipSystemStatsInReceives MUST be counted here.
	 */
	unsigned long in_octets;
	/** ipSystemStatsInHdrErrors
	 *
	 * The number of input IP datagrams discarded due to errors in
	 * their IP headers, including version number mismatch, other
	 * format errors, hop count exceeded, errors discovered in
	 * processing their IP options, etc.
	 */
	unsigned long in_hdr_errors;
	/** ipSystemStatsInAddrErrors
	 *
	 * The number of input IP datagrams discarded because the IP
	 * address in their IP header's destination field was not a
	 * valid address to be received at this entity.  This count
	 * includes invalid addresses (e.g., ::0).  For entities that
	 * are not IP routers and therefore do not forward datagrams,
	 * this counter includes datagrams discarded because the
	 * destination address was not a local address.
	 */
	unsigned long in_addr_errors;
	/** ipSystemStatsInUnknownProtos
	 *
	 * The number of locally-addressed IP datagrams received
	 * successfully but discarded because of an unknown or
	 * unsupported protocol.
	 */
	unsigned long in_unknown_protos;
	/** ipSystemStatsInTruncatedPkts
	 *
	 * The number of input IP datagrams discarded because the
	 * datagram frame didn't carry enough data.
	 */
	unsigned long in_truncated_pkts;
	/** ipSystemStatsReasmReqds
	 *
	 * The number of IP fragments received that needed to be
	 * reassembled at this interface.
	 */
	unsigned long reasm_reqds;
	/** ipSystemStatsReasmOks
	 *
	 * The number of IP datagrams successfully reassembled.
	 */
	unsigned long reasm_oks;
	/** ipSystemStatsReasmFails
	 *
	 * The number of failures detected by the IP re-assembly
	 * algorithm (for whatever reason: timed out, errors, etc.).
	 * Note that this is not necessarily a count of discarded IP
	 * fragments since some algorithms (notably the algorithm in
	 * RFC 815) can lose track of the number of fragments by
	 * combining them as they are received.
	 */
	unsigned long reasm_fails;
	/** ipSystemStatsInDelivers
	 *
	 * The total number of datagrams successfully delivered to IP
	 * user-protocols (including ICMP).
	 */
	unsigned long in_delivers;
	/** ipSystemStatsOutRequests
	 *
	 * The total number of IP datagrams that local IP user-
	 * protocols (including ICMP) supplied to IP in requests for
	 * transmission.
	 */
	unsigned long out_requests;
	/** ipSystemStatsOutNoRoutes
	 *
	 * The number of locally generated IP datagrams discarded
	 * because no route could be found to transmit them to their
	 * destination.
	 */
	unsigned long out_no_routes;
	/** ipSystemStatsOutTransmits
	 *
	 * The total number of IP datagrams that this entity supplied
	 * to the lower layers for transmission.  This includes
	 * datagrams generated locally and those forwarded by this
	 * entity.
	 */
	unsigned long out_transmits;
	/** ipSystemStatsOutOctets
	 *
	 * The total number of octets in IP datagrams delivered to the
	 * lower layers for transmission.  Octets from datagrams
	 * counted in ipSystemStatsOutTransmits MUST be counted here.
	 */
	unsigned long out_octets;
	/** ipSystemStatsInMcastPkts
	 *
	 * The number of IP multicast datagrams received.
	 */
	unsigned long in_mcast_pkts;
	/** ipSystemStatsOutMcastPkts
	 *
	 * The number of IP multicast datagrams transmitted.
	 */
	unsigned long out_mcast_pkts;
	/** ipSystemStatsInBcastPkts
	 *
	 * The number of IP broadcast datagrams received.
	 */
	unsigned long in_bcast_pkts;
	/** ipSystemStatsOutBcastPkts
	 *
	 * The number of IP broadcast datagrams transmitted.
	 */
	unsigned long out_bcast_pkts;
};

/** An IP system statistics family */
struct ip_statistics_family {
	/** IP version */
	unsigned int version;
	/** Statistics */
	struct ip_statistics *stats;
};

/** IP system statistics family table */
#define IP_STATISTICS_FAMILIES \
	__table ( struct ip_statistics_family, "ip_statistics_families" )

/** Declare an IP system statistics family */
#define __ip_statistics_family( order ) \
	__table_entry ( IP_STATISTICS_FAMILIES, order )

#define IP_STATISTICS_IPV4 01
#define IP_STATISTICS_IPV6 02

#endif /* _IPXE_IPSTATS_H */
