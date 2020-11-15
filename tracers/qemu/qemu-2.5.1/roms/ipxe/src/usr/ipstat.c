/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdio.h>
#include <ipxe/ipstat.h>
#include <usr/ipstat.h>

/** @file
 *
 * IP statistics
 *
 */

/**
 * Print IP statistics
 *
 */
void ipstat ( void ) {
	struct ip_statistics_family *family;
	struct ip_statistics *stats;

	for_each_table_entry ( family, IP_STATISTICS_FAMILIES ) {
		stats = family->stats;
		printf ( "IP version %d:\n", family->version );
		printf ( "  InReceives:%ld InMcastPkts:%ld InBcastPkts:%ld "
			 "InOctets:%ld\n", stats->in_receives,
			 stats->in_mcast_pkts, stats->in_bcast_pkts,
			 stats->in_octets );
		printf ( "  InHdrErrors:%ld InAddrErrors:%ld "
			 "InUnknownProtos:%ld InTruncatedPkts:%ld\n",
			 stats->in_hdr_errors, stats->in_addr_errors,
			 stats->in_unknown_protos, stats->in_truncated_pkts );
		printf ( "  ReasmReqds:%ld ReasmOKs:%ld ReasmFails:%ld\n",
			 stats->reasm_reqds, stats->reasm_oks,
			 stats->reasm_fails );
		printf ( "  InDelivers:%ld OutRequests:%ld OutNoRoutes:%ld\n",
			 stats->in_delivers, stats->out_requests,
			 stats->out_no_routes );
		printf ( "  OutTransmits:%ld OutMcastPkts:%ld OutBcastPkts:%ld "
			 "OutOctets:%ld\n", stats->out_transmits,
			 stats->out_mcast_pkts, stats->out_bcast_pkts,
			 stats->out_octets );
	}
}
