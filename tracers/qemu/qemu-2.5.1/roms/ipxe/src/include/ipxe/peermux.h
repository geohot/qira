#ifndef _IPXE_PEERMUX_H
#define _IPXE_PEERMUX_H

/** @file
 *
 * Peer Content Caching and Retrieval (PeerDist) protocol multiplexer
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/list.h>
#include <ipxe/refcnt.h>
#include <ipxe/interface.h>
#include <ipxe/process.h>
#include <ipxe/uri.h>
#include <ipxe/xferbuf.h>
#include <ipxe/pccrc.h>

/** Maximum number of concurrent block downloads */
#define PEERMUX_MAX_BLOCKS 32

/** PeerDist download content information cache */
struct peerdist_info_cache {
	/** Content information */
	struct peerdist_info info;
	/** Content information segment */
	struct peerdist_info_segment segment;
	/** Content information block */
	struct peerdist_info_block block;
};

/** A PeerDist multiplexed block download */
struct peerdist_multiplexed_block {
	/** PeerDist download multiplexer */
	struct peerdist_multiplexer *peermux;
	/** List of multiplexed blocks */
	struct list_head list;
	/** Data transfer interface */
	struct interface xfer;
};

/** A PeerDist download multiplexer */
struct peerdist_multiplexer {
	/** Reference count */
	struct refcnt refcnt;
	/** Data transfer interface */
	struct interface xfer;
	/** Content information interface */
	struct interface info;
	/** Original URI */
	struct uri *uri;

	/** Content information data transfer buffer */
	struct xfer_buffer buffer;
	/** Content information cache */
	struct peerdist_info_cache cache;

	/** Block download initiation process */
	struct process process;
	/** List of busy block downloads */
	struct list_head busy;
	/** List of idle block downloads */
	struct list_head idle;
	/** Block downloads */
	struct peerdist_multiplexed_block block[PEERMUX_MAX_BLOCKS];
};

extern int peermux_filter ( struct interface *xfer, struct interface *info,
			    struct uri *uri );

#endif /* _IPXE_PEERMUX_H */
