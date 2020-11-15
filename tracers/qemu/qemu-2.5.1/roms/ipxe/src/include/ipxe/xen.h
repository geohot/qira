#ifndef _IPXE_XEN_H
#define _IPXE_XEN_H

/** @file
 *
 * Xen interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/* Define Xen interface version before including any Xen header files */
#define __XEN_INTERFACE_VERSION__ 0x00040400

#include <stdint.h>
#include <ipxe/uaccess.h>
#include <xen/xen.h>
#include <xen/event_channel.h>

/* Memory barrier macros used by ring.h */
#define xen_mb() mb()
#define xen_rmb() rmb()
#define xen_wmb() wmb()

struct xen_hypercall;

/** A Xen grant table */
struct xen_grant {
	/** Grant table entries */
	struct grant_entry_v1 *table;
	/** Total grant table length */
	size_t len;
	/** Entry size shift (for later version tables) */
	unsigned int shift;
	/** Number of grant table entries in use */
	unsigned int used;
	/** Most recently used grant reference */
	unsigned int ref;
};

/** A XenStore */
struct xen_store {
	/** XenStore domain interface */
	struct xenstore_domain_interface *intf;
	/** Event channel */
	evtchn_port_t port;
};

/** A Xen hypervisor */
struct xen_hypervisor {
	/** Hypercall table */
	struct xen_hypercall *hypercall;
	/** Shared info page */
	struct shared_info *shared;
	/** Grant table */
	struct xen_grant grant;
	/** XenStore */
	struct xen_store store;
};

#include <bits/xen.h>

/**
 * Convert a Xen status code to an iPXE status code
 *
 * @v xenrc		Xen status code (negated)
 * @ret rc		iPXE status code (before negation)
 *
 * Xen status codes are defined in the file include/xen/errno.h in the
 * Xen repository.  They happen to match the Linux error codes, some
 * of which can be found in our include/ipxe/errno/linux.h.
 */
#define EXEN( xenrc ) EPLATFORM ( EINFO_EPLATFORM, -(xenrc) )

#endif /* _IPXE_XEN_H */
