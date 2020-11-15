#ifndef _IPXE_XENEVENT_H
#define _IPXE_XENEVENT_H

/** @file
 *
 * Xen events
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/xen.h>
#include <xen/event_channel.h>

/**
 * Close event channel
 *
 * @v xen		Xen hypervisor
 * @v close		Event descriptor
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xenevent_close ( struct xen_hypervisor *xen, struct evtchn_close *close ) {

	return xen_hypercall_2 ( xen, __HYPERVISOR_event_channel_op,
				 EVTCHNOP_close, virt_to_phys ( close ) );
}

/**
 * Send event
 *
 * @v xen		Xen hypervisor
 * @v send		Event descriptor
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xenevent_send ( struct xen_hypervisor *xen, struct evtchn_send *send ) {

	return xen_hypercall_2 ( xen, __HYPERVISOR_event_channel_op,
				 EVTCHNOP_send, virt_to_phys ( send ) );
}

/**
 * Allocate an unbound event channel
 *
 * @v xen		Xen hypervisor
 * @v alloc_unbound	Event descriptor
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xenevent_alloc_unbound ( struct xen_hypervisor *xen,
			 struct evtchn_alloc_unbound *alloc_unbound ) {

	return xen_hypercall_2 ( xen, __HYPERVISOR_event_channel_op,
				 EVTCHNOP_alloc_unbound,
				 virt_to_phys ( alloc_unbound ) );
}

#endif /* _IPXE_XENEVENT_H */
