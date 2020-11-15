#ifndef _IPXE_XENVER_H
#define _IPXE_VENVER_H

/** @file
 *
 * Xen version
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/xen.h>
#include <xen/version.h>

/**
 * Get Xen version
 *
 * @v xen		Xen hypervisor
 * @ret version		Version (major.minor: 16 bits each)
 */
static inline __attribute__ (( always_inline )) uint32
xenver_version ( struct xen_hypervisor *xen ) {

	return xen_hypercall_2 ( xen, __HYPERVISOR_xen_version,
				 XENVER_version, 0 );
}

/**
 * Get Xen extra version string
 *
 * @v xen		Xen hypervisor
 * @v extraversion	Extra version string to fill in
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xenver_extraversion ( struct xen_hypervisor *xen,
		      xen_extraversion_t *extraversion ) {

	return xen_hypercall_2 ( xen, __HYPERVISOR_xen_version,
				 XENVER_extraversion,
				 virt_to_phys ( extraversion ) );
}

#endif /* _IPXE_XENVER_H */
