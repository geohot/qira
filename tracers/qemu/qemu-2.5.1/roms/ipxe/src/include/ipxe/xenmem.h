#ifndef _IPXE_XENMEM_H
#define _IPXE_XENMEM_H

/** @file
 *
 * Xen memory operations
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/xen.h>
#include <xen/memory.h>

/**
 * Add page to physical address space
 *
 * @v xen		Xen hypervisor
 * @v add		Page mapping descriptor
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xenmem_add_to_physmap ( struct xen_hypervisor *xen,
			struct xen_add_to_physmap *add ) {

	return xen_hypercall_2 ( xen, __HYPERVISOR_memory_op,
				 XENMEM_add_to_physmap, virt_to_phys ( add ) );
}

/**
 * Remove page from physical address space
 *
 * @v xen		Xen hypervisor
 * @v remove		Page mapping descriptor
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xenmem_remove_from_physmap ( struct xen_hypervisor *xen,
			     struct xen_remove_from_physmap *remove ) {

	return xen_hypercall_2 ( xen, __HYPERVISOR_memory_op,
				 XENMEM_remove_from_physmap,
				 virt_to_phys ( remove ) );
}

#endif /* _IPXE_XENMEM_H */
