#ifndef _HVM_H
#define _HVM_H

/** @file
 *
 * Xen HVM driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/xen.h>
#include <xen/hvm/hvm_op.h>
#include <xen/hvm/params.h>

/** Minimum CPUID base */
#define HVM_CPUID_MIN 0x40000000UL

/** Maximum CPUID base */
#define HVM_CPUID_MAX 0x4000ff00UL

/** Increment between CPUID bases */
#define HVM_CPUID_STEP 0x00000100UL

/** Magic signature */
#define HVM_CPUID_MAGIC "XenVMMXenVMM"

/** Get Xen version */
#define HVM_CPUID_VERSION 1

/** Get number of hypercall pages */
#define HVM_CPUID_PAGES 2

/** PCI MMIO BAR */
#define HVM_MMIO_BAR PCI_BASE_ADDRESS_1

/** A Xen HVM device */
struct hvm_device {
	/** Xen hypervisor */
	struct xen_hypervisor xen;
	/** CPUID base */
	uint32_t cpuid_base;
	/** Length of hypercall table */
	size_t hypercall_len;
	/** MMIO base address */
	unsigned long mmio;
	/** Current offset within MMIO address space */
	size_t mmio_offset;
	/** Length of MMIO address space */
	size_t mmio_len;
};

/**
 * Get HVM parameter value
 *
 * @v xen		Xen hypervisor
 * @v index		Parameter index
 * @v value		Value to fill in
 * @ret xenrc		Xen status code
 */
static inline int xen_hvm_get_param ( struct xen_hypervisor *xen,
				      unsigned int index, uint64_t *value ) {
	struct xen_hvm_param param;
	int xenrc;

	param.domid = DOMID_SELF;
	param.index = index;
	xenrc = xen_hypercall_2 ( xen, __HYPERVISOR_hvm_op, HVMOP_get_param,
				  virt_to_phys ( &param ) );
	*value = param.value;
	return xenrc;
}

#endif /* _HVM_H */
