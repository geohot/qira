#ifndef _IPXE_XENGRANT_H
#define _IPXE_XENGRANT_H

/** @file
 *
 * Xen grant tables
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stdlib.h>
#include <ipxe/io.h>
#include <ipxe/xen.h>
#include <xen/grant_table.h>

/** Induced failure rate (for testing) */
#define XENGRANT_FAIL_RATE 0

/**
 * Query grant table size
 *
 * @v xen		Xen hypervisor
 * @v size		Table size
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xengrant_query_size ( struct xen_hypervisor *xen,
		      struct gnttab_query_size *size ) {

	return xen_hypercall_3 ( xen, __HYPERVISOR_grant_table_op,
				 GNTTABOP_query_size,
				 virt_to_phys ( size ), 1 );
}

/**
 * Set grant table version
 *
 * @v xen		Xen hypervisor
 * @v version		Version
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xengrant_set_version ( struct xen_hypervisor *xen,
		       struct gnttab_set_version *version ) {

	return xen_hypercall_3 ( xen, __HYPERVISOR_grant_table_op,
				 GNTTABOP_set_version,
				 virt_to_phys ( version ), 1 );
}

/**
 * Get grant table version
 *
 * @v xen		Xen hypervisor
 * @v version		Version
 * @ret xenrc		Xen status code
 */
static inline __attribute__ (( always_inline )) int
xengrant_get_version ( struct xen_hypervisor *xen,
		       struct gnttab_get_version *version ) {

	return xen_hypercall_3 ( xen, __HYPERVISOR_grant_table_op,
				 GNTTABOP_get_version,
				 virt_to_phys ( version ), 1 );
}

/**
 * Get number of grant table entries
 *
 * @v xen		Xen hypervisor
 * @ret entries		Number of grant table entries
 */
static inline __attribute__ (( always_inline )) unsigned int
xengrant_entries ( struct xen_hypervisor *xen ) {

	return ( ( xen->grant.len / sizeof ( xen->grant.table[0] ) )
		 >> xen->grant.shift );
}

/**
 * Get grant table entry header
 *
 * @v xen		Xen hypervisor
 * @v ref		Grant reference
 * @ret hdr		Grant table entry header
 */
static inline __attribute__ (( always_inline )) struct grant_entry_header *
xengrant_header ( struct xen_hypervisor *xen, grant_ref_t ref ) {
	struct grant_entry_v1 *v1;

	v1 = &xen->grant.table[ ref << xen->grant.shift ];
	return ( container_of ( &v1->flags, struct grant_entry_header, flags ));
}

/**
 * Get version 1 grant table entry
 *
 * @v hdr		Grant table entry header
 * @ret v1		Version 1 grant table entry
 */
static inline __attribute__ (( always_inline )) struct grant_entry_v1 *
xengrant_v1 ( struct grant_entry_header *hdr ) {

	return ( container_of ( &hdr->flags, struct grant_entry_v1, flags ) );
}

/**
 * Get version 2 grant table entry
 *
 * @v hdr		Grant table entry header
 * @ret v2		Version 2 grant table entry
 */
static inline __attribute__ (( always_inline )) union grant_entry_v2 *
xengrant_v2 ( struct grant_entry_header *hdr ) {

	return ( container_of ( &hdr->flags, union grant_entry_v2, hdr.flags ));
}

/**
 * Zero grant table entry
 *
 * @v xen		Xen hypervisor
 * @v hdr		Grant table entry header
 */
static inline void xengrant_zero ( struct xen_hypervisor *xen,
				   struct grant_entry_header *hdr ) {
	uint32_t *dword = ( ( uint32_t * ) hdr );
	unsigned int i = ( ( sizeof ( xen->grant.table[0] ) / sizeof ( *dword ))
			   << xen->grant.shift );

	while ( i-- )
		writel ( 0, dword++ );
}

/**
 * Invalidate access to a page
 *
 * @v xen		Xen hypervisor
 * @v ref		Grant reference
 */
static inline __attribute__ (( always_inline )) void
xengrant_invalidate ( struct xen_hypervisor *xen, grant_ref_t ref ) {
	struct grant_entry_header *hdr = xengrant_header ( xen, ref );

	/* Sanity check */
	assert ( ( readw ( &hdr->flags ) &
		   ( GTF_reading | GTF_writing ) ) == 0 );

	/* This should apparently be done using a cmpxchg instruction.
	 * We omit this: partly in the interests of simplicity, but
	 * mainly since our control flow generally does not permit
	 * failure paths to themselves fail.
	 */
	writew ( 0, &hdr->flags );

	/* Leave reference marked as in-use (see xengrant_alloc()) */
	writew ( DOMID_SELF, &hdr->domid );
}

/**
 * Permit access to a page
 *
 * @v xen		Xen hypervisor
 * @v ref		Grant reference
 * @v domid		Domain ID
 * @v subflags		Additional flags
 * @v page		Page start
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
xengrant_permit_access ( struct xen_hypervisor *xen, grant_ref_t ref,
			 domid_t domid, unsigned int subflags, void *page ) {
	struct grant_entry_header *hdr = xengrant_header ( xen, ref );
	struct grant_entry_v1 *v1 = xengrant_v1 ( hdr );
	union grant_entry_v2 *v2 = xengrant_v2 ( hdr );
	unsigned long frame = ( virt_to_phys ( page ) / PAGE_SIZE );

	/* Fail (for test purposes) if applicable */
	if ( ( XENGRANT_FAIL_RATE > 0 ) &&
	     ( random() % XENGRANT_FAIL_RATE ) == 0 ) {
		return -EAGAIN;
	}

	/* Record frame number.  This may fail on a 64-bit system if
	 * we are using v1 grant tables.  On a 32-bit system, there is
	 * no way for this code path to fail (with either v1 or v2
	 * grant tables); we allow the compiler to optimise the
	 * failure paths away to save space.
	 */
	if ( sizeof ( physaddr_t ) == sizeof ( uint64_t ) ) {

		/* 64-bit system */
		if ( xen->grant.shift ) {
			/* Version 2 table: no possible failure */
			writeq ( frame, &v2->full_page.frame );
		} else {
			/* Version 1 table: may fail if address above 16TB */
			if ( frame > 0xffffffffUL )
				return -ERANGE;
			writel ( frame, &v1->frame );
		}

	} else {

		/* 32-bit system */
		if ( xen->grant.shift ) {
			/* Version 2 table: no possible failure */
			writel ( frame, &v2->full_page.frame );
		} else {
			/* Version 1 table: no possible failure */
			writel ( frame, &v1->frame );
		}
	}

	/* Record domain ID and flags */
	writew ( domid, &hdr->domid );
	wmb();
	writew ( ( GTF_permit_access | subflags ), &hdr->flags );
	wmb();

	return 0;
}

extern int xengrant_init ( struct xen_hypervisor *xen );
extern int xengrant_alloc ( struct xen_hypervisor *xen, grant_ref_t *refs,
			    unsigned int count );
extern void xengrant_free ( struct xen_hypervisor *xen, grant_ref_t *refs,
			    unsigned int count );

#endif /* _IPXE_XENGRANT_H */
