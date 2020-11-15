#ifndef _IPXE_FAULT_H
#define _IPXE_FAULT_H

/** @file
 *
 * Fault injection
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <config/fault.h>

extern int inject_fault_nonzero ( unsigned int rate );
extern void inject_corruption_nonzero ( unsigned int rate, const void *data,
					size_t len );

/**
 * Inject fault with a specified probability
 *
 * @v rate		Reciprocal of fault probability (zero for no faults)
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
inject_fault ( unsigned int rate ) {

	/* Force dead code elimination in non-fault-injecting builds */
	if ( rate == 0 )
		return 0;

	return inject_fault_nonzero ( rate );
}

/**
 * Corrupt data with a specified probability
 *
 * @v rate		Reciprocal of fault probability (zero for no faults)
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) void
inject_corruption ( unsigned int rate, const void *data, size_t len ) {

	/* Force dead code elimination in non-fault-injecting builds */
	if ( rate == 0 )
		return;

	return inject_corruption_nonzero ( rate, data, len );
}

#endif /* _IPXE_FAULT_H */
