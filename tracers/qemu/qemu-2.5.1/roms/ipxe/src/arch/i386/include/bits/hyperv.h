#ifndef _BITS_HYPERV_H
#define _BITS_HYPERV_H

/** @file
 *
 * Hyper-V interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <stdint.h>
#include <ipxe/io.h>

/**
 * Issue hypercall
 *
 * @v hv		Hyper-V hypervisor
 * @v code		Call code
 * @v in		Input parameters
 * @v out		Output parameters
 * @ret status		Status code
 */
static inline __attribute__ (( always_inline )) int
hv_call ( struct hv_hypervisor *hv, unsigned int code, const void *in,
	  void *out ) {
	void *hypercall = hv->hypercall;
	uint32_t in_phys;
	uint32_t out_phys;
	uint32_t discard_ecx;
	uint32_t discard_edx;
	uint16_t result;

	in_phys = ( ( __builtin_constant_p ( in ) && ( in == NULL ) )
		       ? 0 : virt_to_phys ( in ) );
	out_phys = ( ( __builtin_constant_p ( out ) && ( out == NULL ) )
		       ? 0 : virt_to_phys ( out ) );
	__asm__ __volatile__ ( "call *%9"
			       : "=a" ( result ), "=c" ( discard_ecx ),
				 "=d" ( discard_edx )
			       : "d" ( 0 ), "a" ( code ),
				 "b" ( 0 ), "c" ( in_phys ),
				 "D" ( 0 ), "S" ( out_phys ),
				 "m" ( hypercall ) );
	return result;
}

/**
 * Set bit atomically
 *
 * @v bits		Bit field
 * @v bit		Bit to set
 */
static inline __attribute__ (( always_inline )) void
hv_set_bit ( void *bits, unsigned int bit ) {
	struct {
		uint32_t dword[ ( bit / 32 ) + 1 ];
	} *dwords = bits;

	/* Set bit using "lock bts".  Inform compiler that any memory
	 * from the start of the bit field up to and including the
	 * dword containing this bit may be modified.  (This is
	 * overkill but shouldn't matter in practice since we're
	 * unlikely to subsequently read other bits from the same bit
	 * field.)
	 */
	__asm__ __volatile__ ( "lock bts %1, %0"
			       : "+m" ( *dwords ) : "Ir" ( bit ) );
}

#endif /* _BITS_HYPERV_H */
