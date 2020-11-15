#ifndef _IPXE_MSR_H
#define _IPXE_MSR_H

/** @file
 *
 * Model-specific registers
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Read model-specific register
 *
 * @v msr		Model-specific register
 * @ret value		Value
 */
static inline __attribute__ (( always_inline )) uint64_t
rdmsr ( unsigned int msr ) {
	uint64_t value;

	__asm__ __volatile__ ( "rdmsr" : "=A" ( value ) : "c" ( msr ) );
	return value;
}

/**
 * Write model-specific register
 *
 * @v msr		Model-specific register
 * @v value		Value
 */
static inline __attribute__ (( always_inline )) void
wrmsr ( unsigned int msr, uint64_t value ) {

	__asm__ __volatile__ ( "wrmsr" : : "c" ( msr ), "A" ( value ) );
}

#endif /* _IPXE_MSR_H */
