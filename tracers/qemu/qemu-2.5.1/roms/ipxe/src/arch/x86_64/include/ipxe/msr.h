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
	uint32_t high;
	uint32_t low;

	__asm__ __volatile__ ( "rdmsr" :
			       "=d" ( high ), "=a" ( low ) : "c" ( msr ) );
	return ( ( ( ( uint64_t ) high ) << 32 ) | low );
}

/**
 * Write model-specific register
 *
 * @v msr		Model-specific register
 * @v value		Value
 */
static inline __attribute__ (( always_inline )) void
wrmsr ( unsigned int msr, uint64_t value ) {
	uint32_t high = ( value >> 32 );
	uint32_t low = ( value >> 0 );

	__asm__ __volatile__ ( "wrmsr" : :
			       "c" ( msr ), "d" ( high ), "a" ( low ) );
}

#endif /* _IPXE_MSR_H */
