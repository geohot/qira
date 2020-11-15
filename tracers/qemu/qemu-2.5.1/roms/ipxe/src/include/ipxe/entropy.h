#ifndef _IPXE_ENTROPY_H
#define _IPXE_ENTROPY_H

/** @file
 *
 * Entropy source
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <ipxe/api.h>
#include <ipxe/hash_df.h>
#include <ipxe/sha256.h>
#include <config/entropy.h>

/**
 * Calculate static inline entropy API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define ENTROPY_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( ENTROPY_PREFIX_ ## _subsys, _api_func )

/**
 * Provide a entropy API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_ENTROPY( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( ENTROPY_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline entropy API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_ENTROPY_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( ENTROPY_PREFIX_ ## _subsys, _api_func )

/** A noise sample */
typedef uint8_t noise_sample_t;

/** An entropy sample */
typedef uint8_t entropy_sample_t;

/* Include all architecture-independent entropy API headers */
#include <ipxe/null_entropy.h>
#include <ipxe/efi/efi_entropy.h>
#include <ipxe/linux/linux_entropy.h>

/* Include all architecture-dependent entropy API headers */
#include <bits/entropy.h>

/**
 * Enable entropy gathering
 *
 * @ret rc		Return status code
 */
int entropy_enable ( void );

/**
 * Disable entropy gathering
 *
 */
void entropy_disable ( void );

/**
 * min-entropy per sample
 *
 * @ret min_entropy	min-entropy of each sample
 *
 * min-entropy is defined in ANS X9.82 Part 1-2006 Section 8.3 and in
 * NIST SP 800-90 Appendix C.3 as
 *
 *    H_min = -log2 ( p_max )
 *
 * where p_max is the probability of the most likely sample value.
 *
 * This must be a compile-time constant.
 */
double min_entropy_per_sample ( void );

/**
 * Get noise sample
 *
 * @ret noise		Noise sample
 * @ret rc		Return status code
 *
 * This is the GetNoise function defined in ANS X9.82 Part 2
 * (October 2011 Draft) Section 6.5.2.
 */
int get_noise ( noise_sample_t *noise );

extern int get_entropy_input_tmp ( unsigned int num_samples,
				   uint8_t *tmp, size_t tmp_len );

/** Use SHA-256 as the underlying hash algorithm for Hash_df
 *
 * Hash_df using SHA-256 is an Approved algorithm in ANS X9.82.
 */
#define entropy_hash_df_algorithm sha256_algorithm

/** Underlying hash algorithm output length (in bytes) */
#define ENTROPY_HASH_DF_OUTLEN_BYTES SHA256_DIGEST_SIZE

/**
 * Obtain entropy input
 *
 * @v min_entropy_bits	Minimum amount of entropy, in bits
 * @v data		Data buffer
 * @v min_len		Minimum length of entropy input, in bytes
 * @v max_len		Maximum length of entropy input, in bytes
 * @ret len		Length of entropy input, in bytes, or negative error
 *
 * This is the implementation of the Get_entropy_input function (using
 * an entropy source as the source of entropy input and condensing
 * each entropy source output after each GetEntropy call) as defined
 * in ANS X9.82 Part 4 (April 2011 Draft) Section 13.3.4.2.
 *
 * To minimise code size, the number of samples required is calculated
 * at compilation time.
 */
static inline __attribute__ (( always_inline )) int
get_entropy_input ( unsigned int min_entropy_bits, void *data, size_t min_len,
		    size_t max_len ) {
	size_t tmp_len = ( ( ( min_entropy_bits * 2 ) + 7 ) / 8 );
	uint8_t tmp_buf[ tmp_len ];
	uint8_t *tmp = ( ( tmp_len > max_len ) ? tmp_buf : data );
	double min_samples;
	unsigned int num_samples;
	unsigned int n;
	int rc;

	/* Sanity checks */
	linker_assert ( ( min_entropy_per_sample() <=
			  ( 8 * sizeof ( noise_sample_t ) ) ),
			min_entropy_per_sample_is_impossibly_high );
	linker_assert ( ( min_entropy_bits <= ( 8 * max_len ) ),
			entropy_buffer_too_small );

	/* Round up minimum entropy to an integral number of bytes */
	min_entropy_bits = ( ( min_entropy_bits + 7 ) & ~7 );

	/* Calculate number of samples required to contain sufficient entropy */
	min_samples = ( ( min_entropy_bits * 1.0 ) / min_entropy_per_sample() );

	/* Round up to a whole number of samples.  We don't have the
	 * ceil() function available, so do the rounding by hand.
	 */
	num_samples = min_samples;
	if ( num_samples < min_samples )
		num_samples++;
	linker_assert ( ( num_samples >= min_samples ), rounding_error );

	/* Floating-point operations are not allowed in iPXE since we
	 * never set up a suitable environment.  Abort the build
	 * unless the calculated number of samples is a compile-time
	 * constant.
	 */
	linker_assert ( __builtin_constant_p ( num_samples ),
			num_samples_not_constant );

	/* (Unnumbered).  The output length of the hash function shall
	 * meet or exceed the security strength indicated by the
	 * min_entropy parameter.
	 */
	linker_assert ( ( ( 8 * ENTROPY_HASH_DF_OUTLEN_BYTES ) >=
			  min_entropy_bits ), hash_df_algorithm_too_weak );

	/* 1.  If ( min_length > max_length ), then return ( FAILURE, Null ) */
	linker_assert ( ( min_len <= max_len ), min_len_greater_than_max_len );

	/* 2.  n = 2 * min_entropy */
	n = ( 2 * min_entropy_bits );

	/* 3.  entropy_total = 0
	 * 4.  tmp = a fixed n-bit value, such as 0^n
	 * 5.  While ( entropy_total < min_entropy )
	 *     5.1.  ( status, entropy_bitstring, assessed_entropy )
	 *           = GetEntropy()
	 *     5.2.  If status indicates an error, return ( status, Null )
	 *     5.3.  nonce = MakeNextNonce()
	 *     5.4.  tmp = tmp XOR df ( ( nonce || entropy_bitstring ), n )
	 *     5.5.  entropy_total = entropy_total + assessed_entropy
	 *
	 * (The implementation of these steps is inside the function
	 * get_entropy_input_tmp().)
	 */
	linker_assert ( __builtin_constant_p ( tmp_len ),
			tmp_len_not_constant );
	linker_assert ( ( n == ( 8 * tmp_len ) ), tmp_len_mismatch );
	if ( ( rc = get_entropy_input_tmp ( num_samples, tmp, tmp_len ) ) != 0 )
		return rc;

	/* 6.  If ( n < min_length ), then tmp = tmp || 0^(min_length-n)
	 * 7.  If ( n > max_length ), then tmp = df ( tmp, max_length )
	 * 8.  Return ( SUCCESS, tmp )
	 */
	if ( tmp_len < min_len ) {
		/* (Data is already in-place.) */
		linker_assert ( ( data == tmp ), data_not_inplace );
		memset ( ( data + tmp_len ), 0, ( min_len - tmp_len ) );
		return min_len;
	} else if ( tmp_len > max_len ) {
		linker_assert ( ( tmp == tmp_buf ), data_inplace );
		hash_df ( &entropy_hash_df_algorithm, tmp, tmp_len,
			  data, max_len );
		return max_len;
	} else {
		/* (Data is already in-place.) */
		linker_assert ( ( data == tmp ), data_not_inplace );
		return tmp_len;
	}
}

#endif /* _IPXE_ENTROPY_H */
