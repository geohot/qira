#ifndef _IPXE_BIGINT_H
#define _IPXE_BIGINT_H

/** @file
 *
 * Big integer support
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Define a big-integer type
 *
 * @v size		Number of elements
 * @ret bigint_t	Big integer type
 */
#define bigint_t( size )						\
	struct {							\
		bigint_element_t element[ (size) ];			\
	}

/**
 * Determine number of elements required for a big-integer type
 *
 * @v len		Maximum length of big integer, in bytes
 * @ret size		Number of elements
 */
#define bigint_required_size( len )					\
	( ( (len) + sizeof ( bigint_element_t ) - 1 ) /			\
	  sizeof ( bigint_element_t ) )

/**
 * Determine number of elements in big-integer type
 *
 * @v bigint		Big integer
 * @ret size		Number of elements
 */
#define bigint_size( bigint )						\
	( sizeof ( *(bigint) ) / sizeof ( (bigint)->element[0] ) )

/**
 * Initialise big integer
 *
 * @v value		Big integer to initialise
 * @v data		Raw data
 * @v len		Length of raw data
 */
#define bigint_init( value, data, len ) do {				\
	unsigned int size = bigint_size (value);			\
	assert ( (len) <= ( size * sizeof ( (value)->element[0] ) ) );	\
	bigint_init_raw ( (value)->element, size, (data), (len) );	\
	} while ( 0 )

/**
 * Finalise big integer
 *
 * @v value		Big integer to finalise
 * @v out		Output buffer
 * @v len		Length of output buffer
 */
#define bigint_done( value, out, len ) do {				\
	unsigned int size = bigint_size (value);			\
	bigint_done_raw ( (value)->element, size, (out), (len) );	\
	} while ( 0 )

/**
 * Add big integers
 *
 * @v addend		Big integer to add
 * @v value		Big integer to be added to
 */
#define bigint_add( addend, value ) do {				\
	unsigned int size = bigint_size (addend);			\
	bigint_add_raw ( (addend)->element, (value)->element, size );	\
	} while ( 0 )

/**
 * Subtract big integers
 *
 * @v subtrahend	Big integer to subtract
 * @v value		Big integer to be subtracted from
 */
#define bigint_subtract( subtrahend, value ) do {			\
	unsigned int size = bigint_size (subtrahend);			\
	bigint_subtract_raw ( (subtrahend)->element, (value)->element,	\
			      size );					\
	} while ( 0 )

/**
 * Rotate big integer left
 *
 * @v value		Big integer
 */
#define bigint_rol( value ) do {					\
	unsigned int size = bigint_size (value);			\
	bigint_rol_raw ( (value)->element, size );			\
	} while ( 0 )

/**
 * Rotate big integer right
 *
 * @v value		Big integer
 */
#define bigint_ror( value ) do {					\
	unsigned int size = bigint_size (value);			\
	bigint_ror_raw ( (value)->element, size );			\
	} while ( 0 )

/**
 * Test if big integer is equal to zero
 *
 * @v value		Big integer
 * @v size		Number of elements
 * @ret is_zero		Big integer is equal to zero
 */
#define bigint_is_zero( value ) ( {					\
	unsigned int size = bigint_size (value);			\
	bigint_is_zero_raw ( (value)->element, size ); } )

/**
 * Compare big integers
 *
 * @v value		Big integer
 * @v reference		Reference big integer
 * @ret geq		Big integer is greater than or equal to the reference
 */
#define bigint_is_geq( value, reference ) ( {				\
	unsigned int size = bigint_size (value);			\
	bigint_is_geq_raw ( (value)->element, (reference)->element,	\
			    size ); } )

/**
 * Test if bit is set in big integer
 *
 * @v value		Big integer
 * @v bit		Bit to test
 * @ret is_set		Bit is set
 */
#define bigint_bit_is_set( value, bit ) ( {				\
	unsigned int size = bigint_size (value);			\
	bigint_bit_is_set_raw ( (value)->element, size, bit ); } )

/**
 * Find highest bit set in big integer
 *
 * @v value		Big integer
 * @ret max_bit		Highest bit set + 1 (or 0 if no bits set)
 */
#define bigint_max_set_bit( value ) ( {					\
	unsigned int size = bigint_size (value);			\
	bigint_max_set_bit_raw ( (value)->element, size ); } )

/**
 * Grow big integer
 *
 * @v source		Source big integer
 * @v dest		Destination big integer
 */
#define bigint_grow( source, dest ) do {				\
	unsigned int source_size = bigint_size (source);		\
	unsigned int dest_size = bigint_size (dest);			\
	bigint_grow_raw ( (source)->element, source_size,		\
			  (dest)->element, dest_size );			\
	} while ( 0 )

/**
 * Shrink big integer
 *
 * @v source		Source big integer
 * @v dest		Destination big integer
 */
#define bigint_shrink( source, dest ) do {				\
	unsigned int source_size = bigint_size (source);		\
	unsigned int dest_size = bigint_size (dest);			\
	bigint_shrink_raw ( (source)->element, source_size,		\
			    (dest)->element, dest_size );		\
	} while ( 0 )

/**
 * Multiply big integers
 *
 * @v multiplicand	Big integer to be multiplied
 * @v multiplier	Big integer to be multiplied
 * @v result		Big integer to hold result
 */
#define bigint_multiply( multiplicand, multiplier, result ) do {	\
	unsigned int size = bigint_size (multiplicand);			\
	bigint_multiply_raw ( (multiplicand)->element,			\
			      (multiplier)->element, (result)->element,	\
			      size );					\
	} while ( 0 )

/**
 * Perform modular multiplication of big integers
 *
 * @v multiplicand	Big integer to be multiplied
 * @v multiplier	Big integer to be multiplied
 * @v modulus		Big integer modulus
 * @v result		Big integer to hold result
 * @v tmp		Temporary working space
 */
#define bigint_mod_multiply( multiplicand, multiplier, modulus,		\
			     result, tmp ) do {				\
	unsigned int size = bigint_size (multiplicand);			\
	bigint_mod_multiply_raw ( (multiplicand)->element,		\
				  (multiplier)->element,		\
				  (modulus)->element,			\
				  (result)->element, size, tmp );	\
	} while ( 0 )

/**
 * Calculate temporary working space required for moduluar multiplication
 *
 * @v modulus		Big integer modulus
 * @ret len		Length of temporary working space
 */
#define bigint_mod_multiply_tmp_len( modulus ) ( {			\
	unsigned int size = bigint_size (modulus);			\
	sizeof ( struct {						\
		bigint_t ( size * 2 ) temp_result;			\
		bigint_t ( size * 2 ) temp_modulus;			\
	} ); } )

/**
 * Perform modular exponentiation of big integers
 *
 * @v base		Big integer base
 * @v modulus		Big integer modulus
 * @v exponent		Big integer exponent
 * @v result		Big integer to hold result
 * @v tmp		Temporary working space
 */
#define bigint_mod_exp( base, modulus, exponent, result, tmp ) do {	\
	unsigned int size = bigint_size (base);				\
	unsigned int exponent_size = bigint_size (exponent);		\
	bigint_mod_exp_raw ( (base)->element, (modulus)->element,	\
			     (exponent)->element, (result)->element,	\
			     size, exponent_size, tmp );		\
	} while ( 0 )

/**
 * Calculate temporary working space required for moduluar exponentiation
 *
 * @v modulus		Big integer modulus
 * @v exponent		Big integer exponent
 * @ret len		Length of temporary working space
 */
#define bigint_mod_exp_tmp_len( modulus, exponent ) ( {			\
	unsigned int size = bigint_size (modulus);			\
	unsigned int exponent_size = bigint_size (exponent);		\
	size_t mod_multiply_len =					\
		bigint_mod_multiply_tmp_len (modulus);			\
	sizeof ( struct {						\
		bigint_t ( size ) temp_base;				\
		bigint_t ( exponent_size ) temp_exponent;		\
		uint8_t mod_multiply[mod_multiply_len];			\
	} ); } )

#include <bits/bigint.h>

void bigint_init_raw ( bigint_element_t *value0, unsigned int size,
		       const void *data, size_t len );
void bigint_done_raw ( const bigint_element_t *value0, unsigned int size,
		       void *out, size_t len );
void bigint_add_raw ( const bigint_element_t *addend0,
		      bigint_element_t *value0, unsigned int size );
void bigint_subtract_raw ( const bigint_element_t *subtrahend0,
			   bigint_element_t *value0, unsigned int size );
void bigint_rol_raw ( bigint_element_t *value0, unsigned int size );
void bigint_ror_raw ( bigint_element_t *value0, unsigned int size );
int bigint_is_zero_raw ( const bigint_element_t *value0, unsigned int size );
int bigint_is_geq_raw ( const bigint_element_t *value0,
			const bigint_element_t *reference0,
			unsigned int size );
int bigint_bit_is_set_raw ( const bigint_element_t *value0, unsigned int size,
			    unsigned int bit );
int bigint_max_set_bit_raw ( const bigint_element_t *value0,
			     unsigned int size );
void bigint_grow_raw ( const bigint_element_t *source0,
		       unsigned int source_size, bigint_element_t *dest0,
		       unsigned int dest_size );
void bigint_shrink_raw ( const bigint_element_t *source0,
			 unsigned int source_size, bigint_element_t *dest0,
			 unsigned int dest_size );
void bigint_multiply_raw ( const bigint_element_t *multiplicand0,
			   const bigint_element_t *multiplier0,
			   bigint_element_t *result0,
			   unsigned int size );
void bigint_mod_multiply_raw ( const bigint_element_t *multiplicand0,
			       const bigint_element_t *multiplier0,
			       const bigint_element_t *modulus0,
			       bigint_element_t *result0,
			       unsigned int size, void *tmp );
void bigint_mod_exp_raw ( const bigint_element_t *base0,
			  const bigint_element_t *modulus0,
			  const bigint_element_t *exponent0,
			  bigint_element_t *result0,
			  unsigned int size, unsigned int exponent_size,
			  void *tmp );

#endif /* _IPXE_BIGINT_H */
