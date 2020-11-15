#ifndef _DIGEST_TEST_H
#define _DIGEST_TEST_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/crypto.h>
#include <ipxe/test.h>

/** A digest test */
struct digest_test {
	/** Digest algorithm */
	struct digest_algorithm *digest;
	/** Test data */
	const void *data;
	/** Length of test data */
	size_t len;
	/** Expected digest value */
	const void *expected;
	/** Expected digest length */
	size_t expected_len;
};

/** Define inline test data */
#define DATA(...) { __VA_ARGS__ }

/** Define inline expected digest value */
#define DIGEST(...) { __VA_ARGS__ }

/**
 * Define a digest test
 *
 * @v name		Test name
 * @v DIGEST		Digest algorithm
 * @v DATA		Test data
 * @v EXPECTED		Expected digest value
 * @ret test		Digest test
 */
#define DIGEST_TEST( name, DIGEST, DATA, EXPECTED )			\
	static const uint8_t name ## _data[] = DATA;			\
	static const uint8_t name ## _expected[] = EXPECTED;		\
	static struct digest_test name = {				\
		.digest = DIGEST,					\
		.data = name ## _data,					\
		.len = sizeof ( name ## _data ),			\
		.expected = name ## _expected,				\
		.expected_len = sizeof ( name ## _expected ),		\
	};

/** Standard test vector: empty data */
#define DIGEST_EMPTY DATA()

/** Standard test vector: NIST string "abc"
 *
 * The NIST Cryptographic Toolkit examples for all digest algorithms
 * include a test vector which is the unterminated string
 *
 *   "abc"
 */
#define DIGEST_NIST_ABC							\
	DATA ( 0x61, 0x62, 0x63 )

/** Standard test vector: NIST string "abc...opq"
 *
 * The NIST Cryptographic Toolkit examples for all 32-bit digest
 * algorithms (SHA-1 and the SHA-256 family) include a test vector
 * which is the unterminated string
 *
 *   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 */
#define DIGEST_NIST_ABC_OPQ						\
	DATA ( 0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63,	\
	       0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67, 0x65, 0x66,	\
	       0x67, 0x68, 0x66, 0x67, 0x68, 0x69, 0x67, 0x68, 0x69,	\
	       0x6a, 0x68, 0x69, 0x6a, 0x6b, 0x69, 0x6a, 0x6b, 0x6c,	\
	       0x6a, 0x6b, 0x6c, 0x6d, 0x6b, 0x6c, 0x6d, 0x6e, 0x6c,	\
	       0x6d, 0x6e, 0x6f, 0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f,	\
	       0x70, 0x71 )

/** Standard test vector: NIST string "abc...stu"
 *
 * The NIST Cryptographic Toolkit examples for all 64-bit digest
 * algorithms (SHA-512 family) include a test vector which is the
 * unterminated string
 *
 *   "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
 *   "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
 */
#define DIGEST_NIST_ABC_STU						\
	DATA ( 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x62,	\
	       0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x63, 0x64,	\
	       0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x64, 0x65, 0x66,	\
	       0x67, 0x68, 0x69, 0x6a, 0x6b, 0x65, 0x66, 0x67, 0x68,	\
	       0x69, 0x6a, 0x6b, 0x6c, 0x66, 0x67, 0x68, 0x69, 0x6a,	\
	       0x6b, 0x6c, 0x6d, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,	\
	       0x6d, 0x6e, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,	\
	       0x6f, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,	\
	       0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x6b,	\
	       0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x6c, 0x6d,	\
	       0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x6d, 0x6e, 0x6f,	\
	       0x70, 0x71, 0x72, 0x73, 0x74, 0x6e, 0x6f, 0x70, 0x71,	\
	       0x72, 0x73, 0x74, 0x75 )

/**
 * Report a digest test result
 *
 * @v test		Digest test
 */
#define digest_ok(test) digest_okx ( test, __FILE__, __LINE__ )

extern void digest_okx ( struct digest_test *test, const char *file,
			 unsigned int line );
extern unsigned long digest_cost ( struct digest_algorithm *digest );

#endif /* _DIGEST_TEST_H */
