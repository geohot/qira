/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * Peer Content Caching and Retrieval: Content Identification [MS-PCCRC] tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <ipxe/uaccess.h>
#include <ipxe/pccrc.h>
#include <ipxe/sha256.h>
#include <ipxe/sha512.h>
#include <ipxe/hmac.h>
#include <ipxe/test.h>

/** Define inline raw data */
#define DATA(...) { __VA_ARGS__ }

/**
 * Define an inline content range
 *
 * @v START		Start offset
 * @v END		End offset
 * @ret range		Content range
 */
#define RANGE( START, END ) { .start = START, .end = END }

/**
 * Define an inline trimmed content range
 *
 * @v START		Start offset
 * @v END		End offset
 * @ret trim		Trimmed content range
 */
#define TRIM( START, END ) { .start = START, .end = END }

/** A content information test */
struct peerdist_info_test {
	/** Raw content information */
	const void *data;
	/** Length of raw content information */
	size_t len;
	/** Expected digest algorithm */
	struct digest_algorithm *expected_digest;
	/** Expected digest size */
	size_t expected_digestsize;
	/** Expected content range */
	struct peerdist_range expected_range;
	/** Expected trimmed content range */
	struct peerdist_range expected_trim;
	/** Expected number of segments */
	unsigned int expected_segments;
};

/**
 * Define a content information test
 *
 * @v name		Test name
 * @v DATA		Raw content information
 * @v DIGEST		Expected digest algorithm
 * @v DIGESTSIZE	Expected digest size
 * @v RANGE		Expected content range
 * @v TRIM		Expected trimmer content range
 * @v SEGMENTS		Expected number of segments
 * @ret test		Content information test
 *
 * Raw content information can be obtained from PeerDist-capable web
 * servers using wget's "--header" option to inject the relevant
 * PeerDist headers.  For example:
 *
 *   wget --header "Accept-Encoding: peerdist" \
 *        --header "X-P2P-PeerDist: Version=1.0" \
 *	  http://peerdist.server.address/test.url -O - | xxd -i -c 11
 *
 * Version 1 content information can be retrieved using the headers:
 *
 *   Accept-Encoding: peerdist
 *   X-P2P-PeerDist: Version=1.0
 *
 * Version 2 content information can be retrieved (from compatible
 * servers) using the headers:
 *
 *   Accept-Encoding: peerdist
 *   X-P2P-PeerDist: Version=1.1
 *   X-P2P-PeerDistEx: MinContentInformation=2.0, MaxContentInformation=2.0
 */
#define PEERDIST_INFO_TEST( name, DATA, DIGEST, DIGESTSIZE, RANGE,	\
			    TRIM, SEGMENTS )				\
	static const uint8_t name ## _data[] = DATA;			\
	static struct peerdist_info_test name = {			\
		.data = name ## _data,					\
		.len = sizeof ( name ## _data ),			\
		.expected_digest = DIGEST,				\
		.expected_digestsize = DIGESTSIZE,			\
		.expected_range = RANGE,				\
		.expected_trim = TRIM,					\
		.expected_segments = SEGMENTS,				\
	}

/** A content information segment test */
struct peerdist_info_segment_test {
	/** Segment index */
	unsigned int index;
	/** Expected content range */
	struct peerdist_range expected_range;
	/** Expected number of blocks */
	unsigned int expected_blocks;
	/** Expected block size */
	size_t expected_blksize;
	/** Expected segment hash of data */
	uint8_t expected_hash[PEERDIST_DIGEST_MAX_SIZE];
	/** Expected segment secret */
	uint8_t expected_secret[PEERDIST_DIGEST_MAX_SIZE];
	/** Expected segment identifier */
	uint8_t expected_id[PEERDIST_DIGEST_MAX_SIZE];
};

/**
 * Define a content information segment test
 *
 * @v name		Test name
 * @v INDEX		Segment index
 * @v RANGE		Expected content range
 * @v BLOCKS		Expected number of blocks
 * @v BLKSIZE		Expected block size
 * @v HASH		Expected segment hash of data
 * @v SECRET		Expected segment secret
 * @v ID		Expected segment identifier
 * @ret test		Content information segment test
 */
#define PEERDIST_INFO_SEGMENT_TEST( name, INDEX, RANGE, BLOCKS,		\
				    BLKSIZE, HASH, SECRET, ID )		\
	static struct peerdist_info_segment_test name = {		\
		.index = INDEX,						\
		.expected_range = RANGE,				\
		.expected_blocks = BLOCKS,				\
		.expected_blksize = BLKSIZE,				\
		.expected_hash = HASH,					\
		.expected_secret = SECRET,				\
		.expected_id = ID,					\
	}

/** A content information block test */
struct peerdist_info_block_test {
	/** Block index */
	unsigned int index;
	/** Expected content range */
	struct peerdist_range expected_range;
	/** Expected trimmed content range */
	struct peerdist_range expected_trim;
	/** Expected hash of data */
	uint8_t expected_hash[PEERDIST_DIGEST_MAX_SIZE];
};

/**
 * Define a content information block test
 *
 * @v name		Test name
 * @v INDEX		Block index
 * @v RANGE		Expected content range
 * @v TRIM		Expected trimmed content range
 * @v HASH		Expected hash of data
 * @ret test		Content information block test
 */
#define PEERDIST_INFO_BLOCK_TEST( name, INDEX, RANGE, TRIM, HASH )	\
	static struct peerdist_info_block_test name = {			\
		.index = INDEX,						\
		.expected_range = RANGE,				\
		.expected_trim = TRIM,					\
		.expected_hash = HASH,					\
	}

/**
 * Define a server passphrase
 *
 * @v name		Server passphrase name
 * @v DATA		Raw server passphrase
 *
 * The server passphrase can be exported from a Windows BranchCache
 * server using the command:
 *
 *   netsh branchcache exportkey exported.key somepassword
 *
 * and this encrypted exported key can be decrypted using the
 * oSSL_key_dx or mcrypt_key_dx utilities found in the (prototype)
 * Prequel project at https://fedorahosted.org/prequel/ :
 *
 *   oSSL_key_dx exported.key somepassword
 *     or
 *   mcrypt_key_dx exported.key somepassword
 *
 * Either command will display both the server passphrase and the
 * "Server Secret".  Note that this latter is the version 1 server
 * secret (i.e. the SHA-256 of the server passphrase); the
 * corresponding version 2 server secret can be obtained by
 * calculating the truncated SHA-512 of the server passphrase.
 *
 * We do not know the server passphrase during normal operation.  We
 * use it in the self-tests only to check for typos and other errors
 * in the test vectors, by checking that the segment secret defined in
 * a content information segment test is as expected.
 */
#define SERVER_PASSPHRASE( name, DATA )					\
	static uint8_t name[] = DATA

/** Server passphrase used for these test vectors */
SERVER_PASSPHRASE ( passphrase,
      DATA ( 0x2a, 0x3d, 0x73, 0xeb, 0x43, 0x5e, 0x9f, 0x2b, 0x8a, 0x34, 0x42,
	     0x67, 0xe7, 0x46, 0x7a, 0x3c, 0x73, 0x85, 0xc6, 0xe0, 0x55, 0xe2,
	     0xb4, 0xd3, 0x0d, 0xfe, 0xc7, 0xc3, 0x8b, 0x0e, 0xd7, 0x2c ) );

/** IIS logo (iis-85.png) content information version 1 */
PEERDIST_INFO_TEST ( iis_85_png_v1,
	DATA ( 0x00, 0x01, 0x0c, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	       0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	       0x00, 0x00, 0x00, 0x00, 0x7e, 0x85, 0x01, 0x00, 0x00, 0x00, 0x01,
	       0x00, 0xd8, 0xd9, 0x76, 0x35, 0x4a, 0x48, 0x72, 0xe9, 0x25, 0x76,
	       0x18, 0x03, 0xf4, 0x58, 0xd9, 0xda, 0xaa, 0x67, 0xf8, 0xe3, 0x1c,
	       0x63, 0x0f, 0xb7, 0x4e, 0x6a, 0x31, 0x2e, 0xf8, 0xa2, 0x5a, 0xba,
	       0x11, 0xaf, 0xc0, 0xd7, 0x94, 0x92, 0x43, 0xf9, 0x4f, 0x9c, 0x1f,
	       0xab, 0x35, 0xd9, 0xfd, 0x1e, 0x33, 0x1f, 0xcf, 0x78, 0x11, 0xa2,
	       0xe0, 0x1d, 0x35, 0x87, 0xb3, 0x8d, 0x77, 0x0a, 0x29, 0xe2, 0x02,
	       0x00, 0x00, 0x00, 0x73, 0xc1, 0x8a, 0xb8, 0x54, 0x91, 0x10, 0xf8,
	       0xe9, 0x0e, 0x71, 0xbb, 0xc3, 0xab, 0x2a, 0xa8, 0xc4, 0x4d, 0x13,
	       0xf4, 0x92, 0x94, 0x99, 0x25, 0x5b, 0x66, 0x0f, 0x24, 0xec, 0x77,
	       0x80, 0x0b, 0x97, 0x4b, 0xdd, 0x65, 0x56, 0x7f, 0xde, 0xec, 0xcd,
	       0xaf, 0xe4, 0x57, 0xa9, 0x50, 0x3b, 0x45, 0x48, 0xf6, 0x6e, 0xd3,
	       0xb1, 0x88, 0xdc, 0xfd, 0xa0, 0xac, 0x38, 0x2b, 0x09, 0x71, 0x1a,
	       0xcc ),
	&sha256_algorithm, 32, RANGE ( 0, 99710 ), TRIM ( 0, 99710 ), 1 );

/** IIS logo (iis-85.png) content information version 1 segment 0 */
PEERDIST_INFO_SEGMENT_TEST ( iis_85_png_v1_s0, 0,
	RANGE ( 0, 99710 ), 2, 65536,
	DATA ( 0xd8, 0xd9, 0x76, 0x35, 0x4a, 0x48, 0x72, 0xe9, 0x25, 0x76, 0x18,
	       0x03, 0xf4, 0x58, 0xd9, 0xda, 0xaa, 0x67, 0xf8, 0xe3, 0x1c, 0x63,
	       0x0f, 0xb7, 0x4e, 0x6a, 0x31, 0x2e, 0xf8, 0xa2, 0x5a, 0xba ),
	DATA ( 0x11, 0xaf, 0xc0, 0xd7, 0x94, 0x92, 0x43, 0xf9, 0x4f, 0x9c, 0x1f,
	       0xab, 0x35, 0xd9, 0xfd, 0x1e, 0x33, 0x1f, 0xcf, 0x78, 0x11, 0xa2,
	       0xe0, 0x1d, 0x35, 0x87, 0xb3, 0x8d, 0x77, 0x0a, 0x29, 0xe2 ),
	DATA ( 0x49, 0x1b, 0x21, 0x7d, 0xbe, 0xe2, 0xb5, 0xf1, 0x2c, 0xa7, 0x9b,
	       0x01, 0x5e, 0x06, 0xf4, 0xbb, 0xe6, 0x4f, 0x97, 0x45, 0xba, 0xd7,
	       0x86, 0x7a, 0xef, 0x17, 0xde, 0x59, 0x92, 0x7e, 0xdc, 0xe9 ) );

/** IIS logo (iis-85.png) content information version 1 segment 0 block 0 */
PEERDIST_INFO_BLOCK_TEST ( iis_85_png_v1_s0_b0, 0,
	RANGE ( 0, 65536 ),
	TRIM ( 0, 65536 ),
	DATA ( 0x73, 0xc1, 0x8a, 0xb8, 0x54, 0x91, 0x10, 0xf8, 0xe9, 0x0e, 0x71,
	       0xbb, 0xc3, 0xab, 0x2a, 0xa8, 0xc4, 0x4d, 0x13, 0xf4, 0x92, 0x94,
	       0x99, 0x25, 0x5b, 0x66, 0x0f, 0x24, 0xec, 0x77, 0x80, 0x0b ) );

/** IIS logo (iis-85.png) content information version 1 segment 0 block 1 */
PEERDIST_INFO_BLOCK_TEST ( iis_85_png_v1_s0_b1, 1,
	RANGE ( 65536, 99710 ),
	TRIM ( 65536, 99710 ),
	DATA ( 0x97, 0x4b, 0xdd, 0x65, 0x56, 0x7f, 0xde, 0xec, 0xcd, 0xaf, 0xe4,
	       0x57, 0xa9, 0x50, 0x3b, 0x45, 0x48, 0xf6, 0x6e, 0xd3, 0xb1, 0x88,
	       0xdc, 0xfd, 0xa0, 0xac, 0x38, 0x2b, 0x09, 0x71, 0x1a, 0xcc ) );

/** IIS logo (iis-85.png) content information version 2 */
PEERDIST_INFO_TEST ( iis_85_png_v2,
	DATA ( 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	       0x00, 0x00, 0x88, 0x00, 0x00, 0x99, 0xde, 0xe0, 0xd0, 0xc3, 0x58,
	       0xe2, 0x68, 0x4b, 0x62, 0x33, 0x0d, 0x32, 0xb5, 0xf1, 0x97, 0x87,
	       0x24, 0xa0, 0xd0, 0xa5, 0x2b, 0xdc, 0x5e, 0x78, 0x1f, 0xae, 0x71,
	       0xff, 0x57, 0xa8, 0xbe, 0x3d, 0xd4, 0x58, 0x03, 0x7e, 0xd4, 0x04,
	       0x11, 0x6b, 0xb6, 0x16, 0xd9, 0xb1, 0x41, 0x16, 0x08, 0x85, 0x20,
	       0xc4, 0x7c, 0xdc, 0x50, 0xab, 0xce, 0xa3, 0xfa, 0xe1, 0x88, 0xa9,
	       0x8e, 0xa2, 0x2d, 0xf3, 0xc0, 0x00, 0x00, 0xeb, 0xa0, 0x33, 0x81,
	       0xd0, 0xd0, 0xcb, 0x74, 0xf4, 0xb6, 0x13, 0xd8, 0x21, 0x0f, 0x37,
	       0xf0, 0x02, 0xa0, 0x6f, 0x39, 0x10, 0x58, 0x60, 0x96, 0xa1, 0x30,
	       0xd3, 0x43, 0x98, 0xc0, 0x8e, 0x66, 0xd7, 0xbc, 0xb8, 0xb6, 0xeb,
	       0x77, 0x83, 0xe4, 0xf8, 0x07, 0x64, 0x7b, 0x63, 0xf1, 0x46, 0xb5,
	       0x2f, 0x4a, 0xc8, 0x9c, 0xcc, 0x7a, 0xbf, 0x5f, 0xa1, 0x1a, 0xca,
	       0xfc, 0x2a, 0xcf, 0x50, 0x28, 0x58, 0x6c ),
	&sha512_algorithm, 32, RANGE ( 0, 99710 ), TRIM ( 0, 99710 ), 2 );

/** IIS logo (iis-85.png) content information version 2 segment 0 */
PEERDIST_INFO_SEGMENT_TEST ( iis_85_png_v2_s0, 0,
	RANGE ( 0, 39390 ), 1, 39390,
	DATA ( 0xe0, 0xd0, 0xc3, 0x58, 0xe2, 0x68, 0x4b, 0x62, 0x33, 0x0d, 0x32,
	       0xb5, 0xf1, 0x97, 0x87, 0x24, 0xa0, 0xd0, 0xa5, 0x2b, 0xdc, 0x5e,
	       0x78, 0x1f, 0xae, 0x71, 0xff, 0x57, 0xa8, 0xbe, 0x3d, 0xd4 ),
	DATA ( 0x58, 0x03, 0x7e, 0xd4, 0x04, 0x11, 0x6b, 0xb6, 0x16, 0xd9, 0xb1,
	       0x41, 0x16, 0x08, 0x85, 0x20, 0xc4, 0x7c, 0xdc, 0x50, 0xab, 0xce,
	       0xa3, 0xfa, 0xe1, 0x88, 0xa9, 0x8e, 0xa2, 0x2d, 0xf3, 0xc0 ),
	DATA ( 0x33, 0x71, 0xbb, 0xea, 0xdd, 0xb6, 0x23, 0x53, 0xad, 0xce, 0xf9,
	       0x70, 0xa0, 0x6f, 0xdf, 0x65, 0x00, 0x1e, 0x04, 0x21, 0xf4, 0xc7,
	       0x10, 0x82, 0x76, 0xb0, 0xc3, 0x7a, 0x9f, 0x9e, 0xc1, 0x0f ) );

/** IIS logo (iis-85.png) content information version 2 segment 0 block 0 */
PEERDIST_INFO_BLOCK_TEST ( iis_85_png_v2_s0_b0, 0,
	RANGE ( 0, 39390 ),
	TRIM ( 0, 39390 ),
	DATA ( 0xe0, 0xd0, 0xc3, 0x58, 0xe2, 0x68, 0x4b, 0x62, 0x33, 0x0d, 0x32,
	       0xb5, 0xf1, 0x97, 0x87, 0x24, 0xa0, 0xd0, 0xa5, 0x2b, 0xdc, 0x5e,
	       0x78, 0x1f, 0xae, 0x71, 0xff, 0x57, 0xa8, 0xbe, 0x3d, 0xd4 ) );

/** IIS logo (iis-85.png) content information version 2 segment 1 */
PEERDIST_INFO_SEGMENT_TEST ( iis_85_png_v2_s1, 1,
	RANGE ( 39390, 99710 ), 1, 60320,
	DATA ( 0x33, 0x81, 0xd0, 0xd0, 0xcb, 0x74, 0xf4, 0xb6, 0x13, 0xd8, 0x21,
	       0x0f, 0x37, 0xf0, 0x02, 0xa0, 0x6f, 0x39, 0x10, 0x58, 0x60, 0x96,
	       0xa1, 0x30, 0xd3, 0x43, 0x98, 0xc0, 0x8e, 0x66, 0xd7, 0xbc ),
	DATA ( 0xb8, 0xb6, 0xeb, 0x77, 0x83, 0xe4, 0xf8, 0x07, 0x64, 0x7b, 0x63,
	       0xf1, 0x46, 0xb5, 0x2f, 0x4a, 0xc8, 0x9c, 0xcc, 0x7a, 0xbf, 0x5f,
	       0xa1, 0x1a, 0xca, 0xfc, 0x2a, 0xcf, 0x50, 0x28, 0x58, 0x6c ),
	DATA ( 0xd7, 0xe9, 0x24, 0x42, 0x5e, 0x8f, 0x4f, 0x88, 0xf0, 0x1d, 0xc6,
	       0xa9, 0xbb, 0x1b, 0xc3, 0x7b, 0xe1, 0x13, 0xec, 0x79, 0x17, 0xc7,
	       0x45, 0xd4, 0x96, 0x5c, 0x2b, 0x55, 0xfa, 0x16, 0x3a, 0x6e ) );

/** IIS logo (iis-85.png) content information version 2 segment 1 block 0 */
PEERDIST_INFO_BLOCK_TEST ( iis_85_png_v2_s1_b0, 0,
	RANGE ( 39390, 99710 ),
	TRIM ( 39390, 99710 ),
	DATA ( 0x33, 0x81, 0xd0, 0xd0, 0xcb, 0x74, 0xf4, 0xb6, 0x13, 0xd8, 0x21,
	       0x0f, 0x37, 0xf0, 0x02, 0xa0, 0x6f, 0x39, 0x10, 0x58, 0x60, 0x96,
	       0xa1, 0x30, 0xd3, 0x43, 0x98, 0xc0, 0x8e, 0x66, 0xd7, 0xbc ) );

/**
 * Report content information test result
 *
 * @v test		Content information test
 * @v info		Content information to fill in
 * @v file		Test code file
 * @v line		Test code line
 */
static void peerdist_info_okx ( struct peerdist_info_test *test,
				struct peerdist_info *info,
				const char *file, unsigned int line ) {

	/* Parse content information */
	okx ( peerdist_info ( virt_to_user ( test->data ), test->len,
			      info ) == 0, file, line );

	/* Verify content information */
	okx ( info->raw.data == virt_to_user ( test->data ), file, line );
	okx ( info->raw.len == test->len, file, line );
	okx ( info->digest == test->expected_digest, file, line );
	okx ( info->digestsize == test->expected_digestsize, file, line );
	okx ( info->range.start == test->expected_range.start, file, line );
	okx ( info->range.end == test->expected_range.end, file, line );
	okx ( info->trim.start == test->expected_trim.start, file, line );
	okx ( info->trim.end == test->expected_trim.end, file, line );
	okx ( info->trim.start >= info->range.start, file, line );
	okx ( info->trim.end <= info->range.end, file, line );
	okx ( info->segments == test->expected_segments, file, line );
}
#define peerdist_info_ok( test, info ) \
	peerdist_info_okx ( test, info, __FILE__, __LINE__ )

/**
 * Report content information segment test result
 *
 * @v test		Content information segment test
 * @v info		Content information
 * @v segment		Segment information to fill in
 * @v file		Test code file
 * @v line		Test code line
 */
static void peerdist_info_segment_okx ( struct peerdist_info_segment_test *test,
					const struct peerdist_info *info,
					struct peerdist_info_segment *segment,
					const char *file, unsigned int line ) {
	size_t digestsize = info->digestsize;

	/* Parse content information segment */
	okx ( peerdist_info_segment ( info, segment, test->index ) == 0,
	      file, line );

	/* Verify content information segment */
	okx ( segment->info == info, file, line );
	okx ( segment->index == test->index, file, line );
	okx ( segment->range.start == test->expected_range.start, file, line );
	okx ( segment->range.end == test->expected_range.end, file, line );
	okx ( segment->blocks == test->expected_blocks, file, line );
	okx ( segment->blksize == test->expected_blksize, file, line );
	okx ( memcmp ( segment->hash, test->expected_hash,
		       digestsize ) == 0, file, line );
	okx ( memcmp ( segment->secret, test->expected_secret,
		       digestsize ) == 0, file, line );
	okx ( memcmp ( segment->id, test->expected_id,
		       digestsize ) == 0, file, line );
}
#define peerdist_info_segment_ok( test, info, segment ) \
	peerdist_info_segment_okx ( test, info, segment, __FILE__, __LINE__ )

/**
 * Report content information block test result
 *
 * @v test		Content information block test
 * @v segment		Segment information
 * @v block		Block information to fill in
 * @v file		Test code file
 * @v line		Test code line
 */
static void
peerdist_info_block_okx ( struct peerdist_info_block_test *test,
			  const struct peerdist_info_segment *segment,
			  struct peerdist_info_block *block,
			  const char *file, unsigned int line ) {
	const struct peerdist_info *info = segment->info;
	size_t digestsize = info->digestsize;

	/* Parse content information block */
	okx ( peerdist_info_block ( segment, block, test->index ) == 0,
	      file, line );

	/* Verify content information block */
	okx ( block->segment == segment, file, line );
	okx ( block->index == test->index, file, line );
	okx ( block->range.start == test->expected_range.start, file, line );
	okx ( block->range.end == test->expected_range.end, file, line );
	okx ( block->trim.start == test->expected_trim.start, file, line );
	okx ( block->trim.end == test->expected_trim.end, file, line );
	okx ( memcmp ( block->hash, test->expected_hash,
		       digestsize ) == 0, file, line );
}
#define peerdist_info_block_ok( test, segment, block ) \
	peerdist_info_block_okx ( test, segment, block, __FILE__, __LINE__ )

/**
 * Report server passphrase test result
 *
 * @v test		Content information segment test
 * @v info		Content information
 * @v pass		Server passphrase
 * @v pass_len		Length of server passphrase
 * @v file		Test code file
 * @v line		Test code line
 */
static void
peerdist_info_passphrase_okx ( struct peerdist_info_segment_test *test,
			       const struct peerdist_info *info,
			       uint8_t *pass, size_t pass_len,
			       const char *file, unsigned int line ) {
	struct digest_algorithm *digest = info->digest;
	uint8_t ctx[digest->ctxsize];
	uint8_t secret[digest->digestsize];
	uint8_t expected[digest->digestsize];
	size_t digestsize = info->digestsize;
	size_t secretsize = digestsize;

	/* Calculate server secret */
	digest_init ( digest, ctx );
	digest_update ( digest, ctx, pass, pass_len );
	digest_final ( digest, ctx, secret );

	/* Calculate expected segment secret */
	hmac_init ( digest, ctx, secret, &secretsize );
	assert ( secretsize == digestsize );
	hmac_update ( digest, ctx, test->expected_hash, digestsize );
	hmac_final ( digest, ctx, secret, &secretsize, expected );
	assert ( secretsize == digestsize );

	/* Verify segment secret */
	okx ( memcmp ( test->expected_secret, expected, digestsize ) == 0,
	      file, line );
}
#define peerdist_info_passphrase_ok( test, info, pass, pass_len )	\
	peerdist_info_passphrase_okx ( test, info, pass, pass_len,	\
				       __FILE__, __LINE__ )

/**
 * Perform content information self-tests
 *
 */
static void peerdist_info_test_exec ( void ) {
	struct peerdist_info info;
	struct peerdist_info_segment segment;
	struct peerdist_info_block block;

	/* IIS logo (iis-85.png) content information version 1 */
	peerdist_info_ok ( &iis_85_png_v1, &info );
	peerdist_info_passphrase_ok ( &iis_85_png_v1_s0, &info,
				      passphrase, sizeof ( passphrase ) );
	peerdist_info_segment_ok ( &iis_85_png_v1_s0, &info, &segment );
	peerdist_info_block_ok ( &iis_85_png_v1_s0_b0, &segment, &block );
	peerdist_info_block_ok ( &iis_85_png_v1_s0_b1, &segment, &block );

	/* IIS logo (iis-85.png) content information version 2 */
	peerdist_info_ok ( &iis_85_png_v2, &info );
	peerdist_info_passphrase_ok ( &iis_85_png_v2_s0, &info,
				      passphrase, sizeof ( passphrase ) );
	peerdist_info_segment_ok ( &iis_85_png_v2_s0, &info, &segment );
	peerdist_info_block_ok ( &iis_85_png_v2_s0_b0, &segment, &block );
	peerdist_info_passphrase_ok ( &iis_85_png_v2_s1, &info,
				      passphrase, sizeof ( passphrase ) );
	peerdist_info_segment_ok ( &iis_85_png_v2_s1, &info, &segment );
	peerdist_info_block_ok ( &iis_85_png_v2_s1_b0, &segment, &block );
}

/** Content information self-test */
struct self_test peerdist_info_test __self_test = {
	.name = "pccrc",
	.exec = peerdist_info_test_exec,
};
