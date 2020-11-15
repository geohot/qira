/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
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
 * DEFLATE tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ipxe/deflate.h>
#include <ipxe/test.h>

/** A DEFLATE test */
struct deflate_test {
	/** Compression format */
	enum deflate_format format;
	/** Compressed data */
	const void *compressed;
	/** Length of compressed data */
	size_t compressed_len;
	/** Expected uncompressed data */
	const void *expected;
	/** Length of expected uncompressed data */
	size_t expected_len;
};

/** A DEFLATE fragment list */
struct deflate_test_fragments {
	/** Fragment lengths */
	size_t len[8];
};

/** Define inline data */
#define DATA(...) { __VA_ARGS__ }

/** Define a DEFLATE test */
#define DEFLATE( name, FORMAT, COMPRESSED, EXPECTED )			\
	static const uint8_t name ## _compressed[] = COMPRESSED;	\
	static const uint8_t name ## _expected[] = EXPECTED;		\
	static struct deflate_test name = {				\
		.format = FORMAT,					\
		.compressed = name ## _compressed,			\
		.compressed_len = sizeof ( name ## _compressed ),	\
		.expected = name ## _expected,				\
		.expected_len = sizeof ( name ## _expected ),		\
	};

/* Empty file, no compression */
DEFLATE ( empty_literal, DEFLATE_RAW,
	  DATA ( 0x01, 0x00, 0x00, 0xff, 0xff ), DATA() );

/* "iPXE" string, no compression */
DEFLATE ( literal, DEFLATE_RAW,
	  DATA ( 0x01, 0x04, 0x00, 0xfb, 0xff, 0x69, 0x50, 0x58, 0x45 ),
	  DATA ( 0x69, 0x50, 0x58, 0x45 ) );

/* "iPXE" string, no compression, split into two literals */
DEFLATE ( split_literal, DEFLATE_RAW,
	  DATA ( 0x00, 0x02, 0x00, 0xfd, 0xff, 0x69, 0x50, 0x01, 0x02, 0x00,
		 0xfd, 0xff, 0x58, 0x45 ),
	  DATA ( 0x69, 0x50, 0x58, 0x45 ) );

/* Empty file */
DEFLATE ( empty, DEFLATE_RAW, DATA ( 0x03, 0x00 ), DATA() );

/* "Hello world" */
DEFLATE ( hello_world, DEFLATE_RAW,
	  DATA ( 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca,
		 0x49, 0x01, 0x00 ),
	  DATA ( 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c,
		 0x64 ) );

/* "Hello hello world" */
DEFLATE ( hello_hello_world, DEFLATE_RAW,
	  DATA ( 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x00, 0x93, 0xe5,
		 0xf9, 0x45, 0x39, 0x29, 0x00 ),
	  DATA ( 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c, 0x6c,
		 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64 ) );

/* "This specification defines a lossless compressed data format" */
DEFLATE ( rfc_sentence, DEFLATE_RAW,
	  DATA ( 0x0d, 0xc6, 0xdb, 0x09, 0x00, 0x21, 0x0c, 0x04, 0xc0, 0x56,
		 0xb6, 0x28, 0x1b, 0x08, 0x79, 0x70, 0x01, 0x35, 0xe2, 0xa6,
		 0x7f, 0xce, 0xf9, 0x9a, 0xf1, 0x25, 0xc1, 0xe3, 0x9a, 0x91,
		 0x2a, 0x9d, 0xb5, 0x61, 0x1e, 0xb9, 0x9d, 0x10, 0xcc, 0x22,
		 0xa7, 0x93, 0xd0, 0x5a, 0xe7, 0xbe, 0xb8, 0xc1, 0xa4, 0x05,
		 0x51, 0x77, 0x49, 0xff ),
	  DATA ( 0x54, 0x68, 0x69, 0x73, 0x20, 0x73, 0x70, 0x65, 0x63, 0x69,
		 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x64,
		 0x65, 0x66, 0x69, 0x6e, 0x65, 0x73, 0x20, 0x61, 0x20, 0x6c,
		 0x6f, 0x73, 0x73, 0x6c, 0x65, 0x73, 0x73, 0x20, 0x63, 0x6f,
		 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x20, 0x64,
		 0x61, 0x74, 0x61, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74 ) );

/* "ZLIB Compressed Data Format Specification" */
DEFLATE ( zlib, DEFLATE_ZLIB,
	  DATA ( 0x78, 0x01, 0x8b, 0xf2, 0xf1, 0x74, 0x52, 0x70, 0xce, 0xcf,
		 0x2d, 0x28, 0x4a, 0x2d, 0x2e, 0x4e, 0x4d, 0x51, 0x70, 0x49,
		 0x2c, 0x49, 0x54, 0x70, 0xcb, 0x2f, 0xca, 0x4d, 0x2c, 0x51,
		 0x08, 0x2e, 0x48, 0x4d, 0xce, 0x4c, 0xcb, 0x4c, 0x4e, 0x2c,
		 0xc9, 0xcc, 0xcf, 0x03, 0x00, 0x2c, 0x0e, 0x0e, 0xeb ),
	  DATA ( 0x5a, 0x4c, 0x49, 0x42, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x72,
		 0x65, 0x73, 0x73, 0x65, 0x64, 0x20, 0x44, 0x61, 0x74, 0x61,
		 0x20, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x53, 0x70,
		 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
		 0x6e ) );

/* "ZLIB Compressed Data Format Specification" fragment list */
static struct deflate_test_fragments zlib_fragments[] = {
	{ { -1UL, } },
	{ { 0, 1, 5, -1UL, } },
	{ { 0, 0, 1, 0, 0, 1, -1UL } },
	{ { 10, 8, 4, 7, 11, -1UL } },
	{ { 45, -1UL } },
	{ { 48, -1UL } },
};

/**
 * Report DEFLATE test result
 *
 * @v deflate		Decompressor
 * @v test		Deflate test
 * @v frags		Fragment list, or NULL
 * @v file		Test code file
 * @v line		Test code line
 */
static void deflate_okx ( struct deflate *deflate,
			  struct deflate_test *test,
			  struct deflate_test_fragments *frags,
			  const char *file, unsigned int line ) {
	uint8_t data[ test->expected_len ];
	struct deflate_chunk in;
	struct deflate_chunk out;
	size_t frag_len = -1UL;
	size_t offset = 0;
	size_t remaining = test->compressed_len;
	unsigned int i;

	/* Initialise decompressor */
	deflate_init ( deflate, test->format );

	/* Initialise output chunk */
	deflate_chunk_init ( &out, virt_to_user ( data ), 0, sizeof ( data ) );

	/* Process input (in fragments, if applicable) */
	for ( i = 0 ; i < ( sizeof ( frags->len ) /
			    sizeof ( frags->len[0] ) ) ; i++ ) {

		/* Initialise input chunk */
		if ( frags )
			frag_len = frags->len[i];
		if ( frag_len > remaining )
			frag_len = remaining;
		deflate_chunk_init ( &in, virt_to_user ( test->compressed ),
				     offset, ( offset + frag_len ) );

		/* Decompress this fragment */
		okx ( deflate_inflate ( deflate, &in, &out ) == 0, file, line );
		okx ( in.len == ( offset + frag_len ), file, line );
		okx ( in.offset == in.len, file, line );

		/* Move to next fragment */
		offset = in.offset;
		remaining -= frag_len;
		if ( ! remaining )
			break;

		/* Check that decompression has not terminated early */
		okx ( ! deflate_finished ( deflate ), file, line );
	}

	/* Check decompression has terminated as expected */
	okx ( deflate_finished ( deflate ), file, line );
	okx ( offset == test->compressed_len, file, line );
	okx ( out.offset == test->expected_len, file, line );
	okx ( memcmp ( data, test->expected, test->expected_len ) == 0,
	     file, line );
}
#define deflate_ok( deflate, test, frags ) \
	deflate_okx ( deflate, test, frags, __FILE__, __LINE__ )

/**
 * Perform DEFLATE self-test
 *
 */
static void deflate_test_exec ( void ) {
	struct deflate *deflate;
	unsigned int i;

	/* Allocate shared structure */
	deflate = malloc ( sizeof ( *deflate ) );
	ok ( deflate != NULL );

	/* Perform self-tests */
	if ( deflate ) {

		/* Test as a single pass */
		deflate_ok ( deflate, &empty_literal, NULL );
		deflate_ok ( deflate, &literal, NULL );
		deflate_ok ( deflate, &split_literal, NULL );
		deflate_ok ( deflate, &empty, NULL );
		deflate_ok ( deflate, &hello_world, NULL );
		deflate_ok ( deflate, &hello_hello_world, NULL );
		deflate_ok ( deflate, &rfc_sentence, NULL );
		deflate_ok ( deflate, &zlib, NULL );

		/* Test fragmentation */
		for ( i = 0 ; i < ( sizeof ( zlib_fragments ) /
				    sizeof ( zlib_fragments[0] ) ) ; i++ ) {
			deflate_ok ( deflate, &zlib, &zlib_fragments[i] );
		}
	}

	/* Free shared structure */
	free ( deflate );
}

/** DEFLATE self-test */
struct self_test deflate_test __self_test = {
	.name = "deflate",
	.exec = deflate_test_exec,
};
