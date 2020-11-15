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
 * DNS self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <string.h>
#include <assert.h>
#include <ipxe/dns.h>
#include <ipxe/test.h>

/** Define inline data */
#define DATA(...) { __VA_ARGS__ }

/** A DNS encoding test */
struct dns_encode_test {
	/** String */
	const char *string;
	/** Encoded string */
	const void *data;
	/** Length of encoded string */
	int len;
};

/**
 * Define a DNS encoding test
 *
 * @v _name		Test name
 * @v _string		Test string
 * @v _data		Expected encoded data
 * @ret test		DNS encoding test
 */
#define DNS_ENCODE( _name, _string, _data )				\
	static const uint8_t _name ## __data[] = _data;			\
	static struct dns_encode_test _name = {				\
		.string = _string,					\
		.data =	_name ## __data,				\
		.len = sizeof ( _name ## __data ),			\
	}

/**
 * Report DNS encoding test result
 *
 * @v test		DNS encoding test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_encode_okx ( struct dns_encode_test *test, const char *file,
			     unsigned int line ) {
	uint8_t data[ test->len ];
	struct dns_name name;
	int len;

	/* Check ability to determine length with no buffer */
	memset ( &name, 0, sizeof ( name ) );
	len = dns_encode ( test->string, &name );
	okx ( len >= 0, file, line );
	okx ( len == test->len, file, line );

	/* Check encoded name */
	name.data = data;
	name.len = sizeof ( data );
	len = dns_encode ( test->string, &name );
	okx ( len >= 0, file, line );
	if ( len >= 0 ) {
		okx ( len == test->len, file, line );
		okx ( memcmp ( data, test->data, test->len ) == 0, file, line );
		DBGC ( test, "DNS encoded \"%s\" to:\n", test->string );
		DBGC_HDA ( test, 0, data, len );
	}
}
#define dns_encode_ok( test ) dns_encode_okx ( test, __FILE__, __LINE__ )

/**
 * Report DNS encoding failure test result
 *
 * @v test		DNS encoding test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_encode_fail_okx ( struct dns_encode_test *test,
				  const char *file, unsigned int line ) {
	struct dns_name name = { .data = NULL, .len = 0 };
	int len;

	len = dns_encode ( test->string, &name );
	okx ( len < 0, file, line );
}
#define dns_encode_fail_ok( test ) \
	dns_encode_fail_okx ( test, __FILE__, __LINE__ )

/** A DNS decoding test */
struct dns_decode_test {
	/** Name */
	struct dns_name name;
	/** Expected string */
	const char *string;
};

/**
 * Define a DNS decoding test
 *
 * @v _name		Test name
 * @v _data		RFC1035-encoded data
 * @v _offset		Starting offset within encoded data
 * @v _string		Expected decoded string
 * @ret test		DNS decoding test
 */
#define DNS_DECODE( _name, _data, _offset, _string )			\
	static uint8_t _name ## __data[] = _data;			\
	static struct dns_decode_test _name = {				\
		.name = {						\
			.data = _name ## __data,			\
			.offset = _offset,				\
			.len = sizeof ( _name ## __data ),		\
		},							\
		.string = _string,					\
	}

/**
 * Report DNS decoding test result
 *
 * @v test		DNS decoding test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_decode_okx ( struct dns_decode_test *test, const char *file,
			     unsigned int line ) {
	char string[ strlen ( test->string ) + 1 /* NUL */ ];
	int len;

	/* Check ability to determine length with no buffer */
	len = dns_decode ( &test->name, NULL, 0 );
	okx ( len >= 0, file, line );
	okx ( len == ( ( int ) strlen ( test->string ) ), file, line );

	/* Check decoded string */
	len = dns_decode ( &test->name, string, sizeof ( string ) );
	okx ( len >= 0, file, line );
	if ( len >= 0 ) {
		okx ( strcmp ( string, test->string ) == 0, file, line );
		DBGC ( test, "DNS decoded \"%s\" from offset %#zx in:\n",
		       string, test->name.offset );
		DBGC_HDA ( test, 0, test->name.data, test->name.len );
	}
}
#define dns_decode_ok( test ) dns_decode_okx ( test, __FILE__, __LINE__ )

/**
 * Report DNS decoding failure test result
 *
 * @v test		DNS decoding test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_decode_fail_okx ( struct dns_decode_test *test,
				  const char *file, unsigned int line ) {
	int len;

	len = dns_decode ( &test->name, NULL, 0 );
	okx ( len < 0, file, line );
}
#define dns_decode_fail_ok( test ) \
	dns_decode_fail_okx ( test, __FILE__, __LINE__ )

/** A DNS comparison test */
struct dns_compare_test {
	/** First name */
	struct dns_name first;
	/** Second name */
	struct dns_name second;
};

/**
 * Define a DNS comparison test
 *
 * @v _name		Test name
 * @v _first_data	First RFC1035-encoded data
 * @v _first_offset	Starting offset within first encoded data
 * @v _second_data	Second RFC1035-encoded data
 * @v _second_offset	Starting offset within second encoded data
 * @ret test		DNS comparison test
 */
#define DNS_COMPARE( _name, _first_data, _first_offset, _second_data,	\
		     _second_offset )					\
	static uint8_t _name ## __first_data[] = _first_data;		\
	static uint8_t _name ## __second_data[] = _second_data;		\
	static struct dns_compare_test _name = {			\
		.first = {						\
			.data = _name ## __first_data,			\
			.offset = _first_offset,			\
			.len = sizeof ( _name ## __first_data ),	\
		},							\
		.second = {						\
			.data = _name ## __second_data,			\
			.offset = _second_offset,			\
			.len = sizeof ( _name ## __second_data ),	\
		},							\
	}

/**
 * Report DNS comparison test result
 *
 * @v test		DNS comparison test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_compare_okx ( struct dns_compare_test *test, const char *file,
			      unsigned int line ) {

	okx ( dns_compare ( &test->first, &test->second ) == 0, file, line );
}
#define dns_compare_ok( test ) dns_compare_okx ( test, __FILE__, __LINE__ )

/**
 * Report DNS comparison test failure result
 *
 * @v test		DNS comparison test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_compare_fail_okx ( struct dns_compare_test *test,
				   const char *file, unsigned int line ) {

	okx ( dns_compare ( &test->first, &test->second ) != 0, file, line );
}
#define dns_compare_fail_ok( test ) \
	dns_compare_fail_okx ( test, __FILE__, __LINE__ )

/** A DNS copying test */
struct dns_copy_test {
	/** Source name */
	struct dns_name src;
	/** Expected copied name */
	struct dns_name dst;
};

/**
 * Define a DNS copying test
 *
 * @v _name		Test name
 * @v _src_data		Source RFC1035-encoded data
 * @v _src_offset	Starting offset within source encoded data
 * @v _dst_data		Expected copied RFC1035-encoded data
 * @v _dst_offset	Starting offset withint copied encoded data
 * @ret test		DNS copying test
 */
#define DNS_COPY( _name, _src_data, _src_offset, _dst_data,		\
		  _dst_offset )						\
	static uint8_t _name ## __src_data[] = _src_data;		\
	static uint8_t _name ## __dst_data[] = _dst_data;		\
	static struct dns_copy_test _name = {				\
		.src = {						\
			.data = _name ## __src_data,			\
			.offset = _src_offset,				\
			.len = sizeof ( _name ## __src_data ),		\
		},							\
		.dst = {						\
			.data = _name ## __dst_data,			\
			.offset = _dst_offset,				\
			.len = sizeof ( _name ## __dst_data ),		\
		},							\
	}

/**
 * Report a DNS copying test result
 *
 * @v test		DNS copying test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_copy_okx ( struct dns_copy_test *test,
			   const char *file, unsigned int line ) {
	uint8_t data[ test->dst.len ];
	struct dns_name dst;
	int len;

	/* Check ability to determine length with no buffer */
	memset ( &dst, 0, sizeof ( dst ) );
	len = dns_copy ( &test->src, &dst );
	okx ( len >= 0, file, line );
	okx ( len == ( ( int ) ( test->dst.len - test->dst.offset ) ),
	      file, line );

	/* Check copied name */
	dst.data = data;
	dst.offset = test->dst.offset;
	dst.len = sizeof ( data );
	memcpy ( dst.data, test->dst.data, test->dst.offset );
	len = dns_copy ( &test->src, &dst );
	okx ( len >= 0, file, line );
	okx ( len == ( ( int ) ( test->dst.len - test->dst.offset ) ),
	      file, line );
	okx ( memcmp ( data, test->dst.data, sizeof ( data ) ) == 0,
	      file, line );
	DBGC ( test, "DNS copied:\n" );
	DBGC_HDA ( test, 0, test->src.data, test->src.len );
	DBGC_HDA ( test, 0, data, ( test->dst.offset + len ) );
}
#define dns_copy_ok( test ) dns_copy_okx ( test, __FILE__, __LINE__ )

/**
 * Report a DNS copying failure test result
 *
 * @v test		DNS copying test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_copy_fail_okx ( struct dns_copy_test *test,
				const char *file, unsigned int line ) {
	struct dns_name dst;
	int len;

	memset ( &dst, 0, sizeof ( dst ) );
	len = dns_copy ( &test->src, &dst );
	okx ( len < 0, file, line );
}
#define dns_copy_fail_ok( test ) dns_copy_fail_okx ( test, __FILE__, __LINE__ )

/** A DNS search list test */
struct dns_list_test {
	/** Search list */
	struct dns_name list;
	/** Expected decoded search list */
	const char **strings;
	/** Number of expected decoded string */
	unsigned int count;
};

/**
 * Define a DNS search list test
 *
 * @v _name		Test name
 * @v _list		RFC1035-encoded data
 * @v _strings		Expected decoded strings
 * @ret test		DNS search list test
 */
#define DNS_LIST( _name, _list, _strings )				\
	static uint8_t _name ## __list[] = _list;			\
	static const char * _name ## __strings[] = _strings;		\
	static struct dns_list_test _name = {				\
		.list = {						\
			.data = _name ## __list,			\
			.offset = 0,					\
			.len = sizeof ( _name ## __list ),		\
		},							\
		.strings = _name ## __strings,				\
		.count = ( sizeof ( _name ## __strings ) /		\
			   sizeof ( _name ## __strings[0] ) ),		\
	}

/**
 * Report DNS search list test result
 *
 * @v test		DNS search list test
 * @v file		Test code file
 * @v line		Test code line
 */
static void dns_list_okx ( struct dns_list_test *test, const char *file,
			   unsigned int line ) {
	struct dns_name name;
	unsigned int i;

	DBGC ( test, "DNS search list:\n" );
	DBGC_HDA ( test, 0, test->list.data, test->list.len );
	memcpy ( &name, &test->list, sizeof ( name ) );
	for ( i = 0 ; i < test->count ; i++ ) {
		char buf[ strlen ( test->strings[i] ) + 1 /* NUL */ ];
		int len;
		int offset;

		/* Decode this name */
		len = dns_decode ( &name, buf, sizeof ( buf ) );
		okx ( len >= 0, file, line );
		if ( len >= 0 ) {
			okx ( len == ( ( int ) strlen ( test->strings[i] ) ),
			      file, line );
			okx ( strcmp ( buf, test->strings[i] ) == 0,
			      file, line );
			DBGC ( test, "DNS search list found \"%s\" at offset "
			       "%#zx\n", buf, name.offset );
		}

		/* Skip to next name */
		offset = dns_skip ( &name );
		okx ( offset >= 0, file, line );
		name.offset = offset;
	}

	/* Check that we have consumed the whole search list */
	okx ( name.offset == name.len, file, line );
}
#define dns_list_ok( test ) dns_list_okx ( test, __FILE__, __LINE__ )

/* Simple encoding test */
DNS_ENCODE ( encode_simple, "ipxe.org",
	     DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ) );

/* Single-word encoding test */
DNS_ENCODE ( encode_single, "foo", DATA ( 3, 'f', 'o', 'o', 0 ) );

/* Absolute encoding test */
DNS_ENCODE ( encode_absolute, "git.ipxe.org.",
	     DATA ( 3, 'g', 'i', 't', 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g',
		    0 ) );

/* Empty string encoding test */
DNS_ENCODE ( encode_empty, "", DATA ( 0 ) );

/* Root domain encoding test */
DNS_ENCODE ( encode_root, ".", DATA ( 0 ) );

/* Invalid initial dot encoding test */
DNS_ENCODE ( encode_initial_dot, ".foo", DATA() );

/* Invalid double dot encoding test */
DNS_ENCODE ( encode_double_dot, "ipxe..org", DATA() );

/* Invalid solo double dot encoding test */
DNS_ENCODE ( encode_solo_double_dot, "..", DATA() );

/* Invalid trailing double dot encoding test */
DNS_ENCODE ( encode_trailing_double_dot, "ipxe.org..", DATA() );

/* Invalid overlength label encoding test */
DNS_ENCODE ( encode_overlength,
	     "this-label-is-maliciously-long-in-an-attempt-to-overflow-the-"
	     "length-field-and-generate-a-length-which-looks-like-a-"
	     "compression-pointer", DATA() );

/* Simple decoding test */
DNS_DECODE ( decode_simple,
	     DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0,
	     "ipxe.org" );

/* Compression pointer decoding test */
DNS_DECODE ( decode_ptr,
	     DATA ( 3, 'o', 'r', 'g', 0, 3, 'g', 'i', 't', 4, 'i', 'p', 'x',
		    'e', 0xc0, 0x00 ), 5,
	     "git.ipxe.org" );

/* Root decoding test */
DNS_DECODE ( decode_root,
	     DATA ( 0 ), 0, "" );

/* Incomplete name decoding test */
DNS_DECODE ( decode_incomplete_name,
	     DATA ( 4, 'i', 'p', 'x', 'e' ), 0, NULL );

/* Incomplete label decoding test */
DNS_DECODE ( decode_incomplete_label,
	     DATA ( 4, 'i', 'p', 'x' ), 0, NULL );

/* Incomplete compression pointer decoding test */
DNS_DECODE ( decode_incomplete_ptr,
	     DATA ( 3, 'o', 'r', 'g', 0, 4, 'i', 'p', 'x', 'e', 0xc0 ), 5,
	     NULL );

/* Forward reference decoding test */
DNS_DECODE ( decode_forward,
	     DATA ( 0xc0, 0x02, 3, 'f', 'o', 'o', 0 ), 0, NULL );

/* Infinite loop decoding test */
DNS_DECODE ( decode_infinite,
	     DATA ( 4, 'i', 'p', 'x', 'e', 0xc0, 0x00 ), 0, NULL );

/* Empty decoding test */
DNS_DECODE ( decode_empty,
	     DATA (), 0, NULL );

/* Simple comparison test */
DNS_COMPARE ( compare_simple,
	      DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0,
	      DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0 );

/* Compression pointer comparison test */
DNS_COMPARE ( compare_ptr,
	      DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0,
	      DATA ( 3, 'o', 'r', 'g', 0, 4, 'i', 'p', 'x', 'e',
		     0xc0, 0x00 ), 5 );

/* Case insensitive comparison test */
DNS_COMPARE ( compare_case,
	      DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0,
	      DATA ( 4, 'i', 'p', 'x', 'e', 3, 'O', 'R', 'G', 0 ), 0 );

/* Mismatch comparison test */
DNS_COMPARE ( compare_mismatch,
	      DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0,
	      DATA ( 4, 'g', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0 );

/* Infinite loop comparison test */
DNS_COMPARE ( compare_infinite,
	      DATA ( 3, 'f', 'o', 'o', 0xc0, 0x00 ), 0,
	      DATA ( 3, 'f', 'o', 'o', 0xc0, 0x00 ), 0 );

/* Simple copying test */
DNS_COPY ( copy_simple,
	   DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0,
	   DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0 );

/* Simple copying test with offset */
DNS_COPY ( copy_offset,
	   DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0 ), 0,
	   DATA ( 'f', 'o', 'o', 0, 4, 'i', 'p', 'x', 'e',
		  3, 'o', 'r', 'g', 0 ), 4 );

/* Compression pointer copying test */
DNS_COPY ( copy_ptr,
	   DATA ( 3, 'o', 'r', 'g', 0, 3, 'g', 'i', 't', 4, 'i', 'p', 'x', 'e',
		  0xc0, 0x00 ), 5,
	   DATA ( 3, 'g', 'i', 't', 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g',
		  0 ), 0 );

/* Infinite loop copying test */
DNS_COPY ( copy_infinite,
	   DATA ( 4, 'l', 'o', 'o', 'p', 7, 'f', 'o', 'r', 'e', 'v', 'e', 'r',
		  0xc0, 0x05 ), 0,
	   DATA (), 0 );

/* DNS search list test */
DNS_LIST ( search,
	   DATA ( 4, 'i', 'p', 'x', 'e', 3, 'o', 'r', 'g', 0,
		  4, 'b', 'o', 'o', 't', 0xc0, 0x00,
		  3, 'd', 'e', 'v', 0xc0, 0x0a,
		  11, 'n', 'e', 't', 'w', 'o', 'r', 'k', 'b', 'o', 'o', 't',
		  0xc0, 0x05 ),
	   DATA ( "ipxe.org", "boot.ipxe.org", "dev.boot.ipxe.org",
		  "networkboot.org" ) );

/**
 * Perform DNS self-test
 *
 */
static void dns_test_exec ( void ) {

	/* Encoding tests */
	dns_encode_ok ( &encode_simple );
	dns_encode_ok ( &encode_single );
	dns_encode_ok ( &encode_absolute );
	dns_encode_ok ( &encode_empty );
	dns_encode_ok ( &encode_root );
	dns_encode_fail_ok ( &encode_initial_dot );
	dns_encode_fail_ok ( &encode_double_dot );
	dns_encode_fail_ok ( &encode_solo_double_dot );
	dns_encode_fail_ok ( &encode_trailing_double_dot );
	dns_encode_fail_ok ( &encode_overlength );

	/* Decoding tests */
	dns_decode_ok ( &decode_simple );
	dns_decode_ok ( &decode_ptr );
	dns_decode_ok ( &decode_root );
	dns_decode_fail_ok ( &decode_incomplete_name );
	dns_decode_fail_ok ( &decode_incomplete_label );
	dns_decode_fail_ok ( &decode_incomplete_ptr );
	dns_decode_fail_ok ( &decode_forward );
	dns_decode_fail_ok ( &decode_infinite );
	dns_decode_fail_ok ( &decode_empty );

	/* Comparison tests */
	dns_compare_ok ( &compare_simple );
	dns_compare_ok ( &compare_ptr );
	dns_compare_ok ( &compare_case );
	dns_compare_fail_ok ( &compare_mismatch );
	dns_compare_fail_ok ( &compare_infinite );

	/* Copying tests */
	dns_copy_ok ( &copy_simple );
	dns_copy_ok ( &copy_offset );
	dns_copy_ok ( &copy_ptr );
	dns_copy_fail_ok ( &copy_infinite );

	/* Search list tets */
	dns_list_ok ( &search );
}

/** DNS self-test */
struct self_test dns_test __self_test = {
	.name = "dns",
	.exec = dns_test_exec,
};
