/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Settings self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <string.h>
#include <ipxe/settings.h>
#include <ipxe/test.h>

/** Define inline raw data */
#define RAW(...) { __VA_ARGS__ }

/**
 * Report a formatted-store test result
 *
 * @v _settings		Settings block
 * @v _setting		Setting
 * @v _formatted	Formatted value
 * @v _raw_array	Expected raw value
 */
#define storef_ok( _settings, _setting, _formatted, _raw_array ) do {	\
	const uint8_t expected[] = _raw_array;				\
	uint8_t actual[ sizeof ( expected ) ];				\
	int len;							\
									\
	ok ( storef_setting ( _settings, _setting, _formatted ) == 0 );	\
	len = fetch_setting ( _settings, _setting, NULL, NULL, actual,	\
			      sizeof ( actual ) );			\
	if ( len >= 0 ) {						\
		DBGC ( _settings, "Stored %s \"%s\", got:\n",		\
		       (_setting)->type->name, _formatted );		\
		DBGC_HDA ( _settings, 0, actual, len );			\
	} else {							\
		DBGC ( _settings, "Stored %s \"%s\", got error %s\n",	\
		       (_setting)->type->name, _formatted,		\
		       strerror ( len ) );				\
	}								\
	ok ( len == ( int ) sizeof ( actual ) );			\
	ok ( memcmp ( actual, expected, sizeof ( actual ) ) == 0 );	\
	} while ( 0 )

/**
 * Report a formatted-fetch test result
 *
 * @v _settings		Settings block
 * @v _setting		Setting
 * @v _raw_array	Raw value
 * @v _formatted	Expected formatted value
 */
#define fetchf_ok( _settings, _setting, _raw_array, _formatted ) do {	\
	const uint8_t raw[] = _raw_array;				\
	char actual[ strlen ( _formatted ) + 1 ];			\
	int len;							\
									\
	ok ( store_setting ( _settings, _setting, raw,			\
			     sizeof ( raw ) ) == 0 );			\
	len = fetchf_setting ( _settings, _setting, NULL, NULL, actual,	\
			       sizeof ( actual ) );			\
	DBGC ( _settings, "Fetched %s \"%s\" from:\n",			\
	       (_setting)->type->name, actual );			\
	DBGC_HDA ( _settings, 0, raw, sizeof ( raw ) );			\
	ok ( len == ( int ) ( sizeof ( actual ) - 1 ) );		\
	ok ( strcmp ( actual, _formatted ) == 0 );			\
	} while ( 0 )

/**
 * Report a numeric-store test result
 *
 * @v _settings		Settings block
 * @v _setting		Setting
 * @v _numeric		Numeric value
 * @v _raw_array	Expected raw value
 */
#define storen_ok( _settings, _setting, _numeric, _raw_array ) do {	\
	const uint8_t expected[] = _raw_array;				\
	uint8_t actual[ sizeof ( expected ) ];				\
	int len;							\
									\
	ok ( storen_setting ( _settings, _setting, _numeric ) == 0 );	\
	len = fetch_setting ( _settings, _setting, NULL, NULL, actual,	\
			      sizeof ( actual ) );			\
	if ( len >= 0 ) {						\
		DBGC ( _settings, "Stored %s %#lx, got:\n",		\
		       (_setting)->type->name,				\
		       ( unsigned long ) _numeric );			\
		DBGC_HDA ( _settings, 0, actual, len );			\
	} else {							\
		DBGC ( _settings, "Stored %s %#lx, got error %s\n",	\
		       (_setting)->type->name,				\
		       ( unsigned long ) _numeric, strerror ( len ) );	\
	}								\
	ok ( len == ( int ) sizeof ( actual ) );			\
	ok ( memcmp ( actual, expected, sizeof ( actual ) ) == 0 );	\
	} while ( 0 )

/**
 * Report a numeric-fetch test result
 *
 * @v _settings		Settings block
 * @v _setting		Setting
 * @v _raw_array	Raw array
 * @v _numeric		Expected numeric value
 */
#define fetchn_ok( _settings, _setting, _raw_array, _numeric ) do {	\
	const uint8_t raw[] = _raw_array;				\
	unsigned long actual;						\
									\
	ok ( store_setting ( _settings, _setting, raw,			\
			     sizeof ( raw ) ) == 0 );			\
	ok ( fetchn_setting ( _settings, _setting, NULL, NULL,		\
			      &actual ) == 0 );				\
	DBGC ( _settings, "Fetched %s %#lx from:\n",			\
	       (_setting)->type->name, actual );			\
	DBGC_HDA ( _settings, 0, raw, sizeof ( raw ) );			\
	ok ( actual == ( unsigned long ) _numeric );			\
	} while ( 0 )

/** Test generic settings block */
struct generic_settings test_generic_settings = {
	.settings = {
		.refcnt = NULL,
		.siblings =
		    LIST_HEAD_INIT ( test_generic_settings.settings.siblings ),
		.children =
		    LIST_HEAD_INIT ( test_generic_settings.settings.children ),
		.op = &generic_settings_operations,
	},
	.list = LIST_HEAD_INIT ( test_generic_settings.list ),
};

/** Test settings block */
#define test_settings test_generic_settings.settings

/** Test string setting */
static struct setting test_string_setting = {
	.name = "test_string",
	.type = &setting_type_string,
};

/** Test IPv4 address setting type */
static struct setting test_ipv4_setting = {
	.name = "test_ipv4",
	.type = &setting_type_ipv4,
};

/** Test IPv6 address setting type */
static struct setting test_ipv6_setting = {
	.name = "test_ipv6",
	.type = &setting_type_ipv6,
};

/** Test signed 8-bit integer setting type */
static struct setting test_int8_setting = {
	.name = "test_int8",
	.type = &setting_type_int8,
};

/** Test signed 16-bit integer setting type */
static struct setting test_int16_setting = {
	.name = "test_int16",
	.type = &setting_type_int16,
};

/** Test signed 32-bit integer setting type */
static struct setting test_int32_setting = {
	.name = "test_int32",
	.type = &setting_type_int32,
};

/** Test unsigned 8-bit integer setting type */
static struct setting test_uint8_setting = {
	.name = "test_uint8",
	.type = &setting_type_uint8,
};

/** Test unsigned 16-bit integer setting type */
static struct setting test_uint16_setting = {
	.name = "test_uint16",
	.type = &setting_type_uint16,
};

/** Test unsigned 32-bit integer setting type */
static struct setting test_uint32_setting = {
	.name = "test_uint32",
	.type = &setting_type_uint32,
};

/** Test colon-separated hex string setting type */
static struct setting test_hex_setting = {
	.name = "test_hex",
	.type = &setting_type_hex,
};

/** Test hyphen-separated hex string setting type */
static struct setting test_hexhyp_setting = {
	.name = "test_hexhyp",
	.type = &setting_type_hexhyp,
};

/** Test raw hex string setting type */
static struct setting test_hexraw_setting = {
	.name = "test_hexraw",
	.type = &setting_type_hexraw,
};

/** Test Base64 setting type */
static struct setting test_base64_setting = {
	.name = "test_base64",
	.type = &setting_type_base64,
};

/** Test UUID setting type */
static struct setting test_uuid_setting = {
	.name = "test_uuid",
	.type = &setting_type_uuid,
};

/** Test PCI bus:dev.fn setting type */
static struct setting test_busdevfn_setting = {
	.name = "test_busdevfn",
	.type = &setting_type_busdevfn,
};

/**
 * Perform settings self-tests
 *
 */
static void settings_test_exec ( void ) {

	/* Register test settings block */
	ok ( register_settings ( &test_settings, NULL, "test" ) == 0 );

	/* "string" setting type */
	storef_ok ( &test_settings, &test_string_setting, "hello",
		    RAW ( 'h', 'e', 'l', 'l', 'o' ) );
	fetchf_ok ( &test_settings, &test_string_setting,
		    RAW ( 'w', 'o', 'r', 'l', 'd' ), "world" );

	/* "ipv4" setting type */
	storef_ok ( &test_settings, &test_ipv4_setting, "192.168.0.1",
		    RAW ( 192, 168, 0, 1 ) );
	fetchf_ok ( &test_settings, &test_ipv4_setting,
		    RAW ( 212, 13, 204, 60 ), "212.13.204.60" );

	/* "ipv6" setting type */
	storef_ok ( &test_settings, &test_ipv6_setting,
		    "2001:ba8:0:1d4::6950:5845",
		    RAW ( 0x20, 0x01, 0x0b, 0xa8, 0x00, 0x00, 0x01, 0xd4,
			  0x00, 0x00, 0x00, 0x00, 0x69, 0x50, 0x58, 0x45 ) );
	fetchf_ok ( &test_settings, &test_ipv6_setting,
		    RAW ( 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			  0x02, 0x0c, 0x29, 0xff, 0xfe, 0xc5, 0x39, 0xa1 ),
		    "fe80::20c:29ff:fec5:39a1" );

	/* Integer setting types (as formatted strings) */
	storef_ok ( &test_settings, &test_int8_setting,
		    "54", RAW ( 54 ) );
	storef_ok ( &test_settings, &test_int8_setting,
		    "0x7f", RAW ( 0x7f ) );
	storef_ok ( &test_settings, &test_int8_setting,
		    "0x1234", RAW ( 0x34 ) );
	storef_ok ( &test_settings, &test_int8_setting,
		    "-32", RAW ( -32 ) );
	fetchf_ok ( &test_settings, &test_int8_setting,
		    RAW ( -9 ), "-9" );
	fetchf_ok ( &test_settings, &test_int8_setting,
		    RAW ( 106 ), "106" );
	storef_ok ( &test_settings, &test_uint8_setting,
		    "129", RAW ( 129 ) );
	storef_ok ( &test_settings, &test_uint8_setting,
		    "0x3421", RAW ( 0x21 ) );
	fetchf_ok ( &test_settings, &test_uint8_setting,
		    RAW ( 0x54 ), "0x54" );
	storef_ok ( &test_settings, &test_int16_setting,
		    "29483", RAW ( 0x73, 0x2b ) );
	fetchf_ok ( &test_settings, &test_int16_setting,
		    RAW ( 0x82, 0x14 ), "-32236" );
	fetchf_ok ( &test_settings, &test_int16_setting,
		    RAW ( 0x12, 0x78 ), "4728" );
	storef_ok ( &test_settings, &test_uint16_setting,
		    "48727", RAW ( 0xbe, 0x57 ) );
	fetchf_ok ( &test_settings, &test_uint16_setting,
		    RAW ( 0x9a, 0x24 ), "0x9a24" );
	storef_ok ( &test_settings, &test_int32_setting,
		    "2901274", RAW ( 0x00, 0x2c, 0x45, 0x1a ) );
	fetchf_ok ( &test_settings, &test_int32_setting,
		    RAW ( 0xff, 0x34, 0x2d, 0xaf ), "-13357649" );
	fetchf_ok ( &test_settings, &test_int32_setting,
		    RAW ( 0x01, 0x00, 0x34, 0xab ), "16790699" );
	storef_ok ( &test_settings, &test_uint32_setting,
		    "0xb598d21", RAW ( 0x0b, 0x59, 0x8d, 0x21 ) );
	fetchf_ok ( &test_settings, &test_uint32_setting,
		    RAW ( 0xf2, 0x37, 0xb2, 0x18 ), "0xf237b218" );

	/* Integer setting types (as numeric values) */
	storen_ok ( &test_settings, &test_int8_setting,
		    72, RAW ( 72 ) );
	storen_ok ( &test_settings, &test_int8_setting,
		    0xabcd, RAW ( 0xcd ) );
	fetchn_ok ( &test_settings, &test_int8_setting,
		    RAW ( 0xfe ), -2 );
	storen_ok ( &test_settings, &test_uint8_setting,
		    84, RAW ( 84 ) );
	fetchn_ok ( &test_settings, &test_uint8_setting,
		    RAW ( 0xfe ), 0xfe );
	storen_ok ( &test_settings, &test_int16_setting,
		    0x87bd, RAW ( 0x87, 0xbd ) );
	fetchn_ok ( &test_settings, &test_int16_setting,
		    RAW ( 0x3d, 0x14 ), 0x3d14 );
	fetchn_ok ( &test_settings, &test_int16_setting,
		    RAW ( 0x80 ), -128 );
	storen_ok ( &test_settings, &test_uint16_setting,
		    1, RAW ( 0x00, 0x01 ) );
	fetchn_ok ( &test_settings, &test_uint16_setting,
		    RAW ( 0xbd, 0x87 ), 0xbd87 );
	fetchn_ok ( &test_settings, &test_uint16_setting,
		    RAW ( 0x80 ), 0x0080 );
	storen_ok ( &test_settings, &test_int32_setting,
		    0x0812bfd2, RAW ( 0x08, 0x12, 0xbf, 0xd2 ) );
	fetchn_ok ( &test_settings, &test_int32_setting,
		    RAW ( 0x43, 0x87, 0x91, 0xb4 ), 0x438791b4 );
	fetchn_ok ( &test_settings, &test_int32_setting,
		    RAW ( 0xff, 0xff, 0xfe ), -2 );
	storen_ok ( &test_settings, &test_uint32_setting,
		    0xb5927ab8, RAW ( 0xb5, 0x92, 0x7a, 0xb8 ) );
	fetchn_ok ( &test_settings, &test_uint32_setting,
		    RAW ( 0x98, 0xab, 0x41, 0x81 ), 0x98ab4181 );
	fetchn_ok ( &test_settings, &test_uint32_setting,
		    RAW ( 0xff, 0xff, 0xfe ), 0x00fffffe );
	fetchn_ok ( &test_settings, &test_uint32_setting,
		    RAW ( 0, 0, 0, 0x12, 0x34, 0x56, 0x78 ), 0x12345678 );
	fetchn_ok ( &test_settings, &test_int32_setting,
		    RAW ( 0, 0, 0, 0x12, 0x34, 0x56, 0x78 ), 0x12345678 );
	fetchn_ok ( &test_settings, &test_int32_setting,
		    RAW ( 0xff, 0xff, 0x87, 0x65, 0x43, 0x21 ), -0x789abcdf );

	/* "hex" setting type */
	storef_ok ( &test_settings, &test_hex_setting,
		    "08:12:f5:22:90:1b:4b:47:a8:30:cb:4d:67:4c:d6:76",
		    RAW ( 0x08, 0x12, 0xf5, 0x22, 0x90, 0x1b, 0x4b, 0x47, 0xa8,
			  0x30, 0xcb, 0x4d, 0x67, 0x4c, 0xd6, 0x76 ) );
	fetchf_ok ( &test_settings, &test_hex_setting,
		    RAW ( 0x62, 0xd9, 0xd4, 0xc4, 0x7e, 0x3b, 0x41, 0x46, 0x91,
			  0xc6, 0xfd, 0x0c, 0xbf ),
		    "62:d9:d4:c4:7e:3b:41:46:91:c6:fd:0c:bf" );

	/* "hexhyp" setting type */
	storef_ok ( &test_settings, &test_hexhyp_setting,
		    "11-33-22", RAW ( 0x11, 0x33, 0x22 ) );
	fetchf_ok ( &test_settings, &test_hexhyp_setting,
		    RAW ( 0x9f, 0xe5, 0x6d, 0xfb, 0x24, 0x3a, 0x4c, 0xbb, 0xa9,
			  0x09, 0x6c, 0x66, 0x13, 0xc1, 0xa8, 0xec, 0x27 ),
		    "9f-e5-6d-fb-24-3a-4c-bb-a9-09-6c-66-13-c1-a8-ec-27" );

	/* "hexraw" setting type */
	storef_ok ( &test_settings, &test_hexraw_setting,
		    "012345abcdef", RAW ( 0x01, 0x23, 0x45, 0xab, 0xcd, 0xef ));
	fetchf_ok ( &test_settings, &test_hexraw_setting,
		    RAW ( 0x9e, 0x4b, 0x6e, 0xef, 0x36, 0xb6, 0x46, 0xfe, 0x8f,
			  0x17, 0x06, 0x39, 0x6b, 0xf4, 0x48, 0x4e ),
		    "9e4b6eef36b646fe8f1706396bf4484e" );

	/* "base64" setting type */
	storef_ok ( &test_settings, &test_base64_setting,
		    "cGFzc6\nNwaHJhc2U= ",
		    RAW ( 0x70, 0x61, 0x73, 0x73, 0xa3, 0x70, 0x68, 0x72, 0x61,
			  0x73, 0x65 ) );
	fetchf_ok ( &test_settings, &test_base64_setting,
		    RAW ( 0x80, 0x81, 0x82, 0x83, 0x84, 0x00, 0xff ),
		    "gIGCg4QA/w==" );

	/* "uuid" setting type (no store capability) */
	fetchf_ok ( &test_settings, &test_uuid_setting,
		    RAW ( 0x1a, 0x6a, 0x74, 0x9d, 0x0e, 0xda, 0x46, 0x1a,0xa8,
			  0x7a, 0x7c, 0xfe, 0x4f, 0xca, 0x4a, 0x57 ),
		    "1a6a749d-0eda-461a-a87a-7cfe4fca4a57" );

	/* "busdevfn" setting type (no store capability) */
	fetchf_ok ( &test_settings, &test_busdevfn_setting,
		    RAW ( 0x03, 0x45 ), "03:08.5" );

	/* Clear and unregister test settings block */
	clear_settings ( &test_settings );
	unregister_settings ( &test_settings );
}

/** Settings self-test */
struct self_test settings_test __self_test = {
	.name = "settings",
	.exec = settings_test_exec,
};

/* Include real IPv6 setting type */
REQUIRING_SYMBOL ( settings_test );
REQUIRE_OBJECT ( ipv6 );
