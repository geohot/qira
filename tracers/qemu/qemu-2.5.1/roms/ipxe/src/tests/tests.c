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
 * Self-test collection
 *
 */

/* Drag in all applicable self-tests */
PROVIDE_REQUIRING_SYMBOL();
REQUIRE_OBJECT ( memset_test );
REQUIRE_OBJECT ( memcpy_test );
REQUIRE_OBJECT ( string_test );
REQUIRE_OBJECT ( math_test );
REQUIRE_OBJECT ( vsprintf_test );
REQUIRE_OBJECT ( list_test );
REQUIRE_OBJECT ( byteswap_test );
REQUIRE_OBJECT ( base64_test );
REQUIRE_OBJECT ( base16_test );
REQUIRE_OBJECT ( settings_test );
REQUIRE_OBJECT ( time_test );
REQUIRE_OBJECT ( tcpip_test );
REQUIRE_OBJECT ( ipv4_test );
REQUIRE_OBJECT ( ipv6_test );
REQUIRE_OBJECT ( crc32_test );
REQUIRE_OBJECT ( md5_test );
REQUIRE_OBJECT ( sha1_test );
REQUIRE_OBJECT ( sha256_test );
REQUIRE_OBJECT ( sha512_test );
REQUIRE_OBJECT ( aes_test );
REQUIRE_OBJECT ( hmac_drbg_test );
REQUIRE_OBJECT ( hash_df_test );
REQUIRE_OBJECT ( bigint_test );
REQUIRE_OBJECT ( rsa_test );
REQUIRE_OBJECT ( x509_test );
REQUIRE_OBJECT ( ocsp_test );
REQUIRE_OBJECT ( cms_test );
REQUIRE_OBJECT ( pnm_test );
REQUIRE_OBJECT ( deflate_test );
REQUIRE_OBJECT ( png_test );
REQUIRE_OBJECT ( dns_test );
REQUIRE_OBJECT ( uri_test );
REQUIRE_OBJECT ( profile_test );
REQUIRE_OBJECT ( setjmp_test );
REQUIRE_OBJECT ( pccrc_test );
REQUIRE_OBJECT ( linebuf_test );
