/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/init.h>
#include <ipxe/settings.h>
#include <ipxe/cpuid.h>

/** @file
 *
 * x86 CPUID settings
 *
 * CPUID settings are numerically encoded as:
 *
 *  Bit  31	Extended function
 *  Bits 30-28	Unused
 *  Bits 27-24	Number of consecutive functions to call, minus one
 *  Bit  23	Return result as little-endian (used for strings)
 *  Bits 22-18	Unused
 *  Bits 17-16	Number of registers in register array, minus one
 *  Bits 15-8	Array of register indices.  First entry in array is in
 *		bits 9-8.  Indices are 0-%eax, 1-%ebx, 2-%ecx, 3-%edx.
 *  Bits 7-0	Starting function number (excluding "extended" bit)
 *
 * This encoding scheme is designed to allow the common case of
 * extracting a single register from a single function to be encoded
 * using "cpuid/<register>.<function>", e.g. "cpuid/2.0x80000001" to
 * retrieve the value of %ecx from calling CPUID with %eax=0x80000001.
 */

/** CPUID setting tag register indices */
enum cpuid_registers {
	CPUID_EAX = 0,
	CPUID_EBX = 1,
	CPUID_ECX = 2,
	CPUID_EDX = 3,
};

/**
 * Construct CPUID setting tag
 *
 * @v function		Starting function number
 * @v num_functions	Number of consecutive functions
 * @v little_endian	Return result as little-endian
 * @v num_registers	Number of registers in register array
 * @v register1		First register in register array (or zero, if empty)
 * @v register2		Second register in register array (or zero, if empty)
 * @v register3		Third register in register array (or zero, if empty)
 * @v register4		Fourth register in register array (or zero, if empty)
 * @ret tag		Setting tag
 */
#define CPUID_TAG( function, num_functions, little_endian, num_registers, \
		   register1, register2, register3, register4 )		  \
	( (function) | ( ( (num_functions) - 1 ) << 24 ) |		  \
	  ( (little_endian) << 23 ) | ( ( (num_registers) - 1) << 16 ) |  \
	  ( (register1) << 8 ) | ( (register2) << 10 ) |		  \
	  ( (register3) << 12 ) | ( (register4) << 14 ) )

/**
 * Extract endianness from CPUID setting tag
 *
 * @v tag		Setting tag
 * @ret little_endian	Result should be returned as little-endian
 */
#define CPUID_LITTLE_ENDIAN( tag ) ( (tag) & 0x00800000UL )

/**
 * Extract starting function number from CPUID setting tag
 *
 * @v tag		Setting tag
 * @ret function	Starting function number
 */
#define CPUID_FUNCTION( tag ) ( (tag) & 0x800000ffUL )

/**
 * Extract number of consecutive functions from CPUID setting tag
 *
 * @v tag		Setting tag
 * @ret num_functions	Number of consecutive functions
 */
#define CPUID_NUM_FUNCTIONS( tag ) ( ( ( (tag) >> 24 ) & 0xf ) + 1 )

/**
 * Extract register array from CPUID setting tag
 *
 * @v tag		Setting tag
 * @ret registers	Register array
 */
#define CPUID_REGISTERS( tag ) ( ( (tag) >> 8 ) & 0xff )

/**
 * Extract number of registers from CPUID setting tag
 *
 * @v tag		Setting tag
 * @ret num_registers	Number of registers within register array
 */
#define CPUID_NUM_REGISTERS( tag ) ( ( ( (tag) >> 16 ) & 0x3 ) + 1 )

/** CPUID settings scope */
static const struct settings_scope cpuid_settings_scope;

/**
 * Check applicability of CPUID setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int cpuid_settings_applies ( struct settings *settings __unused,
				    const struct setting *setting ) {

	return ( setting->scope == &cpuid_settings_scope );
}

/**
 * Fetch value of CPUID setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int cpuid_settings_fetch ( struct settings *settings,
				  struct setting *setting,
				  void *data, size_t len ) {
	uint32_t function;
	uint32_t max_function;
	uint32_t num_functions;
	uint32_t registers;
	uint32_t num_registers;
	uint32_t buf[4];
	uint32_t output;
	uint32_t discard_b;
	uint32_t discard_c;
	uint32_t discard_d;
	size_t frag_len;
	size_t result_len = 0;

	/* Fail unless CPUID is supported */
	if ( ! cpuid_is_supported() ) {
		DBGC ( settings, "CPUID not supported\n" );
		return -ENOTSUP;
	}

	/* Find highest supported function number within this set */
	function = CPUID_FUNCTION ( setting->tag );
	cpuid ( function & CPUID_EXTENDED, &max_function, &discard_b,
		&discard_c, &discard_d );

	/* Fail if maximum function number is meaningless (e.g. if we
	 * are attempting to call an extended function on a CPU which
	 * does not support them).
	 */
	if ( ( max_function & CPUID_AMD_CHECK_MASK ) !=
	     ( function & CPUID_AMD_CHECK_MASK ) ) {
		DBGC ( settings, "CPUID invalid maximum function\n" );
		return -ENOTSUP;
	}

	/* Call each function in turn */
	num_functions = CPUID_NUM_FUNCTIONS ( setting->tag );
	for ( ; num_functions-- ; function++ ) {

		/* Fail if this function is not supported */
		if ( function > max_function ) {
			DBGC ( settings, "CPUID function %#08x not supported\n",
			       function );
			return -ENOTSUP;
		}

		/* Issue CPUID */
		cpuid ( function, &buf[CPUID_EAX], &buf[CPUID_EBX],
			&buf[CPUID_ECX], &buf[CPUID_EDX] );
		DBGC ( settings, "CPUID %#08x => %#08x:%#08x:%#08x:%#08x\n",
		       function, buf[0], buf[1], buf[2], buf[3] );

		/* Copy results to buffer */
		registers = CPUID_REGISTERS ( setting->tag );
		num_registers = CPUID_NUM_REGISTERS ( setting->tag );
		for ( ; num_registers-- ; registers >>= 2 ) {
			output = buf[ registers & 0x3 ];
			if ( ! CPUID_LITTLE_ENDIAN ( setting->tag ) )
				output = cpu_to_be32 ( output );
			frag_len = sizeof ( output );
			if ( frag_len > len )
				frag_len = len;
			memcpy ( data, &output, frag_len );
			data += frag_len;
			len -= frag_len;
			result_len += sizeof ( output );
		}
	}

	/* Set type if not already specified */
	if ( ! setting->type )
		setting->type = &setting_type_hexraw;

	return result_len;
}

/** CPUID settings operations */
static struct settings_operations cpuid_settings_operations = {
	.applies = cpuid_settings_applies,
	.fetch = cpuid_settings_fetch,
};

/** CPUID settings */
static struct settings cpuid_settings = {
	.refcnt = NULL,
	.siblings = LIST_HEAD_INIT ( cpuid_settings.siblings ),
	.children = LIST_HEAD_INIT ( cpuid_settings.children ),
	.op = &cpuid_settings_operations,
	.default_scope = &cpuid_settings_scope,
};

/** Initialise CPUID settings */
static void cpuid_settings_init ( void ) {
	int rc;

	if ( ( rc = register_settings ( &cpuid_settings, NULL,
					"cpuid" ) ) != 0 ) {
		DBG ( "CPUID could not register settings: %s\n",
		      strerror ( rc ) );
		return;
	}
}

/** CPUID settings initialiser */
struct init_fn cpuid_settings_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = cpuid_settings_init,
};

/** CPU vendor setting */
const struct setting cpuvendor_setting __setting ( SETTING_HOST_EXTRA,
						   cpuvendor ) = {
	.name = "cpuvendor",
	.description = "CPU vendor",
	.tag = CPUID_TAG ( CPUID_VENDOR_ID, 1, 1, 3,
			   CPUID_EBX, CPUID_EDX, CPUID_ECX, 0 ),
	.type = &setting_type_string,
	.scope = &cpuid_settings_scope,
};

/** CPU model setting */
const struct setting cpumodel_setting __setting ( SETTING_HOST_EXTRA,
						  cpumodel ) = {
	.name = "cpumodel",
	.description = "CPU model",
	.tag = CPUID_TAG ( CPUID_MODEL, 3, 1, 4,
			   CPUID_EAX, CPUID_EBX, CPUID_ECX, CPUID_EDX ),
	.type = &setting_type_string,
	.scope = &cpuid_settings_scope,
};
