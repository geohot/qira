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

#include <string.h>
#include <ipxe/cpuid.h>

/** @file
 *
 * x86 CPU feature detection
 *
 */

/**
 * Check whether or not CPUID instruction is supported
 *
 * @ret is_supported	CPUID instruction is supported
 */
int cpuid_is_supported ( void ) {
	unsigned long original;
	unsigned long inverted;

	__asm__ ( "pushf\n\t"
		  "pushf\n\t"
		  "pop %0\n\t"
		  "mov %0,%1\n\t"
		  "xor %2,%1\n\t"
		  "push %1\n\t"
		  "popf\n\t"
		  "pushf\n\t"
		  "pop %1\n\t"
		  "popf\n\t"
		  : "=&r" ( original ), "=&r" ( inverted )
		  : "ir" ( CPUID_FLAG ) );
	return ( ( original ^ inverted ) & CPUID_FLAG );
}

/**
 * Get Intel-defined x86 CPU features
 *
 * @v features		x86 CPU features to fill in
 */
static void x86_intel_features ( struct x86_features *features ) {
	uint32_t max_level;
	uint32_t discard_a;
	uint32_t discard_b;
	uint32_t discard_c;
	uint32_t discard_d;

	/* Check that features are available via CPUID */
	cpuid ( CPUID_VENDOR_ID, &max_level, &discard_b, &discard_c,
		&discard_d );
	if ( max_level < CPUID_FEATURES ) {
		DBGC ( features, "CPUID has no Intel-defined features (max "
		       "level %08x)\n", max_level );
		return;
	}

	/* Get features */
	cpuid ( CPUID_FEATURES, &discard_a, &discard_b,
		&features->intel.ecx, &features->intel.edx );
	DBGC ( features, "CPUID Intel features: %%ecx=%08x, %%edx=%08x\n",
	       features->intel.ecx, features->intel.edx );

}

/**
 * Get AMD-defined x86 CPU features
 *
 * @v features		x86 CPU features to fill in
 */
static void x86_amd_features ( struct x86_features *features ) {
	uint32_t max_level;
	uint32_t discard_a;
	uint32_t discard_b;
	uint32_t discard_c;
	uint32_t discard_d;

	/* Check that features are available via CPUID */
	cpuid ( CPUID_AMD_MAX_FN, &max_level, &discard_b, &discard_c,
		&discard_d );
	if ( ( max_level & CPUID_AMD_CHECK_MASK ) != CPUID_AMD_CHECK ) {
		DBGC ( features, "CPUID has no extended functions\n" );
		return;
	}
	if ( max_level < CPUID_AMD_FEATURES ) {
		DBGC ( features, "CPUID has no AMD-defined features (max "
		       "level %08x)\n", max_level );
		return;
	}

	/* Get features */
	cpuid ( CPUID_AMD_FEATURES, &discard_a, &discard_b,
		&features->amd.ecx, &features->amd.edx );
	DBGC ( features, "CPUID AMD features: %%ecx=%08x, %%edx=%08x\n",
	       features->amd.ecx, features->amd.edx );
}

/**
 * Get x86 CPU features
 *
 * @v features		x86 CPU features to fill in
 */
void x86_features ( struct x86_features *features ) {

	/* Clear all features */
	memset ( features, 0, sizeof ( *features ) );

	/* Check that CPUID instruction is available */
	if ( ! cpuid_is_supported() ) {
		DBGC ( features, "CPUID instruction is not supported\n" );
		return;
	}

	/* Get Intel-defined features */
	x86_intel_features ( features );

	/* Get AMD-defined features */
	x86_amd_features ( features );
}
