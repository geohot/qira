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

#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/cpuid.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>

/** @file
 *
 * x86 CPU feature detection command
 *
 */

/** "cpuid" options */
struct cpuid_options {
	/** Check AMD-defined features (%eax=0x80000001) */
	int amd;
	/** Check features defined via %ecx */
	int ecx;
};

/** "cpuid" option list */
static struct option_descriptor cpuid_opts[] = {
	OPTION_DESC ( "ext", 'e', no_argument,
		      struct cpuid_options, amd, parse_flag ),
	/* "--amd" retained for backwards compatibility */
	OPTION_DESC ( "amd", 'a', no_argument,
		      struct cpuid_options, amd, parse_flag ),
	OPTION_DESC ( "ecx", 'c', no_argument,
		      struct cpuid_options, ecx, parse_flag ),
};

/** "cpuid" command descriptor */
static struct command_descriptor cpuid_cmd =
	COMMAND_DESC ( struct cpuid_options, cpuid_opts, 1, 1, "<bit>" );

/**
 * The "cpuid" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int cpuid_exec ( int argc, char **argv ) {
	struct cpuid_options opts;
	struct x86_features features;
	struct x86_feature_registers *feature_regs;
	uint32_t feature_reg;
	unsigned int bit;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &cpuid_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse bit number */
	if ( ( rc = parse_integer ( argv[optind], &bit ) ) != 0 )
		return rc;

	/* Get CPU features */
	x86_features ( &features );

	/* Extract relevant feature register */
	feature_regs = ( opts.amd ? &features.amd : &features.intel );
	feature_reg = ( opts.ecx ? feature_regs->ecx : feature_regs->edx );

	/* Check presence of specified feature */
	return ( ( feature_reg & ( 1 << bit ) ) ? 0 : -ENOENT );
}

/** x86 CPU feature detection command */
struct command cpuid_command __command = {
	.name = "cpuid",
	.exec = cpuid_exec,
};
