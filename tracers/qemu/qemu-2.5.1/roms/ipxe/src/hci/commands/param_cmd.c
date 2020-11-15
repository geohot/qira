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

/** @file
 *
 * Form parameter commands
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/params.h>
#include <ipxe/parseopt.h>
#include <ipxe/command.h>

/** "params" options */
struct params_options {
	/** Name */
	char *name;
	/** Delete */
	int delete;
};

/** "params" option list */
static struct option_descriptor params_opts[] = {
	OPTION_DESC ( "name", 'n', required_argument,
		      struct params_options, name, parse_string ),
	OPTION_DESC ( "delete", 'd', no_argument,
		      struct params_options, delete, parse_flag ),
};

/** "params" command descriptor */
static struct command_descriptor params_cmd =
	COMMAND_DESC ( struct params_options, params_opts, 0, 0, NULL );

/**
 * The "params" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int params_exec ( int argc, char **argv ) {
	struct params_options opts;
	struct parameters *params;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &params_cmd, &opts ) ) != 0)
		return rc;

	/* Create parameter list */
	params = create_parameters ( opts.name );
	if ( ! params )
		return -ENOMEM;

	/* Destroy parameter list, if applicable */
	if ( opts.delete ) {
		claim_parameters ( params );
		params_put ( params );
	}

	return 0;
}

/** "param" options */
struct param_options {
	/** Parameter list name */
	char *params;
};

/** "param" option list */
static struct option_descriptor param_opts[] = {
	OPTION_DESC ( "params", 'p', required_argument,
		      struct param_options, params, parse_string ),
};

/** "param" command descriptor */
static struct command_descriptor param_cmd =
	COMMAND_DESC ( struct param_options, param_opts, 1, MAX_ARGUMENTS,
		       "<key> [<value>]" );

/**
 * The "param" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int param_exec ( int argc, char **argv ) {
	struct param_options opts;
	char *key;
	char *value;
	struct parameters *params;
	struct parameter *param;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &param_cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse key */
	key = argv[optind];

	/* Parse value */
	value = concat_args ( &argv[ optind + 1 ] );
	if ( ! value ) {
		rc = -ENOMEM;
		goto err_parse_value;
	}

	/* Identify parameter list */
	if ( ( rc = parse_parameters ( opts.params, &params ) ) != 0 )
		goto err_parse_parameters;

	/* Add parameter */
	param = add_parameter ( params, key, value );
	if ( ! param ) {
		rc = -ENOMEM;
		goto err_add_parameter;
	}

	/* Success */
	rc = 0;

 err_add_parameter:
 err_parse_parameters:
	free ( value );
 err_parse_value:
 err_parse_options:
	return rc;
}

/** Form parameter commands */
struct command param_commands[] __command = {
	{
		.name = "params",
		.exec = params_exec,
	},
	{
		.name = "param",
		.exec = param_exec,
	},
};
