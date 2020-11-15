/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <byteswap.h>
#include <ipxe/settings.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <readline/readline.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * Non-volatile option commands
 *
 */

/** "show" options */
struct show_options {};

/** "show" option list */
static struct option_descriptor show_opts[] = {};

/** "show" command descriptor */
static struct command_descriptor show_cmd =
	COMMAND_DESC ( struct show_options, show_opts, 1, 1, "<setting>" );

/**
 * "show" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int show_exec ( int argc, char **argv ) {
	struct show_options opts;
	struct named_setting setting;
	struct settings *origin;
	struct setting fetched;
	char name_buf[32];
	char *value;
	int len;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &show_cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse setting name */
	if ( ( rc = parse_existing_setting ( argv[optind], &setting ) ) != 0 )
		goto err_parse_setting;

	/* Fetch formatted setting value */
	if ( ( len = fetchf_setting_copy ( setting.settings, &setting.setting,
					   &origin, &fetched, &value ) ) < 0 ) {
		rc = len;
		printf ( "Could not find \"%s\": %s\n",
			 setting.setting.name, strerror ( rc ) );
		goto err_fetchf;
	}

	/* Print setting value */
	setting_name ( origin, &fetched, name_buf, sizeof ( name_buf ) );
	printf ( "%s = %s\n", name_buf, value );

	/* Success */
	rc = 0;

	free ( value );
 err_fetchf:
 err_parse_setting:
 err_parse_options:
	return rc;
}

/** "set", "clear", and "read" options */
struct set_core_options {};

/** "set", "clear", and "read" option list */
static struct option_descriptor set_core_opts[] = {};

/** "set" command descriptor */
static struct command_descriptor set_cmd =
	COMMAND_DESC ( struct set_core_options, set_core_opts, 1, MAX_ARGUMENTS,
		       "<setting> <value>" );

/** "clear" and "read" command descriptor */
static struct command_descriptor clear_read_cmd =
	COMMAND_DESC ( struct set_core_options, set_core_opts, 1, 1,
		       "<setting>" );

/**
 * "set", "clear", and "read" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v cmd		Command descriptor
 * @v get_value		Method to obtain setting value
 * @ret rc		Return status code
 */
static int set_core_exec ( int argc, char **argv,
			   struct command_descriptor *cmd,
			   int ( * get_value ) ( struct named_setting *setting,
						 char **args, char **value ) ) {
	struct set_core_options opts;
	struct named_setting setting;
	char *value;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse setting name */
	if ( ( rc = parse_autovivified_setting ( argv[optind],
						 &setting ) ) != 0 )
		goto err_parse_setting;

	/* Parse setting value */
	if ( ( rc = get_value ( &setting, &argv[ optind + 1 ], &value ) ) != 0 )
		goto err_get_value;

	/* Apply default type if necessary */
	if ( ! setting.setting.type )
		setting.setting.type = &setting_type_string;

	/* Store setting */
	if ( ( rc = storef_setting ( setting.settings, &setting.setting,
				     value ) ) != 0 ) {
		printf ( "Could not store \"%s\": %s\n",
			 setting.setting.name, strerror ( rc ) );
		goto err_store;
	}

 err_store:
	free ( value );
 err_get_value:
 err_parse_setting:
 err_parse_options:
	return rc;
}

/**
 * Get setting value for "set" command
 *
 * @v setting		Named setting
 * @v args		Remaining arguments
 * @ret value		Setting value
 * @ret rc		Return status code
 */
static int set_value ( struct named_setting *setting __unused,
		       char **args, char **value ) {

	*value = concat_args ( args );
	if ( ! *value )
		return -ENOMEM;

	return 0;
}

/**
 * "set" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int set_exec ( int argc, char **argv ) {
	return set_core_exec ( argc, argv, &set_cmd, set_value );
}

/**
 * Get setting value for "clear" command
 *
 * @v setting		Named setting
 * @v args		Remaining arguments
 * @ret value		Setting value
 * @ret rc		Return status code
 */
static int clear_value ( struct named_setting *setting __unused,
			 char **args __unused, char **value ) {

	*value = NULL;
	return 0;
}

/**
 * "clear" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int clear_exec ( int argc, char **argv ) {
	return set_core_exec ( argc, argv, &clear_read_cmd, clear_value );
}

/**
 * Get setting value for "read" command
 *
 * @v setting		Named setting
 * @v args		Remaining arguments
 * @ret value		Setting value
 * @ret rc		Return status code
 */
static int read_value ( struct named_setting *setting, char **args __unused,
			char **value ) {
	char *existing;
	int rc;

	/* Read existing value, treating errors as equivalent to an
	 * empty initial setting.
	 */
	fetchf_setting_copy ( setting->settings, &setting->setting,
			      NULL, &setting->setting, &existing );

	/* Read new value */
	if ( ( rc = readline_history ( NULL, existing, NULL, value ) ) != 0 )
		goto err_readline;

 err_readline:
	free ( existing );
	return rc;
}

/**
 * "read" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int read_exec ( int argc, char **argv ) {
	return set_core_exec ( argc, argv, &clear_read_cmd, read_value );
}

/** "inc" options */
struct inc_options {};

/** "inc" option list */
static struct option_descriptor inc_opts[] = {};

/** "inc" command descriptor */
static struct command_descriptor inc_cmd =
	COMMAND_DESC ( struct inc_options, inc_opts, 1, 2,
		       "<setting> [<increment>]" );

/**
 * "inc" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int inc_exec ( int argc, char **argv ) {
	struct inc_options opts;
	struct named_setting setting;
	unsigned int increment = 1;
	unsigned long value;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &inc_cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse setting name */
	if ( ( rc = parse_existing_setting ( argv[optind], &setting ) ) != 0 )
		goto err_parse_setting;

	/* Parse increment (if present) */
	if ( ( ( optind + 1 ) < argc ) &&
	     ( ( rc = parse_integer ( argv[ optind + 1 ], &increment ) ) != 0))
		goto err_parse_increment;

	/* Read existing value, treating errors as equivalent to a
	 * zero-valued :int32 initial setting.
	 */
	if ( ( rc = fetchn_setting ( setting.settings, &setting.setting,
				     NULL, &setting.setting, &value ) ) != 0 ) {
		value = 0;
		if ( ! setting.setting.type )
			setting.setting.type = &setting_type_int32;
	}

	/* Increment value */
	value += increment;

	/* Store updated setting value */
	if ( ( rc = storen_setting ( setting.settings, &setting.setting,
				     value ) ) != 0 ) {
		printf ( "Could not store \"%s\": %s\n",
			 setting.setting.name, strerror ( rc ) );
		goto err_store;
	}

 err_store:
 err_parse_increment:
 err_parse_setting:
 err_parse_options:
	return rc;
}

/** Non-volatile option commands */
struct command nvo_commands[] __command = {
	{
		.name = "show",
		.exec = show_exec,
	},
	{
		.name = "set",
		.exec = set_exec,
	},	
	{
		.name = "clear",
		.exec = clear_exec,
	},
	{
		.name = "read",
		.exec = read_exec,
	},
	{
		.name = "inc",
		.exec = inc_exec,
	},
};
