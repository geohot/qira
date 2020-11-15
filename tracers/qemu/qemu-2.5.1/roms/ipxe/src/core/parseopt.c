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

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/netdevice.h>
#include <ipxe/menu.h>
#include <ipxe/settings.h>
#include <ipxe/params.h>
#include <ipxe/timer.h>
#include <ipxe/parseopt.h>
#include <config/branding.h>

/** @file
 *
 * Command line option parsing
 *
 */

/** Return status code for "--help" option */
#define ECANCELED_NO_OP __einfo_error ( EINFO_ECANCELED_NO_OP )
#define EINFO_ECANCELED_NO_OP \
	__einfo_uniqify ( EINFO_ECANCELED, 0x01, "Nothing to do" )

/* Disambiguate the various error codes */
#define EINVAL_INTEGER __einfo_error ( EINFO_EINVAL_INTEGER )
#define EINFO_EINVAL_INTEGER \
	__einfo_uniqify ( EINFO_EINVAL, 0x01, "Invalid integer value" )
#define EINVAL_UNKNOWN_OPTION __einfo_error ( EINFO_EINVAL_UNKNOWN_OPTION )
#define EINFO_EINVAL_UNKNOWN_OPTION \
	__einfo_uniqify ( EINFO_EINVAL, 0x02, "Unrecognised option" )
#define EINVAL_MISSING_ARGUMENT __einfo_error ( EINFO_EINVAL_MISSING_ARGUMENT )
#define EINFO_EINVAL_MISSING_ARGUMENT \
	__einfo_uniqify ( EINFO_EINVAL, 0x03, "Missing argument" )

/**
* Parse string value
 *
 * @v text		Text
 * @ret value		String value
 * @ret rc		Return status code
 */
int parse_string ( char *text, char **value ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Parse string */
	*value = text;

	return 0;
}

/**
 * Parse integer value
 *
 * @v text		Text
 * @ret value		Integer value
 * @ret rc		Return status code
 */
int parse_integer ( char *text, unsigned int *value ) {
	char *endp;

	/* Sanity check */
	assert ( text != NULL );

	/* Parse integer */
	*value = strtoul ( text, &endp, 0 );
	if ( *endp ) {
		printf ( "\"%s\": invalid integer value\n", text );
		return -EINVAL_INTEGER;
	}

	return 0;
}

/**
 * Parse timeout value (in ms)
 *
 * @v text		Text
 * @ret value		Integer value
 * @ret rc		Return status code
 */
int parse_timeout ( char *text, unsigned long *value ) {
	unsigned int value_ms;
	int rc;

	/* Parse raw integer value */
	if ( ( rc = parse_integer ( text, &value_ms ) ) != 0 )
		return rc;

	/* Convert to a number of timer ticks */
	*value = ( ( value_ms * TICKS_PER_SEC ) / 1000 );

	return 0;
}

/**
 * Parse network device name
 *
 * @v text		Text
 * @ret netdev		Network device
 * @ret rc		Return status code
 */
int parse_netdev ( char *text, struct net_device **netdev ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Find network device */
	*netdev = find_netdev ( text );
	if ( ! *netdev ) {
		printf ( "\"%s\": no such network device\n", text );
		return -ENODEV;
	}

	return 0;
}

/**
 * Parse network device configurator name
 *
 * @v text		Text
 * @ret configurator	Network device configurator
 * @ret rc		Return status code
 */
int parse_netdev_configurator ( char *text,
				struct net_device_configurator **configurator ){

	/* Sanity check */
	assert ( text != NULL );

	/* Find network device configurator */
	*configurator = find_netdev_configurator ( text );
	if ( ! *configurator ) {
		printf ( "\"%s\": no such configurator\n", text );
		return -ENOTSUP;
	}

	return 0;
}

/**
 * Parse menu name
 *
 * @v text		Text
 * @ret menu		Menu
 * @ret rc		Return status code
 */
int parse_menu ( char *text, struct menu **menu ) {

	/* Find menu */
	*menu = find_menu ( text );
	if ( ! *menu ) {
		if ( text ) {
			printf ( "\"%s\": no such menu\n", text );
		} else {
			printf ( "No default menu\n" );
		}
		return -ENOENT;
	}

	return 0;
}

/**
 * Parse flag
 *
 * @v text		Text (ignored)
 * @ret flag		Flag to set
 * @ret rc		Return status code
 */
int parse_flag ( char *text __unused, int *flag ) {

	/* Set flag */
	*flag = 1;

	return 0;
}

/**
 * Parse key
 *
 * @v text		Text
 * @ret key		Key
 * @ret rc		Return status code
 */
int parse_key ( char *text, unsigned int *key ) {

	/* Interpret single characters as being a literal key character */
	if ( text[0] && ! text[1] ) {
		*key = text[0];
		return 0;
	}

	/* Otherwise, interpret as an integer */
	return parse_integer ( text, key );
}

/**
 * Parse settings block name
 *
 * @v text		Text
 * @ret value		Integer value
 * @ret rc		Return status code
 */
int parse_settings ( char *text, struct settings **value ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Parse scope name */
	*value = find_settings ( text );
	if ( ! *value ) {
		printf ( "\"%s\": no such scope\n", text );
		return -EINVAL;
	}

	return 0;
}

/**
 * Parse setting name
 *
 * @v text		Text
 * @v setting		Named setting to fill in
 * @v get_child		Function to find or create child settings block
 * @ret rc		Return status code
 *
 * Note that this function modifies the original @c text.
 */
int parse_setting ( char *text, struct named_setting *setting,
		    get_child_settings_t get_child ) {
	int rc;

	/* Sanity check */
	assert ( text != NULL );

	/* Parse setting name */
	if ( ( rc = parse_setting_name ( text, get_child, &setting->settings,
					 &setting->setting ) ) != 0 ) {
		printf ( "\"%s\": invalid setting\n", text );
		return rc;
	}

	return 0;
}

/**
 * Parse existing setting name
 *
 * @v text		Text
 * @v setting		Named setting to fill in
 * @ret rc		Return status code
 *
 * Note that this function modifies the original @c text.
 */
int parse_existing_setting ( char *text, struct named_setting *setting ) {

	return parse_setting ( text, setting, find_child_settings );
}

/**
 * Parse and autovivify setting name
 *
 * @v text		Text
 * @v setting		Named setting to fill in
 * @ret rc		Return status code
 *
 * Note that this function modifies the original @c text.
 */
int parse_autovivified_setting ( char *text, struct named_setting *setting ) {

	return parse_setting ( text, setting, autovivify_child_settings );
}

/**
 * Parse form parameter list name
 *
 * @v text		Text
 * @ret params		Parameter list
 * @ret rc		Return status code
 */
int parse_parameters ( char *text, struct parameters **params ) {

	/* Find parameter list */
	*params = find_parameters ( text );
	if ( ! *params ) {
		if ( text ) {
			printf ( "\"%s\": no such parameter list\n", text );
		} else {
			printf ( "No default parameter list\n" );
		}
		return -ENOENT;
	}

	return 0;
}

/**
 * Print command usage message
 *
 * @v cmd		Command descriptor
 * @v argv		Argument list
 */
void print_usage ( struct command_descriptor *cmd, char **argv ) {
	struct option_descriptor *option;
	unsigned int i;
	int is_optional;

	printf ( "Usage:\n\n  %s", argv[0] );
	for ( i = 0 ; i < cmd->num_options ; i++ ) {
		option = &cmd->options[i];
		printf ( " [-%c|--%s", option->shortopt, option->longopt );
		if ( option->has_arg ) {
			is_optional = ( option->has_arg == optional_argument );
			printf ( " %s<%s>%s", ( is_optional ? "[" : "" ),
				 option->longopt, ( is_optional ? "]" : "" ) );
		}
		printf ( "]" );
	}
	if ( cmd->usage )
		printf ( " %s", cmd->usage );
	printf ( "\n\nSee " PRODUCT_COMMAND_URI " for further information\n",
		 argv[0] );
}

/**
 * Reparse command-line options
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v cmd		Command descriptor
 * @v opts		Options (already initialised with default values)
 * @ret rc		Return status code
 */
int reparse_options ( int argc, char **argv, struct command_descriptor *cmd,
		      void *opts ) {
	struct option longopts[ cmd->num_options + 1 /* help */ + 1 /* end */ ];
	char shortopts[ cmd->num_options * 3 /* possible "::" */ + 1 /* "h" */
			+ 1 /* NUL */ ];
	unsigned int shortopt_idx = 0;
	int ( * parse ) ( char *text, void *value );
	void *value;
	unsigned int i;
	unsigned int j;
	unsigned int num_args;
	int c;
	int rc;

	/* Construct long and short option lists for getopt_long() */
	memset ( longopts, 0, sizeof ( longopts ) );
	for ( i = 0 ; i < cmd->num_options ; i++ ) {
		longopts[i].name = cmd->options[i].longopt;
		longopts[i].has_arg = cmd->options[i].has_arg;
		longopts[i].val = cmd->options[i].shortopt;
		shortopts[shortopt_idx++] = cmd->options[i].shortopt;
		assert ( cmd->options[i].has_arg <= optional_argument );
		for ( j = cmd->options[i].has_arg ; j > 0 ; j-- )
			shortopts[shortopt_idx++] = ':';
	}
	longopts[i].name = "help";
	longopts[i].val = 'h';
	shortopts[shortopt_idx++] = 'h';
	shortopts[shortopt_idx++] = '\0';
	assert ( shortopt_idx <= sizeof ( shortopts ) );
	DBGC ( cmd,  "Command \"%s\" has options \"%s\", %d-%d args, len %d\n",
	       argv[0], shortopts, cmd->min_args, cmd->max_args, cmd->len );

	/* Parse options */
	while ( ( c = getopt_long ( argc, argv, shortopts, longopts,
				    NULL ) ) >= 0 ) {
		switch ( c ) {
		case 'h' :
			/* Print help */
			print_usage ( cmd, argv );
			return -ECANCELED_NO_OP;
		case '?' :
			/* Print usage message */
			print_usage ( cmd, argv );
			return -EINVAL_UNKNOWN_OPTION;
		case ':' :
			/* Print usage message */
			print_usage ( cmd, argv );
			return -EINVAL_MISSING_ARGUMENT;
		default:
			/* Search for an option to parse */
			for ( i = 0 ; i < cmd->num_options ; i++ ) {
				if ( c != cmd->options[i].shortopt )
					continue;
				parse = cmd->options[i].parse;
				value = ( opts + cmd->options[i].offset );
				if ( ( rc = parse ( optarg, value ) ) != 0 )
					return rc;
				break;
			}
			assert ( i < cmd->num_options );
		}
	}

	/* Check remaining arguments */
	num_args = ( argc - optind );
	if ( ( num_args < cmd->min_args ) || ( num_args > cmd->max_args ) ) {
		print_usage ( cmd, argv );
		return -ERANGE;
	}

	return 0;
}

/**
 * Parse command-line options
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v cmd		Command descriptor
 * @v opts		Options (may be uninitialised)
 * @ret rc		Return status code
 */
int parse_options ( int argc, char **argv, struct command_descriptor *cmd,
		    void *opts ) {

	/* Clear options */
	memset ( opts, 0, cmd->len );

	return reparse_options ( argc, argv, cmd, opts );
}
