/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <string.h>
#include <stdio.h>
#include <getopt.h>

/** @file
 *
 * Parse command-line options
 *
 */

/**
 * Option argument
 *
 * This will point to the argument for the most recently returned
 * option, if applicable.
 */
char *optarg;

/**
 * Current option index
 *
 * This is an index into the argv[] array.  When getopt() returns -1,
 * @c optind is the index to the first element that is not an option.
 */
int optind;

/**
 * Current option character index
 *
 * This is an index into the current element of argv[].
 */
int nextchar;

/**
 * Unrecognised option
 *
 * When an unrecognised option is encountered, the actual option
 * character is stored in @c optopt.
 */
int optopt;

/**
 * Get option argument from argv[] array
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret argument	Option argument, or NULL
 *
 * Grab the next element of argv[], if it exists and is not an option.
 */
static const char * get_argv_argument ( int argc, char * const argv[] ) {
	char *arg;

	/* Don't overrun argv[] */
	if ( optind >= argc )
		return NULL;
	arg = argv[optind];

	/* If next argv element is an option, then it's not usable as
	 * an argument.
	 */
	if ( *arg == '-' )
		return NULL;

	/** Consume this argv element, and return it */
	optind++;
	return arg;
}

/**
 * Match long option
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v opttext		Option text within current argv[] element
 * @v longopt		Long option specification
 * @ret option		Option to return from getopt()
 * @ret matched		Found a match for this long option
 */
static int match_long_option ( int argc, char * const argv[],
			       const char *opttext,
			       const struct option *longopt, int *option ) {
	size_t optlen;
	const char *argument = NULL;

	/* Compare option name */
	optlen = strlen ( longopt->name );
	if ( strncmp ( opttext, longopt->name, optlen ) != 0 )
		return 0;

	/* Check for inline argument */
	if ( opttext[optlen] == '=' ) {
		argument = &opttext[ optlen + 1 ];
	} else if ( opttext[optlen] ) {
		/* Long option with trailing garbage - no match */
		return 0;
	}

	/* Consume this argv element */
	optind++;

	/* If we want an argument but don't have one yet, try to grab
	 * the next argv element
	 */
	if ( ( longopt->has_arg != no_argument ) && ( ! argument ) )
		argument = get_argv_argument ( argc, argv );

	/* If we need an argument but don't have one, sulk */
	if ( ( longopt->has_arg == required_argument ) && ( ! argument ) ) {
		printf ( "Option \"%s\" requires an argument\n",
			 longopt->name );
		*option = ':';
		return 1;
	}

	/* If we have an argument where we shouldn't have one, sulk */
	if ( ( longopt->has_arg == no_argument ) && argument ) {
		printf ( "Option \"%s\" takes no argument\n", longopt->name );
		*option = ':';
		return 1;
	}

	/* Store values and return success */
	optarg = ( char * ) argument;
	if ( longopt->flag ) {
		*(longopt->flag) = longopt->val;
		*option = 0;
	} else {
		*option = longopt->val;
	}
	return 1;
}

/**
 * Match short option
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v opttext		Option text within current argv[] element
 * @v shortopt		Option character from option specification
 * @ret option		Option to return from getopt()
 * @ret matched		Found a match for this short option
 */
static int match_short_option ( int argc, char * const argv[],
				const char *opttext, int shortopt,
				enum getopt_argument_requirement has_arg,
				int *option ) {
	const char *argument = NULL;

	/* Compare option character */
	if ( *opttext != shortopt )
		return 0;

	/* Consume option character */
	opttext++;
	nextchar++;
	if ( *opttext ) {
		if ( has_arg != no_argument ) {
			/* Consume remainder of element as inline argument */
			argument = opttext;
			optind++;
			nextchar = 0;
		}
	} else {
		/* Reached end of argv element */
		optind++;
		nextchar = 0;
	}

	/* If we want an argument but don't have one yet, try to grab
	 * the next argv element
	 */
	if ( ( has_arg != no_argument ) && ( ! argument ) )
		argument = get_argv_argument ( argc, argv );

	/* If we need an argument but don't have one, sulk */
	if ( ( has_arg == required_argument ) && ( ! argument ) ) {
		printf ( "Option \"%c\" requires an argument\n", shortopt );
		*option = ':';
		return 1;
	}

	/* Store values and return success */
	optarg = ( char * ) argument;
	*option = shortopt;
	return 1;
}

/**
 * Parse command-line options
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v optstring		Option specification string
 * @v longopts		Long option specification table
 * @ret longindex	Index of long option (or NULL)
 * @ret option		Option found, or -1 for no more options
 *
 * Note that the caller must arrange for reset_getopt() to be called
 * before each set of calls to getopt_long().  In Etherboot, this is
 * done automatically by execv().
 */
int getopt_long ( int argc, char * const argv[], const char *optstring,
		  const struct option *longopts, int *longindex ) {
	const char *opttext = argv[optind];
	const struct option *longopt;
	int shortopt;
	enum getopt_argument_requirement has_arg;
	int option;

	/* Check for end of argv array */
	if ( optind >= argc )
		return -1;

	/* Check for end of options */
	if ( *(opttext++) != '-' )
		return -1;

	/* Check for long options */
	if ( *(opttext++) == '-' ) {
		/* "--" indicates end of options */
		if ( *opttext == '\0' ) {
			optind++;
			return -1;
		}
		for ( longopt = longopts ; longopt->name ; longopt++ ) {
			if ( ! match_long_option ( argc, argv, opttext,
						   longopt, &option ) )
				continue;
			if ( longindex )
				*longindex = ( longopt - longopts );
			return option;
		}
		optopt = '?';
		printf ( "Unrecognised option \"--%s\"\n", opttext );
		return '?';
	}

	/* Check for short options */
	if ( nextchar < 1 )
		nextchar = 1;
	opttext = ( argv[optind] + nextchar );
	while ( ( shortopt = *(optstring++) ) ) {
		has_arg = no_argument;
		while ( *optstring == ':' ) {
			has_arg++;
			optstring++;
		}
		if ( match_short_option ( argc, argv, opttext, shortopt,
					  has_arg, &option ) ) {
			return option;
		}
	}
	optopt = *opttext;
	printf ( "Unrecognised option \"-%c\"\n", optopt );
	return '?';
}
