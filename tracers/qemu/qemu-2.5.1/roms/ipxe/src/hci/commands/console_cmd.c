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
 * Console management commands
 *
 */

#include <string.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/console.h>
#include <ipxe/image.h>
#include <ipxe/pixbuf.h>
#include <ipxe/ansiesc.h>
#include <ipxe/ansicol.h>
#include <usr/imgmgmt.h>

/** "console" options */
struct console_options {
	/** Console configuration */
	struct console_configuration config;
	/** Picture URI */
	char *picture;
	/** Keep picture after configuration */
	int keep;
};

/** "console" option list */
static struct option_descriptor console_opts[] = {
	OPTION_DESC ( "x", 'x', required_argument,
		      struct console_options, config.width, parse_integer ),
	OPTION_DESC ( "y", 'y', required_argument,
		      struct console_options, config.height, parse_integer ),
	OPTION_DESC ( "left", 'l', required_argument,
		      struct console_options, config.left, parse_integer ),
	OPTION_DESC ( "right", 'r', required_argument,
		      struct console_options, config.right, parse_integer ),
	OPTION_DESC ( "top", 't', required_argument,
		      struct console_options, config.top, parse_integer ),
	OPTION_DESC ( "bottom", 'b', required_argument,
		      struct console_options, config.bottom, parse_integer ),
	OPTION_DESC ( "depth", 'd', required_argument,
		      struct console_options, config.depth, parse_integer ),
	OPTION_DESC ( "picture", 'p', required_argument,
		      struct console_options, picture, parse_string ),
	OPTION_DESC ( "keep", 'k', no_argument,
		      struct console_options, keep, parse_flag ),
};

/** "console" command descriptor */
static struct command_descriptor console_cmd =
	COMMAND_DESC ( struct console_options, console_opts, 0, 0, NULL );

/**
 * "console" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int console_exec ( int argc, char **argv ) {
	struct console_options opts;
	struct image *image = NULL;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &console_cmd, &opts ) ) != 0 )
		goto err_parse;

	/* Handle background picture, if applicable */
	if ( opts.picture ) {

		/* Acquire image */
		if ( ( rc = imgacquire ( opts.picture, 0, &image ) ) != 0 )
			goto err_acquire;

		/* Convert to pixel buffer */
		if ( ( rc = image_pixbuf ( image, &opts.config.pixbuf ) ) != 0){
			printf ( "Could not use picture: %s\n",
				 strerror ( rc ) );
			goto err_pixbuf;
		}

		/* Apply image's width and height if none specified */
		if ( ! opts.config.width )
			opts.config.width = opts.config.pixbuf->width;
		if ( ! opts.config.height )
			opts.config.height = opts.config.pixbuf->height;
	}

	/* Configure console */
	if ( ( rc = console_configure ( &opts.config ) ) != 0 ) {
		printf ( "Could not configure console: %s\n", strerror ( rc ) );
		goto err_configure;
	}

	/* Reapply default colour pair and clear screen */
	ansicol_set_pair ( CPAIR_DEFAULT );
	printf ( CSI "2J" CSI "H" );

 err_configure:
	pixbuf_put ( opts.config.pixbuf );
 err_pixbuf:
	/* Discard image unless --keep was specified */
	if ( image && ( ! opts.keep ) )
		unregister_image ( image );
 err_acquire:
 err_parse:
	return rc;
}

/** "colour" options */
struct colour_options {
	/** Basic colour */
	unsigned int basic;
	/** 24-bit RGB value */
	unsigned int rgb;
};

/** "colour" option list */
static struct option_descriptor colour_opts[] = {
	OPTION_DESC ( "basic", 'b', required_argument,
		      struct colour_options, basic, parse_integer ),
	OPTION_DESC ( "rgb", 'r', required_argument,
		      struct colour_options, rgb, parse_integer ),
};

/** "colour" command descriptor */
static struct command_descriptor colour_cmd =
	COMMAND_DESC ( struct colour_options, colour_opts, 1, 1, "<colour>" );

/**
 * "colour" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int colour_exec ( int argc, char **argv ) {
	struct colour_options opts;
	unsigned int colour;
	int rc;

	/* Initialise options */
	memset ( &opts, 0, sizeof ( opts ) );
	opts.basic = COLOUR_DEFAULT;
	opts.rgb = ANSICOL_NO_RGB;

	/* Parse options */
	if ( ( rc = reparse_options ( argc, argv, &colour_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse colour index */
	if ( ( rc = parse_integer ( argv[optind], &colour ) ) != 0 )
		return rc;

	/* Define colour */
	if ( ( rc = ansicol_define ( colour, opts.basic, opts.rgb ) ) != 0 ) {
		printf ( "Could not define colour: %s\n", strerror ( rc ) );
		return rc;
	}

	/* Reapply default colour pair, in case definition has changed */
	ansicol_set_pair ( CPAIR_DEFAULT );

	return 0;
}

/** "cpair" options */
struct cpair_options {
	/** Foreground colour */
	unsigned int foreground;
	/** Background colour */
	unsigned int background;
};

/** "cpair" option list */
static struct option_descriptor cpair_opts[] = {
	OPTION_DESC ( "foreground", 'f', required_argument,
		      struct cpair_options, foreground, parse_integer ),
	OPTION_DESC ( "background", 'b', required_argument,
		      struct cpair_options, background, parse_integer ),
};

/** "cpair" command descriptor */
static struct command_descriptor cpair_cmd =
	COMMAND_DESC ( struct cpair_options, cpair_opts, 1, 1, "<cpair>" );

/**
 * "cpair" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int cpair_exec ( int argc, char **argv ) {
	struct cpair_options opts;
	unsigned int cpair;
	int rc;

	/* Initialise options */
	memset ( &opts, 0, sizeof ( opts ) );
	opts.foreground = COLOUR_DEFAULT;
	opts.background = COLOUR_DEFAULT;

	/* Parse options */
	if ( ( rc = reparse_options ( argc, argv, &cpair_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse colour pair index */
	if ( ( rc = parse_integer ( argv[optind], &cpair ) ) != 0 )
		return rc;

	/* Define colour pair */
	if ( ( rc = ansicol_define_pair ( cpair, opts.foreground,
					  opts.background ) ) != 0 ) {
		printf ( "Could not define colour pair: %s\n",
			 strerror ( rc ) );
		return rc;
	}

	/* Reapply default colour pair, in case definition has changed */
	ansicol_set_pair ( CPAIR_DEFAULT );

	return 0;
}

/** Console management commands */
struct command console_commands[] __command = {
	{
		.name = "console",
		.exec = console_exec,
	},
	{
		.name = "colour",
		.exec = colour_exec,
	},
	{
		.name = "cpair",
		.exec = cpair_exec,
	},
};
