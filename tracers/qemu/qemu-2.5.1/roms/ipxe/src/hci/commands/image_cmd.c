/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/image.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/shell.h>
#include <usr/imgmgmt.h>

/** @file
 *
 * Image management commands
 *
 */

/** "img{single}" options */
struct imgsingle_options {
	/** Image name */
	char *name;
	/** Download timeout */
	unsigned long timeout;
	/** Replace image */
	int replace;
	/** Free image after execution */
	int autofree;
};

/** "img{single}" option list */
static union {
	/* "imgexec" takes all three options */
	struct option_descriptor imgexec[4];
	/* Other "img{single}" commands take only --name, --timeout,
	 * and --autofree
	 */
	struct option_descriptor imgsingle[3];
} opts = {
	.imgexec = {
		OPTION_DESC ( "name", 'n', required_argument,
			      struct imgsingle_options, name, parse_string ),
		OPTION_DESC ( "timeout", 't', required_argument,
			      struct imgsingle_options, timeout, parse_timeout),
		OPTION_DESC ( "autofree", 'a', no_argument,
			      struct imgsingle_options, autofree, parse_flag ),
		OPTION_DESC ( "replace", 'r', no_argument,
			      struct imgsingle_options, replace, parse_flag ),
	},
};

/** An "img{single}" family command descriptor */
struct imgsingle_descriptor {
	/** Command descriptor */
	struct command_descriptor *cmd;
	/** Function to use to acquire the image */
	int ( * acquire ) ( const char *name, unsigned long timeout,
			    struct image **image );
	/** Pre-action to take upon image, or NULL */
	void ( * preaction ) ( struct image *image );
	/** Action to take upon image, or NULL */
	int ( * action ) ( struct image *image,
			   struct imgsingle_options *opts );
	/** Verb to describe action */
	const char *verb;
};

/**
 * The "img{single}" family of commands
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v desc		"img{single}" command descriptor
 * @v action_name	Action name (for error messages)
 * @v action		Action to take upon image
 * @ret rc		Return status code
 */
static int imgsingle_exec ( int argc, char **argv,
			    struct imgsingle_descriptor *desc ) {
	struct imgsingle_options opts;
	char *name_uri = NULL;
	char *cmdline = NULL;
	struct image *image;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, desc->cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse name/URI string and command line, if present */
	if ( optind < argc ) {
		name_uri = argv[optind];
		if ( argv[ optind + 1 ] != NULL ) {
			cmdline = concat_args ( &argv[ optind + 1 ] );
			if ( ! cmdline ) {
				rc = -ENOMEM;
				goto err_parse_cmdline;
			}
		}
	}

	/* Acquire the image */
	if ( name_uri ) {
		if ( ( rc = desc->acquire ( name_uri, opts.timeout,
					    &image ) ) != 0 )
			goto err_acquire;
	} else {
		image = image_find_selected();
		if ( ! image ) {
			printf ( "No image selected\n" );
			goto err_acquire;
		}
	}

	/* Carry out command pre-action, if applicable */
	if ( desc->preaction )
		desc->preaction ( image );

	/* Set the image name, if applicable */
	if ( opts.name ) {
		if ( ( rc = image_set_name ( image, opts.name ) ) != 0 ) {
			printf ( "Could not name image: %s\n",
				 strerror ( rc ) );
			goto err_set_name;
		}
	}

	/* Set the command-line arguments, if applicable */
	if ( cmdline ) {
		if ( ( rc = image_set_cmdline ( image, cmdline ) ) != 0 ) {
			printf ( "Could not set arguments: %s\n",
				 strerror ( rc ) );
			goto err_set_cmdline;
		}
	}

	/* Set the auto-unregister flag, if applicable */
	if ( opts.autofree )
		image->flags |= IMAGE_AUTO_UNREGISTER;

	/* Carry out command action, if applicable */
	if ( desc->action ) {
		if ( ( rc = desc->action ( image, &opts ) ) != 0 ) {
			printf ( "Could not %s: %s\n",
				 desc->verb, strerror ( rc ) );
			goto err_action;
		}
	}

	/* Success */
	rc = 0;

 err_action:
 err_set_cmdline:
 err_set_name:
 err_acquire:
	free ( cmdline );
 err_parse_cmdline:
 err_parse_options:
	return rc;
}

/** "imgfetch" command descriptor */
static struct command_descriptor imgfetch_cmd =
	COMMAND_DESC ( struct imgsingle_options, opts.imgsingle,
		       1, MAX_ARGUMENTS, "<uri> [<arguments>...]" );

/** "imgfetch" family command descriptor */
struct imgsingle_descriptor imgfetch_desc = {
	.cmd = &imgfetch_cmd,
	.acquire = imgdownload_string,
};

/**
 * The "imgfetch" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgfetch_exec ( int argc, char **argv ) {
	return imgsingle_exec ( argc, argv, &imgfetch_desc );
}

/**
 * "imgselect" command action
 *
 * @v image		Image
 * @v opts		Options
 * @ret rc		Return status code
 */
static int imgselect ( struct image *image,
		       struct imgsingle_options *opts __unused ) {
	return image_select ( image );
}

/** "imgselect" command descriptor */
static struct command_descriptor imgselect_cmd =
	COMMAND_DESC ( struct imgsingle_options, opts.imgsingle,
		       1, MAX_ARGUMENTS, "<uri|image> [<arguments>...]" );

/** "imgselect" family command descriptor */
struct imgsingle_descriptor imgselect_desc = {
	.cmd = &imgselect_cmd,
	.acquire = imgacquire,
	.action = imgselect,
	.verb = "select",
};

/**
 * The "imgselect" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgselect_exec ( int argc, char **argv ) {
	return imgsingle_exec ( argc, argv, &imgselect_desc );
}

/** "imgexec" command descriptor */
static struct command_descriptor imgexec_cmd =
	COMMAND_DESC ( struct imgsingle_options, opts.imgexec,
		       0, MAX_ARGUMENTS, "[<uri|image> [<arguments>...]]" );

/**
 * "imgexec" command action
 *
 * @v image		Image
 * @v opts		Options
 * @ret rc		Return status code
 */
static int imgexec ( struct image *image, struct imgsingle_options *opts ) {
	int rc;

	/* Perform replacement or execution as applicable */
	if ( opts->replace ) {

		/* Try to replace image */
		if ( ( rc = image_replace ( image ) ) != 0 )
			return rc;

		/* Stop script and tail-recurse into replacement image */
		shell_stop ( SHELL_STOP_COMMAND_SEQUENCE );

	} else {

		/* Try to execute image */
		if ( ( rc = image_exec ( image ) ) != 0 )
			return rc;
	}

	return 0;
}

/** "imgexec" family command descriptor */
struct imgsingle_descriptor imgexec_desc = {
	.cmd = &imgexec_cmd,
	.acquire = imgacquire,
	.action = imgexec,
	.verb = "boot",
};

/**
 * The "imgexec" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgexec_exec ( int argc, char **argv) {
	return imgsingle_exec ( argc, argv, &imgexec_desc );
}

/** "imgargs" command descriptor */
static struct command_descriptor imgargs_cmd =
	COMMAND_DESC ( struct imgsingle_options, opts.imgsingle,
		       1, MAX_ARGUMENTS, "<uri|image> [<arguments>...]" );

/** "imgargs" family command descriptor */
struct imgsingle_descriptor imgargs_desc = {
	.cmd = &imgargs_cmd,
	.acquire = imgacquire,
	.preaction = image_clear_cmdline,
};

/**
 * The "imgargs" command body
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgargs_exec ( int argc, char **argv ) {
	return imgsingle_exec ( argc, argv, &imgargs_desc );
}

/** "img{multi}" options */
struct imgmulti_options {};

/** "img{multi}" option list */
static struct option_descriptor imgmulti_opts[] = {};

/** "img{multi}" command descriptor */
static struct command_descriptor imgmulti_cmd =
	COMMAND_DESC ( struct imgmulti_options, imgmulti_opts, 0, MAX_ARGUMENTS,
		       "[<image>...]" );

/**
 * The "img{multi}" family of commands
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v payload		Function to execute on each image
 * @ret rc		Return status code
 */
static int imgmulti_exec ( int argc, char **argv,
			   void ( * payload ) ( struct image *image ) ) {
	struct imgmulti_options opts;
	struct image *image;
	struct image *tmp;
	int i;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgmulti_cmd, &opts ) ) != 0 )
		return rc;

	/* If no images are explicitly specified, process all images */
	if ( optind == argc ) {
		for_each_image_safe ( image, tmp )
			payload ( image );
		return 0;
	}

	/* Otherwise, process specified images */
	for ( i = optind ; i < argc ; i++ ) {
		image = find_image ( argv[i] );
		if ( ! image ) {
			printf ( "\"%s\": no such image\n", argv[i] );
			return -ENOENT;
		}
		payload ( image );
	}

	return 0;
}

/**
 * The "imgstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgstat_exec ( int argc, char **argv ) {
	return imgmulti_exec ( argc, argv, imgstat );
}

/**
 * The "imgfree" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgfree_exec ( int argc, char **argv ) {
	return imgmulti_exec ( argc, argv, unregister_image );
}

/** Image management commands */
struct command image_commands[] __command = {
	{
		.name = "imgfetch",
		.exec = imgfetch_exec,
	},
	{
		.name = "module",
		.exec = imgfetch_exec, /* synonym for "imgfetch" */
	},
	{
		.name = "initrd",
		.exec = imgfetch_exec, /* synonym for "imgfetch" */
	},
	{
		.name = "kernel",
		.exec = imgselect_exec, /* synonym for "imgselect" */
	},
	{
		.name = "chain",
		.exec = imgexec_exec, /* synonym for "imgexec" */
	},
	{
		.name = "imgselect",
		.exec = imgselect_exec,
	},
	{
		.name = "imgload",
		.exec = imgselect_exec, /* synonym for "imgselect" */
	},
	{
		.name = "imgargs",
		.exec = imgargs_exec,
	},
	{
		.name = "imgexec",
		.exec = imgexec_exec,
	},
	{
		.name = "boot", /* synonym for "imgexec" */
		.exec = imgexec_exec,
	},
	{
		.name = "imgstat",
		.exec = imgstat_exec,
	},
	{
		.name = "imgfree",
		.exec = imgfree_exec,
	},
};
