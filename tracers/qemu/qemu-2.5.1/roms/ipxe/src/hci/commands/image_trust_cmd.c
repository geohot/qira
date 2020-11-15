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
#include <getopt.h>
#include <ipxe/image.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/imgmgmt.h>
#include <usr/imgtrust.h>

/** @file
 *
 * Image trust management commands
 *
 */

/** "imgtrust" options */
struct imgtrust_options {
	/** Allow trusted images */
	int allow;
	/** Make trust requirement permanent */
	int permanent;
};

/** "imgtrust" option list */
static struct option_descriptor imgtrust_opts[] = {
	OPTION_DESC ( "allow", 'a', no_argument,
		      struct imgtrust_options, allow, parse_flag ),
	OPTION_DESC ( "permanent", 'p', no_argument,
		      struct imgtrust_options, permanent, parse_flag ),
};

/** "imgtrust" command descriptor */
static struct command_descriptor imgtrust_cmd =
	COMMAND_DESC ( struct imgtrust_options, imgtrust_opts, 0, 0, NULL );

/**
 * The "imgtrust" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgtrust_exec ( int argc, char **argv ) {
	struct imgtrust_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgtrust_cmd, &opts ) ) != 0 )
		return rc;

	/* Set trust requirement */
	if ( ( rc = image_set_trust ( ( ! opts.allow ),
				      opts.permanent ) ) != 0 ) {
		printf ( "Could not set image trust requirement: %s\n",
			 strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** "imgverify" options */
struct imgverify_options {
	/** Required signer common name */
	char *signer;
	/** Keep signature after verification */
	int keep;
	/** Download timeout */
	unsigned long timeout;
};

/** "imgverify" option list */
static struct option_descriptor imgverify_opts[] = {
	OPTION_DESC ( "signer", 's', required_argument,
		      struct imgverify_options, signer, parse_string ),
	OPTION_DESC ( "keep", 'k', no_argument,
		      struct imgverify_options, keep, parse_flag ),
	OPTION_DESC ( "timeout", 't', required_argument,
		      struct imgverify_options, timeout, parse_timeout),
};

/** "imgverify" command descriptor */
static struct command_descriptor imgverify_cmd =
	COMMAND_DESC ( struct imgverify_options, imgverify_opts, 2, 2,
		       "<uri|image> <signature uri|image>" );

/**
 * The "imgverify" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgverify_exec ( int argc, char **argv ) {
	struct imgverify_options opts;
	const char *image_name_uri;
	const char *signature_name_uri;
	struct image *image;
	struct image *signature;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgverify_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse image name/URI string */
	image_name_uri = argv[optind];

	/* Parse signature name/URI string */
	signature_name_uri = argv[ optind + 1 ];

	/* Acquire the image */
	if ( ( rc = imgacquire ( image_name_uri, opts.timeout, &image ) ) != 0 )
		goto err_acquire_image;

	/* Acquire the signature image */
	if ( ( rc = imgacquire ( signature_name_uri, opts.timeout,
				 &signature ) ) != 0 )
		goto err_acquire_signature;

	/* Verify image */
	if ( ( rc = imgverify ( image, signature, opts.signer ) ) != 0 ) {
		printf ( "Could not verify: %s\n", strerror ( rc ) );
		goto err_verify;
	}

	/* Success */
	rc = 0;

 err_verify:
	/* Discard signature unless --keep was specified */
	if ( ! opts.keep )
		unregister_image ( signature );
 err_acquire_signature:
 err_acquire_image:
	return rc;
}

/** Image trust management commands */
struct command image_trust_commands[] __command = {
	{
		.name = "imgtrust",
		.exec = imgtrust_exec,
	},
	{
		.name = "imgverify",
		.exec = imgverify_exec,
	},
};

/* Drag in objects via command list */
REQUIRING_SYMBOL ( image_trust_commands );

/* Drag in objects typically required for signature verification */
REQUIRE_OBJECT ( rsa );
REQUIRE_OBJECT ( md5 );
REQUIRE_OBJECT ( sha1 );
REQUIRE_OBJECT ( sha256 );
