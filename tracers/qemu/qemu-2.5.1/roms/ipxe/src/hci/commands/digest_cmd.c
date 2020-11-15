/*
 * Copyright (C) 2009 Daniel Verkamp <daniel@drv.nu>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/image.h>
#include <ipxe/crypto.h>
#include <ipxe/md5.h>
#include <ipxe/sha1.h>
#include <usr/imgmgmt.h>

/** @file
 *
 * Digest commands
 *
 */

/** "digest" options */
struct digest_options {};

/** "digest" option list */
static struct option_descriptor digest_opts[] = {};

/** "digest" command descriptor */
static struct command_descriptor digest_cmd =
	COMMAND_DESC ( struct digest_options, digest_opts, 1, MAX_ARGUMENTS,
		       "<image> [<image>...]" );

/**
 * The "digest" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v digest		Digest algorithm
 * @ret rc		Return status code
 */
static int digest_exec ( int argc, char **argv,
			 struct digest_algorithm *digest ) {
	struct digest_options opts;
	struct image *image;
	uint8_t digest_ctx[digest->ctxsize];
	uint8_t digest_out[digest->digestsize];
	uint8_t buf[128];
	size_t offset;
	size_t len;
	size_t frag_len;
	int i;
	unsigned j;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &digest_cmd, &opts ) ) != 0 )
		return rc;

	for ( i = optind ; i < argc ; i++ ) {

		/* Acquire image */
		if ( ( rc = imgacquire ( argv[i], 0, &image ) ) != 0 )
			continue;
		offset = 0;
		len = image->len;

		/* calculate digest */
		digest_init ( digest, digest_ctx );
		while ( len ) {
			frag_len = len;
			if ( frag_len > sizeof ( buf ) )
				frag_len = sizeof ( buf );
			copy_from_user ( buf, image->data, offset, frag_len );
			digest_update ( digest, digest_ctx, buf, frag_len );
			len -= frag_len;
			offset += frag_len;
		}
		digest_final ( digest, digest_ctx, digest_out );

		for ( j = 0 ; j < sizeof ( digest_out ) ; j++ )
			printf ( "%02x", digest_out[j] );

		printf ( "  %s\n", image->name );
	}

	return 0;
}

static int md5sum_exec ( int argc, char **argv ) {
	return digest_exec ( argc, argv, &md5_algorithm );
}

static int sha1sum_exec ( int argc, char **argv ) {
	return digest_exec ( argc, argv, &sha1_algorithm );
}

struct command md5sum_command __command = {
	.name = "md5sum",
	.exec = md5sum_exec,
};

struct command sha1sum_command __command = {
	.name = "sha1sum",
	.exec = sha1sum_exec,
};
