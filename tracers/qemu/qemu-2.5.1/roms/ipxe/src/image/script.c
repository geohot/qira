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

/**
 * @file
 *
 * iPXE scripts
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/image.h>
#include <ipxe/shell.h>
#include <usr/prompt.h>
#include <ipxe/script.h>

/** Offset within current script
 *
 * This is a global in order to allow goto_exec() to update the
 * offset.
 */
static size_t script_offset;

/**
 * Process script lines
 *
 * @v image		Script
 * @v process_line	Line processor
 * @v terminate		Termination check
 * @ret rc		Return status code
 */
static int process_script ( struct image *image,
			    int ( * process_line ) ( struct image *image,
						     size_t offset,
						     const char *label,
						     const char *command ),
			    int ( * terminate ) ( int rc ) ) {
	size_t len = 0;
	char *line = NULL;
	size_t line_offset;
	char *label;
	char *command;
	off_t eol;
	size_t frag_len;
	char *tmp;
	int rc;

	/* Initialise script and line offsets */
	script_offset = 0;
	line_offset = 0;

	do {

		/* Find length of next line, excluding any terminating '\n' */
		eol = memchr_user ( image->data, script_offset, '\n',
				    ( image->len - script_offset ) );
		if ( eol < 0 )
			eol = image->len;
		frag_len = ( eol - script_offset );

		/* Allocate buffer for line */
		tmp = realloc ( line, ( len + frag_len + 1 /* NUL */ ) );
		if ( ! tmp ) {
			rc = -ENOMEM;
			goto err_alloc;
		}
		line = tmp;

		/* Copy line */
		copy_from_user ( ( line + len ), image->data, script_offset,
				 frag_len );
		len += frag_len;

		/* Move to next line in script */
		script_offset += ( frag_len + 1 );

		/* Strip trailing CR, if present */
		if ( len && ( line[ len - 1 ] == '\r' ) )
			len--;

		/* Handle backslash continuations */
		if ( len && ( line[ len - 1 ] == '\\' ) ) {
			len--;
			rc = -EINVAL;
			continue;
		}

		/* Terminate line */
		line[len] = '\0';

		/* Split line into (optional) label and command */
		command = line;
		while ( isspace ( *command ) )
			command++;
		if ( *command == ':' ) {
			label = ++command;
			while ( *command && ! isspace ( *command ) )
				command++;
			if ( *command )
				*(command++) = '\0';
		} else {
			label = NULL;
		}

		/* Process line */
		rc = process_line ( image, line_offset, label, command );
		if ( terminate ( rc ) )
			goto err_process;

		/* Free line */
		free ( line );
		line = NULL;
		len = 0;

		/* Update line offset */
		line_offset = script_offset;

	} while ( script_offset < image->len );

 err_process:
 err_alloc:
	free ( line );
	return rc;
}

/**
 * Terminate script processing on shell exit or command failure
 *
 * @v rc		Line processing status
 * @ret terminate	Terminate script processing
 */
static int terminate_on_exit_or_failure ( int rc ) {

	return ( shell_stopped ( SHELL_STOP_COMMAND_SEQUENCE ) ||
		 ( rc != 0 ) );
}

/**
 * Execute script line
 *
 * @v image		Script
 * @v offset		Offset within script
 * @v label		Label, or NULL
 * @v command		Command
 * @ret rc		Return status code
 */
static int script_exec_line ( struct image *image, size_t offset,
			      const char *label __unused,
			      const char *command ) {
	int rc;

	DBGC ( image, "[%04zx] $ %s\n", offset, command );

	/* Execute command */
	if ( ( rc = system ( command ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Execute script
 *
 * @v image		Script
 * @ret rc		Return status code
 */
static int script_exec ( struct image *image ) {
	size_t saved_offset;
	int rc;

	/* Temporarily de-register image, so that a "boot" command
	 * doesn't throw us into an execution loop.
	 */
	unregister_image ( image );

	/* Preserve state of any currently-running script */
	saved_offset = script_offset;

	/* Process script */
	rc = process_script ( image, script_exec_line,
			      terminate_on_exit_or_failure );

	/* Restore saved state */
	script_offset = saved_offset;

	/* Re-register image (unless we have been replaced) */
	if ( ! image->replacement )
		register_image ( image );

	return rc;
}

/**
 * Probe script image
 *
 * @v image		Script
 * @ret rc		Return status code
 */
static int script_probe ( struct image *image ) {
	static const char ipxe_magic[] = "#!ipxe";
	static const char gpxe_magic[] = "#!gpxe";
	linker_assert ( sizeof ( ipxe_magic ) == sizeof ( gpxe_magic ),
			magic_size_mismatch );
	char test[ sizeof ( ipxe_magic ) - 1 /* NUL */
		   + 1 /* terminating space */];

	/* Sanity check */
	if ( image->len < sizeof ( test ) ) {
		DBGC ( image, "Too short to be a script\n" );
		return -ENOEXEC;
	}

	/* Check for magic signature */
	copy_from_user ( test, image->data, 0, sizeof ( test ) );
	if ( ! ( ( ( memcmp ( test, ipxe_magic, sizeof ( test ) - 1 ) == 0 ) ||
		   ( memcmp ( test, gpxe_magic, sizeof ( test ) - 1 ) == 0 )) &&
		 isspace ( test[ sizeof ( test ) - 1 ] ) ) ) {
		DBGC ( image, "Invalid magic signature\n" );
		return -ENOEXEC;
	}

	return 0;
}

/** Script image type */
struct image_type script_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "script",
	.probe = script_probe,
	.exec = script_exec,
};

/** "goto" options */
struct goto_options {};

/** "goto" option list */
static struct option_descriptor goto_opts[] = {};

/** "goto" command descriptor */
static struct command_descriptor goto_cmd =
	COMMAND_DESC ( struct goto_options, goto_opts, 1, 1, "<label>" );

/**
 * Current "goto" label
 *
 * Valid only during goto_exec().  Consider this part of a closure.
 */
static const char *goto_label;

/**
 * Check for presence of label
 *
 * @v image		Script
 * @v offset		Offset within script
 * @v label		Label
 * @v command		Command
 * @ret rc		Return status code
 */
static int goto_find_label ( struct image *image, size_t offset,
			     const char *label, const char *command __unused ) {

	/* Check label exists */
	if ( ! label )
		return -ENOENT;

	/* Check label matches */
	if ( strcmp ( goto_label, label ) != 0 )
		return -ENOENT;

	/* Update script offset */
	script_offset = offset;
	DBGC ( image, "[%04zx] Gone to :%s\n", offset, label );

	return 0;
}

/**
 * Terminate script processing when label is found
 *
 * @v rc		Line processing status
 * @ret terminate	Terminate script processing
 */
static int terminate_on_label_found ( int rc ) {
	return ( rc == 0 );
}

/**
 * "goto" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int goto_exec ( int argc, char **argv ) {
	struct goto_options opts;
	size_t saved_offset;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &goto_cmd, &opts ) ) != 0 )
		return rc;

	/* Sanity check */
	if ( ! current_image ) {
		rc = -ENOTTY;
		printf ( "Not in a script: %s\n", strerror ( rc ) );
		return rc;
	}

	/* Parse label */
	goto_label = argv[optind];

	/* Find label */
	saved_offset = script_offset;
	if ( ( rc = process_script ( current_image, goto_find_label,
				     terminate_on_label_found ) ) != 0 ) {
		script_offset = saved_offset;
		DBGC ( current_image, "[%04zx] No such label :%s\n",
		       script_offset, goto_label );
		return rc;
	}

	/* Terminate processing of current command */
	shell_stop ( SHELL_STOP_COMMAND );

	return 0;
}

/** "goto" command */
struct command goto_command __command = {
	.name = "goto",
	.exec = goto_exec,
};

/** "prompt" options */
struct prompt_options {
	/** Key to wait for */
	unsigned int key;
	/** Timeout */
	unsigned long timeout;
};

/** "prompt" option list */
static struct option_descriptor prompt_opts[] = {
	OPTION_DESC ( "key", 'k', required_argument,
		      struct prompt_options, key, parse_key ),
	OPTION_DESC ( "timeout", 't', required_argument,
		      struct prompt_options, timeout, parse_timeout ),
};

/** "prompt" command descriptor */
static struct command_descriptor prompt_cmd =
	COMMAND_DESC ( struct prompt_options, prompt_opts, 0, MAX_ARGUMENTS,
		       "[<text>]" );

/**
 * "prompt" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int prompt_exec ( int argc, char **argv ) {
	struct prompt_options opts;
	char *text;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &prompt_cmd, &opts ) ) != 0 )
		goto err_parse;

	/* Parse prompt text */
	text = concat_args ( &argv[optind] );
	if ( ! text ) {
		rc = -ENOMEM;
		goto err_concat;
	}

	/* Display prompt and wait for key */
	if ( ( rc = prompt ( text, opts.timeout, opts.key ) ) != 0 )
		goto err_prompt;

	/* Free prompt text */
	free ( text );

	return 0;

 err_prompt:
	free ( text );
 err_concat:
 err_parse:
	return rc;
}

/** "prompt" command */
struct command prompt_command __command = {
	.name = "prompt",
	.exec = prompt_exec,
};
