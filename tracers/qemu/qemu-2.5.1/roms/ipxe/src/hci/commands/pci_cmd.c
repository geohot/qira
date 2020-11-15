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

#include <stdio.h>
#include <getopt.h>
#include <ipxe/pci.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * PCI commands
 *
 */

/** "pciscan" options */
struct pciscan_options {};

/** "pciscan" option list */
static struct option_descriptor pciscan_opts[] = {};

/** "pciscan" command descriptor */
static struct command_descriptor pciscan_cmd =
	COMMAND_DESC ( struct pciscan_options, pciscan_opts, 1, 1,
		       "<setting>" );

/**
 * "pciscan" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int pciscan_exec ( int argc, char **argv ) {
	struct pciscan_options opts;
	struct named_setting setting;
	struct pci_device pci;
	unsigned long prev;
	int next;
	int len;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &pciscan_cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse setting name */
	if ( ( rc = parse_autovivified_setting ( argv[optind],
						 &setting ) ) != 0 )
		goto err_parse_setting;

	/* Determine starting bus:dev.fn address */
	if ( ( len = fetchn_setting ( setting.settings, &setting.setting,
				      NULL, &setting.setting, &prev ) ) < 0 ) {
		/* Setting not yet defined: start searching from 00:00.0 */
		prev = 0;
	} else {
		/* Setting is defined: start searching from next location */
		prev++;
	}

	/* Find next existent PCI device */
	if ( ( next = pci_find_next ( &pci, prev ) ) < 0 ) {
		rc = next;
		goto err_find_next;
	}

	/* Apply default type if necessary.  Use ":uint16" rather than
	 * ":busdevfn" to allow for easy inclusion within a
	 * "${pci/${location}.x.y}" constructed setting.
	 */
	if ( ! setting.setting.type )
		setting.setting.type = &setting_type_uint16;

	/* Store setting */
	if ( ( rc = storen_setting ( setting.settings, &setting.setting,
				     next ) ) != 0 ) {
		printf ( "Could not store \"%s\": %s\n",
			 setting.setting.name, strerror ( rc ) );
		goto err_store;
	}

 err_store:
 err_find_next:
 err_parse_setting:
 err_parse_options:
	return rc;
}

/** PCI commands */
struct command pci_commands[] __command = {
	{
		.name = "pciscan",
		.exec = pciscan_exec,
	},
};
