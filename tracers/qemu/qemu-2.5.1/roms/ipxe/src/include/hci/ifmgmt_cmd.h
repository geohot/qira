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

#ifndef _IFMGMT_CMD_H
#define _IFMGMT_CMD_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/parseopt.h>

struct net_device;

/** An "if<xxx>" command descriptor */
struct ifcommon_command_descriptor {
	/** Command descriptor */
	struct command_descriptor cmd;
	/** Payload
	 *
	 * @v netdev		Network device
	 * @v opts		Command options
	 * @ret rc		Return status code
	 */
	int ( * payload ) ( struct net_device *netdev, void *opts );
	/** Stop on first success */
	int stop_on_first_success;
};

/**
 * Construct "if<xxx>" command descriptor
 *
 * @v _struct		Options structure type
 * @v _options		Option descriptor array
 * @v _check_args	Remaining argument checker
 * @v _usage		Command usage
 * @ret _command	Command descriptor
 */
#define IFCOMMON_COMMAND_DESC( _struct, _options, _min_args,		\
			       _max_args, _usage, _payload,		\
			       _stop_on_first_success )			\
	{								\
		.cmd = COMMAND_DESC ( _struct, _options, _min_args,	\
				      _max_args, _usage ),		\
		.payload = ( ( int ( * ) ( struct net_device *netdev,	\
					   void *opts ) )		\
			     ( ( ( ( int ( * ) ( struct net_device *,	\
						 _struct * ) ) NULL )	\
				 == ( typeof ( _payload ) * ) NULL )	\
			       ? _payload : _payload ) ),		\
		.stop_on_first_success = _stop_on_first_success,	\
	}

extern int ifcommon_exec (  int argc, char **argv,
			    struct ifcommon_command_descriptor *cmd );
extern int ifconf_exec ( int argc, char **argv );

#endif /* _IFMGMT_CMD_H */
