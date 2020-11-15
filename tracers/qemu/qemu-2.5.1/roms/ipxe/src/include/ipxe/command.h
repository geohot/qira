#ifndef _IPXE_COMMAND_H
#define _IPXE_COMMAND_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/tables.h>

/** A command-line command */
struct command {
	/** Name of the command */
	const char *name;
	/**
	 * Function implementing the command
	 *
	 * @v argc		Argument count
	 * @v argv		Argument list
	 * @ret rc		Return status code
	 */
	int ( * exec ) ( int argc, char **argv );
};

#define COMMANDS __table ( struct command, "commands" )

#define __command __table_entry ( COMMANDS, 01 )

extern char * concat_args ( char **args );

#endif /* _IPXE_COMMAND_H */
