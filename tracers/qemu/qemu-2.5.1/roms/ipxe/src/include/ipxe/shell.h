#ifndef _IPXE_SHELL_H
#define _IPXE_SHELL_H

/** @file
 *
 * Minimal command shell
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Shell stop states */
enum shell_stop_state {
	/** Continue processing */
	SHELL_CONTINUE = 0,
	/**
	 * Stop processing current command line
	 *
	 * This is the stop state entered by commands that change the flow
	 * of execution, such as "goto".
	 */
	SHELL_STOP_COMMAND = 1,
	/**
	 * Stop processing commands
	 *
	 * This is the stop state entered by commands that terminate
	 * the flow of execution, such as "exit".
	 */
	SHELL_STOP_COMMAND_SEQUENCE = 2,
};

extern void shell_stop ( int stop );
extern int shell_stopped ( int stop );
extern int shell ( void );

#endif /* _IPXE_SHELL_H */
