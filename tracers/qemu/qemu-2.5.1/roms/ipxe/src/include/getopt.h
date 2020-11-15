#ifndef _GETOPT_H
#define _GETOPT_H

/** @file
 *
 * Parse command-line options
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>

enum getopt_argument_requirement {
	/** Option does not take an argument */
	no_argument = 0,
	/** Option requires an argument */
	required_argument = 1,
	/** Option may have an argument */
	optional_argument = 2,
};

/** A long option, as used for getopt_long() */
struct option {
	/** Long name of this option */
	const char *name;
	/** Option takes an argument
	 *
	 * Must be one of @c no_argument, @c required_argument, or @c
	 * optional_argument.
	 */
	int has_arg;
	/** Location into which to store @c val, or NULL.
	 *
	 * See the description for @c val for more details.
	 */
	int *flag;
	/** Value to return
	 *
	 * If @c flag is NULL, then this is the value that will be
	 * returned by getopt_long() when this option is found, and
	 * should therefore be set to the equivalent short option
	 * character.
	 *
	 * If @c flag is non-NULL, then this value will be written to
	 * the location pointed to by @flag, and getopt_long() will
	 * return 0.
	 */
	int val;
};

extern char *optarg;
extern int optind;
extern int nextchar;
extern int optopt;

extern int getopt_long ( int argc, char * const argv[], const char *optstring,
			 const struct option *longopts, int *longindex );

/**
 * Parse command-line options
 *
 * @v argv		Argument count
 * @v argv		Argument list
 * @v optstring		Option specification string
 * @ret option		Option found, or -1 for no more options
 *
 * See getopt_long() for full details.
 */
static inline int getopt ( int argc, char * const argv[],
			   const char *optstring ) {
	static const struct option no_options[] = {
		{ NULL, 0, NULL, 0 }
	};
	return getopt_long ( argc, argv, optstring, no_options, NULL );
}

/**
 * Reset getopt() internal state
 *
 * Due to a limitation of the POSIX getopt() API, it is necessary to
 * add a call to reset_getopt() before each set of calls to getopt()
 * or getopt_long().  This arises because POSIX assumes that each
 * process will parse command line arguments no more than once; this
 * assumption is not valid within Etherboot.  We work around the
 * limitation by arranging for execv() to call reset_getopt() before
 * executing the command.
 */
static inline void reset_getopt ( void ) {
	optind = 1;
	nextchar = 0;
}

#endif /* _GETOPT_H */
