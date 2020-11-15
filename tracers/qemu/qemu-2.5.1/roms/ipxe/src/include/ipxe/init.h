#ifndef _IPXE_INIT_H
#define _IPXE_INIT_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/tables.h>

/**
 * An initialisation function
 *
 * Initialisation functions are called exactly once, as part of the
 * call to initialise().
 */
struct init_fn {
	void ( * initialise ) ( void );
};

/** Initialisation function table */
#define INIT_FNS __table ( struct init_fn, "init_fns" )

/** Declare an initialisation functon */
#define __init_fn( init_order ) __table_entry ( INIT_FNS, init_order )

/** @defgroup initfn_order Initialisation function ordering
 * @{
 */

#define INIT_EARLY	01	/**< Early initialisation */
#define	INIT_CONSOLE	02	/**< Console initialisation */
#define INIT_NORMAL	03	/**< Normal initialisation */
#define INIT_LATE	04	/**< Late initialisation */

/** @} */

/**
 * A startup/shutdown function
 *
 * Startup and shutdown functions may be called multiple times, as
 * part of the calls to startup() and shutdown().
 */
struct startup_fn {
	void ( * startup ) ( void );
	void ( * shutdown ) ( int booting );
};

/** Startup/shutdown function table */
#define STARTUP_FNS __table ( struct startup_fn, "startup_fns" )

/** Declare a startup/shutdown function */
#define __startup_fn( startup_order ) \
	__table_entry ( STARTUP_FNS, startup_order )

/** @defgroup startfn_order Startup/shutdown function ordering
 *
 * Shutdown functions are called in the reverse order to startup
 * functions.
 *
 * @{
 */

#define STARTUP_EARLY	01	/**< Early startup */
#define STARTUP_NORMAL	02	/**< Normal startup */
#define STARTUP_LATE	03	/**< Late startup */

/** @} */

extern void initialise ( void );
extern void startup ( void );
extern void shutdown ( int booting );

/**
 * Shut down system for OS boot
 *
 */
static inline void shutdown_boot ( void ) {
	shutdown ( 1 );
}

/**
 * Shut down system for exit back to firmware
 *
 */
static inline void shutdown_exit ( void ) {
	shutdown ( 0 );
}

#endif /* _IPXE_INIT_H */
