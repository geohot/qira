#ifndef _IPXE_JOB_H
#define _IPXE_JOB_H

/** @file
 *
 * Job control interfaces
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/interface.h>

/** Job progress */
struct job_progress {
	/** Amount of operation completed so far
	 *
	 * The units for this quantity are arbitrary.  @c completed
	 * divded by @total should give something which approximately
	 * represents the progress through the operation.  For a
	 * download operation, using byte counts would make sense.
	 */
	unsigned long completed;
	/** Total operation size
	 *
	 * See @c completed.  A zero value means "total size unknown"
	 * and is explcitly permitted; users should take this into
	 * account before calculating @c completed/total.
	 */
	unsigned long total;
};

extern int job_progress ( struct interface *intf,
			  struct job_progress *progress );
#define job_progress_TYPE( object_type ) \
	typeof ( int ( object_type, struct job_progress *progress ) )

#endif /* _IPXE_JOB_H */
