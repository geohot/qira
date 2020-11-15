#ifndef _IPXE_SYSLOG_H
#define _IPXE_SYSLOG_H

/** @file
 *
 * Syslog protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <syslog.h>

/** Syslog server port */
#define SYSLOG_PORT 514

/** Syslog line buffer size
 *
 * This is a policy decision
 */
#define SYSLOG_BUFSIZE 128

/** Syslog default facility
 *
 * This is a policy decision
 */
#define SYSLOG_DEFAULT_FACILITY 0 /* kernel */

/** Syslog default severity
 *
 * This is a policy decision
 */
#define SYSLOG_DEFAULT_SEVERITY LOG_INFO

/** Syslog priority */
#define SYSLOG_PRIORITY( facility, severity ) ( 8 * (facility) + (severity) )

extern int syslog_send ( struct interface *xfer, unsigned int severity,
			 const char *message, const char *terminator );

#endif /* _IPXE_SYSLOG_H */
