#ifndef _SYSLOG_H
#define _SYSLOG_H

/** @file
 *
 * System logger
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdarg.h>
#include <ipxe/ansiesc.h>
#include <config/console.h>

/**
 * @defgroup syslogpri Syslog priorities
 *
 * These values are chosen to match those used in the syslog network
 * protocol (RFC 5424).
 *
 * @{
 */

/** Emergency: system is unusable */
#define LOG_EMERG 0

/** Alert: action must be taken immediately */
#define LOG_ALERT 1

/** Critical: critical conditions */
#define LOG_CRIT 2

/** Error: error conditions */
#define LOG_ERR 3

/** Warning: warning conditions */
#define LOG_WARNING 4

/** Notice: normal but significant conditions */
#define LOG_NOTICE 5

/** Informational: informational messages */
#define LOG_INFO 6

/** Debug: debug-level messages */
#define LOG_DEBUG 7

/** @} */

/** Do not log any messages */
#define LOG_NONE -1

/** Log all messages */
#define LOG_ALL LOG_DEBUG

extern void log_vprintf ( const char *fmt, va_list args );

extern void __attribute__ (( format ( printf, 1, 2 ) ))
log_printf ( const char *fmt, ... );

/** ANSI private escape sequence to set syslog priority
 *
 * @v priority		Priority
 */
#define SYSLOG_SET_PRIORITY( priority ) \
	"\033[" #priority "p"

/** ANSI private escape sequence to clear syslog priority */
#define SYSLOG_CLEAR_PRIORITY "\033[p"

/**
 * Write message to system log
 *
 * @v priority		Message priority
 * @v fmt		Format string
 * @v ...		Arguments
 */
#define vsyslog( priority, fmt, args ) do {				\
	if ( (priority) <= LOG_LEVEL ) {				\
		log_vprintf ( SYSLOG_SET_PRIORITY ( priority ) fmt	\
			      SYSLOG_CLEAR_PRIORITY, (args) );		\
	}								\
	} while ( 0 )

/**
 * Write message to system log
 *
 * @v priority		Message priority
 * @v fmt		Format string
 * @v ...		Arguments
 */
#define syslog( priority, fmt, ... ) do {				\
	if ( (priority) <= LOG_LEVEL ) {				\
		log_printf ( SYSLOG_SET_PRIORITY ( priority ) fmt	\
			     SYSLOG_CLEAR_PRIORITY, ##__VA_ARGS__ );	\
	}								\
	} while ( 0 )

#endif /* _SYSLOG_H */
