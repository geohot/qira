/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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

/** @file
 *
 * Syslog protocol
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <byteswap.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/tcpip.h>
#include <ipxe/dhcp.h>
#include <ipxe/dhcpv6.h>
#include <ipxe/settings.h>
#include <ipxe/console.h>
#include <ipxe/lineconsole.h>
#include <ipxe/syslog.h>
#include <config/console.h>

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_SYSLOG ) && CONSOLE_EXPLICIT ( CONSOLE_SYSLOG ) )
#undef CONSOLE_SYSLOG
#define CONSOLE_SYSLOG ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_TUI )
#endif

/** The syslog server */
static union {
	struct sockaddr sa;
	struct sockaddr_tcpip st;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
} logserver = {
	.st = {
		.st_port = htons ( SYSLOG_PORT ),
	},
};

/** Syslog UDP interface operations */
static struct interface_operation syslogger_operations[] = {};

/** Syslog UDP interface descriptor */
static struct interface_descriptor syslogger_desc =
	INTF_DESC_PURE ( syslogger_operations );

/** The syslog UDP interface */
static struct interface syslogger = INTF_INIT ( syslogger_desc );

/******************************************************************************
 *
 * Console driver
 *
 ******************************************************************************
 */

/** Host name (for log messages) */
static char *syslog_hostname;

/** Domain name (for log messages) */
static char *syslog_domain;

/**
 * Transmit formatted syslog message
 *
 * @v xfer		Data transfer interface
 * @v severity		Severity
 * @v message		Message
 * @v terminator	Message terminator
 * @ret rc		Return status code
 */
int syslog_send ( struct interface *xfer, unsigned int severity,
		  const char *message, const char *terminator ) {
	const char *hostname = ( syslog_hostname ? syslog_hostname : "" );
	const char *domain = ( ( hostname[0] && syslog_domain ) ?
			       syslog_domain : "" );

	return xfer_printf ( xfer, "<%d>%s%s%s%sipxe: %s%s",
			     SYSLOG_PRIORITY ( SYSLOG_DEFAULT_FACILITY,
					       severity ), hostname,
			     ( domain[0] ? "." : "" ), domain,
			     ( hostname[0] ? " " : "" ), message, terminator );
}

/******************************************************************************
 *
 * Console driver
 *
 ******************************************************************************
 */

/** Syslog line buffer */
static char syslog_buffer[SYSLOG_BUFSIZE];

/** Syslog severity */
static unsigned int syslog_severity = SYSLOG_DEFAULT_SEVERITY;

/**
 * Handle ANSI set syslog priority (private sequence)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void syslog_handle_priority ( struct ansiesc_context *ctx __unused,
				     unsigned int count __unused,
				     int params[] ) {
	if ( params[0] >= 0 ) {
		syslog_severity = params[0];
	} else {
		syslog_severity = SYSLOG_DEFAULT_SEVERITY;
	}
}

/** Syslog ANSI escape sequence handlers */
static struct ansiesc_handler syslog_handlers[] = {
	{ ANSIESC_LOG_PRIORITY, syslog_handle_priority },
	{ 0, NULL }
};

/** Syslog line console */
static struct line_console syslog_line = {
	.buffer = syslog_buffer,
	.len = sizeof ( syslog_buffer ),
	.ctx = {
		.handlers = syslog_handlers,
	},
};

/** Syslog recursion marker */
static int syslog_entered;

/**
 * Print a character to syslog console
 *
 * @v character		Character to be printed
 */
static void syslog_putchar ( int character ) {
	int rc;

	/* Ignore if we are already mid-logging */
	if ( syslog_entered )
		return;

	/* Fill line buffer */
	if ( line_putchar ( &syslog_line, character ) == 0 )
		return;

	/* Guard against re-entry */
	syslog_entered = 1;

	/* Send log message */
	if ( ( rc = syslog_send ( &syslogger, syslog_severity,
				  syslog_buffer, "" ) ) != 0 ) {
		DBG ( "SYSLOG could not send log message: %s\n",
		      strerror ( rc ) );
	}

	/* Clear re-entry flag */
	syslog_entered = 0;
}

/** Syslog console driver */
struct console_driver syslog_console __console_driver = {
	.putchar = syslog_putchar,
	.disabled = CONSOLE_DISABLED,
	.usage = CONSOLE_SYSLOG,
};

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/** IPv4 syslog server setting */
const struct setting syslog_setting __setting ( SETTING_MISC, syslog ) = {
	.name = "syslog",
	.description = "Syslog server",
	.tag = DHCP_LOG_SERVERS,
	.type = &setting_type_ipv4,
};

/** IPv6 syslog server setting */
const struct setting syslog6_setting __setting ( SETTING_MISC, syslog6 ) = {
	.name = "syslog6",
	.description = "Syslog server",
	.tag = DHCPV6_LOG_SERVERS,
	.type = &setting_type_ipv6,
	.scope = &ipv6_scope,
};

/**
 * Strip invalid characters from host/domain name
 *
 * @v name		Name to strip
 */
static void syslog_fix_name ( char *name ) {
	char *fixed = name;
	int c;

	/* Do nothing if name does not exist */
	if ( ! name )
		return;

	/* Strip any non-printable or whitespace characters from the name */
	do {
		c = *(name++);
		*fixed = c;
		if ( isprint ( c ) && ! isspace ( c ) )
			fixed++;
	} while ( c );
}

/**
 * Apply syslog settings
 *
 * @ret rc		Return status code
 */
static int apply_syslog_settings ( void ) {
	struct sockaddr old_logserver;
	int rc;

	/* Fetch hostname and domain name */
	free ( syslog_hostname );
	fetch_string_setting_copy ( NULL, &hostname_setting, &syslog_hostname );
	syslog_fix_name ( syslog_hostname );
	free ( syslog_domain );
	fetch_string_setting_copy ( NULL, &domain_setting, &syslog_domain );
	syslog_fix_name ( syslog_domain );

	/* Fetch log server */
	syslog_console.disabled = CONSOLE_DISABLED;
	memcpy ( &old_logserver, &logserver, sizeof ( old_logserver ) );
	logserver.sa.sa_family = 0;
	if ( fetch_ipv6_setting ( NULL, &syslog6_setting,
				  &logserver.sin6.sin6_addr ) >= 0 ) {
		logserver.sin6.sin6_family = AF_INET6;
	} else if ( fetch_ipv4_setting ( NULL, &syslog_setting,
					 &logserver.sin.sin_addr ) >= 0 ) {
		logserver.sin.sin_family = AF_INET;
	}
	if ( logserver.sa.sa_family ) {
		syslog_console.disabled = 0;
		DBG ( "SYSLOG using log server %s\n",
		      sock_ntoa ( &logserver.sa ) );
	}

	/* Do nothing unless log server has changed */
	if ( memcmp ( &logserver, &old_logserver, sizeof ( logserver ) ) == 0 )
		return 0;

	/* Reset syslog connection */
	intf_restart ( &syslogger, 0 );

	/* Do nothing unless we have a log server */
	if ( syslog_console.disabled ) {
		DBG ( "SYSLOG has no log server\n" );
		return 0;
	}

	/* Connect to log server */
	if ( ( rc = xfer_open_socket ( &syslogger, SOCK_DGRAM,
				       &logserver.sa, NULL ) ) != 0 ) {
		DBG ( "SYSLOG cannot connect to log server: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** Syslog settings applicator */
struct settings_applicator syslog_applicator __settings_applicator = {
	.apply = apply_syslog_settings,
};
