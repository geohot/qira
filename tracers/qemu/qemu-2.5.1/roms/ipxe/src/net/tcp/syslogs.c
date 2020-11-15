/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Encrypted syslog protocol
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <byteswap.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/tcpip.h>
#include <ipxe/dhcp.h>
#include <ipxe/settings.h>
#include <ipxe/console.h>
#include <ipxe/lineconsole.h>
#include <ipxe/tls.h>
#include <ipxe/syslog.h>
#include <config/console.h>

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_SYSLOGS ) && CONSOLE_EXPLICIT ( CONSOLE_SYSLOGS ) )
#undef CONSOLE_SYSLOGS
#define CONSOLE_SYSLOGS ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_TUI )
#endif

struct console_driver syslogs_console __console_driver;

/** The encrypted syslog server */
static struct sockaddr_tcpip logserver = {
	.st_port = htons ( SYSLOG_PORT ),
};

/**
 * Handle encrypted syslog TLS interface close
 *
 * @v intf		Interface
 * @v rc		Reason for close
 */
static void syslogs_close ( struct interface *intf __unused, int rc ) {

	DBG ( "SYSLOGS console disconnected: %s\n", strerror ( rc ) );
}

/**
 * Handle encrypted syslog TLS interface window change
 *
 * @v intf		Interface
 */
static void syslogs_window_changed ( struct interface *intf ) {

	/* Mark console as enabled when window first opens, indicating
	 * that TLS negotiation is complete.  (Do not disable console
	 * when window closes again, since TCP will close the window
	 * whenever there is unACKed data.)
	 */
	if ( xfer_window ( intf ) ) {
		if ( syslogs_console.disabled )
			DBG ( "SYSLOGS console connected\n" );
		syslogs_console.disabled = 0;
	}
}

/** Encrypted syslog TLS interface operations */
static struct interface_operation syslogs_operations[] = {
	INTF_OP ( xfer_window_changed, struct interface *,
		  syslogs_window_changed ),
	INTF_OP ( intf_close, struct interface *, syslogs_close ),
};

/** Encrypted syslog TLS interface descriptor */
static struct interface_descriptor syslogs_desc =
	INTF_DESC_PURE ( syslogs_operations );

/** The encrypted syslog TLS interface */
static struct interface syslogs = INTF_INIT ( syslogs_desc );

/******************************************************************************
 *
 * Console driver
 *
 ******************************************************************************
 */

/** Encrypted syslog line buffer */
static char syslogs_buffer[SYSLOG_BUFSIZE];

/** Encrypted syslog severity */
static unsigned int syslogs_severity = SYSLOG_DEFAULT_SEVERITY;

/**
 * Handle ANSI set encrypted syslog priority (private sequence)
 *
 * @v ctx		ANSI escape sequence context
 * @v count		Parameter count
 * @v params		List of graphic rendition aspects
 */
static void syslogs_handle_priority ( struct ansiesc_context *ctx __unused,
				      unsigned int count __unused,
				      int params[] ) {
	if ( params[0] >= 0 ) {
		syslogs_severity = params[0];
	} else {
		syslogs_severity = SYSLOG_DEFAULT_SEVERITY;
	}
}

/** Encrypted syslog ANSI escape sequence handlers */
static struct ansiesc_handler syslogs_handlers[] = {
	{ ANSIESC_LOG_PRIORITY, syslogs_handle_priority },
	{ 0, NULL }
};

/** Encrypted syslog line console */
static struct line_console syslogs_line = {
	.buffer = syslogs_buffer,
	.len = sizeof ( syslogs_buffer ),
	.ctx = {
		.handlers = syslogs_handlers,
	},
};

/** Encrypted syslog recursion marker */
static int syslogs_entered;

/**
 * Print a character to encrypted syslog console
 *
 * @v character		Character to be printed
 */
static void syslogs_putchar ( int character ) {
	int rc;

	/* Ignore if we are already mid-logging */
	if ( syslogs_entered )
		return;

	/* Fill line buffer */
	if ( line_putchar ( &syslogs_line, character ) == 0 )
		return;

	/* Guard against re-entry */
	syslogs_entered = 1;

	/* Send log message */
	if ( ( rc = syslog_send ( &syslogs, syslogs_severity,
				  syslogs_buffer, "\n" ) ) != 0 ) {
		DBG ( "SYSLOGS could not send log message: %s\n",
		      strerror ( rc ) );
	}

	/* Clear re-entry flag */
	syslogs_entered = 0;
}

/** Encrypted syslog console driver */
struct console_driver syslogs_console __console_driver = {
	.putchar = syslogs_putchar,
	.disabled = CONSOLE_DISABLED,
	.usage = CONSOLE_SYSLOGS,
};

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/** Encrypted syslog server setting */
const struct setting syslogs_setting __setting ( SETTING_MISC, syslogs ) = {
	.name = "syslogs",
	.description = "Encrypted syslog server",
	.tag = DHCP_EB_SYSLOGS_SERVER,
	.type = &setting_type_string,
};

/**
 * Apply encrypted syslog settings
 *
 * @ret rc		Return status code
 */
static int apply_syslogs_settings ( void ) {
	static char *old_server;
	char *server;
	struct interface *socket;
	int rc;

	/* Fetch log server */
	fetch_string_setting_copy ( NULL, &syslogs_setting, &server );

	/* Do nothing unless log server has changed */
	if ( ( ( server == NULL ) && ( old_server == NULL ) ) ||
	     ( ( server != NULL ) && ( old_server != NULL ) &&
	       ( strcmp ( server, old_server ) == 0 ) ) ) {
		rc = 0;
		goto out_no_change;
	}
	free ( old_server );
	old_server = NULL;

	/* Reset encrypted syslog connection */
	syslogs_console.disabled = CONSOLE_DISABLED;
	intf_restart ( &syslogs, 0 );

	/* Do nothing unless we have a log server */
	if ( ! server ) {
		DBG ( "SYSLOGS has no log server\n" );
		rc = 0;
		goto out_no_server;
	}

	/* Add TLS filter */
	if ( ( rc = add_tls ( &syslogs, server, &socket ) ) != 0 ) {
		DBG ( "SYSLOGS cannot create TLS filter: %s\n",
		      strerror ( rc ) );
		goto err_add_tls;
	}

	/* Connect to log server */
	if ( ( rc = xfer_open_named_socket ( socket, SOCK_STREAM,
					     (( struct sockaddr *) &logserver ),
					     server, NULL ) ) != 0 ) {
		DBG ( "SYSLOGS cannot connect to log server: %s\n",
		      strerror ( rc ) );
		goto err_open_named_socket;
	}
	DBG ( "SYSLOGS using log server %s\n", server );

	/* Record log server */
	old_server = server;
	server = NULL;

	/* Success */
	rc = 0;

 err_open_named_socket:
 err_add_tls:
 out_no_server:
 out_no_change:
	free ( server );
	return rc;
}

/** Encrypted syslog settings applicator */
struct settings_applicator syslogs_applicator __settings_applicator = {
	.apply = apply_syslogs_settings,
};
