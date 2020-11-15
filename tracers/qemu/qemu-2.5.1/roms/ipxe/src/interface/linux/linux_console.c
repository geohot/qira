/*
 * Copyright (C) 2010 Piotr Jaroszyński <p.jaroszynski@gmail.com>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

FILE_LICENCE(GPL2_OR_LATER);

/** @file
 *
 * Linux console implementation.
 *
 */

#include <ipxe/console.h>

#include <ipxe/init.h>
#include <ipxe/keys.h>
#include <linux_api.h>

#include <linux/termios.h>
#include <asm/errno.h>

#include <config/console.h>

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_LINUX ) && CONSOLE_EXPLICIT ( CONSOLE_LINUX ) )
#undef CONSOLE_LINUX
#define CONSOLE_LINUX ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_LOG )
#endif

static void linux_console_putchar(int c)
{
	/* write to stdout */
	if (linux_write(1, &c, 1) != 1)
		DBG("linux_console write failed (%s)\n", linux_strerror(linux_errno));
}

static int linux_console_getchar()
{
	char c;

	/* read from stdin */
	if (linux_read(0, &c, 1) < 0) {
		DBG("linux_console read failed (%s)\n", linux_strerror(linux_errno));
		return 0;
	}
	/* backspace seems to be returned as ascii del, map it here */
	if (c == 0x7f)
		return KEY_BACKSPACE;
	else
		return c;
}

static int linux_console_iskey()
{
	struct pollfd pfd;
	pfd.fd = 0;
	pfd.events = POLLIN;

	/* poll for data to be read on stdin */
	if (linux_poll(&pfd, 1, 0) == -1) {
		DBG("linux_console poll failed (%s)\n", linux_strerror(linux_errno));
		return 0;
	}

	if (pfd.revents & POLLIN)
		return 1;
	else
		return 0;
}

struct console_driver linux_console __console_driver = {
	.disabled = 0,
	.putchar = linux_console_putchar,
	.getchar = linux_console_getchar,
	.iskey = linux_console_iskey,
	.usage = CONSOLE_LINUX,
};

static int linux_tcgetattr(int fd, struct termios *termios_p)
{
	return linux_ioctl(fd, TCGETS, termios_p);
}

static int linux_tcsetattr(int fd, int optional_actions, const struct termios *termios_p)
{
	unsigned long int cmd;

	switch (optional_actions)
	{
		case TCSANOW:
			cmd = TCSETS;
			break;
		case TCSADRAIN:
			cmd = TCSETSW;
			break;
		case TCSAFLUSH:
			cmd = TCSETSF;
			break;
		default:
			linux_errno = EINVAL;
			return -1;
	}

	return linux_ioctl(fd, cmd, termios_p);
}

/** Saved termios attributes */
static struct termios saved_termios;

/** Setup the terminal for our use */
static void linux_console_startup(void)
{
	struct termios t;

	if (linux_tcgetattr(0, &t)) {
		DBG("linux_console tcgetattr failed (%s)", linux_strerror(linux_errno));
		return;
	}

	saved_termios = t;

	/* Disable canonical mode and echo. Let readline handle that */
	t.c_lflag &= ~(ECHO | ICANON);
	/* stop ^C from sending a signal */
	t.c_cc[VINTR] = 0;

	if (linux_tcsetattr(0, TCSAFLUSH, &t))
		DBG("linux_console tcsetattr failed (%s)", linux_strerror(linux_errno));
}

/** Restores original terminal attributes on shutdown */
static void linux_console_shutdown(int flags __unused)
{
	if (linux_tcsetattr(0, TCSAFLUSH, &saved_termios))
		DBG("linux_console tcsetattr failed (%s)", linux_strerror(linux_errno));
}

struct startup_fn linux_console_startup_fn __startup_fn(STARTUP_EARLY) = {
	.startup = linux_console_startup,
	.shutdown = linux_console_shutdown,
};
