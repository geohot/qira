/*
 *      <console.c>
 *
 *      Simple text console
 *
 *   Copyright (C) 2005 Stefan Reinauer <stepan@openbios.org>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/console.h"
#include "drivers/drivers.h"

#ifdef CONFIG_DEBUG_CONSOLE
/* ******************************************************************
 *      common functions, implementing simple concurrent console
 * ****************************************************************** */

static int mac_putchar(int c)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	escc_uart_putchar(c & 0xff);
#endif
        return c;
}

static int mac_availchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (escc_uart_charav(CONFIG_SERIAL_PORT))
        	return 1;
#endif
        return 0;
}

static int mac_getchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (escc_uart_charav(CONFIG_SERIAL_PORT))
		return (escc_uart_getchar(CONFIG_SERIAL_PORT));
#endif
        return 0;
}

struct _console_ops mac_console_ops = {
	.putchar = mac_putchar,
	.availchar = mac_availchar,
	.getchar = mac_getchar
};

static int prep_putchar(int c)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	uart_putchar(c & 0xff);
#endif
        return c;
}

static int prep_availchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (uart_charav(CONFIG_SERIAL_PORT))
		return 1;
#endif
        return 0;
}

static int prep_getchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (uart_charav(CONFIG_SERIAL_PORT))
		return (uart_getchar(CONFIG_SERIAL_PORT));
#endif
        return 0;
}

struct _console_ops prep_console_ops = {
	.putchar = prep_putchar,
	.availchar = prep_availchar,
	.getchar = prep_getchar
};

#endif	// CONFIG_DEBUG_CONSOLE
