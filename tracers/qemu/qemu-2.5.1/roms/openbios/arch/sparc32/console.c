/*
 * Copyright (C) 2003, 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "kernel/kernel.h"
#include "drivers/drivers.h"
#include "openbios.h"
#include "libopenbios/console.h"
#include "libopenbios/ofmem.h"
#include "libopenbios/video.h"

#ifdef CONFIG_DEBUG_CONSOLE

/* ******************************************************************
 *      common functions, implementing simple concurrent console
 * ****************************************************************** */

static int arch_putchar(int c)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	escc_uart_putchar(c);
#endif
	return c;
}

static int arch_availchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (escc_uart_charav(CONFIG_SERIAL_PORT))
		return 1;
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VIDEO
	if (keyboard_dataready())
		return 1;
#endif
	return 0;
}

static int arch_getchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (escc_uart_charav(CONFIG_SERIAL_PORT))
		return (escc_uart_getchar(CONFIG_SERIAL_PORT));
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VIDEO
	if (keyboard_dataready())
		return (keyboard_readdata());
#endif
	return 0;
}

struct _console_ops arch_console_ops = {
	.putchar = arch_putchar,
	.availchar = arch_availchar,
	.getchar = arch_getchar
};

#endif				// CONFIG_DEBUG_CONSOLE
