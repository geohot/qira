/*
 * Copyright (C) 2003, 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/console.h"
#include "kernel/kernel.h"
#include "drivers/drivers.h"
#include "libopenbios/fontdata.h"
#include "openbios.h"
#include "libc/vsprintf.h"
#include "libopenbios/sys_info.h"
#include "boot.h"

/* ******************************************************************
 *          simple polling video/keyboard console functions
 * ****************************************************************** */

#ifdef CONFIG_DEBUG_CONSOLE
/* ******************************************************************
 *      common functions, implementing simple concurrent console
 * ****************************************************************** */

static int arch_putchar(int c)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	uart_putchar(c);
#endif
	return c;
}

static int arch_availchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (uart_charav(CONFIG_SERIAL_PORT))
		return 1;
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VGA
        if (pc_kbd_dataready())
		return 1;
#endif
	return 0;
}

static int arch_getchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (uart_charav(CONFIG_SERIAL_PORT))
		return (uart_getchar(CONFIG_SERIAL_PORT));
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VGA
        if (pc_kbd_dataready())
                return (pc_kbd_readdata());
#endif
	return 0;
}

struct _console_ops arch_console_ops = {
	.putchar = arch_putchar,
	.availchar = arch_availchar,
	.getchar = arch_getchar
};

#endif // CONFIG_DEBUG_CONSOLE
