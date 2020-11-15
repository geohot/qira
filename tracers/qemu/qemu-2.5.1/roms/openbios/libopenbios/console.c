/*
 *      <console.c>
 *
 *      Simple text console
 *
 *   Copyright (C) 2005 Stefan Reinauer <stepan@openbios.org>
 *   Copyright (C) 2013 Mark Cave-Ayland <mark.cave-ayland@ilande.co.uk>
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

/* ******************************************************************
 *      common functions, implementing simple concurrent console
 * ****************************************************************** */

/* Dummy routines for when console is unassigned */

static int dummy_putchar(int c)
{
    return c;
}

static int dummy_availchar(void)
{
    return 0;
}

static int dummy_getchar(void)
{
    return 0;
}

struct _console_ops console_ops = {
    .putchar = dummy_putchar,
    .availchar = dummy_availchar,
    .getchar = dummy_getchar
};

#ifdef CONFIG_DEBUG_CONSOLE

void init_console(struct _console_ops ops)
{
    console_ops = ops;
}

int putchar(int c)
{
    return (*console_ops.putchar)(c);
}

int availchar(void)
{
    return (*console_ops.availchar)();
}

int getchar(void)
{
    return (*console_ops.getchar)();
}
#endif    // CONFIG_DEBUG_CONSOLE
