/*
 *   <console.h>
 *
 *   Shared console routines
 *
 *   Copyright (C) 2013 Mark Cave-Ayland (mark.cave-ayland@ilande.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_CONSOLE
#define _H_CONSOLE

struct _console_ops {
    int (*putchar)(int c);
    int (*availchar)(void);
    int (*getchar)(void);
};

void init_console(struct _console_ops ops);

#endif   /* _H_CONSOLE */
