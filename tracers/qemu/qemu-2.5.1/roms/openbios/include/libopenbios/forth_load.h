/*
 *   Creation Date: <2010/03/22 18:00:00 mcayland>
 *   Time-stamp: <2010/03/22 18:00:00 mcayland>
 *
 *	<forth_load.h>
 *
 *	Forth loader
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_FORTHLOAD
#define _H_FORTHLOAD

extern int is_forth(char *forth);
extern int forth_load(ihandle_t dev);
extern void forth_init_program(void);

#endif   /* _H_FORTHLOAD */
