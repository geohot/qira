/*
 *   Creation Date: <2010/03/22 18:00:00 mcayland>
 *   Time-stamp: <2010/03/22 18:00:00 mcayland>
 *
 *	<fcode_load.h>
 *
 *	Fcode loader
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_FCODELOAD
#define _H_FCODELOAD

extern int is_fcode(unsigned char *fcode);
extern int fcode_load(ihandle_t dev);
extern void fcode_init_program(void);

#endif   /* _H_FCODELOAD */
