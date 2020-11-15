/*
 *   Creation Date: <2010/03/22 18:00:00 mcayland>
 *   Time-stamp: <2010/03/22 18:00:00 mcayland>
 *
 *	<aout_load.h>
 *
 *	a.out loader
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_AOUTLOAD
#define _H_AOUTLOAD

#include "arch/common/a.out.h"
#include "libopenbios/sys_info.h"

extern int is_aout(struct exec *ehdr);
extern int aout_load(struct sys_info *info, ihandle_t dev);
extern void aout_init_program(void);

#endif   /* _H_AOUTLOAD */
