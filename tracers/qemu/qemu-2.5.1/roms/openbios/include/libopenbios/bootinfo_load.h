/*
 *   Creation Date: <2010/03/22 18:00:00 mcayland>
 *   Time-stamp: <2010/03/22 18:00:00 mcayland>
 *
 *	<bootinfo_load.h>
 *
 *	CHRP boot info loader
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_BOOTINFOLOAD
#define _H_BOOTINFOLOAD

#include "libopenbios/sys_info.h"

extern int is_bootinfo(char *bootinfo);
extern int bootinfo_load(struct sys_info *info, const char *filename);
extern void bootinfo_init_program(void);

#endif   /* _H_BOOTINFOLOAD */
