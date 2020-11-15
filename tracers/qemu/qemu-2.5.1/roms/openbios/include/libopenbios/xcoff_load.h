/*
 *   Creation Date: <2010/03/22 18:00:00 mcayland>
 *   Time-stamp: <2010/03/22 18:00:00 mcayland>
 *
 *	<xcoff_load.h>
 *
 *	XCOFF loader
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_XCOFFLOAD
#define _H_XCOFFLOAD

#include "arch/common/xcoff.h"
#include "libopenbios/sys_info.h"

extern int is_xcoff(COFF_filehdr_t *fhdr);
extern int xcoff_load(struct sys_info *info, const char *filename);
extern void xcoff_init_program(void);

#endif   /* _H_XCOFFLOAD */
