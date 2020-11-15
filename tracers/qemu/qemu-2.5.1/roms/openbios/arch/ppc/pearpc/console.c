
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
#include "libc/diskio.h"
#include "libopenbios/ofmem.h"
#include "pearpc/pearpc.h"


typedef struct osi_fb_info {
	unsigned long   mphys;
	int             rb, w, h, depth;
} osi_fb_info_t;


int PearPC_GetFBInfo( osi_fb_info_t *fb )
{

        fb->w=1024;
        fb->h=768;
        fb->depth=15;
        fb->rb=2048;
        fb->mphys=0x84000000;

	return 0;
}

#define openbios_GetFBInfo(x) PearPC_GetFBInfo(x)

#include "../../../packages/video.c"
#include "../../../libopenbios/console_common.c"
