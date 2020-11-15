/*
 *   Creation Date: <2002/10/23 20:26:40 samuel>
 *   Time-stamp: <2004/01/07 19:39:15 samuel>
 *
 *	<molvideo.c>
 *
 *	Mac-on-Linux display node
 *
 *   Copyright (C) 2002, 2003, 2004 Samuel Rydh (samuel@ibrium.se)
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
#include "drivers/drivers.h"
#include "packages/video.h"
#include "libopenbios/video.h"
#include "drivers/vga.h"


/************************************************************************/
/*	OF methods							*/
/************************************************************************/

DECLARE_NODE( video, 0, 0, "Tdisplay" );

/* ( r g b index -- ) */
static void
molvideo_color_bang( void )
{
	int index = POP();
	int b = POP();
	int g = POP();
	int r = POP();
	unsigned long col = ((r << 16) & 0xff0000) | ((g << 8) & 0x00ff00) | (b & 0xff);
	/* printk("color!: %08lx %08lx %08lx %08lx\n", r, g, b, index ); */

	if( VIDEO_DICT_VALUE(video.depth) == 8 ) {
		OSI_SetColor( index, col );
		OSI_RefreshPalette();
	}
}

/* ( -- ) - really should be reworked as draw-logo */
static void
molvideo_startup_splash( void )
{
	int fd, s, i, y, x, dx, dy;
	int width, height;
	char *pp, *p;
	char buf[64];

	/* only draw logo in 24-bit mode (for now) */
	if( VIDEO_DICT_VALUE(video.depth) < 15 )
		return;

	for( i=0; i<2; i++ ) {
		if( !BootHGetStrResInd("bootlogo", buf, sizeof(buf), 0, i) )
			return;
		*(!i ? &width : &height) = atol(buf);
	}

	if( (s=width * height * 3) > 0x20000 )
		return;

	if( (fd=open_io("pseudo:,bootlogo")) >= 0 ) {
		p = malloc( s );
		if( read_io(fd, p, s) != s )
			printk("bootlogo size error\n");
		close_io( fd );

		dx = (VIDEO_DICT_VALUE(video.w) - width)/2;
		dy = (VIDEO_DICT_VALUE(video.h) - height)/3;

		pp = (char*)VIDEO_DICT_VALUE(video.mvirt) + dy * VIDEO_DICT_VALUE(video.rb) + dx * (VIDEO_DICT_VALUE(video.depth) >= 24 ? 4 : 2);

		for( y=0 ; y<height; y++, pp += VIDEO_DICT_VALUE(video.rb) ) {
			if( VIDEO_DICT_VALUE(video.depth) >= 24 ) {
				unsigned long *d = (unsigned long*)pp;
				for( x=0; x<width; x++, p+=3, d++ )
					*d = ((int)p[0] << 16) | ((int)p[1] << 8) | p[2];
			} else if( VIDEO_DICT_VALUE(video.depth) == 15 ) {
				unsigned short *d = (unsigned short*)pp;
				for( x=0; x<width; x++, p+=3, d++ ) {
					int col = ((int)p[0] << 16) | ((int)p[1] << 8) | p[2];
					*d = ((col>>9) & 0x7c00) | ((col>>6) & 0x03e0) | ((col>>3) & 0x1f);
				}
			}
		}
		free( p );
	}

	/* No bootlogo support yet on other platforms */
	return;
}


NODE_METHODS( video ) = {
	{"mol-startup-splash",	molvideo_startup_splash },
};


/************************************************************************/
/*	init 								*/
/************************************************************************/

void
molvideo_init(void)
{
	xt_t color_bang;

	REGISTER_NODE( video );

	/* Bind the MOL graphic routines to the mol-color! defer */
	color_bang = bind_noname_func(molvideo_color_bang);
	PUSH(color_bang);
	feval(" to mol-color!");
}
