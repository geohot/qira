/*
 *   Creation Date: <2002/10/23 20:26:40 samuel>
 *   Time-stamp: <2004/01/07 19:39:15 samuel>
 *
 *     <video_common.c>
 *
 *     Shared video routines
 *
 *   Copyright (C) 2002, 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libc/vsprintf.h"
#include "libopenbios/bindings.h"
#include "libopenbios/fontdata.h"
#include "libopenbios/ofmem.h"
#include "libopenbios/video.h"
#include "packages/video.h"
#include "drivers/vga.h"
#define NO_QEMU_PROTOS
#include "arch/common/fw_cfg.h"

struct video_info video;

unsigned long
video_get_color( int col_ind )
{
	unsigned long col;
	if( !VIDEO_DICT_VALUE(video.ih) || col_ind < 0 || col_ind > 255 )
		return 0;
	if( VIDEO_DICT_VALUE(video.depth) == 8 )
		return col_ind;
	col = video.pal[col_ind];
	if( VIDEO_DICT_VALUE(video.depth) == 24 || VIDEO_DICT_VALUE(video.depth) == 32 )
		return col;
	if( VIDEO_DICT_VALUE(video.depth) == 15 )
		return ((col>>9) & 0x7c00) | ((col>>6) & 0x03e0) | ((col>>3) & 0x1f);
	return 0;
}

/* ( fbaddr maskaddr width height fgcolor bgcolor -- ) */

void
video_mask_blit(void)
{
	ucell bgcolor = POP();
	ucell fgcolor = POP();
	ucell height = POP();
	ucell width = POP();
	unsigned char *mask = (unsigned char *)POP();
	unsigned char *fbaddr = (unsigned char *)POP();

	ucell color;
	unsigned char *dst, *rowdst;
	int x, y, m, b, d, depthbytes;

	fgcolor = video_get_color(fgcolor);
	bgcolor = video_get_color(bgcolor);
	d = VIDEO_DICT_VALUE(video.depth);
	depthbytes = (d + 1) >> 3;

	dst = fbaddr;
	for( y = 0; y < height; y++) {
		rowdst = dst;
		for( x = 0; x < (width + 1) >> 3; x++ ) {
			for (b = 0; b < 8; b++) {
				m = (1 << (7 - b));

				if (*mask & m) {
					color = fgcolor;
				} else {
					color = bgcolor;
				}

				if( d >= 24 )
					*((uint32_t*)dst) = color;
				else if( d >= 15 )
					*((uint16_t*)dst) = color;
				else
					*dst = color;

				dst += depthbytes;
			}
			mask++;
		}
		dst = rowdst;
		dst += VIDEO_DICT_VALUE(video.rb);
	}
}

/* ( x y w h fgcolor bgcolor -- ) */

void
video_invert_rect( void )
{
	ucell bgcolor = POP();
	ucell fgcolor = POP();
	int h = POP();
	int w = POP();
	int y = POP();
	int x = POP();
	char *pp;

	bgcolor = video_get_color(bgcolor);
	fgcolor = video_get_color(fgcolor);

	if (!VIDEO_DICT_VALUE(video.ih) || x < 0 || y < 0 || w <= 0 || h <= 0 ||
		x + w > VIDEO_DICT_VALUE(video.w) || y + h > VIDEO_DICT_VALUE(video.h))
		return;

	pp = (char*)VIDEO_DICT_VALUE(video.mvirt) + VIDEO_DICT_VALUE(video.rb) * y;
	for( ; h--; pp += *(video.rb) ) {
		int ww = w;
		if( VIDEO_DICT_VALUE(video.depth) == 24 || VIDEO_DICT_VALUE(video.depth) == 32 ) {
			uint32_t *p = (uint32_t*)pp + x;
			while( ww-- ) {
				if (*p == fgcolor) {
					*p++ = bgcolor;
				} else if (*p == bgcolor) {
					*p++ = fgcolor;
				}
			}
		} else if( VIDEO_DICT_VALUE(video.depth) == 16 || VIDEO_DICT_VALUE(video.depth) == 15 ) {
			uint16_t *p = (uint16_t*)pp + x;
			while( ww-- ) {
				if (*p == (uint16_t)fgcolor) {
					*p++ = bgcolor;
				} else if (*p == (uint16_t)bgcolor) {
					*p++ = fgcolor;
				}
			}
		} else {
			char *p = (char *)(pp + x);

			while( ww-- ) {
				if (*p == (char)fgcolor) {
					*p++ = bgcolor;
				} else if (*p == (char)bgcolor) {
					*p++ = fgcolor;
				}
			}
		}
	}
}

/* ( color_ind x y width height -- ) (?) */
void
video_fill_rect(void)
{
	int h = POP();
	int w = POP();
	int y = POP();
	int x = POP();
	int col_ind = POP();

	char *pp;
	unsigned long col = video_get_color(col_ind);

        if (!VIDEO_DICT_VALUE(video.ih) || x < 0 || y < 0 || w <= 0 || h <= 0 ||
            x + w > VIDEO_DICT_VALUE(video.w) || y + h > VIDEO_DICT_VALUE(video.h))
		return;

	pp = (char*)VIDEO_DICT_VALUE(video.mvirt) + VIDEO_DICT_VALUE(video.rb) * y;
	for( ; h--; pp += VIDEO_DICT_VALUE(video.rb) ) {
		int ww = w;
		if( VIDEO_DICT_VALUE(video.depth) == 24 || VIDEO_DICT_VALUE(video.depth) == 32 ) {
			uint32_t *p = (uint32_t*)pp + x;
			while( ww-- )
				*p++ = col;
		} else if( VIDEO_DICT_VALUE(video.depth) == 16 || VIDEO_DICT_VALUE(video.depth) == 15 ) {
			uint16_t *p = (uint16_t*)pp + x;
			while( ww-- )
				*p++ = col;
		} else {
                        char *p = (char *)(pp + x);

			while( ww-- )
				*p++ = col;
		}
	}
}

void setup_video()
{
	/* Make everything inside the video_info structure point to the
	   values in the Forth dictionary. Hence everything is always in
	   sync. */
	phandle_t options;
	char buf[6];

	feval("['] display-ih cell+");
	video.ih = cell2pointer(POP());

	feval("['] frame-buffer-adr cell+");
	video.mvirt = cell2pointer(POP());
	feval("['] openbios-video-width cell+");
	video.w = cell2pointer(POP());
	feval("['] openbios-video-height cell+");
	video.h = cell2pointer(POP());
	feval("['] depth-bits cell+");
	video.depth = cell2pointer(POP());
	feval("['] line-bytes cell+");
	video.rb = cell2pointer(POP());
	feval("['] color-palette cell+");
	video.pal = cell2pointer(POP());

	/* Set global variables ready for fb8-install */
	PUSH( pointer2cell(video_mask_blit) );
	fword("is-noname-cfunc");
	feval("to fb8-blitmask");
	PUSH( pointer2cell(video_fill_rect) );
	fword("is-noname-cfunc");
	feval("to fb8-fillrect");
	PUSH( pointer2cell(video_invert_rect) );
	fword("is-noname-cfunc");
	feval("to fb8-invertrect");

	/* Static information */
	PUSH((ucell)fontdata);
	feval("to (romfont)");
	PUSH(FONT_HEIGHT);
	feval("to (romfont-height)");
	PUSH(FONT_WIDTH);
	feval("to (romfont-width)");

	/* Initialise the structure */
	VIDEO_DICT_VALUE(video.w) = VGA_DEFAULT_WIDTH;
	VIDEO_DICT_VALUE(video.h) = VGA_DEFAULT_HEIGHT;
	VIDEO_DICT_VALUE(video.depth) = VGA_DEFAULT_DEPTH;
	VIDEO_DICT_VALUE(video.rb) = VGA_DEFAULT_LINEBYTES;

#if defined(CONFIG_QEMU) && (defined(CONFIG_PPC) || defined(CONFIG_SPARC32) || defined(CONFIG_SPARC64))
	/* If running from QEMU, grab the parameters from the firmware interface */
	int w, h, d;

	w = fw_cfg_read_i16(FW_CFG_ARCH_WIDTH);
        h = fw_cfg_read_i16(FW_CFG_ARCH_HEIGHT);
        d = fw_cfg_read_i16(FW_CFG_ARCH_DEPTH);
	if (w && h && d) {
		VIDEO_DICT_VALUE(video.w) = w;
		VIDEO_DICT_VALUE(video.h) = h;
		VIDEO_DICT_VALUE(video.depth) = d;
		VIDEO_DICT_VALUE(video.rb) = (w * ((d + 7) / 8));
	}
#endif

	/* Setup screen-#rows/screen-#columns */
	options = find_dev("/options");
	snprintf(buf, sizeof(buf), FMT_ucell, VIDEO_DICT_VALUE(video.w) / FONT_WIDTH);
	set_property(options, "screen-#columns", buf, strlen(buf) + 1);
	snprintf(buf, sizeof(buf), FMT_ucell, VIDEO_DICT_VALUE(video.h) / FONT_HEIGHT);
	set_property(options, "screen-#rows", buf, strlen(buf) + 1);
}
