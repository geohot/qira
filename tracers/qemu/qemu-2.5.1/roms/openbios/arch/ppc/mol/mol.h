/*
 *   Creation Date: <2003/12/20 00:20:12 samuel>
 *   Time-stamp: <2004/03/27 01:52:50 samuel>
 *
 *	<mol.h>
 *
 *
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#ifndef _H_MOL
#define _H_MOL

/* video.c */
extern void		init_video( void );
extern int		video_get_res( int *w, int *h );
extern void		draw_pixel( int x, int y, int colind );
extern void		set_color( int index, unsigned long color );

/* console.c */
extern int		console_draw_fstr(const char *str, int len);
extern void		console_close( void );

/* pseudodisk.c */
extern void		pseudodisk_init( void );

/* osi-blk.c */
extern void		osiblk_init( void );

/* osi-scsi.c */
extern void		osiscsi_init( void );

/* pseudofs.c */
extern void		pseudofs_init( void );

#include "../kernel.h"

#endif   /* _H_MOL */
