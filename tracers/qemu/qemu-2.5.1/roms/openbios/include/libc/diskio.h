/*
 *   Creation Date: <2003/12/20 00:57:01 samuel>
 *   Time-stamp: <2004/01/07 19:32:29 samuel>
 *
 *	<diskio.h>
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

#ifndef _H_DISKIO
#define _H_DISKIO

extern int		open_ih( ihandle_t ih );
extern int 		open_io( const char *spec );
extern int		close_io( int fd );
extern int		read_io( int fd, void *buf, size_t cnt );
extern int		seek_io( int fd, long long offs );
extern long long	tell( int fd );
extern int		reopen( int fd, const char *filename );
extern int		reopen_nwrom( int fd );
extern ihandle_t	get_ih_from_fd( int fd );
const char 		*get_file_path( int fd );
const char		*get_fstype( int fd );
const char		*get_volume_name( int fd );

#endif   /* _H_DISKIO */
