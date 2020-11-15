/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 * Copyright (C) 1996-1998, 2003 Robert Leslie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * $Id: os.h,v 1.1.1.1 2000/07/25 10:33:40 kkaempf Exp $
 */

#ifndef _H_OS
#define _H_OS

/*
 * NAME:	os->same()
 * DESCRIPTION:	return 1 iff path is same as the open descriptor
 */
int os_same( int fd1, int fd2 );

/*
 * NAME:	os->seek()
 * DESCRIPTION:	set a descriptor's seek pointer (offset in blocks)
 */
unsigned long os_seek( int fd, unsigned long offset, int blksize_bits);

/*
 * NAME:	os->read()
 * DESCRIPTION:	read blocks from an open descriptor
 */
unsigned long os_read( int fd, void *buf, unsigned long len, int blksize_bits);

/*
 * NAME:	os->write()
 * DESCRIPTION:	write blocks to an open descriptor
 */
unsigned long os_write( int fd, const void *buf, unsigned long len, int blksize_bits);

/*
 * NAME:	os->seek_offset()
 * DESCRIPTION:	set a descriptor's seek pointer (offset in bytes)
 */
void os_seek_offset( int fd, long long offset );


#endif   /* _H_OS */
