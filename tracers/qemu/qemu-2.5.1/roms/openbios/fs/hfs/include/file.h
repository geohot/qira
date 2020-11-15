/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 * Copyright (C) 1996-1998 Robert Leslie
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
 * $Id: file.h,v 1.6 1998/04/11 08:27:12 rob Exp $
 */

enum {
  fkData = 0x00,
  fkRsrc = 0xff
};

void f_init(hfsfile *, hfsvol *, long, const char *);
void f_selectfork(hfsfile *, int);
void f_getptrs(hfsfile *, ExtDataRec **, unsigned long **, unsigned long **);

int f_doblock(hfsfile *, unsigned long, block *,
	      int (*)(hfsvol *, unsigned int, unsigned int, block *));

# define f_getblock(file, num, bp)  \
    f_doblock((file), (num), (bp), b_readab)
# define f_putblock(file, num, bp)  \
    f_doblock((file), (num), (bp),  \
	      (int (*)(hfsvol *, unsigned int, unsigned int, block *))  \
	      b_writeab)

int f_addextent(hfsfile *, ExtDescriptor *);
long f_alloc(hfsfile *);

int f_trunc(hfsfile *);
int f_flush(hfsfile *);
