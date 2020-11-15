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
 * $Id: block.h,v 1.10 1998/11/02 22:08:53 rob Exp $
 */

int b_init(hfsvol *);
int b_flush(hfsvol *);
int b_finish(hfsvol *);

int b_readpb(hfsvol *, unsigned long, block *, unsigned int);
int b_writepb(hfsvol *, unsigned long, const block *, unsigned int);

int b_readlb(hfsvol *, unsigned long, block *);
int b_writelb(hfsvol *, unsigned long, const block *);

int b_readab(hfsvol *, unsigned int, unsigned int, block *);
int b_writeab(hfsvol *, unsigned int, unsigned int, const block *);

unsigned long b_size(hfsvol *);

# ifdef DEBUG
void b_showstats(const bcache *);
void b_dumpcache(const bcache *);
# endif
