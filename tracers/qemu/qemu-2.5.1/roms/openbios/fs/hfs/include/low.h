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
 * $Id: low.h,v 1.6 1998/04/11 08:27:13 rob Exp $
 */

# define HFS_DDR_SIGWORD	0x4552

# define HFS_PM_SIGWORD		0x504d
# define HFS_PM_SIGWORD_OLD	0x5453

# define HFS_BB_SIGWORD		0x4c4b

# define HFS_BOOTCODE1LEN	(HFS_BLOCKSZ - 148)
# define HFS_BOOTCODE2LEN	HFS_BLOCKSZ

# define HFS_BOOTCODELEN	(HFS_BOOTCODE1LEN + HFS_BOOTCODE2LEN)

int l_getddr(hfsvol *, Block0 *);
int l_putddr(hfsvol *, const Block0 *);

int l_getpmentry(hfsvol *, Partition *, unsigned long);
int l_putpmentry(hfsvol *, const Partition *, unsigned long);

int l_getbb(hfsvol *, BootBlkHdr *, byte *);
int l_putbb(hfsvol *, const BootBlkHdr *, const byte *);

int l_getmdb(hfsvol *, MDB *, int);
int l_putmdb(hfsvol *, const MDB *, int);
