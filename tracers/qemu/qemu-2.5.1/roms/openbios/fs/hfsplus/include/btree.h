/*
 * libhfs - library for reading and writing Macintosh HFS volumes.
 *
 * The fucntions are used to handle the various forms of btrees
 * found on HFS+ volumes.
 *
 * Copyright (C) 2000 Klaus Halfmann <khalfmann@libra.de>
 * Original 1996-1998 Robert Leslie <rob@mars.org>
 * Additional work by  Brad Boyer (flar@pants.nu)
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
 * $Id: btree.h,v 1.10 2000/10/25 05:43:04 hasi Exp $
 */

/** Intialize catalog btree, so that btree_close can safely be called. */
extern void btree_reset(btree* bt);

/** Intialize catalog btree */
extern int btree_init_cat(btree* bt, volume* vol, hfsp_fork_raw* fork);

/** Intialize extents btree */
extern int btree_init_extent(btree* bt, volume* vol, hfsp_fork_raw* fork);

/** close the btree and free any resources */
extern void btree_close(btree* bt);

/* Read node at given index */
extern node_buf* btree_node_by_index(btree* bt, UInt16 index);

/* returns pointer to key given by index in current node */
extern void* btree_key_by_index(btree* bt, node_buf* buf, UInt16 index);

#ifdef DEBUG
    /* Dump all the btree information to stdout */
  extern void btree_print(btree* bt);
#endif
