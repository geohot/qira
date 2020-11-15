/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 * Copyright (C) 2000 Klaus Halfmann <khalfmann@libra.de>^
 * Original 1996-1998 Robert Leslie <rob@mars.org>
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
 * $Id: volume.h,v 1.11 2000/10/17 05:58:46 hasi Exp $
 */

#ifndef _H_VOLUME
#define _H_VOLUME

/* Open the device, read and verify the volume header
   (and its backup) */
extern int volume_open(volume* vol, int os_fd);

/* Write back all data eventually cached and close the device. */
extern int volume_close(volume* vol);

/* read multiple blocks into given memory.
 *
 * returns given pointer or NULL on failure.
 */
extern void* volume_readfromfork(volume* vol, void* buf,
	hfsp_fork_raw* f, UInt32 block,
	UInt32 count, UInt8 forktype, UInt32 fileId);

/* Fill a given buffer with the given block in volume.
 */
int volume_readinbuf(volume * vol,void* buf, long block);

/* invalidat cache hold in volume, will be removed when
 * caching strategy is clear to me. */
/*
extern inline void volume_invalidate_cache(volume* vol)
{
    vol -> currblock = (UInt32) -1;
}
*/

/* Check in Allocation file if given block is allocated. */
extern int volume_allocated(volume* v, UInt32 block);

/* Read a raw hfsp_extent_rec from memory. */
extern void* volume_readextent(void *p, hfsp_extent_rec er);

/* Read fork information from raw memory */
extern void* volume_readfork(void *p, hfsp_fork_raw* f);

/* internal function used to create the extents btree,
   is called by following inline fucntion when needed */
extern void volume_create_extents_tree(volume* vol);

/* accessor for entends btree, is created on demand */
static inline btree* volume_get_extents_tree(volume* vol) {
    if (!vol->extents)
	volume_create_extents_tree(vol);
    return vol->extents;
}

/* Determine whether the volume is a HFS-plus volume */
int volume_probe(int fd, long long offset);

#ifdef DEBUG
    /* Print raw fork information to stdout */
  void volume_print_fork(hfsp_fork_raw* f);
    /* Dump all the volume information to stdout */
  void volume_print(hfsp_vh* vol);
#endif



#endif   /* _H_VOLUME */
