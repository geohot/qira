/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 *
 * The iterator shown here iterates over the blocks of a fork.
 *
 * Copyright (C) 2000 Klaus Halfmann <khalfmann@libra.de>
 * Original work by 1996-1998 Robert Leslie <rob@mars.org>
 * other work 2000 from Brad Boyer (flar@pants.nu)
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
 * $Id: blockiter.h,v 1.1 2000/10/10 11:14:05 hasi Exp $
 */

/*  Structure of the blockiterator */
typedef struct
{
    volume*	    vol;	// volume we iterate over
    UInt32	    curr_block;	// current, absolute block
    UInt32	    block;	// relative block in current extent
    UInt32	    max_block;	// Maximum allowed block
    UInt32	    fileId;	// id of file we iterate over
    int		    index;	// 0 .. 7 in current extent
    hfsp_extent*    file;	// original extent record from file
    hfsp_extent*    e;		// current extentent under examination
    UInt8	    forktype;	// type of fork we iterate over
    UInt8	    in_extent;	// boolean  0 - in file extent
				//	    1 - in extents file
    extent_record   er;		// record to iterate in extents file.
} blockiter;

/* Initialize iterator for a given fork */
extern void blockiter_init(blockiter* b, volume* vol, hfsp_fork_raw* f,
			    UInt8 forktype, UInt32 fileId);

/* find next block of the fork iterating over */
extern int blockiter_next(blockiter *b);

/* skip the indicated number of blocks */
extern int blockiter_skip(blockiter *b, UInt32 skip);

/* return current block */
static inline UInt32 blockiter_curr(blockiter *b)
{
    return b->e->start_block + b->block;
}
