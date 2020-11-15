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
 * $Id: blockiter.c,v 1.2 2000/10/17 05:58:46 hasi Exp $
 */

#include "config.h"
#include "libhfsp.h"
#include "blockiter.h"
#include "volume.h"
#include "record.h"
#include "btree.h"
#include "os.h"
#include "swab.h"
#include "hfstime.h"

/* Initialize iterator for a given fork */
void
blockiter_init(blockiter* b, volume* vol, hfsp_fork_raw* f,
		    UInt8 forktype, UInt32 fileId)
{
    b->vol	    = vol;
    b->curr_block   = 0;
    b->block	    = 0;
    b->max_block    = f->total_blocks;
    b->fileId	    = fileId;
    b->index	    = 0;
    b->file	    = f->extents;
    b->e	    = f->extents;
    b->forktype	    = forktype;
    b->in_extent    = 0;
}

/* get next extent record when needed */
static int
blockiter_next_extent(blockiter *b)
{
    btree*  extents_tree = volume_get_extents_tree(b->vol);
    int	    err;

    b->index = 0;
    if (b->in_extent) // already using extents record ?
    {
	err = record_next_extent(&b->er);
	// Hope there is no need to check this ...
	// if (b->er.key.start_block != b->curr_block)
	//     HFSP_ERROR(ENOENT,
	//	"Extents record inconistent");
    }
    else
    {
	err = record_init_file(&b->er, extents_tree, b->forktype,
		b->fileId, b->curr_block);
	b->in_extent = -1;  // true
    }
    b->e = b->er.extent;
    return err;
}

/* find next block of the fork iterating over */
int
blockiter_next(blockiter *b)
{
    b->curr_block ++;
    b->block ++;
    if (b->curr_block >= b->max_block)
	return -1; // end of Blocks, but no error
    // in current part of extent ?
    if (b->block >= b->e->block_count)
    {
	b->index++;
	b->block = 0;		// reset relative position
	b->e++;
	if (b -> index >= 8)	// need to fetch another extent
	{
	    if (blockiter_next_extent(b))
		HFSP_ERROR(ENOENT, "Extends record not found.");
	}
    }
    return 0;

  fail:
    return -1;
}

/* skip the indicated number of blocks */
int
blockiter_skip(blockiter *b, UInt32 skip)
{
    while (skip > 0)
    {
	// Skip to skip or end of current extent
	UInt32 diff = b->e->block_count - b->block;
	if (skip < diff)
	{
	    diff = skip;
	    skip = 0;
	}
	else
	    skip -= diff;
	b->curr_block += diff;
	b->block      += diff;
	if (b->curr_block >= b->max_block)
	    return -1;	// end of Blocks, but no error
	if (b->block >= b->e->block_count)
	{
	    b->index++;
	    b->block = 0;		// reset relative position
	    b->e++;
	    if (b -> index >= 8)	// need to fetch another extent
	    {
		if (blockiter_next_extent(b))
		    HFSP_ERROR(ENOENT, "Extends record not found.");
	    }
	}
    } // we are here when skip was null, thats ok
    return 0;
  fail:
    return -1;
}
