/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 *
 * Code to acces the basic volume information of a HFS+ volume.
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
 * $Id: volume.c,v 1.21 2000/10/25 05:43:04 hasi Exp $
 */

#include "config.h"
#include "libhfsp.h"
#include "volume.h"
#include "record.h"
#include "btree.h"
#include "blockiter.h"
#include "os.h"
#include "swab.h"
#include "hfstime.h"


/* Fill a given buffer with the given block in volume.
 */
int
volume_readinbuf(volume * vol,void* buf, long block)
{
	UInt16 blksize_bits;
	ASSERT( block < vol->maxblocks);

	blksize_bits = vol->blksize_bits;
	block	+= vol->startblock;
	if( os_seek(vol->os_fd, block, blksize_bits) == block)
		if( 1 == os_read(vol->os_fd, buf, 1, blksize_bits))
			return 0;
	return -1;
}

/* read multiple blocks into given memory.
 *
 * returns given pinter or NULL on failure.
 */
void*
volume_readfromfork(volume* vol, void* buf,
		hfsp_fork_raw* f, UInt32 block,
		UInt32 count, UInt8 forktype, UInt32 fileId)
{
	blockiter iter;
	char *cbuf = buf;

	blockiter_init(&iter, vol, f, forktype, fileId);
	if( blockiter_skip(&iter, block))
		return NULL;

	while( count > 0) {
		--count;
		if( volume_readinbuf(vol, cbuf, blockiter_curr(&iter)))
			return NULL;
		cbuf += vol->blksize;
		if( count > 0 && blockiter_next(&iter))
			return NULL;
	}
	return buf;
}


/* Read a raw hfsp_extent_rec from memory.
 *
 * return pointer right after the structure.
 */
void*
volume_readextent(void *p, hfsp_extent_rec er)
{
	int 		i;
	hfsp_extent	*e;

	for( i=0; i < 8; i++) {
		e = &er[i];
		e->start_block = bswabU32_inc(p);
		e->block_count = bswabU32_inc(p);
	}
	return p;
}

/* Read a raw hfsp_fork from memory.
 *
 * return pointer right after the structure.
 */
void*
volume_readfork(void *p, hfsp_fork_raw* f)
{
	f->total_size   = bswabU64_inc(p);
	f->clump_size   = bswabU32_inc(p);
	f->total_blocks = bswabU32_inc(p);

	return volume_readextent(p, f->extents);
}

/* Read the volume from the given buffer and swap the bytes.
 *
 * ToDo: add more consitency checks.
 */
static int
volume_readbuf(hfsp_vh* vh, char * p)
{
	if(  (vh->signature = bswabU16_inc(p)) != HFSP_VOLHEAD_SIG)
		HFSP_ERROR(-1, "This is not a HFS+ volume");

	vh->version		= bswabU16_inc(p);
	vh->attributes   	= bswabU32_inc(p);
	vh->last_mount_vers	= bswabU32_inc(p);
	vh->reserved		= bswabU32_inc(p);
	vh->create_date		= bswabU32_inc(p);
	vh->modify_date		= bswabU32_inc(p);
	vh->backup_date		= bswabU32_inc(p);
	vh->checked_date	= bswabU32_inc(p);
	vh->file_count		= bswabU32_inc(p);
	vh->folder_count	= bswabU32_inc(p);
	vh->blocksize		= bswabU32_inc(p);
	vh->total_blocks	= bswabU32_inc(p);
	vh->free_blocks		= bswabU32_inc(p);
	vh->next_alloc		= bswabU32_inc(p);
	vh->rsrc_clump_sz	= bswabU32_inc(p);
	vh->data_clump_sz	= bswabU32_inc(p);
	vh->next_cnid		= bswabU32_inc(p);
	vh->write_count		= bswabU32_inc(p);
	vh->encodings_bmp	= bswabU64_inc(p);
	memcpy(vh->finder_info, p, 32);
	p += 32; // So finderinfo must be swapped later, ***
	p = volume_readfork(p, &vh->alloc_file );
	p = volume_readfork(p, &vh->ext_file   );
	p = volume_readfork(p, &vh->cat_file   );
	p = volume_readfork(p, &vh->attr_file  );
        volume_readfork(p, &vh->start_file );
	return 0;
  fail:
	return -1;
}

/* Read the volume from the given block */
static int
volume_read(volume * vol, hfsp_vh* vh, UInt32 block)
{
	char buf[vol->blksize];

	if( volume_readinbuf(vol, buf, block))
		return -1;
        return volume_readbuf(vh, buf);
}

/* Find out wether the volume is wrapped and unwrap it eventually */
static int
volume_read_wrapper(volume * vol, hfsp_vh* vh)
{
	UInt16  signature;
	char	buf[vol->blksize];
        char    *p = buf;
	int	ret;
	UInt64	vol_size;
	
	if( volume_readinbuf(vol, buf, 2) ) // Wrapper or volume header starts here
		return -1;

	signature = bswabU16_inc(p);
	if( signature == HFS_VOLHEAD_SIG) {		/* Wrapper */
		UInt32  drAlBlkSiz;			/* size (in bytes) of allocation blocks */
		UInt32	sect_per_block;			/* how may block build an hfs sector */
		UInt16  drAlBlSt;			/* first allocation block in volume */
		UInt16	embeds, embedl;			/* Start/lenght of embedded area in blocks */

		p += 0x12;			/* skip unneded HFS vol fields */
		drAlBlkSiz = bswabU32_inc(p);		/* offset 0x14 */
		p += 0x4;			/* skip unneded HFS vol fields */
		drAlBlSt = bswabU16_inc(p);		/* offset 0x1C */

		p += 0x5E;			/* skip unneded HFS vol fields */
		signature = bswabU16_inc(p);		/* offset 0x7C, drEmbedSigWord */
		if( signature != HFSP_VOLHEAD_SIG)
			HFSP_ERROR(-1, "This looks like a normal HFS volume");
		embeds = bswabU16_inc(p);
		embedl = bswabU16_inc(p);
		sect_per_block =  (drAlBlkSiz / HFSP_BLOCKSZ);
		// end is absolute (not relative to HFS+ start)
		vol->maxblocks = embedl * sect_per_block;
		vol->startblock = drAlBlSt + embeds * sect_per_block;
		/* Now we can try to read the embedded HFS+ volume header */
		return volume_read(vol,vh,2);
	}
	else if( signature == HFSP_VOLHEAD_SIG) { /* Native HFS+ volume */
		p = buf; // Restore to begin of block
                ret = volume_readbuf(vh, p);
		if( !ret ) {
		    /* When reading the initial partition we must use 512 byte blocks */
		    vol_size = (uint64_t)vh->blocksize * vh->total_blocks;
		    vol->maxblocks = vol_size / HFSP_BLOCKSZ;
		}
		
		return ret;
	} else
		 HFSP_ERROR(-1, "Neither Wrapper nor native HFS+ volume header found");
fail:
	return -1;
}


/* Open the device, read and verify the volume header
   (and its backup) */
int
volume_open( volume* vol, int os_fd )
{
	hfsp_vh backup;	/* backup volume found at second to last block */
	long	sect_per_block;
	int	shift;

	vol->blksize_bits	= HFSP_BLOCKSZ_BITS;
	vol->blksize		= HFSP_BLOCKSZ;
	vol->startblock		= 0;
	vol->maxblocks		= 3;
		/* this should be enough until we find the volume descriptor */
	vol->extents		= NULL; /* Thanks to Jeremias Sauceda */

	btree_reset(&vol->catalog);
	vol->os_fd = os_fd;

	// vol->maxblocks = os_seek(vol->os_fd, -1, HFSP_BLOCKSZ_BITS);
	// This wont work for /dev/... but we do not really need it

	if( volume_read_wrapper(vol, &vol->vol))
		return -1;
	if( volume_read(vol, &backup, vol->maxblocks - 2))
		return -1;

	/* Now switch blksize from HFSP_BLOCKSZ (512) to value given in header
	   and adjust depend values accordingly, after that a block always
	   means a HFS+ allocation size */

	/* Usually 4096 / 512  == 8 */
	sect_per_block = vol->vol.blocksize / HFSP_BLOCKSZ;
	shift = 0;
	if( sect_per_block > 1) {
		shift = 1;
		while( sect_per_block > 2) {
			sect_per_block >>=1;
			shift++;
		}		/* shift = 3 */
	}
	vol -> blksize_bits += shift;
	vol -> blksize = 1 << vol->blksize_bits;
	vol -> startblock >>= shift;
	vol -> maxblocks = vol->vol.total_blocks;	/* cant calculate via shift ? */

	if( btree_init_cat(&vol->catalog, vol, &vol->vol.cat_file))
		return -1;

	return 0;
}

/* Write back all data eventually cached and close the device */
int
volume_close(volume* vol)
{
	btree_close(&vol->catalog);
	if( vol->extents) {
		btree_close(vol->extents);
		FREE(vol->extents);
	}
	return 0;
}

/* internal fucntion used to create the extents btree,
   is called by inline function when needed */
void
volume_create_extents_tree(volume* vol)
{
	btree* result = (btree*) ALLOC(btree*, sizeof(btree));
	if( !result)
		HFSP_ERROR(ENOMEM, "No memory for extents btree");
	if( !btree_init_extent(result, vol, &vol->vol.ext_file)) {
		vol->extents = result;
		return;
	}
  fail:
	vol->extents = NULL;
}

/* Determine whether the volume is a HFS-plus volume */
int
volume_probe(int fd, long long offset)
{
	UInt16 *vol;
	int ret = 0;

	vol = (UInt16 *)malloc(2 * 1 << HFSP_BLOCKSZ_BITS);
	os_seek_offset( fd, 2 * (1 << HFSP_BLOCKSZ_BITS) + offset );
	os_read(fd, vol, 2, HFSP_BLOCKSZ_BITS);

	if (__be16_to_cpu(vol[0]) == HFS_VOLHEAD_SIG &&
		__be16_to_cpu(vol[0x3e]) == HFSP_VOLHEAD_SIG) {
		ret = -1;
	} else if (__be16_to_cpu(vol[0]) == HFSP_VOLHEAD_SIG) {
		ret = -1;
	}

	free(vol);
	return ret;
}

