/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000, 2001  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

/*
 * Elements of this file were originally from the FreeBSD "biosboot"
 * bootloader file "disk.c" dated 4/12/95.
 *
 * The license and header comments from that file are included here.
 */

/*
 * Mach Operating System
 * Copyright (c) 1992, 1991 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 *
 *	from: Mach, Revision 2.2  92/04/04  11:35:49  rpd
 *	$Id: fsys_ffs.c,v 1.10 2001/11/12 06:57:29 okuji Exp $
 */

#ifdef FSYS_FFS

#include "shared.h"

#include "filesys.h"

#include "defs.h"
#include "disk_inode.h"
#include "disk_inode_ffs.h"
#include "dir.h"
#include "fs.h"

/* used for filesystem map blocks */
static int mapblock;
static int mapblock_offset;
static int mapblock_bsize;

/* pointer to superblock */
#define SUPERBLOCK ((struct fs *) ( FSYS_BUF + 8192 ))
#define INODE ((struct icommon *) ( FSYS_BUF + 16384 ))
#define MAPBUF ( FSYS_BUF + 24576 )
#define MAPBUF_LEN 8192


int
ffs_mount (void)
{
  int retval = 1;

  if ((((current_drive & 0x80) || (current_slice != 0))
       && ! IS_PC_SLICE_TYPE_BSD_WITH_FS (current_slice, FS_BSDFFS))
      || part_length < (SBLOCK + (SBSIZE / DEV_BSIZE))
      || !devread (SBLOCK, 0, SBSIZE, (char *) SUPERBLOCK)
      || SUPERBLOCK->fs_magic != FS_MAGIC)
    retval = 0;

  mapblock = -1;
  mapblock_offset = -1;

  return retval;
}

static int
block_map (int file_block)
{
  int bnum, offset, bsize;

  if (file_block < NDADDR)
    return (INODE->i_db[file_block]);

  /* If the blockmap loaded does not include FILE_BLOCK,
     load a new blockmap.  */
  if ((bnum = fsbtodb (SUPERBLOCK, INODE->i_ib[0])) != mapblock
      || (mapblock_offset <= bnum && bnum <= mapblock_offset + mapblock_bsize))
    {
      if (MAPBUF_LEN < SUPERBLOCK->fs_bsize)
	{
	  offset = ((file_block - NDADDR) % NINDIR (SUPERBLOCK));
	  bsize = MAPBUF_LEN;

	  if (offset + MAPBUF_LEN > SUPERBLOCK->fs_bsize)
	    offset = (SUPERBLOCK->fs_bsize - MAPBUF_LEN) / sizeof (int);
	}
      else
	{
	  bsize = SUPERBLOCK->fs_bsize;
	  offset = 0;
	}

      if (! devread (bnum, offset * sizeof (int), bsize, (char *) MAPBUF))
	{
	  mapblock = -1;
	  mapblock_bsize = -1;
	  mapblock_offset = -1;
	  errnum = ERR_FSYS_CORRUPT;
	  return -1;
	}

      mapblock = bnum;
      mapblock_bsize = bsize;
      mapblock_offset = offset;
    }

  return (((int *) MAPBUF)[((file_block - NDADDR) % NINDIR (SUPERBLOCK))
			  - mapblock_offset]);
}


int
ffs_read (char *buf, int len)
{
  int logno, off, size, map, ret = 0;

  while (len && !errnum)
    {
      off = blkoff (SUPERBLOCK, filepos);
      logno = lblkno (SUPERBLOCK, filepos);
      size = blksize (SUPERBLOCK, INODE, logno);

      if ((map = block_map (logno)) < 0)
	break;

      size -= off;

      if (size > len)
	size = len;

      disk_read_func = disk_read_hook;

      devread (fsbtodb (SUPERBLOCK, map), off, size, buf);

      disk_read_func = NULL;

      buf += size;
      len -= size;
      filepos += size;
      ret += size;
    }

  if (errnum)
    ret = 0;

  return ret;
}


int
ffs_dir (char *dirname)
{
  char *rest, ch;
  int block, off, loc, map, ino = ROOTINO;
  struct direct *dp;

/* main loop to find destination inode */
loop:

  /* load current inode (defaults to the root inode) */

	if (!devread (fsbtodb (SUPERBLOCK, itod (SUPERBLOCK, ino)),
								ino % (SUPERBLOCK->fs_inopb) * sizeof (struct dinode),
								sizeof (struct dinode), (char *) INODE))
			return 0;			/* XXX what return value? */

  /* if we have a real file (and we're not just printing possibilities),
     then this is where we want to exit */

  if (!*dirname || isspace (*dirname))
    {
      if ((INODE->i_mode & IFMT) != IFREG)
	{
	  errnum = ERR_BAD_FILETYPE;
	  return 0;
	}

      filemax = INODE->i_size;

      /* incomplete implementation requires this! */
      fsmax = (NDADDR + NINDIR (SUPERBLOCK)) * SUPERBLOCK->fs_bsize;
      return 1;
    }

  /* continue with file/directory name interpretation */

  while (*dirname == '/')
    dirname++;

  if (!(INODE->i_size) || ((INODE->i_mode & IFMT) != IFDIR))
    {
      errnum = ERR_BAD_FILETYPE;
      return 0;
    }

  for (rest = dirname; (ch = *rest) && !isspace (ch) && ch != '/'; rest++);

  *rest = 0;
  loc = 0;

  /* loop for reading a the entries in a directory */

  do
    {
      if (loc >= INODE->i_size)
	{
#if 0
	  putchar ('\n');
#endif

	  if (print_possibilities < 0)
	    return 1;

	  errnum = ERR_FILE_NOT_FOUND;
	  *rest = ch;
	  return 0;
	}

      if (!(off = blkoff (SUPERBLOCK, loc)))
	{
	  block = lblkno (SUPERBLOCK, loc);

	  if ((map = block_map (block)) < 0
	      || !devread (fsbtodb (SUPERBLOCK, map), 0,
			   blksize (SUPERBLOCK, INODE, block),
			   (char *) FSYS_BUF))
	    {
	      errnum = ERR_FSYS_CORRUPT;
	      *rest = ch;
	      return 0;
	    }
	}

      dp = (struct direct *) (FSYS_BUF + off);
      loc += dp->d_reclen;

#ifndef STAGE1_5
      if (dp->d_ino && print_possibilities && ch != '/'
	  && (!*dirname || substring (dirname, dp->d_name) <= 0))
	{
	  if (print_possibilities > 0)
	    print_possibilities = -print_possibilities;

	  print_a_completion (dp->d_name);
	}
#endif /* STAGE1_5 */
    }
  while (!dp->d_ino || (substring (dirname, dp->d_name) != 0
			|| (print_possibilities && ch != '/')));

  /* only get here if we have a matching directory entry */

  ino = dp->d_ino;
  *(dirname = rest) = ch;

  /* go back to main loop at top of function */
  goto loop;
}

int
ffs_embed (int *start_sector, int needed_sectors)
{
  /* XXX: I don't know if this is really correct. Someone who is
     familiar with BSD should check for this.  */
  if (needed_sectors > 14)
    return 0;

  *start_sector = 1;
#if 1
  /* FIXME: Disable the embedding in FFS until someone checks if
     the code above is correct.  */
  return 0;
#else
  return 1;
#endif
}

#endif /* FSYS_FFS */
