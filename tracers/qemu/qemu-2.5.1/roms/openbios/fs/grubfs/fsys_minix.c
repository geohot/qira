/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002  Free Software Foundation, Inc.
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

/* Restrictions:
   This is MINIX V1 only (yet)
   Disk creation is like:
   mkfs.minix -c DEVICE
*/

#ifdef FSYS_MINIX

#include "shared.h"
#include "filesys.h"

/* #define DEBUG_MINIX */

/* indirect blocks */
static int mapblock1, mapblock2, namelen;

/* sizes are always in bytes, BLOCK values are always in DEV_BSIZE (sectors) */
#define DEV_BSIZE 512

/* include/linux/fs.h */
#define BLOCK_SIZE_BITS 10
#define BLOCK_SIZE 	(1<<BLOCK_SIZE_BITS)

/* made up, defaults to 1 but can be passed via mount_opts */
#define WHICH_SUPER 1
/* kind of from fs/ext2/super.c (is OK for minix) */
#define SBLOCK (WHICH_SUPER * BLOCK_SIZE / DEV_BSIZE)	/* = 2 */

/* include/asm-i386/type.h */
typedef __signed__ char __s8;
typedef unsigned char __u8;
typedef __signed__ short __s16;
typedef unsigned short __u16;
typedef __signed__ int __s32;
typedef unsigned int __u32;

/* include/linux/minix_fs.h */
#define MINIX_ROOT_INO 1

/* Not the same as the bogus LINK_MAX in <linux/limits.h>. Oh well. */
#define MINIX_LINK_MAX  250
#define MINIX2_LINK_MAX 65530

#define MINIX_I_MAP_SLOTS       8
#define MINIX_Z_MAP_SLOTS       64
#define MINIX_SUPER_MAGIC       0x137F          /* original minix fs */
#define MINIX_SUPER_MAGIC2      0x138F          /* minix fs, 30 char names */
#define MINIX2_SUPER_MAGIC      0x2468          /* minix V2 fs */
#define MINIX2_SUPER_MAGIC2     0x2478          /* minix V2 fs, 30 char names */
#define MINIX_VALID_FS          0x0001          /* Clean fs. */
#define MINIX_ERROR_FS          0x0002          /* fs has errors. */

#define MINIX_INODES_PER_BLOCK ((BLOCK_SIZE)/(sizeof (struct minix_inode)))
#define MINIX2_INODES_PER_BLOCK ((BLOCK_SIZE)/(sizeof (struct minix2_inode)))

#define MINIX_V1                0x0001          /* original minix fs */
#define MINIX_V2                0x0002          /* minix V2 fs */

/* originally this is :
#define INODE_VERSION(inode)    inode->i_sb->u.minix_sb.s_version
   here we have */
#define INODE_VERSION(inode)	(SUPERBLOCK->s_version)

/*
 * This is the original minix inode layout on disk.
 * Note the 8-bit gid and atime and ctime.
 */
struct minix_inode {
	__u16 i_mode;
	__u16 i_uid;
	__u32 i_size;
	__u32 i_time;
	__u8  i_gid;
	__u8  i_nlinks;
	__u16 i_zone[9];
};

/*
 * The new minix inode has all the time entries, as well as
 * long block numbers and a third indirect block (7+1+1+1
 * instead of 7+1+1). Also, some previously 8-bit values are
 * now 16-bit. The inode is now 64 bytes instead of 32.
 */
struct minix2_inode {
	__u16 i_mode;
	__u16 i_nlinks;
	__u16 i_uid;
	__u16 i_gid;
	__u32 i_size;
	__u32 i_atime;
	__u32 i_mtime;
	__u32 i_ctime;
	__u32 i_zone[10];
};

/*
 * minix super-block data on disk
 */
struct minix_super_block {
        __u16 s_ninodes;
        __u16 s_nzones;
        __u16 s_imap_blocks;
        __u16 s_zmap_blocks;
        __u16 s_firstdatazone;
        __u16 s_log_zone_size;
        __u32 s_max_size;
        __u16 s_magic;
        __u16 s_state;
        __u32 s_zones;
};

struct minix_dir_entry {
        __u16 inode;
        char name[0];
};

/* made up, these are pointers into FSYS_BUF */
/* read once, always stays there: */
#define SUPERBLOCK \
    ((struct minix_super_block *)(FSYS_BUF))
#define INODE \
    ((struct minix_inode *)((char *) SUPERBLOCK + BLOCK_SIZE))
#define DATABLOCK1 \
    ((char *)((char *)INODE + sizeof(struct minix_inode)))
#define DATABLOCK2 \
    ((char *)((char *)DATABLOCK1 + BLOCK_SIZE))

/* linux/stat.h */
#define S_IFMT  00170000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFDIR  0040000
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR)

#define PATH_MAX                1024	/* include/linux/limits.h */
#define MAX_LINK_COUNT             5	/* number of symbolic links to follow */

/* check filesystem types and read superblock into memory buffer */
int
minix_mount (void)
{
  if (((current_drive & 0x80) || current_slice != 0)
      && ! IS_PC_SLICE_TYPE_MINIX (current_slice)
      && ! IS_PC_SLICE_TYPE_BSD_WITH_FS (current_slice, FS_OTHER))
    return 0;			/* The partition is not of MINIX type */

  if (part_length < (SBLOCK +
		     (sizeof (struct minix_super_block) / DEV_BSIZE)))
    return 0;			/* The partition is too short */

  if (!devread (SBLOCK, 0, sizeof (struct minix_super_block),
		(char *) SUPERBLOCK))
    return 0;			/* Cannot read superblock */

  switch (SUPERBLOCK->s_magic)
    {
    case MINIX_SUPER_MAGIC:
      namelen = 14;
      break;
    case MINIX_SUPER_MAGIC2:
      namelen = 30;
      break;
    default:
      return 0;			/* Unsupported type */
    }

  return 1;
}

/* Takes a file system block number and reads it into BUFFER. */
static int
minix_rdfsb (int fsblock, char *buffer)
{
  return devread (fsblock * (BLOCK_SIZE / DEV_BSIZE), 0,
		  BLOCK_SIZE, buffer);
}

/* Maps LOGICAL_BLOCK (the file offset divided by the blocksize) into
   a physical block (the location in the file system) via an inode. */
static int
minix_block_map (int logical_block)
{
  int i;

  if (logical_block < 7)
    return INODE->i_zone[logical_block];

  logical_block -= 7;
  if (logical_block < 512)
    {
      i = INODE->i_zone[7];

      if (!i || ((mapblock1 != 1)
		 && !minix_rdfsb (i, DATABLOCK1)))
	{
	  errnum = ERR_FSYS_CORRUPT;
	  return -1;
	}
      mapblock1 = 1;
      return ((__u16 *) DATABLOCK1) [logical_block];
    }

  logical_block -= 512;
  i = INODE->i_zone[8];
  if (!i || ((mapblock1 != 2)
	     && !minix_rdfsb (i, DATABLOCK1)))
    {
      errnum = ERR_FSYS_CORRUPT;
      return -1;
    }
  mapblock1 = 2;
  i = ((__u16 *) DATABLOCK1)[logical_block >> 9];
  if (!i || ((mapblock2 != i)
	     && !minix_rdfsb (i, DATABLOCK2)))
    {
      errnum = ERR_FSYS_CORRUPT;
      return -1;
    }
  mapblock2 = i;
  return ((__u16 *) DATABLOCK2)[logical_block & 511];
}

/* read from INODE into BUF */
int
minix_read (char *buf, int len)
{
  int logical_block;
  int offset;
  int map;
  int ret = 0;
  int size = 0;

  while (len > 0)
    {
      /* find the (logical) block component of our location */
      logical_block = filepos >> BLOCK_SIZE_BITS;
      offset = filepos & (BLOCK_SIZE - 1);
      map = minix_block_map (logical_block);
#ifdef DEBUG_MINIX
      printf ("map=%d\n", map);
#endif
      if (map < 0)
	break;

      size = BLOCK_SIZE;
      size -= offset;
      if (size > len)
	size = len;

      disk_read_func = disk_read_hook;

      devread (map * (BLOCK_SIZE / DEV_BSIZE),
	       offset, size, buf);

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

/* preconditions: minix_mount already executed, therefore supblk in buffer
     known as SUPERBLOCK
   returns: 0 if error, nonzero iff we were able to find the file successfully
   postconditions: on a nonzero return, buffer known as INODE contains the
     inode of the file we were trying to look up
   side effects: none yet  */
int
minix_dir (char *dirname)
{
  int current_ino = MINIX_ROOT_INO;  /* start at the root */
  int updir_ino = current_ino;	     /* the parent of the current directory */
  int ino_blk;			     /* fs pointer of the inode's info */

  int str_chk = 0;		     /* used ot hold the results of a string
				        compare */

  struct minix_inode * raw_inode;    /* inode info for current_ino */

  char linkbuf[PATH_MAX];	     /* buffer for following sym-links */
  int link_count = 0;

  char * rest;
  char ch;

  int off;			     /* offset within block of directory
					entry */
  int loc;			     /* location within a directory */
  int blk;			     /* which data blk within dir entry */
  long map;			     /* fs pointer of a particular block from
					dir entry */
  struct minix_dir_entry * dp;	     /* pointer to directory entry */

  /* loop invariants:
     current_ino = inode to lookup
     dirname = pointer to filename component we are cur looking up within
     the directory known pointed to by current_ino (if any) */

#ifdef DEBUG_MINIX
  printf ("\n");
#endif

  while (1)
    {
#ifdef DEBUG_MINIX
      printf ("inode %d, dirname %s\n", current_ino, dirname);
#endif

      ino_blk = (2 + SUPERBLOCK->s_imap_blocks + SUPERBLOCK->s_zmap_blocks
		 + (current_ino - 1) / MINIX_INODES_PER_BLOCK);
      if (! minix_rdfsb (ino_blk, (char *) INODE))
	return 0;

      /* reset indirect blocks! */
      mapblock2 = mapblock1 = -1;

      raw_inode = INODE + ((current_ino - 1) % MINIX_INODES_PER_BLOCK);

      /* copy inode to fixed location */
      memmove ((void *) INODE, (void *) raw_inode,
	       sizeof (struct minix_inode));

      /* If we've got a symbolic link, then chase it. */
      if (S_ISLNK (INODE->i_mode))
	{
	  int len;

	  if (++link_count > MAX_LINK_COUNT)
	    {
	      errnum = ERR_SYMLINK_LOOP;
	      return 0;
	    }
#ifdef DEBUG_MINIX
	  printf ("S_ISLNK (%s)\n", dirname);
#endif

	  /* Find out how long our remaining name is. */
	  len = 0;
	  while (dirname[len] && !isspace (dirname[len]))
	    len++;

	  /* Get the symlink size. */
	  filemax = (INODE->i_size);
	  if (filemax + len > sizeof (linkbuf) - 2)
	    {
	      errnum = ERR_FILELENGTH;
	      return 0;
	    }

	  if (len)
	    {
	      /* Copy the remaining name to the end of the symlink data.
	         Note that DIRNAME and LINKBUF may overlap! */
	      memmove (linkbuf + filemax, dirname, len);
	    }
	  linkbuf[filemax + len] = '\0';

	  /* Read the necessary blocks, and reset the file pointer. */
	  len = grub_read (linkbuf, filemax);
	  filepos = 0;
	  if (!len)
	    return 0;

#ifdef DEBUG_MINIX
	  printf ("symlink=%s\n", linkbuf);
#endif

	  dirname = linkbuf;
	  if (*dirname == '/')
	    {
	      /* It's an absolute link, so look it up in root. */
	      current_ino = MINIX_ROOT_INO;
	      updir_ino = current_ino;
	    }
	  else
	    {
	      /* Relative, so look it up in our parent directory. */
	      current_ino = updir_ino;
	    }

	  /* Try again using the new name. */
	  continue;
	}

      /* If end of filename, INODE points to the file's inode */
      if (!*dirname || isspace (*dirname))
	{
	  if (!S_ISREG (INODE->i_mode))
	    {
	      errnum = ERR_BAD_FILETYPE;
	      return 0;
	    }

	  filemax = (INODE->i_size);
	  return 1;
	}

      /* else we have to traverse a directory */
      updir_ino = current_ino;

      /* skip over slashes */
      while (*dirname == '/')
	dirname++;

      /* if this isn't a directory of sufficient size to hold our file,
	 abort */
      if (!(INODE->i_size) || !S_ISDIR (INODE->i_mode))
	{
	  errnum = ERR_BAD_FILETYPE;
	  return 0;
	}

      /* skip to next slash or end of filename (space) */
      for (rest = dirname; (ch = *rest) && !isspace (ch) && ch != '/';
	   rest++);

      /* look through this directory and find the next filename component */
      /* invariant: rest points to slash after the next filename component */
      *rest = 0;
      loc = 0;

      do
	{
#ifdef DEBUG_MINIX
	  printf ("dirname=`%s', rest=`%s', loc=%d\n", dirname, rest, loc);
#endif

	  /* if our location/byte offset into the directory exceeds the size,
	     give up */
	  if (loc >= INODE->i_size)
	    {
	      if (print_possibilities < 0)
		{
#if 0
		  putchar ('\n');
#endif
		}
	      else
		{
		  errnum = ERR_FILE_NOT_FOUND;
		  *rest = ch;
		}
	      return (print_possibilities < 0);
	    }

	  /* else, find the (logical) block component of our location */
	  blk = loc >> BLOCK_SIZE_BITS;

	  /* we know which logical block of the directory entry we are looking
	     for, now we have to translate that to the physical (fs) block on
	     the disk */
	  map = minix_block_map (blk);
#ifdef DEBUG_MINIX
	  printf ("fs block=%d\n", map);
#endif
	  mapblock2 = -1;
	  if ((map < 0) || !minix_rdfsb (map, DATABLOCK2))
	    {
	      errnum = ERR_FSYS_CORRUPT;
	      *rest = ch;
	      return 0;
	    }
	  off = loc & (BLOCK_SIZE - 1);
	  dp = (struct minix_dir_entry *) (DATABLOCK2 + off);
	  /* advance loc prematurely to next on-disk directory entry  */
	  loc += sizeof (dp->inode) + namelen;

	  /* NOTE: minix filenames are NULL terminated if < NAMELEN
	     else exact */

#ifdef DEBUG_MINIX
	  printf ("directory entry ino=%d\n", dp->inode);
	  if (dp->inode)
	    printf ("entry=%s\n", dp->name);
#endif

	  if (dp->inode)
	    {
	      int saved_c = dp->name[namelen];

	      dp->name[namelen] = 0;
	      str_chk = substring (dirname, dp->name);

# ifndef STAGE1_5
	      if (print_possibilities && ch != '/'
		  && (!*dirname || str_chk <= 0))
		{
		  if (print_possibilities > 0)
		    print_possibilities = -print_possibilities;
		  print_a_completion (dp->name);
		}
# endif

	      dp->name[namelen] = saved_c;
	    }

	}
      while (!dp->inode || (str_chk || (print_possibilities && ch != '/')));

      current_ino = dp->inode;
      *(dirname = rest) = ch;
    }
  /* never get here */
}

#endif /* FSYS_MINIX */
