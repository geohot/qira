/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999, 2001  Free Software Foundation, Inc.
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

#ifdef FSYS_EXT2FS

#include "config.h"
#include "shared.h"
#include "filesys.h"
#include "libc/byteorder.h"

#ifdef CONFIG_DEBUG_EXT2FS
#define E2DEBUG
#endif

static int mapblock1, mapblock2;

/* sizes are always in bytes, BLOCK values are always in DEV_BSIZE (sectors) */
#define DEV_BSIZE 512

/* include/linux/fs.h */
#define BLOCK_SIZE 1024		/* initial block size for superblock read */
/* made up, defaults to 1 but can be passed via mount_opts */
#define WHICH_SUPER 1
/* kind of from fs/ext2/super.c */
#define SBLOCK (WHICH_SUPER * BLOCK_SIZE / DEV_BSIZE)	/* = 2 */

/* include/asm-i386/types.h */
typedef __signed__ char __s8;
typedef unsigned char __u8;
typedef __signed__ short __s16;
typedef unsigned short __u16;
typedef __signed__ int __s32;
typedef unsigned int __u32;

/*
 * Constants relative to the data blocks, from ext2_fs.h
 */
#define EXT2_NDIR_BLOCKS                12
#define EXT2_IND_BLOCK                  EXT2_NDIR_BLOCKS
#define EXT2_DIND_BLOCK                 (EXT2_IND_BLOCK + 1)
#define EXT2_TIND_BLOCK                 (EXT2_DIND_BLOCK + 1)
#define EXT2_N_BLOCKS                   (EXT2_TIND_BLOCK + 1)

/* include/linux/ext2_fs.h */
struct ext2_super_block
  {
    __u32 s_inodes_count;	/* Inodes count */
    __u32 s_blocks_count;	/* Blocks count */
    __u32 s_r_blocks_count;	/* Reserved blocks count */
    __u32 s_free_blocks_count;	/* Free blocks count */
    __u32 s_free_inodes_count;	/* Free inodes count */
    __u32 s_first_data_block;	/* First Data Block */
    __u32 s_log_block_size;	/* Block size */
    __s32 s_log_frag_size;	/* Fragment size */
    __u32 s_blocks_per_group;	/* # Blocks per group */
    __u32 s_frags_per_group;	/* # Fragments per group */
    __u32 s_inodes_per_group;	/* # Inodes per group */
    __u32 s_mtime;		/* Mount time */
    __u32 s_wtime;		/* Write time */
    __u16 s_mnt_count;		/* Mount count */
    __s16 s_max_mnt_count;	/* Maximal mount count */
    __u16 s_magic;		/* Magic signature */
    __u16 s_state;		/* File system state */
    __u16 s_errors;		/* Behaviour when detecting errors */
    __u16 s_pad;
    __u32 s_lastcheck;		/* time of last check */
    __u32 s_checkinterval;	/* max. time between checks */
    __u32 s_creator_os;		/* OS */
    __u32 s_rev_level;		/* Revision level */
    __u16 s_def_resuid;		/* Default uid for reserved blocks */
    __u16 s_def_resgid;		/* Default gid for reserved blocks */
    __u32 s_reserved[235];	/* Padding to the end of the block */
  };

struct ext2_group_desc
  {
    __u32 bg_block_bitmap;	/* Blocks bitmap block */
    __u32 bg_inode_bitmap;	/* Inodes bitmap block */
    __u32 bg_inode_table;	/* Inodes table block */
    __u16 bg_free_blocks_count;	/* Free blocks count */
    __u16 bg_free_inodes_count;	/* Free inodes count */
    __u16 bg_used_dirs_count;	/* Directories count */
    __u16 bg_pad;
    __u32 bg_reserved[3];
  };

struct ext2_inode
  {
    __u16 i_mode;		/* File mode */
    __u16 i_uid;		/* Owner Uid */
    __u32 i_size;		/* 4: Size in bytes */
    __u32 i_atime;		/* Access time */
    __u32 i_ctime;		/* 12: Creation time */
    __u32 i_mtime;		/* Modification time */
    __u32 i_dtime;		/* 20: Deletion Time */
    __u16 i_gid;		/* Group Id */
    __u16 i_links_count;	/* 24: Links count */
    __u32 i_blocks;		/* Blocks count */
    __u32 i_flags;		/* 32: File flags */
    union
      {
	struct
	  {
	    __u32 l_i_reserved1;
	  }
	linux1;
	struct
	  {
	    __u32 h_i_translator;
	  }
	hurd1;
	struct
	  {
	    __u32 m_i_reserved1;
	  }
	masix1;
      }
    osd1;			/* OS dependent 1 */
    __u32 i_block[EXT2_N_BLOCKS];	/* 40: Pointers to blocks */
    __u32 i_version;		/* File version (for NFS) */
    __u32 i_file_acl;		/* File ACL */
    __u32 i_dir_acl;		/* Directory ACL */
    __u32 i_faddr;		/* Fragment address */
    union
      {
	struct
	  {
	    __u8 l_i_frag;	/* Fragment number */
	    __u8 l_i_fsize;	/* Fragment size */
	    __u16 i_pad1;
	    __u32 l_i_reserved2[2];
	  }
	linux2;
	struct
	  {
	    __u8 h_i_frag;	/* Fragment number */
	    __u8 h_i_fsize;	/* Fragment size */
	    __u16 h_i_mode_high;
	    __u16 h_i_uid_high;
	    __u16 h_i_gid_high;
	    __u32 h_i_author;
	  }
	hurd2;
	struct
	  {
	    __u8 m_i_frag;	/* Fragment number */
	    __u8 m_i_fsize;	/* Fragment size */
	    __u16 m_pad1;
	    __u32 m_i_reserved2[2];
	  }
	masix2;
      }
    osd2;			/* OS dependent 2 */
  };

/* linux/posix_type.h */
typedef long linux_off_t;

/* linux/ext2fs.h */
#define EXT2_NAME_LEN 255
struct ext2_dir_entry
  {
    __u32 inode;		/* Inode number */
    __u16 rec_len;		/* Directory entry length */
    __u8 name_len;		/* Name length */
    __u8 file_type;
    char name[EXT2_NAME_LEN];	/* File name */
  };

/* ext2/super.c */
#define EXT2_SUPER_MAGIC      0xEF53	/* include/linux/ext2_fs.h */
#define EXT2_ROOT_INO              2	/* include/linux/ext2_fs.h */
#define PATH_MAX                1024	/* include/linux/limits.h */
#define MAX_LINK_COUNT             5	/* number of symbolic links to follow */

/* made up, these are pointers into FSYS_BUF */
/* read once, always stays there: */
#define SUPERBLOCK \
    ((struct ext2_super_block *)(FSYS_BUF))
#define GROUP_DESC \
    ((struct ext2_group_desc *) \
     ((char *)SUPERBLOCK + sizeof(struct ext2_super_block)))
#define INODE \
    ((struct ext2_inode *)((char *)GROUP_DESC + EXT2_BLOCK_SIZE(SUPERBLOCK)))
#define DATABLOCK1 \
    ((char *)((char *)INODE + sizeof(struct ext2_inode)))
#define DATABLOCK2 \
    ((char *)((char *)DATABLOCK1 + EXT2_BLOCK_SIZE(SUPERBLOCK)))

/* linux/ext2_fs.h */
#define EXT2_ADDR_PER_BLOCK(s)          (EXT2_BLOCK_SIZE(s) / sizeof (__u32))
#define EXT2_ADDR_PER_BLOCK_BITS(s)	(log2(EXT2_ADDR_PER_BLOCK(s)))

/* linux/ext2_fs.h */
#define EXT2_BLOCK_SIZE_BITS(s)        (__le32_to_cpu((s)->s_log_block_size) + 10)
/* kind of from ext2/super.c */
#define EXT2_BLOCK_SIZE(s)	(1 << EXT2_BLOCK_SIZE_BITS(s))
/* linux/ext2fs.h */
#define EXT2_DESC_PER_BLOCK(s) \
     (EXT2_BLOCK_SIZE(s) / sizeof (struct ext2_group_desc))
/* linux/stat.h */
#define S_IFMT  00170000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFDIR  0040000
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR)

#ifdef E2DEBUG
void
dump_super(struct ext2_super_block *s)
{
    printf(" superblock 0x%x:\n", s);
    printf("  inodes=%d\n", __le32_to_cpu(s->s_inodes_count));
    printf("  blocks=%d\n", __le32_to_cpu(s->s_blocks_count));
    printf("  reserved=%d\n", __le32_to_cpu(s->s_r_blocks_count));
    printf("  i_free=%d\n", __le32_to_cpu(s->s_free_inodes_count));
    printf("  b_free=%d\n", __le32_to_cpu(s->s_free_blocks_count));
    printf("  first=%d\n", __le32_to_cpu(s->s_first_data_block));
    printf("  log_b_size=%d, b_size=%d\n", __le32_to_cpu(s->s_log_block_size), EXT2_BLOCK_SIZE(s));
    printf("  log_f_size=%d\n", __le32_to_cpu(s->s_log_frag_size));
    printf("  bpg=%d\n", __le32_to_cpu(s->s_blocks_per_group));
    printf("  fpg=%d\n", __le32_to_cpu(s->s_frags_per_group));
    printf("  ipg=%d\n", __le32_to_cpu(s->s_inodes_per_group));
}

void
dump_group_desc(struct ext2_group_desc *g)
{
    printf(" group_desc 0x%x:\n", g);
    printf("  b_bmap block=%d\n", __le32_to_cpu(g->bg_block_bitmap));
    printf("  i_bmap block=%d\n", __le32_to_cpu(g->bg_inode_bitmap));
    printf("  i_tab block=%d\n", __le32_to_cpu(g->bg_inode_table));
    printf("  free_blks=%d\n", __le16_to_cpu(g->bg_free_blocks_count));
    printf("  free_inodes=%d\n", __le16_to_cpu(g->bg_free_inodes_count));
    printf("  used_dirs=%d\n", __le16_to_cpu(g->bg_used_dirs_count));
}

void
dump_inode(struct ext2_inode *i)
{
    printf(" inode 0x%x:\n", i);
    printf("  mode=%o\n", __le16_to_cpu(i->i_mode));
    printf("  uid=%d\n", __le16_to_cpu(i->i_uid));
    printf("  gid=%d\n", __le16_to_cpu(i->i_gid));
    printf("  size=%d\n", __le32_to_cpu(i->i_size));
    printf("  atime=%d\n", __le32_to_cpu(i->i_atime));
    printf("  ctime=%d\n", __le32_to_cpu(i->i_ctime));
    printf("  mtime=%d\n", __le32_to_cpu(i->i_mtime));
    printf("  dtime=%d\n", __le32_to_cpu(i->i_dtime));
    printf("  links=%d\n", __le16_to_cpu(i->i_links_count));
    printf("  blocks=%d\n", __le32_to_cpu(i->i_blocks));
    printf("  flags=%d\n", __le32_to_cpu(i->i_flags));
}

void
dump_inode_data(unsigned char *inode, int len)
{
  static char hexdigit[] = "0123456789abcdef";
  unsigned char *i;
  for (i = inode;
       i < (inode + len);
       i++)
    {
      printf ("%c", hexdigit[*i >> 4]);
      printf ("%c", hexdigit[*i % 16]);
      if (!((i + 1 - inode) % 16))
	{
	  printf ("\n");
	}
      else
	{
	  printf (" ");
	}
    }
}
#endif

/* check filesystem types and read superblock into memory buffer */
int
ext2fs_mount (void)
{
  int retval = 1;

  if ((((current_drive & 0x80) || (current_slice != 0))
       && (current_slice != PC_SLICE_TYPE_EXT2FS)
       && (current_slice != PC_SLICE_TYPE_LINUX_RAID)
       && (! IS_PC_SLICE_TYPE_BSD_WITH_FS (current_slice, FS_EXT2FS))
       && (! IS_PC_SLICE_TYPE_BSD_WITH_FS (current_slice, FS_OTHER)))
      || part_length < (SBLOCK + (sizeof (struct ext2_super_block) / DEV_BSIZE))
      || !devread (SBLOCK, 0, sizeof (struct ext2_super_block),
		   (char *) SUPERBLOCK)
      || __le16_to_cpu(SUPERBLOCK->s_magic) != EXT2_SUPER_MAGIC)
      retval = 0;

  return retval;
}

/* Takes a file system block number and reads it into BUFFER. */
static int
ext2_rdfsb (int fsblock, char * buffer)
{
#ifdef E2DEBUG
  printf ("ext2_rdfsb: fsblock %d, devblock %d, size %d\n", fsblock,
	  fsblock * (EXT2_BLOCK_SIZE (SUPERBLOCK) / DEV_BSIZE),
	  EXT2_BLOCK_SIZE (SUPERBLOCK));
#endif /* E2DEBUG */
  return devread (fsblock * (EXT2_BLOCK_SIZE (SUPERBLOCK) / DEV_BSIZE), 0,
		  EXT2_BLOCK_SIZE (SUPERBLOCK), (char *) buffer);
}

/* from
  ext2/inode.c:ext2_bmap()
*/
/* Maps LOGICAL_BLOCK (the file offset divided by the blocksize) into
   a physical block (the location in the file system) via an inode. */
static int
ext2fs_block_map (int logical_block)
{

#ifdef E2DEBUG
  printf ("ext2fs_block_map(%d)\n", logical_block);
#endif /* E2DEBUG */

  /* if it is directly pointed to by the inode, return that physical addr */
  if (logical_block < EXT2_NDIR_BLOCKS)
    {
#ifdef E2DEBUG
      printf ("ext2fs_block_map: returning %d\n", __le32_to_cpu(INODE->i_block[logical_block]));
#endif /* E2DEBUG */
      return __le32_to_cpu(INODE->i_block[logical_block]);
    }
  /* else */
  logical_block -= EXT2_NDIR_BLOCKS;
  /* try the indirect block */
  if (logical_block < EXT2_ADDR_PER_BLOCK (SUPERBLOCK))
    {
      if (mapblock1 != 1
	  && !ext2_rdfsb (__le32_to_cpu(INODE->i_block[EXT2_IND_BLOCK]), DATABLOCK1))
	{
	  errnum = ERR_FSYS_CORRUPT;
	  return -1;
	}
      mapblock1 = 1;
      return __le32_to_cpu(((__u32 *) DATABLOCK1)[logical_block]);
    }
  /* else */
  logical_block -= EXT2_ADDR_PER_BLOCK (SUPERBLOCK);
  /* now try the double indirect block */
  if (logical_block < (1 << (EXT2_ADDR_PER_BLOCK_BITS (SUPERBLOCK) * 2)))
    {
      int bnum;
      if (mapblock1 != 2
	  && !ext2_rdfsb (__le32_to_cpu(INODE->i_block[EXT2_DIND_BLOCK]), DATABLOCK1))
	{
	  errnum = ERR_FSYS_CORRUPT;
	  return -1;
	}
      mapblock1 = 2;
      if ((bnum = __le32_to_cpu(((__u32 *) DATABLOCK1)
		   [logical_block >> EXT2_ADDR_PER_BLOCK_BITS (SUPERBLOCK)]))
	  != mapblock2
	  && !ext2_rdfsb (bnum, DATABLOCK2))
	{
	  errnum = ERR_FSYS_CORRUPT;
	  return -1;
	}
      mapblock2 = bnum;
      return __le32_to_cpu(((__u32 *) DATABLOCK2)
	[logical_block & (EXT2_ADDR_PER_BLOCK (SUPERBLOCK) - 1)]);
    }
  /* else */
  mapblock2 = -1;
  logical_block -= (1 << (EXT2_ADDR_PER_BLOCK_BITS (SUPERBLOCK) * 2));
  if (mapblock1 != 3
      && !ext2_rdfsb (__le32_to_cpu(INODE->i_block[EXT2_TIND_BLOCK]), DATABLOCK1))
    {
      errnum = ERR_FSYS_CORRUPT;
      return -1;
    }
  mapblock1 = 3;
  if (!ext2_rdfsb (__le32_to_cpu(((__u32 *) DATABLOCK1)
		   [logical_block >> (EXT2_ADDR_PER_BLOCK_BITS (SUPERBLOCK)
				      * 2)]),
		   DATABLOCK2))
    {
      errnum = ERR_FSYS_CORRUPT;
      return -1;
    }
  if (!ext2_rdfsb (__le32_to_cpu(((__u32 *) DATABLOCK2)
		   [(logical_block >> EXT2_ADDR_PER_BLOCK_BITS (SUPERBLOCK))
		    & (EXT2_ADDR_PER_BLOCK (SUPERBLOCK) - 1)]),
		   DATABLOCK2))
    {
      errnum = ERR_FSYS_CORRUPT;
      return -1;
    }
  return __le32_to_cpu(((__u32 *) DATABLOCK2)
    [logical_block & (EXT2_ADDR_PER_BLOCK (SUPERBLOCK) - 1)]);
}

/* preconditions: all preconds of ext2fs_block_map */
int
ext2fs_read (char *buf, int len)
{
  int logical_block;
  int offset;
  int map;
  int ret = 0;
  int size = 0;

#ifdef E2DEBUG
  printf("ext2fs_read(0x%x, %d)\n", buf, len);
  dump_inode(INODE);
  dump_inode_data((unsigned char *)INODE, sizeof (struct ext2_inode));
#endif /* E2DEBUG */
  while (len > 0)
    {
      /* find the (logical) block component of our location */
      logical_block = filepos >> EXT2_BLOCK_SIZE_BITS (SUPERBLOCK);
      offset = filepos & (EXT2_BLOCK_SIZE (SUPERBLOCK) - 1);
      map = ext2fs_block_map (logical_block);
#ifdef E2DEBUG
      printf ("map=%d\n", map);
#endif /* E2DEBUG */
      if (map < 0)
	break;

      size = EXT2_BLOCK_SIZE (SUPERBLOCK);
      size -= offset;
      if (size > len)
	size = len;

      disk_read_func = disk_read_hook;

      devread (map * (EXT2_BLOCK_SIZE (SUPERBLOCK) / DEV_BSIZE),
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


/* Based on:
   def_blk_fops points to
   blkdev_open, which calls (I think):
   sys_open()
   do_open()
   open_namei()
   dir_namei() which accesses current->fs->root
     fs->root was set during original mount:
     (something)... which calls (I think):
     ext2_read_super()
     iget()
     __iget()
     read_inode()
     ext2_read_inode()
       uses desc_per_block_bits, which is set in ext2_read_super()
       also uses group descriptors loaded during ext2_read_super()
   lookup()
   ext2_lookup()
   ext2_find_entry()
   ext2_getblk()

*/

/* preconditions: ext2fs_mount already executed, therefore supblk in buffer
 *   known as SUPERBLOCK
 * returns: 0 if error, nonzero iff we were able to find the file successfully
 * postconditions: on a nonzero return, buffer known as INODE contains the
 *   inode of the file we were trying to look up
 * side effects: messes up GROUP_DESC buffer area
 */
int
ext2fs_dir (char *dirname)
{
  int current_ino = EXT2_ROOT_INO;	/* start at the root */
  int updir_ino = current_ino;	/* the parent of the current directory */
  int group_id;			/* which group the inode is in */
  int group_desc;		/* fs pointer to that group */
  int desc;			/* index within that group */
  int ino_blk;			/* fs pointer of the inode's information */
  int str_chk = 0;		/* used to hold the results of a string compare */
  struct ext2_group_desc *gdp;
  struct ext2_inode *raw_inode;	/* inode info corresponding to current_ino */

  char linkbuf[PATH_MAX];	/* buffer for following symbolic links */
  int link_count = 0;

  char *rest;
  char ch;			/* temp char holder */

  int off;			/* offset within block of directory entry (off mod blocksize) */
  int loc;			/* location within a directory */
  int blk;			/* which data blk within dir entry (off div blocksize) */
  long map;			/* fs pointer of a particular block from dir entry */
  struct ext2_dir_entry *dp;	/* pointer to directory entry */

  /* loop invariants:
     current_ino = inode to lookup
     dirname = pointer to filename component we are cur looking up within
     the directory known pointed to by current_ino (if any)
   */

#ifdef E2DEBUG
  printf("****** ext2fs_dir(%s)\n", dirname);
  dump_super(SUPERBLOCK);
#endif /* E2DEBUG */

  while (1)
    {
#ifdef E2DEBUG
      printf ("ext2fs_dir: inode %d\n", current_ino);
      printf ("ext2fs_dir: dirname=%s\n", dirname);
#endif /* E2DEBUG */

      /* look up an inode */
      group_id = (current_ino - 1) / __le32_to_cpu(SUPERBLOCK->s_inodes_per_group);
      group_desc = group_id >> log2 (EXT2_DESC_PER_BLOCK (SUPERBLOCK));
      desc = group_id & (EXT2_DESC_PER_BLOCK (SUPERBLOCK) - 1);
#ifdef E2DEBUG
      printf ("ext2fs_dir: ipg=%d, dpb=%d\n", __le32_to_cpu(SUPERBLOCK->s_inodes_per_group),
	      EXT2_DESC_PER_BLOCK (SUPERBLOCK));
      printf ("ext2fs_dir: group_id=%d group_desc=%d desc=%d\n", group_id, group_desc, desc);
#endif /* E2DEBUG */
      if (!ext2_rdfsb (
			(WHICH_SUPER + group_desc + __le32_to_cpu(SUPERBLOCK->s_first_data_block)),
			(char*) GROUP_DESC))
	{
	  return 0;
	}

#ifdef E2DEBUG
      dump_group_desc(GROUP_DESC);
#endif /* E2DEBUG */

      gdp = GROUP_DESC;
      ino_blk = __le32_to_cpu(gdp[desc].bg_inode_table) +
	(((current_ino - 1) % __le32_to_cpu(SUPERBLOCK->s_inodes_per_group))
	 >> log2 (EXT2_BLOCK_SIZE (SUPERBLOCK) / sizeof (struct ext2_inode)));
#ifdef E2DEBUG
      printf ("ext2fs_dir: itab_blk=%d, i_in_grp=%d, log2=%d\n",
	 __le32_to_cpu(gdp[desc].bg_inode_table),
	 ((current_ino - 1) % __le32_to_cpu(SUPERBLOCK->s_inodes_per_group)),
	 log2 (EXT2_BLOCK_SIZE (SUPERBLOCK) / sizeof (struct ext2_inode)));
      printf ("ext2fs_dir: inode table fsblock=%d\n", ino_blk);
#endif /* E2DEBUG */
      if (!ext2_rdfsb (ino_blk, (char *)INODE))
	{
	  return 0;
	}

      /* reset indirect blocks! */
      mapblock2 = mapblock1 = -1;

      raw_inode = INODE +
	((current_ino - 1)
	 & (EXT2_BLOCK_SIZE (SUPERBLOCK) / sizeof (struct ext2_inode) - 1));
#ifdef E2DEBUG
      printf ("ext2fs_dir: ipb=%d, sizeof(inode)=%d\n",
	      (EXT2_BLOCK_SIZE (SUPERBLOCK) / sizeof (struct ext2_inode)),
	      sizeof (struct ext2_inode));
      printf ("ext2fs_dir: inode=%x, raw_inode=%x\n", INODE, raw_inode);
      printf ("ext2fs_dir: offset into inode table block=%d\n", (int) raw_inode - (int) INODE);
      dump_inode(raw_inode);
      dump_inode_data((unsigned char *)INODE, EXT2_BLOCK_SIZE(SUPERBLOCK));
      printf ("ext2fs_dir: first word=%x\n", *((int *) raw_inode));
#endif /* E2DEBUG */

      /* copy inode to fixed location */
      memmove ((void *) INODE, (void *) raw_inode, sizeof (struct ext2_inode));

#ifdef E2DEBUG
      dump_inode(INODE);
      printf ("ext2fs_dir: first word=%x\n", *((int *) INODE));
#endif /* E2DEBUG */

      /* If we've got a symbolic link, then chase it. */
      if (S_ISLNK (__le16_to_cpu(INODE->i_mode)))
	{
	  int len;
	  if (++link_count > MAX_LINK_COUNT)
	    {
	      errnum = ERR_SYMLINK_LOOP;
	      return 0;
	    }

	  /* Find out how long our remaining name is. */
	  len = 0;
	  while (dirname[len] && !isspace (dirname[len]))
	    len++;

	  /* Get the symlink size. */
	  filemax = __le32_to_cpu(INODE->i_size);
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

	  /* Read the symlink data. */
	  if (__le32_to_cpu(INODE->i_blocks))
	    {
	      /* Read the necessary blocks, and reset the file pointer. */
	      len = file_read (linkbuf, filemax);
	      filepos = 0;
	      if (!len)
		return 0;
	    }
	  else
	    {
	      /* Copy the data directly from the inode. */
	      len = filemax;
	      memmove (linkbuf, (char *) INODE->i_block, len);
	    }

#ifdef E2DEBUG
	  printf ("ext2fs_dir: symlink=%s\n", linkbuf);
#endif

	  dirname = linkbuf;
	  if (*dirname == '/')
	    {
	      /* It's an absolute link, so look it up in root. */
	      current_ino = EXT2_ROOT_INO;
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

      /* if end of filename, INODE points to the file's inode */
      if (!*dirname || isspace (*dirname))
	{
	  if (!S_ISREG (__le16_to_cpu(INODE->i_mode)))
	    {
	      errnum = ERR_BAD_FILETYPE;
	      return 0;
	    }

	  filemax = __le32_to_cpu(INODE->i_size);
	  return 1;
	}

      /* else we have to traverse a directory */
      updir_ino = current_ino;

      /* skip over slashes */
      while (*dirname == '/')
	dirname++;

      /* if this isn't a directory of sufficient size to hold our file, abort */
      if (!(__le32_to_cpu(INODE->i_size)) || !S_ISDIR (__le16_to_cpu(INODE->i_mode)))
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

#ifdef E2DEBUG
	  printf ("ext2fs_dir: dirname=%s, rest=%s, loc=%d\n", dirname, rest, loc);
#endif /* E2DEBUG */

	  /* if our location/byte offset into the directory exceeds the size,
	     give up */
	  if (loc >= __le32_to_cpu(INODE->i_size))
	    {
	      if (print_possibilities < 0)
		{
# if 0
		  putchar ('\n');
# endif
		}
	      else
		{
		  errnum = ERR_FILE_NOT_FOUND;
		  *rest = ch;
		}
	      return (print_possibilities < 0);
	    }

	  /* else, find the (logical) block component of our location */
	  blk = loc >> EXT2_BLOCK_SIZE_BITS (SUPERBLOCK);

	  /* we know which logical block of the directory entry we are looking
	     for, now we have to translate that to the physical (fs) block on
	     the disk */
	  map = ext2fs_block_map (blk);
#ifdef E2DEBUG
	  printf ("ext2fs_dir: fs block=%d\n", map);
#endif /* E2DEBUG */
	  mapblock2 = -1;
	  if ((map < 0) || !ext2_rdfsb (map, DATABLOCK2))
	    {
	      errnum = ERR_FSYS_CORRUPT;
	      *rest = ch;
	      return 0;
	    }
	  off = loc & (EXT2_BLOCK_SIZE (SUPERBLOCK) - 1);
	  dp = (struct ext2_dir_entry *) (DATABLOCK2 + off);
	  /* advance loc prematurely to next on-disk directory entry  */
	  loc += __le16_to_cpu(dp->rec_len);

	  /* NOTE: ext2fs filenames are NOT null-terminated */

#ifdef E2DEBUG
	  printf ("ext2fs_dir: directory entry ino=%d\n", __le32_to_cpu(dp->inode));
	  if (__le32_to_cpu(dp->inode))
	    printf ("entry=%s\n", dp->name);
#endif /* E2DEBUG */

	  if (__le32_to_cpu(dp->inode))
	    {
	      int saved_c = dp->name[dp->name_len];

	      dp->name[dp->name_len] = 0;
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

	      dp->name[dp->name_len] = saved_c;
	    }

	}
      while (!__le32_to_cpu(dp->inode) || (str_chk || (print_possibilities && ch != '/')));

      current_ino = __le32_to_cpu(dp->inode);
      *(dirname = rest) = ch;
    }
  /* never get here */
}

#endif /* FSYS_EXT2_FS */
