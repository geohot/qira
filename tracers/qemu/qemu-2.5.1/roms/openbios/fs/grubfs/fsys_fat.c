/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000, 2001   Free Software Foundation, Inc.
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

#ifdef FSYS_FAT

#include "shared.h"
#include "filesys.h"
#include "fat.h"

struct fat_superblock
{
  int fat_offset;
  int fat_length;
  int fat_size;
  int root_offset;
  int root_max;
  int data_offset;

  int num_sectors;
  int num_clust;
  int clust_eof_marker;
  int sects_per_clust;
  int sectsize_bits;
  int clustsize_bits;
  int root_cluster;

  int cached_fat;
  int file_cluster;
  int current_cluster_num;
  int current_cluster;
};

/* pointer(s) into filesystem info buffer for DOS stuff */
#define FAT_SUPER ( (struct fat_superblock *) \
 		    ( FSYS_BUF + 32256) )/* 512 bytes long */
#define FAT_BUF   ( FSYS_BUF + 30208 )	/* 4 sector FAT buffer */
#define NAME_BUF  ( FSYS_BUF + 29184 )	/* Filename buffer (833 bytes) */

#define FAT_CACHE_SIZE 2048

int
fat_mount (void)
{
  struct fat_bpb bpb;
  __u32 magic, first_fat;

  /* Check partition type for harddisk */
  if (((current_drive & 0x80) || (current_slice != 0))
      && ! IS_PC_SLICE_TYPE_FAT (current_slice)
      && (! IS_PC_SLICE_TYPE_BSD_WITH_FS (current_slice, FS_MSDOS)))
    return 0;

  /* Read bpb */
  if (! devread (0, 0, sizeof (bpb), (char *) &bpb))
    return 0;

  /* Check if the number of sectors per cluster is zero here, to avoid
     zero division.  */
  if (bpb.sects_per_clust == 0)
    return 0;

  FAT_SUPER->sectsize_bits = log2 (bpb.bytes_per_sect);
  FAT_SUPER->clustsize_bits
    = FAT_SUPER->sectsize_bits + log2 (bpb.sects_per_clust);

  /* Fill in info about super block */
  FAT_SUPER->num_sectors = bpb.short_sectors
    ? bpb.short_sectors : bpb.long_sectors;

  /* FAT offset and length */
  FAT_SUPER->fat_offset = bpb.reserved_sects;
  FAT_SUPER->fat_length =
    bpb.fat_length ? bpb.fat_length : bpb.fat32_length;

  /* Rootdir offset and length for FAT12/16 */
  FAT_SUPER->root_offset =
    FAT_SUPER->fat_offset + bpb.num_fats * FAT_SUPER->fat_length;
  FAT_SUPER->root_max = FAT_DIRENTRY_LENGTH * bpb.dir_entries;

  /* Data offset and number of clusters */
  FAT_SUPER->data_offset =
    FAT_SUPER->root_offset
    + ((FAT_SUPER->root_max - 1) >> FAT_SUPER->sectsize_bits) + 1;
  FAT_SUPER->num_clust =
    2 + ((FAT_SUPER->num_sectors - FAT_SUPER->data_offset)
	 / bpb.sects_per_clust);
  FAT_SUPER->sects_per_clust = bpb.sects_per_clust;

  if (!bpb.fat_length)
    {
      /* This is a FAT32 */
      if (bpb.dir_entries)
 	return 0;

      if (bpb.flags & 0x0080)
	{
	  /* FAT mirroring is disabled, get active FAT */
	  int active_fat = bpb.flags & 0x000f;
	  if (active_fat >= bpb.num_fats)
	    return 0;
	  FAT_SUPER->fat_offset += active_fat * FAT_SUPER->fat_length;
	}

      FAT_SUPER->fat_size = 8;
      FAT_SUPER->root_cluster = bpb.root_cluster;

      /* Yes the following is correct.  FAT32 should be called FAT28 :) */
      FAT_SUPER->clust_eof_marker = 0xffffff8;
    }
  else
    {
      if (!FAT_SUPER->root_max)
 	return 0;

      FAT_SUPER->root_cluster = -1;
      if (FAT_SUPER->num_clust > FAT_MAX_12BIT_CLUST)
	{
	  FAT_SUPER->fat_size = 4;
	  FAT_SUPER->clust_eof_marker = 0xfff8;
	}
      else
	{
	  FAT_SUPER->fat_size = 3;
	  FAT_SUPER->clust_eof_marker = 0xff8;
	}
    }


  /* Now do some sanity checks */

  if (bpb.bytes_per_sect != (1 << FAT_SUPER->sectsize_bits)
      || bpb.bytes_per_sect != SECTOR_SIZE
      || bpb.sects_per_clust != (1 << (FAT_SUPER->clustsize_bits
 				       - FAT_SUPER->sectsize_bits))
      || FAT_SUPER->num_clust <= 2
      || (FAT_SUPER->fat_size * FAT_SUPER->num_clust / (2 * SECTOR_SIZE)
 	  > FAT_SUPER->fat_length))
    return 0;

  /* kbs: Media check on first FAT entry [ported from PUPA] */

  if (!devread(FAT_SUPER->fat_offset, 0,
               sizeof(first_fat), (char *)&first_fat))
    return 0;

  if (FAT_SUPER->fat_size == 8)
    {
      first_fat &= 0x0fffffff;
      magic = 0x0fffff00;
    }
  else if (FAT_SUPER->fat_size == 4)
    {
      first_fat &= 0x0000ffff;
      magic = 0xff00;
    }
  else
    {
      first_fat &= 0x00000fff;
      magic = 0x0f00;
    }

  if (first_fat != (magic | bpb.media))
    return 0;

  FAT_SUPER->cached_fat = - 2 * FAT_CACHE_SIZE;
  return 1;
}

int
fat_read (char *buf, int len)
{
  int logical_clust;
  int offset;
  int ret = 0;
  int size;

  if (FAT_SUPER->file_cluster < 0)
    {
      /* root directory for fat16 */
      size = FAT_SUPER->root_max - filepos;
      if (size > len)
 	size = len;
      if (!devread(FAT_SUPER->root_offset, filepos, size, buf))
 	return 0;
      filepos += size;
      return size;
    }

  logical_clust = filepos >> FAT_SUPER->clustsize_bits;
  offset = (filepos & ((1 << FAT_SUPER->clustsize_bits) - 1));
  if (logical_clust < FAT_SUPER->current_cluster_num)
    {
      FAT_SUPER->current_cluster_num = 0;
      FAT_SUPER->current_cluster = FAT_SUPER->file_cluster;
    }

  while (len > 0)
    {
      int sector;
      while (logical_clust > FAT_SUPER->current_cluster_num)
	{
	  /* calculate next cluster */
	  int fat_entry =
	    FAT_SUPER->current_cluster * FAT_SUPER->fat_size;
	  int next_cluster;
	  int cached_pos = (fat_entry - FAT_SUPER->cached_fat);

	  if (cached_pos < 0 ||
	      (cached_pos + FAT_SUPER->fat_size) > 2*FAT_CACHE_SIZE)
	    {
	      FAT_SUPER->cached_fat = (fat_entry & ~(2*SECTOR_SIZE - 1));
	      cached_pos = (fat_entry - FAT_SUPER->cached_fat);
	      sector = FAT_SUPER->fat_offset
		+ FAT_SUPER->cached_fat / (2*SECTOR_SIZE);
	      if (!devread (sector, 0, FAT_CACHE_SIZE, (char*) FAT_BUF))
		return 0;
	    }
	  next_cluster = * (unsigned long *) (FAT_BUF + (cached_pos >> 1));
	  if (FAT_SUPER->fat_size == 3)
	    {
	      if (cached_pos & 1)
		next_cluster >>= 4;
	      next_cluster &= 0xFFF;
	    }
	  else if (FAT_SUPER->fat_size == 4)
	    next_cluster &= 0xFFFF;

	  if (next_cluster >= FAT_SUPER->clust_eof_marker)
	    return ret;
	  if (next_cluster < 2 || next_cluster >= FAT_SUPER->num_clust)
	    {
	      errnum = ERR_FSYS_CORRUPT;
	      return 0;
	    }

	  FAT_SUPER->current_cluster = next_cluster;
	  FAT_SUPER->current_cluster_num++;
	}

      sector = FAT_SUPER->data_offset +
	((FAT_SUPER->current_cluster - 2) << (FAT_SUPER->clustsize_bits
 					      - FAT_SUPER->sectsize_bits));
      size = (1 << FAT_SUPER->clustsize_bits) - offset;
      if (size > len)
	size = len;

      disk_read_func = disk_read_hook;

      devread(sector, offset, size, buf);

      disk_read_func = NULL;

      len -= size;
      buf += size;
      ret += size;
      filepos += size;
      logical_clust++;
      offset = 0;
    }
  return errnum ? 0 : ret;
}

int
fat_dir (char *dirname)
{
  char *rest, ch, dir_buf[FAT_DIRENTRY_LENGTH];
  char *filename = (char *) NAME_BUF;
  int attrib = FAT_ATTRIB_DIR;
#ifndef STAGE1_5
  int do_possibilities = 0;
#endif

  /* XXX I18N:
   * the positions 2,4,6 etc are high bytes of a 16 bit unicode char
   */
  static unsigned char longdir_pos[] =
  { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
  int slot = -2;
  int alias_checksum = -1;

  FAT_SUPER->file_cluster = FAT_SUPER->root_cluster;
  filepos = 0;
  FAT_SUPER->current_cluster_num = MAXINT;

  /* main loop to find desired directory entry */
 loop:

  /* if we have a real file (and we're not just printing possibilities),
     then this is where we want to exit */

  if (!*dirname || isspace (*dirname))
    {
      if (attrib & FAT_ATTRIB_DIR)
	{
	  errnum = ERR_BAD_FILETYPE;
	  return 0;
	}

      return 1;
    }

  /* continue with the file/directory name interpretation */

  while (*dirname == '/')
    dirname++;

  if (!(attrib & FAT_ATTRIB_DIR))
    {
      errnum = ERR_BAD_FILETYPE;
      return 0;
    }
  /* Directories don't have a file size */
  filemax = MAXINT;

  for (rest = dirname; (ch = *rest) && !isspace (ch) && ch != '/'; rest++);

  *rest = 0;

# ifndef STAGE1_5
  if (print_possibilities && ch != '/')
    do_possibilities = 1;
# endif

  while (1)
    {
      if (fat_read (dir_buf, FAT_DIRENTRY_LENGTH) != FAT_DIRENTRY_LENGTH
	  || dir_buf[0] == 0)
	{
	  if (!errnum)
	    {
# ifndef STAGE1_5
	      if (print_possibilities < 0)
		{
#if 0
		  putchar ('\n');
#endif
		  return 1;
		}
# endif /* STAGE1_5 */

	      errnum = ERR_FILE_NOT_FOUND;
	      *rest = ch;
	    }

	  return 0;
	}

      if (FAT_DIRENTRY_ATTRIB (dir_buf) == FAT_ATTRIB_LONGNAME)
	{
	  /* This is a long filename.  The filename is build from back
	   * to front and may span multiple entries.  To bind these
	   * entries together they all contain the same checksum over
	   * the short alias.
	   *
	   * The id field tells if this is the first entry (the last
	   * part) of the long filename, and also at which offset this
	   * belongs.
	   *
	   * We just write the part of the long filename this entry
	   * describes and continue with the next dir entry.
	   */
	  int i, offset;
	  unsigned char id = FAT_LONGDIR_ID(dir_buf);

	  if ((id & 0x40))
	    {
	      id &= 0x3f;
	      slot = id;
	      filename[slot * 13] = 0;
	      alias_checksum = FAT_LONGDIR_ALIASCHECKSUM(dir_buf);
	    }

	  if (id != slot || slot == 0
	      || alias_checksum != FAT_LONGDIR_ALIASCHECKSUM(dir_buf))
	    {
	      alias_checksum = -1;
	      continue;
	    }

	  slot--;
	  offset = slot * 13;

	  for (i=0; i < 13; i++)
	    filename[offset+i] = dir_buf[longdir_pos[i]];
	  continue;
	}

      if (!FAT_DIRENTRY_VALID (dir_buf))
	continue;

      if (alias_checksum != -1 && slot == 0)
	{
	  int i;
	  unsigned char sum;

	  slot = -2;
	  for (sum = 0, i = 0; i< 11; i++)
	    sum = ((sum >> 1) | (sum << 7)) + dir_buf[i];

	  if (sum == alias_checksum)
	    {
# ifndef STAGE1_5
	      if (do_possibilities)
		goto print_filename;
# endif /* STAGE1_5 */

	      if (substring (dirname, filename) == 0)
		break;
	    }
	}

      /* XXX convert to 8.3 filename format here */
      {
	int i, j, c;

	for (i = 0; i < 8 && (c = filename[i] = tolower (dir_buf[i]))
	       && !isspace (c); i++);

	filename[i++] = '.';

	for (j = 0; j < 3 && (c = filename[i + j] = tolower (dir_buf[8 + j]))
	       && !isspace (c); j++);

	if (j == 0)
	  i--;

	filename[i + j] = 0;
      }

# ifndef STAGE1_5
      if (do_possibilities)
	{
	print_filename:
	  if (substring (dirname, filename) <= 0)
	    {
	      if (print_possibilities > 0)
		print_possibilities = -print_possibilities;
	      print_a_completion (filename);
	    }
	  continue;
	}
# endif /* STAGE1_5 */

      if (substring (dirname, filename) == 0)
	break;
    }

  *(dirname = rest) = ch;

  attrib = FAT_DIRENTRY_ATTRIB (dir_buf);
  filemax = FAT_DIRENTRY_FILELENGTH (dir_buf);
  filepos = 0;
  FAT_SUPER->file_cluster = FAT_DIRENTRY_FIRST_CLUSTER (dir_buf);
  FAT_SUPER->current_cluster_num = MAXINT;

  /* go back to main loop at top of function */
  goto loop;
}

#endif /* FSYS_FAT */
