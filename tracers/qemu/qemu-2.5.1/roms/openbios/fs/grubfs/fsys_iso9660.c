/*
 *  ISO 9660 filesystem backend for GRUB (GRand Unified Bootloader)
 *  including Rock Ridge Extensions support
 *
 *  Copyright (C) 1998, 1999  Kousuke Takai  <tak@kmc.kyoto-u.ac.jp>
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
 *  References:
 *	linux/fs/isofs/rock.[ch]
 *	mkisofs-1.11.1/diag/isoinfo.c
 *	mkisofs-1.11.1/iso9660.h
 *		(all are written by Eric Youngdale)
 *
 *  Modifications by:
 *	Leonid Lisovskiy   <lly@pisem.net>	2003
 */

/*
 * Modified to make it work with FILO
 * 2003-10 by SONE Takeshi
 */

#ifdef FSYS_ISO9660

#include "shared.h"
#include "filesys.h"
#include "iso9660.h"
#include "debug.h"

#if defined(__sparc__) || defined(__PPC__)
#define ENDIAN b
#else
#define ENDIAN l
#endif

struct iso_superblock {
    unsigned long vol_sector;

    unsigned long file_start;
};

#define ISO_SUPER	((struct iso_superblock *)(FSYS_BUF))
#define PRIMDESC        ((struct iso_primary_descriptor *)(FSYS_BUF + 2048))
#define DIRREC          ((struct iso_directory_record *)(FSYS_BUF + 4096))
#define RRCONT_BUF      ((unsigned char *)(FSYS_BUF + 6144))
#define NAME_BUF        ((unsigned char *)(FSYS_BUF + 8192))

static int
iso9660_devread (int sector, int byte_offset, int byte_len, char *buf)
{
  /* FILO uses 512-byte "soft" sector, and ISO-9660 uses 2048-byte
   * CD-ROM sector */
  return devread(sector<<2, byte_offset, byte_len, buf);
}

int
iso9660_mount (void)
{
  unsigned int sector;

  /*
   *  Because there is no defined slice type ID for ISO-9660 filesystem,
   *  this test will pass only either (1) if entire disk is used, or
   *  (2) if current partition is BSD style sub-partition whose ID is
   *  ISO-9660.
   */
  /*if ((current_partition != 0xFFFFFF)
      && !IS_PC_SLICE_TYPE_BSD_WITH_FS(current_slice, FS_ISO9660))
    return 0;*/

  /*
   *  Currently, only FIRST session of MultiSession disks are supported !!!
   */
  for (sector = 16 ; sector < 32 ; sector++)
    {
      if (!iso9660_devread(sector, 0, sizeof(*PRIMDESC), (char *)PRIMDESC))
	break;
      /* check ISO_VD_PRIMARY and ISO_STANDARD_ID */
      if (CHECK4(&PRIMDESC->type, ISO_VD_PRIMARY, 'C', 'D', '0')
	  && CHECK2(PRIMDESC->id + 3, '0', '1'))
	{
	  ISO_SUPER->vol_sector = sector;
	  ISO_SUPER->file_start = 0;
          fsmax = PRIMDESC->volume_space_size.ENDIAN;
	  return 1;
	}
    }

  return 0;
}

int
iso9660_dir (char *dirname)
{
  struct iso_directory_record *idr;
  RR_ptr_t rr_ptr;
  struct rock_ridge *ce_ptr;
  unsigned int pathlen;
  int size;
  unsigned int extent;
  unsigned int rr_len;
  unsigned char file_type;
  unsigned char rr_flag;

  idr = &PRIMDESC->root_directory_record;
  ISO_SUPER->file_start = 0;

  do
  {
      while (*dirname == '/')	/* skip leading slashes */
	  dirname++;
      /* pathlen = strcspn(dirname, "/\n\t "); */
      for (pathlen = 0 ;
	  dirname[pathlen]
	     && !isspace(dirname[pathlen]) && dirname[pathlen] != '/' ;
	  pathlen++)
	;

      size = idr->size.ENDIAN;
      extent = idr->extent.ENDIAN;

      while (size > 0)
      {
	  if (!iso9660_devread(extent, 0, ISO_SECTOR_SIZE, (char *)DIRREC))
	  {
	      errnum = ERR_FSYS_CORRUPT;
	      return 0;
	  }
	  extent++;

	  idr = (struct iso_directory_record *)DIRREC;
	  for (; idr->length.ENDIAN > 0;
                 idr = (struct iso_directory_record *)((char *)idr + idr->length.ENDIAN) )
	  {
              const char *name = (char *)idr->name;
              unsigned int name_len = idr->name_len.ENDIAN;

              file_type = (idr->flags.ENDIAN & 2) ? ISO_DIRECTORY : ISO_REGULAR;
	      if (name_len == 1)
	      {
		  if ((name[0] == 0) ||	/* self */
		      (name[0] == 1)) 	/* parent */
		    continue;
	      }
	      if (name_len > 2 && CHECK2(name + name_len - 2, ';', '1'))
	      {
		  name_len -= 2;	/* truncate trailing file version */
		  if (name_len > 1 && name[name_len - 1] == '.')
		    name_len--;		/* truncate trailing dot */
	      }

	      /*
	       *  Parse Rock-Ridge extension
	       */
              rr_len = (idr->length.ENDIAN - idr->name_len.ENDIAN
			- (unsigned char)sizeof(struct iso_directory_record)
			+ (unsigned char)sizeof(idr->name));
              rr_ptr.ptr = ((char *)idr + idr->name_len.ENDIAN
			    + sizeof(struct iso_directory_record)
			    - sizeof(idr->name));
	      if (rr_len & 1)
		rr_ptr.ptr++, rr_len--;
	      ce_ptr = NULL;
	      rr_flag = RR_FLAG_NM | RR_FLAG_PX;

	      while (rr_len >= 4)
	      {
		  if (rr_ptr.rr->version != 1)
		  {
#ifndef STAGE1_5
		    if (debug)
		      printf(
			    "Non-supported version (%d) RockRidge chunk "
			    "`%c%c'\n", rr_ptr.rr->version,
			    rr_ptr.rr->signature & 0xFF,
			    rr_ptr.rr->signature >> 8);
#endif
		  }
                  else if (CHECK2(&rr_ptr.rr->signature, 'R', 'R')
			   && rr_ptr.rr->len >= 5)
                      rr_flag &= rr_ptr.rr->u.rr.flags.ENDIAN;
                  else if (CHECK2(&rr_ptr.rr->signature, 'N', 'M'))
		  {
		      name = (char *)rr_ptr.rr->u.nm.name;
		      name_len = rr_ptr.rr->len - 5;
		      rr_flag &= ~RR_FLAG_NM;
		  }
                  else if (CHECK2(&rr_ptr.rr->signature, 'P', 'X')
			   && rr_ptr.rr->len >= 36)
		  {
                      file_type = ((rr_ptr.rr->u.px.mode.ENDIAN & POSIX_S_IFMT)
				   == POSIX_S_IFREG
				   ? ISO_REGULAR
                                   : ((rr_ptr.rr->u.px.mode.ENDIAN & POSIX_S_IFMT)
				      == POSIX_S_IFDIR
				      ? ISO_DIRECTORY : ISO_OTHER));
		      rr_flag &= ~RR_FLAG_PX;
		  }
                  else if (CHECK2(&rr_ptr.rr->signature, 'C', 'E')
			   && rr_ptr.rr->len >= 28)
		    ce_ptr = rr_ptr.rr;
		  if (!rr_flag)
		    /*
		     * There is no more extension we expects...
		     */
		    break;
		  rr_len -= rr_ptr.rr->len;
		  rr_ptr.ptr += rr_ptr.rr->len;
		  if (rr_len < 4 && ce_ptr != NULL)
		  {
		      /* preserve name before loading new extent. */
		      if( RRCONT_BUF <= (unsigned char *)name
			  && (unsigned char *)name < RRCONT_BUF + ISO_SECTOR_SIZE )
		      {
			  memcpy(NAME_BUF, name, name_len);
			  name = (char *)NAME_BUF;
		      }
                      rr_ptr.ptr = (char *)(RRCONT_BUF + ce_ptr->u.ce.offset.ENDIAN);
                      rr_len = ce_ptr->u.ce.size.ENDIAN;
                      if (!iso9660_devread(ce_ptr->u.ce.extent.ENDIAN, 0,
                                           ISO_SECTOR_SIZE, (char *)RRCONT_BUF))
		      {
			  errnum = 0;	/* this is not fatal. */
			  break;
		      }
		      ce_ptr = NULL;
		   }
	      } /* rr_len >= 4 */

	      filemax = MAXINT;
	      if (name_len >= pathlen
                  && !strnicmp(name, dirname, pathlen))
	      {
                if (dirname[pathlen] == '/' || !print_possibilities)
		{
		  /*
		   *  DIRNAME is directory component of pathname,
		   *  or we are to open a file.
		   */
		  if (pathlen == name_len)
		  {
		      if (dirname[pathlen] == '/')
		      {
		          if (file_type != ISO_DIRECTORY)
		          {
			      errnum = ERR_BAD_FILETYPE;
			      return 0;
			  }
                          goto next_dir_level;
		      }
		      if (file_type != ISO_REGULAR)
		      {
		          errnum = ERR_BAD_FILETYPE;
		          return 0;
		      }
                      ISO_SUPER->file_start = idr->extent.ENDIAN;
		      filepos = 0;
                      filemax = idr->size.ENDIAN;
		      return 1;
		  }
		}
	        else	/* Completion */
	        {
#ifndef STAGE1_5
 		  if (print_possibilities > 0)
		      print_possibilities = -print_possibilities;
		  memcpy(NAME_BUF, name, name_len);
		  NAME_BUF[name_len] = '\0';
            	  print_a_completion (NAME_BUF);
#endif
	        }
	      }
	  } /* for */

	  size -= ISO_SECTOR_SIZE;
      } /* size>0 */

      if (dirname[pathlen] == '/' || print_possibilities >= 0)
      {
	  errnum = ERR_FILE_NOT_FOUND;
	  return 0;
      }

next_dir_level:
      dirname += pathlen;

  } while (*dirname == '/');

  return 1;
}

int
iso9660_read (char *buf, int len)
{
  int sector, blkoffset, size, ret;

  if (ISO_SUPER->file_start == 0)
    return 0;

  ret = 0;
  blkoffset = filepos & (ISO_SECTOR_SIZE - 1);
  sector = filepos >> ISO_SECTOR_BITS;
  while (len > 0)
  {
    size = ISO_SECTOR_SIZE - blkoffset;
    if (size > len)
        size = len;

    disk_read_func = disk_read_hook;

    if (!iso9660_devread(ISO_SUPER->file_start + sector, blkoffset, size, buf))
	return 0;

    disk_read_func = NULL;

    len -= size;
    buf += size;
    ret += size;
    filepos += size;
    sector++;
    blkoffset = 0;
  }

  return ret;
}

#endif /* FSYS_ISO9660 */
