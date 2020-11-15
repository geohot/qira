/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 * Copyright (C) 1996-1998 Robert Leslie
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
 * $Id: hfs.h,v 1.11 1998/11/02 22:09:01 rob Exp $
 */

# define HFS_BLOCKSZ		512
# define HFS_BLOCKSZ_BITS	9

# define HFS_MAX_FLEN		31
# define HFS_MAX_VLEN		27

typedef struct _hfsvol_  hfsvol;
typedef struct _hfsfile_ hfsfile;
typedef struct _hfsdir_  hfsdir;

typedef struct {
  char name[HFS_MAX_VLEN + 1];	/* name of volume (MacOS Standard Roman) */
  int flags;			/* volume flags */

  unsigned long totbytes;	/* total bytes on volume */
  unsigned long freebytes;	/* free bytes on volume */

  unsigned long alblocksz;	/* volume allocation block size */
  unsigned long clumpsz;	/* default file clump size */

  unsigned long numfiles;	/* number of files in volume */
  unsigned long numdirs;	/* number of directories in volume */

  time_t crdate;		/* volume creation date */
  time_t mddate;		/* last volume modification date */
  time_t bkdate;		/* last volume backup date */

  unsigned long blessed;	/* CNID of MacOS System Folder */
} hfsvolent;

typedef struct {
  char name[HFS_MAX_FLEN + 1];	/* catalog name (MacOS Standard Roman) */
  int flags;			/* bit flags */
  unsigned long cnid;		/* catalog node id (CNID) */
  unsigned long parid;		/* CNID of parent directory */

  time_t crdate;		/* date of creation */
  time_t mddate;		/* date of last modification */
  time_t bkdate;		/* date of last backup */

  short fdflags;		/* Macintosh Finder flags */

  struct {
    signed short v;		/* Finder icon vertical coordinate */
    signed short h;		/* horizontal coordinate */
  } fdlocation;

  union {
    struct {
      unsigned long dsize;	/* size of data fork */
      unsigned long rsize;	/* size of resource fork */

      char type[5];		/* file type code (plus null) */
      char creator[5];		/* file creator code (plus null) */
    } file;

    struct {
      unsigned short valence;	/* number of items in directory */

      struct {
	signed short top;	/* top edge of folder's rectangle */
	signed short left;	/* left edge */
	signed short bottom;	/* bottom edge */
	signed short right;	/* right edge */
      } rect;
    } dir;
  } u;
} hfsdirent;

# define HFS_ISDIR		0x0001
# define HFS_ISLOCKED		0x0002

# define HFS_CNID_ROOTPAR	1
# define HFS_CNID_ROOTDIR	2
# define HFS_CNID_EXT		3
# define HFS_CNID_CAT		4
# define HFS_CNID_BADALLOC	5

# define HFS_FNDR_ISONDESK		(1 <<  0)
# define HFS_FNDR_COLOR			0x0e
# define HFS_FNDR_COLORRESERVED		(1 <<  4)
# define HFS_FNDR_REQUIRESSWITCHLAUNCH	(1 <<  5)
# define HFS_FNDR_ISSHARED		(1 <<  6)
# define HFS_FNDR_HASNOINITS		(1 <<  7)
# define HFS_FNDR_HASBEENINITED		(1 <<  8)
# define HFS_FNDR_RESERVED		(1 <<  9)
# define HFS_FNDR_HASCUSTOMICON		(1 << 10)
# define HFS_FNDR_ISSTATIONERY		(1 << 11)
# define HFS_FNDR_NAMELOCKED		(1 << 12)
# define HFS_FNDR_HASBUNDLE		(1 << 13)
# define HFS_FNDR_ISINVISIBLE		(1 << 14)
# define HFS_FNDR_ISALIAS		(1 << 15)

extern const char *hfs_error;
extern const unsigned char hfs_charorder[];

# define HFS_MODE_RDONLY	0
# define HFS_MODE_RDWR		1
# define HFS_MODE_ANY		2

# define HFS_MODE_MASK		0x0003

# define HFS_OPT_NOCACHE	0x0100
# define HFS_OPT_2048		0x0200
# define HFS_OPT_ZERO		0x0400

# define HFS_SEEK_SET		0
# define HFS_SEEK_CUR		1
# define HFS_SEEK_END		2

hfsvol *hfs_mount( int os_fd, int);
int hfs_flush(hfsvol *);
void hfs_flushall(void);
int hfs_umount(hfsvol *);
void hfs_umountall(void);
hfsvol *hfs_getvol(const char *);
void hfs_setvol(hfsvol *);

int hfs_vstat(hfsvol *, hfsvolent *);
int hfs_vsetattr(hfsvol *, hfsvolent *);

int hfs_chdir(hfsvol *, const char *);
unsigned long hfs_getcwd(hfsvol *);
int hfs_setcwd(hfsvol *, unsigned long);
int hfs_dirinfo(hfsvol *, unsigned long *, char *);

hfsdir *hfs_opendir(hfsvol *, const char *);
int hfs_readdir(hfsdir *, hfsdirent *);
int hfs_closedir(hfsdir *);

hfsfile *hfs_create(hfsvol *, const char *, const char *, const char *);
hfsfile *hfs_open(hfsvol *, const char *);
int hfs_setfork(hfsfile *, int);
int hfs_getfork(hfsfile *);
unsigned long hfs_read(hfsfile *, void *, unsigned long);
unsigned long hfs_write(hfsfile *, const void *, unsigned long);
int hfs_truncate(hfsfile *, unsigned long);
unsigned long hfs_seek(hfsfile *, long, int);
int hfs_close(hfsfile *);

int hfs_stat(hfsvol *, const char *, hfsdirent *);
int hfs_fstat(hfsfile *, hfsdirent *);
int hfs_setattr(hfsvol *, const char *, const hfsdirent *);
int hfs_fsetattr(hfsfile *, const hfsdirent *);

int hfs_mkdir(hfsvol *, const char *);
int hfs_rmdir(hfsvol *, const char *);

int hfs_delete(hfsvol *, const char *);
int hfs_rename(hfsvol *, const char *, const char *);

int hfs_zero(const char *, unsigned int, unsigned long *);
int hfs_mkpart(const char *, unsigned long);
int hfs_nparts(const char *);

int hfs_format(const char *, int, int,
	       const char *, unsigned int, const unsigned long []);
int hfs_probe(int fd, long long offset);
