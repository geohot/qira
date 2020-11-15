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
 * $Id: libhfs.h,v 1.7 1998/11/02 22:09:02 rob Exp $
 */

# include "hfs.h"
# include "apple.h"

# define ERROR(code, str)  \
    do { hfs_error = (str), errno = (code); goto fail; } while (0)

# ifdef DEBUG
#  define ASSERT(cond)	do { if (! (cond)) abort(); } while (0)
# else
#  define ASSERT(cond)	/* nothing */
# endif

# define SIZE(type, n)		((size_t) (sizeof(type) * (n)))
# define ALLOC(type, n)		((type *) malloc(SIZE(type, n)))
# define ALLOCX(type, n)	((n) ? ALLOC(type, n) : (type *) 0)
# define FREE(ptr)		((ptr) ? (void) free((void *) ptr) : (void) 0)

# define REALLOC(ptr, type, n)  \
    ((type *) ((ptr) ? realloc(ptr, SIZE(type, n)) : malloc(SIZE(type, n))))
# define REALLOCX(ptr, type, n)  \
    ((n) ? REALLOC(ptr, type, n) : (FREE(ptr), (type *) 0))

# define BMTST(bm, num)  \
    (((const byte *) (bm))[(num) >> 3]  &  (0x80 >> ((num) & 0x07)))
# define BMSET(bm, num)  \
          (((byte *) (bm))[(num) >> 3] |=  (0x80 >> ((num) & 0x07)))
# define BMCLR(bm, num)  \
          (((byte *) (bm))[(num) >> 3] &= ~(0x80 >> ((num) & 0x07)))

# define STRINGIZE(x)		#x
# define STR(x)			STRINGIZE(x)

typedef unsigned char byte;
typedef byte block[HFS_BLOCKSZ];

typedef struct _bucket_ {
  int flags;			/* bit flags */
  unsigned int count;		/* number of times this block is requested */

  unsigned long bnum;		/* logical block number */
  block *data;			/* pointer to block contents */

  struct _bucket_ *cnext;	/* next bucket in cache chain */
  struct _bucket_ *cprev;	/* previous bucket in cache chain */

  struct _bucket_ *hnext;	/* next bucket in hash chain */
  struct _bucket_ **hprev;	/* previous bucket's pointer to this bucket */
} bucket;

# define HFS_BUCKET_INUSE	0x01
# define HFS_BUCKET_DIRTY	0x02

# define HFS_CACHESZ		128
# define HFS_HASHSZ		32
# define HFS_BLOCKBUFSZ		16

typedef struct {
  struct _hfsvol_ *vol;		/* volume to which cache belongs */
  bucket *tail;			/* end of bucket chain */

  unsigned int hits;		/* number of cache hits */
  unsigned int misses;		/* number of cache misses */

  bucket chain[HFS_CACHESZ];	/* cache bucket chain */
  bucket *hash[HFS_HASHSZ];	/* hash table for bucket chain */

  block pool[HFS_CACHESZ];	/* physical blocks in cache */
} bcache;

# define HFS_MAP1SZ  256
# define HFS_MAPXSZ  492

# define HFS_NODEREC(nd, rnum)	((nd).data + (nd).roff[rnum])
# define HFS_RECLEN(nd, rnum)	((nd).roff[(rnum) + 1] - (nd).roff[rnum])

# define HFS_RECKEYLEN(ptr)	(*(const byte *) (ptr))
# define HFS_RECKEYSKIP(ptr)	((size_t) ((1 + HFS_RECKEYLEN(ptr) + 1) & ~1))
# define HFS_RECDATA(ptr)	((ptr) + HFS_RECKEYSKIP(ptr))

# define HFS_SETKEYLEN(ptr, x)	(*(byte *) (ptr) = (x))

# define HFS_CATDATALEN		sizeof(CatDataRec)
# define HFS_EXTDATALEN		sizeof(ExtDataRec)
# define HFS_MAX_DATALEN	(HFS_CATDATALEN > HFS_EXTDATALEN ?  \
				 HFS_CATDATALEN : HFS_EXTDATALEN)

# define HFS_CATKEYLEN		sizeof(CatKeyRec)
# define HFS_EXTKEYLEN		sizeof(ExtKeyRec)
# define HFS_MAX_KEYLEN		(HFS_CATKEYLEN > HFS_EXTKEYLEN ?  \
				 HFS_CATKEYLEN : HFS_EXTKEYLEN)

# define HFS_MAX_CATRECLEN	(HFS_CATKEYLEN + HFS_CATDATALEN)
# define HFS_MAX_EXTRECLEN	(HFS_EXTKEYLEN + HFS_EXTDATALEN)
# define HFS_MAX_RECLEN		(HFS_MAX_KEYLEN + HFS_MAX_DATALEN)

# define HFS_SIGWORD		0x4244
# define HFS_SIGWORD_MFS	((Integer) 0xd2d7)

# define HFS_ATRB_BUSY		(1 <<  6)
# define HFS_ATRB_HLOCKED	(1 <<  7)
# define HFS_ATRB_UMOUNTED	(1 <<  8)
# define HFS_ATRB_BBSPARED	(1 <<  9)
# define HFS_ATRB_BVINCONSIS	(1 << 11)
# define HFS_ATRB_COPYPROT	(1 << 14)
# define HFS_ATRB_SLOCKED	(1 << 15)

struct _hfsfile_ {
  struct _hfsvol_ *vol;		/* pointer to volume descriptor */
  unsigned long parid;		/* parent directory ID of this file */
  char name[HFS_MAX_FLEN + 1];	/* catalog name of this file */
  CatDataRec cat;		/* catalog information */
  ExtDataRec ext;		/* current extent record */
  unsigned int fabn;		/* starting file allocation block number */
  int fork;			/* current selected fork for I/O */
  unsigned long pos;		/* current file seek pointer */
  int flags;			/* bit flags */

  struct _hfsfile_ *prev;
  struct _hfsfile_ *next;
};

# define HFS_FILE_UPDATE_CATREC	0x01

# define HFS_MAX_NRECS	35	/* maximum based on minimum record size */

typedef struct _node_ {
  struct _btree_ *bt;		/* btree to which this node belongs */
  unsigned long nnum;		/* node index */
  NodeDescriptor nd;		/* node descriptor */
  int rnum;			/* current record index */
  UInteger roff[HFS_MAX_NRECS + 1];
				/* record offsets */
  block data;			/* raw contents of node */
} node;

struct _hfsdir_ {
  struct _hfsvol_ *vol;		/* associated volume */
  unsigned long dirid;		/* directory ID of interest (or 0) */

  node n;			/* current B*-tree node */
  struct _hfsvol_ *vptr;	/* current volume pointer */

  struct _hfsdir_ *prev;
  struct _hfsdir_ *next;
};

typedef void (*keyunpackfunc)(const byte *, void *);
typedef int (*keycomparefunc)(const void *, const void *);

typedef struct _btree_ {
  hfsfile f;			/* subset file information */
  node hdrnd;			/* header node */
  BTHdrRec hdr;			/* header record */
  byte *map;			/* usage bitmap */
  unsigned long mapsz;		/* number of bytes in bitmap */
  int flags;			/* bit flags */

  keyunpackfunc keyunpack;	/* key unpacking function */
  keycomparefunc keycompare;	/* key comparison function */
} btree;

# define HFS_BT_UPDATE_HDR	0x01

struct _hfsvol_ {
  int os_fd;		/* OS-dependent private descriptor data */
  int flags;		/* bit flags */

  int pnum;		/* ordinal HFS partition number */
  unsigned long vstart;	/* logical block offset to start of volume */
  unsigned long vlen;	/* number of logical blocks in volume */
  unsigned int lpa;	/* number of logical blocks per allocation block */

  bcache *cache;	/* cache of recently used blocks */

  MDB mdb;		/* master directory block */
  block *vbm;		/* volume bitmap */
  unsigned short vbmsz;	/* number of blocks in bitmap */

  btree ext;		/* B*-tree control block for extents overflow file */
  btree cat;		/* B*-tree control block for catalog file */

  unsigned long cwd;	/* directory id of current working directory */

  int refs;		/* number of external references to this volume */
  hfsfile *files;	/* list of open files */
  hfsdir *dirs;		/* list of open directories */

  struct _hfsvol_ *prev;
  struct _hfsvol_ *next;
};

# define HFS_VOL_OPEN		0x0001
# define HFS_VOL_MOUNTED	0x0002
# define HFS_VOL_READONLY	0x0004
# define HFS_VOL_USINGCACHE	0x0008

# define HFS_VOL_UPDATE_MDB	0x0010
# define HFS_VOL_UPDATE_ALTMDB	0x0020
# define HFS_VOL_UPDATE_VBM	0x0040

# define HFS_VOL_OPT_MASK	0xff00

extern hfsvol *hfs_mounts;
