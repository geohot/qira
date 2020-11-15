/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 * Copyright (C) 2000 Klaus Halfmann (khalfmann@libra.de)
 * Original work by 1996-1998 Robert Leslie (rob@mars.org)
 *
 * This file defines constants,structs etc needed for this library.
 * Everything found here is usually not related to Apple defintions.
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
 * $Id: libhfsp.h,v 1.17 2000/10/20 06:16:52 hasi Exp $
 */

# include "apple.h"
# include "hfs.h"
# include "hfsp.h"

/* Last error is eventually found here */
extern const char *hfsp_error;

# define HFSP_ERROR(code, str)  \
    do { hfsp_error = (str), errno = (code); goto fail; } while (0)

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

/* used by internal routines to specify the open modes */
# define HFSP_MODE_RDONLY        0
# define HFSP_MODE_RDWR          1
# define HFSP_MODE_ANY           2

/* Signatures registered with Apple to identify this driver */
    /* Identifies the userland implementation */
# define HPLS_SIGNATURE 0x482B4C58	// 'H+LX'
    /* Identifies the kernel module by Brad Boyer (flar@pants.nu) */
# define HPLS_SIGRES1	0x482B4C78	// 'H+Lx'
    /* not jet in use ... */
# define HPLS_SIGRES2	0x482B6C78	// 'H+lx'
    /* Signature used by Apple */
# define HPAPPLE_SIGNATURE  0x382e3130	// '8.10'

/* Version used for this implementation of HFS+. This is not related
 * to the VERSION file found at the top-level of this package,
 * but designates the version of the low level code */
#define HPLS_VERSION	1   /* must fit in a short */


/* Othe Signatures may follow for informational purpos */

/* prototype for key comparing functions. */
typedef int (*hfsp_key_compare) (void* key1, void* key2);

/* prototype for key reading (necessary for byte swapping) */
typedef void* (*hfsp_key_read) (void* p, void* key);

struct volume; /* foreward declaration for btree needed */

/* Structures for a node cache. The cache is an array
 * with linear search. (So making it to big may make
 * things slower). It is searched in a round robin
 * fashion.
 */

typedef struct
{
    UInt32		priority;
	// as lower this number as higher the priority.
	// decremetned on any sucessfull usage
	// incremented else, intial value height*DEPTHFACTOR
    UInt16		index;	// of node in fork
	// 0 means empty, since first node is node header
	// contents of node in original byte order
    UInt16		flags;	// like DIRTY etc.
} node_entry;

typedef struct
{
    UInt32		index;	    // duplicate of above
    btree_node_desc	desc;	    // header of node
    char		node[0];    // actual node_size
	// contents of node in original byte order
} node_buf;

typedef struct
{
    int		size;	     // number of nodes in the cache
    int		currindex;   // round robin index
    int		nodebufsize; // size of complete node_buf, including node
    node_entry	*entries;
    char	*buffers;   // actually *node_buf
} node_cache;

typedef struct
{
    struct volume*	vol;	/* pointer to volume this tree is part of */
    hfsp_fork_raw*	fork;	/* pointer to fork this tree is part of */
    UInt32		cnid;	/* (pseudo) file id for the fork */
    hfsp_key_compare	kcomp;
	/* function used for key compare in _this_ btree */
    hfsp_key_read	kread;
	/* fucntion used to read a key int _this_ btree */
    btree_head		head;

    UInt16		blkpernode;
	 /* Number of volume blocks per node (usually 1-4) */
    node_cache		cache;
    /* Warning all functions of btrees and records may modify
       the following values ! */
    // UInt16		node_index; /* index of node in fork */
    // btree_node_desc	node;	/* current node under examination */
    // char*		buf;	/* buf with size of a node */
} btree;

/* Function on btrees are defined in btree.h */

/* A Wrapper around the raw hfs+ volume header for additional information
 * needed by this library.
 */

typedef struct volume
{
    int		os_fd;		/* OS dependend reference to device */
    UInt16	blksize_bits;   /* blocksize of device = 1 << blksize_bits */
    UInt16	filler;
    UInt32	blksize;	/* always 1 << blksize_bits */
    UInt32	startblock;
	/* Offset from physical to logical blocks,
	   eventually intodruced by HFS wrapper */
    UInt32  	maxblocks;	/* maximum number of blocks in device */
    // UInt32	currblock;	/* value of current block, to cache blocks */
    hfsp_vh	vol;		/* raw volume data */
    // void*	blockbuf;	/* (single) buffer for fetching one block */
     /* Buffer has double size of blksize to allow cross block reading */

    btree*	extents;	/* is NULL by default and intialized when needed */
    btree	catalog;	/* This is always neeeded */
} volume;

/* Functions on volumes are defined in volume.h */

typedef struct {    // may not be used as found here
    btree*		tree;	// tree where this record is contained in.
    UInt16		node_index; /* index of record in btree */
    UInt16		keyind;	/* index of current key in btree */
    hfsp_cat_key	key;	/* current key */
    UInt32		child;	/* child node belonging to this key */
} index_record;

typedef struct {
    btree*		tree;	// tree where this record is contained in.
    UInt16		node_index; /* index of record in btree */
    UInt16		keyind;	/* index of current key in btree */
    hfsp_extent_key	key;	/* current key */
    hfsp_extent_rec	extent; /* The payload carried around */
} extent_record;

typedef struct {
    btree*		tree;	// tree where this record is contained in.
    UInt16		node_index; /* index of record in btree */
    UInt16		keyind;	/* index of current key in btree */
    hfsp_cat_key	key;	/* current key */
    hfsp_cat_entry	record;	/* current record */
} record;

/* Functions on records are defined in record.h */
