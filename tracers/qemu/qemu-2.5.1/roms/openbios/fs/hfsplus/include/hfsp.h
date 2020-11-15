/*
 * libhfsp - library for reading and writing Macintosh HFS+ volumes
 *
 * This file includes definitions for the structures found on
 * HFS+ Volumes. The structures are further wrapped by struct
 * found in libhfsp.h. fucntions on those enhanced structures
 * are found in files mentioned in comments below.
 *
 * Copyright (C) 2000 Klaus Halfmann <khalfmann@libra.de>
 * Original code 1996-1998 by Robert Leslie <rob@mars.rog>
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
 * $Id: hfsp.h,v 1.17 2000/10/20 06:16:52 hasi Exp $
 */

#define HFSP_BLOCKSZ            512	/* A sector for Apple is always 512 bytes */
#define HFSP_BLOCKSZ_BITS       9	/* 1<<9 == 512  */
#define	HFSP_VOLHEAD_SIG	0x482B	/* 'H+'	*/

/* HFS+ includes POSIX permissions , although marked as reserved they will be
 * used as such. Is ignored by MacOS 8-9 but probably not by MacOS X.
 */
typedef struct {
        UInt32         owner;
        UInt32         group;
        UInt32         mode;
        UInt32         dev;
} hfsp_perm;

/* A single contiguous area (fragment) of a file */
typedef struct {
        UInt32         start_block;
        UInt32         block_count;
} hfsp_extent;

/* A file may contain up to 8 normale extents, all other
   are found in some extra extent area */
typedef hfsp_extent hfsp_extent_rec[8];

/* Information for a "Fork" in a file
 * Forks are the "usual" DATA and RSRC forks or special files
 * (e.g. the Volume Bitmap)
 */
typedef struct {
        UInt64		total_size;  // logical size
        UInt32		clump_size;  // number of bytes to preallocate
        UInt32		total_blocks;
        hfsp_extent_rec extents;     // initial (8) extents
} hfsp_fork_raw;

/* HFS+ Volume Header
 * Always found at block 2 of the disk, a copy is stored
 * at the second to last block of the disk.
 */
typedef struct hfsp_vh {
        UInt16         signature;   // must be HFSPLUS_VOLHEAD_SIG 'H+'
        UInt16         version;     // currently 4, ignored
        UInt32         attributes;  // See bit constants below
        UInt32         last_mount_vers;
                // Use a registered creator code here (what do we use ?)
		// Mac OS uses '8.10' well
        UInt32         reserved;

        UInt32         create_date; // local time !
        UInt32         modify_date; // GMT (?)
        UInt32         backup_date; // GMT (?)
        UInt32         checked_date; // GMT (?) fsck ?

        UInt32         file_count;
         // not including special files but including DATA and RSRC forks
        UInt32         folder_count; // excluding the root folder

        UInt32         blocksize;
         // must be multiple of HFSPLUS_SECTOR_SIZE,
         // should be a multiple of 4k for harddisk
        UInt32         total_blocks;
        UInt32         free_blocks;
         // The total number of unused allocation blocks on the disk.

        UInt32         next_alloc;
         // hint wher to search for next allocation blocks
        UInt32         rsrc_clump_sz;
         // default clump size for rsrc forks
        UInt32         data_clump_sz;
         // default clump size for data forks
        UInt32	       next_cnid;
         // next unused catalog id
        UInt32         write_count;
         // increment on every mount (and write ?)
        UInt64        encodings_bmp;
                // for every encoding used on the disk a bit is set
                // ignored but eventually must be cared for
        Char          finder_info[32];
	hfsp_fork_raw   alloc_file;
         // stores bitmap of use/free blocks
        hfsp_fork_raw   ext_file;
         // stores oferflow extents
        hfsp_fork_raw   cat_file;
	 // This contains the root directory
        hfsp_fork_raw   attr_file;
        hfsp_fork_raw   start_file;
         // a special startup file may be described here (used by ?)
} hfsp_vh;

/* HFS+ volume attributes */
/* 0-6 reserved, may be used in memory only */
#define HFSPLUS_VOL_RESERVED1 0x000000FF
#define HFSPLUS_VOL_HARDLOCK  0x00000080 // Used in Memory by finder only
#define HFSPLUS_VOL_UNMNT     0x00000100
        // clear this bit when mounting, set as last step of unmounting
        // This is checked by (slower) ROM code
#define HFSPLUS_VOL_SPARE_BLK 0x00000200
#define HFSPLUS_VOL_NOCACHE   0x00000400
        // in case of RAM or ROM disk (try a HFS+ Ramdisk :)
#define HFSPLUS_VOL_INCNSTNT  0x00000800
        // Reverse meaning as of HFSPLUS_VOL_UNMNT
        // This is checked by (faster) Mac OS code
/* 12-14 reserved */
#define HFSPLUS_VOL_RESERVED2 0x00007000
#define HFSPLUS_VOL_SOFTLOCK  0x00008000
#define HFSPLUS_VOL_RESERVED3 0xFFFF0000

/* HFS+ Btree node descriptor */
typedef struct {
	UInt32	    next;   /* pointer to next node of this kind, or 0 */
	UInt32	    prev;   /* pointer to previous node of this kind, or 0 */
	UInt8	    kind;   /* see below */
	UInt8	    height; /* root node starts with 0 */
	UInt16	    num_rec;	/* number of records in this node */
	UInt16	    reserved;	/* fill up to 4 byte alignment */
} btree_node_desc;

/* HFS+ Btree Node types */
#define HFSP_NODE_NDX	0x00
#define HFSP_NODE_HEAD	0x01
#define HFSP_NODE_MAP	0x02
#define HFSP_NODE_LEAF	0xFF

#define HFSP_CATALOG_MIN_NODE_SIZE  0x1000
#define HFSP_ATTRMIN_DOE_SIZE	    0x1000

/* The record offsets are found at the end of the fork
 * containing the Btree */

typedef UInt16	btree_record_offset;

typedef struct {
        UInt16         depth;
	    // equal to height of btree_node_desc
        UInt32         root;
	    // root node of the hierarchy
        UInt32         leaf_count;
        UInt32         leaf_head;
        UInt32         leaf_tail;
        UInt16         node_size;
	    // node size of _all_ nodes in this fork
        UInt16         max_key_len;
        UInt32         node_count;
	    // count of all (free and used) nodes in tree
        UInt32         free_nodes;
        UInt16         reserved1;
        UInt32         clump_size;
         // ignored my MacOS used by ?
        UInt8	       btree_type;
         // always 0 for HFS+
        UInt8	       reserved2;
        UInt32         attributes;
	 // see below
        UInt32         reserved3[16];
} btree_head;

/* BTree attributes */
#define HFSPLUS_BAD_CLOSE            0x01
  // Btree was not properly closed and should be checked
  // not used for HFS+ but reserved
#define HFSPLUS_TREE_BIGKEYS         0x02
  // always set for HFS+
#define HFSPLUS_TREE_VAR_NDXKEY_SIZE 0x04
  // use variable length index nodes, always set for catalog btree,
  // always cleared for extents btree.

#define HFSPLUS_TREE_UNUSED          0xFFFFFFF8

/* Some special File ID numbers */
#define HFSP_POR_CNID             1  /* Parent Of the Root */
#define HFSP_ROOT_CNID            2  /* ROOT directory */
#define HFSP_EXT_CNID             3  /* EXTents B-tree */
#define HFSP_CAT_CNID             4  /* CATalog B-tree */
#define HFSP_BAD_CNID             5  /* BAD blocks file */
#define HFSP_ALLOC_CNID           6  /* ALLOCation file */
#define HFSP_START_CNID           7  /* STARTup file */
#define HFSP_ATTR_CNID            8  /* ATTRibutes file  */
#define HFSP_EXCH_CNID           15  /* ExchangeFiles temp id */
#define HFPS_MIN_CNID		 15  /* Minimum expected value */

/* Unicode String */
typedef struct {
    UInt16		strlen;
    UInt16		name[255];	// unicode charcters
} hfsp_unistr255;

/* HFS+ catalog entry key */
typedef struct {
    UInt16		key_length;	/* excluding length */
    UInt32		parent_cnid;
    hfsp_unistr255	name;
} hfsp_cat_key;

/* HFS+ exnteds entry key */
typedef struct {
    UInt16		key_length;	/* excluding length */
    UInt8		fork_type;	/* Seee below */
    UInt8		filler;
    UInt32		file_id;
    UInt32		start_block;
} hfsp_extent_key;

#define HFSP_EXTENT_DATA    0x00
#define HFSP_EXTENT_RSRC    0xFF

/* The key is followed by a record, an index or some other data */

/* The types of these records are defined as follows */

#define HFSP_FOLDER         0x0001  // entry fo a Folder
#define HFSP_FILE           0x0002  // entry for a File
#define HFSP_FOLDER_THREAD  0x0003
    // Like '.' in unix, identifies the folder by its id, only
#define HFSP_FILE_THREAD    0x0004
    // Im unsure if this is used by HFS+, too

/* HFS+ folder data (part of an hfsp_cat_entry) */
typedef struct {
    UInt16          flags;		/* no flags defined yet */
    UInt32	    valence;		/* Numer of files and folders contained in folder */
    UInt32	    id;
    UInt32	    create_date;	// GMT
    UInt32	    content_mod_date;	// GMT
    UInt32	    attribute_mod_date;	// GMT
    UInt32	    access_date;	// GMT
    UInt32	    backup_date;	// GMT
    hfsp_perm	    permissions;
    DInfo	    user_info;
    DXInfo	    finder_info;
    UInt32	    text_encoding;
	 // hint fo the finder what encoding to use, unused here
    UInt32         reserved;
} hfsp_cat_folder;

/* HFS+ file data (part of a cat_entry) */
typedef struct {
    UInt16          flags;		/* See below */
    UInt32	    reserved1;
    UInt32	    id;
    UInt32	    create_date;
    UInt32	    content_mod_date;
    UInt32	    attribute_mod_date;
    UInt32	    access_date;
    UInt32	    backup_date;
    hfsp_perm	    permissions;
    FInfo           user_info;
    FXInfo	    finder_info;
    UInt32	    text_encoding;
    UInt32	    reserved2;

    hfsp_fork_raw   data_fork;
    hfsp_fork_raw   res_fork;
} hfsp_cat_file;

/* File attribute bits */
#define HFSP_FILE_LOCKED      0x0001
#define HFSP_THREAD_EXISTS    0x0002 /* Always set in HFS+ */

/* HFS+ catalog thread (part of a cat_entry) */
typedef struct {
    UInt16          reserved;
    UInt32	    parentID;
    hfsp_unistr255   nodeName;
} hfsp_cat_thread;


/* A data record in the catalog tree */
typedef struct {
    UInt16	    type;
    union {
	hfsp_cat_folder folder;
	hfsp_cat_file   file;
	hfsp_cat_thread thread;
    } u;
} hfsp_cat_entry;
