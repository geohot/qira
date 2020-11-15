/*
 * <hfs.c>
 *
 * Open Hack'Ware BIOS HFS file system management
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Major rework and debug by Thayne Harbaugh <thayne@realmsys.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"
#include "libfs.h"

//#define DEBUG_HFS 1

/* HFS / HFSplus */
#if defined (DEBUG_HFS)
#define HFS_DPRINTF(fmt, args...) \
do { dprintf("%s: " fmt, __func__ , ##args); } while (0)
#else
#define HFS_DPRINTF(fmt, args...) \
do { } while (0)
#endif
#define HFS_ERROR(fmt, args...) \
do { dprintf("HFS ERROR in %s: " fmt, __func__ , ##args); } while (0)

/* HFS/HFS+ common definitions */
#define HFS_SECTOR_SIZE        512
#define HFS_VOLHEAD_SECTOR       2
#define HFS_NODE_SIZE          0x200

/* HFS signature */
#define HFS_VOLHEAD_SIG         0x4244
/* HFS+ signature */
#define HFSPLUS_VOLHEAD_SIG     0x482b

/* HFS+ filesystem support */
/* Files CNID */
enum {
    HFS_ROOT_PARENT  = 1,  /* Parent of root folder */
    HFS_ROOT_FOLDER  = 2,  /* root folder */
    HFS_EXTENT_FILE  = 3,  /* file extents file */
    HFS_CATALOG_FILE = 4,  /* catalog file */
    HFS_BBLOCS_FILE  = 5,  /* badblocks file */
    HFS_ALLOC_FILE   = 6,  /* allocation file (HFSplus) */
    HFS_STARTUP_FILE = 7,  /* startup file (HFSplus) */
    HFS_ATTR_FILE    = 8,  /* attribute file (HFSplus) */
    HFS_BEXTENT_FILE = 15, /* file extents temporary file */
    HFS_FIRST_USERID = 16,
};

typedef uint32_t HFS_cnid_t;

static inline HFS_cnid_t HFS_get_cnid (HFS_cnid_t *cnidp)
{
    return get_be32(cnidp);
}

typedef uint16_t HFSP_unichr_t;

static inline HFSP_unichr_t HFSP_get_unichr (HFSP_unichr_t *chrp)
{
    return get_be16(chrp);
}

/* A single contiguous area of a file */
typedef struct HFSP_extent_t HFSP_extent_t;
struct HFSP_extent_t {
    uint32_t start_block;
    uint32_t block_count;
} __attribute__ ((packed));

static inline HFSP_extent_t *HFSP_get_extent (HFSP_extent_t *extp)
{
    extp->start_block = get_be32(&extp->start_block);
    extp->block_count = get_be32(&extp->block_count);

    return extp;
}

/* Information for a "Fork" in a file */
typedef struct HFSP_fork_t HFSP_fork_t;
struct HFSP_fork_t {
    /* 0x00 */
    uint64_t total_size;
    uint32_t clump_size;
    uint32_t total_blocks;
    /* 0x10 */
    HFSP_extent_t extents[8];
    /* 0x50 */
} __attribute__ ((packed));

static inline HFSP_fork_t *HFSP_get_fork (HFSP_fork_t *forkp)
{
    int i;

    forkp->total_size = get_be64(&forkp->total_size);
    forkp->clump_size = get_be32(&forkp->clump_size);
    forkp->total_blocks = get_be32(&forkp->total_blocks);
    for (i = 0; i < 8; i++) {
        HFSP_get_extent(&forkp->extents[i]);
    }

    return forkp;
}

/* HFS+ Volume Header */
typedef struct HFSP_vh_t HFSP_vh_t;
struct HFSP_vh_t {
    /* 0x000 */
    uint16_t signature;
    uint16_t version;
    uint32_t attributes;
    uint32_t last_mount_vers;
    uint32_t reserved;
    
    /* 0x010 */
    uint32_t create_date;
    uint32_t modify_date;
    uint32_t backup_date;
    uint32_t checked_date;
    
    /* 0x020 */
    uint32_t file_count;
    uint32_t folder_count;
    uint32_t blocksize;
    uint32_t total_blocks;

    /* 0x030 */
    uint32_t free_blocks;
    uint32_t next_alloc;
    uint32_t rsrc_clump_sz;
    uint32_t data_clump_sz;

    /* 0x040 */
    HFS_cnid_t next_cnid;
    uint32_t write_count;
    uint64_t encodings_bmp;
    
    /* 0x050 */
    uint32_t finder_info[8];
    
    /* 0x070 */
    HFSP_fork_t alloc_file;
    /* 0x0C0 */
    HFSP_fork_t ext_file;
    /* 0x110 */
    HFSP_fork_t cat_file;
    /* 0x160 */
    HFSP_fork_t attr_file;
    /* 0x1B0 */
    HFSP_fork_t start_file;
    /* 0x1F0 */
    uint8_t pad[16];
} __attribute__ ((packed));

static HFSP_vh_t *HFSP_read_volhead (part_t *part, uint32_t bloc,
                                     uint32_t offset, void *buffer, int size)
{
    HFSP_vh_t *vh;
    int i;
    
    if (part_seek(part, bloc, offset) == -1)
        return NULL;
    if (part_read(part, buffer, size) < 0)
        return NULL;
    vh = buffer;
    vh->signature = get_be16(&vh->signature);
    vh->version = get_be16(&vh->version);
    vh->attributes = get_be32(&vh->attributes);
    vh->last_mount_vers = get_be32(&vh->last_mount_vers);
    vh->create_date = get_be32(&vh->create_date);
    vh->modify_date = get_be32(&vh->modify_date);
    vh->backup_date = get_be32(&vh->backup_date);
    vh->checked_date = get_be32(&vh->checked_date);
    vh->file_count = get_be32(&vh->file_count);
    vh->folder_count = get_be32(&vh->folder_count);
    vh->blocksize = get_be32(&vh->blocksize);
    vh->total_blocks = get_be32(&vh->total_blocks);
    vh->free_blocks = get_be32(&vh->free_blocks);
    vh->next_alloc = get_be32(&vh->next_alloc);
    vh->rsrc_clump_sz = get_be32(&vh->rsrc_clump_sz);
    vh->data_clump_sz = get_be32(&vh->data_clump_sz);
    HFS_get_cnid(&vh->next_cnid);
    vh->write_count = get_be32(&vh->write_count);
    vh->encodings_bmp = get_be32(&vh->encodings_bmp);
    for (i = 0; i < 8; i++) {
        vh->finder_info[i] = get_be32(&vh->finder_info[i]);
    }
    HFSP_get_fork(&vh->alloc_file);
    HFSP_get_fork(&vh->ext_file);
    HFSP_get_fork(&vh->cat_file);
    HFSP_get_fork(&vh->attr_file);
    HFSP_get_fork(&vh->start_file);

    return vh;
}

/* HFS support */
/* A single contiguous area of a file */
typedef struct HFS_extent_t HFS_extent_t;
struct HFS_extent_t {
    uint16_t start_block;
    uint16_t block_count;
} __attribute__ ((packed));

static inline HFS_extent_t *HFS_get_extent (HFS_extent_t *extp)
{
    extp->start_block = get_be16(&extp->start_block);
    extp->block_count = get_be16(&extp->block_count);

    return extp;
}

/* HFS Volume Header */
typedef struct HFS_vh_t HFS_vh_t;
struct HFS_vh_t {
    /* 0x000 */
    uint16_t signature;
    uint32_t create_date;
    uint32_t modify_date;
    uint16_t attributes;
    uint16_t root_file_count;
    uint16_t bitmap_start;

    /* 0x010 */
    uint16_t alloc_ptr;
    uint16_t alloc_blocs;
    uint32_t alloc_size;

    /* 0x018 */
    uint32_t clump_size;
    uint16_t alloc_start;
    HFS_cnid_t next_cnid;
    uint16_t free_blocs;

    /* 0x024 */
    uint8_t  label[28];

    /* 0x040 */
    uint32_t backup_tmsp;
    uint16_t backup_seq;
    uint32_t write_count;

    /* 0x04A */
    uint32_t ext_clump_size;
    /* 0x04E */
    uint32_t cat_clump_size;

    /* 0x052 */
    uint16_t root_dir_cnt;
    /* 0x054 */
    uint32_t file_cnt;
    uint32_t dir_cnt;
    /* 0x05C */
    uint32_t finder_info[8];

    /* 0x07C */
    uint16_t embed_sig;
    HFS_extent_t embed_ext;

    /* 0x082 */
    uint32_t ext_size;
    HFS_extent_t ext_rec[3];

    /* 0x092 */
    uint32_t cat_size;
    HFS_extent_t cat_rec[3];

    /* 0x0A2 */
} __attribute__(( __packed__ ));

static HFS_vh_t *HFS_read_volhead (part_t *part, uint32_t bloc,
                                   uint32_t offset, void *buffer, int size)
{
    HFS_vh_t *vh;
    int i;
    
    if (part_seek(part, bloc, offset) == -1)
        return NULL;
    if (part_read(part, buffer, size) < 0)
        return NULL;
    vh = buffer;
    vh->signature = get_be16(&vh->signature);
    vh->create_date = get_be32(&vh->create_date);
    vh->modify_date = get_be32(&vh->modify_date);
    vh->attributes = get_be16(&vh->attributes);
    vh->root_file_count = get_be16(&vh->root_file_count);
    vh->bitmap_start = get_be16(&vh->bitmap_start);
    vh->alloc_ptr = get_be16(&vh->alloc_ptr);
    vh->alloc_blocs = get_be16(&vh->alloc_blocs);
    vh->alloc_size = get_be32(&vh->alloc_size);
    vh->clump_size = get_be32(&vh->clump_size);
    vh->alloc_start = get_be16(&vh->alloc_start);
    HFS_get_cnid(&vh->next_cnid);
    vh->free_blocs = get_be16(&vh->free_blocs);
    vh->backup_tmsp = get_be32(&vh->backup_tmsp);
    vh->backup_seq = get_be16(&vh->backup_seq);
    vh->write_count = get_be32(&vh->write_count);
    vh->ext_clump_size = get_be32(&vh->ext_clump_size);
    vh->cat_clump_size = get_be32(&vh->cat_clump_size);
    vh->root_dir_cnt = get_be16(&vh->root_dir_cnt);
    vh->file_cnt = get_be32(&vh->file_cnt);
    vh->dir_cnt = get_be32(&vh->dir_cnt);
    for (i = 0; i < 8; i++) {
        vh->finder_info[i] = get_be32(&vh->finder_info[i]);
    }
    vh->embed_sig = get_be16(&vh->embed_sig);
    HFS_get_extent(&vh->embed_ext);
    vh->ext_size = get_be16(&vh->ext_size);
    for (i = 0; i < 3; i++) {
        HFS_get_extent(&vh->ext_rec[i]);
    }
    vh->cat_size = get_be16(&vh->cat_size);
    for (i = 0; i < 3; i++) {
        HFS_get_extent(&vh->cat_rec[i]);
    }

    return vh;
}

enum {
    HFS_NODE_LEAF = 0xFF,
    HFS_NODE_IDX  = 0x00,
    HFS_NODE_HEAD = 0x01,
    HFS_NODE_MAP  = 0x02,
};

/* HFS B-tree structures */
typedef struct HFS_bnode_t HFS_bnode_t;
struct HFS_bnode_t {
    uint32_t next;
    uint32_t prev;
    uint8_t  type;
    uint8_t  height;
    uint16_t nrecs;
    uint16_t pad;
} __attribute__ ((packed));

static HFS_bnode_t *HFS_read_Hnode (part_t *part, uint32_t bloc,
                                    uint32_t offset, void *buffer, int nsize)
{
    HFS_bnode_t *Hnode;
    
    if (part_seek(part, bloc, offset) == -1) {
        HFS_DPRINTF("seek failed\n");
        return NULL;
    }
    if (part_read(part, buffer, nsize) < 0) {
        HFS_DPRINTF("read failed\n");
        return NULL;
    }
    Hnode = (void *)buffer;
    Hnode->next = get_be32(&Hnode->next);
    Hnode->prev = get_be32(&Hnode->prev);
    Hnode->nrecs = get_be16(&Hnode->nrecs);

    return Hnode;
}

typedef struct HFS_headrec_t HFS_headrec_t;
struct HFS_headrec_t {
    /* 0x00 */
    uint16_t depth;
    uint32_t rootnode;
    /* 0x06 */
    uint32_t nbleaves;
    uint32_t firstleaf;
    /* 0x0E */
    uint32_t lastleaf;
    uint16_t nodesize;
    /* 0x14 */
    uint16_t maxkeylen;
    uint32_t nbnodes;
    /* 0x18 */
    uint32_t freenodes;
    uint16_t pad0;
    /* 0x1E */
    uint32_t clump_size;
    uint8_t  type;
    uint8_t  pad1;
    /* 0x24 */
    uint32_t attr;
    /* 0x28 */
    uint32_t pad2[16];
    /* 0x68 */
} __attribute__ ((packed));

static HFS_headrec_t *HFS_get_headrec (void *pos)
{
    HFS_headrec_t *head = pos;

    head->depth = get_be16(&head->depth);
    head->rootnode = get_be32(&head->rootnode);
    head->nbleaves = get_be32(&head->nbleaves);
    head->firstleaf = get_be32(&head->firstleaf);
    head->lastleaf = get_be32(&head->lastleaf);
    head->maxkeylen = get_be16(&head->maxkeylen);
    head->nbnodes = get_be32(&head->nbnodes);
    head->freenodes = get_be32(&head->freenodes);
    head->clump_size = get_be32(&head->clump_size);
    head->attr = get_be32(&head->attr);

    return head;
}

typedef struct HFS_catkey_t HFS_catkey_t;
struct HFS_catkey_t {
    uint8_t len;
    uint8_t pad;
    HFS_cnid_t pID;
    uint8_t nlen;
    unsigned char name[0x1F];
} __attribute__ ((packed));

typedef struct HFSP_catkey_t HFSP_catkey_t;
struct HFSP_catkey_t {
    uint16_t len;
    HFS_cnid_t pID;
    uint16_t nlen;
    HFSP_unichr_t uniname[255];
} __attribute__ ((packed));

enum {
    HFS_CAT_FOLDER  = 0x0100,
    HFS_CAT_FILE    = 0x0200,
    HFS_CAT_FOLDTH  = 0x0300,
    HFS_CAT_FILETH  = 0x0400,
    HFSP_CAT_FOLDER = 0x0001,
    HFSP_CAT_FILE   = 0x0002,
    HFSP_CAT_FOLDTH = 0x0003,
    HFSP_CAT_FILETH = 0x0004,
};

typedef struct HFS_win_t HFS_win_t;
struct HFS_win_t {
    uint16_t top;
    uint16_t left;
    uint16_t bot;
    uint16_t right;
}  __attribute__ ((packed));

typedef struct HFS_pos_t HFS_pos_t;
struct HFS_pos_t {
    uint16_t y;
    uint16_t x;
} __attribute__ ((packed));

typedef struct HFS_fdir_info_t HFS_fdir_info_t;
struct HFS_fdir_info_t {
    HFS_win_t win;
    uint16_t  flags;
    HFS_pos_t pos;
    uint16_t  pad;
} __attribute__ ((packed));

typedef struct HFS_file_info_t HFS_file_info_t;
struct HFS_file_info_t {
    uint32_t  ftype;
    uint32_t  owner;
    uint16_t  flags;
    HFS_pos_t pos;
    uint16_t  pad;
} __attribute__ ((packed));

typedef struct HFSP_BSD_info_t HFSP_BSD_info_t;
struct HFSP_BSD_info_t {
    uint32_t owner;
    uint32_t group;
    uint8_t aflags;
    uint8_t oflags;
    uint16_t mode;
    union {
        uint32_t inum;
        uint32_t lcount;
        uint32_t device;
    } u;
} __attribute__ ((packed));

typedef struct HFS_fold_t HFS_fold_t;
struct HFS_fold_t {
    uint16_t type;
    uint16_t flags;
    uint16_t valence;
    HFS_cnid_t ID;
    uint32_t created;
    uint32_t modifd;
    uint32_t backupd;
    HFS_fdir_info_t finder_dir;
    uint8_t  finder_pad[16];
    uint32_t pad[4];
} __attribute__ ((packed));

typedef struct HFSP_fold_t HFSP_fold_t;
struct HFSP_fold_t {
    uint16_t type;
    uint16_t flags;
    uint32_t valence;
    HFS_cnid_t ID;
    uint32_t created;
    uint32_t modifd;
    uint32_t attrd;
    uint32_t accessd;
    uint32_t attrmd;
    HFSP_BSD_info_t BSD_infos;
    HFS_fdir_info_t finder_dir;
    uint8_t  finder_pad[16];
    uint32_t encoding;
    uint32_t pad;
} __attribute__ ((packed));

typedef struct HFS_file_t HFS_file_t;
struct HFS_file_t {
    /* 0x00 */
    uint16_t type;
    uint8_t  flags;
    uint8_t  ftype;
    /* 0x04 */
    HFS_file_info_t finder_file;
    /* 0x14 */
    HFS_cnid_t ID;
    /* 0x18 */
    uint16_t dstart;
    uint32_t dlsize;
    uint32_t dpsize;
    uint16_t rstart;
    /* 0x24 */
    uint32_t rlsize;
    uint32_t rpsize;
    /* 0x2C */
    uint32_t created;
    /* 0x30 */
    uint32_t modifd;
    uint32_t backupd;
    /* 0x38 */
    uint8_t  finder_pad[16];
    /* 0x48 */
    uint16_t clump_size;
    /* 0x4C */
    HFS_extent_t extents[3];
    /* 0x54 */
} __attribute__ ((packed));

typedef struct HFSP_file_t HFSP_file_t;
struct HFSP_file_t {
    /* 0x00 */
    uint16_t type;
    uint16_t flags;
    uint32_t pad;
    /* 0x08 */
    HFS_cnid_t ID;
    uint32_t created;
    /* 0x10 */
    uint32_t modifd;
    uint32_t attrd;
    uint32_t accessd;
    uint32_t backupd;
    /* 0x20 */
    HFSP_BSD_info_t BSD_infos;
    /* 0x30 */
    HFS_file_info_t finder_file;
    /* 0x40 */
    uint8_t  finder_pad[16];
    /* 0x50 */
    uint32_t encoding;
    uint32_t pad1[3];
    HFSP_fork_t data;
    HFSP_fork_t ressources;
} __attribute__ ((packed));

typedef struct HFS_thread_t HFS_thread_t;
struct HFS_thread_t {
    uint16_t type;
    uint32_t pad[2];
    HFS_cnid_t pid;
    uint8_t pad0;
    unsigned char name[32];
} __attribute__ ((packed));

typedef struct HFSP_thread_t HFSP_thread_t;
struct HFSP_thread_t {
    uint16_t type;
    uint16_t pad;
    HFS_cnid_t pid;
    uint16_t nlen;
    HFSP_unichr_t uniname[255];
} __attribute__ ((packed));

/* in memory structures */
typedef struct hfs_vol_t hfs_vol_t;
typedef struct hfs_btree_t hfs_btree_t;
typedef struct hfs_rec_t hfs_rec_t;

/* Volume/file structures */
typedef struct hfs_extent_t {
    uint32_t start;
    uint32_t count;
} hfs_extent_t;

typedef struct hfs_fork_t {
    hfs_vol_t *volume;
    uint32_t nb_blocs;
    hfs_extent_t extents[8];
    hfs_rec_t *catrec;
    hfs_rec_t *extrec;
} hfs_fork_t;

struct hfs_vol_t {
    part_t *part;
    int type;
    HFS_cnid_t boot_id;
    uint32_t embed_offset;
    uint32_t start_offset;
    uint32_t bsize;
    hfs_fork_t alloc_file;
    hfs_fork_t cat_file;
    hfs_fork_t ext_file;
    hfs_fork_t *boot_file;
    hfs_btree_t *cat_tree;
    hfs_btree_t *ext_tree;
};

/* Btree structures */
/* Btree node */
typedef struct hfs_bnode_t {
    hfs_btree_t *tree;
    uint32_t prev;
    uint32_t next;
    int type;
    uint32_t nrecs;
    hfs_rec_t *recs;
} hfs_bnode_t;

/* Cached Btree node */
typedef struct hfs_cbnode_t hfs_cbnode_t;
struct hfs_cbnode_t {
    uint32_t location;
    hfs_cbnode_t *next;
    hfs_bnode_t bnode;
};

/* Bnode records */
enum {
    RECORD_HEAD = 0,
    RECORD_IDX,
    RECORD_CAT,
    RECORD_EXT,
};

/* Header record */
typedef struct hfs_headrec_t {
    uint32_t rootnode;
    uint32_t firstleaf;
    uint32_t lastleaf;
    uint32_t nodesize;
} hfs_headrec_t;

/* Index record */
typedef struct hfs_idxrec_t {
    HFS_cnid_t pid;
    HFS_cnid_t uid;
    unsigned char name[0x20];
} hfs_idxrec_t;

/* File extent records */
/* TODO */
typedef struct hfs_extrec_t {
    HFS_cnid_t ID;
} hfs_extrec_t;

/* Catalog records */
typedef struct hfs_catrec_t {
    HFS_cnid_t ID;
    HFS_cnid_t pid;
    int type;
    unsigned char name[0x20];
    unsigned char finfo[9];
    hfs_fork_t fork;
} hfs_catrec_t;

/* Generic record */
struct hfs_rec_t {
    hfs_bnode_t *node;
    int type;
    int num;
    union {
        hfs_headrec_t headrec;
        hfs_idxrec_t  idxrec;
        hfs_catrec_t  catrec;
        hfs_extrec_t  extrec;
    } u;
};

struct hfs_btree_t {
    hfs_fork_t *file;
    hfs_cbnode_t *cache;
    hfs_rec_t *head_rec;
    hfs_bnode_t *root_node;
    hfs_rec_t *root_catrec;
    hfs_rec_t *root_extrec;
    uint32_t nodesize;
    unsigned char *buf;
    int type;
    int (*compare)(int type, HFS_cnid_t cnid,
                   const void *more, hfs_rec_t *rec, int rectype);
};

/* Unicode to ISO-8859-15, stolen from Linux nls */
static unsigned char page00[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 0x00-0x07 */
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* 0x08-0x0f */
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, /* 0x10-0x17 */
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, /* 0x18-0x1f */
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, /* 0x20-0x27 */
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, /* 0x28-0x2f */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 0x30-0x37 */
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, /* 0x38-0x3f */
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, /* 0x40-0x47 */
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, /* 0x48-0x4f */
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, /* 0x50-0x57 */
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, /* 0x58-0x5f */
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* 0x60-0x67 */
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, /* 0x68-0x6f */
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, /* 0x70-0x77 */
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, /* 0x78-0x7f */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x80-0x87 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x88-0x8f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x90-0x97 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x98-0x9f */
    0xa0, 0xa1, 0xa2, 0xa3, 0x00, 0xa5, 0x00, 0xa7, /* 0xa0-0xa7 */
    0x00, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, /* 0xa8-0xaf */
    0xb0, 0xb1, 0xb2, 0xb3, 0x00, 0xb5, 0xb6, 0xb7, /* 0xb0-0xb7 */
    0x00, 0xb9, 0xba, 0xbb, 0x00, 0x00, 0x00, 0xbf, /* 0xb8-0xbf */
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, /* 0xc0-0xc7 */
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, /* 0xc8-0xcf */
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, /* 0xd0-0xd7 */
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, /* 0xd8-0xdf */
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, /* 0xe0-0xe7 */
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, /* 0xe8-0xef */
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, /* 0xf0-0xf7 */
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, /* 0xf8-0xff */
};

static unsigned char page01[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x00-0x07 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x08-0x0f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x10-0x17 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x18-0x1f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x20-0x27 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x28-0x2f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x30-0x37 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x38-0x3f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x40-0x47 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x48-0x4f */
    0x00, 0x00, 0xbc, 0xbd, 0x00, 0x00, 0x00, 0x00, /* 0x50-0x57 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x58-0x5f */
    0xa6, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x60-0x67 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x68-0x6f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x70-0x77 */
    0xbe, 0x00, 0x00, 0x00, 0x00, 0xb4, 0xb8, 0x00, /* 0x78-0x7f */
};

static unsigned char page20[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x00-0x07 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x08-0x0f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x10-0x17 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x18-0x1f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x20-0x27 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x28-0x2f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x30-0x37 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x38-0x3f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x40-0x47 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x48-0x4f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x50-0x57 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x58-0x5f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x60-0x67 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x68-0x6f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x70-0x77 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x78-0x7f */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x80-0x87 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x88-0x8f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x90-0x97 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x98-0x9f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0xa0-0xa7 */
    0x00, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00, 0x00, /* 0xa8-0xaf */
};

static unsigned char *page_uni2charset[256] = {
    page00, page01, NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   
    NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,
    
    NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,
    NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,
    
    page20, NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,
    NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,   NULL,
};

static int uni2char (uint16_t uni, unsigned char *out)
{
    unsigned char *uni2charset;
    unsigned char cl = uni & 0x00ff;
    unsigned char ch = (uni & 0xff00) >> 8;

    uni2charset = page_uni2charset[ch];
    if (uni2charset && uni2charset[cl])
        *out = uni2charset[cl];
    else
        return -1;

    return 0;
}

static void hfs_get_str (unsigned char *out, int len, uint16_t *hfs_str)
{
    int i;
    char c;
 
    for (i = 0; i < len; i++) {
        if (uni2char(*hfs_str++, &c) < 0)
            c = '?';
        out[i] = c;
    }
    out[i] = '\0';
}

/* Locate a bloc in the partition given a file and an offset */
static uint32_t hfs_get_bloc (hfs_fork_t *file, uint32_t bloc)
{
    hfs_vol_t *volume;
    hfs_extent_t *extent;
    uint32_t abloc, aoffset;
    int i;
    
    volume = file->volume;
    abloc = bloc / volume->bsize;
    aoffset = bloc - (abloc * volume->bsize);
    extent = file->extents;
#if 0
    HFS_DPRINTF("Look for bloc %08x => %08x %08x (%08x)\n",
                bloc, abloc, aoffset, volume->bsize);
#endif
    for (i = 0; i < 8; i++) {
#if 0
        HFS_DPRINTF("Check extent %d %08x %08x (%08x)\n",
                    i, extent->start, extent->count, abloc);
#endif
        if (extent->count == 0)
            break;
        if (abloc < extent->count) {
            return volume->start_offset + /*volume->embed_offset +*/
                ((extent->start + abloc) * volume->bsize) + aoffset;
        }
        abloc -= extent->count;
        extent++;
    }
    HFS_ERROR("Block %d not found\n", bloc);

    return -1;
}

/* Convert HFS/HFS plus extent/fork records to memory structure */
static inline void hfs_get_extent (hfs_extent_t *dst, HFS_extent_t *src)
{
    dst->start = src->start_block;
    dst->count = src->block_count;
}

static void hfs_get_fork (hfs_fork_t *dst, uint32_t blocs,
                          HFS_extent_t *extents)
{
    int i;

    dst->nb_blocs = blocs;
    for (i = 0; i < 3; i++) {
        hfs_get_extent(&dst->extents[i], &extents[i]);
    }
    memset(&dst->extents[3], 0, 5 * sizeof(hfs_extent_t));
}

static inline void hfsp_get_extent (hfs_extent_t *dst, HFSP_extent_t *src)
{
    dst->start = src->start_block;
    dst->count = src->block_count;
}

static void hfsp_get_fork (hfs_fork_t *dst, uint32_t blocs,
                           HFSP_extent_t *extents)
{
    int i;

    dst->nb_blocs = blocs;
    for (i = 0; i < 8; i++) {
        hfsp_get_extent(&dst->extents[i], &extents[i]);
    }
}

static void hfs_dump_fork (hfs_fork_t *fork)
{
    int i;

    HFS_DPRINTF("Nb blocs: %d\n", fork->nb_blocs);
    for (i = 0; i < 8; i++) {
        if (fork->extents[i].count == 0)
            break;
        HFS_DPRINTF("  extent %d: start: %08x count: %08x\n",
                    i, fork->extents[i].start, fork->extents[i].count);
    }
}

/* Btree nodes cache */
static inline void *hfs_brec_get (HFS_bnode_t *node, uint32_t nodesize, int nb)
{
    uint16_t *off;

    if (nb < 1 || nb > node->nrecs) {
        HFS_ERROR("nb=%d nrec=%d\n", nb, node->nrecs);
        return NULL;
    }
    off = (void *)((char *)node + nodesize);
    off -= nb;
    HFS_DPRINTF("%d => %02x node %p off %p %p %d\n",
                nb, *off, node, off, (char *)node + nodesize, nodesize);
    
    return (char *)node + *off;
}

static hfs_bnode_t *hfs_bnode_get (hfs_btree_t *tree, uint32_t location)
{
    unsigned char *buffer, tmpbuf[HFS_NODE_SIZE];
    void *HFS_recp;
    HFS_bnode_t *Hnode;
    HFS_headrec_t *Hhead;
    HFSP_catkey_t *HPkey = NULL;
    HFS_catkey_t *Hkey = NULL;
    HFSP_thread_t *HPthread;
    HFS_thread_t *Hthread;
    HFSP_fold_t *HPdir;
    HFS_fold_t *Hdir;
    HFSP_file_t *HPfile;
    HFS_file_t *Hfile;
    hfs_headrec_t *head;
    hfs_cbnode_t **cur;
    hfs_bnode_t *node;
    hfs_rec_t *rec;
    uint32_t bloc, offset, bsize, *upID, nsize;
    uint16_t *ptype;
    int i, j, is_hfs;
    
#if 1
    for (cur = &tree->cache; *cur != NULL; cur = &((*cur)->next)) {
        if ((*cur)->location == location) {
            HFS_DPRINTF("found node %08x in cache (%08x %08x)\n",
                        location, (*cur)->bnode.prev, (*cur)->bnode.next);
            return &(*cur)->bnode;
        }
    }
#endif
    /* Not found in cache, get it from disk */
    head = &tree->head_rec->u.headrec;
    if (tree->nodesize != 0) {
        nsize = tree->nodesize;
        buffer = tree->buf;
    } else {
        nsize = HFS_NODE_SIZE;
        buffer = tmpbuf;
    }
    bsize = part_blocsize(tree->file->volume->part);
    bloc = location * nsize / 512;
    HFS_DPRINTF("Get node from %08x %08x %p\n",
                bloc, nsize, tree->file->volume->part);
    bloc = hfs_get_bloc(tree->file, bloc);
    if (bloc == (uint32_t)-1)
        return NULL;
    HFS_DPRINTF("  => %08x\n", bloc);
#if 0
    offset = bloc % bsize;
    bloc /= bsize;
#else
    offset = 0;
#endif
    HFS_DPRINTF("  => %08x %08x (%d)\n", bloc, offset, bsize);
    Hnode = HFS_read_Hnode(tree->file->volume->part,
                           bloc, offset, buffer, nsize);
    if (Hnode == NULL) {
        HFS_DPRINTF("No Hnode !\n");
        return NULL;
    }
    *cur = malloc(sizeof(hfs_cbnode_t) + (Hnode->nrecs * sizeof(hfs_rec_t)));
    if (*cur == NULL)
        return NULL;
    memset(*cur, 0, sizeof(hfs_cbnode_t) + (Hnode->nrecs * sizeof(hfs_rec_t)));
    (*cur)->location = location;
    node = &(*cur)->bnode;
    node->tree = tree;
    node->prev = Hnode->prev;
    node->next = Hnode->next;
    node->type = Hnode->type;
    node->nrecs = Hnode->nrecs;
    node->recs = (void *)(node + 1);
    if (tree->nodesize == 0 && node->type != HFS_NODE_HEAD) {
        HFS_ERROR("first node should be a header !\n");
        return NULL;
    }
    if (node->type == HFS_NODE_HEAD) {
        Hhead = HFS_get_headrec(Hnode + 1);
        nsize = Hhead->nodesize;
        if (nsize == 0)
            nsize = HFS_NODE_SIZE;
        HFS_DPRINTF("Set node size to %d\n", nsize);
        tree->nodesize = nsize;
        tree->buf = malloc(nsize);
        if (tree->buf == NULL)
            return NULL;
        memset(tree->buf, 0, nsize);
        buffer = tree->buf;
        Hnode = HFS_read_Hnode(tree->file->volume->part,
                               bloc, offset, buffer, nsize);
        if (Hnode == NULL)
            return NULL;
    }
    HFS_DPRINTF("New node %08x prev: %08x next: %08x type: %d nrecs: %d\n",
                location, node->prev, node->next, node->type, node->nrecs);
    is_hfs = tree->file->volume->type == FS_TYPE_HFS;
    for (i = 0; i < (int)node->nrecs; i++) {
        rec = &node->recs[i];
        rec->node = node;
        rec->num = i + 1;
        HFS_recp = hfs_brec_get(Hnode, nsize, i + 1);
        if (HFS_recp == NULL) {
            HFS_ERROR("can't get record %d\n", i + 1);
            continue;
        }
        if (is_hfs) {
            Hkey = HFS_recp;
#if 0
            upID = (void *)(((uint32_t)Hkey + 2 + Hkey->len));
#else
            upID = (void *)(((uint32_t)Hkey + 2 + Hkey->len) & ~1);
#endif
        } else {
            HPkey = HFS_recp;
            upID = (void *)(((uint32_t)HPkey + 2 + HPkey->len) & ~1);
        }
        switch (node->type) {
        case HFS_NODE_LEAF:
            HFS_DPRINTF("record %d: leaf %p %p %d\n", i + 1, upID, HFS_recp,
                        (char *)upID - (char *)HFS_recp);
            rec->type = tree->type;
            switch (rec->type) {
            case RECORD_CAT:
                ptype = (void *)upID;
                if (is_hfs) {
                    memcpy(rec->u.catrec.name, Hkey->name, Hkey->nlen);
                    rec->u.catrec.name[Hkey->nlen] = '\0';
                    rec->u.catrec.pid = Hkey->pID;
                } else {
                    hfs_get_str(rec->u.catrec.name,
                                HPkey->nlen, HPkey->uniname);
                    rec->u.catrec.pid = HPkey->pID;
                }
                rec->u.catrec.type = *ptype;
                rec->u.catrec.fork.volume = tree->file->volume;
                rec->u.catrec.fork.catrec = rec;
                switch (*ptype) {
                case HFS_CAT_FOLDER:
                    Hdir = (void *)ptype;
                    rec->u.catrec.ID = Hdir->ID;
                    HFS_DPRINTF("HFS Catalog folder ID: %08x name '%s' %08x\n",
                                rec->u.catrec.ID, rec->u.catrec.name,
                                rec->u.catrec.pid);
                    break;
                case HFS_CAT_FILE:
                    Hfile = (void *)ptype;
                    rec->u.catrec.ID = Hfile->ID;
                    memcpy(rec->u.catrec.finfo, &Hfile->finder_file, 8);
                    rec->u.catrec.finfo[8] = '\0';
                    for (j = 0; j < 3; j++) {
                        hfs_get_extent(&rec->u.catrec.fork.extents[j],
                                       &Hfile->extents[j]);
#if 0
                        HFS_DPRINTF("Extent %04x %04x => %08x %08x\n",
                                    Hfile->extents[j].start_block,
                                    Hfile->extents[j].block_count,
                                    rec->u.catrec.fork.extents[j].start,
                                    rec->u.catrec.fork.extents[j].count);
#endif
                    }
                    memset(&rec->u.catrec.fork.extents[3], 0,
                           5 * sizeof(hfs_extent_t));
                    HFS_DPRINTF("HFS Catalog file ID: %08x name '%s' '%s' %08x\n",
                                rec->u.catrec.ID, rec->u.catrec.name,
                                rec->u.catrec.finfo, rec->u.catrec.pid);
#if 0
                    HFS_DPRINTF("Extent %08x %08x\n",
                                rec->u.catrec.fork.extents[0].start,
                                rec->u.catrec.fork.extents[0].count);
#endif
                    break;
                case HFS_CAT_FOLDTH:
                    Hthread = (void *)ptype;
                    strcpy(rec->u.catrec.name, Hthread->name);
                    rec->u.catrec.ID = rec->u.catrec.pid;
                    rec->u.catrec.pid = Hthread->pid;
                    HFS_DPRINTF("HFS Catalog folder thread '%s' %08x %08x\n",
                                rec->u.catrec.name, rec->u.catrec.ID,
                                rec->u.catrec.pid);
                    continue;
                case HFS_CAT_FILETH:
                    Hthread = (void *)ptype;
                    strcpy(rec->u.catrec.name, Hthread->name);
                    rec->u.catrec.ID = rec->u.catrec.pid;
                    rec->u.catrec.pid = Hthread->pid;
                    HFS_DPRINTF("HFS Catalog file thread '%s' %08x %08x\n",
                                rec->u.catrec.name, rec->u.catrec.ID,
                                rec->u.catrec.pid);
                    continue;
                case HFSP_CAT_FOLDER:
                    HPdir = (void *)ptype;
                    rec->u.catrec.ID = HPdir->ID;
                    HFS_DPRINTF("HFSplus Catalog folder ID: %08x name '%s'\n",
                                rec->u.catrec.ID, rec->u.catrec.name);
                    break;
                case HFSP_CAT_FILE:
                    HPfile = (void *)ptype;
                    rec->u.catrec.ID = HPfile->ID;
                    memcpy(rec->u.catrec.finfo, &HPfile->finder_file, 8);
                    rec->u.catrec.finfo[8] = '\0';
                    memcpy(&rec->u.catrec.fork, &HPfile->data,
                           sizeof(HFSP_fork_t));
                    HFS_DPRINTF("HFSPlus Catalog file ID: %08x name '%s' '%s'\n",
                                rec->u.catrec.ID, rec->u.catrec.name,
                                rec->u.catrec.finfo);
                    HFS_DPRINTF("Extent %08x %08x\n",
                                rec->u.catrec.fork.extents[0].start,
                                rec->u.catrec.fork.extents[0].count);
                    break;
                case HFSP_CAT_FOLDTH:
                    HPthread = (void *)ptype;
                    rec->u.catrec.ID = rec->u.catrec.pid;
                    rec->u.catrec.pid = HPthread->pid;
                    hfs_get_str(rec->u.catrec.name,
                                HPthread->nlen, HPthread->uniname);
                    HFS_DPRINTF("HFSplus Catalog folder thread '%s'...\n",
                                rec->u.catrec.name);
                    break;
                case HFSP_CAT_FILETH:
                    HPthread = (void *)ptype;
                    hfs_get_str(rec->u.catrec.name,
                                HPthread->nlen, HPthread->uniname);
                    rec->u.catrec.ID = rec->u.catrec.pid;
                    rec->u.catrec.pid = HPthread->pid;
                    HFS_DPRINTF("HFSplus Catalog file thread '%s'...\n",
                                rec->u.catrec.name);
                    break;
                default:
                    printf("Unknown catalog entry %d %d '%s' %d\n", rec->type,
                           *ptype, rec->u.catrec.name, (char *)ptype - (char *)Hkey);
                    continue;
                }
                break;
            case RECORD_EXT:
                /* TODO */
                HFS_DPRINTF("Extent file entry\n");
                continue;
            default:
                HFS_ERROR("Unknown entry\n");
                continue;
            }
            break;
        case HFS_NODE_IDX:
            rec->type = RECORD_IDX;
            rec->u.idxrec.uid = *upID;
            if (is_hfs) {
                rec->u.idxrec.pid = Hkey->pID;
                memcpy(rec->u.idxrec.name, Hkey->name, Hkey->nlen);
                rec->u.idxrec.name[Hkey->nlen] = '\0';
                HFS_DPRINTF("HFS IDX record %d parent: %08x up: %08x name '%s'\n",
                            i + 1, rec->u.idxrec.pid, rec->u.idxrec.uid,
                            rec->u.idxrec.name);
                HFS_DPRINTF("uidp : %d %d\n", (char *)upID - (char *)Hkey,
                            (char *)(Hkey + 1) - (char *)Hkey);
            } else {
                rec->u.idxrec.pid = HPkey->pID;
                hfs_get_str(rec->u.idxrec.name,
                            HPkey->nlen, HPkey->uniname);
                HFS_DPRINTF("HFSplus IDX record %d parent: %08x up: %08x "
                            "name '%s'\n", i + 1, rec->u.idxrec.pid,
                            rec->u.idxrec.uid, rec->u.idxrec.name);
            }
            break;
        case HFS_NODE_HEAD:
            Hhead = HFS_get_headrec(HFS_recp);
            rec->type = RECORD_HEAD;
            rec->u.headrec.rootnode = Hhead->rootnode;
            rec->u.headrec.firstleaf = Hhead->firstleaf;
            rec->u.headrec.lastleaf = Hhead->lastleaf;
            rec->u.headrec.nodesize = Hhead->nodesize;
            HFS_DPRINTF("Header record %d root: %08x first: %08x last: %08x "
                        "size: %08x\n", i + 1, rec->u.headrec.rootnode,
                        rec->u.headrec.firstleaf, rec->u.headrec.lastleaf,
                        rec->u.headrec.nodesize);
            node->nrecs = 1;
            goto out;
        case HFS_NODE_MAP:
            /* TODO */
        default:
            continue;
        }
    }

 out:
    return node;
}

static inline hfs_rec_t *hfs_rec_get (hfs_bnode_t *node, int nb)
{
    if (nb < 1 || nb > (int)node->nrecs) {
        HFS_ERROR("nb: %d min: %d max: %d\n", nb, 1, node->nrecs);
        return NULL;
    }

    return &node->recs[nb - 1];
}

static inline hfs_bnode_t *hfs_bnode_prev (hfs_bnode_t *cur)
{
    if (cur->prev == 0x00000000)
        return NULL;

    return hfs_bnode_get(cur->tree, cur->prev);
}

static inline hfs_bnode_t *hfs_bnode_next (hfs_bnode_t *cur)
{
    if (cur->next == 0x00000000)
        return NULL;

    return hfs_bnode_get(cur->tree, cur->next);
}

unused static hfs_rec_t *hfs_rec_prev (hfs_rec_t *cur)
{
    hfs_bnode_t *curn;
    int num;

    num = cur->num;
    curn = cur->node;
    if (num == 1) {
        curn = hfs_bnode_prev(curn);
        if (curn == NULL)
            return NULL;
        num = curn->nrecs + 1;
    }
    
    return hfs_rec_get(curn, num - 1);
}

unused static hfs_rec_t *hfs_rec_next (hfs_rec_t *cur)
{
    hfs_bnode_t *curn;
    int num;

    num = cur->num;
    curn = cur->node;
    if (num == (int)curn->nrecs) {
        curn = hfs_bnode_next(curn);
        if (curn == NULL)
            return NULL;
        num = 1;
    }
    
    return hfs_rec_get(curn, num - 1);
}

static int hfs_cat_compare (int type, HFS_cnid_t cnid,
                            const void *more, hfs_rec_t *rec, int rectype);

/* Simplified Btree recurse function from Linux */
static hfs_rec_t *hfs_rec_find (hfs_btree_t *tree,
                                HFS_cnid_t cnid, const char *name, int rectype)
{
    hfs_bnode_t *curn;
    hfs_rec_t *cur;
    unsigned int i;
    int ret;

    /*
     * This is an ugly scattering of #if, but it's wonderful for debugging
     * hfs_rec_find().  If you set this to 1, then the loop will traverse
     * and show all of the records in a node before descending the correct
     * record.
     */
#define DEBUG_HFS_REC_FIND 0
#if DEBUG_HFS_REC_FIND
    hfs_rec_t *idx_cur;
    unsigned int idx;
    int idx_ret;
#endif /* DEBUG_HFS_REC_FIND */

    HFS_DPRINTF("look for ID: %08x '%s'\n", cnid, name);
    cur = NULL;
    ret = -1;
    i = 0;
    for (curn = tree->root_node; curn != NULL;) {
#if DEBUG_HFS_REC_FIND
        idx = 0;
        idx_ret = 0;
        idx_cur = NULL;
#endif /* DEBUG_HFS_REC_FIND */
        for (i = curn->nrecs; i != 0; i--) {
            cur = hfs_rec_get(curn, i);
            if (cur == NULL) {
                HFS_ERROR("Cannot get record %d\n", i);
                return NULL;
            }
            HFS_DPRINTF("Check record %d %d %p %p %p\n", i, cur->type, cur,
                        curn->tree->compare, &hfs_cat_compare);
            ret = (*curn->tree->compare)(cur->type, cnid, name, cur, rectype);
            HFS_DPRINTF("\t%u:%d\n", i, ret);
            if (ret >= 0) {
#if !DEBUG_HFS_REC_FIND
                break;
#else
                if (!idx) {
                    idx = i;
                    idx_ret = ret;
                    idx_cur = cur;
                }
#endif /* DEBUG_HFS_REC_FIND */
            }
        }
#if DEBUG_HFS_REC_FIND
        if (idx) {
            i = idx;
            ret = idx_ret;
            cur = idx_cur;
        }
#endif /* DEBUG_HFS_REC_FIND */
        HFS_DPRINTF("ret=%d HFS_NODE=%02x RECORD=%02x\n",
                    ret, curn->type, cur->type);
        if (i == 0 ||                          /* exhausted all the records */
            curn->type == HFS_NODE_LEAF) {     /* Can't descend any lower */
            break;
        }
        HFS_DPRINTF("Recurse to record: %d %08x => %08x\n",
                    i, cnid, cur->u.idxrec.uid);
        curn = hfs_bnode_get(curn->tree, cur->u.idxrec.uid);
    }
    if (ret != 0 || curn == NULL) {
        /* We won't find what we're looking for... */
        HFS_DPRINTF("NOT FOUND\n");
        return NULL;
    }
#if 0
    if (ret != 0 && cur->u.catrec.ID != cnid) {
        HFS_ERROR("%d %d\n", cur->u.catrec.ID, cnid);
        return NULL;
    }
#endif
    HFS_DPRINTF("found %p %p %d %p\n", cur, curn, i, hfs_rec_get(curn, i));
    
    return cur;
}

static inline hfs_rec_t *hfs_get_dir (hfs_btree_t *tree, HFS_cnid_t cnid,
                                      const unsigned char *name)
{
    return hfs_rec_find(tree, cnid, name, 1);
}

static hfs_rec_t *hfs_get_dirfile (hfs_rec_t *dir, HFS_cnid_t cnid,
                                   const unsigned char *name,
                                   const unsigned char *info)
{
    hfs_btree_t *tree;
    hfs_bnode_t *cur;
    hfs_rec_t *rec;
    hfs_catrec_t *frec;
    int idx;

    cur = dir->node;
    tree = cur->tree;
    for (idx = dir->num + 1;; idx++) {
        if (idx > (int)cur->nrecs) {
            HFS_DPRINTF("Go to next node %08x\n", cur->next);
            cur = hfs_bnode_next(cur);
            if (cur == NULL) {
                HFS_ERROR("Node %08x not found\n", cur->next);
                break;
            }
            idx = 1;
        }
        rec = hfs_rec_get(cur, idx);
        if (rec == NULL) {
            HFS_ERROR("Cannot get record %d\n", idx);
            return NULL;
        }
        HFS_DPRINTF("Check record %d '%s' '%s' '%s' '%s'\n",
                   idx, rec->u.catrec.name, rec->u.catrec.finfo, name, info);
        if (rec->type == RECORD_IDX) {
            continue;
        }
        frec = &rec->u.catrec;
        if (frec->type != HFS_CAT_FILE && frec->type != HFS_CAT_FILETH &&
            frec->type != HFSP_CAT_FILE && frec->type != HFSP_CAT_FILETH)
            continue;
        if (frec->pid != cnid) {
            HFS_ERROR("Out of directory %08x %08x\n", cnid, frec->pid);
            break;
        }
        if (info != NULL && memcmp(frec->finfo, info, strlen(info)) != 0)
            continue;
        /* Beware: HFS is case insensitive ! */
        if (name != NULL && strcasecmp(frec->name, name) != 0)
            continue;
        return rec;
    }

    return NULL;
}

static hfs_btree_t *hfs_btree_open (hfs_fork_t *fork, int type,
                                    int (*compare)(int type,
                                                   HFS_cnid_t cnid,
                                                   const void *more,
                                                   hfs_rec_t *rec,
                                                   int rectype))
{
    hfs_bnode_t *node;
    hfs_rec_t *rec;
    hfs_headrec_t *head;
    hfs_btree_t *newt;
    uint32_t bloc;

    bloc = hfs_get_bloc(fork, 0);
    if (bloc == (uint32_t)-1)
        return NULL;
    HFS_DPRINTF("Open btree: bloc=%08x\n", bloc);
    /* Allocate tree */
    newt = malloc(sizeof(hfs_btree_t));
    if (newt == NULL)
        return NULL;
    memset(newt, 0, sizeof(hfs_btree_t));
    newt->file = fork;
    newt->cache = NULL;
    newt->type = type;
    newt->compare = compare;
    /* Get tree header */
    HFS_DPRINTF("Get first node\n");
    node = hfs_bnode_get(newt, 0);
    if (node == NULL) {
        HFS_ERROR("Cannot get tree head\n");
        return NULL;
    }
    HFS_DPRINTF("Get first record\n");
    rec = hfs_rec_get(node, 1);
    if (rec == NULL) {
        HFS_ERROR("Cannot get first record\n");
        return NULL;
    }
    if (rec->type != RECORD_HEAD) {
        HFS_ERROR("Not an header record !\n");
        return NULL;
    }
    head = &rec->u.headrec;
    newt->head_rec = rec;
    /* Get root node */
    HFS_DPRINTF("Get root entry node: %08x\n", head->rootnode);
    newt->root_node = hfs_bnode_get(newt, head->rootnode);
    if (newt->root_node == NULL)
        return NULL;
    /* Get root directory record */
    HFS_DPRINTF("Get root folder record\n");
    newt->root_catrec = hfs_get_dir(newt, HFS_ROOT_FOLDER, "");
    HFS_DPRINTF("Found root folder record: %p\n", newt->root_catrec);
    if (newt->root_catrec == NULL)
        return NULL;
    
    return newt;
}

static int hfs_cat_compare (int type, HFS_cnid_t cnid,
                            const void *more, hfs_rec_t *rec, int rectype)
{
    hfs_idxrec_t *idxrec;
    hfs_catrec_t *catrec;
    const unsigned char *name;
    HFS_cnid_t id;
    int ret;
    
    if (type == RECORD_IDX) {
        idxrec = &rec->u.idxrec;
        id = idxrec->pid;
        name = idxrec->name;
        catrec = NULL;
    } else {
        catrec = &rec->u.catrec;
        name = catrec->name;
        if (type != RECORD_IDX &&
            (catrec->type == HFS_CAT_FOLDTH ||
             catrec->type == HFS_CAT_FILETH ||
             catrec->type == HFSP_CAT_FOLDTH ||
             catrec->type == HFSP_CAT_FILETH)) {
            HFS_DPRINTF("CHECK FOLDER %08x %08x!\n", catrec->ID, catrec->pid);
            id = catrec->ID;
        } else {
            id = catrec->pid;
        }
    }
    HFS_DPRINTF("Compare cnid (%08x '%s') vs (%08x '%s') %08x %d\n",
                cnid, (char *)more, id, name, catrec->type, rectype);
    
    /*
     * Always diff Record_IDXs, but diff RECORDS_CATs iff they match the type
     * being looked for: THREAD vs NON-THREAD (rectype).
     */
    ret = cnid - id;
    
    if (ret == 0 && type != RECORD_IDX) {
        /* out on a leaf - don't compare different types */
        if (rectype &&
            (catrec->type == HFS_CAT_FILE ||
             catrec->type == HFS_CAT_FOLDER ||
             catrec->type == HFSP_CAT_FILE ||
             catrec->type == HFSP_CAT_FOLDER)) {
            /* looking for thread and this is a file/folder - keep looking */
            ret = -1;
        } else if (!rectype &&
                   (catrec->type == HFS_CAT_FILETH ||
                    catrec->type == HFS_CAT_FOLDTH ||
                    catrec->type == HFSP_CAT_FILETH ||
                    catrec->type == HFSP_CAT_FOLDTH)) {
            /* looking for file/folder and this is a thread - keep looking */
            ret = -1;
        }
    }

    if (ret == 0 &&
       /* Apparently there is still a match - further constrain it by
        * checking if the name matches.  Name matchs should be
        * skipped if we're looking for a thread and we've reached a
        * leaf record (that case will match solely on the record
        * type and the cnid which has already been done).
        */
        (type == RECORD_IDX ||
         (!rectype &&
          (catrec->type == HFS_CAT_FILE ||
           catrec->type == HFS_CAT_FOLDER ||
           catrec->type == HFSP_CAT_FILE ||
           catrec->type == HFSP_CAT_FOLDER)))) {
        /* HFS is case insensitive - HFSP *can* be case sensitive */
        ret = strcasecmp(more, name);
    }
    
    HFS_DPRINTF("ret %d catrec %p catrec->type %08x\n",
                ret, catrec, catrec ? catrec->type : 0);
    return ret;
}

static hfs_btree_t *hfs_cat_open (hfs_vol_t *volume)
{
    HFS_DPRINTF("Open HFS catalog\n");
    return hfs_btree_open(&volume->cat_file, RECORD_CAT, &hfs_cat_compare);
}

unused static int hfs_ext_compare (unused int type, unused HFS_cnid_t cnid,
                                   unused const void *more,
                                   unused hfs_rec_t *rec)
{
    /* TODO */
    return -1;
}

static hfs_btree_t *hfs_ext_open (unused hfs_vol_t *volume)
{
    HFS_DPRINTF("Open HFS extents file\n");
#if 0
    return hfs_btree_open(&volume->ext_file, RECORD_EXT, &hfs_ext_compare);
#else
    return NULL;
#endif
}

static void hfs_map_boot_file (part_t *part, hfs_vol_t *volume,
                               uint32_t *boot_start, uint32_t *boot_offset,
                               uint32_t *boot_size)
{
    uint32_t bloc, size;

    /* Now, patch the partition to register the boot file
     * XXX: we "know" that only one extent is used...
     *      this may not be true if booting from a hard drive...
     */
    volume->boot_file->volume = volume;
    bloc = hfs_get_bloc(volume->boot_file, 0);
    if (bloc == (uint32_t)(-1)) {
        printf("Cannot get boot file start bloc\n");
        return;
    }
    size = volume->boot_file->extents[0].count * volume->bsize;
    //    printf("Map boot file bloc 0 to %08x\n", bloc);
    part_set_boot_file(part, bloc, 0, size);
    *boot_start = bloc;
    *boot_size = size;
    *boot_offset = 0;
}

static inode_t *fs_hfs_get_inode (inode_t *parent, const unsigned char *name)
{
    inode_t *new;
    hfs_fork_t *pfile, *file;
    hfs_rec_t *catrec, *extrec;
    uint32_t size;
    int i;

    pfile = parent->private;
    HFS_DPRINTF("Get inode '%s' %p %p %p %08x\n", name, pfile, pfile->catrec,
                pfile->catrec->node->tree, pfile->catrec->u.catrec.pid);
    catrec = hfs_rec_find(pfile->catrec->node->tree,
                          pfile->catrec->u.catrec.ID, name, 0);
#if 0
    extrec = hfs_rec_find(pfile->extrec->node->tree,
                          pfile->extrec->u.extrec.pid, name, 0);
#else
    extrec = NULL;
#endif
    if (catrec == NULL /* || extrec == NULL */)
        return NULL;
    new = malloc(sizeof(inode_t));
    if (new == NULL)
        return NULL;
    memset(new, 0, sizeof(inode_t));
    new->flags = 0;
    file = &catrec->u.catrec.fork;
    new->private = file;
    size = 0;
    for (i = 0; i < 8; i++) {
        if (file->extents[i].count == 0)
            break;
        size += file->extents[i].count;
    }
    size *= file->volume->bsize;
    new->size.bloc = size;
    new->size.offset = 0;
    HFS_DPRINTF("File: '%s'\n", name);
    hfs_dump_fork(new->private); 
   
    return new;
}

static void fs_hfs_put_inode (unused inode_t *inode)
{
}

static uint32_t fs_hfs_map_bloc (inode_t *inode, uint32_t bloc)
{
    return hfs_get_bloc(inode->private, bloc);
}

static inode_t *fs_hfs_get_special_inode (fs_t *fs, int type)
{
    hfs_vol_t *volume;
    inode_t *bfile, *bdir, *cur;
    hfs_rec_t *drec, *rec;
    hfs_fork_t *fork;
    uint32_t boot_start, boot_size, boot_offset;
    HFS_cnid_t id;

    volume = fs->private;
    switch (type) {
    case FILE_ROOT:
        if (fs->root == NULL) {
            volume->cat_tree = hfs_cat_open(volume);
            volume->ext_tree = hfs_ext_open(volume);
            if (volume->cat_tree == NULL /*|| volume->ext_tree == NULL*/) {
                HFS_ERROR("Can't open volume catalog/extent files\n");
                return NULL;
            }
            cur = malloc(sizeof(inode_t));
            if (cur == NULL)
                return NULL;
            memset(cur, 0, sizeof(inode_t));
            cur->flags = INODE_TYPE_DIR;
            cur->private = &volume->cat_tree->root_catrec->u.catrec.fork;
            cur->parent = NULL;
        } else {
            cur = fs->root;
        }
        return cur;
    case FILE_BOOT:
        if (fs->bootfile != NULL)
            return fs->bootfile;
        break;
    case FILE_BOOTDIR:
        if (fs->bootdir != NULL)
            return fs->bootdir;
        if (volume->boot_file != NULL) {
            bfile = malloc(sizeof(inode_t));
            if (bfile == NULL)
                return NULL;
            memset(bfile, 0, sizeof(inode_t));
            fs->bootfile = bfile;
            rec = volume->boot_file->catrec;
            bfile->name = strdup(rec->u.catrec.name);
            if (bfile->name == NULL) {
                free(bfile);
                fs->bootfile = NULL;
                return NULL;
            }
            bfile->private = volume->boot_file;
            bfile->flags = INODE_TYPE_FILE | INODE_FLAG_EXEC | INODE_FLAG_BOOT;
            fs->bootdir = fs->root;
            hfs_map_boot_file(fs->part, volume,
                              &boot_start, &boot_offset, &boot_size);
        }
        break;
    default:
        return NULL;
    }
    HFS_DPRINTF("Look for boot file (%d)\n", volume->boot_id);
    if (volume->boot_file == NULL ||
        volume->boot_file->extents[0].count == 0) {
        if (volume->boot_id != 0x00000000) {
            /* Try to find regular MacOS bootfile */
            drec = hfs_get_dir(volume->cat_tree, volume->boot_id, "");
            if (drec == NULL) {
                HFS_ERROR("Didn't find boot directory %d\n", volume->boot_id);
                return NULL;
            }
            HFS_DPRINTF("Found boot directory '%s'\n", drec->u.catrec.name);
            rec = hfs_get_dirfile(drec, volume->boot_id, NULL, "tbxi");
        } else {
            /* Try NetBSD boot */
            drec = hfs_get_dir(volume->cat_tree, HFS_ROOT_FOLDER, "");
            if (drec == NULL)
                return NULL;
            rec = hfs_get_dirfile(drec, HFS_ROOT_FOLDER, "ofwboot", NULL);
            if (rec == NULL) {
                rec = hfs_get_dirfile(drec, HFS_ROOT_FOLDER,
                                      "ofwboot.xcf", NULL);
                if (rec == NULL) {
                    rec = hfs_get_dirfile(drec, HFS_ROOT_FOLDER,
                                          "ofwboot.elf", NULL);
                }
            }
            if (rec != NULL) {
                volume->boot_id = rec->u.catrec.pid;
                drec = hfs_get_dir(volume->cat_tree, volume->boot_id, "");
            }
        }
        if (rec == NULL) {
            HFS_ERROR("Didn't find boot file\n");
            return NULL;
        }
        volume->boot_file = &rec->u.catrec.fork;
        hfs_map_boot_file(fs->part, volume,
                          &boot_start, &boot_offset, &boot_size);
        HFS_DPRINTF("boot file mapped: %08x-%08x %08x\n",
                    boot_start, boot_offset, boot_size);
#if 0
        hfs_treat_boot_file(fs->part, volume,
                            &boot_start, &boot_offset, &boot_size);
#endif
        HFS_DPRINTF("Dump boot file\n");
        hfs_dump_fork(volume->boot_file);
        HFS_DPRINTF("boot file mapped: %08x-%08x %08x\n",
                    boot_start, boot_offset, boot_size);
    } else {
        drec = hfs_get_dir(volume->cat_tree, HFS_ROOT_FOLDER, "");
        if (drec == NULL)
            return NULL;
    }
    rec = volume->boot_file->catrec;
    fork = volume->boot_file;
    HFS_DPRINTF("boot file: %p '%s' boot dir: %p '%s'\n",
                rec, rec->u.catrec.name, drec, drec->u.catrec.name);
    bfile = malloc(sizeof(inode_t));
    if (bfile == NULL)
        return NULL;
    memset(bfile, 0, sizeof(inode_t));
    fs->bootfile = bfile;
    bfile->name = strdup(rec->u.catrec.name);
    if (bfile->name == NULL) {
        free(bfile);
        return NULL;
    }
    bfile->private = fork;
    bfile->flags = INODE_TYPE_FILE | INODE_FLAG_EXEC | INODE_FLAG_BOOT;
    bfile->size.bloc = boot_size / part_blocsize(volume->part);
    bfile->size.offset = boot_size % part_blocsize(volume->part);
    HFS_DPRINTF("%s: look for parent ID: %08x\n", __func__, volume->boot_id);
    bdir = NULL;
    cur = NULL;
    if (type == FILE_BOOT) {
        cur = bfile;
    }
    for (id = volume->boot_id; id != HFS_ROOT_FOLDER;
         id = drec->u.catrec.pid) {
        drec = hfs_get_dir(volume->cat_tree, id, "");
        if (drec == NULL)
            return NULL;
        bdir = malloc(sizeof(inode_t));
        if (bdir == NULL)
            return NULL;
        memset(bdir, 0, sizeof(inode_t));
        if (id == volume->boot_id) {
            if (type == FILE_BOOTDIR)
                cur = bdir;
            fs->bootdir = bdir;
        }
        bdir->name = strdup(drec->u.catrec.name);
        if (bdir->name == NULL) {
            free(bdir);
            return NULL;
        }
        bdir->private = &drec->u.catrec.fork;
        bdir->flags = INODE_TYPE_DIR;
        bfile->parent = bdir;
        HFS_DPRINTF("%s: cache '%s' into '%s'\n",
                    __func__, bfile->name, bdir->name);
        fs_cache_add_inode(bdir, bfile);
        bfile = bdir;
    }
    bfile->parent = fs->root;
    HFS_DPRINTF("%s: cache '%s' into root dir\n", __func__, bfile->name);
    fs_cache_add_inode(fs->root, bfile);
    if (bdir == NULL) {
        bdir = fs->root;
        fs->bootdir = bdir;
        if (type == FILE_BOOTDIR)
            cur = bdir;
    }
    cur->fs = fs;
    HFS_DPRINTF("boot file: %p '%s' boot dir: %p '%s'\n",
                fs->bootfile, fs->bootfile->name,
                fs->bootdir, fs->bootdir->name);
    HFS_DPRINTF("boot fork %p rec %p %p %08x\n",
                bfile->private, rec, rec->u.catrec.fork.catrec,
                rec->u.catrec.ID);
    HFS_DPRINTF("boot dir fork %p rec %p %p %08x %08x\n",
                bdir->private, drec, drec->u.catrec.fork.catrec,
                drec->u.catrec.ID, volume->boot_id);
    HFS_DPRINTF("FS cat tree: %p\n", volume->cat_tree);

    return cur;
}

static fs_ops_t hfs_fs_ops = {
    &fs_hfs_get_inode,
    &fs_hfs_put_inode,
    &fs_hfs_map_bloc,
    &fs_hfs_get_special_inode,
};

int fs_hfs_probe (part_t *part, uint32_t *size,
                  fs_ops_t **fs_ops, unsigned char **name,
                  void **private)
{
    unsigned char buffer[512];
    HFSP_vh_t *hfsp_vh;
    HFS_vh_t *hfs_vh;
    hfs_vol_t *volume;
    uint32_t embed_offset = 0, boot_id;
    int type;

    hfs_vh = HFS_read_volhead(part, HFS_VOLHEAD_SECTOR, 0, buffer, 512);
    hfsp_vh = NULL;
    if (hfs_vh == NULL) {
        DPRINTF("Can't read HFS volume header\n");
        return -1;
    }
    type = -1;
    if (hfs_vh->signature == HFS_VOLHEAD_SIG) {
        /* HFS volume */
        printf("HFS volume\n");
        if (hfs_vh->embed_sig == HFSPLUS_VOLHEAD_SIG) {
            embed_offset = hfs_vh->embed_ext.start_block *
                hfs_vh->alloc_size / HFS_SECTOR_SIZE;
            embed_offset += hfs_vh->alloc_start;
            printf("HFSplus embedded volume offset=%08x\n", embed_offset);
            hfsp_vh = HFSP_read_volhead(part,
                                        HFS_VOLHEAD_SECTOR + embed_offset,
                                        0, buffer, 512);
            goto handle_hfsp;
        }
        boot_id = hfs_vh->finder_info[0];
        DPRINTF("HFS boot id : %d %04x\n", boot_id, boot_id);
        volume = malloc(sizeof(hfs_vol_t));
        if (volume == NULL)
            return -1;
        memset(volume, 0, sizeof(hfs_vol_t));
        HFS_DPRINTF("sig: %x %x %x\n", hfs_vh->signature,
                    hfs_vh->embed_sig, HFSPLUS_VOLHEAD_SIG);
        HFS_DPRINTF("cr: %08x mod: %08x attr: %04x count: %04x\n",
                    hfs_vh->create_date, hfs_vh->modify_date,
                    hfs_vh->attributes, hfs_vh->root_file_count);
        HFS_DPRINTF("alloc ptr: %04x blocs: %04x size: %08x bmap %04x\n",
                    hfs_vh->alloc_ptr, hfs_vh->alloc_blocs, hfs_vh->alloc_size,
                    hfs_vh->bitmap_start);
        volume->bsize = hfs_vh->alloc_size / HFS_SECTOR_SIZE;
        volume->start_offset = hfs_vh->alloc_start;
        /* Alloc file */
        volume->alloc_file.volume = volume;
        volume->alloc_file.nb_blocs = hfs_vh->alloc_size * volume->bsize;
        volume->alloc_file.extents[0].start = 0;
        volume->alloc_file.extents[0].count = hfs_vh->alloc_size;
        /* Catalog file */
        volume->cat_file.volume = volume;
        hfs_get_fork(&volume->cat_file, hfs_vh->cat_size, hfs_vh->cat_rec);
        /* Extents file */
        volume->ext_file.volume = volume;
        hfs_get_fork(&volume->ext_file, hfs_vh->ext_size, hfs_vh->ext_rec);
        *size = hfs_vh->alloc_blocs * volume->bsize;
        *name = strdup(hfs_vh->label);
        if (*name == NULL)
            return -1;
        type = FS_TYPE_HFS;
    } else {
        hfsp_vh = HFSP_read_volhead(part, HFS_VOLHEAD_SECTOR, 0, buffer, 512);
    handle_hfsp:
        if (hfsp_vh == NULL) {
            DPRINTF("Can't read HFS+ volume header\n");
            return -1;
        }
        if (hfsp_vh->signature != HFSPLUS_VOLHEAD_SIG) {
            DPRINTF("Bad HFS+ signature %02x %02x\n",
                    hfsp_vh->signature, HFSPLUS_VOLHEAD_SIG);
            return -1;
        }
        /* HFS+ volume */
        printf("HFSplus volume\n");
        volume = malloc(sizeof(hfs_vol_t));
        if (volume == NULL)
            return -1;
        memset(volume, 0, sizeof(hfs_vol_t));
        volume->embed_offset = embed_offset;
        volume->start_offset = embed_offset;
        volume->bsize = hfsp_vh->blocksize / HFS_SECTOR_SIZE;
        //        volume->bsize = 2048;
        /* Boot file */
        HFS_DPRINTF("Boot file: %d %d\n",
                    hfsp_vh->start_file.total_blocks,
                    hfsp_vh->start_file.extents[0].block_count);
        if (hfsp_vh->start_file.total_blocks != 0) {
            volume->boot_file = malloc(sizeof(hfs_fork_t));
            memset(volume->boot_file, 0, sizeof(hfs_fork_t));
            volume->boot_file->volume = volume;
            hfsp_get_fork(volume->boot_file,
                          hfsp_vh->start_file.total_blocks,
                          hfsp_vh->start_file.extents);
            boot_id = 2;
        } else {
            boot_id = hfsp_vh->finder_info[0];
        }
            DPRINTF("HFS+ boot id : %d %04x %d\n", boot_id, boot_id,
                    hfsp_vh->start_file.total_blocks);
        /* Catalog file */
        volume->cat_file.volume = volume;
        hfsp_get_fork(&volume->cat_file,
                      hfsp_vh->cat_file.total_blocks,
                      hfsp_vh->cat_file.extents);
        /* Extents file */
        volume->ext_file.volume = volume;
        hfsp_get_fork(&volume->ext_file,
                      hfsp_vh->ext_file.total_blocks,
                      hfsp_vh->ext_file.extents);
        *size = hfsp_vh->total_blocks * volume->bsize;
        type = FS_TYPE_HFSP;
    }
    volume->boot_id = boot_id;
    volume->type = type;
    HFS_DPRINTF("%s volume: type: %d bsize: %d start_offset: %d\n",
                type == FS_TYPE_HFS ? "HFS" : "HFSplus",
                volume->type, volume->bsize, volume->start_offset);
    HFS_DPRINTF("Catalog file:\n");
    hfs_dump_fork(&volume->cat_file);
    HFS_DPRINTF("Extents file:\n");
    hfs_dump_fork(&volume->ext_file);
    if (volume->boot_file != NULL) {
        HFS_DPRINTF("Boot file:\n");
        hfs_dump_fork(volume->boot_file);
    }
    *fs_ops = &hfs_fs_ops;
    HFS_DPRINTF("Set part to %p\n", part);
    volume->part = part;
    *private = volume;

    return type;
}
