/*
 * <libfs.h>
 *
 * Open Hack'Ware BIOS: file system library definitions
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
 */

#if !defined(__OHW_LIBFS_H__)
#define __OHW_LIBFS_H__

//#define DEBUG_FS 1
#define FS_SPECIAL "<special>"

static inline int is_special_file (const unsigned char *name)
{
    int splen = strlen(FS_SPECIAL);

    return name[0] == '\0' && memcmp(name + 1, FS_SPECIAL, splen) == 0 &&
        name[splen + 1] == '\0';
}

#if defined (DEBUG_FS)
#define FS_DPRINTF(fmt, args...) \
do { dprintf("%s: " fmt, __func__ , ##args); } while (0)
#else
#define FS_DPRINTF(fmt, args...) \
do { } while (0)
#endif
#define FS_ERROR(fmt, args...) \
do { printf("ERROR in %s: " fmt, __func__ , ##args); } while (0)

typedef struct fs_ops_t {
    inode_t *(*get_inode)(inode_t *parent, const unsigned char *name);
    void (*put_inode)(inode_t *inode);
    uint32_t (*map_bloc)(inode_t *inode, uint32_t bloc);
    inode_t *(*get_special_inode)(fs_t *fs, int type);
} fs_ops_t;

#define MAXNAME_LEN 1024

struct fs_t {
    int type;
    part_t *part;
    inode_t *root;
    fs_ops_t *fs_ops;
    uint32_t size;
    unsigned char *name;
    inode_t *bootfile;
    inode_t *bootdir;
    void *private;
};

struct dir_t {
    inode_t *inode;
    dirent_t *cur;
    int pos;
};

/* All internals use inodes */
struct inode_t {
    fs_t *fs;
    /* parent inode */
    inode_t *parent;
    /* Next inode at the same level */
    inode_t *next;
    /* First child inode */
    inode_t *child;
    /* Private data */
    int refcount;
    uint32_t flags;
    unsigned char *name;
    int nb_blocs;
    pos_t *blocs;
    pos_t size;
    void *private;
    uint32_t vbloc;
    uint32_t vpos;
};

/* Low-level helpers */
enum {
    FILE_UNKNOWN = -1,
    FILE_ROOT    = 0,
    FILE_BOOT,
    FILE_BOOTDIR,
};

void fs_cache_add_inode (inode_t *parent, inode_t *inode);

int fs_raw_probe (part_t *part, uint32_t *size,
                  fs_ops_t **fs_ops, unsigned char **name,
                  void **private);
int fs_ext2_probe (part_t *part, uint32_t *size,
                   fs_ops_t **fs_ops, unsigned char **name,
                   void **private);
int fs_isofs_probe (part_t *part, uint32_t *size,
                    fs_ops_t **fs_ops, unsigned char **name,
                    void **private);
int fs_hfs_probe (part_t *part, uint32_t *size,
                  fs_ops_t **fs_ops, unsigned char **name,
                  void **private);
int fs_raw_set_bootfile (part_t *part,
                         uint32_t start_bloc, uint32_t start_offset,
                         uint32_t size_bloc, uint32_t size_offset);

enum {
    FS_TYPE_UNKNOWN = -1,
    FS_TYPE_RAW     = 0,
    FS_TYPE_EXT2,
    FS_TYPE_ISOFS,
    FS_TYPE_HFS,
    FS_TYPE_HFSP,
};

#endif /* !defined(__OHW_LIBFS_H__) */
