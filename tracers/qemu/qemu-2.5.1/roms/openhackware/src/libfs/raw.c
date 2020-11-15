/*
 * <raw.c>
 *
 * Open Hack'Ware BIOS raw file system management
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

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"
#include "../libpart/libpart.h"
#include "libfs.h"

/* Raw filesystem (ie no filesystem) */
static inode_t *fs_raw_get_inode (inode_t *parent, const unsigned char *name)
{
    inode_t *new;
    fs_t *fs;
    int flags;

    if (parent != NULL) {
        return NULL;
    }
    /* Open root inode */
    flags = INODE_TYPE_DIR;
    fs = NULL;
    new = malloc(sizeof(inode_t));
    memset(new, 0, sizeof(inode_t));
    new->flags = flags;
    new->name = strdup(name);

    return new;
}

static void fs_raw_put_inode (inode_t *inode)
{
    free(inode);
}

static uint32_t fs_raw_map_bloc (unused inode_t *inode, uint32_t bloc)
{
    if (inode != NULL
        /* XXX: can't figure out why I did this... */
        /* && inode == inode->fs->bootfile*/
        )
         bloc += inode->blocs[0].bloc;

    return bloc;
}

static inode_t *fs_raw_get_special_inode (fs_t *fs, int type)
{
    const unsigned char *name;
    inode_t *new, *parent, **inp;
    int flags;

    new = NULL;
    name = NULL;
    parent = NULL;
    inp = NULL;
    flags = 0;
    switch (type) {
    case FILE_ROOT:
        if (fs->root != NULL) {
            new = fs->root;
        } else {
            flags = INODE_TYPE_DIR;
            parent = NULL;
            name = NULL;
            inp = &fs->root;
        }
        break;
    case FILE_BOOT:
        if (fs->bootfile != NULL) {
            dprintf("bootfile already exists\n");
            new = fs->bootfile;
        } else {
            new = part_private_get(fs_part(fs));
            if (fs->bootdir == NULL) {
                dprintf("Get boot directory\n");
                fs->bootdir = fs_raw_get_special_inode(fs, FILE_BOOTDIR);
            }
            parent = fs->bootdir;
            if (new != NULL) {
                dprintf("Fix bootfile\n");
                new->parent = parent;
                new->fs = fs;
            } else {
                dprintf("New bootfile\n");
                flags = INODE_TYPE_FILE | INODE_FLAG_EXEC | INODE_FLAG_BOOT;
                name = "ofwboot";
                inp = &fs->bootfile;
            }
        }
        break;
    case FILE_BOOTDIR:
        if (fs->bootdir != NULL) {
            new = fs->bootdir;
        } else {
            flags = INODE_TYPE_DIR;
            parent = fs->root;
            name = "boot";
            inp = &fs->bootdir;
        }
        break;
    default:
        return NULL;
    }
    if (new == NULL) {
        new = malloc(sizeof(inode_t));
        memset(new, 0, sizeof(inode_t));
        new->flags = flags;
        new->parent = parent;
        if (name != NULL)
            new->name = strdup(name);
        new->fs = fs;
        *inp = new;
    }
    
    return new;
}

static fs_ops_t fs_ops_raw = {
    &fs_raw_get_inode,
    &fs_raw_put_inode,
    &fs_raw_map_bloc,
    &fs_raw_get_special_inode,
};

int fs_raw_set_bootfile (part_t *part,
                         uint32_t start_bloc, uint32_t start_offset,
                         uint32_t size_bloc, uint32_t size_offset)
{
    inode_t *new;

    new = malloc(sizeof(inode_t));
    if (new == NULL)
        return -1;
    DPRINTF("%s: pos %d %d size %d %d\n", __func__, start_bloc, start_offset,
            size_bloc, size_offset);
    memset(new, 0, sizeof(inode_t));
    new->flags = INODE_TYPE_FILE | INODE_FLAG_EXEC | INODE_FLAG_BOOT;
    new->name = "ofwboot";
    new->blocs[0].bloc = start_bloc;
    new->blocs[0].offset = start_offset;
    new->size.bloc = size_bloc;
    new->size.offset = size_offset;
    new->nb_blocs = size_bloc;
    part_private_set(part, new);

    return 0;
}

int fs_raw_probe (part_t *part, uint32_t *size,
                  fs_ops_t **fs_ops, unsigned char **name,
                  unused void **private)
{
    DPRINTF("%s: %p map_bloc %p\n", __func__, &fs_ops_raw, &fs_raw_map_bloc);
    *fs_ops = &fs_ops_raw;
    *name = "Raw FS";
    *size = part_size(part);

    return FS_TYPE_RAW;
}
