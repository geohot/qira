/*
 * <fs.c>
 *
 * Open Hack'Ware BIOS file systems management
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
#include "libfs.h"
#undef FS_DPRINTF
#define FS_DPRINTF(fmt, args...) do { } while (0)

static int special_file_get_type (const unsigned char *name)
{
    int ret;

    if (strcmp(name, "root") == 0)
        ret = FILE_ROOT;
    else if (strcmp(name, "boot") == 0)
        ret = FILE_BOOT;
    else if (strcmp(name, "bootdir") == 0)
        ret = FILE_BOOTDIR;
    else
        ret = FILE_UNKNOWN;

    return ret;
}

void fs_cache_add_inode (inode_t *parent, inode_t *inode)
{
    inode_t **cur;

    if (parent == NULL || inode == NULL)
        return;
    FS_DPRINTF("Add inode '%s' to '%s' cache\n", inode->name, parent->name);
    for (cur = &parent->child; *cur != NULL; cur = &((*cur)->next)) {
        if (strcmp((*cur)->name, inode->name) == 0) {
            return;
        }
    }
    *cur = inode;
}

static inode_t *fs_cache_get_inode (inode_t *parent,
                                    const unsigned char *name)
{
    inode_t *cur, *rec;
    int dec;

    FS_DPRINTF("Look for '%s' into '%s' cache\n", name, parent->name);
    if (name == NULL || parent == NULL)
        return NULL;
    if (name[0] == '/' && name[1] == '\0')
        return parent->fs->root;
    if (is_special_file(name))
        dec = strlen(FS_SPECIAL) + 2;
    else
        dec = 0;
    for (cur = parent->child; cur != NULL; cur = cur->next) {
        if (strcmp(cur->name + dec, name + dec) == 0) {
            cur->refcount++;
            for (rec = parent; rec != NULL; rec = rec->parent)
                rec->refcount++;
            break;
        }
    }
    cur = NULL;

    return cur;
}

static void fs_cache_put_inode (inode_t *inode)
{
    void (*put_inode)(inode_t *inode);
    inode_t *cur, **upd;

    if (inode != NULL && --inode->refcount == 0) {
        if (inode->parent == NULL)
            return;
        fs_cache_put_inode(inode->parent);
        upd = &inode->parent->child;
        for (cur = *upd; cur != NULL; cur = cur->next) {
            if (cur == inode) {
                (*upd) = cur->next;
                put_inode = inode->fs->fs_ops->put_inode;
                (*put_inode)(cur);
                FS_DPRINTF("Free inode '%s' from '%s' cache\n",
                           inode->name, inode->parent->name);
                free(cur);
                return;
            }
            upd = &cur;
        }
        FS_ERROR("didn't find inode in list !\n");
    }
}

static inode_t *fs_get_inode (inode_t *parent, const unsigned char *name)
{
    inode_t *(*get_inode)(inode_t *parent, const unsigned char *name);
    inode_t *cur;

    if (parent == NULL) {
        FS_ERROR("Invalide inode '%s' (NULL)\n", name);
        return NULL;
    } else {
        if (fs_inode_get_type(parent) != INODE_TYPE_DIR) {
            FS_ERROR("Try to recurse in a non-directory inode (%d)\n",
                     parent->flags);
            return NULL;
        }
    }
    if (is_special_file(name)) {
        int type;
        /* Special files */
        FS_DPRINTF("look for special file '%s'\n",
                   name + strlen(FS_SPECIAL) + 2);
        type = special_file_get_type(name + strlen(FS_SPECIAL) + 2);
        if (type == FILE_UNKNOWN) {
            FS_ERROR("Unknown special file '%s'\n",
                     name + strlen(FS_SPECIAL) + 2);
            return NULL;
        }
        cur = (*parent->fs->fs_ops->get_special_inode)(parent->fs, type);
        FS_DPRINTF("boot file: %p '%s' %p boot dir: %p '%s' %p\n",
                   parent->fs->bootfile, parent->fs->bootfile->name,
                   &parent->fs->bootfile,
                   parent->fs->bootdir, parent->fs->bootdir->name,
                   &parent->fs->bootdir);
        switch (type) {
        case FILE_ROOT:
            parent->fs->root = cur;
            cur->parent = NULL;
            cur->fs = parent->fs;
            cur->name = strdup("");
            return cur;
        case FILE_BOOT:
            parent->fs->bootfile = cur;
            break;
        case FILE_BOOTDIR:
            parent->fs->bootdir = cur;
            break;
        }
#if 0
        parent = cur->parent;
#else
        cur->fs = parent->fs;
        return cur;
#endif
    } else {
        FS_DPRINTF("look for file '%s' in %p '%s'\n", name, parent,
                   parent->name);
        DPRINTF("look for file '%s' in %p '%s'\n", name, parent,
                   parent->name);
        cur = fs_cache_get_inode(parent, name);
        if (cur != NULL) {
            FS_DPRINTF("found inode '%s' %p in cache\n", name, cur);
            DPRINTF("found inode '%s' %p in cache\n", name, cur);
            return cur;
        }
        get_inode = parent->fs->fs_ops->get_inode;
        cur = (*get_inode)(parent, name);
        cur->name = strdup(name);
    }
    if (cur != NULL) {
        cur->parent = parent;
        cur->fs = parent->fs;
        fs_cache_add_inode(parent, cur);
        FS_DPRINTF("Inode '%s' in '%s': %d blocs size %d %d\n",
                   name, parent->name, cur->nb_blocs, cur->size.bloc,
                   cur->size.offset);
        DPRINTF("Inode '%s' in '%s': %d blocs size %d %d\n",
                name, parent->name, cur->nb_blocs, cur->size.bloc,
                cur->size.offset);
    } else {
        FS_ERROR("Inode '%s' not found in '%s'\n", name, parent->name);
    }

    return cur;
}

static inline void fs_put_inode (inode_t *inode)
{
    fs_cache_put_inode(inode);
}

static inode_t *_fs_walk (inode_t *parent, const unsigned char *name)
{
    unsigned char tmpname[MAXNAME_LEN], *sl;
    inode_t *new, *subdir;
    
    FS_DPRINTF("'%s' %p\n", name, parent);
    DPRINTF("'%s' %p\n", name, parent);
    for (; *name == '/'; name++)
        continue;
    DPRINTF("'%s' %p\n", name, parent);
    strcpy(tmpname, name);
    sl = strchr(tmpname, '/');
    if (sl != NULL) {
        *sl = '\0';
        subdir = fs_get_inode(parent, tmpname);
        if (subdir == NULL)
            return NULL;
        new = _fs_walk(subdir, sl + 1);
    } else {
        new = fs_get_inode(parent, tmpname);
    }

    return new;
}

static inode_t *fs_walk (inode_t *parent, const unsigned char *name)
{
    unsigned char tmpname[MAXNAME_LEN];
    int len;
    
    FS_DPRINTF("'%s' %p\n", name, parent);
    DPRINTF("'%s' %p %p\n", name, parent, parent->fs->root);
    len = strlen(name);
    memcpy(tmpname, name, len + 1);
    if (tmpname[len - 1] == '/')
        tmpname[--len] = '\0';
    if (parent == parent->fs->root && tmpname[0] == '\0')
        return parent->fs->root;

    return _fs_walk(parent, tmpname);
}

static unsigned char *fs_inode_get_path (inode_t *inode)
{
    unsigned char tmpname[MAXNAME_LEN], *pname;
    int len;
    inode_t *parent;

    parent = inode->parent;
    if (parent == NULL || (inode->name[0] == '/' && inode->name[1] == '\0')) {
        FS_DPRINTF("Reached root node '/'\n");
        return strdup("/");
    }
    FS_DPRINTF("Recurse to root '%s'...\n", inode->name);
    pname = fs_inode_get_path(parent);
    FS_DPRINTF("'%s' '%s'\n", pname, inode->name);
    len = strlen(pname);
    memcpy(tmpname, pname, len);
    if (tmpname[len - 1] != '/')
        tmpname[len++] = '/';
    strcpy(tmpname + len, inode->name);
    free(pname);
    FS_DPRINTF(" => '%s'\n", tmpname);

    return strdup(tmpname);
}

static inline uint32_t fs_map_bloc (inode_t *inode, uint32_t bloc)
{
    FS_DPRINTF("%s: inode %p bloc %d %p %p %p\n", __func__, inode, bloc,
               inode->fs, inode->fs->fs_ops, inode->fs->fs_ops->map_bloc);
    return (*inode->fs->fs_ops->map_bloc)(inode, bloc);
}

fs_t *fs_probe (part_t *part, int set_raw)
{
    fs_t *new;
    inode_t fake_inode;
    fs_ops_t *fs_ops = NULL;
    unsigned char *name = NULL;
    void *private = NULL;
    uint32_t size = 0;
    int type = FS_TYPE_UNKNOWN;

    FS_DPRINTF("\n");
    if (set_raw == 2) {
        DPRINTF("Check raw only\n");
        goto raw_only;
    }
    DPRINTF("Probe ext2\n");
    type = fs_ext2_probe(part, &size, &fs_ops, &name, &private);
    if (type == FS_TYPE_UNKNOWN) {
        DPRINTF("Probe isofs\n");
        type = fs_isofs_probe(part, &size, &fs_ops, &name, &private);
        if (type == FS_TYPE_UNKNOWN) {
            DPRINTF("Probe HFS\n");
            type = fs_hfs_probe(part, &size, &fs_ops, &name, &private);
            if (set_raw) {
                DPRINTF("Probe raw\n");
            raw_only:
                type = fs_raw_probe(part, &size, &fs_ops, &name, &private);
            }
            if (type == FS_TYPE_UNKNOWN) {
                FS_ERROR("FS not identified\n");
                return NULL;
            }
        }
    }
    if (fs_ops == NULL || size == 0) {
        FS_ERROR("Missing param: %p %d\n", fs_ops, size);
        return NULL;
    }
    new = malloc(sizeof(fs_t));
    if (new == NULL)
        return NULL;
    new->type = type;
    new->part = part;
    new->size = size;
    new->fs_ops = fs_ops;
    new->name = name;
    new->private = private;
    /* Get root inode */
    memset(&fake_inode, 0, sizeof(inode_t));
    fake_inode.name = "fake_root";
    fake_inode.fs = new;
    fake_inode.refcount = 1;
    fs_get_inode(&fake_inode, "\0" FS_SPECIAL "\0root");
    if (new->root == NULL) {
        FS_ERROR("Didn't find root inode\n");
        free(new);
        return NULL;
    }
    FS_DPRINTF("fs: %p root: %p root fs: %p\n", new, new->root, new->root->fs);
    FS_DPRINTF("OK\n");

    return new;
}

dir_t *fs_opendir (fs_t *fs, const unsigned char *name)
{
    inode_t *inode;
    dir_t *new;

    FS_DPRINTF("'%s'\n", name);
    inode = fs_walk(fs->root, name);
    if (inode == NULL)
        return NULL;
    new = malloc(sizeof(dir_t));
    new->inode = inode;

    return new;
}

dirent_t *fs_readdir (dir_t *dir)
{
    void (*put_inode)(inode_t *inode);
    inode_t *inode;

    inode = fs_get_inode(dir->inode, NULL);
    if (inode == NULL)
        return NULL;
    if (dir->cur == NULL) {
        dir->cur = malloc(sizeof(dirent_t));
        dir->cur->dir = dir;
    } else {
        put_inode = dir->inode->fs->fs_ops->put_inode;
        (*put_inode)(dir->cur->inode);
    }
    dir->cur->inode = inode;
    dir->cur->dname = inode->name;

    return dir->cur;
}

unsigned char *fs_get_path (dirent_t *dirent)
{
    return fs_inode_get_path(dirent->inode);
}

void fs_closedir (dir_t *dir)
{
    void (*put_inode)(inode_t *inode);

    if (dir->cur != NULL) {
        put_inode = dir->inode->fs->fs_ops->put_inode;
        (*put_inode)(dir->cur->inode);
        free(dir->cur);
    }
    free(dir);
}

inode_t *fs_open (fs_t *fs, const unsigned char *name)
{
    inode_t *inode;

    FS_DPRINTF("'%s'\n", name);
    inode = fs_walk(fs->root, name);
    if (inode != NULL)
        fs_seek(inode, 0, 0);

    return inode;
}

int fs_seek (inode_t *inode, uint32_t bloc, uint32_t pos)
{
    if (inode == NULL || inode->fs == NULL) {
        ERROR("%s: no inode / fs ! %p %p\n", __func__, inode,
              inode == NULL ? NULL : inode->fs);
        return -1;
    }
    FS_DPRINTF("%08x %08x\n", bloc, pos);
    if (part_seek(inode->fs->part, fs_map_bloc(inode, bloc), pos) == -1)
        return -1;
    inode->vbloc = bloc;
    inode->vpos = pos;

    return 0;
}

int fs_read (inode_t *inode, void *buffer, int len)
{
    uint32_t bsize, total;
    int done, tmp;
    
    bsize = part_blocsize(inode->fs->part);
    total = 0;
    if (fs_seek(inode, inode->vbloc, inode->vpos) < 0)
        return -1;
    for (; len != 0; len -= done) {
        tmp = bsize - inode->vpos;
        if (len < tmp)
            tmp = len;
        done = part_read(inode->fs->part, buffer, tmp);
        if (done < 0)
            return -1;
        inode->vpos += done;
        if (inode->vpos >= bsize) {
            inode->vbloc++;
            inode->vpos -= bsize;
        }
        buffer += done;
        total += done;
    }

    return total;
}

int fs_write (inode_t *inode, const void *buffer, unused int len)
{
    uint32_t bsize, total;
    int done, tmp;
    
    bsize = part_blocsize(inode->fs->part);
    total = 0;
    for (; len != 0; len -= done) {
        tmp = bsize - inode->vpos;
        if (len < tmp)
            tmp = len;
        done = part_write(inode->fs->part, buffer, tmp);
        if (done < 0)
            return -1;
        inode->vpos += done;
        if (inode->vpos >= bsize) {
            inode->vbloc++;
            inode->vpos -= bsize;
            if (fs_seek(inode, inode->vbloc, inode->vpos) < 0)
                return -1;
        }
        buffer += done;
        total += done;
    }

    return total;
}

void fs_close (inode_t *inode)
{
    fs_put_inode(inode);
}

uint32_t fs_inode_get_type (inode_t *inode)
{
    return inode->flags & INODE_TYPE_MASK;
}

uint32_t fs_inode_get_flags (inode_t *inode)
{
    return inode->flags & INODE_FLAG_MASK;
}

uint32_t fs_inode_get_size (inode_t *inode)
{
    DPRINTF("%s: (%d * %d) + %d\n", __func__, inode->size.bloc,
            part_blocsize(inode->fs->part), inode->size.offset);
    return (inode->size.bloc * part_blocsize(inode->fs->part)) +
        inode->size.offset;
}

part_t *fs_part (fs_t *fs)
{
    return fs->part;
}

uint32_t fs_get_type (fs_t *fs)
{
    return fs->type;
}

part_t *fs_inode_get_part (inode_t *inode)
{
    return inode->fs->part;
}

inode_t *fs_get_bootdir (fs_t *fs)
{
    FS_DPRINTF("fs: %p root: %p root fs: %p\n", fs, fs->root, fs->root->fs);
    if (fs->bootdir == NULL) {
        fs->bootdir = fs_get_inode(fs->root, "\0" FS_SPECIAL "\0bootdir");
    }
    FS_DPRINTF("fs: %p root: %p root fs: %p\n", fs, fs->root, fs->root->fs);
    FS_DPRINTF("boot file: %p '%s' %p boot dir: %p '%s' %p\n",
               fs->bootfile, fs->bootfile->name, &fs->bootfile,
               fs->bootdir, fs->bootdir->name, &fs->bootdir);

    return fs->bootdir;
}
unsigned char *fs_get_boot_dirname (fs_t *fs)
{
    if (fs->bootdir == NULL) {
        fs_get_bootdir(fs);
        if (fs->bootdir == NULL)
            return NULL;
    }
    FS_DPRINTF("boot file: %p '%s' boot dir: %p '%s'\n",
               fs->bootfile, fs->bootfile->name,
               fs->bootdir, fs->bootdir->name);

    return fs_inode_get_path(fs->bootdir);
}

inode_t *fs_get_bootfile (fs_t *fs)
{
    FS_DPRINTF("fs: %p root: %p root fs: %p\n", fs, fs->root, fs->root->fs);
    FS_DPRINTF("boot file: %p '%s' %p boot dir: %p '%s' %p\n",
               fs->bootfile, fs->bootfile->name, &fs->bootfile,
               fs->bootdir, fs->bootdir->name, &fs->bootdir);
    if (fs->bootfile == NULL) {
        if (fs->bootdir == NULL)
            fs_get_bootdir(fs);
        if (fs->bootdir == NULL)
            return NULL;
        fs->bootfile = fs_get_inode(fs->bootdir, "\0" FS_SPECIAL "\0boot");
    }
    FS_DPRINTF("fs: %p root: %p root fs: %p\n", fs, fs->root, fs->root->fs);
    FS_DPRINTF("boot file: %p '%s' %p boot dir: %p '%s' %p\n",
               fs->bootfile, fs->bootfile->name, &fs->bootfile,
               fs->bootdir, fs->bootdir->name, &fs->bootdir);

    return fs->bootfile;
}
