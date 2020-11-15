/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#ifndef __LIBEXT2_H__
#define __LIBEXT2_H__

#include "config.h"
#include "ext2.h"

extern ext2_VOLUME* ext2_mount(int fd);
extern int ext2_umount(ext2_VOLUME *volume);
extern ext2_DIR* ext2_opendir(ext2_VOLUME *, const char *name);
extern struct ext2_dir_entry_2* ext2_readdir(ext2_DIR* dir);
extern void ext2_closedir(ext2_DIR *dir);
extern ext2_FILE* ext2_open(ext2_VOLUME *, const char* pathname);
extern size_t ext2_read(ext2_FILE *file, void *buf, size_t count);
extern void ext2_close(ext2_FILE *file);
extern int ext2_lseek(ext2_FILE *file, long offset, int whence);

#endif /* __LIBEXT2_H__ */
