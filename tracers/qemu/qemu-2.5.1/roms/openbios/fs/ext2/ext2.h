/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#ifndef __EXT2_H__
#define __EXT2_H__

#include "ext2_fs.h"

typedef struct ext2_VOLUME {
        int fd;
	struct ext2_super_block *super;
	unsigned int current;
	char *buffer;
} ext2_VOLUME;

typedef struct ext2_DIR {
        ext2_VOLUME *volume;
	struct ext2_inode *inode;
	off_t index;
} ext2_DIR;

typedef struct ext2_FILE {
        ext2_VOLUME *volume;
	struct ext2_inode *inode;
	off_t offset;
	char *path;
} ext2_FILE;
#endif /* __LIBEXT2_H__ */
