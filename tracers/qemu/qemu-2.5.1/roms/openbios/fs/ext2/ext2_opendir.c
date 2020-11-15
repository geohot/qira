/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libext2.h"
#include "ext2.h"
#include "ext2_utils.h"

ext2_DIR* ext2_opendir(ext2_VOLUME *volume, const char *name)
{
	ext2_DIR* dir;
	int ino;
	struct ext2_inode *inode;
	int ret;

	ino = ext2_seek_name(volume, name);
	if (ino == 0)
		return NULL;

	inode = (struct ext2_inode*)malloc(sizeof(struct ext2_inode));
	if (inode == NULL)
		return NULL;

	ret = ext2_get_inode(volume, ino, inode);
	if (ret == -1) {
		free(inode);
		return NULL;
	}

	if (!S_ISDIR(inode->i_mode)) {
		free(inode);
		return NULL;
	}

	dir = (ext2_DIR*)malloc(sizeof(ext2_DIR));
	if (dir == NULL) {
		free(inode);
		return NULL;
	}
	dir->volume = (ext2_VOLUME*)volume;
	dir->inode = inode;
	dir->index = 0;

	return dir;
}
