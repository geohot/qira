/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libext2.h"
#include "ext2_utils.h"

static struct ext2_dir_entry_2 entry;

struct ext2_dir_entry_2 *ext2_readdir(ext2_DIR *dir)
{
	int ret;

	ret = ext2_dir_entry(dir->volume, dir->inode, dir->index, &entry);
	if (ret == -1)
		return NULL;
	dir->index = ret;

	entry.name[entry.name_len] = 0;
	return &entry;
}
