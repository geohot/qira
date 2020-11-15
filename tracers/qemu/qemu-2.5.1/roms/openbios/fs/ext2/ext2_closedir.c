/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libext2.h"
#include "ext2.h"

void ext2_closedir(ext2_DIR *dir)
{
	if (dir == NULL)
		return;
	free(dir->inode);
	free(dir);
}
