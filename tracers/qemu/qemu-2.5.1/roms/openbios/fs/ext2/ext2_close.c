/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libext2.h"

void ext2_close(ext2_FILE *file)
{
	if (file == NULL)
		return;
	free(file->inode);
	free(file->path);
	free(file);
}
