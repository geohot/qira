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

size_t ext2_read(ext2_FILE *file, void *buf, size_t count)
{
	int ret;

	ret = ext2_read_data(file->volume, file->inode, file->offset,
			     buf, count);
	if (ret == -1)
		return -1;
	file->offset += ret;
	return ret;
}
