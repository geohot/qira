/*
 *
 * (c) 2005-2009 Laurent Vivier <Laurent@vivier.eu>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libiso9660.h"
#include "libopenbios/bindings.h"
#include "libc/diskio.h"

#define offsetof(t,m)	((long)&(((t *)0)->m))

static void read_extent(iso9660_DIR *dir)
{
	seek_io(dir->volume->fd, dir->extent * ISOFS_BLOCK_SIZE);
	read_io(dir->volume->fd, dir->buffer, ISOFS_BLOCK_SIZE);

	dir->len -= ISOFS_BLOCK_SIZE;
	dir->extent ++;
	dir->index = 0;
}

struct iso_directory_record *iso9660_readdir(iso9660_DIR *dir)
{
	struct iso_directory_record *idr;

	if (dir->index >
	    ISOFS_BLOCK_SIZE - offsetof(struct iso_directory_record, name[0]))
	{
		if (dir->len <= 0)
			return NULL;

		read_extent(dir);
	}

	idr = (struct iso_directory_record *) &dir->buffer[dir->index];
	if (idr->length[0] == 0)  {
		if (dir->len <= 0)
			return NULL;

		read_extent(dir);
		idr = (struct iso_directory_record *) &dir->buffer[dir->index];
	}

	dir->index += dir->buffer[dir->index];

	return idr;
}
