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

size_t iso9660_read(iso9660_FILE *_file, char *buf, size_t count)
{
	iso9660_FILE *file = (iso9660_FILE*)_file;
	size_t read = 0;

	if ( count > (file->size  - file->offset) )
		count = file->size  - file->offset;

	while (count > 0)
	{
		size_t part;
		int offset_extent;
		int offset_index;

		offset_extent = file->base +
				    (file->offset / ISOFS_BLOCK_SIZE);
		offset_index = file->offset % ISOFS_BLOCK_SIZE;

		if (file->current != offset_extent)
		{
			if ( (offset_index == 0) &&
			     (count >= ISOFS_BLOCK_SIZE) )
			{
				/* direct i/o */

				int extents_nb;

				extents_nb = count / ISOFS_BLOCK_SIZE;

				part = extents_nb * ISOFS_BLOCK_SIZE;

				seek_io(file->volume->fd,
					offset_extent * ISOFS_BLOCK_SIZE);
				read_io(file->volume->fd, buf + read, part);

				file->offset += part;
				count -= part;
				read += part;

				continue;
			}

			file->current = offset_extent;
			seek_io(file->volume->fd,
				offset_extent * ISOFS_BLOCK_SIZE);
			read_io(file->volume->fd, file->buffer,
				ISOFS_BLOCK_SIZE);
		}

		part = ISOFS_BLOCK_SIZE - offset_index;
		if (count < part)
			part = count;

		memcpy(buf + read, file->buffer + offset_index, part);

		file->offset += part;
		count -= part;
		read += part;
	}

	return read;
}
