/*
 *
 * (c) 2005-2009 Laurent Vivier <Laurent@vivier.eu>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libiso9660.h"

int iso9660_lseek(iso9660_FILE *_file, long offset, int whence)
{
	iso9660_FILE *file = (iso9660_FILE*)_file;
	long new_offset;

	switch(whence)
	{
	case SEEK_SET:
		new_offset = offset;
		break;
	case SEEK_CUR:
		new_offset = file->offset + offset;
		break;
	case SEEK_END:
		new_offset = file->size + offset;
		break;
	default:
		return -1;
	}

	if ( (new_offset < 0) || (new_offset > file->size) )
		return -1;

	file->offset = new_offset;

	return new_offset;
}
