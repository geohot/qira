/*
 *
 * (c) 2005-2009 Laurent Vivier <Laurent@vivier.eu>
 *
 * This file has been copied from EMILE bootloader, http://emile.sf.net
 *
 */

#include "libiso9660.h"

void iso9660_close(iso9660_FILE *file)
{
	free(file->path);
	free(file);
}
