/*
 *
 * (c) 2005-2009 Laurent Vivier <Laurent@vivier.eu>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libiso9660.h"

int iso9660_closedir(iso9660_DIR *dir)
{
	if (dir == NULL)
		return -1;

	free(dir);

	return 0;
}
