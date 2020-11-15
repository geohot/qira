/*
 *
 * (c) 2005-2009 Laurent Vivier <Laurent@vivier.eu>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libiso9660.h"

iso9660_FILE* iso9660_open(iso9660_VOLUME *volume, const char* pathname)
{
	struct iso_directory_record *root;
	struct iso_directory_record *idr;
	iso9660_FILE *file;

	root = iso9660_get_root_node(volume);
	if (root == NULL)
		return NULL;

	idr = iso9660_get_node(volume, root, pathname);
	if (idr == NULL)
		return NULL;

	file = (iso9660_FILE*)malloc(sizeof(iso9660_FILE));
	if (file == NULL)
		return NULL;

	file->base = isonum_733((char *)idr->extent);
	file->size = isonum_733((char *)idr->size);
	file->offset = 0;
	file->current = -1;
	file->volume = volume;
	file->path = strdup(pathname);

	free(idr);

	return file;
}
