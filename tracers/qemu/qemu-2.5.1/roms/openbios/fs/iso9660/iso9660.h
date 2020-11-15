/*
 *
 * (c) 2005-2009 Laurent Vivier <Laurent@vivier.eu>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#ifndef __ISO9660_H__
#define __ISO9660_H__

#include "iso9660_fs.h"

typedef struct iso9660_VOLUME {
	int ucs_level;
	struct iso_primary_descriptor *descriptor;
	int fd;
} iso9660_VOLUME;

typedef struct iso9660_DIR {
	iso9660_VOLUME *volume;
	int extent;
	int len;
	int index;
	unsigned char buffer[ISOFS_BLOCK_SIZE];
} iso9660_DIR;

typedef struct iso9660_FILE {
	iso9660_VOLUME *volume;
	char *path;
	int base;			/* first extent of the file */
	int size;			/* size of the file */
	int offset;
	int current;
	unsigned char buffer[ISOFS_BLOCK_SIZE];
} iso9660_FILE;

static inline int isonum_721(char *p)
{
        return ((p[0] & 0xff)
                | ((p[1] & 0xff) << 8));
}

static inline int isonum_723(char *p)
{
        return (isonum_721(p));
}

static inline int isonum_733(char *p)
{
	return ((p[0] & 0xff) | ((p[1] & 0xff) << 8) |
		((p[2] & 0xff) << 16) | ((p[3] & 0xff) << 24));
}

extern struct iso_directory_record *iso9660_get_root_node(iso9660_VOLUME* volume);
extern struct iso_directory_record* iso9660_get_node(iso9660_VOLUME *volume, struct iso_directory_record *dirnode, const char *path);

#endif /* __ISO9660_H__ */
