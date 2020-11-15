/*
 *
 * (c) 2005-2009 Laurent Vivier <Laurent@vivier.eu>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#ifndef __LIBISO9660_H__
#define __LIBISO9660_H__

#include "config.h"
#include "iso9660.h"

extern iso9660_VOLUME* iso9660_mount(int fd);
extern int iso9660_umount(iso9660_VOLUME *volume);
extern int iso9660_probe(int fd, long long offs);
extern iso9660_DIR* iso9660_opendir(iso9660_VOLUME *, const char *name);
extern iso9660_FILE* iso9660_open(iso9660_VOLUME *, const char *pathname);
extern int iso9660_closedir(iso9660_DIR *dir);
extern struct iso_directory_record *iso9660_readdir(iso9660_DIR *dir);
extern size_t iso9660_read(iso9660_FILE *file, char *buf, size_t count);
extern void iso9660_close(iso9660_FILE *file);
extern int iso9660_lseek(iso9660_FILE *file, long offset, int whence);
extern void iso9660_name(iso9660_VOLUME *volume, struct iso_directory_record * idr, char *buffer);

#endif /* __LIBISO9660_H__ */
