#ifndef __GLUE_H
#define __GLUE_H

#include "asm/types.h"
#include "config.h"
#include "libc/byteorder.h"

typedef uint64_t sector_t;

int devopen(void);

int devread(unsigned long sector, unsigned long byte_offset,
	unsigned long byte_len, void *buf);

int file_open(const char *filename);
int file_read(void *buf, unsigned long len);
int file_seek(unsigned long offset);
unsigned long file_size(void);
void file_close(void);

int mount_fs(void);

extern int using_devsize;

/*
 * some of the filesystem drivers don't correctly provide their
 * prototypes. we fix this here so we can leave them untouched.
 */

int ffs_mount (void);
int ffs_read (char *buf, int len);
int ffs_dir (char *dirname);
int ffs_embed (int *start_sector, int needed_sectors);

int vstafs_mount (void);
int vstafs_dir (char *dirname);
int vstafs_read (char *addr, int len);

int ntfs_mount (void);
int ntfs_dir (char *dirname);
int ntfs_read (char *addr, int len);

int affs_mount (void);
int affs_dir (char *dirname);
int affs_read (char *addr, int len);


#endif /* FS_H */
