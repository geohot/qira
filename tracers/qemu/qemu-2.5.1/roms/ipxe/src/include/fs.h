#ifndef FS_H
#define FS_H

#include <stdint.h>

//typedef uint64_t sector_t;

#ifdef IDE_DISK
int ide_probe(int drive);
int ide_read(int drive, sector_t sector, void *buffer);
#endif

#ifdef USB_DISK
int usb_probe(int drive);
int usb_read(int drive, sector_t sector, void *buffer);
#endif

#define DISK_IDE 1
#define DISK_MEM 2
#define DISK_USB 3

int devopen(const char *name, int *reopen);
int devread(unsigned long sector, unsigned long byte_offset,
	unsigned long byte_len, void *buf);

int file_open(const char *filename);
int file_read(void *buf, unsigned long len);
int file_seek(unsigned long offset);
unsigned long file_size(void);

#define PARTITION_UNKNOWN 0xbad6a7

#ifdef ELTORITO
int open_eltorito_image(int part, unsigned long *start, unsigned long *length);
#else
# define open_eltorito_image(x,y,z) PARTITION_UNKNOWN
#endif

extern int using_devsize;

#endif /* FS_H */
