/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#ifndef __EXT2_UTILS_H__
#define __EXT2_UTILS_H__

#include "ext2_fs.h"
#include "ext2.h"

/* from linux/stat.h */

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

/* utilities */

extern int ext2_probe(int fd, long long offset);
extern void ext2_get_super(int fd, struct ext2_super_block *super);
extern void ext2_read_block(ext2_VOLUME* volume, unsigned int fsblock);
extern void ext2_get_group_desc(ext2_VOLUME* volume,
				int group_id, struct ext2_group_desc *gdp);
extern int ext2_get_inode(ext2_VOLUME* volume,
			  unsigned int ino, struct ext2_inode *inode);
extern unsigned int ext2_get_block_addr(ext2_VOLUME* volume,
					struct ext2_inode *inode,
					unsigned int logical);
extern int ext2_read_data(ext2_VOLUME* volume, struct ext2_inode *inode,
			  off_t offset, char *buffer, size_t length);
extern off_t ext2_dir_entry(ext2_VOLUME *volume, struct ext2_inode *inode,
			    off_t offset, struct ext2_dir_entry_2 *entry);
extern unsigned int ext2_seek_name(ext2_VOLUME *volume, const char *name);
#endif /* __EXT2_UTILS_H__ */
