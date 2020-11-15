/*
 * <unistd.h>
 *
 * Open Hack'Ware BIOS: subset of POSIX unistd definitions
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if !defined (__OHW_UNISTD_H__)
#define __OHW_UNISTD_H__

/* size_t is defined here */
/* mode_t is defined here (SHOULD NOT !) */
/* off_t is defined here */
#include <stddef.h>

int open (const char *pathname, int flags, mode_t mode);
int close (int fd);
ssize_t read (int fd, void *buf, size_t count);
ssize_t write (int fd, const void *buf, size_t count);
enum {
    SEEK_SET = 0x01,
    SEEK_CUR = 0x02,
    SEEK_END = 0x03,
};
off_t lseek (int fd, off_t offset, int whence);
int truncate (const char *path, off_t length);
int ftruncate (int fd, off_t length);

#endif /* !defined (__OHW_UNISTD_H__) */
