/*
 * Copyright (C) 2010 Piotr Jaroszyński <p.jaroszynski@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LINUX_API_H
#define _LINUX_API_H

/** * @file
 *
 * Linux API prototypes.
 * Most of the functions map directly to linux syscalls and are the equivalent
 * of POSIX functions with the linux_ prefix removed.
 */

FILE_LICENCE(GPL2_OR_LATER);

#include <bits/linux_api.h>
#include <bits/linux_api_platform.h>

#include <stdint.h>

#define __KERNEL_STRICT_NAMES
#include <linux/types.h>
#include <linux/posix_types.h>
typedef __kernel_pid_t pid_t;
typedef __kernel_suseconds_t suseconds_t;
typedef __kernel_loff_t loff_t;
#include <linux/time.h>
#include <linux/mman.h>
#include <linux/fcntl.h>
#include <linux/ioctl.h>
#include <linux/poll.h>
typedef unsigned long nfds_t;
typedef uint32_t useconds_t;
#define MAP_FAILED ( ( void * ) -1 )
#define SEEK_SET 0

extern long linux_syscall ( int number, ... );

extern int linux_open ( const char *pathname, int flags );
extern int linux_close ( int fd );
extern off_t linux_lseek ( int fd, off_t offset, int whence );
extern __kernel_ssize_t linux_read ( int fd, void *buf, __kernel_size_t count );
extern __kernel_ssize_t linux_write ( int fd, const void *buf,
				      __kernel_size_t count );
extern int linux_fcntl ( int fd, int cmd, ... );
extern int linux_ioctl ( int fd, int request, ... );
extern int linux_poll ( struct pollfd *fds, nfds_t nfds, int timeout );
extern int linux_nanosleep ( const struct timespec *req, struct timespec *rem );
extern int linux_usleep ( useconds_t usec );
extern int linux_gettimeofday ( struct timeval *tv, struct timezone *tz );
extern void * linux_mmap ( void *addr, __kernel_size_t length, int prot,
			   int flags, int fd, off_t offset );
extern void * linux_mremap ( void *old_address, __kernel_size_t old_size,
			     __kernel_size_t new_size, int flags );
extern int linux_munmap ( void *addr, __kernel_size_t length );

extern const char * linux_strerror ( int errnum );

#endif /* _LINUX_API_H */
