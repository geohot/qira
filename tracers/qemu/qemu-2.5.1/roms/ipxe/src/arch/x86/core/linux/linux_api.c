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

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * Implementation of most of the linux API.
 */

#include <linux_api.h>

#include <stdarg.h>
#include <asm/unistd.h>
#include <string.h>

int linux_open ( const char *pathname, int flags ) {
	return linux_syscall ( __NR_open, pathname, flags );
}

int linux_close ( int fd ) {
	return linux_syscall ( __NR_close, fd );
}

off_t linux_lseek ( int fd, off_t offset, int whence ) {
	return linux_syscall ( __NR_lseek, fd, offset, whence );
}

__kernel_ssize_t linux_read ( int fd, void *buf, __kernel_size_t count ) {
	return linux_syscall ( __NR_read, fd, buf, count );
}

__kernel_ssize_t linux_write ( int fd, const void *buf,
			       __kernel_size_t count ) {
	return linux_syscall  (  __NR_write, fd, buf, count );
}

int linux_fcntl ( int fd, int cmd, ... ) {
	long arg;
	va_list list;

	va_start ( list, cmd );
	arg = va_arg ( list, long );
	va_end ( list );

	return linux_syscall ( __NR_fcntl, fd, cmd, arg );
}

int linux_ioctl ( int fd, int request, ... ) {
	void *arg;
	va_list list;

	va_start ( list, request );
	arg = va_arg ( list, void * );
	va_end ( list );

	return linux_syscall ( __NR_ioctl, fd, request, arg );
}

int linux_poll ( struct pollfd *fds, nfds_t nfds, int timeout ) {
	return linux_syscall ( __NR_poll, fds, nfds, timeout );
}

int linux_nanosleep ( const struct timespec *req, struct timespec *rem ) {
	return linux_syscall ( __NR_nanosleep, req, rem );
}

int linux_usleep ( useconds_t usec ) {
	struct timespec ts = {
		.tv_sec = ( ( long ) ( usec / 1000000 ) ),
		.tv_nsec = ( ( long ) ( usec % 1000000 ) * 1000UL ),
	};

	return linux_nanosleep ( &ts, NULL );
}

int linux_gettimeofday ( struct timeval *tv, struct timezone *tz ) {
	return linux_syscall ( __NR_gettimeofday, tv, tz );
}

void * linux_mmap ( void *addr, __kernel_size_t length, int prot, int flags,
		    int fd, __kernel_off_t offset ) {
	return ( void * ) linux_syscall ( __SYSCALL_mmap, addr, length, prot,
					  flags, fd, offset );
}

void * linux_mremap ( void *old_address, __kernel_size_t old_size,
		      __kernel_size_t new_size, int flags ) {
	return ( void * ) linux_syscall ( __NR_mremap, old_address, old_size,
					  new_size, flags );
}

int linux_munmap ( void *addr, __kernel_size_t length ) {
	return linux_syscall ( __NR_munmap, addr, length );
}
