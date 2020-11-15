/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <fileio.h>
#include <kernel.h>
#include <of.h>
#include <sys/socket.h>

extern int vsprintf(char *, const char *, va_list);
extern void _exit(int status);

void exit(int status);

int open(const char* name, int flags)
{
	int fd;

	/* search free file descriptor */
	for (fd=0; fd<FILEIO_MAX; ++fd) {
		if(fd_array[fd].type == FILEIO_TYPE_EMPTY) {
			break;
		}
	}
	if (fd == FILEIO_MAX) {
		printf("Can not open \"%s\" because file descriptor list is full\n", name);
		/* there is no free file descriptor available */
		return -2;
	}

	fd_array[fd].ih = of_open(name);
	if (fd_array[fd].ih == 0)
		return -1;

	fd_array[fd].type = FILEIO_TYPE_FILE;

	return fd;
}

int pre_open_ih(int fd, ihandle_t ih)
{
	if (fd_array[fd].type != FILEIO_TYPE_EMPTY)
		return -2;
	fd_array[fd].ih = ih;
	fd_array[fd].type = FILEIO_TYPE_FILE;

	return fd;
}

int socket(int domain, int type, int proto, char *mac_addr)
{
	uint8_t tmpbuf[8];
	int fd;
	phandle_t ph;

	/* search free file descriptor */
	for (fd=0; fd<FILEIO_MAX; ++fd) {
		if(fd_array[fd].type == FILEIO_TYPE_EMPTY) {
			break;
		}
	}
	if (fd == FILEIO_MAX) {
		printf("Can not open socket, file descriptor list is full\n");
		/* there is no free file descriptor available */
		return -2;
	}

	fd_array[fd].ih = of_interpret_1("my-parent", tmpbuf);
	if (fd_array[fd].ih == 0) {
		printf("Can not open socket, no parent instance\n");
		return -1;
	}
	ph = of_instance_to_package(fd_array[fd].ih);
	if (ph == -1) {
		printf("Can not open socket, no parent package\n");
		return -1;
	}
	if (of_get_mac(ph, mac_addr) < 0) {
		printf("Can not open socket, no MAC address\n");
		return -1;
	}
	fd_array[fd].type = FILEIO_TYPE_SOCKET;

	return fd;
}

int close(int fd)
{
	if (fd < 0 || fd >= FILEIO_MAX ||
	    fd_array[fd].type == FILEIO_TYPE_EMPTY)
		return -1;
	if (fd_array[fd].type == FILEIO_TYPE_FILE)
		of_close(fd_array[fd].ih);
	fd_array[fd].type = FILEIO_TYPE_EMPTY;
	return 0;
}

ssize_t read(int fd, void *buf, size_t len)
{
	if (fd < 0 || fd >= FILEIO_MAX ||
	    fd_array[fd].type == FILEIO_TYPE_EMPTY)
		return -1;

	return of_read(fd_array[fd].ih, buf, len);
}

ssize_t write (int fd, const void *buf, size_t len)
{
	char dest_buf[512];
	char *dest_buf_ptr;
	const char *dbuf = buf;
	int i;

	if (fd == 1 || fd == 2) {
		dest_buf_ptr = &dest_buf[0];
		for (i = 0; i < len && i < 256; i++)
			{
				*dest_buf_ptr++ = *dbuf++;
				if (dbuf[-1] == '\n')
					*dest_buf_ptr++ = '\r';
			}
		len = dest_buf_ptr - &dest_buf[0];
		buf = &dest_buf[0];
	}

	if(fd < 0 || fd >= FILEIO_MAX ||
	   fd_array[fd].type == FILEIO_TYPE_EMPTY)
		return -1;

	return of_write(fd_array[fd].ih, (void *)buf, len);
}

ssize_t lseek (int fd, long offset, int whence)
{
	return 0; // this syscall is unused !!!
#if 0
    if (whence != 0)
	return -1;

    of_seek (fd_array[fd], (unsigned int) (offset>>32), (unsigned int) (offset & 0xffffffffULL));

    return offset;
#endif
}

int recv(int fd, void *packet, int packet_len, int flags)
{
	return read(fd, packet, packet_len);
}

int send(int fd, const void *packet, int packet_len, int flags)
{
	return write(fd, packet, packet_len);
}

int sendto(int fd, const void *packet, int packet_len, int flags,
	   const void *sock_addr, int sock_addr_len)
{
	return send(fd, packet, packet_len, flags);
}

void exit(int status)
{
	_exit(status);
}
