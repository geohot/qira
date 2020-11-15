/*
 *   Creation Date: <2003/12/07 19:36:00 samuel>
 *   Time-stamp: <2004/01/07 19:28:43 samuel>
 *
 *	<diskio.c>
 *
 *	I/O wrappers
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/diskio.h"

//#define CONFIG_DEBUG_DISKIO
#ifdef CONFIG_DEBUG_DISKIO
#define DPRINTF(fmt, args...)                   \
    do { printk(fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...)
#endif

typedef struct {
	ihandle_t ih;
	int	do_close;
	xt_t	read_xt;
	xt_t	seek_xt;

	xt_t	reopen_xt;
	xt_t	tell_xt;
	xt_t	get_path_xt;
	xt_t	get_fstype_xt;
	xt_t	open_nwrom_xt;
	xt_t	volume_name_xt;
} priv_fd_t;

#define MAX_FD 32
static priv_fd_t *file_descriptors[MAX_FD];

static int
lookup_xt( ihandle_t ih, const char *method, xt_t *xt )
{
	if( *xt )
		return 0;
	*xt = find_ih_method( method, ih );
	return (*xt) ? 0:1;
}

int
open_ih( ihandle_t ih )
{
	xt_t read_xt=0, seek_xt=0;
	priv_fd_t *fdp;
	int fd;

	if( !ih || lookup_xt(ih, "read", &read_xt) )
		return -1;
	if( lookup_xt(ih, "seek", &seek_xt) )
		return -1;

	for (fd=0; fd<MAX_FD; fd++)
		if(file_descriptors[fd]==NULL)
			break;
	if(fd==MAX_FD)
		return -1;

	fdp = malloc( sizeof(*fdp) );
	/* Better clear the fd, as it
	 * contains valuable information
	 */
	memset(fdp, 0, sizeof(*fdp));
	fdp->ih = ih;
	fdp->read_xt = read_xt;
	fdp->seek_xt = seek_xt;
	fdp->do_close = 0;

	file_descriptors[fd]=fdp;
        DPRINTF("%s(0x%lx) = %d\n", __func__, (unsigned long)ih, fd);
	return fd;
}

int
open_io( const char *spec )
{
	int fd;
	ihandle_t ih = open_dev( spec );
	priv_fd_t *fdp;

        DPRINTF("%s(%s)\n", __func__, spec);
	if( !ih )
		return -1;

	if( (fd=open_ih(ih)) == -1 ) {
		close_dev( ih );
		return -1;
	}

	fdp = file_descriptors[fd];
	fdp->do_close = 1;

	return fd;
}

int
reopen( int fd, const char *filename )
{
	priv_fd_t *fdp = file_descriptors[fd];
	int ret;

	if( lookup_xt(fdp->ih, "reopen", &fdp->reopen_xt) )
		return -1;

	push_str( filename );
	call_package( fdp->reopen_xt, fdp->ih );
        ret = (POP() == (ucell)-1)? 0 : -1;

        DPRINTF("%s(%d, %s) = %d\n", __func__, fd, filename, ret);
	return ret;
}

int
reopen_nwrom( int fd )
{
	priv_fd_t *fdp = file_descriptors[fd];

        DPRINTF("%s(%d)\n", __func__, fd);
	if( lookup_xt(fdp->ih, "open-nwrom", &fdp->open_nwrom_xt) )
		return -1;
	call_package( fdp->open_nwrom_xt, fdp->ih );
        return (POP() == (ucell)-1)? 0 : -1;
}

ihandle_t
get_ih_from_fd( int fd )
{
	priv_fd_t *fdp = file_descriptors[fd];
	return fdp->ih;
}

const char *
get_file_path( int fd )
{
	priv_fd_t *fdp = file_descriptors[fd];
	if( lookup_xt(fdp->ih, "get-path", &fdp->get_path_xt) )
		return NULL;
	call_package( fdp->get_path_xt, fdp->ih );
	return (char*)cell2pointer(POP());
}

const char *
get_volume_name( int fd )
{
	priv_fd_t *fdp = file_descriptors[fd];
	if( lookup_xt(fdp->ih, "volume-name", &fdp->volume_name_xt) )
		return NULL;
	call_package( fdp->volume_name_xt, fdp->ih );
	return (char*)cell2pointer(POP());
}

const char *
get_fstype( int fd )
{
	priv_fd_t *fdp = file_descriptors[fd];
	if( lookup_xt(fdp->ih, "get-fstype", &fdp->get_fstype_xt) )
		return NULL;
	call_package( fdp->get_fstype_xt, fdp->ih );
	return (char*)cell2pointer(POP());
}

int
read_io( int fd, void *buf, size_t cnt )
{
	priv_fd_t *fdp;
	ucell ret;

        DPRINTF("%s(%d, %p, %u)\n", __func__, fd, buf, cnt);
	if (fd != -1) {
		fdp = file_descriptors[fd];

		PUSH( pointer2cell(buf) );
		PUSH( cnt );
		call_package( fdp->read_xt, fdp->ih );
		ret = POP();

		if( !ret && cnt )
			ret = -1;
	} else {
		ret = -1;
	}

	return ret;
}

int
seek_io( int fd, long long offs )
{
	priv_fd_t *fdp;

        DPRINTF("%s(%d, %lld)\n", __func__, fd, offs);
	if (fd != -1) {
		fdp = file_descriptors[fd];
		
		DPUSH( offs );
		call_package( fdp->seek_xt, fdp->ih );
		return ((((cell)POP()) >= 0)? 0 : -1);
	} else {
		return -1;
	}
}

long long
tell( int fd )
{
	priv_fd_t *fdp = file_descriptors[fd];
	long long offs;

	if( lookup_xt(fdp->ih, "tell", &fdp->tell_xt) )
		return -1;
	call_package( fdp->tell_xt, fdp->ih );
	offs = DPOP();
        DPRINTF("%s(%d) = %lld\n", __func__, fd, offs);
	return offs;
}

int
close_io( int fd )
{
	priv_fd_t *fdp;

        DPRINTF("%s(%d)\n", __func__, fd);
	if (fd != -1) {
		fdp = file_descriptors[fd];

		if( fdp->do_close )
			close_dev( fdp->ih );
		free( fdp );

		file_descriptors[fd]=NULL;
	}

	return 0;
}
