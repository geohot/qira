/*
 *   Creation Date: <2001/05/06 22:27:09 samuel>
 *   Time-stamp: <2003/12/12 02:24:56 samuel>
 *
 *	<fs.c>
 *
 *     	I/O API used by the filesystem code
 *
 *   Copyright (C) 2001, 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "fs/fs.h"
#include "libc/diskio.h"
#include "os.h"
#include "hfs_mdb.h"

/************************************************************************/
/*	functionsions used by the various filesystems			*/
/************************************************************************/

char *
get_hfs_vol_name( int fd, char *buf, int size )
{
	char sect[512];
	hfs_mdb_t *mdb = (hfs_mdb_t*)&sect;

	seek_io( fd, 0x400 );
	read_io( fd, sect, sizeof(sect) );
	if( hfs_get_ushort(mdb->drSigWord) == HFS_SIGNATURE ) {
		unsigned int n = mdb->drVN[0];
		if( n >= size )
			n = size - 1;
		memcpy( buf, &mdb->drVN[1], n );
		buf[n] = 0;
	} else if( hfs_get_ushort(mdb->drSigWord) == HFS_PLUS_SIGNATURE ) {
		strncpy( buf, "Unembedded HFS+", size );
	} else {
		strncpy( buf, "Error", size );
	}
	return buf;
}

unsigned long
os_read( int fd, void *buf, unsigned long len, int blksize_bits )
{
	/* printk("os_read %d\n", (int)len); */

	int cnt = read_io( fd, buf, len << blksize_bits );
	return (cnt > 0)? (cnt >> blksize_bits) : cnt;
}

unsigned long
os_seek( int fd, unsigned long blknum, int blksize_bits )
{
	/* printk("os_seek %d\n", blknum ); */
	long long offs = (long long)blknum << blksize_bits;

	/* offset == -1 means seek to EOF */
	if( (int)blknum == -1 )
		offs = -1;

	if( seek_io(fd, offs) ) {
		/* printk("os_seek failure\n"); */
		return (unsigned long)-1;
	}

	if( (int)blknum == -1 ) {
		if( (offs=tell(fd)) < 0 )
			return -1;
		blknum = offs >> blksize_bits;
	}
	return blknum;
}

void
os_seek_offset( int fd, long long offset )
{
	seek_io(fd, offset);
}

int
os_same( int fd1, int fd2 )
{
	return fd1 == fd2;
}
