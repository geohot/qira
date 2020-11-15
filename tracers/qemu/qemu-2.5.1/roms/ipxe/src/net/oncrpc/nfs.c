/*
 * Copyright (C) 2013 Marin Hannache <ipxe@mareo.fr>.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <byteswap.h>
#include <ipxe/time.h>
#include <ipxe/iobuf.h>
#include <ipxe/open.h>
#include <ipxe/features.h>
#include <ipxe/nfs.h>
#include <ipxe/oncrpc.h>
#include <ipxe/oncrpc_iob.h>
#include <ipxe/portmap.h>
#include <ipxe/mount.h>
#include <ipxe/settings.h>

/** @file
 *
 * Network File System protocol
 *
 */

/** NFS LOOKUP procedure */
#define NFS_LOOKUP      3
/** NFS READLINK procedure */
#define NFS_READLINK    5
/** NFS READ procedure */
#define NFS_READ        6

/**
 * Extract a file handle from the beginning of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v fh                File handle
 * @ret size            Size of the data read
 */
size_t nfs_iob_get_fh ( struct io_buffer *io_buf, struct nfs_fh *fh ) {
	fh->size = oncrpc_iob_get_int ( io_buf );

	if ( fh->size > 64 )
		return sizeof ( uint32_t );

	memcpy (fh->fh, io_buf->data, fh->size );
	iob_pull ( io_buf, fh->size );

	return fh->size + sizeof ( uint32_t );
}

/**
 * Add a file handle to the end of an I/O buffer
 *
 * @v io_buf            I/O buffer
 * @v fh                File handle
 * @ret size            Size of the data written
 */
size_t nfs_iob_add_fh ( struct io_buffer *io_buf, const struct nfs_fh *fh ) {
	size_t s;

	s = oncrpc_iob_add_int ( io_buf, fh->size );
	memcpy ( iob_put ( io_buf, fh->size ), &fh->fh, fh->size );

	return s + fh->size;
}

/**
 * Send a LOOKUP request
 *
 * @v intf              Interface to send the request on
 * @v session           ONC RPC session
 * @v fh                The file handle of the the directory
 * @v filename          The file name
 * @ret rc              Return status code
 */
int nfs_lookup ( struct interface *intf, struct oncrpc_session *session,
                 const struct nfs_fh *fh, const char *filename ) {
	struct oncrpc_field fields[] = {
		ONCRPC_SUBFIELD ( array, fh->size, &fh->fh ),
		ONCRPC_FIELD ( str, filename ),
		ONCRPC_FIELD_END,
	};

	return oncrpc_call ( intf, session, NFS_LOOKUP, fields );
}

/**
 * Send a READLINK request
 *
 * @v intf              Interface to send the request on
 * @v session           ONC RPC session
 * @v fh                The symlink file handle
 * @ret rc              Return status code
 */
int nfs_readlink ( struct interface *intf, struct oncrpc_session *session,
                   const struct nfs_fh *fh ) {
	struct oncrpc_field fields[] = {
		ONCRPC_SUBFIELD ( array, fh->size, &fh->fh ),
		ONCRPC_FIELD_END,
	};

	return oncrpc_call ( intf, session, NFS_READLINK, fields );
}

/**
 * Send a READ request
 *
 * @v intf              Interface to send the request on
 * @v session           ONC RPC session
 * @v fh                The file handle
 * @v offset            Offset
 * @v count             Byte count
 * @ret rc              Return status code
 */
int nfs_read ( struct interface *intf, struct oncrpc_session *session,
               const struct nfs_fh *fh, uint64_t offset, uint32_t count ) {
	struct oncrpc_field fields[] = {
		ONCRPC_SUBFIELD ( array, fh->size, &fh->fh ),
		ONCRPC_FIELD ( int64, offset ),
		ONCRPC_FIELD ( int32, count ),
		ONCRPC_FIELD_END,
	};

	return oncrpc_call ( intf, session, NFS_READ, fields );
}

/**
 * Parse a LOOKUP reply
 *
 * @v lookup_reply      A structure where the data will be saved
 * @v reply             The ONC RPC reply to get data from
 * @ret rc              Return status code
 */
int nfs_get_lookup_reply ( struct nfs_lookup_reply *lookup_reply,
                           struct oncrpc_reply *reply ) {
	if ( ! lookup_reply || ! reply )
		return -EINVAL;

	lookup_reply->status = oncrpc_iob_get_int ( reply->data );
	switch ( lookup_reply->status )
	{
	case NFS3_OK:
		break;
	case NFS3ERR_PERM:
		return -EPERM;
	case NFS3ERR_NOENT:
		return -ENOENT;
	case NFS3ERR_IO:
		return -EIO;
	case NFS3ERR_ACCES:
		return -EACCES;
	case NFS3ERR_NOTDIR:
		return -ENOTDIR;
	case NFS3ERR_NAMETOOLONG:
		return -ENAMETOOLONG;
	case NFS3ERR_STALE:
		return -ESTALE;
	case NFS3ERR_BADHANDLE:
	case NFS3ERR_SERVERFAULT:
	default:
		return -EPROTO;
	}

	nfs_iob_get_fh ( reply->data, &lookup_reply->fh );

	if ( oncrpc_iob_get_int ( reply->data ) == 1 )
		lookup_reply->ent_type = oncrpc_iob_get_int ( reply->data );

	return 0;
}
/**
 * Parse a READLINK reply
 *
 * @v readlink_reply    A structure where the data will be saved
 * @v reply             The ONC RPC reply to get data from
 * @ret rc              Return status code
 */
int nfs_get_readlink_reply ( struct nfs_readlink_reply *readlink_reply,
                             struct oncrpc_reply *reply ) {
	if ( ! readlink_reply || ! reply )
		return -EINVAL;

	readlink_reply->status = oncrpc_iob_get_int ( reply->data );
	switch ( readlink_reply->status )
	{
	case NFS3_OK:
		 break;
	case NFS3ERR_IO:
		return -EIO;
	case NFS3ERR_ACCES:
		return -EACCES;
	case NFS3ERR_INVAL:
		return -EINVAL;
	case NFS3ERR_NOTSUPP:
		return -ENOTSUP;
	case NFS3ERR_STALE:
		return -ESTALE;
	case NFS3ERR_BADHANDLE:
	case NFS3ERR_SERVERFAULT:
	default:
		return -EPROTO;
	}

	if ( oncrpc_iob_get_int ( reply->data ) == 1 )
		iob_pull ( reply->data, 5 * sizeof ( uint32_t ) +
		                        8 * sizeof ( uint64_t ) );

	readlink_reply->path_len = oncrpc_iob_get_int ( reply->data );
	readlink_reply->path     = reply->data->data;

	return 0;
}

/**
 * Parse a READ reply
 *
 * @v read_reply        A structure where the data will be saved
 * @v reply             The ONC RPC reply to get data from
 * @ret rc              Return status code
 */
int nfs_get_read_reply ( struct nfs_read_reply *read_reply,
                         struct oncrpc_reply *reply ) {
	if ( ! read_reply || ! reply )
		return -EINVAL;

	read_reply->status = oncrpc_iob_get_int ( reply->data );
	switch ( read_reply->status )
	{
	case NFS3_OK:
		 break;
	case NFS3ERR_PERM:
		return -EPERM;
	case NFS3ERR_NOENT:
		return -ENOENT;
	case NFS3ERR_IO:
		return -EIO;
	case NFS3ERR_NXIO:
		return -ENXIO;
	case NFS3ERR_ACCES:
		return -EACCES;
	case NFS3ERR_INVAL:
		return -EINVAL;
	case NFS3ERR_STALE:
		return -ESTALE;
	case NFS3ERR_BADHANDLE:
	case NFS3ERR_SERVERFAULT:
	default:
		return -EPROTO;
	}

	if ( oncrpc_iob_get_int ( reply->data ) == 1 )
	{
		iob_pull ( reply->data, 5 * sizeof ( uint32_t ) );
		read_reply->filesize = oncrpc_iob_get_int64 ( reply->data );
		iob_pull ( reply->data, 7 * sizeof ( uint64_t ) );
	}

	read_reply->count    = oncrpc_iob_get_int ( reply->data );
	read_reply->eof      = oncrpc_iob_get_int ( reply->data );
	read_reply->data_len = oncrpc_iob_get_int ( reply->data );
	read_reply->data     = reply->data->data;

	if ( read_reply->count != read_reply->data_len )
		return -EPROTO;

	return 0;
}

