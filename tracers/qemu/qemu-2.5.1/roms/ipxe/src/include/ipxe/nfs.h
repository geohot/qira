#ifndef _IPXE_NFS_H
#define _IPXE_NFS_H

#include <stdint.h>
#include <ipxe/oncrpc.h>

/** @file
 *
 * Network File System protocol.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** NFS protocol number */
#define ONCRPC_NFS 100003

/** NFS protocol version */
#define NFS_VERS   3

/** No error*/
#define NFS3_OK             0
/** Not owner */
#define NFS3ERR_PERM        1
/** No such file or directory */
#define NFS3ERR_NOENT       2
/** I/O error */
#define NFS3ERR_IO          5
/** No such device or address */
#define NFS3ERR_NXIO        6
/** Permission denied */
#define NFS3ERR_ACCES       13
/** The file specified already exists */
#define NFS3ERR_EXIST       17
/**  Attempt to do a cross-device hard link */
#define NFS3ERR_XDEV        18
/** No such device */
#define NFS3ERR_NODEV       19
/** Not a directory */
#define NFS3ERR_NOTDIR      20
 /**Is a directory */
#define NFS3ERR_ISDIR       21
/** Invalid argument */
#define NFS3ERR_INVAL       22
/** Filename too long */
#define NFS3ERR_NAMETOOLONG 63
/** Invalid file handle */
#define NFS3ERR_STALE       70
/** Too many levels of remote in path */
#define NFS3ERR_REMOTE      71
/** Illegal NFS file handle */
#define NFS3ERR_BADHANDLE   10001
/**  READDIR or READDIRPLUS cookie is stale */
#define NFS3ERR_BAD_COOKIE  10003
/** Operation not supported */
#define NFS3ERR_NOTSUPP     10004
/** Buffer or request is too small */
#define NFS3ERR_TOOSMALL    10005
/** An error occurred on the server which does not map to any  of the legal NFS
 * version 3 protocol error values */
#define NFS3ERR_SERVERFAULT 10006
/** The server initiated the request, but was not able to complete it in a
 * timely fashion */
#define NFS3ERR_JUKEBOX     10008

enum nfs_attr_type {
	NFS_ATTR_SYMLINK = 5,
};

/**
 * A NFS file handle
 *
 */
struct nfs_fh {
	uint8_t               fh[64];
	size_t                size;
};

/**
 * A NFS LOOKUP reply
 *
 */
struct nfs_lookup_reply {
	/** Reply status */
	uint32_t             status;
	/** Entity type */
	enum nfs_attr_type   ent_type;
	/** File handle */
	struct nfs_fh        fh;
};

/**
 * A NFS READLINK reply
 *
 */
struct nfs_readlink_reply {
	/** Reply status */
	uint32_t             status;
	/** File path length */
	uint32_t             path_len;
	/** File path */
	char                 *path;
};


/**
 * A NFS READ reply
 *
 */
struct nfs_read_reply {
	/** Reply status */
	uint32_t             status;
	/** File size */
	uint64_t             filesize;
	/** Bytes read */
	uint32_t             count;
	/** End-of-File indicator */
	uint32_t             eof;
	/** Data length */
	uint32_t             data_len;
	/** Data read */
	void                 *data;
};

size_t nfs_iob_get_fh ( struct io_buffer *io_buf, struct nfs_fh *fh );
size_t nfs_iob_add_fh ( struct io_buffer *io_buf, const struct nfs_fh *fh );

/**
 * Prepare an ONC RPC session to be used as a NFS session
 *
 * @v session           ONC RPC session
 * @v credential        ONC RPC credential
 *
 * The credential parameter must not be NULL, use 'oncrpc_auth_none' if you
 * don't want a particular scheme to be used.
 */
static inline void nfs_init_session ( struct oncrpc_session *session,
                                      struct oncrpc_cred *credential ) {
	oncrpc_init_session ( session, credential, &oncrpc_auth_none,
	                      ONCRPC_NFS, NFS_VERS );
}

int nfs_lookup ( struct interface *intf, struct oncrpc_session *session,
                 const struct nfs_fh *fh, const char *filename );
int nfs_readlink ( struct interface *intf, struct oncrpc_session *session,
                   const struct nfs_fh *fh );
int nfs_read ( struct interface *intf, struct oncrpc_session *session,
               const struct nfs_fh *fh, uint64_t offset, uint32_t count );

int nfs_get_lookup_reply ( struct nfs_lookup_reply *lookup_reply,
                           struct oncrpc_reply *reply );
int nfs_get_readlink_reply ( struct nfs_readlink_reply *readlink_reply,
                             struct oncrpc_reply *reply );
int nfs_get_read_reply ( struct nfs_read_reply *read_reply,
                         struct oncrpc_reply *reply );

#endif /* _IPXE_NFS_H */
