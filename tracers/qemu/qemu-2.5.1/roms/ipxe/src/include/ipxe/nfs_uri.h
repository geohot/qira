#ifndef _IPXE_NFS_URI_H
#define _IPXE_NFS_URI_H

/** @file
 *
 * Network File System protocol URI handling functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/uri.h>

struct nfs_uri {
	char *mountpoint;
	char *filename;
	char *path;
	char *lookup_pos;
};

int nfs_uri_init ( struct nfs_uri *nfs_uri, const struct uri *uri );
int nfs_uri_next_mountpoint ( struct nfs_uri *uri );
int nfs_uri_symlink ( struct nfs_uri *uri, const char *symlink_value );
char *nfs_uri_mountpoint ( const struct nfs_uri *uri );
char *nfs_uri_next_path_component ( struct nfs_uri *uri );
void nfs_uri_free ( struct nfs_uri *uri );


#endif /* _IPXE_NFS_URI_H */
