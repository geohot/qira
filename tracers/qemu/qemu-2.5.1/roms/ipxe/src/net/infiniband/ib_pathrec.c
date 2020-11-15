/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/infiniband.h>
#include <ipxe/ib_mi.h>
#include <ipxe/ib_pathrec.h>

/** @file
 *
 * Infiniband path lookups
 *
 */

/**
 * Handle path transaction completion
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v madx		Management transaction
 * @v rc		Status code
 * @v mad		Received MAD (or NULL on error)
 * @v av		Source address vector (or NULL on error)
 */
static void ib_path_complete ( struct ib_device *ibdev,
			       struct ib_mad_interface *mi,
			       struct ib_mad_transaction *madx,
			       int rc, union ib_mad *mad,
			       struct ib_address_vector *av __unused ) {
	struct ib_path *path = ib_madx_get_ownerdata ( madx );
	union ib_gid *dgid = &path->av.gid;
	struct ib_path_record *pathrec = &mad->sa.sa_data.path_record;

	/* Report failures */
	if ( ( rc == 0 ) && ( mad->hdr.status != htons ( IB_MGMT_STATUS_OK ) ))
		rc = -ENETUNREACH;
	if ( rc != 0 ) {
		DBGC ( ibdev, "IBDEV %p path lookup for " IB_GID_FMT
		       " failed: %s\n",
		       ibdev, IB_GID_ARGS ( dgid ), strerror ( rc ) );
		goto out;
	}

	/* Extract values from MAD */
	path->av.lid = ntohs ( pathrec->dlid );
	path->av.sl = ( pathrec->reserved__sl & 0x0f );
	path->av.rate = ( pathrec->rate_selector__rate & 0x3f );
	DBGC ( ibdev, "IBDEV %p path to " IB_GID_FMT " is %04x sl %d rate "
	       "%d\n", ibdev, IB_GID_ARGS ( dgid ), path->av.lid, path->av.sl,
	       path->av.rate );

 out:
	/* Destroy the completed transaction */
	ib_destroy_madx ( ibdev, mi, madx );
	path->madx = NULL;

	/* Hand off to upper completion handler */
	path->op->complete ( ibdev, path, rc, &path->av );
}

/** Path transaction completion operations */
static struct ib_mad_transaction_operations ib_path_op = {
	.complete = ib_path_complete,
};

/**
 * Create path
 *
 * @v ibdev		Infiniband device
 * @v av		Address vector to complete
 * @v op		Path operations
 * @ret path		Path
 */
struct ib_path *
ib_create_path ( struct ib_device *ibdev, struct ib_address_vector *av,
		 struct ib_path_operations *op ) {
	struct ib_path *path;
	union ib_mad mad;
	struct ib_mad_sa *sa = &mad.sa;

	/* Allocate and initialise structure */
	path = zalloc ( sizeof ( *path ) );
	if ( ! path )
		goto err_alloc_path;
	path->ibdev = ibdev;
	memcpy ( &path->av, av, sizeof ( path->av ) );
	path->op = op;

	/* Construct path request */
	memset ( sa, 0, sizeof ( *sa ) );
	sa->mad_hdr.mgmt_class = IB_MGMT_CLASS_SUBN_ADM;
	sa->mad_hdr.class_version = IB_SA_CLASS_VERSION;
	sa->mad_hdr.method = IB_MGMT_METHOD_GET;
	sa->mad_hdr.attr_id = htons ( IB_SA_ATTR_PATH_REC );
	sa->sa_hdr.comp_mask[1] =
		htonl ( IB_SA_PATH_REC_DGID | IB_SA_PATH_REC_SGID );
	memcpy ( &sa->sa_data.path_record.dgid, &path->av.gid,
		 sizeof ( sa->sa_data.path_record.dgid ) );
	memcpy ( &sa->sa_data.path_record.sgid, &ibdev->gid,
		 sizeof ( sa->sa_data.path_record.sgid ) );

	/* Create management transaction */
	path->madx = ib_create_madx ( ibdev, ibdev->gsi, &mad, NULL,
				      &ib_path_op );
	if ( ! path->madx )
		goto err_create_madx;
	ib_madx_set_ownerdata ( path->madx, path );

	return path;

	ib_destroy_madx ( ibdev, ibdev->gsi, path->madx );
 err_create_madx:
	free ( path );
 err_alloc_path:
	return NULL;
}

/**
 * Destroy path
 *
 * @v ibdev		Infiniband device
 * @v path		Path
 */
void ib_destroy_path ( struct ib_device *ibdev, struct ib_path *path ) {

	if ( path->madx )
		ib_destroy_madx ( ibdev, ibdev->gsi, path->madx );
	free ( path );
}

/** Number of path cache entries
 *
 * Must be a power of two.
 */
#define IB_NUM_CACHED_PATHS 4

/** A cached path */
struct ib_cached_path {
	/** Path */
	struct ib_path *path;
};

/** Path cache */
static struct ib_cached_path ib_path_cache[IB_NUM_CACHED_PATHS];

/** Oldest path cache entry index */
static unsigned int ib_path_cache_idx;

/**
 * Find path cache entry
 *
 * @v ibdev		Infiniband device
 * @v dgid		Destination GID
 * @ret path		Path cache entry, or NULL
 */
static struct ib_cached_path *
ib_find_path_cache_entry ( struct ib_device *ibdev, union ib_gid *dgid ) {
	struct ib_cached_path *cached;
	unsigned int i;

	for ( i = 0 ; i < IB_NUM_CACHED_PATHS ; i++ ) {
		cached = &ib_path_cache[i];
		if ( ! cached->path )
			continue;
		if ( cached->path->ibdev != ibdev )
			continue;
		if ( memcmp ( &cached->path->av.gid, dgid,
			      sizeof ( cached->path->av.gid ) ) != 0 )
			continue;
		return cached;
	}

	return NULL;
}

/**
 * Handle cached path transaction completion
 *
 * @v ibdev		Infiniband device
 * @v path		Path
 * @v rc		Status code
 * @v av		Address vector, or NULL on error
 */
static void ib_cached_path_complete ( struct ib_device *ibdev,
				      struct ib_path *path, int rc,
				      struct ib_address_vector *av __unused ) {
	struct ib_cached_path *cached = ib_path_get_ownerdata ( path );

	/* If the transaction failed, erase the cache entry */
	if ( rc != 0 ) {
		/* Destroy the old cache entry */
		ib_destroy_path ( ibdev, path );
		memset ( cached, 0, sizeof ( *cached ) );
		return;
	}

	/* Do not destroy the completed transaction; we still need to
	 * refer to the resolved path.
	 */
}

/** Cached path transaction completion operations */
static struct ib_path_operations ib_cached_path_op = {
	.complete = ib_cached_path_complete,
};

/**
 * Resolve path
 *
 * @v ibdev		Infiniband device
 * @v av		Address vector to complete
 * @ret rc		Return status code
 *
 * This provides a non-transactional way to resolve a path, via a
 * cache similar to ARP.
 */
int ib_resolve_path ( struct ib_device *ibdev, struct ib_address_vector *av ) {
	union ib_gid *gid = &av->gid;
	struct ib_cached_path *cached;
	unsigned int cache_idx;

	/* Sanity check */
	if ( ! av->gid_present ) {
		DBGC ( ibdev, "IBDEV %p attempt to look up path without GID\n",
		       ibdev );
		return -EINVAL;
	}

	/* Look in cache for a matching entry */
	cached = ib_find_path_cache_entry ( ibdev, gid );
	if ( cached && cached->path->av.lid ) {
		/* Populated entry found */
		av->lid = cached->path->av.lid;
		av->rate = cached->path->av.rate;
		av->sl = cached->path->av.sl;
		DBGC2 ( ibdev, "IBDEV %p cache hit for " IB_GID_FMT "\n",
			ibdev, IB_GID_ARGS ( gid ) );
		return 0;
	}
	DBGC ( ibdev, "IBDEV %p cache miss for " IB_GID_FMT "%s\n", ibdev,
	       IB_GID_ARGS ( gid ), ( cached ? " (in progress)" : "" ) );

	/* If lookup is already in progress, do nothing */
	if ( cached )
		return -ENOENT;

	/* Locate a new cache entry to use */
	cache_idx = ( (ib_path_cache_idx++) % IB_NUM_CACHED_PATHS );
	cached = &ib_path_cache[cache_idx];

	/* Destroy the old cache entry */
	if ( cached->path )
		ib_destroy_path ( ibdev, cached->path );
	memset ( cached, 0, sizeof ( *cached ) );

	/* Create new path */
	cached->path = ib_create_path ( ibdev, av, &ib_cached_path_op );
	if ( ! cached->path ) {
		DBGC ( ibdev, "IBDEV %p could not create path\n",
		       ibdev );
		return -ENOMEM;
	}
	ib_path_set_ownerdata ( cached->path, cached );

	/* Not found yet */
	return -ENOENT;
}
