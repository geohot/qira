#ifndef _IPXE_IB_PATHREC_H
#define _IPXE_IB_PATHREC_H

/** @file
 *
 * Infiniband path records
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/infiniband.h>

struct ib_mad_transaction;
struct ib_path;

/** Infiniband path operations */
struct ib_path_operations {
	/** Handle path transaction completion
	 *
	 * @v ibdev		Infiniband device
	 * @v path		Path
	 * @v rc		Status code
	 * @v av		Address vector, or NULL on error
	 */
	void ( * complete ) ( struct ib_device *ibdev,
			      struct ib_path *path, int rc,
			      struct ib_address_vector *av );
};

/** An Infiniband path */
struct ib_path {
	/** Infiniband device */
	struct ib_device *ibdev;
	/** Address vector */
	struct ib_address_vector av;
	/** Management transaction */
	struct ib_mad_transaction *madx;
	/** Path operations */
	struct ib_path_operations *op;
	/** Owner private data */
	void *owner_priv;
};

/**
 * Set Infiniband path owner-private data
 *
 * @v path		Path
 * @v priv		Private data
 */
static inline __always_inline void
ib_path_set_ownerdata ( struct ib_path *path, void *priv ) {
	path->owner_priv = priv;
}

/**
 * Get Infiniband path owner-private data
 *
 * @v path		Path
 * @ret priv		Private data
 */
static inline __always_inline void *
ib_path_get_ownerdata ( struct ib_path *path ) {
	return path->owner_priv;
}

extern struct ib_path *
ib_create_path ( struct ib_device *ibdev, struct ib_address_vector *av,
		 struct ib_path_operations *op );
extern void ib_destroy_path ( struct ib_device *ibdev,
			      struct ib_path *path );

extern int ib_resolve_path ( struct ib_device *ibdev,
			     struct ib_address_vector *av );

#endif /* _IPXE_IB_PATHREC_H */
