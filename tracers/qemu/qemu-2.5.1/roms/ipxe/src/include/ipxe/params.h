#ifndef _IPXE_PARAMS_H
#define _IPXE_PARAMS_H

/** @file
 *
 * Form parameters
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/list.h>
#include <ipxe/refcnt.h>

/** A form parameter list */
struct parameters {
	/** Reference count */
	struct refcnt refcnt;
	/** List of all parameter lists */
	struct list_head list;
	/** Name */
	const char *name;
	/** Parameters */
	struct list_head entries;
};

/** A form parameter */
struct parameter {
	/** List of form parameters */
	struct list_head list;
	/** Key */
	const char *key;
	/** Value */
	const char *value;
};

/**
 * Increment form parameter list reference count
 *
 * @v params		Parameter list, or NULL
 * @ret params		Parameter list as passed in
 */
static inline __attribute__ (( always_inline )) struct parameters *
params_get ( struct parameters *params ) {
	ref_get ( &params->refcnt );
	return params;
}

/**
 * Decrement form parameter list reference count
 *
 * @v params		Parameter list, or NULL
 */
static inline __attribute__ (( always_inline )) void
params_put ( struct parameters *params ) {
	ref_put ( &params->refcnt );
}

/**
 * Claim ownership of form parameter list
 *
 * @v params		Parameter list
 * @ret params		Parameter list
 */
static inline __attribute__ (( always_inline )) struct parameters *
claim_parameters ( struct parameters *params ) {

	/* Remove from list of parameter lists */
	list_del ( &params->list );

	return params;
}

/** Iterate over all form parameters in a list */
#define for_each_param( param, params )				\
	list_for_each_entry ( (param), &(params)->entries, list )

extern struct parameters * find_parameters ( const char *name );
extern struct parameters * create_parameters ( const char *name );
extern struct parameter * add_parameter ( struct parameters *params,
					  const char *key, const char *value );

#endif /* _IPXE_PARAMS_H */
