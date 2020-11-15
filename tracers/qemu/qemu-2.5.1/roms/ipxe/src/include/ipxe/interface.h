#ifndef _IPXE_INTERFACE_H
#define _IPXE_INTERFACE_H

/** @file
 *
 * Object interfaces
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <ipxe/refcnt.h>

/** An object interface operation */
struct interface_operation {
	/** Operation type */
	void *type;
	/** Implementing method */
	void *func;
};

/**
 * Define an object interface operation
 *
 * @v op_type		Operation type
 * @v object_type	Implementing method's expected object type
 * @v op_func		Implementing method
 * @ret op		Object interface operation
 */
#define INTF_OP( op_type, object_type, op_func ) {			      \
		.type = op_type,					      \
		.func = ( ( ( ( typeof ( op_func ) * ) NULL ) ==	      \
			    ( ( op_type ## _TYPE ( object_type ) * ) NULL ) ) \
			  ? op_func : op_func ),			      \
	}

/** An object interface descriptor */
struct interface_descriptor {
	/** Offset of interface within containing object */
	size_t offset;
	/** Number of interface operations */
	unsigned int num_op;
	/** Object interface operations */
	struct interface_operation *op;
	/** Offset to pass-through interface, if present */
	ssize_t passthru_offset;
};

#define intf_offset( object_type, intf )				      \
	( ( ( ( typeof ( ( ( object_type * ) NULL )->intf ) * ) NULL )	      \
	    == ( ( struct interface * ) NULL ) )			      \
	  ? offsetof ( object_type, intf )				      \
	  : offsetof ( object_type, intf ) )

/**
 * Define an object interface descriptor
 *
 * @v object_type	Containing object data type
 * @v intf		Interface name (i.e. field within object data type)
 * @v operations	Object interface operations array
 * @ret desc		Object interface descriptor
 */
#define INTF_DESC( object_type, intf, operations ) {			      \
		.offset = intf_offset ( object_type, intf ),		      \
		.op = operations,					      \
		.num_op = ( sizeof ( operations ) /			      \
			    sizeof ( operations[0] ) ),			      \
		.passthru_offset = 0,					      \
	}

/**
 * Define an object interface descriptor with pass-through interface
 *
 * @v object_type	Containing object data type
 * @v intf		Interface name (i.e. field within object data type)
 * @v operations	Object interface operations array
 * @v passthru		Pass-through interface name
 * @ret desc		Object interface descriptor
 */
#define INTF_DESC_PASSTHRU( object_type, intf, operations, passthru ) {	      \
		.offset = offsetof ( object_type, intf ),		      \
		.op = operations,					      \
		.num_op = ( sizeof ( operations ) /			      \
			    sizeof ( operations[0] ) ),			      \
		.passthru_offset = ( intf_offset ( object_type, passthru ) -  \
				     intf_offset ( object_type, intf ) ),     \
	}

/**
 * Define an object interface descriptor for a pure-interface object
 *
 * @v operations	Object interface operations array
 * @ret desc		Object interface descriptor
 *
 * A pure-interface object is an object that consists solely of a
 * single interface.
 */
#define INTF_DESC_PURE( operations ) {					      \
		.offset = 0,						      \
		.op = operations,					      \
		.num_op = ( sizeof ( operations ) /			      \
			    sizeof ( operations[0] ) ),			      \
		.passthru_offset = 0,					      \
	}

/** An object interface */
struct interface {
	/** Destination object interface
	 *
	 * When the containing object invokes an operation on this
	 * interface, it will be executed by the destination object.
	 *
	 * This pointer may never be NULL.  When the interface is
	 * unplugged, it should point to the null interface.
	 */
	struct interface *dest;
	/** Reference counter
	 *
	 * If this interface is not part of a reference-counted
	 * object, this field may be NULL.
	 */
	struct refcnt *refcnt;
	/** Interface descriptor */
	struct interface_descriptor *desc;
};

extern void intf_plug ( struct interface *intf, struct interface *dest );
extern void intf_plug_plug ( struct interface *a, struct interface *b );
extern void intf_unplug ( struct interface *intf );
extern void intf_nullify ( struct interface *intf );
extern struct interface * intf_get ( struct interface *intf );
extern void intf_put ( struct interface *intf );
extern void * __attribute__ (( pure )) intf_object ( struct interface *intf );
extern void * intf_get_dest_op_no_passthru_untyped ( struct interface *intf,
						     void *type,
						     struct interface **dest );
extern void * intf_get_dest_op_untyped ( struct interface *intf, void *type,
					 struct interface **dest );

extern void intf_close ( struct interface *intf, int rc );
#define intf_close_TYPE( object_type ) \
	typeof ( void ( object_type, int rc ) )

extern void intf_shutdown ( struct interface *intf, int rc );
extern void intf_restart ( struct interface *intf, int rc );

extern void intf_poke ( struct interface *intf,
			void ( type ) ( struct interface *intf ) );
#define intf_poke_TYPE( object_type ) \
	typeof ( void ( object_type ) )

extern struct interface_descriptor null_intf_desc;
extern struct interface null_intf;

/**
 * Initialise an object interface
 *
 * @v intf		Object interface
 * @v desc		Object interface descriptor
 * @v refcnt		Containing object reference counter, or NULL
 */
static inline void intf_init ( struct interface *intf,
			       struct interface_descriptor *desc,
			       struct refcnt *refcnt ) {
	intf->dest = &null_intf;
	intf->refcnt = refcnt;
	intf->desc = desc;
}

/**
 * Initialise a static object interface
 *
 * @v descriptor	Object interface descriptor
 */
#define INTF_INIT( descriptor ) {		\
		.dest = &null_intf,		\
		.refcnt = NULL,			\
		.desc = &(descriptor),		\
	}

/**
 * Get object interface destination and operation method (without pass-through)
 *
 * @v intf		Object interface
 * @v type		Operation type
 * @ret dest		Destination interface
 * @ret func		Implementing method, or NULL
 */
#define intf_get_dest_op_no_passthru( intf, type, dest )		\
	( ( type ## _TYPE ( void * ) * )				\
	  intf_get_dest_op_no_passthru_untyped ( intf, type, dest ) )

/**
 * Get object interface destination and operation method
 *
 * @v intf		Object interface
 * @v type		Operation type
 * @ret dest		Destination interface
 * @ret func		Implementing method, or NULL
 */
#define intf_get_dest_op( intf, type, dest )				\
	( ( type ## _TYPE ( void * ) * )				\
	  intf_get_dest_op_untyped ( intf, type, dest ) )

/**
 * Find debugging colourisation for an object interface
 *
 * @v intf		Object interface
 * @ret col		Debugging colourisation
 *
 * Use as the first argument to DBGC() or equivalent macro.
 */
#define INTF_COL( intf ) intf_object ( intf )

/** printf() format string for INTF_DBG() */
#define INTF_FMT "%p+%zx"

/**
 * printf() arguments for representing an object interface
 *
 * @v intf		Object interface
 * @ret args		printf() argument list corresponding to INTF_FMT
 */
#define INTF_DBG( intf ) intf_object ( intf ), (intf)->desc->offset

/** printf() format string for INTF_INTF_DBG() */
#define INTF_INTF_FMT INTF_FMT "->" INTF_FMT

/**
 * printf() arguments for representing an object interface pair
 *
 * @v intf		Object interface
 * @v dest		Destination object interface
 * @ret args		printf() argument list corresponding to INTF_INTF_FMT
 */
#define INTF_INTF_DBG( intf, dest ) INTF_DBG ( intf ), INTF_DBG ( dest )

#endif /* _IPXE_INTERFACE_H */
