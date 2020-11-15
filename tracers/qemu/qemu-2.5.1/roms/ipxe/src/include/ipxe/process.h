#ifndef _IPXE_PROCESS_H
#define _IPXE_PROCESS_H

/** @file
 *
 * Processes
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/list.h>
#include <ipxe/refcnt.h>
#include <ipxe/tables.h>

/** A process */
struct process {
	/** List of processes */
	struct list_head list;
	/** Process descriptor */
	struct process_descriptor *desc;
	/** Reference counter
	 *
	 * If this process is not part of a reference-counted object,
	 * this field may be NULL.
	 */
	struct refcnt *refcnt;
};

/** A process descriptor */
struct process_descriptor {
	/** Offset of process within containing object */
	size_t offset;
	/**
	 * Single-step the process
	 *
	 * This method should execute a single step of the process.
	 * Returning from this method is isomorphic to yielding the
	 * CPU to another process.
	 */
	void ( * step ) ( void *object );
	/** Automatically reschedule the process */
	int reschedule;
};

/**
 * Define a process step() method
 *
 * @v object_type	Implementing method's expected object type
 * @v step		Implementing method
 * @ret step		Process step method
 */
#define PROC_STEP( object_type, step )					      \
	( ( ( ( typeof ( step ) * ) NULL ) ==				      \
	    ( ( void ( * ) ( object_type *object ) ) NULL ) ) ?		      \
	  ( void ( * ) ( void *object ) ) step :			      \
	  ( void ( * ) ( void *object ) ) step )

/**
 * Calculate offset of process within containing object
 *
 * @v object_type	Containing object data type
 * @v name		Process name (i.e. field within object data type)
 * @ret offset		Offset of process within containing object
 */
#define process_offset( object_type, name )				      \
	( ( ( ( typeof ( ( ( object_type * ) NULL )->name ) * ) NULL )	      \
	    == ( ( struct process * ) NULL ) )			      	      \
	  ? offsetof ( object_type, name )				      \
	  : offsetof ( object_type, name ) )

/**
 * Define a process descriptor
 *
 * @v object_type	Containing object data type
 * @v process		Process name (i.e. field within object data type)
 * @v step		Process' step() method
 * @ret desc		Object interface descriptor
 */
#define PROC_DESC( object_type, process, _step ) {			      \
		.offset = process_offset ( object_type, process ),	      \
		.step = PROC_STEP ( object_type, _step ),		      \
		.reschedule = 1,					      \
	}

/**
 * Define a process descriptor for a process that runs only once
 *
 * @v object_type	Containing object data type
 * @v process		Process name (i.e. field within object data type)
 * @v step		Process' step() method
 * @ret desc		Object interface descriptor
 */
#define PROC_DESC_ONCE( object_type, process, _step ) {			      \
		.offset = process_offset ( object_type, process ),	      \
		.step = PROC_STEP ( object_type, _step ),		      \
		.reschedule = 0,					      \
	}

/**
 * Define a process descriptor for a pure process
 *
 * A pure process is a process that does not have a containing object.
 *
 * @v step		Process' step() method
 * @ret desc		Object interface descriptor
 */
#define PROC_DESC_PURE( _step ) {					      \
		.offset = 0,						      \
		.step = PROC_STEP ( struct process, _step ),		      \
		.reschedule = 1,					      \
	}

extern void * __attribute__ (( pure ))
process_object ( struct process *process );
extern void process_add ( struct process *process );
extern void process_del ( struct process *process );
extern void step ( void );

/**
 * Initialise process without adding to process list
 *
 * @v process		Process
 * @v desc		Process descriptor
 * @v refcnt		Containing object reference count, or NULL
 */
static inline __attribute__ (( always_inline )) void
process_init_stopped ( struct process *process,
		       struct process_descriptor *desc,
		       struct refcnt *refcnt ) {
	INIT_LIST_HEAD ( &process->list );
	process->desc = desc;
	process->refcnt = refcnt;
}

/**
 * Initialise process and add to process list
 *
 * @v process		Process
 * @v desc		Process descriptor
 * @v refcnt		Containing object reference count, or NULL
 */
static inline __attribute__ (( always_inline )) void
process_init ( struct process *process,
	       struct process_descriptor *desc,
	       struct refcnt *refcnt ) {
	process_init_stopped ( process, desc, refcnt );
	process_add ( process );
}

/**
 * Check if process is running
 *
 * @v process		Process
 * @ret running		Process is running
 */
static inline __attribute__ (( always_inline )) int
process_running ( struct process *process ) {
	return ( ! list_empty ( &process->list ) );
}

/** Permanent process table */
#define PERMANENT_PROCESSES __table ( struct process, "processes" )

/**
 * Declare a permanent process
 *
 * Permanent processes will be automatically added to the process list
 * at initialisation time.
 */
#define __permanent_process __table_entry ( PERMANENT_PROCESSES, 01 )

/** Define a permanent process
 *
 */
#define PERMANENT_PROCESS( name, step )					      \
static struct process_descriptor name ## _desc = PROC_DESC_PURE ( step );     \
struct process name __permanent_process = {				      \
	.list = LIST_HEAD_INIT ( name.list ),				      \
	.desc = & name ## _desc,					      \
	.refcnt = NULL,							      \
};

/**
 * Find debugging colourisation for a process
 *
 * @v process		Process
 * @ret col		Debugging colourisation
 *
 * Use as the first argument to DBGC() or equivalent macro.
 */
#define PROC_COL( process ) process_object ( process )

/** printf() format string for PROC_DBG() */
#define PROC_FMT "%p+%zx"

/**
 * printf() arguments for representing a process
 *
 * @v process		Process
 * @ret args		printf() argument list corresponding to PROC_FMT
 */
#define PROC_DBG( process ) process_object ( process ), (process)->desc->offset

#endif /* _IPXE_PROCESS_H */
