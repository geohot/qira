/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <ipxe/list.h>
#include <ipxe/init.h>
#include <ipxe/process.h>

/** @file
 *
 * Processes
 *
 * We implement a trivial form of cooperative multitasking, in which
 * all processes share a single stack and address space.
 */

/** Process run queue */
static LIST_HEAD ( run_queue );

/**
 * Get pointer to object containing process
 *
 * @v process		Process
 * @ret object		Containing object
 */
void * process_object ( struct process *process ) {
	return ( ( ( void * ) process ) - process->desc->offset );
}

/**
 * Add process to process list
 *
 * @v process		Process
 *
 * It is safe to call process_add() multiple times; further calls will
 * have no effect.
 */
void process_add ( struct process *process ) {
	if ( ! process_running ( process ) ) {
		DBGC ( PROC_COL ( process ), "PROCESS " PROC_FMT
		       " starting\n", PROC_DBG ( process ) );
		ref_get ( process->refcnt );
		list_add_tail ( &process->list, &run_queue );
	} else {
		DBGC ( PROC_COL ( process ), "PROCESS " PROC_FMT
		       " already started\n", PROC_DBG ( process ) );
	}
}

/**
 * Remove process from process list
 *
 * @v process		Process
 *
 * It is safe to call process_del() multiple times; further calls will
 * have no effect.
 */
void process_del ( struct process *process ) {
	if ( process_running ( process ) ) {
		DBGC ( PROC_COL ( process ), "PROCESS " PROC_FMT
		       " stopping\n", PROC_DBG ( process ) );
		list_del ( &process->list );
		INIT_LIST_HEAD ( &process->list );
		ref_put ( process->refcnt );
	} else {
		DBGC ( PROC_COL ( process ), "PROCESS " PROC_FMT
		       " already stopped\n", PROC_DBG ( process ) );
	}
}

/**
 * Single-step a single process
 *
 * This executes a single step of the first process in the run queue,
 * and moves the process to the end of the run queue.
 */
void step ( void ) {
	struct process *process;
	struct process_descriptor *desc;
	void *object;

	if ( ( process = list_first_entry ( &run_queue, struct process,
					    list ) ) ) {
		ref_get ( process->refcnt ); /* Inhibit destruction mid-step */
		desc = process->desc;
		object = process_object ( process );
		if ( desc->reschedule ) {
			list_del ( &process->list );
			list_add_tail ( &process->list, &run_queue );
		} else {
			process_del ( process );
		}
		DBGC2 ( PROC_COL ( process ), "PROCESS " PROC_FMT
			" executing\n", PROC_DBG ( process ) );
		desc->step ( object );
		DBGC2 ( PROC_COL ( process ), "PROCESS " PROC_FMT
			" finished executing\n", PROC_DBG ( process ) );
		ref_put ( process->refcnt ); /* Allow destruction */
	}
}

/**
 * Initialise processes
 *
 */
static void init_processes ( void ) {
	struct process *process;

	for_each_table_entry ( process, PERMANENT_PROCESSES )
		process_add ( process );
}

/** Process initialiser */
struct init_fn process_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = init_processes,
};
