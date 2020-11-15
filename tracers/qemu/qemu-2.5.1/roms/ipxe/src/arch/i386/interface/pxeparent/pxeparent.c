/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/dhcp.h>
#include <ipxe/profile.h>
#include <pxeparent.h>
#include <pxe_api.h>
#include <pxe_types.h>
#include <pxe.h>

/** @file
 *
 * Call interface to parent PXE stack
 *
 */

/* Disambiguate the various error causes */
#define EINFO_EPXECALL							\
	__einfo_uniqify ( EINFO_EPLATFORM, 0x01,			\
			  "External PXE API error" )
#define EPXECALL( status ) EPLATFORM ( EINFO_EPXECALL, status )

/** A parent PXE API call profiler */
struct pxeparent_profiler {
	/** Total time spent performing REAL_CALL() */
	struct profiler total;
	/** Time spent transitioning to real mode */
	struct profiler p2r;
	/** Time spent in external code */
	struct profiler ext;
	/** Time spent transitioning back to protected mode */
	struct profiler r2p;
};

/** PXENV_UNDI_TRANSMIT profiler */
static struct pxeparent_profiler pxeparent_tx_profiler __profiler = {
	{ .name = "pxeparent.tx" },
	{ .name = "pxeparent.tx_p2r" },
	{ .name = "pxeparent.tx_ext" },
	{ .name = "pxeparent.tx_r2p" },
};

/** PXENV_UNDI_ISR profiler
 *
 * Note that this profiler will not see calls to
 * PXENV_UNDI_ISR_IN_START, which are handled by the UNDI ISR and do
 * not go via pxeparent_call().
 */
static struct pxeparent_profiler pxeparent_isr_profiler __profiler = {
	{ .name = "pxeparent.isr" },
	{ .name = "pxeparent.isr_p2r" },
	{ .name = "pxeparent.isr_ext" },
	{ .name = "pxeparent.isr_r2p" },
};

/** PXE unknown API call profiler
 *
 * This profiler can be used to measure the overhead of a dummy PXE
 * API call.
 */
static struct pxeparent_profiler pxeparent_unknown_profiler __profiler = {
	{ .name = "pxeparent.unknown" },
	{ .name = "pxeparent.unknown_p2r" },
	{ .name = "pxeparent.unknown_ext" },
	{ .name = "pxeparent.unknown_r2p" },
};

/** Miscellaneous PXE API call profiler */
static struct pxeparent_profiler pxeparent_misc_profiler __profiler = {
	{ .name = "pxeparent.misc" },
	{ .name = "pxeparent.misc_p2r" },
	{ .name = "pxeparent.misc_ext" },
	{ .name = "pxeparent.misc_r2p" },
};

/**
 * Name PXE API call
 *
 * @v function		API call number
 * @ret name		API call name
 */
static inline __attribute__ (( always_inline )) const char *
pxeparent_function_name ( unsigned int function ) {
	switch ( function ) {
	case PXENV_START_UNDI:
		return "PXENV_START_UNDI";
	case PXENV_STOP_UNDI:
		return "PXENV_STOP_UNDI";
	case PXENV_UNDI_STARTUP:
		return "PXENV_UNDI_STARTUP";
	case PXENV_UNDI_CLEANUP:
		return "PXENV_UNDI_CLEANUP";
	case PXENV_UNDI_INITIALIZE:
		return "PXENV_UNDI_INITIALIZE";
	case PXENV_UNDI_RESET_ADAPTER:
		return "PXENV_UNDI_RESET_ADAPTER";
	case PXENV_UNDI_SHUTDOWN:
		return "PXENV_UNDI_SHUTDOWN";
	case PXENV_UNDI_OPEN:
		return "PXENV_UNDI_OPEN";
	case PXENV_UNDI_CLOSE:
		return "PXENV_UNDI_CLOSE";
	case PXENV_UNDI_TRANSMIT:
		return "PXENV_UNDI_TRANSMIT";
	case PXENV_UNDI_SET_MCAST_ADDRESS:
		return "PXENV_UNDI_SET_MCAST_ADDRESS";
	case PXENV_UNDI_SET_STATION_ADDRESS:
		return "PXENV_UNDI_SET_STATION_ADDRESS";
	case PXENV_UNDI_SET_PACKET_FILTER:
		return "PXENV_UNDI_SET_PACKET_FILTER";
	case PXENV_UNDI_GET_INFORMATION:
		return "PXENV_UNDI_GET_INFORMATION";
	case PXENV_UNDI_GET_STATISTICS:
		return "PXENV_UNDI_GET_STATISTICS";
	case PXENV_UNDI_CLEAR_STATISTICS:
		return "PXENV_UNDI_CLEAR_STATISTICS";
	case PXENV_UNDI_INITIATE_DIAGS:
		return "PXENV_UNDI_INITIATE_DIAGS";
	case PXENV_UNDI_FORCE_INTERRUPT:
		return "PXENV_UNDI_FORCE_INTERRUPT";
	case PXENV_UNDI_GET_MCAST_ADDRESS:
		return "PXENV_UNDI_GET_MCAST_ADDRESS";
	case PXENV_UNDI_GET_NIC_TYPE:
		return "PXENV_UNDI_GET_NIC_TYPE";
	case PXENV_UNDI_GET_IFACE_INFO:
		return "PXENV_UNDI_GET_IFACE_INFO";
	/*
	 * Duplicate case value; this is a bug in the PXE specification.
	 *
	 *	case PXENV_UNDI_GET_STATE:
	 *		return "PXENV_UNDI_GET_STATE";
	 */
	case PXENV_UNDI_ISR:
		return "PXENV_UNDI_ISR";
	case PXENV_GET_CACHED_INFO:
		return "PXENV_GET_CACHED_INFO";
	default:
		return "UNKNOWN API CALL";
	}
}

/**
 * Determine applicable profiler pair (for debugging)
 *
 * @v function		API call number
 * @ret profiler	Profiler
 */
static struct pxeparent_profiler * pxeparent_profiler ( unsigned int function ){

	/* Determine applicable profiler */
	switch ( function ) {
	case PXENV_UNDI_TRANSMIT:
		return &pxeparent_tx_profiler;
	case PXENV_UNDI_ISR:
		return &pxeparent_isr_profiler;
	case PXENV_UNKNOWN:
		return &pxeparent_unknown_profiler;
	default:
		return &pxeparent_misc_profiler;
	}
}

/**
 * PXE parent parameter block
 *
 * Used as the parameter block for all parent PXE API calls.  Resides
 * in base memory.
 */
static union u_PXENV_ANY __bss16 ( pxeparent_params );
#define pxeparent_params __use_data16 ( pxeparent_params )

/** PXE parent entry point
 *
 * Used as the indirection vector for all parent PXE API calls.  Resides in
 * base memory.
 */
SEGOFF16_t __bss16 ( pxeparent_entry_point );
#define pxeparent_entry_point __use_data16 ( pxeparent_entry_point )

/**
 * Issue parent PXE API call
 *
 * @v entry		Parent PXE stack entry point
 * @v function		API call number
 * @v params		PXE parameter block
 * @v params_len	Length of PXE parameter block
 * @ret rc		Return status code
 */
int pxeparent_call ( SEGOFF16_t entry, unsigned int function,
		     void *params, size_t params_len ) {
	struct pxeparent_profiler *profiler = pxeparent_profiler ( function );
	PXENV_EXIT_t exit;
	unsigned long started;
	unsigned long stopped;
	int discard_D;
	int rc;

	/* Copy parameter block and entry point */
	assert ( params_len <= sizeof ( pxeparent_params ) );
	memcpy ( &pxeparent_params, params, params_len );
	memcpy ( &pxeparent_entry_point, &entry, sizeof ( entry ) );

	/* Call real-mode entry point.  This calling convention will
	 * work with both the !PXE and the PXENV+ entry points.
	 */
	profile_start ( &profiler->total );
	__asm__ __volatile__ ( REAL_CODE ( "pushl %%ebp\n\t" /* gcc bug */
					   "rdtsc\n\t"
					   "pushl %%eax\n\t"
					   "pushw %%es\n\t"
					   "pushw %%di\n\t"
					   "pushw %%bx\n\t"
					   "lcall *pxeparent_entry_point\n\t"
					   "movw %%ax, %%bx\n\t"
					   "rdtsc\n\t"
					   "addw $6, %%sp\n\t"
					   "popl %%edx\n\t"
					   "popl %%ebp\n\t" /* gcc bug */ )
			       : "=a" ( stopped ), "=d" ( started ),
				 "=b" ( exit ), "=D" ( discard_D )
			       : "b" ( function ),
			         "D" ( __from_data16 ( &pxeparent_params ) )
			       : "ecx", "esi" );
	profile_stop ( &profiler->total );
	profile_start_at ( &profiler->p2r, profile_started ( &profiler->total));
	profile_stop_at ( &profiler->p2r, started );
	profile_start_at ( &profiler->ext, started );
	profile_stop_at ( &profiler->ext, stopped );
	profile_start_at ( &profiler->r2p, stopped );
	profile_stop_at ( &profiler->r2p, profile_stopped ( &profiler->total ));

	/* Determine return status code based on PXENV_EXIT and
	 * PXENV_STATUS
	 */
	rc = ( ( exit == PXENV_EXIT_SUCCESS ) ?
	       0 : -EPXECALL ( pxeparent_params.Status ) );

	/* If anything goes wrong, print as much debug information as
	 * it's possible to give.
	 */
	if ( rc != 0 ) {
		SEGOFF16_t rm_params = {
			.segment = rm_ds,
			.offset = __from_data16 ( &pxeparent_params ),
		};

		DBG ( "PXEPARENT %s failed: %s\n",
		       pxeparent_function_name ( function ), strerror ( rc ) );
		DBG ( "PXEPARENT parameters at %04x:%04x length "
		       "%#02zx, entry point at %04x:%04x\n",
		       rm_params.segment, rm_params.offset, params_len,
		       pxeparent_entry_point.segment,
		       pxeparent_entry_point.offset );
		DBG ( "PXEPARENT parameters provided:\n" );
		DBG_HDA ( rm_params, params, params_len );
		DBG ( "PXEPARENT parameters returned:\n" );
		DBG_HDA ( rm_params, &pxeparent_params, params_len );
	}

	/* Copy parameter block back */
	memcpy ( params, &pxeparent_params, params_len );

	return rc;
}

