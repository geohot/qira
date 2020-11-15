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

#include <ipxe/uaccess.h>
#include <ipxe/init.h>
#include <ipxe/profile.h>
#include <setjmp.h>
#include <registers.h>
#include <biosint.h>
#include <pxe.h>
#include <pxe_call.h>

/** @file
 *
 * PXE API entry point
 */

/* Disambiguate the various error causes */
#define EINFO_EPXENBP							\
	__einfo_uniqify ( EINFO_EPLATFORM, 0x01,			\
			  "External PXE NBP error" )
#define EPXENBP( status ) EPLATFORM ( EINFO_EPXENBP, status )

/** Vector for chaining INT 1A */
extern struct segoff __text16 ( pxe_int_1a_vector );
#define pxe_int_1a_vector __use_text16 ( pxe_int_1a_vector )

/** INT 1A handler */
extern void pxe_int_1a ( void );

/** INT 1A hooked flag */
static int int_1a_hooked = 0;

/** PXENV_UNDI_TRANSMIT API call profiler */
static struct profiler pxe_api_tx_profiler __profiler =
	{ .name = "pxeapi.tx" };

/** PXENV_UNDI_ISR API call profiler */
static struct profiler pxe_api_isr_profiler __profiler =
	{ .name = "pxeapi.isr" };

/** PXE unknown API call profiler
 *
 * This profiler can be used to measure the overhead of a dummy PXE
 * API call.
 */
static struct profiler pxe_api_unknown_profiler __profiler =
	{ .name = "pxeapi.unknown" };

/** Miscellaneous PXE API call profiler */
static struct profiler pxe_api_misc_profiler __profiler =
	{ .name = "pxeapi.misc" };

/**
 * Handle an unknown PXE API call
 *
 * @v pxenv_unknown 			Pointer to a struct s_PXENV_UNKNOWN
 * @ret #PXENV_EXIT_FAILURE		Always
 * @err #PXENV_STATUS_UNSUPPORTED	Always
 */
static PXENV_EXIT_t pxenv_unknown ( struct s_PXENV_UNKNOWN *pxenv_unknown ) {
	pxenv_unknown->Status = PXENV_STATUS_UNSUPPORTED;
	return PXENV_EXIT_FAILURE;
}

/** Unknown PXE API call list */
struct pxe_api_call pxenv_unknown_api __pxe_api_call =
	PXE_API_CALL ( PXENV_UNKNOWN, pxenv_unknown, struct s_PXENV_UNKNOWN );

/**
 * Locate PXE API call
 *
 * @v opcode		Opcode
 * @ret call		PXE API call, or NULL
 */
static struct pxe_api_call * find_pxe_api_call ( uint16_t opcode ) {
	struct pxe_api_call *call;

	for_each_table_entry ( call, PXE_API_CALLS ) {
		if ( call->opcode == opcode )
			return call;
	}
	return NULL;
}

/**
 * Determine applicable profiler (for debugging)
 *
 * @v opcode		PXE opcode
 * @ret profiler	Profiler
 */
static struct profiler * pxe_api_profiler ( unsigned int opcode ) {

	/* Determine applicable profiler */
	switch ( opcode ) {
	case PXENV_UNDI_TRANSMIT:
		return &pxe_api_tx_profiler;
	case PXENV_UNDI_ISR:
		return &pxe_api_isr_profiler;
	case PXENV_UNKNOWN:
		return &pxe_api_unknown_profiler;
	default:
		return &pxe_api_misc_profiler;
	}
}

/**
 * Dispatch PXE API call
 *
 * @v bx		PXE opcode
 * @v es:di		Address of PXE parameter block
 * @ret ax		PXE exit code
 */
__asmcall void pxe_api_call ( struct i386_all_regs *ix86 ) {
	uint16_t opcode = ix86->regs.bx;
	userptr_t uparams = real_to_user ( ix86->segs.es, ix86->regs.di );
	struct profiler *profiler = pxe_api_profiler ( opcode );
	struct pxe_api_call *call;
	union u_PXENV_ANY params;
	PXENV_EXIT_t ret;

	/* Start profiling */
	profile_start ( profiler );

	/* Locate API call */
	call = find_pxe_api_call ( opcode );
	if ( ! call ) {
		DBGC ( &pxe_netdev, "PXENV_UNKNOWN_%04x\n", opcode );
		call = &pxenv_unknown_api;
	}

	/* Copy parameter block from caller */
	copy_from_user ( &params, uparams, 0, call->params_len );

	/* Set default status in case child routine fails to do so */
	params.Status = PXENV_STATUS_FAILURE;

	/* Hand off to relevant API routine */
	ret = call->entry ( &params );

	/* Copy modified parameter block back to caller and return */
	copy_to_user ( uparams, 0, &params, call->params_len );
	ix86->regs.ax = ret;

	/* Stop profiling, if applicable */
	profile_stop ( profiler );
}

/**
 * Dispatch weak PXE API call with PXE stack available
 *
 * @v ix86		Registers for PXE call
 * @ret present		Zero (PXE stack present)
 */
int pxe_api_call_weak ( struct i386_all_regs *ix86 ) {
	pxe_api_call ( ix86 );
	return 0;
}

/**
 * Dispatch PXE loader call
 *
 * @v es:di		Address of PXE parameter block
 * @ret ax		PXE exit code
 */
__asmcall void pxe_loader_call ( struct i386_all_regs *ix86 ) {
	userptr_t uparams = real_to_user ( ix86->segs.es, ix86->regs.di );
	struct s_UNDI_LOADER params;
	PXENV_EXIT_t ret;

	/* Copy parameter block from caller */
	copy_from_user ( &params, uparams, 0, sizeof ( params ) );

	/* Fill in ROM segment address */
	ppxe.UNDIROMID.segment = ix86->segs.ds;

	/* Set default status in case child routine fails to do so */
	params.Status = PXENV_STATUS_FAILURE;

	/* Call UNDI loader */
	ret = undi_loader ( &params );

	/* Copy modified parameter block back to caller and return */
	copy_to_user ( uparams, 0, &params, sizeof ( params ) );
	ix86->regs.ax = ret;
}

/**
 * Calculate byte checksum as used by PXE
 *
 * @v data		Data
 * @v size		Length of data
 * @ret sum		Checksum
 */
static uint8_t pxe_checksum ( void *data, size_t size ) {
	uint8_t *bytes = data;
	uint8_t sum = 0;

	while ( size-- ) {
		sum += *bytes++;
	}
	return sum;
}

/**
 * Initialise !PXE and PXENV+ structures
 *
 */
static void pxe_init_structures ( void ) {
	uint32_t rm_cs_phys = ( rm_cs << 4 );
	uint32_t rm_ds_phys = ( rm_ds << 4 );

	/* Fill in missing segment fields */
	ppxe.EntryPointSP.segment = rm_cs;
	ppxe.EntryPointESP.segment = rm_cs;
	ppxe.Stack.segment_address = rm_ds;
	ppxe.Stack.Physical_address = rm_ds_phys;
	ppxe.UNDIData.segment_address = rm_ds;
	ppxe.UNDIData.Physical_address = rm_ds_phys;
	ppxe.UNDICode.segment_address = rm_cs;
	ppxe.UNDICode.Physical_address = rm_cs_phys;
	ppxe.UNDICodeWrite.segment_address = rm_cs;
	ppxe.UNDICodeWrite.Physical_address = rm_cs_phys;
	pxenv.RMEntry.segment = rm_cs;
	pxenv.StackSeg = rm_ds;
	pxenv.UNDIDataSeg = rm_ds;
	pxenv.UNDICodeSeg = rm_cs;
	pxenv.PXEPtr.segment = rm_cs;

	/* Update checksums */
	ppxe.StructCksum -= pxe_checksum ( &ppxe, sizeof ( ppxe ) );
	pxenv.Checksum -= pxe_checksum ( &pxenv, sizeof ( pxenv ) );
}

/** PXE structure initialiser */
struct init_fn pxe_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = pxe_init_structures,
};

/**
 * Activate PXE stack
 *
 * @v netdev		Net device to use as PXE net device
 */
void pxe_activate ( struct net_device *netdev ) {

	/* Ensure INT 1A is hooked */
	if ( ! int_1a_hooked ) {
		hook_bios_interrupt ( 0x1a, ( unsigned int ) pxe_int_1a,
				      &pxe_int_1a_vector );
		devices_get();
		int_1a_hooked = 1;
	}

	/* Set PXE network device */
	pxe_set_netdev ( netdev );
}

/**
 * Deactivate PXE stack
 *
 * @ret rc		Return status code
 */
int pxe_deactivate ( void ) {
	int rc;

	/* Clear PXE network device */
	pxe_set_netdev ( NULL );

	/* Ensure INT 1A is unhooked, if possible */
	if ( int_1a_hooked ) {
		if ( ( rc = unhook_bios_interrupt ( 0x1a,
						    (unsigned int) pxe_int_1a,
						    &pxe_int_1a_vector ))!= 0){
			DBG ( "Could not unhook INT 1A: %s\n",
			      strerror ( rc ) );
			return rc;
		}
		devices_put();
		int_1a_hooked = 0;
	}

	return 0;
}

/** Jump buffer for PXENV_RESTART_TFTP */
rmjmp_buf pxe_restart_nbp;

/**
 * Start PXE NBP at 0000:7c00
 *
 * @ret rc		Return status code
 */
int pxe_start_nbp ( void ) {
	int jmp;
	int discard_b, discard_c, discard_d, discard_D;
	uint16_t status;

	/* Allow restarting NBP via PXENV_RESTART_TFTP */
	jmp = rmsetjmp ( pxe_restart_nbp );
	if ( jmp )
		DBG ( "Restarting NBP (%x)\n", jmp );

	/* Far call to PXE NBP */
	__asm__ __volatile__ ( REAL_CODE ( "pushl %%ebp\n\t" /* gcc bug */
					   "movw %%cx, %%es\n\t"
					   "pushw %%es\n\t"
					   "pushw %%di\n\t"
					   "sti\n\t"
					   "lcall $0, $0x7c00\n\t"
					   "popl %%ebp\n\t" /* discard */
					   "popl %%ebp\n\t" /* gcc bug */ )
			       : "=a" ( status ), "=b" ( discard_b ),
				 "=c" ( discard_c ), "=d" ( discard_d ),
				 "=D" ( discard_D )
			       : "a" ( 0 ), "b" ( __from_text16 ( &pxenv ) ),
			         "c" ( rm_cs ),
			         "d" ( virt_to_phys ( &pxenv ) ),
				 "D" ( __from_text16 ( &ppxe ) )
			       : "esi", "memory" );
	if ( status )
		return -EPXENBP ( status );

	return 0;
}

REQUIRING_SYMBOL ( pxe_api_call );
REQUIRE_OBJECT ( pxe_preboot );
REQUIRE_OBJECT ( pxe_undi );
REQUIRE_OBJECT ( pxe_udp );
REQUIRE_OBJECT ( pxe_tftp );
REQUIRE_OBJECT ( pxe_file );
