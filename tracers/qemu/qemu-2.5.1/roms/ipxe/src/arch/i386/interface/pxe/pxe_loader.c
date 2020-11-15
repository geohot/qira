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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/init.h>
#include "pxe.h"
#include "pxe_call.h"

/** @file
 *
 * PXE UNDI loader
 *
 */

/* PXENV_UNDI_LOADER
 *
 */
PXENV_EXIT_t undi_loader ( struct s_UNDI_LOADER *undi_loader ) {

	/* Perform one-time initialisation (e.g. heap) */
	initialise();

	DBG ( "[PXENV_UNDI_LOADER to CS %04x DS %04x]",
	      undi_loader->UNDI_CS, undi_loader->UNDI_DS );

	/* Fill in UNDI loader structure */
	undi_loader->PXEptr.segment = rm_cs;
	undi_loader->PXEptr.offset = __from_text16 ( &ppxe );
	undi_loader->PXENVptr.segment = rm_cs;
	undi_loader->PXENVptr.offset = __from_text16 ( &pxenv );

	undi_loader->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}
