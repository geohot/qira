/** @file
 *
 * PXE exit hook
 *
 */

/*
 * Copyright (C) 2010 Shao Miller <shao.miller@yrdsb.edu.on.ca>.
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
#include <realmode.h>
#include <pxe.h>

/** PXE exit hook */
extern segoff_t __data16 ( pxe_exit_hook );
#define pxe_exit_hook __use_data16 ( pxe_exit_hook )

/**
 * FILE EXIT HOOK
 *
 * @v file_exit_hook			Pointer to a struct
 *					s_PXENV_FILE_EXIT_HOOK
 * @v s_PXENV_FILE_EXIT_HOOK::Hook	SEG16:OFF16 to jump to
 * @ret #PXENV_EXIT_SUCCESS		Successfully set hook
 * @ret #PXENV_EXIT_FAILURE		We're not an NBP build
 * @ret s_PXENV_FILE_EXIT_HOOK::Status	PXE status code
 *
 */
static PXENV_EXIT_t
pxenv_file_exit_hook ( struct s_PXENV_FILE_EXIT_HOOK *file_exit_hook ) {
	DBG ( "PXENV_FILE_EXIT_HOOK" );

	/* We'll jump to the specified SEG16:OFF16 during exit */
	pxe_exit_hook.segment = file_exit_hook->Hook.segment;
	pxe_exit_hook.offset = file_exit_hook->Hook.offset;
	file_exit_hook->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/** PXE file API */
struct pxe_api_call pxe_file_api_exit_hook __pxe_api_call =
	PXE_API_CALL ( PXENV_FILE_EXIT_HOOK, pxenv_file_exit_hook,
		       struct s_PXENV_FILE_EXIT_HOOK );
