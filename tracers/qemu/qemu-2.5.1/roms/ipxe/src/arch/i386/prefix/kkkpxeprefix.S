/*****************************************************************************
 * PXE prefix that keeps the whole PXE stack present and provides an exit hook
 *
 * This prefix is essentially intended solely for the case of ipxelinux.0
 *****************************************************************************
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

/* Provide the PXENV_FILE_EXIT_HOOK API call */
REQUIRING_SYMBOL ( _kkkpxe_start )
REQUIRE_OBJECT ( pxe_exit_hook )

#define PXELOADER_KEEP_UNDI
#define PXELOADER_KEEP_PXE
#define _pxe_start _kkkpxe_start
#include "pxeprefix.S"
