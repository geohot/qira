/*****************************************************************************
 * PXE prefix that keep the UNDI portion of the PXE stack present
 *****************************************************************************
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

#define PXELOADER_KEEP_UNDI
#define _pxe_start _kpxe_start
#include "pxeprefix.S"
