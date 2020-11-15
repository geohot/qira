/*****************************************************************************
 * PXE prefix that keeps the whole PXE stack present
 *****************************************************************************
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

#define PXELOADER_KEEP_UNDI
#define PXELOADER_KEEP_PXE
#define _pxe_start _kkpxe_start
#include "pxeprefix.S"
