#ifndef _IPXE_ERRORTAB_H
#define _IPXE_ERRORTAB_H

/** @file
 *
 * Error message tables
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/tables.h>

struct errortab {
	int errno;
	const char *text;
};

#define ERRORTAB __table ( struct errortab, "errortab" )

#define __errortab __table_entry ( ERRORTAB, 01 )

#define __einfo_errortab( einfo ) {			\
	.errno = __einfo_errno ( einfo ),		\
	.text = __einfo_desc ( einfo ),			\
	}

#endif /* _IPXE_ERRORTAB_H */
