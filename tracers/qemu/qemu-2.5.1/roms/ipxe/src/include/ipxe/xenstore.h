#ifndef _IPXE_XENSTORE_H
#define _IPXE_XENSTORE_H

/** @file
 *
 * XenStore interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/xen.h>

extern __attribute__ (( sentinel )) int
xenstore_read ( struct xen_hypervisor *xen, char **value, ... );
extern __attribute__ (( sentinel )) int
xenstore_read_num ( struct xen_hypervisor *xen, unsigned long *num, ... );
extern __attribute__ (( sentinel )) int
xenstore_write ( struct xen_hypervisor *xen, const char *value, ... );
extern __attribute__ (( sentinel )) int
xenstore_write_num ( struct xen_hypervisor *xen, unsigned long num, ... );
extern __attribute__ (( sentinel )) int
xenstore_rm ( struct xen_hypervisor *xen, ... );
extern __attribute__ (( sentinel )) int
xenstore_directory ( struct xen_hypervisor *xen, char **children, size_t *len,
		     ... );
extern void xenstore_dump ( struct xen_hypervisor *xen, const char *key );

#endif /* _IPXE_XENSTORE_H */
