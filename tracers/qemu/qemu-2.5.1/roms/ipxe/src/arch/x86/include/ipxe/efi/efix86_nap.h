#ifndef _IPXE_EFIX86_NAP_H
#define _IPXE_EFIX86_NAP_H

/** @file
 *
 * EFI CPU sleeping
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef NAP_EFIX86
#define NAP_PREFIX_efix86
#else
#define NAP_PREFIX_efix86 __efix86_
#endif

#endif /* _IPXE_EFIX86_NAP_H */
