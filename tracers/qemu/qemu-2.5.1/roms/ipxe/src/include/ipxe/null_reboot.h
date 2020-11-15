#ifndef _IPXE_NULL_REBOOT_H
#define _IPXE_NULL_REBOOT_H

/** @file
 *
 * iPXE do-nothing reboot API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef REBOOT_NULL
#define REBOOT_PREFIX_null
#else
#define REBOOT_PREFIX_null __null_
#endif

#endif /* _IPXE_NULL_REBOOT_H */
