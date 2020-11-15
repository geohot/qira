#ifndef _SNPNET_H
#define _SNPNET_H

/** @file
 *
 * SNP NIC driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

struct efi_device;

extern int snpnet_start ( struct efi_device *efidev );
extern void snpnet_stop ( struct efi_device *efidev );

#endif /* _SNPNET_H */
