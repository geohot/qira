#ifndef _IPXE_EFI_STRINGS_H
#define _IPXE_EFI_STRINGS_H

/** @file
 *
 * EFI strings
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

extern int efi_vsnprintf ( wchar_t *wbuf, size_t wsize, const char *fmt,
			   va_list args );
extern int efi_snprintf ( wchar_t *wbuf, size_t wsize, const char *fmt, ... );
extern int efi_vssnprintf ( wchar_t *wbuf, ssize_t swsize, const char *fmt,
			    va_list args );
extern int efi_ssnprintf ( wchar_t *wbuf, ssize_t swsize,
			   const char *fmt, ... );

#endif /* _IPXE_EFI_STRINGS_H */
