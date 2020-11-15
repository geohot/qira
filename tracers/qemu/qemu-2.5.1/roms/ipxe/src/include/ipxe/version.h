#ifndef _IPXE_VERSION_H
#define _IPXE_VERSION_H

/** @file
 *
 * Version number
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <wchar.h>

extern unsigned long build_timestamp;
extern unsigned long build_id;
extern const int product_major_version;
extern const int product_minor_version;
extern const char product_version[];
extern const char product_name[];
extern const char product_short_name[];
extern const char build_name[];
extern const wchar_t product_wversion[];
extern const wchar_t product_wname[];
extern const wchar_t product_short_wname[];
extern const wchar_t build_wname[];

#endif /* _IPXE_VERSION_H */
