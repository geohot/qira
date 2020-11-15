#ifndef _IPXE_CRC32_H
#define _IPXE_CRC32_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

u32 crc32_le ( u32 seed, const void *data, size_t len );

#endif
