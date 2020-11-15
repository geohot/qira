/******************************************************************************
 * Copyright (c) 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

/*
 * Common byteorder (endianness) macros
 */

#ifndef BYTEORDER_H
#define BYTEORDER_H

#include <stdint.h>

static inline uint16_t
bswap_16 (uint16_t x)
{
	return __builtin_bswap16(x);
}

static inline uint32_t
bswap_32 (uint32_t x)
{
	return __builtin_bswap32(x);
}

static inline uint64_t
bswap_64 (uint64_t x)
{
	return __builtin_bswap64(x);
}

static inline void
bswap_16p (uint16_t *x)
{
	*x = __builtin_bswap16(*x);
}

static inline void
bswap_32p (uint32_t *x)
{
	*x = __builtin_bswap32(*x);
}

static inline void
bswap_64p (uint64_t *x)
{
	*x = __builtin_bswap64(*x);
}


/* gcc defines __BIG_ENDIAN__ on big endian targets */
#ifdef __BIG_ENDIAN__

#define cpu_to_be16(x) (x)
#define cpu_to_be32(x) (x)
#define cpu_to_be64(x) (x)

#define be16_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#define be64_to_cpu(x) (x)

#define le16_to_cpu(x) bswap_16(x)
#define le32_to_cpu(x) bswap_32(x)
#define le64_to_cpu(x) bswap_64(x)

#define cpu_to_le16(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)

#else

#define cpu_to_be16(x) bswap_16(x)
#define cpu_to_be32(x) bswap_32(x)
#define cpu_to_be64(x) bswap_64(x)

#define be16_to_cpu(x) bswap_16(x)
#define be32_to_cpu(x) bswap_32(x)
#define be64_to_cpu(x) bswap_64(x)

#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)

#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)

#endif  /* __BIG_ENDIAN__ */

#endif  /* BYTEORDER_H */
