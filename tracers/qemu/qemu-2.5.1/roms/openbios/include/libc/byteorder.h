/* tag: byteorder prototypes
 *
 * Copyright (C) 2004 Stefan Reinauer
 *
 * see the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */
#ifndef __BYTEORDER_H
#define __BYTEORDER_H

#define __bswap32(x) \
	((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
	(((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

#define __bswap16(x) ((((x) & 0xff00) >>  8) | (((x) & 0x00ff) << 8))

#define __bswap64(x) ( (__bswap32( (x)  >> 32)) | \
		(__bswap32((x) & 0xffffffff) << 32) )

#ifdef CONFIG_LITTLE_ENDIAN
#define __cpu_to_le64(x) ((u64) (x))
#define __le64_to_cpu(x) ((u64) (x))
#define __cpu_to_le32(x) ((u32) (x))
#define __le32_to_cpu(x) ((u32) (x))
#define __cpu_to_le16(x) ((u16) (x))
#define __le16_to_cpu(x) ((u16) (x))
#define __cpu_to_be64(x) (__bswap64((u64) (x)))
#define __be64_to_cpu(x) (__bswap64((u64) (x)))
#define __cpu_to_be32(x) (__bswap32((u32) (x)))
#define __be32_to_cpu(x) (__bswap32((u32) (x)))
#define __cpu_to_be16(x) (__bswap16((u16) (x)))
#define __be16_to_cpu(x) (__bswap16((u16) (x)))
#endif
#ifdef CONFIG_BIG_ENDIAN
#define __cpu_to_le64(x) (__bswap64((u64) (x)))
#define __le64_to_cpu(x) (__bswap64((u64) (x)))
#define __cpu_to_le32(x) (__bswap32((u32) (x)))
#define __le32_to_cpu(x) (__bswap32((u32) (x)))
#define __cpu_to_le16(x) (__bswap16((u16) (x)))
#define __le16_to_cpu(x) (__bswap16((u16) (x)))
#define __cpu_to_be64(x) ((u64) (x))
#define __be64_to_cpu(x) ((u64) (x))
#define __cpu_to_be32(x) ((u32) (x))
#define __be32_to_cpu(x) ((u32) (x))
#define __cpu_to_be16(x) ((u16) (x))
#define __be16_to_cpu(x) ((u16) (x))
#endif

#if BITS==32
#define __becell_to_cpu(x) (__be32_to_cpu(x))
#define __lecell_to_cpu(x) (__le32_to_cpu(x))
#define __cpu_to_becell(x) (__cpu_to_be32(x))
#define __cpu_to_lecell(x) (__cpu_to_le32(x))
#else
#define __becell_to_cpu(x) (__be64_to_cpu(x))
#define __lecell_to_cpu(x) (__le64_to_cpu(x))
#define __cpu_to_becell(x) (__cpu_to_be64(x))
#define __cpu_to_lecell(x) (__cpu_to_le64(x))
#endif

#endif
