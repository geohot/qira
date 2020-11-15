/*
 * <endian.h>
 *
 * Open Hack'Ware BIOS: provides all common endianness conversions functions
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * This file provides:
 *  void cpu_to_be16p (uint16_t *outp, uint16_t in);
 *  void cpu_to_be32p (uint32_t *outp, uint32_t in);
 *  void cpu_to_be64p (uint64_t *outp, uint64_t in);
 *  void cpu_to_le16p (uint16_t *outp, uint16_t in);
 *  void cpu_to_le32p (uint32_t *outp, uint32_t in);
 *  void cpu_to_le64p (uint64_t *outp, uint64_t in);
 *  void endian_to_cpu16p (uint16_t *outp, uint16_t in, endian_t endian);
 *  void endian_to_cpu32p (uint32_t *outp, uint32_t in, endian_t endian);
 *  void endian_to_cpu64p (uint64_t *outp, uint64_t in, endian_t endian);
 *  void cpu16_to_endianp (uint16_t *outp, uint16_t in, endian_t endian);
 *  void cpu32_to_endianp (uint32_t *outp, uint32_t in, endian_t endian);
 *  void cpu64_to_endianp (uint64_t *outp, uint64_t in, endian_t endian);
 *
 */

#if !defined (__OHW_ENDIAN_H__)
#define __OHW_ENDIAN_H__

#include <stdint.h>

typedef enum endian_t endian_t;
enum endian_t {
    ENDIAN_1234 = 0,
    ENDIAN_4321,
    ENDIAN_3412,
    ENDIAN_2143,
};

/* Generic endian conversion functions */
static inline void generic_cpu_swap16p (uint16_t *outp, uint16_t in)
{
    *outp = ((in & 0xFF00) >> 8) | ((in & 0x00FF) << 8);
}

static inline void generic_cpu_swap32p (uint32_t *outp, uint32_t in)
{
    *outp = ((in & 0xFF000000) >> 24) | ((in & 0x00FF0000) >> 8) |
        ((in & 0x0000FF00) << 8) | ((in & 0x000000FF) << 24);
}

static inline void generic_cpu_swap64p (uint64_t *outp, uint64_t in)
{
    *outp = ((in & 0xFF00000000000000ULL) >> 56) |
        ((in & 0x00FF000000000000ULL) >> 40) |
        ((in & 0x0000FF0000000000ULL) >> 24) |
        ((in & 0x000000FF00000000ULL) >> 8) |
        ((in & 0x00000000FF000000ULL) << 8) |
        ((in & 0x0000000000FF0000ULL) << 24) |
        ((in & 0x000000000000FF00ULL) << 40) |
        ((in & 0x00000000000000FFULL) << 56);
}

static inline void generic_cpu_swap64p_32 (uint64_t *outp, uint64_t in)
{
    uint32_t *_outp = (uint32_t *)outp;

    generic_cpu_swap32p(_outp, in);
    generic_cpu_swap32p(_outp + 1, in >> 32);
}

#if defined (__i386__)

#define __CPU_ENDIAN_4321__
#define __CPU_LENGTH_32__

#elif defined (__x86_64__)

#define __CPU_ENDIAN_4321__
#define __CPU_LENGTH_64__

#elif defined (__powerpc__) || defined (_ARCH_PPC)

#define __CPU_ENDIAN_1234__
#define __CPU_LENGTH_32__

#define __HAVE_CPU_SWAP16P__
static inline void cpu_swap16p (uint16_t *outp, uint16_t in)
{
    __asm__ __volatile__ ("sthbrx %4, 0(%3)");
}

#define __HAVE_CPU_SWAP32P__
static inline void cpu_swap32p (uint32_t *outp, uint32_t in)
{
    __asm__ __volatile__ ("stwbrx %4, 0(%3)");
}

#define __HAVE_CPU_SWAP64P__
static inline void cpu_swap64p (uint64_t *outp, uint64_t in)
{
    return generic_cpu_swap64p_32(outp, in);
}

#else

#error "unsupported CPU architecture"

#endif

/* Use generic swap function if no cpu specific were provided */
#if !defined (__HAVE_CPU_SWAP16P__)
static inline void cpu_swap16p (uint16_t *outp, uint16_t in)
{
    generic_cpu_swap16p(outp, in);
}
#endif

#if !defined (__HAVE_CPU_SWAP32P__)
static inline void cpu_swap32p (uint32_t *outp, uint32_t in)
{
    generic_cpu_swap32p(outp, in);
}
#endif

#if !defined (__HAVE_CPU_SWAP64P__)
static inline void cpu_swap64p (uint64_t *outp, uint64_t in)
{
#if defined (__CPU_LENGTH_64__)
    generic_cpu_swap64p(outp, in);
#elif defined (__CPU_LENGTH_32__)
    generic_cpu_swap64p_32(outp, in);
#else
#error "Don't know how to make 64 bits swapping on this arch"
#endif
}
#endif

static inline void cpu_nswap16p (uint16_t *outp, uint16_t in)
{
    *outp = in;
}

static inline void cpu_nswap32p (uint32_t *outp, uint32_t in)
{
    *outp = in;
}

static inline void cpu_nswap64p (uint64_t *outp, uint64_t in)
{
    *outp = in;
}

static inline void _endian_be16_p (uint16_t *outp, uint16_t in,
                                   endian_t endian)
{
    switch (endian) {
    case ENDIAN_4321:
    case ENDIAN_2143:
        cpu_swap16p(outp, in);
        break;
    case ENDIAN_1234:
    case ENDIAN_3412:
        cpu_nswap16p(outp, in);
        break;
    }
}        

static inline void _endian_be32_p (uint32_t *outp, uint32_t in,
                                   endian_t endian)
{
    switch (endian) {
    case ENDIAN_4321:
        cpu_swap32p(outp, in);
        break;
    case ENDIAN_1234:
        cpu_nswap32p(outp, in);
        break;
    case ENDIAN_2143:
        /* TODO */
        break;
    case ENDIAN_3412:
        /* TODO */
        break;
    }
}        

static inline void _endian_be64_p (uint64_t *outp, uint64_t in,
                                   endian_t endian)
{
    switch (endian) {
    case ENDIAN_4321:
        cpu_swap64p(outp, in);
        break;
    case ENDIAN_1234:
        cpu_nswap64p(outp, in);
        break;
    case ENDIAN_2143:
        /* TODO */
        break;
    case ENDIAN_3412:
        /* TODO */
        break;
    }
}        

static inline void _endian_le16_p (uint16_t *outp, uint16_t in,
                                   endian_t endian)
{
    switch (endian) {
    case ENDIAN_4321:
    case ENDIAN_2143:
        cpu_nswap16p(outp, in);
        break;
    case ENDIAN_1234:
    case ENDIAN_3412:
        cpu_swap16p(outp, in);
        break;
    }
}        

static inline void _endian_le32_p (uint32_t *outp, uint32_t in,
                                   endian_t endian)
{
    switch (endian) {
    case ENDIAN_4321:
        cpu_nswap32p(outp, in);
        break;
    case ENDIAN_1234:
        cpu_swap32p(outp, in);
        break;
    case ENDIAN_2143:
        /* TODO */
        break;
    case ENDIAN_3412:
        /* TODO */
        break;
    }
}        

static inline void _endian_le64_p (uint64_t *outp, uint64_t in,
                                   endian_t endian)
{
    switch (endian) {
    case ENDIAN_4321:
        cpu_nswap64p(outp, in);
        break;
    case ENDIAN_1234:
        cpu_swap64p(outp, in);
        break;
    case ENDIAN_2143:
        /* TODO */
        break;
    case ENDIAN_3412:
        /* TODO */
        break;
    }
}        

static inline void endian_to_be16p (uint16_t *outp, uint16_t in,
                                    endian_t endian)
{
    _endian_be16_p(outp, in, endian);
}

static inline void endian_to_be32p (uint32_t *outp, uint32_t in,
                                    endian_t endian)
{
    _endian_be32_p(outp, in, endian);
}

static inline void endian_to_be64p (uint64_t *outp, uint64_t in,
                                    endian_t endian)
{
    _endian_be64_p(outp, in, endian);
}

static inline void endian_to_le16p (uint16_t *outp, uint16_t in,
                                    endian_t endian)
{
    _endian_le16_p(outp, in, endian);
}

static inline void endian_to_le32p (uint32_t *outp, uint32_t in,
                                    endian_t endian)
{
    _endian_le32_p(outp, in, endian);
}

static inline void endian_to_le64p (uint64_t *outp, uint64_t in,
                                    endian_t endian)
{
    _endian_le64_p(outp, in, endian);
}

static inline void be16_to_endianp (uint16_t *outp, uint16_t in,
                                    endian_t endian)
{
    _endian_be16_p(outp, in, endian);
}

static inline void be32_to_endianp (uint32_t *outp, uint32_t in,
                                    endian_t endian)
{
    _endian_be32_p(outp, in, endian);
}

static inline void be64_to_endianp (uint64_t *outp, uint64_t in,
                                    endian_t endian)
{
    _endian_be64_p(outp, in, endian);
}

static inline void le16_to_endianp (uint16_t *outp, uint16_t in,
                                    endian_t endian)
{
    _endian_le16_p(outp, in, endian);
}

static inline void le32_to_endianp (uint32_t *outp, uint32_t in,
                                    endian_t endian)
{
    _endian_le32_p(outp, in, endian);
}

static inline void le64_to_endianp (uint64_t *outp, uint64_t in,
                                    endian_t endian)
{
    _endian_le64_p(outp, in, endian);
}

#if defined (__CPU_ENDIAN_4321__)

static inline void cpu_to_be16p (uint16_t *outp, uint16_t in)
{
    cpu_swap16p(outp, in);
}

static inline void cpu_to_be32p (uint32_t *outp, uint32_t in)
{
    cpu_swap32p(outp, in);
}

static inline void cpu_to_be64p (uint64_t *outp, uint64_t in)
{
    cpu_swap64p(outp, in);
}

static inline void cpu_to_le16p (uint16_t *outp, uint16_t in)
{
    cpu_nswap16p(outp, in);
}

static inline void cpu_to_le32p (uint32_t *outp, uint32_t in)
{
    cpu_nswap32p(outp, in);
}

static inline void cpu_to_le64p (uint64_t *outp, uint64_t in)
{
    cpu_nswap64p(outp, in);
}

static inline void be16_to_cpup (uint16_t *outp, uint16_t in)
{
    cpu_swap16p(outp, in);
}

static inline void be32_to_cpup (uint32_t *outp, uint32_t in)
{
    cpu_swap32p(outp, in);
}

static inline void be64_to_cpup (uint64_t *outp, uint64_t in)
{
    cpu_swap64p(outp, in);
}

static inline void le16_to_cpup (uint16_t *outp, uint16_t in)
{
    cpu_nswap16p(outp, in);
}

static inline void le32_to_cpup (uint32_t *outp, uint32_t in)
{
    cpu_nswap32p(outp, in);
}

static inline void le64_to_cpup (uint64_t *outp, uint64_t in)
{
    cpu_nswap64p(outp, in);
}

static inline void endian_to_cpu16p (uint16_t *outp, uint16_t in,
                                     endian_t endian)
{
    endian_to_le16p(outp, in, endian);
}

static inline void endian_to_cpu32p (uint32_t *outp, uint32_t in,
                                     endian_t endian)
{
    endian_to_le32p(outp, in, endian);
}

static inline void endian_to_cpu64p (uint64_t *outp, uint64_t in,
                                     endian_t endian)
{
    endian_to_le64p(outp, in, endian);
}

static inline void cpu16_to_endianp (uint16_t *outp, uint16_t in,
                                     endian_t endian)
{
    le16_to_endianp(outp, in, endian);
}

static inline void cpu32_to_endianp (uint32_t *outp, uint32_t in,
                                     endian_t endian)
{
    le32_to_endianp(outp, in, endian);
}

static inline void cpu64_to_endianp (uint64_t *outp, uint64_t in,
                                     endian_t endian)
{
    le64_to_endianp(outp, in, endian);
}

#elif defined (__CPU_ENDIAN_1234__)

static inline void cpu_to_be16p (uint16_t *outp, uint16_t in)
{
    cpu_nswap16p(outp, in);
}

static inline void cpu_to_be32p (uint32_t *outp, uint32_t in)
{
    cpu_nswap32p(outp, in);
}

static inline void cpu_to_be64p (uint64_t *outp, uint64_t in)
{
    cpu_nswap64p(outp, in);
}

static inline void cpu_to_le16p (uint16_t *outp, uint16_t in)
{
    cpu_swap16p(outp, in);
}

static inline void cpu_to_le32p (uint32_t *outp, uint32_t in)
{
    cpu_swap32p(outp, in);
}

static inline void cpu_to_le64p (uint64_t *outp, uint64_t in)
{
    cpu_swap64p(outp, in);
}

static inline void endian_to_cpu16p (uint16_t *outp, uint16_t in,
                                     endian_t endian)
{
    endian_to_be16p(outp, in, endian);
}

static inline void endian_to_cpu32p (uint32_t *outp, uint32_t in,
                                     endian_t endian)
{
    endian_to_be32p(outp, in, endian);
}

static inline void endian_to_cpu64p (uint64_t *outp, uint64_t in,
                                     endian_t endian)
{
    endian_to_be64p(outp, in, endian);
}

static inline void cpu16_to_endianp (uint16_t *outp, uint16_t in,
                                     endian_t endian)
{
    be16_to_endianp(outp, in, endian);
}

static inline void cpu32_to_endianp (uint32_t *outp, uint32_t in,
                                     endian_t endian)
{
    be32_to_endianp(outp, in, endian);
}

static inline void cpu64_to_endianp (uint64_t *outp, uint64_t in,
                                     endian_t endian)
{
    be64_to_endianp(outp, in, endian);
}

#else /* 2143 / 3412 */
/* TODO */
#error "TODO"
#endif

#endif /* !defined (__OHW_ENDIAN_H__) */
