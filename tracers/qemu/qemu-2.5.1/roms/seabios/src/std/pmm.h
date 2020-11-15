#ifndef __PMM_H
#define __PMM_H

#include "types.h" // u32

#define PMM_SIGNATURE 0x4d4d5024 // $PMM

struct pmmheader {
    u32 signature;
    u8 version;
    u8 length;
    u8 checksum;
    struct segoff_s entry;
    u8 reserved[5];
} PACKED;

#define PMM_FUNCTION_NOT_SUPPORTED 0xffffffff

#endif // pmm.h
