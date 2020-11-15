#ifndef __MPTABLE_H
#define __MPTABLE_H

#include "types.h" // u32

#define MPTABLE_SIGNATURE 0x5f504d5f  // "_MP_"

struct mptable_floating_s {
    u32 signature;
    u32 physaddr;
    u8 length;
    u8 spec_rev;
    u8 checksum;
    u8 feature1;
    u8 feature2;
    u8 reserved[3];
};

#define MPCONFIG_SIGNATURE 0x504d4350  // "PCMP"

struct mptable_config_s {
    u32 signature;
    u16 length;
    u8 spec;
    u8 checksum;
    char oemid[8];
    char productid[12];
    u32 oemptr;
    u16 oemsize;
    u16 entrycount;
    u32 lapic;
    u16 exttable_length;
    u8 exttable_checksum;
    u8 reserved;
} PACKED;

#define MPT_TYPE_CPU 0
#define MPT_TYPE_BUS 1
#define MPT_TYPE_IOAPIC 2
#define MPT_TYPE_INTSRC 3
#define MPT_TYPE_LOCAL_INT 4

struct mpt_cpu {
    u8 type;
    u8 apicid;
    u8 apicver;
    u8 cpuflag;
    u32 cpusignature;
    u32 featureflag;
    u32 reserved[2];
} PACKED;

struct mpt_bus {
    u8 type;
    u8 busid;
    char bustype[6];
} PACKED;

struct mpt_ioapic {
    u8 type;
    u8 apicid;
    u8 apicver;
    u8 flags;
    u32 apicaddr;
} PACKED;

struct mpt_intsrc {
    u8 type;
    u8 irqtype;
    u16 irqflag;
    u8 srcbus;
    u8 srcbusirq;
    u8 dstapic;
    u8 dstirq;
} PACKED;

#endif // mptable.h
