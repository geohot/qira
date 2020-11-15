#ifndef __PNPHEADER_H
#define __PNPHEADER_H

#define PNP_SIGNATURE 0x506e5024 // $PnP

struct pnpheader {
    u32 signature;
    u8 version;
    u8 length;
    u16 control;
    u8 checksum;
    u32 eventloc;
    u16 real_ip;
    u16 real_cs;
    u16 prot_ip;
    u32 prot_base;
    u32 oemid;
    u16 real_ds;
    u32 prot_database;
} PACKED;

#define FUNCTION_NOT_SUPPORTED 0x82

#endif // pnpheader.h
