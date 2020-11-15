#ifndef PCI_H
#define PCI_H

#define PCI_VENDOR_ID		0x00
#define PCI_DEVICE_ID		0x02

#define PCI_COMMAND		0x04
#define  PCI_COMMAND_IO		0x01
#define  PCI_COMMAND_MEMORY	0x02
#define  PCI_COMMAND_BUS_MASTER	0x04

#define PCI_STATUS              0x06    /* 16 bits */
#define  PCI_STATUS_CAP_LIST    0x10    /* Support Capability List */
#define  PCI_STATUS_66MHZ       0x20    /* Support 66 Mhz PCI 2.1 bus */
#define  PCI_STATUS_UDF         0x40    /* Support User Definable Features
					   [obsolete] */
#define  PCI_STATUS_FAST_BACK   0x80    /* Accept fast-back to back */
#define  PCI_STATUS_PARITY      0x100   /* Detected parity error */
#define  PCI_STATUS_DEVSEL_MASK 0x600   /* DEVSEL timing */
#define  PCI_STATUS_DEVSEL_FAST 0x000
#define  PCI_STATUS_DEVSEL_MEDIUM 0x200
#define  PCI_STATUS_DEVSEL_SLOW 0x400
#define  PCI_STATUS_SIG_TARGET_ABORT 0x800 /* Set on target abort */
#define  PCI_STATUS_REC_TARGET_ABORT 0x1000 /* Master ack of " */
#define  PCI_STATUS_REC_MASTER_ABORT 0x2000 /* Set on master abort */
#define  PCI_STATUS_SIG_SYSTEM_ERROR 0x4000 /* Set when we drive SERR */
#define  PCI_STATUS_DETECTED_PARITY 0x8000 /* Set on parity error */


#define PCI_REVISION_ID 	0x08    /* Revision ID */
#define PCI_CLASS_DISPLAY	0x03
#define PCI_CLASS_PROG		0x09
#define PCI_CLASS_DEVICE	0x0a
#define PCI_CACHE_LINE_SIZE     0x0c    /* 8 bits */
#define PCI_HEADER_TYPE		0x0e
#define  PCI_HEADER_TYPE_NORMAL 0x00
#define  PCI_HEADER_TYPE_BRIDGE 0x01
#define  PCI_HEADER_TYPE_CARDBUS 0x02
#define PCI_PRIMARY_BUS     0x18
#define PCI_SECONDARY_BUS   0x19
#define PCI_SUBORDINATE_BUS 0x1A
#define PCI_BASE_ADDR_0		0x10
#define PCI_BASE_ADDR_1		0x14
#define PCI_BASE_ADDR_2		0x18
#define PCI_BASE_ADDR_3		0x1c
#define PCI_BASE_ADDR_4		0x20
#define PCI_BASE_ADDR_5		0x24

#define PCI_SUBSYSTEM_VENDOR_ID 0x2c
#define PCI_SUBSYSTEM_ID        0x2e

#define PCI_ROM_ADDRESS		0x30    /* Bits 31..11 are address, 10..1 reserved */
#define PCI_ROM_ADDRESS_ENABLE	0x01
#define PCI_ROM_ADDRESS_MASK	(~0x7ffUL)
#define PCI_ROM_ADDRESS1	0x38    /* ROM_ADDRESS in bridge header */

#define PCI_INTERRUPT_LINE      0x3c    /* 8 bits */
#define PCI_INTERRUPT_PIN       0x3d    /* 8 bits */
#define PCI_MIN_GNT             0x3e    /* 8 bits */
#define PCI_MAX_LAT             0x3f    /* 8 bits */

typedef struct {
        u16     signature;
        u8      reserved[0x16];
        u16     dptr;
} rom_header_t;

typedef struct {
        u32     signature;
        u16     vendor;
        u16     device;
        u16     reserved_1;
        u16     dlen;
        u8      drevision;
        u8      class_hi;
        u16     class_lo;
        u16     ilen;
        u16     irevision;
        u8      type;
        u8      indicator;
        u16     reserved_2;
} pci_data_t;


#include "asm/pci.h"

#endif /* PCI_H */
