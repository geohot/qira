#ifndef __CONFIG_H
#define __CONFIG_H

#include "autoconf.h"

// Configuration definitions.

//#define BUILD_APPNAME  "QEMU"
//#define BUILD_CPUNAME8 "QEMUCPU "
//#define BUILD_APPNAME6 "QEMU  "
//#define BUILD_APPNAME4 "QEMU"
#define BUILD_APPNAME  "Bochs"
#define BUILD_CPUNAME8 "BOCHSCPU"
#define BUILD_APPNAME6 "BOCHS "
#define BUILD_APPNAME4 "BXPC"

// Maximum number of map entries in the e820 map
#define BUILD_MAX_E820 32
// Space to reserve in high-memory for tables
#define BUILD_MAX_HIGHTABLE (256*1024)
// Largest supported externaly facing drive id
#define BUILD_MAX_EXTDRIVE 16
// Number of bytes the smbios may be and still live in the f-segment
#define BUILD_MAX_SMBIOS_FSEG     600

#define BUILD_MODEL_ID      0xFC
#define BUILD_SUBMODEL_ID   0x00
#define BUILD_BIOS_REVISION 0x01

// Various memory addresses used by the code.
#define BUILD_STACK_ADDR          0x7000
#define BUILD_S3RESUME_STACK_ADDR 0x1000
#define BUILD_AP_BOOT_ADDR        0x10000
#define BUILD_EBDA_MINIMUM        0x90000
#define BUILD_LOWRAM_END          0xa0000
#define BUILD_ROM_START           0xc0000
#define BUILD_BIOS_ADDR           0xf0000
#define BUILD_BIOS_SIZE           0x10000
#define BUILD_EXTRA_STACK_SIZE    0x800
// 32KB for shadow ram copying (works around emulator deficiencies)
#define BUILD_BIOS_TMP_ADDR       0x30000
#define BUILD_SMM_INIT_ADDR       0x30000
#define BUILD_SMM_ADDR            0xa0000

#define BUILD_PCIMEM_START        0xe0000000
#define BUILD_PCIMEM_END          0xfec00000    /* IOAPIC is mapped at */
#define BUILD_PCIMEM64_START      0x8000000000ULL
#define BUILD_PCIMEM64_END        0x10000000000ULL

#define BUILD_IOAPIC_ADDR         0xfec00000
#define BUILD_IOAPIC_ID           0
#define BUILD_HPET_ADDRESS        0xfed00000
#define BUILD_APIC_ADDR           0xfee00000

// PCI IRQS
#define BUILD_PCI_IRQS            ((1<<5) | (1<<9) | (1<<10) | (1<<11))

// Important real-mode segments
#define SEG_IVT      0x0000
#define SEG_BDA      0x0040
#define SEG_BIOS     0xf000

// Segment definitions in protected mode (see rombios32_gdt in misc.c)
#define SEG32_MODE32_CS    (1 << 3)
#define SEG32_MODE32_DS    (2 << 3)
#define SEG32_MODE16_CS    (3 << 3)
#define SEG32_MODE16_DS    (4 << 3)
#define SEG32_MODE16BIG_CS (5 << 3)
#define SEG32_MODE16BIG_DS (6 << 3)

// Debugging levels.  If non-zero and CONFIG_DEBUG_LEVEL is greater
// than the specified value, then the corresponding irq handler will
// report every enter event.
#define DEBUG_ISR_02 1
#define DEBUG_HDL_05 1
#define DEBUG_ISR_08 20
#define DEBUG_ISR_09 9
#define DEBUG_ISR_0e 9
#define DEBUG_HDL_10 20
#define DEBUG_HDL_11 2
#define DEBUG_HDL_12 2
#define DEBUG_HDL_13 10
#define DEBUG_HDL_14 2
#define DEBUG_HDL_15 9
#define DEBUG_HDL_16 9
#define DEBUG_HDL_17 2
#define DEBUG_HDL_18 1
#define DEBUG_HDL_19 1
#define DEBUG_HDL_1a 9
#define DEBUG_HDL_40 1
#define DEBUG_ISR_70 9
#define DEBUG_ISR_74 9
#define DEBUG_ISR_75 1
#define DEBUG_ISR_76 10
#define DEBUG_ISR_hwpic1 5
#define DEBUG_ISR_hwpic2 5
#define DEBUG_HDL_smi 9
#define DEBUG_HDL_smp 1
#define DEBUG_HDL_pnp 1
#define DEBUG_HDL_pmm 1
#define DEBUG_HDL_pcibios 9
#define DEBUG_HDL_apm 9

#define DEBUG_unimplemented 2
#define DEBUG_invalid 3
#define DEBUG_thread 2

#endif // config.h
