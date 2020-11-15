#ifndef __ACPI_H
#define __ACPI_H

#include "types.h" // u32

/*
 * ACPI 2.0 Generic Address Space definition.
 */
struct acpi_20_generic_address {
    u8  address_space_id;
    u8  register_bit_width;
    u8  register_bit_offset;
    u8  reserved;
    u64 address;
} PACKED;

#define RSDP_SIGNATURE 0x2052545020445352LL // "RSD PTR "

struct rsdp_descriptor {        /* Root System Descriptor Pointer */
    u64 signature;              /* ACPI signature, contains "RSD PTR " */
    u8  checksum;               /* To make sum of struct == 0 */
    u8  oem_id [6];             /* OEM identification */
    u8  revision;               /* Must be 0 for 1.0, 2 for 2.0 */
    u32 rsdt_physical_address;  /* 32-bit physical address of RSDT */
    u32 length;                 /* XSDT Length in bytes including hdr */
    u64 xsdt_physical_address;  /* 64-bit physical address of XSDT */
    u8  extended_checksum;      /* Checksum of entire table */
    u8  reserved [3];           /* Reserved field must be 0 */
};

/* Table structure from Linux kernel (the ACPI tables are under the
   BSD license) */

#define ACPI_TABLE_HEADER_DEF   /* ACPI common table header */ \
    u32 signature;          /* ACPI signature (4 ASCII characters) */ \
    u32 length;                 /* Length of table, in bytes, including header */ \
    u8  revision;               /* ACPI Specification minor version # */ \
    u8  checksum;               /* To make sum of entire table == 0 */ \
    u8  oem_id [6];             /* OEM identification */ \
    u8  oem_table_id [8];       /* OEM table identification */ \
    u32 oem_revision;           /* OEM revision number */ \
    u8  asl_compiler_id [4];    /* ASL compiler vendor ID */ \
    u32 asl_compiler_revision;  /* ASL compiler revision number */

/*
 * Fixed ACPI Description Table Fixed Feature Flags
 */
#define    ACPI_FADT_F_WBINVD            (1 << 0)
#define    ACPI_FADT_F_WBINVD_FLUSH      (1 << 1)
#define    ACPI_FADT_F_PROC_C1           (1 << 2)
#define    ACPI_FADT_F_P_LVL2_UP         (1 << 3)
#define    ACPI_FADT_F_PWR_BUTTON        (1 << 4)
#define    ACPI_FADT_F_SLP_BUTTON        (1 << 5)
#define    ACPI_FADT_F_FIX_RTC           (1 << 6)
#define    ACPI_FADT_F_RTC_S4            (1 << 7)
#define    ACPI_FADT_F_TMR_VAL_EXT       (1 << 8)
#define    ACPI_FADT_F_DCK_CAP           (1 << 9)
#define    ACPI_FADT_F_RESET_REG_SUP     (1 << 10)
#define    ACPI_FADT_F_SEALED_CASE       (1 << 11)
#define    ACPI_FADT_F_HEADLESS          (1 << 12)
#define    ACPI_FADT_F_CPU_SW_SLP        (1 << 13)
#define    ACPI_FADT_F_PCI_EXP_WAK       (1 << 14)
#define    ACPI_FADT_F_USE_PLATFORM_CLOCK (1 << 15)
#define    ACPI_FADT_F_S4_RTC_STS_VALID   (1 << 16)
#define    ACPI_FADT_F_REMOTE_POWER_ON_CAPABLE  (1 << 17)
#define    ACPI_FADT_F_FORCE_APIC_CLUSTER_MODEL  (1 << 18)
#define    ACPI_FADT_F_FORCE_APIC_PHYSICAL_DESTINATION_MODE  (1 << 19)
#define    ACPI_FADT_F_HW_REDUCED_ACPI    (1 << 20)
#define    ACPI_FADT_F_LOW_POWER_S0_IDLE_CAPABLE  (1 << 21)

/*
 * ACPI 1.0 Fixed ACPI Description Table (FADT)
 */
#define FACP_SIGNATURE 0x50434146 // FACP
struct fadt_descriptor_rev1
{
    ACPI_TABLE_HEADER_DEF     /* ACPI common table header */
    u32 firmware_ctrl;          /* Physical address of FACS */
    u32 dsdt;                   /* Physical address of DSDT */
    u8  model;                  /* System Interrupt Model */
    u8  reserved1;              /* Reserved */
    u16 sci_int;                /* System vector of SCI interrupt */
    u32 smi_cmd;                /* Port address of SMI command port */
    u8  acpi_enable;            /* Value to write to smi_cmd to enable ACPI */
    u8  acpi_disable;           /* Value to write to smi_cmd to disable ACPI */
    u8  S4bios_req;             /* Value to write to SMI CMD to enter S4BIOS state */
    u8  reserved2;              /* Reserved - must be zero */
    u32 pm1a_evt_blk;           /* Port address of Power Mgt 1a acpi_event Reg Blk */
    u32 pm1b_evt_blk;           /* Port address of Power Mgt 1b acpi_event Reg Blk */
    u32 pm1a_cnt_blk;           /* Port address of Power Mgt 1a Control Reg Blk */
    u32 pm1b_cnt_blk;           /* Port address of Power Mgt 1b Control Reg Blk */
    u32 pm2_cnt_blk;            /* Port address of Power Mgt 2 Control Reg Blk */
    u32 pm_tmr_blk;             /* Port address of Power Mgt Timer Ctrl Reg Blk */
    u32 gpe0_blk;               /* Port addr of General Purpose acpi_event 0 Reg Blk */
    u32 gpe1_blk;               /* Port addr of General Purpose acpi_event 1 Reg Blk */
    u8  pm1_evt_len;            /* Byte length of ports at pm1_x_evt_blk */
    u8  pm1_cnt_len;            /* Byte length of ports at pm1_x_cnt_blk */
    u8  pm2_cnt_len;            /* Byte Length of ports at pm2_cnt_blk */
    u8  pm_tmr_len;             /* Byte Length of ports at pm_tm_blk */
    u8  gpe0_blk_len;           /* Byte Length of ports at gpe0_blk */
    u8  gpe1_blk_len;           /* Byte Length of ports at gpe1_blk */
    u8  gpe1_base;              /* Offset in gpe model where gpe1 events start */
    u8  reserved3;              /* Reserved */
    u16 plvl2_lat;              /* Worst case HW latency to enter/exit C2 state */
    u16 plvl3_lat;              /* Worst case HW latency to enter/exit C3 state */
    u16 flush_size;             /* Size of area read to flush caches */
    u16 flush_stride;           /* Stride used in flushing caches */
    u8  duty_offset;            /* Bit location of duty cycle field in p_cnt reg */
    u8  duty_width;             /* Bit width of duty cycle field in p_cnt reg */
    u8  day_alrm;               /* Index to day-of-month alarm in RTC CMOS RAM */
    u8  mon_alrm;               /* Index to month-of-year alarm in RTC CMOS RAM */
    u8  century;                /* Index to century in RTC CMOS RAM */
    u8  reserved4;              /* Reserved */
    u8  reserved4a;             /* Reserved */
    u8  reserved4b;             /* Reserved */
    u32 flags;
} PACKED;

struct acpi_table_header         /* ACPI common table header */
{
    ACPI_TABLE_HEADER_DEF
} PACKED;

/*
 * ACPI 1.0 Root System Description Table (RSDT)
 */
#define RSDT_SIGNATURE 0x54445352 // RSDT
struct rsdt_descriptor_rev1
{
    ACPI_TABLE_HEADER_DEF       /* ACPI common table header */
    u32 table_offset_entry[0];  /* Array of pointers to other */
    /* ACPI tables */
} PACKED;

/*
 * ACPI 1.0 Firmware ACPI Control Structure (FACS)
 */
#define FACS_SIGNATURE 0x53434146 // FACS
struct facs_descriptor_rev1
{
    u32 signature;           /* ACPI Signature */
    u32 length;                 /* Length of structure, in bytes */
    u32 hardware_signature;     /* Hardware configuration signature */
    u32 firmware_waking_vector; /* ACPI OS waking vector */
    u32 global_lock;            /* Global Lock */
    u32 flags;
    u8  resverved3 [40];        /* Reserved - must be zero */
} PACKED;

/*
 * Differentiated System Description Table (DSDT)
 */
#define DSDT_SIGNATURE 0x54445344 // DSDT

/*
 * MADT values and structures
 */

/* Values for MADT PCATCompat */

#define DUAL_PIC                0
#define MULTIPLE_APIC           1

/* Master MADT */

#define APIC_SIGNATURE 0x43495041 // APIC
struct multiple_apic_table
{
    ACPI_TABLE_HEADER_DEF     /* ACPI common table header */
    u32 local_apic_address;     /* Physical address of local APIC */
    u32 flags;
} PACKED;

/* Values for Type in APIC sub-headers */

#define APIC_PROCESSOR          0
#define APIC_IO                 1
#define APIC_XRUPT_OVERRIDE     2
#define APIC_NMI                3
#define APIC_LOCAL_NMI          4
#define APIC_ADDRESS_OVERRIDE   5
#define APIC_IO_SAPIC           6
#define APIC_LOCAL_SAPIC        7
#define APIC_XRUPT_SOURCE       8
#define APIC_RESERVED           9           /* 9 and greater are reserved */

/*
 * MADT sub-structures (Follow MULTIPLE_APIC_DESCRIPTION_TABLE)
 */
#define ACPI_SUB_HEADER_DEF   /* Common ACPI sub-structure header */\
    u8  type;                               \
    u8  length;

/* Sub-structures for MADT */

struct madt_processor_apic
{
    ACPI_SUB_HEADER_DEF
    u8  processor_id;           /* ACPI processor id */
    u8  local_apic_id;          /* Processor's local APIC id */
    u32 flags;
} PACKED;

struct madt_io_apic
{
    ACPI_SUB_HEADER_DEF
    u8  io_apic_id;             /* I/O APIC ID */
    u8  reserved;               /* Reserved - must be zero */
    u32 address;                /* APIC physical address */
    u32 interrupt;              /* Global system interrupt where INTI
                                 * lines start */
} PACKED;

struct madt_intsrcovr {
    ACPI_SUB_HEADER_DEF
    u8  bus;
    u8  source;
    u32 gsi;
    u16 flags;
} PACKED;

struct madt_local_nmi {
    ACPI_SUB_HEADER_DEF
    u8  processor_id;           /* ACPI processor id */
    u16 flags;                  /* MPS INTI flags */
    u8  lint;                   /* Local APIC LINT# */
} PACKED;

/*
 * HPET Description Table
 */
#define HPET_SIGNATURE 0x54455048 // HPET
struct acpi_20_hpet {
    ACPI_TABLE_HEADER_DEF                    /* ACPI common table header */
    u32           timer_block_id;
    struct acpi_20_generic_address addr;
    u8            hpet_number;
    u16           min_tick;
    u8            page_protect;
} PACKED;

/*
 * SRAT (NUMA topology description) table
 */

#define SRAT_SIGNATURE 0x54415253 // SRAT
struct system_resource_affinity_table
{
    ACPI_TABLE_HEADER_DEF
    u32    reserved1;
    u32    reserved2[2];
} PACKED;

#define SRAT_PROCESSOR          0
#define SRAT_MEMORY             1

struct srat_processor_affinity
{
    ACPI_SUB_HEADER_DEF
    u8     proximity_lo;
    u8     local_apic_id;
    u32    flags;
    u8     local_sapic_eid;
    u8     proximity_hi[3];
    u32    reserved;
} PACKED;

struct srat_memory_affinity
{
    ACPI_SUB_HEADER_DEF
    u8     proximity[4];
    u16    reserved1;
    u64    base_addr;
    u64    range_length;
    u32    reserved2;
    u32    flags;
    u32    reserved3[2];
} PACKED;

/* PCI fw r3.0 MCFG table. */
/* Subtable */
struct acpi_mcfg_allocation {
    u64 address;                /* Base address, processor-relative */
    u16 pci_segment;            /* PCI segment group number */
    u8 start_bus_number;       /* Starting PCI Bus number */
    u8 end_bus_number;         /* Final PCI Bus number */
    u32 reserved;
} PACKED;

#define MCFG_SIGNATURE 0x4746434d       // MCFG
struct acpi_table_mcfg {
    ACPI_TABLE_HEADER_DEF;
    u8 reserved[8];
    struct acpi_mcfg_allocation allocation[0];
} PACKED;

#endif // acpi.h
