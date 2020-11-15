// Paravirtualization support.
//
// Copyright (C) 2013  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2009 Red Hat Inc.
//
// Authors:
//  Gleb Natapov <gnatapov@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "byteorder.h" // be32_to_cpu
#include "config.h" // CONFIG_QEMU
#include "hw/pci.h" // create_pirtable
#include "hw/pci_regs.h" // PCI_DEVICE_ID
#include "hw/rtc.h" // CMOS_*
#include "malloc.h" // malloc_tmp
#include "memmap.h" // add_e820
#include "output.h" // dprintf
#include "paravirt.h" // qemu_cfg_preinit
#include "romfile.h" // romfile_loadint
#include "romfile_loader.h" // romfile_loader_execute
#include "string.h" // memset
#include "util.h" // pci_setup
#include "x86.h" // cpuid
#include "xen.h" // xen_biostable_setup

// Amount of continuous ram under 4Gig
u32 RamSize;
// Amount of continuous ram >4Gig
u64 RamSizeOver4G;
// Type of emulator platform.
int PlatformRunningOn VARFSEG;

/* This CPUID returns the signature 'KVMKVMKVM' in ebx, ecx, and edx.  It
 * should be used to determine that a VM is running under KVM.
 */
#define KVM_CPUID_SIGNATURE     0x40000000

static void kvm_detect(void)
{
    unsigned int eax, ebx, ecx, edx;
    char signature[13];

    cpuid(KVM_CPUID_SIGNATURE, &eax, &ebx, &ecx, &edx);
    memcpy(signature + 0, &ebx, 4);
    memcpy(signature + 4, &ecx, 4);
    memcpy(signature + 8, &edx, 4);
    signature[12] = 0;

    if (strcmp(signature, "KVMKVMKVM") == 0) {
        dprintf(1, "Running on KVM\n");
        PlatformRunningOn |= PF_KVM;
    }
}

static void qemu_detect(void)
{
    if (!CONFIG_QEMU_HARDWARE)
        return;

    // check northbridge @ 00:00.0
    u16 v = pci_config_readw(0, PCI_VENDOR_ID);
    if (v == 0x0000 || v == 0xffff)
        return;
    u16 d = pci_config_readw(0, PCI_DEVICE_ID);
    u16 sv = pci_config_readw(0, PCI_SUBSYSTEM_VENDOR_ID);
    u16 sd = pci_config_readw(0, PCI_SUBSYSTEM_ID);

    if (sv != 0x1af4 || /* Red Hat, Inc */
        sd != 0x1100)   /* Qemu virtual machine */
        return;

    PlatformRunningOn |= PF_QEMU;
    switch (d) {
    case 0x1237:
        dprintf(1, "Running on QEMU (i440fx)\n");
        break;
    case 0x29c0:
        dprintf(1, "Running on QEMU (q35)\n");
        break;
    default:
        dprintf(1, "Running on QEMU (unknown nb: %04x:%04x)\n", v, d);
        break;
    }
    kvm_detect();
}

void
qemu_preinit(void)
{
    qemu_detect();

    if (!CONFIG_QEMU)
        return;

    if (runningOnXen()) {
        xen_ramsize_preinit();
        return;
    }

    if (!runningOnQEMU()) {
        dprintf(1, "Warning: No QEMU Northbridge found (isapc?)\n");
        PlatformRunningOn |= PF_QEMU;
        kvm_detect();
    }

    // On emulators, get memory size from nvram.
    u32 rs = ((rtc_read(CMOS_MEM_EXTMEM2_LOW) << 16)
              | (rtc_read(CMOS_MEM_EXTMEM2_HIGH) << 24));
    if (rs)
        rs += 16 * 1024 * 1024;
    else
        rs = (((rtc_read(CMOS_MEM_EXTMEM_LOW) << 10)
               | (rtc_read(CMOS_MEM_EXTMEM_HIGH) << 18))
              + 1 * 1024 * 1024);
    RamSize = rs;
    add_e820(0, rs, E820_RAM);

    /* reserve 256KB BIOS area at the end of 4 GB */
    add_e820(0xfffc0000, 256*1024, E820_RESERVED);

    dprintf(1, "RamSize: 0x%08x [cmos]\n", RamSize);
}

void
qemu_platform_setup(void)
{
    if (!CONFIG_QEMU)
        return;

    if (runningOnXen()) {
        pci_probe_devices();
        xen_hypercall_setup();
        xen_biostable_setup();
        return;
    }

    // Initialize pci
    pci_setup();
    smm_device_setup();
    smm_setup();

    // Initialize mtrr and smp
    mtrr_setup();
    smp_setup();

    // Create bios tables
    pirtable_setup();
    mptable_setup();
    smbios_setup();

    if (CONFIG_FW_ROMFILE_LOAD) {
        int loader_err;

        dprintf(3, "load ACPI tables\n");

        loader_err = romfile_loader_execute("etc/table-loader");

        RsdpAddr = find_acpi_rsdp();

        if (RsdpAddr)
            return;

        /* If present, loader should have installed an RSDP.
         * Not installed? We might still be able to continue
         * using the builtin RSDP.
         */
        if (!loader_err)
            warn_internalerror();
    }

    acpi_setup();
}


/****************************************************************
 * QEMU firmware config (fw_cfg) interface
 ****************************************************************/

// List of QEMU fw_cfg entries.  DO NOT ADD MORE.  (All new content
// should be passed via the fw_cfg "file" interface.)
#define QEMU_CFG_SIGNATURE              0x00
#define QEMU_CFG_ID                     0x01
#define QEMU_CFG_UUID                   0x02
#define QEMU_CFG_NUMA                   0x0d
#define QEMU_CFG_BOOT_MENU              0x0e
#define QEMU_CFG_MAX_CPUS               0x0f
#define QEMU_CFG_FILE_DIR               0x19
#define QEMU_CFG_ARCH_LOCAL             0x8000
#define QEMU_CFG_ACPI_TABLES            (QEMU_CFG_ARCH_LOCAL + 0)
#define QEMU_CFG_SMBIOS_ENTRIES         (QEMU_CFG_ARCH_LOCAL + 1)
#define QEMU_CFG_IRQ0_OVERRIDE          (QEMU_CFG_ARCH_LOCAL + 2)
#define QEMU_CFG_E820_TABLE             (QEMU_CFG_ARCH_LOCAL + 3)

static void
qemu_cfg_select(u16 f)
{
    outw(f, PORT_QEMU_CFG_CTL);
}

static void
qemu_cfg_read(void *buf, int len)
{
    insb(PORT_QEMU_CFG_DATA, buf, len);
}

static void
qemu_cfg_skip(int len)
{
    while (len--)
        inb(PORT_QEMU_CFG_DATA);
}

static void
qemu_cfg_read_entry(void *buf, int e, int len)
{
    qemu_cfg_select(e);
    qemu_cfg_read(buf, len);
}

struct qemu_romfile_s {
    struct romfile_s file;
    int select, skip;
};

static int
qemu_cfg_read_file(struct romfile_s *file, void *dst, u32 maxlen)
{
    if (file->size > maxlen)
        return -1;
    struct qemu_romfile_s *qfile;
    qfile = container_of(file, struct qemu_romfile_s, file);
    qemu_cfg_select(qfile->select);
    qemu_cfg_skip(qfile->skip);
    qemu_cfg_read(dst, file->size);
    return file->size;
}

static void
qemu_romfile_add(char *name, int select, int skip, int size)
{
    struct qemu_romfile_s *qfile = malloc_tmp(sizeof(*qfile));
    if (!qfile) {
        warn_noalloc();
        return;
    }
    memset(qfile, 0, sizeof(*qfile));
    strtcpy(qfile->file.name, name, sizeof(qfile->file.name));
    qfile->file.size = size;
    qfile->select = select;
    qfile->skip = skip;
    qfile->file.copy = qemu_cfg_read_file;
    romfile_add(&qfile->file);
}

struct e820_reservation {
    u64 address;
    u64 length;
    u32 type;
};

#define SMBIOS_FIELD_ENTRY 0
#define SMBIOS_TABLE_ENTRY 1

struct qemu_smbios_header {
    u16 length;
    u8 headertype;
    u8 tabletype;
    u16 fieldoffset;
} PACKED;

static void
qemu_cfg_e820(void)
{
    struct e820_reservation *table;
    int i, size;

    if (!CONFIG_QEMU)
        return;

    // "etc/e820" has both ram and reservations
    table = romfile_loadfile("etc/e820", &size);
    if (table) {
        for (i = 0; i < size / sizeof(struct e820_reservation); i++) {
            switch (table[i].type) {
            case E820_RAM:
                dprintf(1, "RamBlock: addr 0x%016llx len 0x%016llx [e820]\n",
                        table[i].address, table[i].length);
                if (table[i].address < RamSize)
                    // ignore, preinit got it from cmos already and
                    // adding this again would ruin any reservations
                    // done so far
                    continue;
                if (table[i].address < 0x100000000LL) {
                    // below 4g -- adjust RamSize to mark highest lowram addr
                    if (RamSize < table[i].address + table[i].length)
                        RamSize = table[i].address + table[i].length;
                } else {
                    // above 4g -- adjust RamSizeOver4G to mark highest ram addr
                    if (0x100000000LL + RamSizeOver4G < table[i].address + table[i].length)
                        RamSizeOver4G = table[i].address + table[i].length - 0x100000000LL;
                }
                /* fall through */
            case E820_RESERVED:
                add_e820(table[i].address, table[i].length, table[i].type);
                break;
            default:
                /*
                 * Qemu 1.7 uses RAM + RESERVED only.  Ignore
                 * everything else, so we have the option to
                 * extend this in the future without breakage.
                 */
                break;
            }
        }
        return;
    }

    // QEMU_CFG_E820_TABLE has reservations only
    u32 count32;
    qemu_cfg_read_entry(&count32, QEMU_CFG_E820_TABLE, sizeof(count32));
    if (count32) {
        struct e820_reservation entry;
        int i;
        for (i = 0; i < count32; i++) {
            qemu_cfg_read(&entry, sizeof(entry));
            add_e820(entry.address, entry.length, entry.type);
        }
    } else if (runningOnKVM()) {
        // Backwards compatibility - provide hard coded range.
        // 4 pages before the bios, 3 pages for vmx tss pages, the
        // other page for EPT real mode pagetable
        add_e820(0xfffbc000, 4*4096, E820_RESERVED);
    }

    // Check for memory over 4Gig in cmos
    u64 high = ((rtc_read(CMOS_MEM_HIGHMEM_LOW) << 16)
                | ((u32)rtc_read(CMOS_MEM_HIGHMEM_MID) << 24)
                | ((u64)rtc_read(CMOS_MEM_HIGHMEM_HIGH) << 32));
    RamSizeOver4G = high;
    add_e820(0x100000000ull, high, E820_RAM);
    dprintf(1, "RamSizeOver4G: 0x%016llx [cmos]\n", RamSizeOver4G);
}

// Populate romfile entries for legacy fw_cfg ports (that predate the
// "file" interface).
static void
qemu_cfg_legacy(void)
{
    if (!CONFIG_QEMU)
        return;

    // Misc config items.
    qemu_romfile_add("etc/show-boot-menu", QEMU_CFG_BOOT_MENU, 0, 2);
    qemu_romfile_add("etc/irq0-override", QEMU_CFG_IRQ0_OVERRIDE, 0, 1);
    qemu_romfile_add("etc/max-cpus", QEMU_CFG_MAX_CPUS, 0, 2);

    // NUMA data
    u64 numacount;
    qemu_cfg_read_entry(&numacount, QEMU_CFG_NUMA, sizeof(numacount));
    int max_cpu = romfile_loadint("etc/max-cpus", 0);
    qemu_romfile_add("etc/numa-cpu-map", QEMU_CFG_NUMA, sizeof(numacount)
                     , max_cpu*sizeof(u64));
    qemu_romfile_add("etc/numa-nodes", QEMU_CFG_NUMA
                     , sizeof(numacount) + max_cpu*sizeof(u64)
                     , numacount*sizeof(u64));

    // ACPI tables
    char name[128];
    u16 cnt;
    qemu_cfg_read_entry(&cnt, QEMU_CFG_ACPI_TABLES, sizeof(cnt));
    int i, offset = sizeof(cnt);
    for (i = 0; i < cnt; i++) {
        u16 len;
        qemu_cfg_read(&len, sizeof(len));
        offset += sizeof(len);
        snprintf(name, sizeof(name), "acpi/table%d", i);
        qemu_romfile_add(name, QEMU_CFG_ACPI_TABLES, offset, len);
        qemu_cfg_skip(len);
        offset += len;
    }

    // SMBIOS info
    qemu_cfg_read_entry(&cnt, QEMU_CFG_SMBIOS_ENTRIES, sizeof(cnt));
    offset = sizeof(cnt);
    for (i = 0; i < cnt; i++) {
        struct qemu_smbios_header header;
        qemu_cfg_read(&header, sizeof(header));
        if (header.headertype == SMBIOS_FIELD_ENTRY) {
            snprintf(name, sizeof(name), "smbios/field%d-%d"
                     , header.tabletype, header.fieldoffset);
            qemu_romfile_add(name, QEMU_CFG_SMBIOS_ENTRIES
                             , offset + sizeof(header)
                             , header.length - sizeof(header));
        } else {
            snprintf(name, sizeof(name), "smbios/table%d-%d"
                     , header.tabletype, i);
            qemu_romfile_add(name, QEMU_CFG_SMBIOS_ENTRIES
                             , offset + 3, header.length - 3);
        }
        qemu_cfg_skip(header.length - sizeof(header));
        offset += header.length;
    }
}

struct QemuCfgFile {
    u32  size;        /* file size */
    u16  select;      /* write this to 0x510 to read it */
    u16  reserved;
    char name[56];
};

void qemu_cfg_init(void)
{
    if (!runningOnQEMU())
        return;

    // Detect fw_cfg interface.
    qemu_cfg_select(QEMU_CFG_SIGNATURE);
    char *sig = "QEMU";
    int i;
    for (i = 0; i < 4; i++)
        if (inb(PORT_QEMU_CFG_DATA) != sig[i])
            return;
    dprintf(1, "Found QEMU fw_cfg\n");

    // Populate romfiles for legacy fw_cfg entries
    qemu_cfg_legacy();

    // Load files found in the fw_cfg file directory
    u32 count;
    qemu_cfg_read_entry(&count, QEMU_CFG_FILE_DIR, sizeof(count));
    count = be32_to_cpu(count);
    u32 e;
    for (e = 0; e < count; e++) {
        struct QemuCfgFile qfile;
        qemu_cfg_read(&qfile, sizeof(qfile));
        qemu_romfile_add(qfile.name, be16_to_cpu(qfile.select)
                         , 0, be32_to_cpu(qfile.size));
    }

    qemu_cfg_e820();

    if (romfile_find("etc/table-loader")) {
        acpi_pm_base = 0x0600;
        dprintf(1, "Moving pm_base to 0x%x\n", acpi_pm_base);
    }
}
