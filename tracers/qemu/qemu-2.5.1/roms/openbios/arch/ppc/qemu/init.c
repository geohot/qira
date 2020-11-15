/*
 *   Creation Date: <2004/08/28 18:38:22 greg>
 *   Time-stamp: <2004/08/28 18:38:22 greg>
 *
 *	<init.c>
 *
 *	Initialization for qemu
 *
 *   Copyright (C) 2004 Greg Watson
 *   Copyright (C) 2005 Stefan Reinauer
 *
 *   based on mol/init.c:
 *
 *   Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004 Samuel & David Rydh
 *      (samuel@ibrium.se, dary@lindesign.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/openbios.h"
#include "libopenbios/bindings.h"
#include "libopenbios/console.h"
#include "drivers/pci.h"
#include "arch/common/nvram.h"
#include "drivers/drivers.h"
#include "qemu/qemu.h"
#include "libopenbios/ofmem.h"
#include "openbios-version.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#define NO_QEMU_PROTOS
#include "arch/common/fw_cfg.h"
#include "arch/ppc/processor.h"

#define UUID_FMT "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"

struct cpudef {
    unsigned int iu_version;
    const char *name;
    int icache_size, dcache_size;
    int icache_sets, dcache_sets;
    int icache_block_size, dcache_block_size;
    int tlb_sets, tlb_size;
    void (*initfn)(const struct cpudef *cpu);
};

static uint16_t machine_id = 0;

extern void unexpected_excep(int vector);

void
unexpected_excep(int vector)
{
    printk("openbios panic: Unexpected exception %x\n", vector);
    for (;;) {
    }
}

extern void __divide_error(void);

void
__divide_error(void)
{
    return;
}

enum {
    ARCH_PREP = 0,
    ARCH_MAC99,
    ARCH_HEATHROW,
    ARCH_MAC99_U3,
};

int is_apple(void)
{
    return is_oldworld() || is_newworld();
}

int is_oldworld(void)
{
    return machine_id == ARCH_HEATHROW;
}

int is_newworld(void)
{
    return (machine_id == ARCH_MAC99) ||
           (machine_id == ARCH_MAC99_U3);
}

static const pci_arch_t known_arch[] = {
    [ARCH_PREP] = {
        .name = "PREP",
        .vendor_id = PCI_VENDOR_ID_MOTOROLA,
        .device_id = PCI_DEVICE_ID_MOTOROLA_RAVEN,
        .cfg_addr = 0x80000cf8,
        .cfg_data = 0x80000cfc,
        .cfg_base = 0x80000000,
        .cfg_len = 0x00100000,
        .host_pci_base = 0xc0000000,
        .pci_mem_base = 0x100000, /* avoid VGA at 0xa0000 */
        .mem_len = 0x10000000,
        .io_base = 0x80000000,
        .io_len = 0x00010000,
        .rbase = 0x00000000,
        .rlen = 0x00400000,
        .irqs = { 9, 11, 9, 11 }
    },
    [ARCH_MAC99] = {
        .name = "MAC99",
        .vendor_id = PCI_VENDOR_ID_APPLE,
        .device_id = PCI_DEVICE_ID_APPLE_UNI_N_PCI,
        .cfg_addr = 0xf2800000,
        .cfg_data = 0xf2c00000,
        .cfg_base = 0xf2000000,
        .cfg_len = 0x02000000,
        .host_pci_base = 0x0,
        .pci_mem_base = 0x80000000,
        .mem_len = 0x10000000,
        .io_base = 0xf2000000,
        .io_len = 0x00800000,
        .rbase = 0x00000000,
        .rlen = 0x01000000,
        .irqs = { 0x1b, 0x1c, 0x1d, 0x1e }
    },
    [ARCH_MAC99_U3] = {
        .name = "MAC99_U3",
        .vendor_id = PCI_VENDOR_ID_APPLE,
        .device_id = PCI_DEVICE_ID_APPLE_U3_AGP,
        .cfg_addr = 0xf0800000,
        .cfg_data = 0xf0c00000,
        .cfg_base = 0xf0000000,
        .cfg_len = 0x02000000,
        .host_pci_base = 0x0,
        .pci_mem_base = 0x80000000,
        .mem_len = 0x10000000,
        .io_base = 0xf2000000,
        .io_len = 0x00800000,
        .rbase = 0x00000000,
        .rlen = 0x01000000,
        .irqs = { 0x1b, 0x1c, 0x1d, 0x1e }
    },
    [ARCH_HEATHROW] = {
        .name = "HEATHROW",
        .vendor_id = PCI_VENDOR_ID_MOTOROLA,
        .device_id = PCI_DEVICE_ID_MOTOROLA_MPC106,
        .cfg_addr = 0xfec00000,
        .cfg_data = 0xfee00000,
        .cfg_base = 0x80000000,
        .cfg_len = 0x7f000000,
        .host_pci_base = 0x0,
        .pci_mem_base = 0x80000000,
        .mem_len = 0x10000000,
        .io_base = 0xfe000000,
        .io_len = 0x00800000,
        .rbase = 0xfd000000,
        .rlen = 0x01000000,
        .irqs = { 21, 22, 23, 24 }
    },
};
unsigned long isa_io_base;

extern struct _console_ops mac_console_ops, prep_console_ops;

void
entry(void)
{
    uint32_t temp = 0;
    char buf[5];

    arch = &known_arch[ARCH_HEATHROW];

    fw_cfg_init();

    fw_cfg_read(FW_CFG_SIGNATURE, buf, 4);
    buf[4] = '\0';
    if (strncmp(buf, "QEMU", 4) == 0) {
        temp = fw_cfg_read_i32(FW_CFG_ID);
        if (temp == 1) {
            machine_id = fw_cfg_read_i16(FW_CFG_MACHINE_ID);
            arch = &known_arch[machine_id];
        }
    }

    isa_io_base = arch->io_base;

#ifdef CONFIG_DEBUG_CONSOLE
    if (is_apple()) {
        init_console(mac_console_ops);
    } else {
        init_console(prep_console_ops);
    }
#endif

    if (temp != 1) {
        printk("Incompatible configuration device version, freezing\n");
        for (;;) {
        }
    }

    ofmem_init();
    initialize_forth();
    /* won't return */

    printk("of_startup returned!\n");
    for (;;) {
    }
}

/* -- phys.lo ... phys.hi */
static void
push_physaddr(phys_addr_t value)
{
    PUSH(value);
#ifdef CONFIG_PPC64
    PUSH(value >> 32);
#endif
}

/* From drivers/timer.c */
extern unsigned long timer_freq;

static void
cpu_generic_init(const struct cpudef *cpu)
{
    push_str("/cpus");
    fword("find-device");

    fword("new-device");

    push_str(cpu->name);
    fword("device-name");

    push_str("cpu");
    fword("device-type");

    PUSH(mfpvr());
    fword("encode-int");
    push_str("cpu-version");
    fword("property");

    PUSH(cpu->dcache_size);
    fword("encode-int");
    push_str("d-cache-size");
    fword("property");

    PUSH(cpu->icache_size);
    fword("encode-int");
    push_str("i-cache-size");
    fword("property");

    PUSH(cpu->dcache_sets);
    fword("encode-int");
    push_str("d-cache-sets");
    fword("property");

    PUSH(cpu->icache_sets);
    fword("encode-int");
    push_str("i-cache-sets");
    fword("property");

    PUSH(cpu->dcache_block_size);
    fword("encode-int");
    push_str("d-cache-block-size");
    fword("property");

    PUSH(cpu->icache_block_size);
    fword("encode-int");
    push_str("i-cache-block-size");
    fword("property");

    PUSH(cpu->tlb_sets);
    fword("encode-int");
    push_str("tlb-sets");
    fword("property");

    PUSH(cpu->tlb_size);
    fword("encode-int");
    push_str("tlb-size");
    fword("property");

    timer_freq = fw_cfg_read_i32(FW_CFG_PPC_TBFREQ);
    PUSH(timer_freq);
    fword("encode-int");
    push_str("timebase-frequency");
    fword("property");

    PUSH(fw_cfg_read_i32(FW_CFG_PPC_CLOCKFREQ));
    fword("encode-int");
    push_str("clock-frequency");
    fword("property");

    PUSH(fw_cfg_read_i32(FW_CFG_PPC_BUSFREQ));
    fword("encode-int");
    push_str("bus-frequency");
    fword("property");

    push_str("running");
    fword("encode-string");
    push_str("state");
    fword("property");

    PUSH(0x20);
    fword("encode-int");
    push_str("reservation-granule-size");
    fword("property");
}

static void
cpu_add_pir_property(void)
{
    unsigned long pir;

    asm("mfspr %0, 1023\n"
        : "=r"(pir) :);
    PUSH(pir);
    fword("encode-int");
    push_str("reg");
    fword("property");
}

static void
cpu_604_init(const struct cpudef *cpu)
{
    cpu_generic_init(cpu);
    cpu_add_pir_property();

    fword("finish-device");
}

static void
cpu_750_init(const struct cpudef *cpu)
{
    cpu_generic_init(cpu);

    PUSH(0);
    fword("encode-int");
    push_str("reg");
    fword("property");

    fword("finish-device");
}

static void
cpu_g4_init(const struct cpudef *cpu)
{
    cpu_generic_init(cpu);
    cpu_add_pir_property();

    fword("finish-device");
}

#ifdef CONFIG_PPC_64BITSUPPORT
/* In order to get 64 bit aware handlers that rescue all our
   GPRs from getting truncated to 32 bits, we need to patch the
   existing handlers so they jump to our 64 bit aware ones. */
static void
ppc64_patch_handlers(void)
{
    uint32_t *dsi = (uint32_t *)0x300UL;
    uint32_t *isi = (uint32_t *)0x400UL;

    // Patch the first DSI handler instruction to: ba 0x2000
    *dsi = 0x48002002;

    // Patch the first ISI handler instruction to: ba 0x2200
    *isi = 0x48002202;

    // Invalidate the cache lines
    asm ("icbi 0, %0" : : "r"(dsi));
    asm ("icbi 0, %0" : : "r"(isi));
}
#endif

static void
cpu_970_init(const struct cpudef *cpu)
{
    cpu_generic_init(cpu);

    PUSH(0);
    fword("encode-int");
    push_str("reg");
    fword("property");
    
    PUSH(0);
    PUSH(0);
    fword("encode-bytes");
    push_str("64-bit");
    fword("property");

    fword("finish-device");

#ifdef CONFIG_PPC_64BITSUPPORT
    /* The 970 is a PPC64 CPU, so we need to activate
     * 64bit aware interrupt handlers */

    ppc64_patch_handlers();
#endif

    /* The 970 also implements the HIOR which we need to set to 0 */

    mtspr(S_HIOR, 0);
}

static const struct cpudef ppc_defs[] = {
    {
        .iu_version = 0x00040000,
        .name = "PowerPC,604",
        .icache_size = 0x4000,
        .dcache_size = 0x4000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_604_init,
    },
    { // XXX find out real values
        .iu_version = 0x00090000,
        .name = "PowerPC,604e",
        .icache_size = 0x4000,
        .dcache_size = 0x4000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_604_init,
    },
    { // XXX find out real values
        .iu_version = 0x000a0000,
        .name = "PowerPC,604r",
        .icache_size = 0x4000,
        .dcache_size = 0x4000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_604_init,
    },
    { // XXX find out real values
        .iu_version = 0x80040000,
        .name = "PowerPC,MPC86xx",
        .icache_size = 0x8000,
        .dcache_size = 0x8000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_750_init,
    },
    {
        .iu_version = 0x000080000,
        .name = "PowerPC,750",
        .icache_size = 0x8000,
        .dcache_size = 0x8000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_750_init,
    },
    { // XXX find out real values
        .iu_version = 0x10080000,
        .name = "PowerPC,750",
        .icache_size = 0x8000,
        .dcache_size = 0x8000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_750_init,
    },
    { // XXX find out real values
        .iu_version = 0x70000000,
        .name = "PowerPC,750",
        .icache_size = 0x8000,
        .dcache_size = 0x8000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_750_init,
    },
    { // XXX find out real values
        .iu_version = 0x70020000,
        .name = "PowerPC,750",
        .icache_size = 0x8000,
        .dcache_size = 0x8000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_750_init,
    },
    { // XXX find out real values
        .iu_version = 0x800c0000,
        .name = "PowerPC,74xx",
        .icache_size = 0x8000,
        .dcache_size = 0x8000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_750_init,
    },
    {
        .iu_version = 0x0000c0000,
        .name = "PowerPC,G4",
        .icache_size = 0x8000,
        .dcache_size = 0x8000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x20,
        .dcache_block_size = 0x20,
        .tlb_sets = 0x40,
        .tlb_size = 0x80,
        .initfn = cpu_g4_init,
    },
    {
        .iu_version = 0x00390000,
        .name = "PowerPC,970",
        .icache_size = 0x10000,
        .dcache_size = 0x8000,
        .icache_sets = 0x200,
        .dcache_sets = 0x80,
        .icache_block_size = 0x80,
        .dcache_block_size = 0x80,
        .tlb_sets = 0x100,
        .tlb_size = 0x1000,
        .initfn = cpu_970_init,
    },
    { // XXX find out real values
        .iu_version = 0x003C0000,
        .name = "PowerPC,970FX",
        .icache_size = 0x10000,
        .dcache_size = 0x8000,
        .icache_sets = 0x80,
        .dcache_sets = 0x80,
        .icache_block_size = 0x80,
        .dcache_block_size = 0x80,
        .tlb_sets = 0x100,
        .tlb_size = 0x1000,
        .initfn = cpu_970_init,
    },
    {
        .iu_version = 0x00350000,
        .name = "PowerPC,POWER4",
        .icache_size = 0x10000,
        .dcache_size = 0x8000,
        .icache_sets = 0x100,
        .dcache_sets = 0x40,
        .icache_block_size = 0x80,
        .dcache_block_size = 0x80,
        .tlb_sets = 0x100,
        .tlb_size = 0x1000,
        .initfn = cpu_970_init,
    },
};

static const struct cpudef *
id_cpu(void)
{
    unsigned int iu_version;
    unsigned int i;

    iu_version = mfpvr() & 0xffff0000;

    for (i = 0; i < sizeof(ppc_defs) / sizeof(struct cpudef); i++) {
        if (iu_version == ppc_defs[i].iu_version)
            return &ppc_defs[i];
    }
    printk("Unknown cpu (pvr %x), freezing!\n", iu_version);
    for (;;) {
    }
}

static void go(void);

static void
go(void)
{
    ucell addr;

    feval("saved-program-state >sps.entry @");
    addr = POP();

    call_elf(0, 0, addr);
}

static void kvm_of_init(void)
{
    char hypercall[4 * 4];
    uint32_t *hc32;

    /* Don't expose /hypervisor when not in KVM */
    if (!fw_cfg_read_i32(FW_CFG_PPC_IS_KVM))
        return;

    push_str("/");
    fword("find-device");

    fword("new-device");

    push_str("hypervisor");
    fword("device-name");

    push_str("hypervisor");
    fword("device-type");

    /* compatible */

    push_str("linux,kvm");
    fword("encode-string");
    push_str("epapr,hypervisor-0.2");
    fword("encode-string");
    fword("encode+");
    push_str("compatible");
    fword("property");

    /* Tell the guest about the hypercall instructions */
    fw_cfg_read(FW_CFG_PPC_KVM_HC, hypercall, 4 * 4);
    hc32 = (uint32_t*)hypercall;
    PUSH(hc32[0]);
    fword("encode-int");
    PUSH(hc32[1]);
    fword("encode-int");
    fword("encode+");
    PUSH(hc32[2]);
    fword("encode-int");
    fword("encode+");
    PUSH(hc32[3]);
    fword("encode-int");
    fword("encode+");
    push_str("hcall-instructions");
    fword("property");

    /* ePAPR requires us to provide a unique guest id */
    PUSH(fw_cfg_read_i32(FW_CFG_PPC_KVM_PID));
    fword("encode-int");
    push_str("guest-id");
    fword("property");

    /* ePAPR requires us to provide a guest name */
    push_str("KVM guest");
    fword("encode-string");
    push_str("guest-name");
    fword("property");

    fword("finish-device");
}

/*
 *  filll        ( addr bytes quad -- )
 */

static void ffilll(void)
{
    const u32 longval = POP();
    u32 bytes = POP();
    u32 *laddr = (u32 *)cell2pointer(POP());
    u32 len;
    
    for (len = 0; len < bytes / sizeof(u32); len++) {
        *laddr++ = longval;
    }   
}

/*
 * adler32        ( adler buf len -- checksum )
 *
 * Adapted from Mark Adler's original implementation (zlib license)
 *
 * Both OS 9 and BootX require this word for payload validation.
 */

#define DO1(buf,i)  {s1 += buf[i]; s2 += s1;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

static void adler32(void)
{
    uint32_t len = (uint32_t)POP();
    char *buf = (char *)POP();
    uint32_t adler = (uint32_t)POP();

    if (buf == NULL) {
        RET(-1);
    }

    uint32_t base = 65521;
    uint32_t nmax = 5552;

    uint32_t s1 = adler & 0xffff;
    uint32_t s2 = (adler >> 16) & 0xffff;

    uint32_t k;
    while (len > 0) {
        k = (len < nmax ? len : nmax);
        len -= k;

        while (k >= 16) {
            DO16(buf);
            buf += 16;
            k -= 16;
        }
        if (k != 0) {
            do {
                s1 += *buf++;
                s2 += s1;
            } while (--k);
        }

        s1 %= base;
        s2 %= base;
    }

    RET(s2 << 16 | s1);
}

void
arch_of_init(void)
{
#ifdef CONFIG_RTAS
    phandle_t ph;
#endif
    uint64_t ram_size;
    const struct cpudef *cpu;
    char buf[64], qemu_uuid[16];
    const char *stdin_path, *stdout_path, *boot_path;
    uint32_t temp = 0;
    char *boot_device;
    ofmem_t *ofmem = ofmem_arch_get_private();

    openbios_init();
    modules_init();
    setup_timers();
#ifdef CONFIG_DRIVER_PCI
    ob_pci_init();
#endif

    printk("\n");
    printk("=============================================================\n");
    printk(PROGRAM_NAME " " OPENBIOS_VERSION_STR " [%s]\n",
           OPENBIOS_BUILD_DATE);

    fw_cfg_read(FW_CFG_SIGNATURE, buf, 4);
    buf[4] = '\0';
    printk("Configuration device id %s", buf);

    temp = fw_cfg_read_i32(FW_CFG_ID);
    printk(" version %d machine id %d\n", temp, machine_id);

    temp = fw_cfg_read_i32(FW_CFG_NB_CPUS);

    printk("CPUs: %x\n", temp);

    ram_size = ofmem->ramsize;

    printk("Memory: %lldM\n", ram_size / 1024 / 1024);

    fw_cfg_read(FW_CFG_UUID, qemu_uuid, 16);

    printk("UUID: " UUID_FMT "\n", qemu_uuid[0], qemu_uuid[1], qemu_uuid[2],
           qemu_uuid[3], qemu_uuid[4], qemu_uuid[5], qemu_uuid[6],
           qemu_uuid[7], qemu_uuid[8], qemu_uuid[9], qemu_uuid[10],
           qemu_uuid[11], qemu_uuid[12], qemu_uuid[13], qemu_uuid[14],
           qemu_uuid[15]);

    /* set device tree root info */

    push_str("/");
    fword("find-device");

    switch(machine_id) {
    case ARCH_HEATHROW:	/* OldWorld */

        /* model */

        push_str("Power Macintosh");
        fword("model");

        /* compatible */

        push_str("AAPL,PowerMac G3");
        fword("encode-string");
        push_str("MacRISC");
        fword("encode-string");
        fword("encode+");
        push_str("compatible");
        fword("property");

        /* misc */

        push_str("device-tree");
        fword("encode-string");
        push_str("AAPL,original-name");
        fword("property");

        PUSH(0);
        fword("encode-int");
        push_str("AAPL,cpu-id");
        fword("property");

        PUSH(66 * 1000 * 1000);
        fword("encode-int");
        push_str("clock-frequency");
        fword("property");
        break;

    case ARCH_MAC99:
    case ARCH_MAC99_U3:
    case ARCH_PREP:
    default:

        /* model */

        push_str("PowerMac3,1");
        fword("model");

        /* compatible */

        push_str("PowerMac3,1");
        fword("encode-string");
        push_str("MacRISC");
        fword("encode-string");
        fword("encode+");
        push_str("MacRISC2");
        fword("encode-string");
        fword("encode+");
        push_str("Power Macintosh");
        fword("encode-string");
        fword("encode+");
        push_str("compatible");
        fword("property");

        /* misc */

        push_str("bootrom");
        fword("device-type");

        PUSH(100 * 1000 * 1000);
        fword("encode-int");
        push_str("clock-frequency");
        fword("property");
        break;
    }

    /* Perhaps we can store UUID here ? */

    push_str("0000000000000");
    fword("encode-string");
    push_str("system-id");
    fword("property");

    /* memory info */

    push_str("/memory");
    fword("find-device");

    /* all memory */

    push_physaddr(0);
    fword("encode-phys");
    /* This needs adjusting if #size-cells gets increased.
       Alternatively use multiple (address, size) tuples. */
    PUSH(ram_size & 0xffffffff);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    cpu = id_cpu();
    cpu->initfn(cpu);
    printk("CPU type %s\n", cpu->name);

    snprintf(buf, sizeof(buf), "/cpus/%s", cpu->name);
    ofmem_register(find_dev("/memory"), find_dev(buf));
    node_methods_init(buf);

#ifdef CONFIG_RTAS
    /* OldWorld Macs don't have an /rtas node. */
    switch (machine_id) {
    case ARCH_MAC99:
    case ARCH_MAC99_U3:
        if (!(ph = find_dev("/rtas"))) {
            printk("Warning: No /rtas node\n");
        } else {
            unsigned long size = 0x1000;
            while (size < (unsigned long)of_rtas_end - (unsigned long)of_rtas_start)
                size *= 2;
            set_property(ph, "rtas-size", (char*)&size, sizeof(size));
            set_int_property(ph, "rtas-version", is_apple() ? 0x41 : 1);
        }
        break;
    }
#endif

    if (fw_cfg_read_i16(FW_CFG_NOGRAPHIC)) {
        if (is_apple()) {
            if (CONFIG_SERIAL_PORT) {
                stdin_path = "scca";
                stdout_path = "scca";
            } else {
                stdin_path = "sccb";
                stdout_path = "sccb";
            }
        } else {
            stdin_path = "ttya";
            stdout_path = "ttya";
        }

        /* Some bootloaders force the output to the screen device, so
           let's create a screen alias for the serial device too */

        push_str("/aliases");
        fword("find-device");

        push_str(stdout_path);
        fword("pathres-resolve-aliases");
        fword("encode-string");
        push_str("screen");
        fword("property");
    } else {
        if (is_apple()) {
            stdin_path = "adb-keyboard";
            stdout_path = "screen";
        } else {
            stdin_path = "keyboard";
            stdout_path = "screen";
        }
    }

    kvm_of_init();

    /* Setup nvram variables */
    push_str("/options");
    fword("find-device");

    /* Setup default boot devices (not overriding user settings) */
    fword("boot-device");
    boot_device = pop_fstr_copy();
    if (boot_device && strcmp(boot_device, "disk") == 0) {
        switch (fw_cfg_read_i16(FW_CFG_BOOT_DEVICE)) {
            case 'c':
                boot_path = "hd";
                break;
            default:
            case 'd':
                boot_path = "cd";
                break;
        }

        snprintf(buf, sizeof(buf), "%s:,\\\\:tbxi %s:,\\ppc\\bootinfo.txt %s:,%%BOOT", boot_path, boot_path, boot_path);
        push_str(buf);
        fword("encode-string");
        push_str("boot-device");
        fword("property");
    }
    free(boot_device);

    /* Set up other properties */

    push_str("/chosen");
    fword("find-device");

    push_str(stdin_path);
    fword("pathres-resolve-aliases");
    push_str("input-device");
    fword("$setenv");

    push_str(stdout_path);
    fword("pathres-resolve-aliases");
    push_str("output-device");
    fword("$setenv");

#if 0
    if(getbool("tty-interface?") == 1)
#endif
        fword("activate-tty-interface");

    device_end();

    /* Implementation of filll word (required by BootX) */
    bind_func("filll", ffilll);

    /* Implementation of adler32 word (required by OS 9, BootX) */
    bind_func("(adler32)", adler32);
    
    bind_func("platform-boot", boot);
    bind_func("(go)", go);
}
