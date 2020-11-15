/* tag: openbios forth environment, executable code
 *
 * Copyright (C) 2003 Patrick Mauritz, Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "libopenbios/openbios.h"
#include "libopenbios/bindings.h"
#include "libopenbios/console.h"
#include "drivers/drivers.h"
#include "asm/types.h"
#include "dict.h"
#include "kernel/kernel.h"
#include "kernel/stack.h"
#include "arch/common/nvram.h"
#include "packages/nvram.h"
#include "../../drivers/timer.h" // XXX
#include "libopenbios/sys_info.h"
#include "openbios.h"
#include "boot.h"
#include "romvec.h"
#include "openprom.h"
#include "psr.h"
#include "libopenbios/video.h"
#define NO_QEMU_PROTOS
#include "arch/common/fw_cfg.h"
#include "arch/sparc32/ofmem_sparc32.h"

#define MEMORY_SIZE     (128*1024)       /* 128K ram for hosted system */
#define UUID_FMT "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define FW_CFG_SUN4M_DEPTH   (FW_CFG_ARCH_LOCAL + 0x00)

int qemu_machine_type;

struct hwdef {
    uint64_t iommu_base, slavio_base;
    uint64_t intctl_base, counter_base, nvram_base, ms_kb_base, serial_base;
    unsigned long fd_offset, counter_offset, intr_offset;
    unsigned long aux1_offset, aux2_offset;
    uint64_t dma_base, esp_base, le_base;
    uint64_t tcx_base;
    int intr_ncpu;
    int mid_offset;
    int machine_id_low, machine_id_high;
};

static const struct hwdef hwdefs[] = {
    /* SS-5 */
    {
        .iommu_base   = 0x10000000,
        .tcx_base     = 0x50000000,
        .slavio_base  = 0x71000000,
        .ms_kb_base   = 0x71000000,
        .serial_base  = 0x71100000,
        .nvram_base   = 0x71200000,
        .fd_offset    = 0x00400000,
        .counter_offset = 0x00d00000,
        .intr_offset  = 0x00e00000,
        .intr_ncpu    = 1,
        .aux1_offset  = 0x00900000,
        .aux2_offset  = 0x00910000,
        .dma_base     = 0x78400000,
        .esp_base     = 0x78800000,
        .le_base      = 0x78c00000,
        .mid_offset   = 0,
        .machine_id_low = 32,
        .machine_id_high = 63,
    },
    /* SS-10, SS-20 */
    {
        .iommu_base   = 0xfe0000000ULL,
        .tcx_base     = 0xe20000000ULL,
        .slavio_base  = 0xff1000000ULL,
        .ms_kb_base   = 0xff1000000ULL,
        .serial_base  = 0xff1100000ULL,
        .nvram_base   = 0xff1200000ULL,
        .fd_offset    = 0x00700000, // 0xff1700000ULL,
        .counter_offset = 0x00300000, // 0xff1300000ULL,
        .intr_offset  = 0x00400000, // 0xff1400000ULL,
        .intr_ncpu    = 4,
        .aux1_offset  = 0x00800000, // 0xff1800000ULL,
        .aux2_offset  = 0x00a01000, // 0xff1a01000ULL,
        .dma_base     = 0xef0400000ULL,
        .esp_base     = 0xef0800000ULL,
        .le_base      = 0xef0c00000ULL,
        .mid_offset   = 8,
        .machine_id_low = 64,
        .machine_id_high = 65,
    },
    /* SS-600MP */
    {
        .iommu_base   = 0xfe0000000ULL,
        .tcx_base     = 0xe20000000ULL,
        .slavio_base  = 0xff1000000ULL,
        .ms_kb_base   = 0xff1000000ULL,
        .serial_base  = 0xff1100000ULL,
        .nvram_base   = 0xff1200000ULL,
        .fd_offset    = -1,
        .counter_offset = 0x00300000, // 0xff1300000ULL,
        .intr_offset  = 0x00400000, // 0xff1400000ULL,
        .intr_ncpu    = 4,
        .aux1_offset  = 0x00800000, // 0xff1800000ULL,
        .aux2_offset  = 0x00a01000, // 0xff1a01000ULL, XXX should not exist
        .dma_base     = 0xef0081000ULL,
        .esp_base     = 0xef0080000ULL,
        .le_base      = 0xef0060000ULL,
        .mid_offset   = 8,
        .machine_id_low = 66,
        .machine_id_high = 66,
    },
};

static const struct hwdef *hwdef;

void setup_timers(void)
{
}

void udelay(unsigned int usecs)
{
}

void mdelay(unsigned int msecs)
{
}

static void mb86904_init(void)
{
    PUSH(32);
    fword("encode-int");
    push_str("cache-line-size");
    fword("property");

    PUSH(512);
    fword("encode-int");
    push_str("cache-nlines");
    fword("property");

    PUSH(0x23);
    fword("encode-int");
    push_str("mask_rev");
    fword("property");
}

static void tms390z55_init(void)
{
    push_str("");
    fword("encode-string");
    push_str("ecache-parity?");
    fword("property");

    push_str("");
    fword("encode-string");
    push_str("bfill?");
    fword("property");

    push_str("");
    fword("encode-string");
    push_str("bcopy?");
    fword("property");

    push_str("");
    fword("encode-string");
    push_str("cache-physical?");
    fword("property");

    PUSH(0xf);
    fword("encode-int");
    PUSH(0xf8fffffc);
    fword("encode-int");
    fword("encode+");
    PUSH(4);
    fword("encode-int");
    fword("encode+");

    PUSH(0xf);
    fword("encode-int");
    fword("encode+");
    PUSH(0xf8c00000);
    fword("encode-int");
    fword("encode+");
    PUSH(0x1000);
    fword("encode-int");
    fword("encode+");

    PUSH(0xf);
    fword("encode-int");
    fword("encode+");
    PUSH(0xf8000000);
    fword("encode-int");
    fword("encode+");
    PUSH(0x1000);
    fword("encode-int");
    fword("encode+");

    PUSH(0xf);
    fword("encode-int");
    fword("encode+");
    PUSH(0xf8800000);
    fword("encode-int");
    fword("encode+");
    PUSH(0x1000);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");
}

static void rt625_init(void)
{
    PUSH(32);
    fword("encode-int");
    push_str("cache-line-size");
    fword("property");

    PUSH(512);
    fword("encode-int");
    push_str("cache-nlines");
    fword("property");

}

static void bad_cpu_init(void)
{
    printk("This CPU is not supported yet, freezing.\n");
    for(;;);
}

struct cpudef {
    unsigned long iu_version;
    const char *name;
    int psr_impl, psr_vers, impl, vers;
    int dcache_line_size, dcache_lines, dcache_assoc;
    int icache_line_size, icache_lines, icache_assoc;
    int ecache_line_size, ecache_lines, ecache_assoc;
    int mmu_nctx;
    void (*initfn)(void);
};

static const struct cpudef sparc_defs[] = {
    {
        .iu_version = 0x00 << 24, /* Impl 0, ver 0 */
        .name = "FMI,MB86900",
        .initfn = bad_cpu_init,
    },
    {
        .iu_version = 0x04 << 24, /* Impl 0, ver 4 */
        .name = "FMI,MB86904",
        .psr_impl = 0,
        .psr_vers = 4,
        .impl = 0,
        .vers = 4,
        .dcache_line_size = 0x10,
        .dcache_lines = 0x200,
        .dcache_assoc = 1,
        .icache_line_size = 0x20,
        .icache_lines = 0x200,
        .icache_assoc = 1,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x4000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x100,
        .initfn = mb86904_init,
    },
    {
        .iu_version = 0x05 << 24, /* Impl 0, ver 5 */
        .name = "FMI,MB86907",
        .psr_impl = 0,
        .psr_vers = 5,
        .impl = 0,
        .vers = 5,
        .dcache_line_size = 0x20,
        .dcache_lines = 0x200,
        .dcache_assoc = 1,
        .icache_line_size = 0x20,
        .icache_lines = 0x200,
        .icache_assoc = 1,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x4000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x100,
        .initfn = mb86904_init,
    },
    {
        .iu_version = 0x10 << 24, /* Impl 1, ver 0 */
        .name = "LSI,L64811",
        .initfn = bad_cpu_init,
    },
    {
        .iu_version = 0x11 << 24, /* Impl 1, ver 1 */
        .name = "CY,CY7C601",
        .psr_impl = 1,
        .psr_vers = 1,
        .impl = 1,
        .vers = 1,
        .mmu_nctx = 0x10,
        .initfn = bad_cpu_init,
    },
    {
        .iu_version = 0x13 << 24, /* Impl 1, ver 3 */
        .name = "CY,CY7C611",
        .initfn = bad_cpu_init,
    },
    {
        .iu_version = 0x40000000,
        .name = "TI,TMS390Z55",
        .psr_impl = 4,
        .psr_vers = 0,
        .impl = 0,
        .vers = 4,
        .dcache_line_size = 0x20,
        .dcache_lines = 0x80,
        .dcache_assoc = 4,
        .icache_line_size = 0x40,
        .icache_lines = 0x40,
        .icache_assoc = 5,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x8000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x10000,
        .initfn = tms390z55_init,
    },
    {
        .iu_version = 0x41000000,
        .name = "TI,TMS390S10",
        .psr_impl = 4,
        .psr_vers = 1,
        .impl = 4,
        .vers = 1,
        .dcache_line_size = 0x10,
        .dcache_lines = 0x80,
        .dcache_assoc = 4,
        .icache_line_size = 0x20,
        .icache_lines = 0x80,
        .icache_assoc = 5,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x8000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x10000,
        .initfn = tms390z55_init,
    },
    {
        .iu_version = 0x42000000,
        .name = "TI,TMS390S10",
        .psr_impl = 4,
        .psr_vers = 2,
        .impl = 4,
        .vers = 2,
        .dcache_line_size = 0x10,
        .dcache_lines = 0x80,
        .dcache_assoc = 4,
        .icache_line_size = 0x20,
        .icache_lines = 0x80,
        .icache_assoc = 5,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x8000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x10000,
        .initfn = tms390z55_init,
    },
    {
        .iu_version = 0x43000000,
        .name = "TI,TMS390S10",
        .psr_impl = 4,
        .psr_vers = 3,
        .impl = 4,
        .vers = 3,
        .dcache_line_size = 0x10,
        .dcache_lines = 0x80,
        .dcache_assoc = 4,
        .icache_line_size = 0x20,
        .icache_lines = 0x80,
        .icache_assoc = 5,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x8000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x10000,
        .initfn = tms390z55_init,
    },
    {
        .iu_version = 0x44000000,
        .name = "TI,TMS390S10",
        .psr_impl = 4,
        .psr_vers = 4,
        .impl = 4,
        .vers = 4,
        .dcache_line_size = 0x10,
        .dcache_lines = 0x80,
        .dcache_assoc = 4,
        .icache_line_size = 0x20,
        .icache_lines = 0x80,
        .icache_assoc = 5,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x8000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x10000,
        .initfn = tms390z55_init,
    },
    {
        .iu_version = 0x1e000000,
        .name = "Ross,RT625",
        .psr_impl = 1,
        .psr_vers = 14,
        .impl = 1,
        .vers = 7,
        .dcache_line_size = 0x20,
        .dcache_lines = 0x80,
        .dcache_assoc = 4,
        .icache_line_size = 0x40,
        .icache_lines = 0x40,
        .icache_assoc = 5,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x8000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x10000,
        .initfn = rt625_init,
    },
    {
        .iu_version = 0x1f000000,
        .name = "Ross,RT620",
        .psr_impl = 1,
        .psr_vers = 15,
        .impl = 1,
        .vers = 7,
        .dcache_line_size = 0x20,
        .dcache_lines = 0x80,
        .dcache_assoc = 4,
        .icache_line_size = 0x40,
        .icache_lines = 0x40,
        .icache_assoc = 5,
        .ecache_line_size = 0x20,
        .ecache_lines = 0x8000,
        .ecache_assoc = 1,
        .mmu_nctx = 0x10000,
        .initfn = rt625_init,
    },
    {
        .iu_version = 0x20000000,
        .name = "BIT,B5010",
        .initfn = bad_cpu_init,
    },
    {
        .iu_version = 0x50000000,
        .name = "MC,MN10501",
        .initfn = bad_cpu_init,
    },
    {
        .iu_version = 0x90 << 24, /* Impl 9, ver 0 */
        .name = "Weitek,W8601",
        .initfn = bad_cpu_init,
    },
    {
        .iu_version = 0xf2000000,
        .name = "GR,LEON2",
        .initfn = bad_cpu_init,
    },
    {
        .iu_version = 0xf3000000,
        .name = "GR,LEON3",
        .initfn = bad_cpu_init,
    },
};

static const struct cpudef *
id_cpu(void)
{
    unsigned long iu_version;
    unsigned int i;

    asm("rd %%psr, %0\n"
        : "=r"(iu_version) :);
    iu_version &= 0xff000000;

    for (i = 0; i < sizeof(sparc_defs)/sizeof(struct cpudef); i++) {
        if (iu_version == sparc_defs[i].iu_version)
            return &sparc_defs[i];
    }
    printk("Unknown cpu (psr %lx), freezing!\n", iu_version);
    for (;;);
}

static void setup_cpu(int mid_offset)
{
    uint32_t temp;
    unsigned int i;
    const struct cpudef *cpu;

    // Add cpus
    temp = fw_cfg_read_i32(FW_CFG_NB_CPUS);

    printk("CPUs: %x", temp);
    cpu = id_cpu();
    printk(" x %s\n", cpu->name);
    for (i = 0; i < temp; i++) {
        push_str("/");
        fword("find-device");

        fword("new-device");

        push_str(cpu->name);
        fword("device-name");

        push_str("cpu");
        fword("device-type");

        PUSH(cpu->psr_impl);
        fword("encode-int");
        push_str("psr-implementation");
        fword("property");

        PUSH(cpu->psr_vers);
        fword("encode-int");
        push_str("psr-version");
        fword("property");

        PUSH(cpu->impl);
        fword("encode-int");
        push_str("implementation");
        fword("property");

        PUSH(cpu->vers);
        fword("encode-int");
        push_str("version");
        fword("property");

        PUSH(4096);
        fword("encode-int");
        push_str("page-size");
        fword("property");

        PUSH(cpu->dcache_line_size);
        fword("encode-int");
        push_str("dcache-line-size");
        fword("property");

        PUSH(cpu->dcache_lines);
        fword("encode-int");
        push_str("dcache-nlines");
        fword("property");

        PUSH(cpu->dcache_assoc);
        fword("encode-int");
        push_str("dcache-associativity");
        fword("property");

        PUSH(cpu->icache_line_size);
        fword("encode-int");
        push_str("icache-line-size");
        fword("property");

        PUSH(cpu->icache_lines);
        fword("encode-int");
        push_str("icache-nlines");
        fword("property");

        PUSH(cpu->icache_assoc);
        fword("encode-int");
        push_str("icache-associativity");
        fword("property");

        PUSH(cpu->ecache_line_size);
        fword("encode-int");
        push_str("ecache-line-size");
        fword("property");

        PUSH(cpu->ecache_lines);
        fword("encode-int");
        push_str("ecache-nlines");
        fword("property");

        PUSH(cpu->ecache_assoc);
        fword("encode-int");
        push_str("ecache-associativity");
        fword("property");

        PUSH(2);
        fword("encode-int");
        push_str("ncaches");
        fword("property");

        PUSH(cpu->mmu_nctx);
        fword("encode-int");
        push_str("mmu-nctx");
        fword("property");

        PUSH(8);
        fword("encode-int");
        push_str("sparc-version");
        fword("property");

        push_str("");
        fword("encode-string");
        push_str("cache-coherence?");
        fword("property");

        PUSH(i + mid_offset);
        fword("encode-int");
        push_str("mid");
        fword("property");

        cpu->initfn();

        fword("finish-device");
    }
}

static void dummy_mach_init(uint64_t base)
{
}

struct machdef {
    uint16_t machine_id;
    const char *banner_name;
    const char *model;
    const char *name;
    void (*initfn)(uint64_t base);
};

static const struct machdef sun4m_defs[] = {
    {
        .machine_id = 32,
        .banner_name = "SPARCstation 5",
        .model = "SUNW,501-3059",
        .name = "SUNW,SPARCstation-5",
        .initfn = ss5_init,
    },
    {
        .machine_id = 33,
        .banner_name = "SPARCstation Voyager",
        .model = "SUNW,501-2581",
        .name = "SUNW,SPARCstation-Voyager",
        .initfn = dummy_mach_init,
    },
    {
        .machine_id = 34,
        .banner_name = "SPARCstation LX",
        .model = "SUNW,501-2031",
        .name = "SUNW,SPARCstation-LX",
        .initfn = dummy_mach_init,
    },
    {
        .machine_id = 35,
        .banner_name = "SPARCstation 4",
        .model = "SUNW,501-2572",
        .name = "SUNW,SPARCstation-4",
        .initfn = ss5_init,
    },
    {
        .machine_id = 36,
        .banner_name = "SPARCstation Classic",
        .model = "SUNW,501-2326",
        .name = "SUNW,SPARCstation-Classic",
        .initfn = dummy_mach_init,
    },
    {
        .machine_id = 37,
        .banner_name = "Tadpole S3 GX",
        .model = "S3",
        .name = "Tadpole_S3GX",
        .initfn = ss5_init,
    },
    {
        .machine_id = 64,
        .banner_name = "SPARCstation 10 (1 X 390Z55)",
        .model = "SUNW,S10,501-2365",
        .name = "SUNW,SPARCstation-10",
        .initfn = ob_eccmemctl_init,
    },
    {
        .machine_id = 65,
        .banner_name = "SPARCstation 20 (1 X 390Z55)",
        .model = "SUNW,S20,501-2324",
        .name = "SUNW,SPARCstation-20",
        .initfn = ob_eccmemctl_init,
    },
    {
        .machine_id = 66,
        .banner_name = "SPARCsystem 600(1 X 390Z55)",
        .model = NULL,
        .name = "SUNW,SPARCsystem-600",
        .initfn = ob_eccmemctl_init,
    },
};

static const struct machdef *
id_machine(uint16_t machine_id)
{
    unsigned int i;

    for (i = 0; i < sizeof(sun4m_defs)/sizeof(struct machdef); i++) {
        if (machine_id == sun4m_defs[i].machine_id)
            return &sun4m_defs[i];
    }
    printk("Unknown machine (ID %d), freezing!\n", machine_id);
    for (;;);
}

static void setup_machine(uint64_t base)
{
    uint16_t machine_id;
    const struct machdef *mach;

    machine_id = fw_cfg_read_i16(FW_CFG_MACHINE_ID);
    mach = id_machine(machine_id);

    push_str("/");
    fword("find-device");
    push_str(mach->banner_name);
    fword("encode-string");
    push_str("banner-name");
    fword("property");

    if (mach->model) {
        push_str(mach->model);
        fword("encode-string");
        push_str("model");
        fword("property");
    }
    push_str(mach->name);
    fword("encode-string");
    push_str("name");
    fword("property");

    mach->initfn(base);
}

/* Add /uuid */
static void setup_uuid(void)
{
    static uint8_t qemu_uuid[16];

    fw_cfg_read(FW_CFG_UUID, (char *)qemu_uuid, 16);

    printk("UUID: " UUID_FMT "\n", qemu_uuid[0], qemu_uuid[1], qemu_uuid[2],
           qemu_uuid[3], qemu_uuid[4], qemu_uuid[5], qemu_uuid[6],
           qemu_uuid[7], qemu_uuid[8], qemu_uuid[9], qemu_uuid[10],
           qemu_uuid[11], qemu_uuid[12], qemu_uuid[13], qemu_uuid[14],
           qemu_uuid[15]);

    push_str("/");
    fword("find-device");

    PUSH((long)&qemu_uuid);
    PUSH(16);
    fword("encode-bytes");
    push_str("uuid");
    fword("property");
}

static void setup_stdio(void)
{
    char nographic;
    const char *stdin, *stdout;

    fw_cfg_read(FW_CFG_NOGRAPHIC, &nographic, 1);
    if (nographic) {
        obp_stdin = PROMDEV_TTYA;
        obp_stdout = PROMDEV_TTYA;
        stdin = "ttya";
        stdout = "ttya";
    } else {
        obp_stdin = PROMDEV_KBD;
        obp_stdout = PROMDEV_SCREEN;
        stdin = "keyboard";
        stdout = "screen";
    }

    push_str(stdin);
    push_str("input-device");
    fword("$setenv");

    push_str(stdout);
    push_str("output-device");
    fword("$setenv");

    obp_stdin_path = stdin;
    obp_stdout_path = stdout;
}

static void init_memory(void)
{
    phys_addr_t phys;
    ucell virt;
    
    /* Claim the memory from OFMEM */
    phys = ofmem_claim_phys(-1, MEMORY_SIZE, PAGE_SIZE);
    if (!phys)
        printk("panic: not enough physical memory on host system.\n");
    
    virt = ofmem_claim_virt(OF_CODE_START - MEMORY_SIZE, MEMORY_SIZE, 0);
    if (!virt)
        printk("panic: not enough virtual memory on host system.\n");

    /* Generate the mapping (and lock translation into the TLBs) */
    ofmem_map(phys, virt, MEMORY_SIZE, ofmem_arch_default_translation_mode(phys));

    /* we push start and end of memory to the stack
     * so that it can be used by the forth word QUIT
     * to initialize the memory allocator
     */
    
    PUSH(virt);
    PUSH(virt + MEMORY_SIZE);
}

static void
arch_init( void )
{
	char *cmdline;
        const char *kernel_cmdline;
        uint32_t temp;
        uint16_t machine_id;
        char buf[256];
        unsigned long mem_size;

        fw_cfg_init();

        fw_cfg_read(FW_CFG_SIGNATURE, buf, 4);
        buf[4] = '\0';

        printk("Configuration device id %s", buf);

        temp = fw_cfg_read_i32(FW_CFG_ID);
        machine_id = fw_cfg_read_i16(FW_CFG_MACHINE_ID);

        printk(" version %d machine id %d\n", temp, machine_id);

        if (temp != 1) {
            printk("Incompatible configuration device version, freezing\n");
            for(;;);
        }

        graphic_depth = fw_cfg_read_i16(FW_CFG_SUN4M_DEPTH);

	openbios_init();
	modules_init();
        ob_init_mmu();
        ob_init_iommu(hwdef->iommu_base);
#ifdef CONFIG_DRIVER_OBIO
        mem_size = fw_cfg_read_i32(FW_CFG_RAM_SIZE);
	ob_obio_init(hwdef->slavio_base, hwdef->fd_offset,
                     hwdef->counter_offset, hwdef->intr_offset, hwdef->intr_ncpu,
                     hwdef->aux1_offset, hwdef->aux2_offset,
                     mem_size);

        setup_machine(hwdef->slavio_base);

        nvconf_init();
#endif
#ifdef CONFIG_DRIVER_SBUS
#ifdef CONFIG_DEBUG_CONSOLE_VIDEO
	setup_video();
#endif
	ob_sbus_init(hwdef->iommu_base + 0x1000ULL, qemu_machine_type);
#endif
	device_end();

        setup_cpu(hwdef->mid_offset);

        setup_stdio();
	/* Initialiase openprom romvec */
        romvec = init_openprom();

	kernel_size = fw_cfg_read_i32(FW_CFG_KERNEL_SIZE);
	if (kernel_size) {
		kernel_image = fw_cfg_read_i32(FW_CFG_KERNEL_ADDR);

		/* Mark the kernel memory as in use */
		ofmem_claim_phys(PAGE_ALIGN(kernel_image), PAGE_ALIGN(kernel_size), 0);
		ofmem_claim_virt(PAGE_ALIGN(kernel_image), PAGE_ALIGN(kernel_size), 0);
	}

        kernel_cmdline = (const char *) fw_cfg_read_i32(FW_CFG_KERNEL_CMDLINE);
        if (kernel_cmdline) {
            cmdline = strdup(kernel_cmdline);
            obp_arg.argv[1] = cmdline;
        } else {
	    cmdline = strdup("");
	}
	qemu_cmdline = (uint32_t)cmdline;

        /* Setup nvram variables */
        push_str("/options");
        fword("find-device");
        push_str(cmdline);
        fword("encode-string");
        push_str("boot-file");
        fword("property");

	boot_device = fw_cfg_read_i16(FW_CFG_BOOT_DEVICE);

	switch (boot_device) {
	case 'a':
		push_str("floppy");
		break;
	case 'c':
		push_str("disk");
		break;
	default:
	case 'd':
		push_str("cdrom:d cdrom");
		break;
	case 'n':
		push_str("net");
		break;
	}

	fword("encode-string");
	push_str("boot-device");
	fword("property");

	device_end();
	
	bind_func("platform-boot", boot );
	bind_func("(go)", go );
	
	/* Set up other properties */
        push_str("/chosen");
        fword("find-device");

        setup_uuid();

	/* Enable interrupts */
	temp = get_psr();
	temp = (temp & ~PSR_PIL) | (13 << 8); /* Enable CPU timer interrupt (level 14) */
	put_psr(temp);
}

extern struct _console_ops arch_console_ops;

int openbios(void)
{
        unsigned int i;

        for (i = 0; i < sizeof(hwdefs) / sizeof(struct hwdef); i++) {
            if (hwdefs[i].machine_id_low <= qemu_machine_type &&
                hwdefs[i].machine_id_high >= qemu_machine_type) {
                hwdef = &hwdefs[i];
                break;
            }
        }
        if (!hwdef)
            for(;;); // Internal inconsistency, hang

#ifdef CONFIG_DEBUG_CONSOLE
        init_console(arch_console_ops);
#endif
        /* Make sure we setup OFMEM before the MMU as we need malloc() to setup page tables */
        ofmem_init();

#ifdef CONFIG_DRIVER_SBUS
        init_mmu_swift();
#endif
#ifdef CONFIG_DEBUG_CONSOLE
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	escc_uart_init(hwdef->serial_base | (CONFIG_SERIAL_PORT? 0ULL: 4ULL),
                  CONFIG_SERIAL_SPEED);
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VIDEO
	kbd_init(hwdef->ms_kb_base);
#endif
#endif

        collect_sys_info(&sys_info);

        dict = (unsigned char *)sys_info.dict_start;
        dicthead = (cell)sys_info.dict_end;
        last = sys_info.dict_last;
        dictlimit = sys_info.dict_limit;

	forth_init();

#ifdef CONFIG_DEBUG_BOOT
	printk("forth started.\n");
	printk("initializing memory...");
#endif

	init_memory();

#ifdef CONFIG_DEBUG_BOOT
	printk("done\n");
#endif

	PUSH_xt( bind_noname_func(arch_init) );
	fword("PREPOST-initializer");

	PC = (ucell)findword("initialize-of");

	if (!PC) {
		printk("panic: no dictionary entry point.\n");
		return -1;
	}
#ifdef CONFIG_DEBUG_DICTIONARY
	printk("done (%d bytes).\n", dicthead);
	printk("Jumping to dictionary...\n");
#endif

	enterforth((xt_t)PC);

        free(dict);
	return 0;
}
