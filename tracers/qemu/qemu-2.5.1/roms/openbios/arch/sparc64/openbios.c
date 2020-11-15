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
#include "dict.h"
#include "arch/common/nvram.h"
#include "packages/nvram.h"
#include "libopenbios/sys_info.h"
#include "openbios.h"
#include "drivers/pci.h"
#include "asm/pci.h"
#include "boot.h"
#include "../../drivers/timer.h" // XXX
#define NO_QEMU_PROTOS
#include "arch/common/fw_cfg.h"
#include "arch/sparc64/ofmem_sparc64.h"
#include "spitfire.h"

#define UUID_FMT "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"

#define APB_SPECIAL_BASE     0x1fe00000000ULL
#define APB_MEM_BASE         0x1ff00000000ULL

#define MEMORY_SIZE     (512*1024)      /* 512K ram for hosted system */

// XXX
#define NVRAM_BASE       0x2000
#define NVRAM_SIZE       0x2000
#define NVRAM_IDPROM     0x1fd8
#define NVRAM_IDPROM_SIZE 32
#define NVRAM_OB_START   (0)
#define NVRAM_OB_SIZE    ((NVRAM_IDPROM - NVRAM_OB_START) & ~15)

static uint8_t idprom[NVRAM_IDPROM_SIZE];

struct hwdef {
    pci_arch_t pci;
    uint16_t machine_id_low, machine_id_high;
};

static const struct hwdef hwdefs[] = {
    {
        .pci = {
            .name = "SUNW,sabre",
            .vendor_id = PCI_VENDOR_ID_SUN,
            .device_id = PCI_DEVICE_ID_SUN_SABRE,
            .cfg_addr = APB_SPECIAL_BASE + 0x1000000ULL, // PCI bus configuration space
            .cfg_data = APB_MEM_BASE,                    // PCI bus memory space
            .cfg_base = APB_SPECIAL_BASE,
            .cfg_len = 0x2000000,
            .host_pci_base = APB_MEM_BASE,
            .pci_mem_base = 0x100000, /* avoid VGA at 0xa0000 */
            .mem_len = 0x10000000,
            .io_base = APB_SPECIAL_BASE + 0x2000000ULL, // PCI Bus I/O space
            .io_len = 0x10000,
            .irqs = { 0, 1, 2, 3 },
        },
        .machine_id_low = 0,
        .machine_id_high = 255,
    },
};

struct cpudef {
    unsigned long iu_version;
    const char *name;
    unsigned long ecache_associativity;
    unsigned long ecache_line_size;
    unsigned long ecache_size;
    unsigned long num_dtlb_entries;
    unsigned long dcache_associativity;
    unsigned long dcache_line_size;
    unsigned long dcache_size;
    unsigned long num_itlb_entries;
    unsigned long icache_associativity;
    unsigned long icache_line_size;
    unsigned long icache_size;
};

/*
  ( addr -- ? )
*/

extern volatile uint64_t client_tba;

static void
set_trap_table(void)
{
    unsigned long addr;

    addr = POP();

    /* Update client_tba to be updated on CIF exit */
    client_tba = addr;
}

/* Reset control register is defined in 17.2.7.3 of US IIi User Manual */
static void
sparc64_reset_all(void)
{
    unsigned long addr = 0x1fe0000f020ULL;
    unsigned long val = 1 << 29;

    asm("stxa %0, [%1] 0x15\n\t"
        : : "r" (val), "r" (addr) : "memory");
}

/* PCI Target Address Space Register (see UltraSPARC IIi User's Manual
  section 19.3.0.4) */
#define PBM_PCI_TARGET_AS              0x2028
#define PBM_PCI_TARGET_AS_CD_ENABLE    0x40

static void
sparc64_set_tas_register(unsigned long val)
{
    unsigned long addr = APB_SPECIAL_BASE + PBM_PCI_TARGET_AS;

    asm("stxa %0, [%1] 0x15\n\t"
        : : "r" (val), "r" (addr) : "memory");
}

static void cpu_generic_init(const struct cpudef *cpu, uint32_t clock_frequency)
{
    unsigned long iu_version;

    push_str("/");
    fword("find-device");

    fword("new-device");

    push_str(cpu->name);
    fword("device-name");

    push_str("cpu");
    fword("device-type");

    asm("rdpr %%ver, %0\n"
        : "=r"(iu_version) :);

    PUSH((iu_version >> 48) & 0xff);
    fword("encode-int");
    push_str("manufacturer#");
    fword("property");

    PUSH((iu_version >> 32) & 0xff);
    fword("encode-int");
    push_str("implementation#");
    fword("property");

    PUSH((iu_version >> 24) & 0xff);
    fword("encode-int");
    push_str("mask#");
    fword("property");

    PUSH(9);
    fword("encode-int");
    push_str("sparc-version");
    fword("property");

    PUSH(0);
    fword("encode-int");
    push_str("cpuid");
    fword("property");

    PUSH(0);
    fword("encode-int");
    push_str("upa-portid");
    fword("property");

    PUSH(clock_frequency);
    fword("encode-int");
    push_str("clock-frequency");
    fword("property");

    PUSH(cpu->ecache_associativity);
    fword("encode-int");
    push_str("ecache-associativity");
    fword("property");

    PUSH(cpu->ecache_line_size);
    fword("encode-int");
    push_str("ecache-line-size");
    fword("property");

    PUSH(cpu->ecache_size);
    fword("encode-int");
    push_str("ecache-size");
    fword("property");

    PUSH(cpu->dcache_associativity);
    fword("encode-int");
    push_str("dcache-associativity");
    fword("property");

    PUSH(cpu->dcache_line_size);
    fword("encode-int");
    push_str("dcache-line-size");
    fword("property");

    PUSH(cpu->dcache_size);
    fword("encode-int");
    push_str("dcache-size");
    fword("property");

    PUSH(cpu->icache_associativity);
    fword("encode-int");
    push_str("icache-associativity");
    fword("property");

    PUSH(cpu->ecache_line_size);
    fword("encode-int");
    push_str("icache-line-size");
    fword("property");

    PUSH(cpu->ecache_size);
    fword("encode-int");
    push_str("icache-size");
    fword("property");

    PUSH(cpu->num_itlb_entries);
    fword("encode-int");
    push_str("#itlb-entries");
    fword("property");

    PUSH(cpu->num_dtlb_entries);
    fword("encode-int");
    push_str("#dtlb-entries");
    fword("property");

    fword("finish-device");

    // Trap table
    push_str("/openprom/client-services");
    fword("find-device");
    bind_func("SUNW,set-trap-table", set_trap_table);

    // Reset
    bind_func("sparc64-reset-all", sparc64_reset_all);
    push_str("' sparc64-reset-all to reset-all");
    fword("eval");
}

static const struct cpudef sparc_defs[] = {
    {
        .iu_version = (0x04ULL << 48) | (0x02ULL << 32),
        .name = "FJSV,GP",
    },
    {
        .iu_version = (0x04ULL << 48) | (0x03ULL << 32),
        .name = "FJSV,GPUSK",
    },
    {
        .iu_version = (0x04ULL << 48) | (0x04ULL << 32),
        .name = "FJSV,GPUSC",
    },
    {
        .iu_version = (0x04ULL << 48) | (0x05ULL << 32),
        .name = "FJSV,GPUZC",
    },
    {
        .iu_version = (0x17ULL << 48) | (0x10ULL << 32),
        .name = "SUNW,UltraSPARC",
	.ecache_associativity = 1, .ecache_line_size = 0x40, .ecache_size = 0x100000,
	.dcache_associativity = 1, .dcache_line_size = 0x20, .dcache_size = 0x4000,
	.icache_associativity = 2, .icache_line_size = 0x20, .icache_size = 0x4000,
	.num_dtlb_entries = 0x40, .num_itlb_entries = 0x40,
    },
    {
        .iu_version = (0x17ULL << 48) | (0x11ULL << 32),
        .name = "SUNW,UltraSPARC-II",
	.ecache_associativity = 1, .ecache_line_size = 0x40, .ecache_size = 0x100000,
	.dcache_associativity = 1, .dcache_line_size = 0x20, .dcache_size = 0x4000,
	.icache_associativity = 2, .icache_line_size = 0x20, .icache_size = 0x4000,
	.num_dtlb_entries = 0x40, .num_itlb_entries = 0x40,
    },
    {
        .iu_version = (0x17ULL << 48) | (0x12ULL << 32),
        .name = "SUNW,UltraSPARC-IIi",
	.ecache_associativity = 1, .ecache_line_size = 0x40, .ecache_size = 0x40000,
	.dcache_associativity = 1, .dcache_line_size = 0x20, .dcache_size = 0x4000,
	.icache_associativity = 2, .icache_line_size = 0x20, .icache_size = 0x4000,
	.num_dtlb_entries = 0x40, .num_itlb_entries = 0x40,
    },
    {
        .iu_version = (0x17ULL << 48) | (0x13ULL << 32),
        .name = "SUNW,UltraSPARC-IIe",
    },
    {
        .iu_version = (0x3eULL << 48) | (0x14ULL << 32),
        .name = "SUNW,UltraSPARC-III",
    },
    {
        .iu_version = (0x3eULL << 48) | (0x15ULL << 32),
        .name = "SUNW,UltraSPARC-III+",
    },
    {
        .iu_version = (0x3eULL << 48) | (0x16ULL << 32),
        .name = "SUNW,UltraSPARC-IIIi",
    },
    {
        .iu_version = (0x3eULL << 48) | (0x18ULL << 32),
        .name = "SUNW,UltraSPARC-IV",
    },
    {
        .iu_version = (0x3eULL << 48) | (0x19ULL << 32),
        .name = "SUNW,UltraSPARC-IV+",
    },
    {
        .iu_version = (0x3eULL << 48) | (0x22ULL << 32),
        .name = "SUNW,UltraSPARC-IIIi+",
    },
    {
        .iu_version = (0x3eULL << 48) | (0x23ULL << 32),
        .name = "SUNW,UltraSPARC-T1",
    },
    {
        .iu_version = (0x3eULL << 48) | (0x24ULL << 32),
        .name = "SUNW,UltraSPARC-T2",
    },
    {
        .iu_version = (0x22ULL << 48) | (0x10ULL << 32),
        .name = "SUNW,UltraSPARC",
    },
};

static const struct cpudef *
id_cpu(void)
{
    unsigned long iu_version;
    unsigned int i;

    asm("rdpr %%ver, %0\n"
        : "=r"(iu_version) :);
    iu_version &= 0xffffffff00000000ULL;

    for (i = 0; i < sizeof(sparc_defs)/sizeof(struct cpudef); i++) {
        if (iu_version == sparc_defs[i].iu_version)
            return &sparc_defs[i];
    }
    printk("Unknown cpu (psr %lx), freezing!\n", iu_version);
    for (;;);
}

static void nvram_read(uint16_t offset, char *buf, unsigned int nbytes)
{
    unsigned int i;

    for (i = 0; i < nbytes; i++) {
        buf[i] = inb(NVRAM_BASE + offset + i);
    }
}

static void nvram_write(uint16_t offset, const char *buf, unsigned int nbytes)
{
    unsigned int i;

    for (i = 0; i < nbytes; i++) {
        outb(buf[i], NVRAM_BASE + offset + i);
    }
}

static uint8_t qemu_uuid[16];

void arch_nvram_get(char *data)
{
    char *obio_cmdline;
    uint32_t size = 0;
    const struct cpudef *cpu;
    char buf[256];
    uint32_t temp;
    uint64_t ram_size;
    uint32_t clock_frequency;
    uint16_t machine_id;
    const char *stdin_path, *stdout_path;

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

    kernel_size = fw_cfg_read_i32(FW_CFG_KERNEL_SIZE);
    if (kernel_size)
        kernel_image = fw_cfg_read_i64(FW_CFG_KERNEL_ADDR);

    size = fw_cfg_read_i32(FW_CFG_CMDLINE_SIZE);
    if (size) {
	obio_cmdline = (char *)malloc(size + 1);
        fw_cfg_read(FW_CFG_CMDLINE_DATA, obio_cmdline, size);
	obio_cmdline[size] = '\0';
    } else {
	obio_cmdline = strdup("");    
    }
    qemu_cmdline = (uint64_t)obio_cmdline;
    cmdline_size = size;
    boot_device = fw_cfg_read_i16(FW_CFG_BOOT_DEVICE);

    if (kernel_size)
        printk("kernel addr %llx size %llx\n", kernel_image, kernel_size);
    if (size)
        printk("kernel cmdline %s\n", obio_cmdline);

    nvram_read(NVRAM_OB_START, data, NVRAM_OB_SIZE);

    temp = fw_cfg_read_i32(FW_CFG_NB_CPUS);

    printk("CPUs: %x", temp);

    clock_frequency = 100000000;

    cpu = id_cpu();
    //cpu->initfn();
    cpu_generic_init(cpu, clock_frequency);
    printk(" x %s\n", cpu->name);

    // Add /uuid
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

    // Add /idprom
    nvram_read(NVRAM_IDPROM, (char *)idprom, NVRAM_IDPROM_SIZE);

    PUSH((long)&idprom);
    PUSH(32);
    fword("encode-bytes");
    push_str("idprom");
    fword("property");

    PUSH(500 * 1000 * 1000);
    fword("encode-int");
    push_str("clock-frequency");
    fword("property");

    ram_size = fw_cfg_read_i64(FW_CFG_RAM_SIZE);

    ob_mmu_init(cpu->name, ram_size);

    /* Setup nvram variables */
    push_str("/options");
    fword("find-device");

    switch (boot_device) {
        case 'a':
            push_str("/obio/SUNW,fdtwo");
            break;
        case 'c':
            push_str("disk:a");
            break;
        default:
        case 'd':
            push_str("cdrom:f cdrom");
            break;
        case 'n':
            push_str("net");
            break;
    }

    fword("encode-string");
    push_str("boot-device");
    fword("property");

    push_str(obio_cmdline);
    fword("encode-string");
    push_str("boot-file");
    fword("property");

    /* Set up other properties */
    push_str("/chosen");
    fword("find-device");

    if (fw_cfg_read_i16(FW_CFG_NOGRAPHIC)) {
        stdin_path = stdout_path = "ttya";
    } else {
        stdin_path = "keyboard";
        stdout_path = "screen";
    }

    push_str(stdin_path);
    push_str("input-device");
    fword("$setenv");

    push_str(stdout_path);
    push_str("output-device");
    fword("$setenv");
}

void arch_nvram_put(char *data)
{
    nvram_write(0, data, NVRAM_OB_SIZE);
}

int arch_nvram_size(void)
{
    return NVRAM_OB_SIZE;
}

void setup_timers(void)
{
}

void udelay(unsigned int usecs)
{
    volatile int i;

    for (i = 0; i < usecs * 100; i++);
}

static void init_memory(void)
{
    phys_addr_t phys;
    ucell virt;
    
    /* Claim the memory from OFMEM (align to 512K so we only take 1 TLB slot) */
    phys = ofmem_claim_phys(-1, MEMORY_SIZE, PAGE_SIZE_512K);
    if (!phys)
        printk("panic: not enough physical memory on host system.\n");
    
    virt = ofmem_claim_virt(-1, MEMORY_SIZE, PAGE_SIZE_512K);
    if (!virt)
        printk("panic: not enough virtual memory on host system.\n");

    /* Generate the mapping (and lock translation into the TLBs) */
    ofmem_map(phys, virt, MEMORY_SIZE, ofmem_arch_default_translation_mode(phys) | SPITFIRE_TTE_LOCKED);

    /* we push start and end of memory to the stack
     * so that it can be used by the forth word QUIT
     * to initialize the memory allocator
     */
    
    PUSH(virt);
    PUSH(virt + MEMORY_SIZE);
}

extern volatile uint64_t *obp_ticks_pointer;

static void
arch_init( void )
{
	openbios_init();
	modules_init();
#ifdef CONFIG_DRIVER_PCI
        ob_pci_init();

        /* Set TAS register to match the virtual-dma properties
           set during sabre configure */
        sparc64_set_tas_register(PBM_PCI_TARGET_AS_CD_ENABLE);
#endif
        nvconf_init();
        device_end();

        /* Point to the Forth obp-ticks variable */
        fword("obp-ticks");
        obp_ticks_pointer = cell2pointer(POP());

	bind_func("platform-boot", boot );
	bind_func("(go)", go);
}

unsigned long isa_io_base;

extern struct _console_ops arch_console_ops;

int openbios(void)
{
        unsigned int i;
        uint16_t machine_id;
        const struct hwdef *hwdef = NULL;


        for (i = 0; i < sizeof(hwdefs) / sizeof(struct hwdef); i++) {
            isa_io_base = hwdefs[i].pci.io_base;
            machine_id = fw_cfg_read_i16(FW_CFG_MACHINE_ID);
            if (hwdefs[i].machine_id_low <= machine_id &&
                hwdefs[i].machine_id_high >= machine_id) {
                hwdef = &hwdefs[i];
                arch = &hwdefs[i].pci;
                break;
            }
        }
        if (!hwdef)
            for(;;); // Internal inconsistency, hang

#ifdef CONFIG_DEBUG_CONSOLE
        init_console(arch_console_ops);
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	uart_init(CONFIG_SERIAL_PORT, CONFIG_SERIAL_SPEED);
#endif
        printk("OpenBIOS for Sparc64\n");
#endif

        ofmem_init();

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
        printk("falling off...\n");
        free(dict);
	return 0;
}
