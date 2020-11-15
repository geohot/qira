/*
 *   OpenBIOS Sparc OBIO driver
 *
 *   (C) 2004 Stefan Reinauer <stepan@openbios.org>
 *   (C) 2005 Ed Schouten <ed@fxq.nl>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "kernel/kernel.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "drivers/drivers.h"
#include "arch/common/nvram.h"
#include "libopenbios/ofmem.h"
#include "obio.h"
#include "escc.h"

#define	PROMDEV_KBD	0		/* input from keyboard */
#define	PROMDEV_SCREEN	0		/* output to screen */
#define	PROMDEV_TTYA	1		/* in/out to ttya */

/* DECLARE data structures for the nodes.  */
DECLARE_UNNAMED_NODE( ob_obio, INSTALL_OPEN, sizeof(int) );

void
ob_new_obio_device(const char *name, const char *type)
{
    push_str("/obio");
    fword("find-device");
    fword("new-device");

    push_str(name);
    fword("device-name");

    if (type) {
        push_str(type);
        fword("device-type");
    }
}

static unsigned long
map_reg(uint64_t base, uint64_t offset, unsigned long size, int map,
        int phys_hi)
{
    PUSH(phys_hi);
    fword("encode-int");
    PUSH(offset);
    fword("encode-int");
    fword("encode+");
    PUSH(size);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    if (map) {
        unsigned long addr;

        addr = (unsigned long)ofmem_map_io(base + offset, size);

        PUSH(addr);
        fword("encode-int");
        push_str("address");
        fword("property");
        return addr;
    }
    return 0;
}

unsigned long
ob_reg(uint64_t base, uint64_t offset, unsigned long size, int map)
{
    return map_reg(base, offset, size, map, 0);
}

void
ob_intr(int intr)
{
    PUSH(intr);
    fword("encode-int");
    PUSH(0);
    fword("encode-int");
    fword("encode+");
    push_str("intr");
    fword("property");
}

void
ob_eccmemctl_init(uint64_t base)
{
    uint32_t version, *regs;
    const char *mc_type;

    push_str("/");
    fword("find-device");
    fword("new-device");

    push_str("eccmemctl");
    fword("device-name");

    PUSH(0x20);
    fword("encode-int");
    push_str("width");
    fword("property");

    regs = (uint32_t *)map_reg(ECC_BASE, 0, ECC_SIZE, 1, ECC_BASE >> 32);

    version = regs[0];
    switch (version) {
    case 0x00000000:
        mc_type = "MCC";
        break;
    case 0x10000000:
        mc_type = "EMC";
        break;
    default:
    case 0x20000000:
        mc_type = "SMC";
        break;
    }
    push_str(mc_type);
    fword("encode-string");
    push_str("mc-type");
    fword("property");

    fword("finish-device");
}

static unsigned char *nvram;

#define NVRAM_OB_START   (0)
#define NVRAM_OB_SIZE    ((NVRAM_IDPROM - NVRAM_OB_START) & ~15)

void
arch_nvram_get(char *data)
{
    memcpy(data, &nvram[NVRAM_OB_START], NVRAM_OB_SIZE);
}

void
arch_nvram_put(char *data)
{
    memcpy(&nvram[NVRAM_OB_START], data, NVRAM_OB_SIZE);
}

int
arch_nvram_size(void)
{
    return NVRAM_OB_SIZE;
}

void
ss5_init(uint64_t base)
{
    ob_new_obio_device("slavioconfig", NULL);

    ob_reg(base, SLAVIO_SCONFIG, SCONFIG_REGS, 0);

    fword("finish-device");
}

static void
ob_nvram_init(uint64_t base, uint64_t offset)
{
    ob_new_obio_device("eeprom", NULL);

    nvram = (unsigned char *)ob_reg(base, offset, NVRAM_SIZE, 1);

    PUSH((unsigned long)nvram);
    fword("encode-int");
    push_str("address");
    fword("property");

    push_str("mk48t08");
    fword("model");

    fword("finish-device");

    // Add /idprom
    push_str("/");
    fword("find-device");

    PUSH((long)&nvram[NVRAM_IDPROM]);
    PUSH(32);
    fword("encode-bytes");
    push_str("idprom");
    fword("property");
}

static void
ob_fd_init(uint64_t base, uint64_t offset, int intr)
{
    unsigned long addr;

    ob_new_obio_device("SUNW,fdtwo", "block");

    addr = ob_reg(base, offset, FD_REGS, 1);

    ob_intr(intr);

    fword("is-deblocker");

    ob_floppy_init("/obio", "SUNW,fdtwo", 0, addr);

    fword("finish-device");
}

static void
ob_auxio_init(uint64_t base, uint64_t offset)
{
    ob_new_obio_device("auxio", NULL);

    ob_reg(base, offset, AUXIO_REGS, 1);

    fword("finish-device");
}

volatile unsigned char *power_reg;
volatile unsigned int *reset_reg;

static void
sparc32_reset_all(void)
{
    *reset_reg = 1;
}

// AUX 2 (Software Powerdown Control) and reset
static void
ob_aux2_reset_init(uint64_t base, uint64_t offset, int intr)
{
    ob_new_obio_device("power", NULL);

    power_reg = (void *)ob_reg(base, offset, AUXIO2_REGS, 1);

    // Not in device tree
    reset_reg = (unsigned int *)ofmem_map_io(base + (uint64_t)SLAVIO_RESET, RESET_REGS);

    bind_func("sparc32-reset-all", sparc32_reset_all);
    push_str("' sparc32-reset-all to reset-all");
    fword("eval");

    ob_intr(intr);

    fword("finish-device");
}

volatile struct sun4m_timer_regs *counter_regs;

static void
ob_counter_init(uint64_t base, unsigned long offset, int ncpu)
{
    int i;

    ob_new_obio_device("counter", NULL);

    for (i = 0; i < ncpu; i++) {
        PUSH(0);
        fword("encode-int");
        if (i != 0) fword("encode+");
        PUSH(offset + (i * PAGE_SIZE));
        fword("encode-int");
        fword("encode+");
        PUSH(COUNTER_REGS);
        fword("encode-int");
        fword("encode+");
    }

    PUSH(0);
    fword("encode-int");
    fword("encode+");
    PUSH(offset + 0x10000);
    fword("encode-int");
    fword("encode+");
    PUSH(COUNTER_REGS);
    fword("encode-int");
    fword("encode+");

    push_str("reg");
    fword("property");


    counter_regs = (struct sun4m_timer_regs *)ofmem_map_io(base + (uint64_t)offset, sizeof(*counter_regs));
    counter_regs->cfg = 0xfffffffe;
    counter_regs->l10_timer_limit = 0;
    counter_regs->cpu_timers[0].l14_timer_limit = 0x9c4000;    /* see comment in obio.h */
    counter_regs->cpu_timers[0].cntrl = 1;

    for (i = 0; i < ncpu; i++) {
        PUSH((unsigned long)&counter_regs->cpu_timers[i]);
        fword("encode-int");
        if (i != 0)
            fword("encode+");
    }
    PUSH((unsigned long)&counter_regs->l10_timer_limit);
    fword("encode-int");
    fword("encode+");
    push_str("address");
    fword("property");

    fword("finish-device");
}

static volatile struct sun4m_intregs *intregs;

static void
ob_interrupt_init(uint64_t base, unsigned long offset, int ncpu)
{
    int i;

    ob_new_obio_device("interrupt", NULL);

    for (i = 0; i < ncpu; i++) {
        PUSH(0);
        fword("encode-int");
        if (i != 0) fword("encode+");
        PUSH(offset + (i * PAGE_SIZE));
        fword("encode-int");
        fword("encode+");
        PUSH(INTERRUPT_REGS);
        fword("encode-int");
        fword("encode+");
    }

    PUSH(0);
    fword("encode-int");
    fword("encode+");
    PUSH(offset + 0x10000);
    fword("encode-int");
    fword("encode+");
    PUSH(INTERRUPT_REGS);
    fword("encode-int");
    fword("encode+");

    push_str("reg");
    fword("property");

    intregs = (struct sun4m_intregs *)ofmem_map_io(base | (uint64_t)offset, sizeof(*intregs));
    intregs->clear = ~SUN4M_INT_MASKALL;
    intregs->cpu_intregs[0].clear = ~0x17fff;

    for (i = 0; i < ncpu; i++) {
        PUSH((unsigned long)&intregs->cpu_intregs[i]);
        fword("encode-int");
        if (i != 0)
            fword("encode+");
    }
    PUSH((unsigned long)&intregs->tbt);
    fword("encode-int");
    fword("encode+");
    push_str("address");
    fword("property");

    fword("finish-device");
}

/* SMP CPU boot structure */
struct smp_cfg {
    uint32_t smp_ctx;
    uint32_t smp_ctxtbl;
    uint32_t smp_entry;
    uint32_t valid;
};

static struct smp_cfg *smp_header;

int
start_cpu(unsigned int pc, unsigned int context_ptr, unsigned int context, int cpu)
{
    if (!cpu)
        return -1;

    cpu &= 7;

    smp_header->smp_entry = pc;
    smp_header->smp_ctxtbl = context_ptr;
    smp_header->smp_ctx = context;
    smp_header->valid = cpu;

    intregs->cpu_intregs[cpu].set = SUN4M_SOFT_INT(14);

    return 0;
}

static void
ob_smp_init(unsigned long mem_size)
{
    // See arch/sparc32/entry.S for memory layout
    smp_header = (struct smp_cfg *)ofmem_map_io((uint64_t)(mem_size - 0x100),
                                          sizeof(struct smp_cfg));
}

static void
ob_obio_open(__attribute__((unused))int *idx)
{
	int ret=1;
	RET ( -ret );
}

static void
ob_obio_close(__attribute__((unused))int *idx)
{
	selfword("close-deblocker");
}

static void
ob_obio_initialize(__attribute__((unused))int *idx)
{
    push_str("/");
    fword("find-device");
    fword("new-device");

    push_str("obio");
    fword("device-name");

    push_str("hierarchical");
    fword("device-type");

    PUSH(2);
    fword("encode-int");
    push_str("#address-cells");
    fword("property");

    PUSH(1);
    fword("encode-int");
    push_str("#size-cells");
    fword("property");

    fword("finish-device");
}

static void
ob_set_obio_ranges(uint64_t base)
{
    push_str("/obio");
    fword("find-device");
    PUSH(0);
    fword("encode-int");
    PUSH(0);
    fword("encode-int");
    fword("encode+");
    PUSH(base >> 32);
    fword("encode-int");
    fword("encode+");
    PUSH(base & 0xffffffff);
    fword("encode-int");
    fword("encode+");
    PUSH(SLAVIO_SIZE);
    fword("encode-int");
    fword("encode+");
    push_str("ranges");
    fword("property");
}

static void
ob_obio_decodeunit(__attribute__((unused)) int *idx)
{
    fword("decode-unit-sbus");
}


static void
ob_obio_encodeunit(__attribute__((unused)) int *idx)
{
    fword("encode-unit-sbus");
}

NODE_METHODS(ob_obio) = {
	{ NULL,			ob_obio_initialize	},
	{ "open",		ob_obio_open		},
	{ "close",		ob_obio_close		},
	{ "encode-unit",	ob_obio_encodeunit	},
	{ "decode-unit",	ob_obio_decodeunit	},
};


int
ob_obio_init(uint64_t slavio_base, unsigned long fd_offset,
             unsigned long counter_offset, unsigned long intr_offset,
             int intr_ncpu, unsigned long aux1_offset, unsigned long aux2_offset,
             unsigned long mem_size)
{

    // All devices were integrated to NCR89C105, see
    // http://www.ibiblio.org/pub/historic-linux/early-ports/Sparc/NCR/NCR89C105.txt

    //printk("Initializing OBIO devices...\n");
#if 0 // XXX
    REGISTER_NAMED_NODE(ob_obio, "/obio");
    device_end();
#endif
    ob_set_obio_ranges(slavio_base);

    // Zilog Z8530 serial ports, see http://www.zilog.com
    // Must be before zs@0,0 or Linux won't boot
    ob_zs_init(slavio_base, SLAVIO_ZS1, ZS_INTR, 0, 0);

    ob_zs_init(slavio_base, SLAVIO_ZS, ZS_INTR, 1, 1);

    // M48T08 NVRAM, see http://www.st.com
    ob_nvram_init(slavio_base, SLAVIO_NVRAM);

    // 82078 FDC
    if (fd_offset != (unsigned long) -1)
        ob_fd_init(slavio_base, fd_offset, FD_INTR);

    ob_auxio_init(slavio_base, aux1_offset);

    if (aux2_offset != (unsigned long) -1)
        ob_aux2_reset_init(slavio_base, aux2_offset, AUXIO2_INTR);

    ob_counter_init(slavio_base, counter_offset, intr_ncpu);

    ob_interrupt_init(slavio_base, intr_offset, intr_ncpu);

    ob_smp_init(mem_size);

    return 0;
}
