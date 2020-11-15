// Initialize PCI devices (on emulators)
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2006 Fabrice Bellard
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "byteorder.h" // le64_to_cpu
#include "config.h" // CONFIG_*
#include "dev-q35.h" // Q35_HOST_BRIDGE_PCIEXBAR_ADDR
#include "dev-piix.h" // PIIX_*
#include "hw/ata.h" // PORT_ATA1_CMD_BASE
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_ids.h" // PCI_VENDOR_ID_INTEL
#include "hw/pci_regs.h" // PCI_COMMAND
#include "list.h" // struct hlist_node
#include "malloc.h" // free
#include "memmap.h" // add_e820
#include "output.h" // dprintf
#include "paravirt.h" // RamSize
#include "romfile.h" // romfile_loadint
#include "string.h" // memset
#include "util.h" // pci_setup
#include "x86.h" // outb

#define PCI_DEVICE_MEM_MIN    (1<<12)  // 4k == page size
#define PCI_BRIDGE_MEM_MIN    (1<<21)  // 2M == hugepage size
#define PCI_BRIDGE_IO_MIN      0x1000  // mandated by pci bridge spec

static const char *region_type_name[] = {
    [ PCI_REGION_TYPE_IO ]      = "io",
    [ PCI_REGION_TYPE_MEM ]     = "mem",
    [ PCI_REGION_TYPE_PREFMEM ] = "prefmem",
};

u64 pcimem_start   = BUILD_PCIMEM_START;
u64 pcimem_end     = BUILD_PCIMEM_END;
u64 pcimem64_start = BUILD_PCIMEM64_START;
u64 pcimem64_end   = BUILD_PCIMEM64_END;
u64 pci_io_low_end = 0xa000;

struct pci_region_entry {
    struct pci_device *dev;
    int bar;
    u64 size;
    u64 align;
    int is64;
    enum pci_region_type type;
    struct hlist_node node;
};

struct pci_region {
    /* pci region assignments */
    u64 base;
    struct hlist_head list;
};

struct pci_bus {
    struct pci_region r[PCI_REGION_TYPE_COUNT];
    struct pci_device *bus_dev;
};

static u32 pci_bar(struct pci_device *pci, int region_num)
{
    if (region_num != PCI_ROM_SLOT) {
        return PCI_BASE_ADDRESS_0 + region_num * 4;
    }

#define PCI_HEADER_TYPE_MULTI_FUNCTION 0x80
    u8 type = pci->header_type & ~PCI_HEADER_TYPE_MULTI_FUNCTION;
    return type == PCI_HEADER_TYPE_BRIDGE ? PCI_ROM_ADDRESS1 : PCI_ROM_ADDRESS;
}

static void
pci_set_io_region_addr(struct pci_device *pci, int bar, u64 addr, int is64)
{
    u32 ofs = pci_bar(pci, bar);
    pci_config_writel(pci->bdf, ofs, addr);
    if (is64)
        pci_config_writel(pci->bdf, ofs + 4, addr >> 32);
}


/****************************************************************
 * Misc. device init
 ****************************************************************/

/* host irqs corresponding to PCI irqs A-D */
const u8 pci_irqs[4] = {
    10, 10, 11, 11
};

static int dummy_pci_slot_get_irq(struct pci_device *pci, int pin)
{
    dprintf(1, "pci_slot_get_irq called with unknown routing\n");

    return 0xff; /* PCI defined "unknown" or "no connection" for x86 */
}

static int (*pci_slot_get_irq)(struct pci_device *pci, int pin) =
    dummy_pci_slot_get_irq;

// Return the global irq number corresponding to a host bus device irq pin.
static int piix_pci_slot_get_irq(struct pci_device *pci, int pin)
{
    int slot_addend = 0;

    while (pci->parent != NULL) {
        slot_addend += pci_bdf_to_dev(pci->bdf);
        pci = pci->parent;
    }
    slot_addend += pci_bdf_to_dev(pci->bdf) - 1;
    return pci_irqs[(pin - 1 + slot_addend) & 3];
}

static int mch_pci_slot_get_irq(struct pci_device *pci, int pin)
{
    int pin_addend = 0;
    while (pci->parent != NULL) {
        pin_addend += pci_bdf_to_dev(pci->bdf);
        pci = pci->parent;
    }
    u8 slot = pci_bdf_to_dev(pci->bdf);
    if (slot <= 24)
        /* Slots 0-24 rotate slot:pin mapping similar to piix above, but
           with a different starting index - see q35-acpi-dsdt.dsl */
        return pci_irqs[(pin - 1 + pin_addend + slot) & 3];
    /* Slots 25-31 all use LNKA mapping (or LNKE, but A:D = E:H) */
    return pci_irqs[(pin - 1 + pin_addend) & 3];
}

/* PIIX3/PIIX4 PCI to ISA bridge */
static void piix_isa_bridge_setup(struct pci_device *pci, void *arg)
{
    int i, irq;
    u8 elcr[2];

    elcr[0] = 0x00;
    elcr[1] = 0x00;
    for (i = 0; i < 4; i++) {
        irq = pci_irqs[i];
        /* set to trigger level */
        elcr[irq >> 3] |= (1 << (irq & 7));
        /* activate irq remapping in PIIX */
        pci_config_writeb(pci->bdf, 0x60 + i, irq);
    }
    outb(elcr[0], PIIX_PORT_ELCR1);
    outb(elcr[1], PIIX_PORT_ELCR2);
    dprintf(1, "PIIX3/PIIX4 init: elcr=%02x %02x\n", elcr[0], elcr[1]);
}

/* ICH9 LPC PCI to ISA bridge */
/* PCI_VENDOR_ID_INTEL && PCI_DEVICE_ID_INTEL_ICH9_LPC */
static void mch_isa_bridge_setup(struct pci_device *dev, void *arg)
{
    u16 bdf = dev->bdf;
    int i, irq;
    u8 elcr[2];

    elcr[0] = 0x00;
    elcr[1] = 0x00;

    for (i = 0; i < 4; i++) {
        irq = pci_irqs[i];
        /* set to trigger level */
        elcr[irq >> 3] |= (1 << (irq & 7));

        /* activate irq remapping in LPC */

        /* PIRQ[A-D] routing */
        pci_config_writeb(bdf, ICH9_LPC_PIRQA_ROUT + i, irq);
        /* PIRQ[E-H] routing */
        pci_config_writeb(bdf, ICH9_LPC_PIRQE_ROUT + i, irq);
    }
    outb(elcr[0], ICH9_LPC_PORT_ELCR1);
    outb(elcr[1], ICH9_LPC_PORT_ELCR2);
    dprintf(1, "Q35 LPC init: elcr=%02x %02x\n", elcr[0], elcr[1]);

    /* pm io base */
    pci_config_writel(bdf, ICH9_LPC_PMBASE,
                      acpi_pm_base | ICH9_LPC_PMBASE_RTE);

    /* acpi enable, SCI: IRQ9 000b = irq9*/
    pci_config_writeb(bdf, ICH9_LPC_ACPI_CTRL, ICH9_LPC_ACPI_CTRL_ACPI_EN);

    acpi_pm1a_cnt = acpi_pm_base + 0x04;
    pmtimer_setup(acpi_pm_base + 0x08);
}

static void storage_ide_setup(struct pci_device *pci, void *arg)
{
    /* IDE: we map it as in ISA mode */
    pci_set_io_region_addr(pci, 0, PORT_ATA1_CMD_BASE, 0);
    pci_set_io_region_addr(pci, 1, PORT_ATA1_CTRL_BASE, 0);
    pci_set_io_region_addr(pci, 2, PORT_ATA2_CMD_BASE, 0);
    pci_set_io_region_addr(pci, 3, PORT_ATA2_CTRL_BASE, 0);
}

/* PIIX3/PIIX4 IDE */
static void piix_ide_setup(struct pci_device *pci, void *arg)
{
    u16 bdf = pci->bdf;
    pci_config_writew(bdf, 0x40, 0x8000); // enable IDE0
    pci_config_writew(bdf, 0x42, 0x8000); // enable IDE1
}

static void pic_ibm_setup(struct pci_device *pci, void *arg)
{
    /* PIC, IBM, MPIC & MPIC2 */
    pci_set_io_region_addr(pci, 0, 0x80800000 + 0x00040000, 0);
}

static void apple_macio_setup(struct pci_device *pci, void *arg)
{
    /* macio bridge */
    pci_set_io_region_addr(pci, 0, 0x80800000, 0);
}

static void piix4_pm_config_setup(u16 bdf)
{
    // acpi sci is hardwired to 9
    pci_config_writeb(bdf, PCI_INTERRUPT_LINE, 9);

    pci_config_writel(bdf, PIIX_PMBASE, acpi_pm_base | 1);
    pci_config_writeb(bdf, PIIX_PMREGMISC, 0x01); /* enable PM io space */
    pci_config_writel(bdf, PIIX_SMBHSTBASE, (acpi_pm_base + 0x100) | 1);
    pci_config_writeb(bdf, PIIX_SMBHSTCFG, 0x09); /* enable SMBus io space */
}

static int PiixPmBDF = -1;

/* PIIX4 Power Management device (for ACPI) */
static void piix4_pm_setup(struct pci_device *pci, void *arg)
{
    PiixPmBDF = pci->bdf;
    piix4_pm_config_setup(pci->bdf);

    acpi_pm1a_cnt = acpi_pm_base + 0x04;
    pmtimer_setup(acpi_pm_base + 0x08);
}

/* ICH9 SMBUS */
/* PCI_VENDOR_ID_INTEL && PCI_DEVICE_ID_INTEL_ICH9_SMBUS */
static void ich9_smbus_setup(struct pci_device *dev, void *arg)
{
    u16 bdf = dev->bdf;
    /* map smbus into io space */
    pci_config_writel(bdf, ICH9_SMB_SMB_BASE,
                      (acpi_pm_base + 0x100) | PCI_BASE_ADDRESS_SPACE_IO);

    /* enable SMBus */
    pci_config_writeb(bdf, ICH9_SMB_HOSTC, ICH9_SMB_HOSTC_HST_EN);
}

static const struct pci_device_id pci_device_tbl[] = {
    /* PIIX3/PIIX4 PCI to ISA bridge */
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371SB_0,
               piix_isa_bridge_setup),
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371AB_0,
               piix_isa_bridge_setup),
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH9_LPC,
               mch_isa_bridge_setup),

    /* STORAGE IDE */
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371SB_1,
                     PCI_CLASS_STORAGE_IDE, piix_ide_setup),
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371AB,
                     PCI_CLASS_STORAGE_IDE, piix_ide_setup),
    PCI_DEVICE_CLASS(PCI_ANY_ID, PCI_ANY_ID, PCI_CLASS_STORAGE_IDE,
                     storage_ide_setup),

    /* PIC, IBM, MIPC & MPIC2 */
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_IBM, 0x0046, PCI_CLASS_SYSTEM_PIC,
                     pic_ibm_setup),
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_IBM, 0xFFFF, PCI_CLASS_SYSTEM_PIC,
                     pic_ibm_setup),

    /* PIIX4 Power Management device (for ACPI) */
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371AB_3,
               piix4_pm_setup),
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH9_SMBUS,
               ich9_smbus_setup),

    /* 0xff00 */
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_APPLE, 0x0017, 0xff00, apple_macio_setup),
    PCI_DEVICE_CLASS(PCI_VENDOR_ID_APPLE, 0x0022, 0xff00, apple_macio_setup),

    PCI_DEVICE_END,
};

void pci_resume(void)
{
    if (!CONFIG_QEMU) {
        return;
    }

    if (PiixPmBDF >= 0) {
        piix4_pm_config_setup(PiixPmBDF);
    }
}

static void pci_bios_init_device(struct pci_device *pci)
{
    u16 bdf = pci->bdf;
    dprintf(1, "PCI: init bdf=%02x:%02x.%x id=%04x:%04x\n"
            , pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf), pci_bdf_to_fn(bdf)
            , pci->vendor, pci->device);

    /* map the interrupt */
    int pin = pci_config_readb(bdf, PCI_INTERRUPT_PIN);
    if (pin != 0)
        pci_config_writeb(bdf, PCI_INTERRUPT_LINE, pci_slot_get_irq(pci, pin));

    pci_init_device(pci_device_tbl, pci, NULL);

    /* enable memory mappings */
    pci_config_maskw(bdf, PCI_COMMAND, 0,
                     PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_SERR);
}

static void pci_bios_init_devices(void)
{
    struct pci_device *pci;
    foreachpci(pci) {
        pci_bios_init_device(pci);
    }
}

static void pci_enable_default_vga(void)
{
    struct pci_device *pci;

    foreachpci(pci) {
        if (is_pci_vga(pci)) {
            dprintf(1, "PCI: Using %02x:%02x.%x for primary VGA\n",
                    pci_bdf_to_bus(pci->bdf), pci_bdf_to_dev(pci->bdf),
                    pci_bdf_to_fn(pci->bdf));
            return;
        }
    }

    pci = pci_find_class(PCI_CLASS_DISPLAY_VGA);
    if (!pci) {
        dprintf(1, "PCI: No VGA devices found\n");
        return;
    }

    dprintf(1, "PCI: Enabling %02x:%02x.%x for primary VGA\n",
            pci_bdf_to_bus(pci->bdf), pci_bdf_to_dev(pci->bdf),
            pci_bdf_to_fn(pci->bdf));

    pci_config_maskw(pci->bdf, PCI_COMMAND, 0,
                     PCI_COMMAND_IO | PCI_COMMAND_MEMORY);

    while (pci->parent) {
        pci = pci->parent;

        dprintf(1, "PCI: Setting VGA enable on bridge %02x:%02x.%x\n",
                pci_bdf_to_bus(pci->bdf), pci_bdf_to_dev(pci->bdf),
                pci_bdf_to_fn(pci->bdf));

        pci_config_maskw(pci->bdf, PCI_BRIDGE_CONTROL, 0, PCI_BRIDGE_CTL_VGA);
        pci_config_maskw(pci->bdf, PCI_COMMAND, 0,
                         PCI_COMMAND_IO | PCI_COMMAND_MEMORY);
    }
}

/****************************************************************
 * Platform device initialization
 ****************************************************************/

static void i440fx_mem_addr_setup(struct pci_device *dev, void *arg)
{
    if (RamSize <= 0x80000000)
        pcimem_start = 0x80000000;
    else if (RamSize <= 0xc0000000)
        pcimem_start = 0xc0000000;

    pci_slot_get_irq = piix_pci_slot_get_irq;
}

static void mch_mem_addr_setup(struct pci_device *dev, void *arg)
{
    u64 addr = Q35_HOST_BRIDGE_PCIEXBAR_ADDR;
    u32 size = Q35_HOST_BRIDGE_PCIEXBAR_SIZE;

    /* setup mmconfig */
    u16 bdf = dev->bdf;
    u32 upper = addr >> 32;
    u32 lower = (addr & 0xffffffff) | Q35_HOST_BRIDGE_PCIEXBAREN;
    pci_config_writel(bdf, Q35_HOST_BRIDGE_PCIEXBAR, 0);
    pci_config_writel(bdf, Q35_HOST_BRIDGE_PCIEXBAR + 4, upper);
    pci_config_writel(bdf, Q35_HOST_BRIDGE_PCIEXBAR, lower);
    add_e820(addr, size, E820_RESERVED);

    /* setup pci i/o window (above mmconfig) */
    pcimem_start = addr + size;

    pci_slot_get_irq = mch_pci_slot_get_irq;

    /* setup io address space */
    if (acpi_pm_base < 0x1000)
        pci_io_low_end = 0x10000;
    else
        pci_io_low_end = acpi_pm_base;
}

static const struct pci_device_id pci_platform_tbl[] = {
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82441,
               i440fx_mem_addr_setup),
    PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_Q35_MCH,
               mch_mem_addr_setup),
    PCI_DEVICE_END
};

static void pci_bios_init_platform(void)
{
    struct pci_device *pci;
    foreachpci(pci) {
        pci_init_device(pci_platform_tbl, pci, NULL);
    }
}


/****************************************************************
 * Bus initialization
 ****************************************************************/

static void
pci_bios_init_bus_rec(int bus, u8 *pci_bus)
{
    int bdf;
    u16 class;

    dprintf(1, "PCI: %s bus = 0x%x\n", __func__, bus);

    /* prevent accidental access to unintended devices */
    foreachbdf(bdf, bus) {
        class = pci_config_readw(bdf, PCI_CLASS_DEVICE);
        if (class == PCI_CLASS_BRIDGE_PCI) {
            pci_config_writeb(bdf, PCI_SECONDARY_BUS, 255);
            pci_config_writeb(bdf, PCI_SUBORDINATE_BUS, 0);
        }
    }

    foreachbdf(bdf, bus) {
        class = pci_config_readw(bdf, PCI_CLASS_DEVICE);
        if (class != PCI_CLASS_BRIDGE_PCI) {
            continue;
        }
        dprintf(1, "PCI: %s bdf = 0x%x\n", __func__, bdf);

        u8 pribus = pci_config_readb(bdf, PCI_PRIMARY_BUS);
        if (pribus != bus) {
            dprintf(1, "PCI: primary bus = 0x%x -> 0x%x\n", pribus, bus);
            pci_config_writeb(bdf, PCI_PRIMARY_BUS, bus);
        } else {
            dprintf(1, "PCI: primary bus = 0x%x\n", pribus);
        }

        u8 secbus = pci_config_readb(bdf, PCI_SECONDARY_BUS);
        (*pci_bus)++;
        if (*pci_bus != secbus) {
            dprintf(1, "PCI: secondary bus = 0x%x -> 0x%x\n",
                    secbus, *pci_bus);
            secbus = *pci_bus;
            pci_config_writeb(bdf, PCI_SECONDARY_BUS, secbus);
        } else {
            dprintf(1, "PCI: secondary bus = 0x%x\n", secbus);
        }

        /* set to max for access to all subordinate buses.
           later set it to accurate value */
        u8 subbus = pci_config_readb(bdf, PCI_SUBORDINATE_BUS);
        pci_config_writeb(bdf, PCI_SUBORDINATE_BUS, 255);

        pci_bios_init_bus_rec(secbus, pci_bus);

        if (subbus != *pci_bus) {
            dprintf(1, "PCI: subordinate bus = 0x%x -> 0x%x\n",
                    subbus, *pci_bus);
            subbus = *pci_bus;
        } else {
            dprintf(1, "PCI: subordinate bus = 0x%x\n", subbus);
        }
        pci_config_writeb(bdf, PCI_SUBORDINATE_BUS, subbus);
    }
}

static void
pci_bios_init_bus(void)
{
    u8 extraroots = romfile_loadint("etc/extra-pci-roots", 0);
    u8 pci_bus = 0;

    pci_bios_init_bus_rec(0 /* host bus */, &pci_bus);

    if (extraroots) {
        while (pci_bus < 0xff) {
            pci_bus++;
            pci_bios_init_bus_rec(pci_bus, &pci_bus);
        }
    }
}


/****************************************************************
 * Bus sizing
 ****************************************************************/

static void
pci_bios_get_bar(struct pci_device *pci, int bar,
                 int *ptype, u64 *psize, int *pis64)
{
    u32 ofs = pci_bar(pci, bar);
    u16 bdf = pci->bdf;
    u32 old = pci_config_readl(bdf, ofs);
    int is64 = 0, type = PCI_REGION_TYPE_MEM;
    u64 mask;

    if (bar == PCI_ROM_SLOT) {
        mask = PCI_ROM_ADDRESS_MASK;
        pci_config_writel(bdf, ofs, mask);
    } else {
        if (old & PCI_BASE_ADDRESS_SPACE_IO) {
            mask = PCI_BASE_ADDRESS_IO_MASK;
            type = PCI_REGION_TYPE_IO;
        } else {
            mask = PCI_BASE_ADDRESS_MEM_MASK;
            if (old & PCI_BASE_ADDRESS_MEM_PREFETCH)
                type = PCI_REGION_TYPE_PREFMEM;
            is64 = ((old & PCI_BASE_ADDRESS_MEM_TYPE_MASK)
                    == PCI_BASE_ADDRESS_MEM_TYPE_64);
        }
        pci_config_writel(bdf, ofs, ~0);
    }
    u64 val = pci_config_readl(bdf, ofs);
    pci_config_writel(bdf, ofs, old);
    if (is64) {
        u32 hold = pci_config_readl(bdf, ofs + 4);
        pci_config_writel(bdf, ofs + 4, ~0);
        u32 high = pci_config_readl(bdf, ofs + 4);
        pci_config_writel(bdf, ofs + 4, hold);
        val |= ((u64)high << 32);
        mask |= ((u64)0xffffffff << 32);
        *psize = (~(val & mask)) + 1;
    } else {
        *psize = ((~(val & mask)) + 1) & 0xffffffff;
    }
    *ptype = type;
    *pis64 = is64;
}

static int pci_bios_bridge_region_is64(struct pci_region *r,
                                 struct pci_device *pci, int type)
{
    if (type != PCI_REGION_TYPE_PREFMEM)
        return 0;
    u32 pmem = pci_config_readl(pci->bdf, PCI_PREF_MEMORY_BASE);
    if (!pmem) {
        pci_config_writel(pci->bdf, PCI_PREF_MEMORY_BASE, 0xfff0fff0);
        pmem = pci_config_readl(pci->bdf, PCI_PREF_MEMORY_BASE);
        pci_config_writel(pci->bdf, PCI_PREF_MEMORY_BASE, 0x0);
    }
    if ((pmem & PCI_PREF_RANGE_TYPE_MASK) != PCI_PREF_RANGE_TYPE_64)
       return 0;
    struct pci_region_entry *entry;
    hlist_for_each_entry(entry, &r->list, node) {
        if (!entry->is64)
            return 0;
    }
    return 1;
}

static u64 pci_region_align(struct pci_region *r)
{
    struct pci_region_entry *entry;
    hlist_for_each_entry(entry, &r->list, node) {
        // The first entry in the sorted list has the largest alignment
        return entry->align;
    }
    return 1;
}

static u64 pci_region_sum(struct pci_region *r)
{
    u64 sum = 0;
    struct pci_region_entry *entry;
    hlist_for_each_entry(entry, &r->list, node) {
        sum += entry->size;
    }
    return sum;
}

static void pci_region_migrate_64bit_entries(struct pci_region *from,
                                             struct pci_region *to)
{
    struct hlist_node *n, **last = &to->list.first;
    struct pci_region_entry *entry;
    hlist_for_each_entry_safe(entry, n, &from->list, node) {
        if (!entry->is64)
            continue;
        if (entry->dev->class == PCI_CLASS_SERIAL_USB)
            continue;
        // Move from source list to destination list.
        hlist_del(&entry->node);
        hlist_add(&entry->node, last);
        last = &entry->node.next;
    }
}

static struct pci_region_entry *
pci_region_create_entry(struct pci_bus *bus, struct pci_device *dev,
                        int bar, u64 size, u64 align, int type, int is64)
{
    struct pci_region_entry *entry = malloc_tmp(sizeof(*entry));
    if (!entry) {
        warn_noalloc();
        return NULL;
    }
    memset(entry, 0, sizeof(*entry));
    entry->dev = dev;
    entry->bar = bar;
    entry->size = size;
    entry->align = align;
    entry->is64 = is64;
    entry->type = type;
    // Insert into list in sorted order.
    struct hlist_node **pprev;
    struct pci_region_entry *pos;
    hlist_for_each_entry_pprev(pos, pprev, &bus->r[type].list, node) {
        if (pos->align < align || (pos->align == align && pos->size < size))
            break;
    }
    hlist_add(&entry->node, pprev);
    return entry;
}

static int pci_bus_hotplug_support(struct pci_bus *bus)
{
    u8 pcie_cap = pci_find_capability(bus->bus_dev, PCI_CAP_ID_EXP);
    u8 shpc_cap;

    if (pcie_cap) {
        u16 pcie_flags = pci_config_readw(bus->bus_dev->bdf,
                                          pcie_cap + PCI_EXP_FLAGS);
        u8 port_type = ((pcie_flags & PCI_EXP_FLAGS_TYPE) >>
                       (__builtin_ffs(PCI_EXP_FLAGS_TYPE) - 1));
        u8 downstream_port = (port_type == PCI_EXP_TYPE_DOWNSTREAM) ||
                             (port_type == PCI_EXP_TYPE_ROOT_PORT);
        /*
         * PCI Express SPEC, 7.8.2:
         *   Slot Implemented – When Set, this bit indicates that the Link
         *   HwInit associated with this Port is connected to a slot (as
         *   compared to being connected to a system-integrated device or
         *   being disabled).
         *   This bit is valid for Downstream Ports. This bit is undefined
         *   for Upstream Ports.
         */
        u16 slot_implemented = pcie_flags & PCI_EXP_FLAGS_SLOT;

        return downstream_port && slot_implemented;
    }

    shpc_cap = pci_find_capability(bus->bus_dev, PCI_CAP_ID_SHPC);
    return !!shpc_cap;
}

static int pci_bios_check_devices(struct pci_bus *busses)
{
    dprintf(1, "PCI: check devices\n");

    // Calculate resources needed for regular (non-bus) devices.
    struct pci_device *pci;
    foreachpci(pci) {
        if (pci->class == PCI_CLASS_BRIDGE_PCI)
            busses[pci->secondary_bus].bus_dev = pci;

        struct pci_bus *bus = &busses[pci_bdf_to_bus(pci->bdf)];
        if (!bus->bus_dev)
            /*
             * Resources for all root busses go in busses[0]
             */
            bus = &busses[0];
        int i;
        for (i = 0; i < PCI_NUM_REGIONS; i++) {
            if ((pci->class == PCI_CLASS_BRIDGE_PCI) &&
                (i >= PCI_BRIDGE_NUM_REGIONS && i < PCI_ROM_SLOT))
                continue;
            int type, is64;
            u64 size;
            pci_bios_get_bar(pci, i, &type, &size, &is64);
            if (size == 0)
                continue;

            if (type != PCI_REGION_TYPE_IO && size < PCI_DEVICE_MEM_MIN)
                size = PCI_DEVICE_MEM_MIN;
            struct pci_region_entry *entry = pci_region_create_entry(
                bus, pci, i, size, size, type, is64);
            if (!entry)
                return -1;

            if (is64)
                i++;
        }
    }

    // Propagate required bus resources to parent busses.
    int secondary_bus;
    for (secondary_bus=MaxPCIBus; secondary_bus>0; secondary_bus--) {
        struct pci_bus *s = &busses[secondary_bus];
        if (!s->bus_dev)
            continue;
        struct pci_bus *parent = &busses[pci_bdf_to_bus(s->bus_dev->bdf)];
        if (!parent->bus_dev)
            /*
             * Resources for all root busses go in busses[0]
             */
            parent = &busses[0];
        int type;
        int hotplug_support = pci_bus_hotplug_support(s);
        for (type = 0; type < PCI_REGION_TYPE_COUNT; type++) {
            u64 align = (type == PCI_REGION_TYPE_IO) ?
                PCI_BRIDGE_IO_MIN : PCI_BRIDGE_MEM_MIN;
            if (!pci_bridge_has_region(s->bus_dev, type))
                continue;
            if (pci_region_align(&s->r[type]) > align)
                 align = pci_region_align(&s->r[type]);
            u64 sum = pci_region_sum(&s->r[type]);
            if (!sum && hotplug_support)
                sum = align; /* reserve min size for hot-plug */
            u64 size = ALIGN(sum, align);
            int is64 = pci_bios_bridge_region_is64(&s->r[type],
                                            s->bus_dev, type);
            // entry->bar is -1 if the entry represents a bridge region
            struct pci_region_entry *entry = pci_region_create_entry(
                parent, s->bus_dev, -1, size, align, type, is64);
            if (!entry)
                return -1;
            dprintf(1, "PCI: secondary bus %d size %08llx type %s\n",
                      entry->dev->secondary_bus, size,
                      region_type_name[entry->type]);
        }
    }
    return 0;
}


/****************************************************************
 * BAR assignment
 ****************************************************************/

// Setup region bases (given the regions' size and alignment)
static int pci_bios_init_root_regions_io(struct pci_bus *bus)
{
    /*
     * QEMU I/O address space usage:
     *   0000 - 0fff    legacy isa, pci config, pci root bus, ...
     *   1000 - 9fff    free
     *   a000 - afff    hotplug (cpu, pci via acpi, i440fx/piix only)
     *   b000 - bfff    power management (PORT_ACPI_PM_BASE)
     *                  [ qemu 1.4+ implements pci config registers
     *                    properly so guests can place the registers
     *                    where they want, on older versions its fixed ]
     *   c000 - ffff    free, traditionally used for pci io
     */
    struct pci_region *r_io = &bus->r[PCI_REGION_TYPE_IO];
    u64 sum = pci_region_sum(r_io);
    if (sum < 0x4000) {
        /* traditional region is big enougth, use it */
        r_io->base = 0xc000;
    } else if (sum < pci_io_low_end - 0x1000) {
        /* use the larger region at 0x1000 */
        r_io->base = 0x1000;
    } else {
        /* not enouth io address space -> error out */
        return -1;
    }
    dprintf(1, "PCI: IO: %4llx - %4llx\n", r_io->base, r_io->base + sum - 1);
    return 0;
}

static int pci_bios_init_root_regions_mem(struct pci_bus *bus)
{
    struct pci_region *r_end = &bus->r[PCI_REGION_TYPE_PREFMEM];
    struct pci_region *r_start = &bus->r[PCI_REGION_TYPE_MEM];

    if (pci_region_align(r_start) < pci_region_align(r_end)) {
        // Swap regions to improve alignment.
        r_end = r_start;
        r_start = &bus->r[PCI_REGION_TYPE_PREFMEM];
    }
    u64 sum = pci_region_sum(r_end);
    u64 align = pci_region_align(r_end);
    r_end->base = ALIGN_DOWN((pcimem_end - sum), align);
    sum = pci_region_sum(r_start);
    align = pci_region_align(r_start);
    r_start->base = ALIGN_DOWN((r_end->base - sum), align);

    if ((r_start->base < pcimem_start) ||
         (r_start->base > pcimem_end))
        // Memory range requested is larger than available.
        return -1;
    return 0;
}

#define PCI_IO_SHIFT            8
#define PCI_MEMORY_SHIFT        16
#define PCI_PREF_MEMORY_SHIFT   16

static void
pci_region_map_one_entry(struct pci_region_entry *entry, u64 addr)
{
    u16 bdf = entry->dev->bdf;
    if (entry->bar >= 0) {
        dprintf(1, "PCI: map device bdf=%02x:%02x.%x"
                "  bar %d, addr %08llx, size %08llx [%s]\n",
                pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf), pci_bdf_to_fn(bdf),
                entry->bar, addr, entry->size, region_type_name[entry->type]);

        pci_set_io_region_addr(entry->dev, entry->bar, addr, entry->is64);
        return;
    }

    u64 limit = addr + entry->size - 1;
    if (entry->type == PCI_REGION_TYPE_IO) {
        pci_config_writeb(bdf, PCI_IO_BASE, addr >> PCI_IO_SHIFT);
        pci_config_writew(bdf, PCI_IO_BASE_UPPER16, 0);
        pci_config_writeb(bdf, PCI_IO_LIMIT, limit >> PCI_IO_SHIFT);
        pci_config_writew(bdf, PCI_IO_LIMIT_UPPER16, 0);
    }
    if (entry->type == PCI_REGION_TYPE_MEM) {
        pci_config_writew(bdf, PCI_MEMORY_BASE, addr >> PCI_MEMORY_SHIFT);
        pci_config_writew(bdf, PCI_MEMORY_LIMIT, limit >> PCI_MEMORY_SHIFT);
    }
    if (entry->type == PCI_REGION_TYPE_PREFMEM) {
        pci_config_writew(bdf, PCI_PREF_MEMORY_BASE, addr >> PCI_PREF_MEMORY_SHIFT);
        pci_config_writew(bdf, PCI_PREF_MEMORY_LIMIT, limit >> PCI_PREF_MEMORY_SHIFT);
        pci_config_writel(bdf, PCI_PREF_BASE_UPPER32, addr >> 32);
        pci_config_writel(bdf, PCI_PREF_LIMIT_UPPER32, limit >> 32);
    }
}

static void pci_region_map_entries(struct pci_bus *busses, struct pci_region *r)
{
    struct hlist_node *n;
    struct pci_region_entry *entry;
    hlist_for_each_entry_safe(entry, n, &r->list, node) {
        u64 addr = r->base;
        r->base += entry->size;
        if (entry->bar == -1)
            // Update bus base address if entry is a bridge region
            busses[entry->dev->secondary_bus].r[entry->type].base = addr;
        pci_region_map_one_entry(entry, addr);
        hlist_del(&entry->node);
        free(entry);
    }
}

static void pci_bios_map_devices(struct pci_bus *busses)
{
    if (pci_bios_init_root_regions_io(busses))
        panic("PCI: out of I/O address space\n");

    dprintf(1, "PCI: 32: %016llx - %016llx\n", pcimem_start, pcimem_end);
    if (pci_bios_init_root_regions_mem(busses)) {
        struct pci_region r64_mem, r64_pref;
        r64_mem.list.first = NULL;
        r64_pref.list.first = NULL;
        pci_region_migrate_64bit_entries(&busses[0].r[PCI_REGION_TYPE_MEM],
                                         &r64_mem);
        pci_region_migrate_64bit_entries(&busses[0].r[PCI_REGION_TYPE_PREFMEM],
                                         &r64_pref);

        if (pci_bios_init_root_regions_mem(busses))
            panic("PCI: out of 32bit address space\n");

        u64 sum_mem = pci_region_sum(&r64_mem);
        u64 sum_pref = pci_region_sum(&r64_pref);
        u64 align_mem = pci_region_align(&r64_mem);
        u64 align_pref = pci_region_align(&r64_pref);

        r64_mem.base = le64_to_cpu(romfile_loadint("etc/reserved-memory-end", 0));
        if (r64_mem.base < 0x100000000LL + RamSizeOver4G)
            r64_mem.base = 0x100000000LL + RamSizeOver4G;
        r64_mem.base = ALIGN(r64_mem.base, align_mem);
        r64_mem.base = ALIGN(r64_mem.base, (1LL<<30));    // 1G hugepage
        r64_pref.base = r64_mem.base + sum_mem;
        r64_pref.base = ALIGN(r64_pref.base, align_pref);
        r64_pref.base = ALIGN(r64_pref.base, (1LL<<30));  // 1G hugepage
        pcimem64_start = r64_mem.base;
        pcimem64_end = r64_pref.base + sum_pref;
        pcimem64_end = ALIGN(pcimem64_end, (1LL<<30));    // 1G hugepage
        dprintf(1, "PCI: 64: %016llx - %016llx\n", pcimem64_start, pcimem64_end);

        pci_region_map_entries(busses, &r64_mem);
        pci_region_map_entries(busses, &r64_pref);
    } else {
        // no bars mapped high -> drop 64bit window (see dsdt)
        pcimem64_start = 0;
    }
    // Map regions on each device.
    int bus;
    for (bus = 0; bus<=MaxPCIBus; bus++) {
        int type;
        for (type = 0; type < PCI_REGION_TYPE_COUNT; type++)
            pci_region_map_entries(busses, &busses[bus].r[type]);
    }
}


/****************************************************************
 * Main setup code
 ****************************************************************/

void
pci_setup(void)
{
    if (!CONFIG_QEMU)
        return;

    dprintf(3, "pci setup\n");

    dprintf(1, "=== PCI bus & bridge init ===\n");
    if (pci_probe_host() != 0) {
        return;
    }
    pci_bios_init_bus();

    dprintf(1, "=== PCI device probing ===\n");
    pci_probe_devices();

    pcimem_start = RamSize;
    pci_bios_init_platform();

    dprintf(1, "=== PCI new allocation pass #1 ===\n");
    struct pci_bus *busses = malloc_tmp(sizeof(*busses) * (MaxPCIBus + 1));
    if (!busses) {
        warn_noalloc();
        return;
    }
    memset(busses, 0, sizeof(*busses) * (MaxPCIBus + 1));
    if (pci_bios_check_devices(busses))
        return;

    dprintf(1, "=== PCI new allocation pass #2 ===\n");
    pci_bios_map_devices(busses);

    pci_bios_init_devices();

    free(busses);

    pci_enable_default_vga();
}
