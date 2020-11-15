// MPTable generation (on emulators)
// DO NOT ADD NEW FEATURES HERE.  (See paravirt.c / biostables.c instead.)
//
// Copyright (C) 2008-2010  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2006 Fabrice Bellard
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // CONFIG_*
#include "hw/pci.h"
#include "hw/pci_regs.h"
#include "malloc.h" // free
#include "output.h" // dprintf
#include "romfile.h" // romfile_loadint
#include "std/mptable.h" // MPTABLE_SIGNATURE
#include "string.h" // memset
#include "util.h" // MaxCountCPUs
#include "x86.h" // cpuid

void
mptable_setup(void)
{
    if (! CONFIG_MPTABLE)
        return;

    dprintf(3, "init MPTable\n");

    // Config structure in temp area.
    struct mptable_config_s *config = malloc_tmp(32*1024);
    if (!config) {
        warn_noalloc();
        return;
    }
    memset(config, 0, sizeof(*config));
    config->signature = MPCONFIG_SIGNATURE;
    config->spec = 4;
    memcpy(config->oemid, BUILD_CPUNAME8, sizeof(config->oemid));
    memcpy(config->productid, "0.1         ", sizeof(config->productid));
    config->lapic = BUILD_APIC_ADDR;

    // Detect cpu info
    u32 cpuid_signature, ebx, ecx, cpuid_features;
    cpuid(1, &cpuid_signature, &ebx, &ecx, &cpuid_features);
    if (! cpuid_signature) {
        // Use default values.
        cpuid_signature = 0x600;
        cpuid_features = 0x201;
    }
    int pkgcpus = 1;
    if (cpuid_features & (1 << 28)) {
        /* Only populate the MPS tables with the first logical CPU in
           each package */
        pkgcpus = (ebx >> 16) & 0xff;
        pkgcpus = 1 << (__fls(pkgcpus - 1) + 1); /* round up to power of 2 */
    }
    u8 apic_version = readl((u8*)BUILD_APIC_ADDR + 0x30) & 0xff;

    // CPU definitions.
    struct mpt_cpu *cpus = (void*)&config[1], *cpu = cpus;
    int i;
    for (i = 0; i < MaxCountCPUs; i+=pkgcpus) {
        memset(cpu, 0, sizeof(*cpu));
        cpu->type = MPT_TYPE_CPU;
        cpu->apicid = i;
        cpu->apicver = apic_version;
        /* cpu flags: enabled, bootstrap cpu */
        cpu->cpuflag = (apic_id_is_present(i) ? 0x01 : 0x00) | ((i==0) ? 0x02 : 0x00);
        cpu->cpusignature = cpuid_signature;
        cpu->featureflag = cpuid_features;
        cpu++;
    }
    int entrycount = cpu - cpus;

    // PCI bus
    struct mpt_bus *buses = (void*)cpu, *bus = buses;
    if (!hlist_empty(&PCIDevices)) {
        memset(bus, 0, sizeof(*bus));
        bus->type = MPT_TYPE_BUS;
        bus->busid = 0;
        memcpy(bus->bustype, "PCI   ", sizeof(bus->bustype));
        bus++;
        entrycount++;
    }

    /* isa bus */
    int isabusid = bus - buses;
    memset(bus, 0, sizeof(*bus));
    bus->type = MPT_TYPE_BUS;
    bus->busid = isabusid;
    memcpy(bus->bustype, "ISA   ", sizeof(bus->bustype));
    bus++;
    entrycount++;

    /* ioapic */
    u8 ioapic_id = BUILD_IOAPIC_ID;
    struct mpt_ioapic *ioapic = (void*)bus;
    memset(ioapic, 0, sizeof(*ioapic));
    ioapic->type = MPT_TYPE_IOAPIC;
    ioapic->apicid = ioapic_id;
    ioapic->apicver = 0x11;
    ioapic->flags = 1; // enable
    ioapic->apicaddr = BUILD_IOAPIC_ADDR;
    entrycount++;

    /* irqs */
    struct mpt_intsrc *intsrcs = (void*)&ioapic[1], *intsrc = intsrcs;
    int dev = -1;
    unsigned short pinmask = 0;

    struct pci_device *pci;
    foreachpci(pci) {
        u16 bdf = pci->bdf;
        if (pci_bdf_to_bus(bdf) != 0)
            break;
        int pin = pci_config_readb(bdf, PCI_INTERRUPT_PIN);
        int irq = pci_config_readb(bdf, PCI_INTERRUPT_LINE);
        if (pin == 0)
            continue;
        if (dev != pci_bdf_to_busdev(bdf)) {
            dev = pci_bdf_to_busdev(bdf);
            pinmask = 0;
        }
        if (pinmask & (1 << pin)) /* pin was seen already */
            continue;
        pinmask |= (1 << pin);
        memset(intsrc, 0, sizeof(*intsrc));
        intsrc->type = MPT_TYPE_INTSRC;
        intsrc->irqtype = 0; /* INT */
        intsrc->irqflag = 1; /* active high */
        intsrc->srcbus = pci_bdf_to_bus(bdf); /* PCI bus */
        intsrc->srcbusirq = (pci_bdf_to_dev(bdf) << 2) | (pin - 1);
        intsrc->dstapic = ioapic_id;
        intsrc->dstirq = irq;
        intsrc++;
    }

    int irq0_override = romfile_loadint("etc/irq0-override", 0);
    for (i = 0; i < 16; i++) {
        memset(intsrc, 0, sizeof(*intsrc));
        if (BUILD_PCI_IRQS & (1 << i))
            continue;
        intsrc->type = MPT_TYPE_INTSRC;
        intsrc->irqtype = 0; /* INT */
        intsrc->irqflag = 0; /* conform to bus spec */
        intsrc->srcbus = isabusid; /* ISA bus */
        intsrc->srcbusirq = i;
        intsrc->dstapic = ioapic_id;
        intsrc->dstirq = i;
        if (irq0_override) {
            /* Destination 2 is covered by irq0->inti2 override (i ==
               0). Source IRQ 2 is unused */
            if (i == 0)
                intsrc->dstirq = 2;
            else if (i == 2)
                intsrc--;
        }
        intsrc++;
    }

    /* Local interrupt assignment */
    intsrc->type = MPT_TYPE_LOCAL_INT;
    intsrc->irqtype = 3; /* ExtINT */
    intsrc->irqflag = 0; /* PO, EL default */
    intsrc->srcbus = isabusid; /* ISA */
    intsrc->srcbusirq = 0;
    intsrc->dstapic = 0; /* BSP == APIC #0 */
    intsrc->dstirq = 0; /* LINTIN0 */
    intsrc++;

    intsrc->type = MPT_TYPE_LOCAL_INT;
    intsrc->irqtype = 1; /* NMI */
    intsrc->irqflag = 0; /* PO, EL default */
    intsrc->srcbus = isabusid; /* ISA */
    intsrc->srcbusirq = 0;
    intsrc->dstapic = 0xff; /* to all local APICs */
    intsrc->dstirq = 1; /* LINTIN1 */
    intsrc++;
    entrycount += intsrc - intsrcs;

    // Finalize config structure.
    int length = (void*)intsrc - (void*)config;
    config->entrycount = entrycount;
    config->length = length;
    config->checksum -= checksum(config, length);

    // floating pointer structure
    struct mptable_floating_s floating;
    memset(&floating, 0, sizeof(floating));
    floating.signature = MPTABLE_SIGNATURE;
    floating.physaddr = (u32)config;
    floating.length = 1;
    floating.spec_rev = 4;
    floating.checksum -= checksum(&floating, sizeof(floating));
    copy_mptable(&floating);
    free(config);
}
