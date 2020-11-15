// Xen HVM support
//
// Copyright (C) 2011 Citrix Systems.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h"
#include "hw/serialio.h" // DebugOutputPort
#include "malloc.h" // memalign_high
#include "memmap.h" // add_e820
#include "output.h" // dprintf
#include "paravirt.h" // PlatformRunningOn
#include "string.h" // memcpy
#include "util.h" // copy_acpi_rsdp
#include "x86.h" // cpuid
#include "xen.h"

#define INFO_PHYSICAL_ADDRESS 0x00001000

u32 xen_cpuid_base = 0;
unsigned long xen_hypercall_page = 0;

struct xen_seabios_info {
    char signature[14]; /* XenHVMSeaBIOS\0 */
    u8 length;     /* Length of this struct */
    u8 checksum;   /* Set such that the sum over bytes 0..length == 0 */
    /*
     * Physical address of an array of tables_nr elements.
     *
     * Each element is a 32 bit value contianing the physical address
     * of a BIOS table.
     */
    u32 tables;
    u32 tables_nr;
    /*
     * Physical address of the e820 table, contains e820_nr entries.
     */
    u32 e820;
    u32 e820_nr;
} PACKED;

static void validate_info(struct xen_seabios_info *t)
{
    if ( memcmp(t->signature, "XenHVMSeaBIOS", 14) )
        panic("Bad Xen info signature\n");

    if ( t->length < sizeof(struct xen_seabios_info) )
        panic("Bad Xen info length\n");

    if (checksum(t, t->length) != 0)
        panic("Bad Xen info checksum\n");
}

void xen_preinit(void)
{
    u32 base, eax, ebx, ecx, edx;
    char signature[13];

    if (!CONFIG_XEN)
        return;

    for (base = 0x40000000; base < 0x40010000; base += 0x100) {
        cpuid(base, &eax, &ebx, &ecx, &edx);
        memcpy(signature + 0, &ebx, 4);
        memcpy(signature + 4, &ecx, 4);
        memcpy(signature + 8, &edx, 4);
        signature[12] = 0;

        dprintf(9, "Found hypervisor signature \"%s\" at %x\n",
                signature, base);
        if (strcmp(signature, "XenVMMXenVMM") == 0) {
            /* Set debug_io_port first, so the following messages work. */
            DebugOutputPort = 0xe9;
            debug_banner();
            dprintf(1, "\nFound Xen hypervisor signature at %x\n", base);
            if ((eax - base) < 2)
                panic("Insufficient Xen cpuid leaves. eax=%x at base %x\n",
                      eax, base);
            xen_cpuid_base = base;
            break;
        }
    }
    if (!xen_cpuid_base) {
        dprintf(1, "No Xen hypervisor found.\n");
        return;
    }
    PlatformRunningOn = PF_QEMU|PF_XEN;
}

static int hypercall_xen_version( int cmd, void *arg)
{
    return _hypercall2(int, xen_version, cmd, arg);
}

/* Fill in hypercall transfer pages. */
void xen_hypercall_setup(void)
{
    u32 eax, ebx, ecx, edx;
    xen_extraversion_t extraversion;
    unsigned long i;

    if (!runningOnXen())
        return;

    cpuid(xen_cpuid_base + 2, &eax, &ebx, &ecx, &edx);

    xen_hypercall_page = (unsigned long)memalign_high(PAGE_SIZE, eax*PAGE_SIZE);
    if (!xen_hypercall_page)
        panic("unable to allocate Xen hypercall page\n");

    dprintf(1, "Allocated Xen hypercall page at %lx\n", xen_hypercall_page);
    for ( i = 0; i < eax; i++ )
        wrmsr(ebx, xen_hypercall_page + (i << 12) + i);

    /* Print version information. */
    cpuid(xen_cpuid_base + 1, &eax, &ebx, &ecx, &edx);
    hypercall_xen_version(XENVER_extraversion, extraversion);
    dprintf(1, "Detected Xen v%u.%u%s\n", eax >> 16, eax & 0xffff, extraversion);
}

void xen_biostable_setup(void)
{
    struct xen_seabios_info *info = (void *)INFO_PHYSICAL_ADDRESS;
    void **tables = (void*)info->tables;
    int i;

    dprintf(1, "xen: copy BIOS tables...\n");
    for (i=0; i<info->tables_nr; i++)
        copy_table(tables[i]);

    find_acpi_features();
}

void xen_ramsize_preinit(void)
{
    int i;
    struct xen_seabios_info *info = (void *)INFO_PHYSICAL_ADDRESS;
    struct e820entry *e820 = (struct e820entry *)info->e820;
    validate_info(info);

    dprintf(1, "xen: copy e820...\n");

    for (i = 0; i < info->e820_nr; i++) {
        struct e820entry *e = &e820[i];
        add_e820(e->start, e->size, e->type);
    }
}
