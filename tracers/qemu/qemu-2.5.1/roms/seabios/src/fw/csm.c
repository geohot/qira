// Compatibility Support Module (CSM) for UEFI / EDK-II
//
// Copyright © 2013 Intel Corporation
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "bregs.h"
#include "config.h" // CONFIG_*
#include "farptr.h" // MAKE_FLATPTR
#include "hw/pci.h"
#include "hw/pic.h"
#include "malloc.h" // csm_malloc_preinit
#include "memmap.h"
#include "output.h" // dprintf
#include "stacks.h" // wait_threads
#include "std/acpi.h" // RSDP_SIGNATURE
#include "std/bda.h" // struct bios_data_area_s
#include "std/optionrom.h" // struct rom_header
#include "util.h" // copy_smbios
#include "paravirt.h" // qemu_preinit

#define UINT8 u8
#define UINT16 u16
#define UINT32 u32
#include "std/LegacyBios.h"

struct rsdp_descriptor csm_rsdp VARFSEG __aligned(16);

EFI_COMPATIBILITY16_TABLE csm_compat_table VARFSEG __aligned(16) = {
    .Signature = 0x24454649,
    .TableChecksum = 0 /* Filled in by checkrom.py */,
    .TableLength = sizeof(csm_compat_table),
    .Compatibility16CallSegment = SEG_BIOS,
    .Compatibility16CallOffset = 0 /* Filled in by checkrom.py */,
    .OemIdStringPointer = (u32)"SeaBIOS",
    .AcpiRsdPtrPointer = (u32)&csm_rsdp,
};

EFI_TO_COMPATIBILITY16_INIT_TABLE *csm_init_table;
EFI_TO_COMPATIBILITY16_BOOT_TABLE *csm_boot_table;

static u16 PICMask = PIC_IRQMASK_DEFAULT;

extern void __csm_return(struct bregs *regs) __noreturn;

static void
csm_return(struct bregs *regs)
{
    u32 rommax = rom_get_max();
    extern u8 final_readonly_start[];

    dprintf(3, "handle_csm returning AX=%04x\n", regs->ax);

    csm_compat_table.UmaAddress = rommax;
    csm_compat_table.UmaSize = (u32)final_readonly_start - rommax;

    PICMask = pic_irqmask_read();
    __csm_return(regs);
}

static void
csm_maininit(struct bregs *regs)
{
    interface_init();
    pci_probe_devices();

    csm_compat_table.PnPInstallationCheckSegment = SEG_BIOS;
    csm_compat_table.PnPInstallationCheckOffset = get_pnp_offset();

    regs->ax = 0;

    csm_return(regs);
}

/* Legacy16InitializeYourself */
static void
handle_csm_0000(struct bregs *regs)
{
    qemu_preinit();

    dprintf(3, "Legacy16InitializeYourself table %04x:%04x\n", regs->es,
            regs->bx);

    csm_init_table = MAKE_FLATPTR(regs->es, regs->bx);

    dprintf(3, "BiosLessThan1MB %08x\n", csm_init_table->BiosLessThan1MB);
    dprintf(3, "HiPmmMemory     %08x\n", csm_init_table->HiPmmMemory);
    dprintf(3, "HiPmmMemorySize %08x\n", csm_init_table->HiPmmMemorySizeInBytes);
    dprintf(3, "ReverseThunk    %04x:%04x\n", csm_init_table->ReverseThunkCallSegment,
            csm_init_table->ReverseThunkCallOffset);
    dprintf(3, "NumE820Entries  %08x\n", csm_init_table->NumberE820Entries);
    dprintf(3, "OsMemoryAbove1M %08x\n", csm_init_table->OsMemoryAbove1Mb);
    dprintf(3, "ThunkStart      %08x\n", csm_init_table->ThunkStart);
    dprintf(3, "ThunkSize       %08x\n", csm_init_table->ThunkSizeInBytes);
    dprintf(3, "LoPmmMemory     %08x\n", csm_init_table->LowPmmMemory);
    dprintf(3, "LoPmmMemorySize %08x\n", csm_init_table->LowPmmMemorySizeInBytes);

    csm_malloc_preinit(csm_init_table->LowPmmMemory,
                       csm_init_table->LowPmmMemorySizeInBytes,
                       csm_init_table->HiPmmMemory,
                       csm_init_table->HiPmmMemorySizeInBytes);
    reloc_preinit(csm_maininit, regs);
}

/* Legacy16UpdateBbs */
static void
handle_csm_0001(struct bregs *regs)
{
    if (!CONFIG_BOOT) {
        regs->ax = 1;
        return;
    }

    dprintf(3, "Legacy16UpdateBbs table %04x:%04x\n", regs->es, regs->bx);

    csm_boot_table = MAKE_FLATPTR(regs->es, regs->bx);
    dprintf(3, "MajorVersion %04x\n", csm_boot_table->MajorVersion);
    dprintf(3, "MinorVersion %04x\n", csm_boot_table->MinorVersion);
    dprintf(3, "AcpiTable %08x\n", csm_boot_table->AcpiTable);
    dprintf(3, "SmbiosTable %08x\n", csm_boot_table->SmbiosTable);
    dprintf(3, "SmbiosTableLength %08x\n", csm_boot_table->SmbiosTableLength);
//    dprintf(3, "SioData %08x\n", csm_boot_table->SioData);
    dprintf(3, "DevicePathType %04x\n", csm_boot_table->DevicePathType);
    dprintf(3, "PciIrqMask %04x\n", csm_boot_table->PciIrqMask);
    dprintf(3, "NumberE820Entries %08x\n", csm_boot_table->NumberE820Entries);
//    dprintf(3, "HddInfo %08x\n", csm_boot_table->HddInfo);
    dprintf(3, "NumberBbsEntries %08x\n", csm_boot_table->NumberBbsEntries);
    dprintf(3, "BBsTable %08x\n", csm_boot_table->BbsTable);
    dprintf(3, "SmmTable %08x\n", csm_boot_table->SmmTable);
    dprintf(3, "OsMemoryAbove1Mb %08x\n", csm_boot_table->OsMemoryAbove1Mb);
    dprintf(3, "UnconventionalDeviceTable %08x\n", csm_boot_table->UnconventionalDeviceTable);

    regs->ax = 0;
}

/* PrepareToBoot */
static void
handle_csm_0002(struct bregs *regs)
{
    if (!CONFIG_BOOT) {
        regs->ax = 1;
        return;
    }

    dprintf(3, "PrepareToBoot table %04x:%04x\n", regs->es, regs->bx);

    struct e820entry *p = (void *)csm_compat_table.E820Pointer;
    int i;
    for (i=0; i < csm_compat_table.E820Length / sizeof(struct e820entry); i++)
        add_e820(p[i].start, p[i].size, p[i].type);

    if (csm_init_table->HiPmmMemorySizeInBytes > BUILD_MAX_HIGHTABLE) {
        u32 hi_pmm_end = csm_init_table->HiPmmMemory + csm_init_table->HiPmmMemorySizeInBytes;
        add_e820(hi_pmm_end - BUILD_MAX_HIGHTABLE, BUILD_MAX_HIGHTABLE, E820_RESERVED);
    }

    // For PCIBIOS 1ab10e
    if (csm_compat_table.IrqRoutingTablePointer &&
        csm_compat_table.IrqRoutingTableLength) {
        PirAddr = (void *)csm_compat_table.IrqRoutingTablePointer;
        dprintf(3, "CSM PIRQ table at %p\n", PirAddr);
    }

    // For find_resume_vector()... and find_acpi_features()
    if (csm_rsdp.signature == RSDP_SIGNATURE) {
        RsdpAddr = &csm_rsdp;
        dprintf(3, "CSM ACPI RSDP at %p\n", RsdpAddr);

        find_acpi_features();
    }

    // SMBIOS table needs to be copied into the f-seg
    // XX: OVMF doesn't seem to set SmbiosTableLength so don't check it
    if (csm_boot_table->SmbiosTable && !SMBiosAddr)
        copy_smbios((void *)csm_boot_table->SmbiosTable);

    // MPTABLE is just there; we don't care where.

    // EFI may have reinitialised the video using its *own* driver.
    enable_vga_console();

    // EFI fills this in for us. Zero it for now...
    struct bios_data_area_s *bda = MAKE_FLATPTR(SEG_BDA, 0);
    bda->hdcount = 0;

    mathcp_setup();
    timer_setup();
    clock_setup();
    device_hardware_setup();
    wait_threads();
    interactive_bootmenu();

    prepareboot();

    regs->ax = 0;
}

/* Boot */
static void
handle_csm_0003(struct bregs *regs)
{
    if (!CONFIG_BOOT) {
        regs->ax = 1;
        return;
    }

    dprintf(3, "Boot\n");

    startBoot();

    regs->ax = 1;
}

/* Legacy16DispatchOprom */
static void
handle_csm_0005(struct bregs *regs)
{
    EFI_DISPATCH_OPROM_TABLE *table = MAKE_FLATPTR(regs->es, regs->bx);
    struct rom_header *rom;
    u16 bdf;

    if (!CONFIG_OPTIONROMS) {
        regs->ax = 1;
        return;
    }

    dprintf(3, "Legacy16DispatchOprom rom %p\n", table);

    dprintf(3, "OpromSegment   %04x\n", table->OpromSegment);
    dprintf(3, "RuntimeSegment %04x\n", table->RuntimeSegment);
    dprintf(3, "PnPInstallationCheck %04x:%04x\n",
            table->PnPInstallationCheckSegment,
            table->PnPInstallationCheckOffset);
    dprintf(3, "RuntimeSegment %04x\n", table->RuntimeSegment);

    rom = MAKE_FLATPTR(table->OpromSegment, 0);
    bdf = pci_bus_devfn_to_bdf(table->PciBus, table->PciDeviceFunction);

    rom_reserve(rom->size * 512);

    // XX PnP seg/ofs should never be other than default
    callrom(rom, bdf);

    rom_confirm(rom->size * 512);

    regs->bx = 0; // FIXME
    regs->ax = 0;
}

/* Legacy16GetTableAddress */
static void
handle_csm_0006(struct bregs *regs)
{
    u16 size = regs->cx;
    u16 align = regs->dx;
    u16 region = regs->bx; // (1 for F000 seg, 2 for E000 seg, 0 for either)
    void *chunk = NULL;

    if (!region)
        region = 3;

    dprintf(3, "Legacy16GetTableAddress size %x align %x region %d\n",
        size, align, region);

    if (region & 2)
        chunk = _malloc(&ZoneLow, size, align);
    if (!chunk && (region & 1))
        chunk = _malloc(&ZoneFSeg, size, align);

    dprintf(3, "Legacy16GetTableAddress size %x align %x region %d yields %p\n",
        size, align, region, chunk);
    if (chunk) {
        regs->ds = FLATPTR_TO_SEG(chunk);
        regs->bx = FLATPTR_TO_OFFSET(chunk);
        regs->ax = 0;
    } else {
        regs->ax = 1;
    }
}

void VISIBLE32INIT
handle_csm(struct bregs *regs)
{
    ASSERT32FLAT();

    if (!CONFIG_CSM)
        return;

    dprintf(3, "handle_csm regs %p AX=%04x\n", regs, regs->ax);

    pic_irqmask_write(PICMask);

    switch(regs->ax) {
    case 0000: handle_csm_0000(regs); break;
    case 0001: handle_csm_0001(regs); break;
    case 0002: handle_csm_0002(regs); break;
    case 0003: handle_csm_0003(regs); break;
//    case 0004: handle_csm_0004(regs); break;
    case 0005: handle_csm_0005(regs); break;
    case 0006: handle_csm_0006(regs); break;
//    case 0007: handle_csm_0007(regs); break;
//    case 0008: hamdle_csm_0008(regs); break;
    default: regs->al = 1;
    }

    csm_return(regs);
}

int csm_bootprio_ata(struct pci_device *pci, int chanid, int slave)
{
    if (!csm_boot_table)
        return -1;
    BBS_TABLE *bbs = (void *)csm_boot_table->BbsTable;
    int index = 1 + (chanid * 2) + slave;
    dprintf(3, "CSM bootprio for ATA%d,%d (index %d) is %d\n", chanid, slave,
            index, bbs[index].BootPriority);
    return bbs[index].BootPriority;
}

int csm_bootprio_fdc(struct pci_device *pci, int port, int fdid)
{
    if (!csm_boot_table)
        return -1;
    BBS_TABLE *bbs = (void *)csm_boot_table->BbsTable;
    dprintf(3, "CSM bootprio for FDC is %d\n", bbs[0].BootPriority);
    return bbs[0].BootPriority;
}

int csm_bootprio_pci(struct pci_device *pci)
{
    if (!csm_boot_table)
        return -1;
    BBS_TABLE *bbs = (void *)csm_boot_table->BbsTable;
    int i;

    for (i = 5; i < csm_boot_table->NumberBbsEntries; i++) {
        if (pci->bdf == pci_to_bdf(bbs[i].Bus, bbs[i].Device, bbs[i].Function)) {
            dprintf(3, "CSM bootprio for PCI(%d,%d,%d) is %d\n", bbs[i].Bus,
                    bbs[i].Device, bbs[i].Function, bbs[i].BootPriority);
            return bbs[i].BootPriority;
        }
    }
    return -1;
}
