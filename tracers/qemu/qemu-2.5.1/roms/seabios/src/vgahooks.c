// Hooks for via vgabios calls into main bios.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "bregs.h" // set_code_invalid
#include "config.h" // CONFIG_*
#include "hw/pci.h" // pci_find_device
#include "hw/pci_ids.h" // PCI_VENDOR_ID_VIA
#include "hw/pci_regs.h" // PCI_VENDOR_ID
#include "output.h" // dprintf
#include "string.h" // strcmp
#include "util.h" // handle_155f, handle_157f

#define VH_VIA 1
#define VH_INTEL 2
#define VH_SMI 3

int VGAHookHandlerType VARFSEG;

static void
handle_155fXX(struct bregs *regs)
{
    set_code_unimplemented(regs, RET_EUNSUPPORTED);
}

static void
handle_157fXX(struct bregs *regs)
{
    set_code_unimplemented(regs, RET_EUNSUPPORTED);
}

/****************************************************************
 * Via hooks
 ****************************************************************/

int ViaFBsize VARFSEG, ViaRamSpeed VARFSEG;

static void
via_155f01(struct bregs *regs)
{
    regs->eax = 0x5f;
    regs->cl = 2; // panel type =  2 = 1024 * 768
    set_success(regs);
    dprintf(1, "Warning: VGA panel type is hardcoded\n");
}

static void
via_155f02(struct bregs *regs)
{
    regs->eax = 0x5f;
    regs->bx = 2;
    regs->cx = 0x401;  // PAL + crt only
    regs->dx = 0;  // TV Layout - default
    set_success(regs);
    dprintf(1, "Warning: VGA TV/CRT output type is hardcoded\n");
}

static void
via_155f18(struct bregs *regs)
{
    int fbsize = GET_GLOBAL(ViaFBsize), ramspeed = GET_GLOBAL(ViaRamSpeed);
    if (fbsize < 0 || ramspeed < 0) {
        set_code_invalid(regs, RET_EUNSUPPORTED);
        return;
    }
    regs->eax = 0x5f;
    regs->ebx = 0x500 | (ramspeed << 4) | fbsize;
    regs->ecx = 0x060;
    set_success(regs);
}

static void
via_155f19(struct bregs *regs)
{
    set_invalid_silent(regs);
}

static void
via_155f(struct bregs *regs)
{
    switch (regs->al) {
    case 0x01: via_155f01(regs); break;
    case 0x02: via_155f02(regs); break;
    case 0x18: via_155f18(regs); break;
    case 0x19: via_155f19(regs); break;
    default:   handle_155fXX(regs); break;
    }
}

static int
getFBSize(struct pci_device *pci)
{
    /* FB config */
    u8 reg = pci_config_readb(pci->bdf, 0xa1);

    /* GFX disabled ? */
    if (!(reg & 0x80))
        return -1;

    static u8 mem_power[] = {0, 3, 4, 5, 6, 7, 8, 9};
    return mem_power[(reg >> 4) & 0x7];
}

static int
getViaRamSpeed(struct pci_device *pci)
{
    return (pci_config_readb(pci->bdf, 0x90) & 0x07) + 3;
}

static int
getAMDRamSpeed(void)
{
    struct pci_device *pci = pci_find_device(PCI_VENDOR_ID_AMD
                                             , PCI_DEVICE_ID_AMD_K8_NB_MEMCTL);
    if (!pci)
        return -1;

    /* mem clk 0 = DDR2 400 */
    return (pci_config_readb(pci->bdf, 0x94) & 0x7) + 6;
}

/* int 0x15 - 5f18

   ECX = unknown/dont care
   EBX[3..0] Frame Buffer Size 2^N MiB
   EBX[7..4] Memory speed:
       0: SDR  66Mhz
       1: SDR 100Mhz
       2: SDR 133Mhz
       3: DDR 100Mhz (PC1600 or DDR200)
       4: DDR 133Mhz (PC2100 or DDR266)
       5: DDR 166Mhz (PC2700 or DDR333)
       6: DDR 200Mhz (PC3200 or DDR400)
       7: DDR2 133Mhz (DDR2 533)
       8: DDR2 166Mhz (DDR2 667)
       9: DDR2 200Mhz (DDR2 800)
       A: DDR2 233Mhz (DDR2 1066)
       B: and above: Unknown
   EBX[?..8] Total memory size?
   EAX = 0x5f for success
*/

#define PCI_DEVICE_ID_VIA_K8M890CE_3    0x3336
#define PCI_DEVICE_ID_VIA_VX855_MEMCTRL 0x3409

static void
via_setup(struct pci_device *pci)
{
    VGAHookHandlerType = VH_VIA;

    struct pci_device *d = pci_find_device(PCI_VENDOR_ID_VIA
                                           , PCI_DEVICE_ID_VIA_K8M890CE_3);
    if (d) {
        ViaFBsize = getFBSize(d);
        ViaRamSpeed = getAMDRamSpeed();
        return;
    }
    d = pci_find_device(PCI_VENDOR_ID_VIA, PCI_DEVICE_ID_VIA_VX855_MEMCTRL);
    if (d) {
        ViaFBsize = getFBSize(d);
        ViaRamSpeed = getViaRamSpeed(d);
        return;
    }

    dprintf(1, "Warning: VGA memory size and speed is hardcoded\n");
    ViaFBsize = 5; // 32M frame buffer
    ViaRamSpeed = 4; // MCLK = DDR266
}


/****************************************************************
 * Intel VGA hooks
 ****************************************************************/

u8 IntelDisplayType VARFSEG, IntelDisplayId VARFSEG;

static void
intel_155f35(struct bregs *regs)
{
    regs->ax = 0x005f;
    regs->cl = GET_GLOBAL(IntelDisplayType);
    set_success(regs);
}

static void
intel_155f40(struct bregs *regs)
{
    regs->ax = 0x005f;
    regs->cl = GET_GLOBAL(IntelDisplayId);
    set_success(regs);
}

static void
intel_155f50(struct bregs *regs)
{
    /* Mandatory hook on some Dell laptops */
    regs->ax = 0x005f;
    set_success(regs);
}

static void
intel_155f(struct bregs *regs)
{
    switch (regs->al) {
    case 0x35: intel_155f35(regs); break;
    case 0x40: intel_155f40(regs); break;
    case 0x50: intel_155f50(regs); break;
    default:   handle_155fXX(regs); break;
    }
}

#define BOOT_DISPLAY_DEFAULT    (0)
#define BOOT_DISPLAY_CRT        (1 << 0)
#define BOOT_DISPLAY_TV         (1 << 1)
#define BOOT_DISPLAY_EFP        (1 << 2)
#define BOOT_DISPLAY_LCD        (1 << 3)
#define BOOT_DISPLAY_CRT2       (1 << 4)
#define BOOT_DISPLAY_TV2        (1 << 5)
#define BOOT_DISPLAY_EFP2       (1 << 6)
#define BOOT_DISPLAY_LCD2       (1 << 7)

static void
intel_setup(struct pci_device *pci)
{
    VGAHookHandlerType = VH_INTEL;

    IntelDisplayType = BOOT_DISPLAY_DEFAULT;
    IntelDisplayId = 3;
}

static void
roda_setup(struct pci_device *pci)
{
    VGAHookHandlerType = VH_INTEL;
    // IntelDisplayType = BOOT_DISPLAY_DEFAULT;
    IntelDisplayType = BOOT_DISPLAY_LCD;
    // IntelDisplayId = inb(0x60f) & 0x0f; // Correct according to Crete
    IntelDisplayId = 3; // Correct according to empirical studies
}

static void
kontron_setup(struct pci_device *pci)
{
    VGAHookHandlerType = VH_INTEL;
    IntelDisplayType = BOOT_DISPLAY_CRT;
    IntelDisplayId = 3;
}

static void
getac_setup(struct pci_device *pci)
{
}

/****************************************************************
 * Silicon Motion hooks
 ****************************************************************/

u8 SmiBootDisplay VARFSEG; // 1: LCD, 2: CRT, 3: Both */

static void
smi_157f02(struct bregs *regs)
{
    /* Boot Display Device Override */
    regs->ax = 0x007f;
    regs->bl = GET_GLOBAL(SmiBootDisplay);
    set_success(regs);
}

static void
smi_157f14(struct bregs *regs)
{
    /* ReduceOn support default status */
    regs->ax = 0x007f;
    regs->bl = 0x00;
    set_success(regs);
}

static void
smi_157f(struct bregs *regs)
{
    switch (regs->al) {
    case 0x02: smi_157f02(regs); break;
    case 0x14: smi_157f14(regs); break;
    default:   handle_157fXX(regs); break;
    }
}

static void
winent_mb6047_setup(struct pci_device *pci)
{
    VGAHookHandlerType = VH_SMI;
    SmiBootDisplay = 0x02;
}

/****************************************************************
 * Entry and setup
 ****************************************************************/

// Main 16bit entry point
void
handle_155f(struct bregs *regs)
{
    if (!CONFIG_VGAHOOKS) {
        handle_155fXX(regs);
        return;
    }

    int htype = GET_GLOBAL(VGAHookHandlerType);
    switch (htype) {
    case VH_VIA:   via_155f(regs); break;
    case VH_INTEL: intel_155f(regs); break;
    default:       handle_155fXX(regs); break;
    }
}

// Main 16bit entry point
void
handle_157f(struct bregs *regs)
{
    if (!CONFIG_VGAHOOKS) {
        handle_157fXX(regs);
        return;
    }

    int htype = GET_GLOBAL(VGAHookHandlerType);
    switch (htype) {
    case VH_SMI:   smi_157f(regs); break;
    default:       handle_157fXX(regs); break;
    }
}

// Setup
void
vgahook_setup(struct pci_device *pci)
{
    if (!CONFIG_VGAHOOKS)
        return;

    if (strcmp(CBvendor, "KONTRON") == 0 && strcmp(CBpart, "986LCD-M") == 0)
        kontron_setup(pci);
    else if (strcmp(CBvendor, "GETAC") == 0 && strcmp(CBpart, "P470") == 0)
        getac_setup(pci);
    else if (strcmp(CBvendor, "RODA") == 0 && strcmp(CBpart, "RK886EX") == 0)
        roda_setup(pci);
    else if (strcmp(CBvendor, "Win Enterprise") == 0 && strcmp(CBpart, "MB6047") == 0)
        winent_mb6047_setup(pci);
    else if (pci->vendor == PCI_VENDOR_ID_VIA)
        via_setup(pci);
    else if (pci->vendor == PCI_VENDOR_ID_INTEL)
        intel_setup(pci);
}
