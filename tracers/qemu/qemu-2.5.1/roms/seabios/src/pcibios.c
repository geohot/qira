// PCI BIOS (int 1a/b1) calls
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "bregs.h" // struct bregs
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_regs.h" // PCI_VENDOR_ID
#include "output.h" // dprintf
#include "std/pirtable.h" // struct pir_header
#include "string.h" // checksum
#include "util.h" // handle_1ab1

// romlayout.S
extern void entry_bios32(void);
extern void entry_pcibios32(void);

#define RET_FUNC_NOT_SUPPORTED 0x81
#define RET_BAD_VENDOR_ID      0x83
#define RET_DEVICE_NOT_FOUND   0x86
#define RET_BUFFER_TOO_SMALL   0x89

// installation check
static void
handle_1ab101(struct bregs *regs)
{
    regs->al = 0x01; // Flags - "Config Mechanism #1" supported.
    regs->bx = 0x0210; // PCI version 2.10
    regs->cl = GET_GLOBAL(MaxPCIBus);
    regs->edx = 0x20494350; // "PCI "
    regs->edi = (u32)entry_pcibios32 + BUILD_BIOS_ADDR;
    set_code_success(regs);
}

// find pci device
static void
handle_1ab102(struct bregs *regs)
{
    u32 id = (regs->cx << 16) | regs->dx;
    int count = regs->si;
    int bus = -1;
    while (bus < GET_GLOBAL(MaxPCIBus)) {
        bus++;
        int bdf;
        foreachbdf(bdf, bus) {
            u32 v = pci_config_readl(bdf, PCI_VENDOR_ID);
            if (v != id)
                continue;
            if (count--)
                continue;
            regs->bx = bdf;
            set_code_success(regs);
            return;
        }
    }
    set_code_invalid(regs, RET_DEVICE_NOT_FOUND);
}

// find class code
static void
handle_1ab103(struct bregs *regs)
{
    int count = regs->si;
    u32 classprog = regs->ecx;
    int bus = -1;
    while (bus < GET_GLOBAL(MaxPCIBus)) {
        bus++;
        int bdf;
        foreachbdf(bdf, bus) {
            u32 v = pci_config_readl(bdf, PCI_CLASS_REVISION);
            if ((v>>8) != classprog)
                continue;
            if (count--)
                continue;
            regs->bx = bdf;
            set_code_success(regs);
            return;
        }
    }
    set_code_invalid(regs, RET_DEVICE_NOT_FOUND);
}

// read configuration byte
static void
handle_1ab108(struct bregs *regs)
{
    regs->cl = pci_config_readb(regs->bx, regs->di);
    set_code_success(regs);
}

// read configuration word
static void
handle_1ab109(struct bregs *regs)
{
    regs->cx = pci_config_readw(regs->bx, regs->di);
    set_code_success(regs);
}

// read configuration dword
static void
handle_1ab10a(struct bregs *regs)
{
    regs->ecx = pci_config_readl(regs->bx, regs->di);
    set_code_success(regs);
}

// write configuration byte
static void
handle_1ab10b(struct bregs *regs)
{
    pci_config_writeb(regs->bx, regs->di, regs->cl);
    set_code_success(regs);
}

// write configuration word
static void
handle_1ab10c(struct bregs *regs)
{
    pci_config_writew(regs->bx, regs->di, regs->cx);
    set_code_success(regs);
}

// write configuration dword
static void
handle_1ab10d(struct bregs *regs)
{
    pci_config_writel(regs->bx, regs->di, regs->ecx);
    set_code_success(regs);
}

// get irq routing options
static void
handle_1ab10e(struct bregs *regs)
{
    struct pir_header *pirtable_gf = GET_GLOBAL(PirAddr);
    if (! pirtable_gf) {
        set_code_invalid(regs, RET_FUNC_NOT_SUPPORTED);
        return;
    }
    struct pir_header *pirtable_g = GLOBALFLAT2GLOBAL(pirtable_gf);

    struct param_s {
        u16 size;
        u16 buf_off;
        u16 buf_seg;
    } *param_far = (void*)(regs->di+0);

    // Validate and update size.
    u16 bufsize = GET_FARVAR(regs->es, param_far->size);
    u16 pirsize = GET_GLOBAL(pirtable_g->size) - sizeof(struct pir_header);
    SET_FARVAR(regs->es, param_far->size, pirsize);
    if (bufsize < pirsize) {
        set_code_invalid(regs, RET_BUFFER_TOO_SMALL);
        return;
    }

    // Get dest buffer.
    void *buf_far = (void*)(GET_FARVAR(regs->es, param_far->buf_off)+0);
    u16 buf_seg = GET_FARVAR(regs->es, param_far->buf_seg);

    // Memcpy pir table slots to dest buffer.
    memcpy_far(buf_seg, buf_far
               , get_global_seg()
               , (void*)(pirtable_g->slots) + get_global_offset()
               , pirsize);

    // XXX - bochs bios sets bx to (1 << 9) | (1 << 11)
    regs->bx = GET_GLOBAL(pirtable_g->exclusive_irqs);
    set_code_success(regs);
}

static void
handle_1ab1XX(struct bregs *regs)
{
    set_code_unimplemented(regs, RET_FUNC_NOT_SUPPORTED);
}

void
handle_1ab1(struct bregs *regs)
{
    //debug_stub(regs);

    if (! CONFIG_PCIBIOS) {
        set_invalid(regs);
        return;
    }

    switch (regs->al) {
    case 0x01: handle_1ab101(regs); break;
    case 0x02: handle_1ab102(regs); break;
    case 0x03: handle_1ab103(regs); break;
    case 0x08: handle_1ab108(regs); break;
    case 0x09: handle_1ab109(regs); break;
    case 0x0a: handle_1ab10a(regs); break;
    case 0x0b: handle_1ab10b(regs); break;
    case 0x0c: handle_1ab10c(regs); break;
    case 0x0d: handle_1ab10d(regs); break;
    case 0x0e: handle_1ab10e(regs); break;
    default:   handle_1ab1XX(regs); break;
    }
}

// Entry point for pci bios functions.
void VISIBLE16 VISIBLE32SEG
handle_pcibios(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_pcibios);
    handle_1ab1(regs);
}


/****************************************************************
 * 32bit interface
 ****************************************************************/

struct bios32_s {
    u32 signature;
    u32 entry;
    u8 version;
    u8 length;
    u8 checksum;
    u8 reserved[5];
} PACKED;

struct bios32_s BIOS32HEADER __aligned(16) VARFSEG = {
    .signature = 0x5f32335f, // _32_
    .length = sizeof(BIOS32HEADER) / 16,
};

void
bios32_init(void)
{
    dprintf(3, "init bios32\n");

    BIOS32HEADER.entry = (u32)entry_bios32;
    BIOS32HEADER.checksum -= checksum(&BIOS32HEADER, sizeof(BIOS32HEADER));
}
