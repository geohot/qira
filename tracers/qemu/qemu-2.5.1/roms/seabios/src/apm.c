// Basic support for apmbios callbacks.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2005 Struan Bartlett
// Copyright (C) 2004 Fabrice Bellard
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "bregs.h" // struct bregs
#include "config.h" // CONFIG_*
#include "output.h" // dprintf
#include "stacks.h" // yield_toirq
#include "util.h" // apm_shutdown
#include "x86.h" // outb

// APM installation check
static void
handle_155300(struct bregs *regs)
{
    regs->ah = 1; // APM major version
    regs->al = 2; // APM minor version
    regs->bh = 'P';
    regs->bl = 'M';
    // bit 0 : 16 bit interface supported
    // bit 1 : 32 bit interface supported
    regs->cx = 0x03;
    set_success(regs);
}

// APM real mode interface connect
static void
handle_155301(struct bregs *regs)
{
    set_success(regs);
}

// APM 16 bit protected mode interface connect
static void
handle_155302(struct bregs *regs)
{
    extern void entry_apm16(void);
    regs->bx = (u32)entry_apm16;
    regs->ax = SEG_BIOS; // 16 bit code segment base
    regs->si = 0xfff0;   // 16 bit code segment size
    regs->cx = SEG_BIOS; // data segment address
    regs->di = 0xfff0;   // data segment length
    set_success(regs);
}

// APM 32 bit protected mode interface connect
static void
handle_155303(struct bregs *regs)
{
    extern void entry_apm32(void);
    regs->ax = SEG_BIOS; // 32 bit code segment base
    regs->ebx = (u32)entry_apm32;
    regs->cx = SEG_BIOS; // 16 bit code segment base
    // 32 bit code segment size (low 16 bits)
    // 16 bit code segment size (high 16 bits)
    regs->esi = 0xfff0fff0;
    regs->dx = SEG_BIOS; // data segment address
    regs->di = 0xfff0; // data segment length
    set_success(regs);
}

// APM interface disconnect
static void
handle_155304(struct bregs *regs)
{
    set_success(regs);
}

// APM cpu idle
static void
handle_155305(struct bregs *regs)
{
    yield_toirq();
    set_success(regs);
}

// APM cpu busy
static void
handle_155306(struct bregs *regs)
{
    set_success(regs);
}

void
apm_shutdown(void)
{
    u16 pm1a_cnt = GET_GLOBAL(acpi_pm1a_cnt);
    if (pm1a_cnt)
        outw(0x2000, pm1a_cnt);

    irq_disable();
    for (;;)
        hlt();
}

// APM Set Power State
static void
handle_155307(struct bregs *regs)
{
    if (regs->bx != 1) {
        set_success(regs);
        return;
    }
    switch (regs->cx) {
    case 1:
        dprintf(1, "APM standby request\n");
        break;
    case 2:
        dprintf(1, "APM suspend request\n");
        break;
    case 3:
        apm_shutdown();
        break;
    }
    set_success(regs);
}

static void
handle_155308(struct bregs *regs)
{
    set_success(regs);
}

// Get Power Status
static void
handle_15530a(struct bregs *regs)
{
    regs->bh = 0x01; // on line
    regs->bl = 0xff; // unknown battery status
    regs->ch = 0x80; // no system battery
    regs->cl = 0xff; // unknown remaining time
    regs->dx = 0xffff; // unknown remaining time
    regs->si = 0x00; // zero battery
    set_success(regs);
}

#define RET_ENOEVENT 0x80

// Get PM Event
static void
handle_15530b(struct bregs *regs)
{
    set_code_invalid_silent(regs, RET_ENOEVENT);
}

// APM Driver Version
static void
handle_15530e(struct bregs *regs)
{
    regs->ah = 1;
    regs->al = 2;
    set_success(regs);
}

// APM Engage / Disengage
static void
handle_15530f(struct bregs *regs)
{
    set_success(regs);
}

// APM Get Capabilities
static void
handle_155310(struct bregs *regs)
{
    regs->bl = 0;
    regs->cx = 0;
    set_success(regs);
}

static void
handle_1553XX(struct bregs *regs)
{
    set_unimplemented(regs);
}

void
handle_1553(struct bregs *regs)
{
    if (! CONFIG_APMBIOS) {
        set_code_invalid(regs, RET_EUNSUPPORTED);
        return;
    }

    //debug_stub(regs);
    switch (regs->al) {
    case 0x00: handle_155300(regs); break;
    case 0x01: handle_155301(regs); break;
    case 0x02: handle_155302(regs); break;
    case 0x03: handle_155303(regs); break;
    case 0x04: handle_155304(regs); break;
    case 0x05: handle_155305(regs); break;
    case 0x06: handle_155306(regs); break;
    case 0x07: handle_155307(regs); break;
    case 0x08: handle_155308(regs); break;
    case 0x0a: handle_15530a(regs); break;
    case 0x0b: handle_15530b(regs); break;
    case 0x0e: handle_15530e(regs); break;
    case 0x0f: handle_15530f(regs); break;
    case 0x10: handle_155310(regs); break;
    default:   handle_1553XX(regs); break;
    }
}

void VISIBLE16 VISIBLE32SEG
handle_apm(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_apm);
    handle_1553(regs);
}
