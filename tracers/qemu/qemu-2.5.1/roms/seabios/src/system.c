// Handler for int 0x15 "system" calls
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "bregs.h" // struct bregs
#include "hw/pic.h" // pic_reset
#include "malloc.h" // LegacyRamSize
#include "memmap.h" // E820_RAM
#include "output.h" // debug_enter
#include "string.h" // memcpy_far
#include "util.h" // handle_1553
#include "x86.h" // set_a20

static void
handle_152400(struct bregs *regs)
{
    set_a20(0);
    set_code_success(regs);
}

static void
handle_152401(struct bregs *regs)
{
    set_a20(1);
    set_code_success(regs);
}

static void
handle_152402(struct bregs *regs)
{
    regs->al = get_a20();
    set_code_success(regs);
}

static void
handle_152403(struct bregs *regs)
{
    regs->bx = 3;
    set_code_success(regs);
}

static void
handle_1524XX(struct bregs *regs)
{
    set_code_unimplemented(regs, RET_EUNSUPPORTED);
}

static void
handle_1524(struct bregs *regs)
{
    switch (regs->al) {
    case 0x00: handle_152400(regs); break;
    case 0x01: handle_152401(regs); break;
    case 0x02: handle_152402(regs); break;
    case 0x03: handle_152403(regs); break;
    default:   handle_1524XX(regs); break;
    }
}

// removable media eject
static void
handle_1552(struct bregs *regs)
{
    set_code_success(regs);
}

static void
handle_1587(struct bregs *regs)
{
    // +++ should probably have descriptor checks
    // +++ should have exception handlers

    u8 prev_a20_enable = set_a20(1); // enable A20 line

    // 128K max of transfer on 386+ ???
    // source == destination ???

    // ES:SI points to descriptor table
    // offset   use     initially  comments
    // ==============================================
    // 00..07   Unused  zeros      Null descriptor
    // 08..0f   GDT     zeros      filled in by BIOS
    // 10..17   source  ssssssss   source of data
    // 18..1f   dest    dddddddd   destination of data
    // 20..27   CS      zeros      filled in by BIOS
    // 28..2f   SS      zeros      filled in by BIOS

// check for access rights of source & dest here

    // Initialize GDT descriptor
    u64 *gdt_far = (void*)(regs->si + 0);
    u16 gdt_seg = regs->es;
    u32 loc = (u32)MAKE_FLATPTR(gdt_seg, gdt_far);
    SET_FARVAR(gdt_seg, gdt_far[1], GDT_DATA | GDT_LIMIT((6*sizeof(u64))-1)
               | GDT_BASE(loc));
    // Initialize CS descriptor
    u64 lim = GDT_LIMIT(0x0ffff);
    if (in_post())
        lim = GDT_GRANLIMIT(0xffffffff);
    SET_FARVAR(gdt_seg, gdt_far[4], GDT_CODE | lim | GDT_BASE(BUILD_BIOS_ADDR));
    // Initialize SS descriptor
    loc = (u32)MAKE_FLATPTR(GET_SEG(SS), 0);
    SET_FARVAR(gdt_seg, gdt_far[5], GDT_DATA | lim | GDT_BASE(loc));

    SET_SEG(ES, gdt_seg);
    u16 count = regs->cx, si = 0, di = 0;
    asm volatile(
        // Load new descriptor tables
        "  lgdtw %%es:(1<<3)(%%eax)\n"
        "  lidtw %%cs:pmode_IDT_info\n"

        // Enable protected mode
        "  movl %%cr0, %%eax\n"
        "  orl $" __stringify(CR0_PE) ", %%eax\n"
        "  movl %%eax, %%cr0\n"

        // far jump to flush CPU queue after transition to protected mode
        "  ljmpw $(4<<3), $1f\n"

        // GDT points to valid descriptor table, now load DS, ES
        "1:movw $(2<<3), %%ax\n" // 2nd descriptor in table, TI=GDT, RPL=00
        "  movw %%ax, %%ds\n"
        "  movw $(3<<3), %%ax\n" // 3rd descriptor in table, TI=GDT, RPL=00
        "  movw %%ax, %%es\n"

        // memcpy CX words using 32bit memcpy if applicable
        "  testw $1, %%cx\n"
        "  jnz 3f\n"
        "  shrw $1, %%cx\n"
        "  rep movsl %%ds:(%%si), %%es:(%%di)\n"

        // Restore DS and ES segment limits to 0xffff
        "2:movw $(5<<3), %%ax\n" // 5th descriptor in table (SS)
        "  movw %%ax, %%ds\n"
        "  movw %%ax, %%es\n"

        // Disable protected mode
        "  movl %%cr0, %%eax\n"
        "  andl $~" __stringify(CR0_PE) ", %%eax\n"
        "  movl %%eax, %%cr0\n"

        // far jump to flush CPU queue after transition to real mode
        "  ljmpw $" __stringify(SEG_BIOS) ", $4f\n"

        // Slower 16bit copy method
        "3:rep movsw %%ds:(%%si), %%es:(%%di)\n"
        "  jmp 2b\n"

        // restore IDT to normal real-mode defaults
        "4:lidtw %%cs:rmode_IDT_info\n"

        // Restore %ds (from %ss)
        "  movw %%ss, %%ax\n"
        "  movw %%ax, %%ds\n"
        : "+a" (gdt_far), "+c"(count), "+m" (__segment_ES)
        : "S" (si), "D" (di)
        : "cc");

    set_a20(prev_a20_enable);

    set_code_success(regs);
}

// Get the amount of extended memory (above 1M)
static void
handle_1588(struct bregs *regs)
{
    u32 rs = GET_GLOBAL(LegacyRamSize);

    // According to Ralf Brown's interrupt the limit should be 15M,
    // but real machines mostly return max. 63M.
    if (rs > 64*1024*1024)
        regs->ax = 63 * 1024;
    else
        regs->ax = (rs - 1*1024*1024) / 1024;
    set_success(regs);
}

// Switch to protected mode
void VISIBLE16
handle_1589(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_15);
    set_a20(1);

    pic_reset(regs->bl, regs->bh);

    u64 *gdt_far = (void*)(regs->si + 0);
    u16 gdt_seg = regs->es;
    SET_FARVAR(gdt_seg, gdt_far[7], GDT_CODE | GDT_LIMIT(BUILD_BIOS_SIZE-1)
               | GDT_BASE(BUILD_BIOS_ADDR));

    regs->ds = 3<<3; // 3rd gdt descriptor is %ds
    regs->es = 4<<3; // 4th gdt descriptor is %es
    regs->code.seg = 6<<3; // 6th gdt descriptor is %cs

    set_code_success(regs);

    asm volatile(
        // Load new descriptor tables
        "  lgdtw %%es:(1<<3)(%%si)\n"
        "  lidtw %%es:(2<<3)(%%si)\n"

        // Enable protected mode
        "  movl %%cr0, %%eax\n"
        "  orl $" __stringify(CR0_PE) ", %%eax\n"
        "  movl %%eax, %%cr0\n"

        // far jump to flush CPU queue after transition to protected mode
        "  ljmpw $(7<<3), $1f\n"

        // GDT points to valid descriptor table, now load SS
        "1:movw $(5<<3), %%ax\n"
        "  movw %%ax, %%ds\n"
        "  movw %%ax, %%ss\n"
        :
        : "S"(gdt_far), "m" (__segment_ES)
        : "eax", "cc");
}

// Device busy interrupt.  Called by Int 16h when no key available
static void
handle_1590(struct bregs *regs)
{
}

// Interrupt complete.  Called by Int 16h when key becomes available
static void
handle_1591(struct bregs *regs)
{
}

// keyboard intercept
static void
handle_154f(struct bregs *regs)
{
    set_invalid_silent(regs);
}

static void
handle_15c0(struct bregs *regs)
{
    regs->es = SEG_BIOS;
    regs->bx = (u32)&BIOS_CONFIG_TABLE;
    set_code_success(regs);
}

static void
handle_15c1(struct bregs *regs)
{
    regs->es = get_ebda_seg();
    set_success(regs);
}

static void
handle_15e801(struct bregs *regs)
{
    // my real system sets ax and bx to 0
    // this is confirmed by Ralph Brown list
    // but syslinux v1.48 is known to behave
    // strangely if ax is set to 0
    // regs.u.r16.ax = 0;
    // regs.u.r16.bx = 0;

    u32 rs = GET_GLOBAL(LegacyRamSize);

    // Get the amount of extended memory (above 1M)
    if (rs > 16*1024*1024) {
        // limit to 15M
        regs->cx = 15*1024;
        // Get the amount of extended memory above 16M in 64k blocks
        regs->dx = (rs - 16*1024*1024) / (64*1024);
    } else {
        regs->cx = (rs - 1*1024*1024) / 1024;
        regs->dx = 0;
    }

    // Set configured memory equal to extended memory
    regs->ax = regs->cx;
    regs->bx = regs->dx;

    set_success(regs);
}

static void
handle_15e820(struct bregs *regs)
{
    int count = GET_GLOBAL(e820_count);
    if (regs->edx != 0x534D4150 || regs->bx >= count
        || regs->ecx < sizeof(e820_list[0])) {
        set_code_invalid(regs, RET_EUNSUPPORTED);
        return;
    }

    memcpy_far(regs->es, (void*)(regs->di+0)
               , get_global_seg(), &e820_list[regs->bx]
               , sizeof(e820_list[0]));
    if (regs->bx == count-1)
        regs->ebx = 0;
    else
        regs->ebx++;
    regs->eax = 0x534D4150;
    regs->ecx = sizeof(e820_list[0]);
    set_success(regs);
}

static void
handle_15e8XX(struct bregs *regs)
{
    set_code_unimplemented(regs, RET_EUNSUPPORTED);
}

static void
handle_15e8(struct bregs *regs)
{
    switch (regs->al) {
    case 0x01: handle_15e801(regs); break;
    case 0x20: handle_15e820(regs); break;
    default:   handle_15e8XX(regs); break;
    }
}

static void
handle_15XX(struct bregs *regs)
{
    set_code_unimplemented(regs, RET_EUNSUPPORTED);
}

// INT 15h System Services Entry Point
void VISIBLE16
handle_15(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_15);
    switch (regs->ah) {
    case 0x24: handle_1524(regs); break;
    case 0x4f: handle_154f(regs); break;
    case 0x52: handle_1552(regs); break;
    case 0x53: handle_1553(regs); break;
    case 0x5f: handle_155f(regs); break;
    case 0x7f: handle_157f(regs); break;
    case 0x83: handle_1583(regs); break;
    case 0x86: handle_1586(regs); break;
    case 0x87: handle_1587(regs); break;
    case 0x88: handle_1588(regs); break;
    case 0x90: handle_1590(regs); break;
    case 0x91: handle_1591(regs); break;
    case 0xc0: handle_15c0(regs); break;
    case 0xc1: handle_15c1(regs); break;
    case 0xc2: handle_15c2(regs); break;
    case 0xe8: handle_15e8(regs); break;
    default:   handle_15XX(regs); break;
    }
}
