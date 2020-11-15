// Code for misc 16bit handlers and variables.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "bregs.h" // struct bregs
#include "hw/pic.h" // enable_hwirq
#include "output.h" // debug_enter
#include "stacks.h" // call16_int
#include "string.h" // memset

#define PORT_MATH_CLEAR        0x00f0

// Indicator if POST phase has been started (and if it has completed).
int HaveRunPost VARFSEG;

int
in_post(void)
{
    return GET_GLOBAL(HaveRunPost) == 1;
}


/****************************************************************
 * Misc 16bit ISRs
 ****************************************************************/

// INT 12h Memory Size Service Entry Point
void VISIBLE16
handle_12(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_12);
    regs->ax = GET_BDA(mem_size_kb);
}

// INT 11h Equipment List Service Entry Point
void VISIBLE16
handle_11(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_11);
    regs->ax = GET_BDA(equipment_list_flags);
}

// INT 05h Print Screen Service Entry Point
void VISIBLE16
handle_05(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_05);
}

// INT 10h Video Support Service Entry Point
void VISIBLE16
handle_10(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_10);
    // dont do anything, since the VGA BIOS handles int10h requests
}

// NMI handler
void VISIBLE16
handle_02(void)
{
    debug_isr(DEBUG_ISR_02);
}

void
mathcp_setup(void)
{
    dprintf(3, "math cp init\n");
    // 80x87 coprocessor installed
    set_equipment_flags(0x02, 0x02);
    enable_hwirq(13, FUNC16(entry_75));
}

// INT 75 - IRQ13 - MATH COPROCESSOR EXCEPTION
void VISIBLE16
handle_75(void)
{
    debug_isr(DEBUG_ISR_75);

    // clear irq13
    outb(0, PORT_MATH_CLEAR);
    // clear interrupt
    pic_eoi2();
    // legacy nmi call
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.flags = F_IF;
    call16_int(0x02, &br);
}


/****************************************************************
 * BIOS_CONFIG_TABLE
 ****************************************************************/

// DMA channel 3 used by hard disk BIOS
#define CBT_F1_DMA3USED (1<<7)
// 2nd interrupt controller (8259) installed
#define CBT_F1_2NDPIC   (1<<6)
// Real-Time Clock installed
#define CBT_F1_RTC      (1<<5)
// INT 15/AH=4Fh called upon INT 09h
#define CBT_F1_INT154F  (1<<4)
// wait for external event (INT 15/AH=41h) supported
#define CBT_F1_WAITEXT  (1<<3)
// extended BIOS area allocated (usually at top of RAM)
#define CBT_F1_EBDA     (1<<2)
// bus is Micro Channel instead of ISA
#define CBT_F1_MCA      (1<<1)
// system has dual bus (Micro Channel + ISA)
#define CBT_F1_MCAISA   (1<<0)

// INT 16/AH=09h (keyboard functionality) supported
#define CBT_F2_INT1609  (1<<6)

struct bios_config_table_s BIOS_CONFIG_TABLE VARFSEGFIXED(0xe6f5) = {
    .size     = sizeof(BIOS_CONFIG_TABLE) - 2,
    .model    = BUILD_MODEL_ID,
    .submodel = BUILD_SUBMODEL_ID,
    .biosrev  = BUILD_BIOS_REVISION,
    .feature1 = (
        CBT_F1_2NDPIC | CBT_F1_RTC | CBT_F1_EBDA
        | (CONFIG_KBD_CALL_INT15_4F ? CBT_F1_INT154F : 0)),
    .feature2 = CBT_F2_INT1609,
    .feature3 = 0,
    .feature4 = 0,
    .feature5 = 0,
};


/****************************************************************
 * GDT and IDT tables
 ****************************************************************/

// Real mode IDT descriptor
struct descloc_s rmode_IDT_info VARFSEG = {
    .length = sizeof(struct rmode_IVT) - 1,
    .addr = (u32)MAKE_FLATPTR(SEG_IVT, 0),
};

// Dummy IDT that forces a machine shutdown if an irq happens in
// protected mode.
u8 dummy_IDT VARFSEG;

// Protected mode IDT descriptor
struct descloc_s pmode_IDT_info VARFSEG = {
    .length = sizeof(dummy_IDT) - 1,
    .addr = (u32)&dummy_IDT,
};

// GDT
u64 rombios32_gdt[] VARFSEG __aligned(8) = {
    // First entry can't be used.
    0x0000000000000000LL,
    // 32 bit flat code segment (SEG32_MODE32_CS)
    GDT_GRANLIMIT(0xffffffff) | GDT_CODE | GDT_B,
    // 32 bit flat data segment (SEG32_MODE32_DS)
    GDT_GRANLIMIT(0xffffffff) | GDT_DATA | GDT_B,
    // 16 bit code segment base=0xf0000 limit=0xffff (SEG32_MODE16_CS)
    GDT_LIMIT(BUILD_BIOS_SIZE-1) | GDT_CODE | GDT_BASE(BUILD_BIOS_ADDR),
    // 16 bit data segment base=0x0 limit=0xffff (SEG32_MODE16_DS)
    GDT_LIMIT(0x0ffff) | GDT_DATA,
    // 16 bit code segment base=0xf0000 limit=0xffffffff (SEG32_MODE16BIG_CS)
    GDT_GRANLIMIT(0xffffffff) | GDT_CODE | GDT_BASE(BUILD_BIOS_ADDR),
    // 16 bit data segment base=0 limit=0xffffffff (SEG32_MODE16BIG_DS)
    GDT_GRANLIMIT(0xffffffff) | GDT_DATA,
};

// GDT descriptor
struct descloc_s rombios32_gdt_48 VARFSEG = {
    .length = sizeof(rombios32_gdt) - 1,
    .addr = (u32)rombios32_gdt,
};


/****************************************************************
 * Misc fixed vars
 ****************************************************************/

// BIOS build date
char BiosDate[] VARFSEGFIXED(0xfff5) = "06/23/99";

u8 BiosModelId VARFSEGFIXED(0xfffe) = BUILD_MODEL_ID;

u8 BiosChecksum VARFSEGFIXED(0xffff);

struct floppy_dbt_s diskette_param_table VARFSEGFIXED(0xefc7);

// Old Fixed Disk Parameter Table (newer tables are in the ebda).
struct fdpt_s OldFDPT VARFSEGFIXED(0xe401);

// XXX - Baud Rate Generator Table
u8 BaudTable[16] VARFSEGFIXED(0xe729);

// XXX - Initial Interrupt Vector Offsets Loaded by POST
u8 InitVectors[13] VARFSEGFIXED(0xfef3);

// XXX - INT 1D - SYSTEM DATA - VIDEO PARAMETER TABLES
u8 VideoParams[88] VARFSEGFIXED(0xf0a4);
