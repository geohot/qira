//  QEMU Cirrus CLGD 54xx VGABIOS Extension.
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
//  Copyright (c) 2004 Makoto Suzuki (suzu)
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "bregs.h" // struct bregs
#include "clext.h" // clext_setup
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_regs.h" // PCI_BASE_ADDRESS_0
#include "output.h" // dprintf
#include "stdvga.h" // VGAREG_SEQU_ADDRESS
#include "string.h" // memset16_far
#include "vgabios.h" // VBE_VENDOR_STRING


/****************************************************************
 * Cirrus mode tables
 ****************************************************************/

/* VGA */
static u16 cseq_vga[] VAR16 = {0x0007,0xffff};
static u16 cgraph_vga[] VAR16 = {0x0009,0x000a,0x000b,0xffff};
static u16 ccrtc_vga[] VAR16 = {0x001a,0x001b,0x001d,0xffff};

/* extensions */
static u16 cgraph_svgacolor[] VAR16 = {
    0x0000,0x0001,0x0002,0x0003,0x0004,0x4005,0x0506,0x0f07,0xff08,
    0x0009,0x000a,0x000b,
    0xffff
};
/* 640x480x8 */
static u16 cseq_640x480x8[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1107,
    0x580b,0x580c,0x580d,0x580e,
    0x0412,0x0013,0x2017,
    0x331b,0x331c,0x331d,0x331e,
    0xffff
};
static u16 ccrtc_640x480x8[] VAR16 = {
    0x2c11,
    0x5f00,0x4f01,0x4f02,0x8003,0x5204,0x1e05,0x0b06,0x3e07,
    0x4009,0x000c,0x000d,
    0xea10,0xdf12,0x5013,0x4014,0xdf15,0x0b16,0xc317,0xff18,
    0x001a,0x221b,0x001d,
    0xffff
};
/* 640x480x16 */
static u16 cseq_640x480x16[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1707,
    0x580b,0x580c,0x580d,0x580e,
    0x0412,0x0013,0x2017,
    0x331b,0x331c,0x331d,0x331e,
    0xffff
};
static u16 ccrtc_640x480x16[] VAR16 = {
    0x2c11,
    0x5f00,0x4f01,0x4f02,0x8003,0x5204,0x1e05,0x0b06,0x3e07,
    0x4009,0x000c,0x000d,
    0xea10,0xdf12,0xa013,0x4014,0xdf15,0x0b16,0xc317,0xff18,
    0x001a,0x221b,0x001d,
    0xffff
};
/* 640x480x24 */
static u16 cseq_640x480x24[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1507,
    0x580b,0x580c,0x580d,0x580e,
    0x0412,0x0013,0x2017,
    0x331b,0x331c,0x331d,0x331e,
    0xffff
};
static u16 ccrtc_640x480x24[] VAR16 = {
    0x2c11,
    0x5f00,0x4f01,0x4f02,0x8003,0x5204,0x1e05,0x0b06,0x3e07,
    0x4009,0x000c,0x000d,
    0xea10,0xdf12,0xf013,0x4014,0xdf15,0x0b16,0xc317,0xff18,
    0x001a,0x221b,0x001d,
    0xffff
};
/* 800x600x8 */
static u16 cseq_800x600x8[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1107,
    0x230b,0x230c,0x230d,0x230e,
    0x0412,0x0013,0x2017,
    0x141b,0x141c,0x141d,0x141e,
    0xffff
};
static u16 ccrtc_800x600x8[] VAR16 = {
    0x2311,0x7d00,0x6301,0x6302,0x8003,0x6b04,0x1a05,0x9806,0xf007,
    0x6009,0x000c,0x000d,
    0x7d10,0x5712,0x6413,0x4014,0x5715,0x9816,0xc317,0xff18,
    0x001a,0x221b,0x001d,
    0xffff
};
/* 800x600x16 */
static u16 cseq_800x600x16[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1707,
    0x230b,0x230c,0x230d,0x230e,
    0x0412,0x0013,0x2017,
    0x141b,0x141c,0x141d,0x141e,
    0xffff
};
static u16 ccrtc_800x600x16[] VAR16 = {
    0x2311,0x7d00,0x6301,0x6302,0x8003,0x6b04,0x1a05,0x9806,0xf007,
    0x6009,0x000c,0x000d,
    0x7d10,0x5712,0xc813,0x4014,0x5715,0x9816,0xc317,0xff18,
    0x001a,0x221b,0x001d,
    0xffff
};
/* 800x600x24 */
static u16 cseq_800x600x24[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1507,
    0x230b,0x230c,0x230d,0x230e,
    0x0412,0x0013,0x2017,
    0x141b,0x141c,0x141d,0x141e,
    0xffff
};
static u16 ccrtc_800x600x24[] VAR16 = {
    0x2311,0x7d00,0x6301,0x6302,0x8003,0x6b04,0x1a05,0x9806,0xf007,
    0x6009,0x000c,0x000d,
    0x7d10,0x5712,0x2c13,0x4014,0x5715,0x9816,0xc317,0xff18,
    0x001a,0x321b,0x001d,
    0xffff
};
/* 1024x768x8 */
static u16 cseq_1024x768x8[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1107,
    0x760b,0x760c,0x760d,0x760e,
    0x0412,0x0013,0x2017,
    0x341b,0x341c,0x341d,0x341e,
    0xffff
};
static u16 ccrtc_1024x768x8[] VAR16 = {
    0x2911,0xa300,0x7f01,0x7f02,0x8603,0x8304,0x9405,0x2406,0xf507,
    0x6009,0x000c,0x000d,
    0x0310,0xff12,0x8013,0x4014,0xff15,0x2416,0xc317,0xff18,
    0x001a,0x221b,0x001d,
    0xffff
};
/* 1024x768x16 */
static u16 cseq_1024x768x16[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1707,
    0x760b,0x760c,0x760d,0x760e,
    0x0412,0x0013,0x2017,
    0x341b,0x341c,0x341d,0x341e,
    0xffff
};
static u16 ccrtc_1024x768x16[] VAR16 = {
    0x2911,0xa300,0x7f01,0x7f02,0x8603,0x8304,0x9405,0x2406,0xf507,
    0x6009,0x000c,0x000d,
    0x0310,0xff12,0x0013,0x4014,0xff15,0x2416,0xc317,0xff18,
    0x001a,0x321b,0x001d,
    0xffff
};
/* 1024x768x24 */
static u16 cseq_1024x768x24[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1507,
    0x760b,0x760c,0x760d,0x760e,
    0x0412,0x0013,0x2017,
    0x341b,0x341c,0x341d,0x341e,
    0xffff
};
static u16 ccrtc_1024x768x24[] VAR16 = {
    0x2911,0xa300,0x7f01,0x7f02,0x8603,0x8304,0x9405,0x2406,0xf507,
    0x6009,0x000c,0x000d,
    0x0310,0xff12,0x8013,0x4014,0xff15,0x2416,0xc317,0xff18,
    0x001a,0x321b,0x001d,
    0xffff
};
/* 1280x1024x8 */
static u16 cseq_1280x1024x8[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1107,
    0x760b,0x760c,0x760d,0x760e,
    0x0412,0x0013,0x2017,
    0x341b,0x341c,0x341d,0x341e,
    0xffff
};
static u16 ccrtc_1280x1024x8[] VAR16 = {
    0x2911,0xc300,0x9f01,0x9f02,0x8603,0x8304,0x9405,0x2406,0xf707,
    0x6009,0x000c,0x000d,
    0x0310,0xff12,0xa013,0x4014,0xff15,0x2416,0xc317,0xff18,
    0x001a,0x221b,0x001d,
    0xffff
};
/* 1280x1024x16 */
static u16 cseq_1280x1024x16[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1707,
    0x760b,0x760c,0x760d,0x760e,
    0x0412,0x0013,0x2017,
    0x341b,0x341c,0x341d,0x341e,
    0xffff
};
static u16 ccrtc_1280x1024x16[] VAR16 = {
    0x2911,0xc300,0x9f01,0x9f02,0x8603,0x8304,0x9405,0x2406,0xf707,
    0x6009,0x000c,0x000d,
    0x0310,0xff12,0x4013,0x4014,0xff15,0x2416,0xc317,0xff18,
    0x001a,0x321b,0x001d,
    0xffff
};

/* 1600x1200x8 */
static u16 cseq_1600x1200x8[] VAR16 = {
    0x0300,0x2101,0x0f02,0x0003,0x0e04,0x1107,
    0x760b,0x760c,0x760d,0x760e,
    0x0412,0x0013,0x2017,
    0x341b,0x341c,0x341d,0x341e,
    0xffff
};
static u16 ccrtc_1600x1200x8[] VAR16 = {
    0x2911,0xc300,0x9f01,0x9f02,0x8603,0x8304,0x9405,0x2406,0xf707,
    0x6009,0x000c,0x000d,
    0x0310,0xff12,0xc813,0x4014,0xff15,0x2416,0xc317,0xff18,
    0x001a,0x221b,0x001d,
    0xffff
};

struct cirrus_mode_s {
    u16 mode, vesamode;
    struct vgamode_s info;

    u16 hidden_dac; /* 0x3c6 */
    u16 *seq; /* 0x3c4 */
    u16 *graph; /* 0x3ce */
    u16 *crtc; /* 0x3d4 */
};

static struct cirrus_mode_s cirrus_modes[] VAR16 = {
    {0x5f,0x101,{MM_PACKED,640,480,8,8,16,SEG_GRAPH},0x00,
     cseq_640x480x8,cgraph_svgacolor,ccrtc_640x480x8},
    {0x64,0x111,{MM_DIRECT,640,480,16,8,16,SEG_GRAPH},0xe1,
     cseq_640x480x16,cgraph_svgacolor,ccrtc_640x480x16},
    {0x66,0x110,{MM_DIRECT,640,480,15,8,16,SEG_GRAPH},0xf0,
     cseq_640x480x16,cgraph_svgacolor,ccrtc_640x480x16},
    {0x71,0x112,{MM_DIRECT,640,480,24,8,16,SEG_GRAPH},0xe5,
     cseq_640x480x24,cgraph_svgacolor,ccrtc_640x480x24},

    {0x5c,0x103,{MM_PACKED,800,600,8,8,16,SEG_GRAPH},0x00,
     cseq_800x600x8,cgraph_svgacolor,ccrtc_800x600x8},
    {0x65,0x114,{MM_DIRECT,800,600,16,8,16,SEG_GRAPH},0xe1,
     cseq_800x600x16,cgraph_svgacolor,ccrtc_800x600x16},
    {0x67,0x113,{MM_DIRECT,800,600,15,8,16,SEG_GRAPH},0xf0,
     cseq_800x600x16,cgraph_svgacolor,ccrtc_800x600x16},

    {0x60,0x105,{MM_PACKED,1024,768,8,8,16,SEG_GRAPH},0x00,
     cseq_1024x768x8,cgraph_svgacolor,ccrtc_1024x768x8},
    {0x74,0x117,{MM_DIRECT,1024,768,16,8,16,SEG_GRAPH},0xe1,
     cseq_1024x768x16,cgraph_svgacolor,ccrtc_1024x768x16},
    {0x68,0x116,{MM_DIRECT,1024,768,15,8,16,SEG_GRAPH},0xf0,
     cseq_1024x768x16,cgraph_svgacolor,ccrtc_1024x768x16},

    {0x78,0x115,{MM_DIRECT,800,600,24,8,16,SEG_GRAPH},0xe5,
     cseq_800x600x24,cgraph_svgacolor,ccrtc_800x600x24},
    {0x79,0x118,{MM_DIRECT,1024,768,24,8,16,SEG_GRAPH},0xe5,
     cseq_1024x768x24,cgraph_svgacolor,ccrtc_1024x768x24},

    {0x6d,0x107,{MM_PACKED,1280,1024,8,8,16,SEG_GRAPH},0x00,
     cseq_1280x1024x8,cgraph_svgacolor,ccrtc_1280x1024x8},
    {0x69,0x119,{MM_DIRECT,1280,1024,15,8,16,SEG_GRAPH},0xf0,
     cseq_1280x1024x16,cgraph_svgacolor,ccrtc_1280x1024x16},
    {0x75,0x11a,{MM_DIRECT,1280,1024,16,8,16,SEG_GRAPH},0xe1,
     cseq_1280x1024x16,cgraph_svgacolor,ccrtc_1280x1024x16},

    {0x7b,0xffff,{MM_PACKED,1600,1200,8,8,16,SEG_GRAPH},0x00,
     cseq_1600x1200x8,cgraph_svgacolor,ccrtc_1600x1200x8},
};

static struct cirrus_mode_s mode_switchback VAR16 =
    {0xfe,0xffff,{0xff},0,cseq_vga,cgraph_vga,ccrtc_vga};

int
is_cirrus_mode(struct vgamode_s *vmode_g)
{
    return (vmode_g >= &cirrus_modes[0].info
            && vmode_g <= &cirrus_modes[ARRAY_SIZE(cirrus_modes)-1].info);
}

struct vgamode_s *
clext_find_mode(int mode)
{
    struct cirrus_mode_s *table_g = cirrus_modes;
    while (table_g < &cirrus_modes[ARRAY_SIZE(cirrus_modes)]) {
        if (GET_GLOBAL(table_g->mode) == mode
            || GET_GLOBAL(table_g->vesamode) == mode)
            return &table_g->info;
        table_g++;
    }
    return stdvga_find_mode(mode);
}

void
clext_list_modes(u16 seg, u16 *dest, u16 *last)
{
    int i;
    for (i=0; i<ARRAY_SIZE(cirrus_modes) && dest<last; i++) {
        u16 mode = GET_GLOBAL(cirrus_modes[i].vesamode);
        if (mode == 0xffff)
            continue;
        SET_FARVAR(seg, *dest, mode);
        dest++;
    }
    stdvga_list_modes(seg, dest, last);
}


/****************************************************************
 * helper functions
 ****************************************************************/

int
clext_get_window(struct vgamode_s *vmode_g, int window)
{
    return stdvga_grdc_read(window + 9);
}

int
clext_set_window(struct vgamode_s *vmode_g, int window, int val)
{
    if (val >= 0x100)
        return -1;
    stdvga_grdc_write(window + 9, val);
    return 0;
}

int
clext_get_linelength(struct vgamode_s *vmode_g)
{
    u16 crtc_addr = stdvga_get_crtc();
    u8 reg13 = stdvga_crtc_read(crtc_addr, 0x13);
    u8 reg1b = stdvga_crtc_read(crtc_addr, 0x1b);
    return (((reg1b & 0x10) << 4) + reg13) * 8 / stdvga_vram_ratio(vmode_g);
}

int
clext_set_linelength(struct vgamode_s *vmode_g, int val)
{
    u16 crtc_addr = stdvga_get_crtc();
    val = DIV_ROUND_UP(val * stdvga_vram_ratio(vmode_g), 8);
    stdvga_crtc_write(crtc_addr, 0x13, val);
    stdvga_crtc_mask(crtc_addr, 0x1b, 0x10, (val & 0x100) >> 4);
    return 0;
}

int
clext_get_displaystart(struct vgamode_s *vmode_g)
{
    u16 crtc_addr = stdvga_get_crtc();
    u8 b2 = stdvga_crtc_read(crtc_addr, 0x0c);
    u8 b1 = stdvga_crtc_read(crtc_addr, 0x0d);
    u8 b3 = stdvga_crtc_read(crtc_addr, 0x1b);
    u8 b4 = stdvga_crtc_read(crtc_addr, 0x1d);
    int val = (b1 | (b2<<8) | ((b3 & 0x01) << 16) | ((b3 & 0x0c) << 15)
               | ((b4 & 0x80) << 12));
    return val * 4 / stdvga_vram_ratio(vmode_g);
}

int
clext_set_displaystart(struct vgamode_s *vmode_g, int val)
{
    u16 crtc_addr = stdvga_get_crtc();
    val = val * stdvga_vram_ratio(vmode_g) / 4;
    stdvga_crtc_write(crtc_addr, 0x0d, val);
    stdvga_crtc_write(crtc_addr, 0x0c, val >> 8);
    stdvga_crtc_mask(crtc_addr, 0x1d, 0x80, (val & 0x0800) >> 4);
    stdvga_crtc_mask(crtc_addr, 0x1b, 0x0d
                     , ((val & 0x0100) >> 8) | ((val & 0x0600) >> 7));
    return 0;
}

int
clext_save_restore(int cmd, u16 seg, void *data)
{
    if (cmd & SR_REGISTERS)
        return -1;
    return stdvga_save_restore(cmd, seg, data);
}


/****************************************************************
 * Mode setting
 ****************************************************************/

static void
cirrus_switch_mode_setregs(u16 *data, u16 port)
{
    for (;;) {
        u16 val = GET_GLOBAL(*data);
        if (val == 0xffff)
            return;
        outw(val, port);
        data++;
    }
}

static void
cirrus_switch_mode(struct cirrus_mode_s *table)
{
    // Unlock cirrus special
    stdvga_sequ_write(0x06, 0x12);
    cirrus_switch_mode_setregs(GET_GLOBAL(table->seq), VGAREG_SEQU_ADDRESS);
    cirrus_switch_mode_setregs(GET_GLOBAL(table->graph), VGAREG_GRDC_ADDRESS);
    cirrus_switch_mode_setregs(GET_GLOBAL(table->crtc), stdvga_get_crtc());

    stdvga_pelmask_write(0x00);
    stdvga_pelmask_read();
    stdvga_pelmask_read();
    stdvga_pelmask_read();
    stdvga_pelmask_read();
    stdvga_pelmask_write(GET_GLOBAL(table->hidden_dac));
    stdvga_pelmask_write(0xff);

    u8 memmodel = GET_GLOBAL(table->info.memmodel);
    u8 on = 0;
    if (memmodel == MM_PLANAR)
        on = 0x41;
    else if (memmodel != MM_TEXT)
        on = 0x01;
    stdvga_attr_mask(0x10, 0x01, on);
    stdvga_attrindex_write(0x20);
}

static void
cirrus_enable_16k_granularity(void)
{
    stdvga_grdc_mask(0x0b, 0x00, 0x20);
}

static void
cirrus_clear_vram(u16 fill)
{
    cirrus_enable_16k_granularity();
    int count = GET_GLOBAL(VBE_total_memory) / (16 * 1024);
    int i;
    for (i=0; i<count; i++) {
        stdvga_grdc_write(0x09, i);
        memset16_far(SEG_GRAPH, 0, fill, 16 * 1024);
    }
    stdvga_grdc_write(0x09, 0x00);
}

int
clext_set_mode(struct vgamode_s *vmode_g, int flags)
{
    if (!is_cirrus_mode(vmode_g)) {
        cirrus_switch_mode(&mode_switchback);
        dprintf(1, "cirrus mode switch regular\n");
        return stdvga_set_mode(vmode_g, flags);
    }
    struct cirrus_mode_s *table_g = container_of(
        vmode_g, struct cirrus_mode_s, info);
    cirrus_switch_mode(table_g);
    if (GET_GLOBAL(vmode_g->memmodel) == MM_PACKED && !(flags & MF_NOPALETTE))
        stdvga_set_packed_palette();
    if (!(flags & MF_LINEARFB))
        cirrus_enable_16k_granularity();
    if (!(flags & MF_NOCLEARMEM))
        // fill with 0xff to keep win 2K happy
        cirrus_clear_vram(flags & MF_LEGACY ? 0xffff : 0x0000);
    return 0;
}


/****************************************************************
 * extbios
 ****************************************************************/

static void
clext_101280(struct bregs *regs)
{
    u8 v = stdvga_crtc_read(stdvga_get_crtc(), 0x27);
    if (v == 0xa0)
        // 5430
        regs->ax = 0x0032;
    else if (v == 0xb8)
        // 5446
        regs->ax = 0x0039;
    else
        regs->ax = 0x00ff;
    regs->bx = 0x00;
    return;
}

static void
clext_101281(struct bregs *regs)
{
    // XXX
    regs->ax = 0x0100;
}

static void
clext_101282(struct bregs *regs)
{
    regs->al = stdvga_crtc_read(stdvga_get_crtc(), 0x27) & 0x03;
    regs->ah = 0xAF;
}

static void
clext_101285(struct bregs *regs)
{
    regs->al = GET_GLOBAL(VBE_total_memory) / (64*1024);
}

static void
clext_10129a(struct bregs *regs)
{
    regs->ax = 0x4060;
    regs->cx = 0x1132;
}

extern void a0h_callback(void);
ASM16(
    // fatal: not implemented yet
    "a0h_callback:"
    "cli\n"
    "hlt\n"
    "lretw");

static void
clext_1012a0(struct bregs *regs)
{
    struct vgamode_s *table_g = clext_find_mode(regs->al & 0x7f);
    regs->ah = (table_g ? 1 : 0);
    regs->bx = (u32)a0h_callback;
    regs->ds = regs->si = regs->es = regs->di = 0xffff;
}

static void
clext_1012a1(struct bregs *regs)
{
    regs->bx = 0x0e00; // IBM 8512/8513, color
}

static void
clext_1012a2(struct bregs *regs)
{
    regs->al = 0x07; // HSync 31.5 - 64.0 kHz
}

static void
clext_1012ae(struct bregs *regs)
{
    regs->al = 0x01; // High Refresh 75Hz
}

static void
clext_1012XX(struct bregs *regs)
{
    debug_stub(regs);
}

void
clext_1012(struct bregs *regs)
{
    switch (regs->bl) {
    case 0x80: clext_101280(regs); break;
    case 0x81: clext_101281(regs); break;
    case 0x82: clext_101282(regs); break;
    case 0x85: clext_101285(regs); break;
    case 0x9a: clext_10129a(regs); break;
    case 0xa0: clext_1012a0(regs); break;
    case 0xa1: clext_1012a1(regs); break;
    case 0xa2: clext_1012a2(regs); break;
    case 0xae: clext_1012ae(regs); break;
    default:   clext_1012XX(regs); break;
    }
}


/****************************************************************
 * init
 ****************************************************************/

static int
cirrus_check(void)
{
    stdvga_sequ_write(0x06, 0x92);
    return stdvga_sequ_read(0x06) == 0x12;
}

static u8
cirrus_get_memsize(void)
{
    // get DRAM band width
    u8 v = stdvga_sequ_read(0x0f);
    u8 x = (v >> 3) & 0x03;
    if (x == 0x03 && v & 0x80)
        // 4MB
        return 0x40;
    return 0x04 << x;
}

int
clext_setup(void)
{
    int ret = stdvga_setup();
    if (ret)
        return ret;

    dprintf(1, "cirrus init\n");
    if (! cirrus_check())
        return -1;
    dprintf(1, "cirrus init 2\n");

    // memory setup
    stdvga_sequ_write(0x0a, stdvga_sequ_read(0x0f) & 0x18);
    // set vga mode
    stdvga_sequ_write(0x07, 0x00);
    // reset bitblt
    stdvga_grdc_write(0x31, 0x04);
    stdvga_grdc_write(0x31, 0x00);

    if (GET_GLOBAL(HaveRunInit))
        return 0;

    u32 lfb_addr = 0;
    int bdf = GET_GLOBAL(VgaBDF);
    if (CONFIG_VGA_PCI && bdf >= 0)
        lfb_addr = (pci_config_readl(bdf, PCI_BASE_ADDRESS_0)
                    & PCI_BASE_ADDRESS_MEM_MASK);
    SET_VGA(VBE_framebuffer, lfb_addr);
    u16 totalmem = cirrus_get_memsize();
    SET_VGA(VBE_total_memory, totalmem * 64 * 1024);
    SET_VGA(VBE_win_granularity, 16);

    return 0;
}
