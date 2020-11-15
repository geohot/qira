// VGA bios implementation
//
// Copyright (C) 2009-2013  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2001-2008 the LGPL VGABios developers Team
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "bregs.h" // struct bregs
#include "clext.h" // clext_1012
#include "config.h" // CONFIG_*
#include "output.h" // dprintf
#include "std/vbe.h" // VBE_RETURN_STATUS_FAILED
#include "stdvga.h" // stdvga_set_cursor_shape
#include "string.h" // memset_far
#include "vgabios.h" // calc_page_size
#include "vgahw.h" // vgahw_set_mode


/****************************************************************
 * Helper functions
 ****************************************************************/

// Return the bits per pixel in system memory for a given mode.
int
vga_bpp(struct vgamode_s *vmode_g)
{
    switch (GET_GLOBAL(vmode_g->memmodel)) {
    case MM_TEXT:
        return 16;
    case MM_PLANAR:
        return 1;
    }
    u8 depth = GET_GLOBAL(vmode_g->depth);
    if (depth > 8)
        return ALIGN(depth, 8);
    return depth;
}

u16
calc_page_size(u8 memmodel, u16 width, u16 height)
{
    switch (memmodel) {
    case MM_TEXT:
        return ALIGN(width * height * 2, 2*1024);
    case MM_CGA:
        return 16*1024;
    default:
        return ALIGN(width * height / 8, 8*1024);
    }
}

// Determine cursor shape (taking into account possible cursor scaling)
u16
get_cursor_shape(void)
{
    u16 cursor_type = GET_BDA(cursor_type);
    u8 emulate_cursor = (GET_BDA(video_ctl) & 1) == 0;
    if (!emulate_cursor)
        return cursor_type;
    u8 start = (cursor_type >> 8) & 0x3f;
    u8 end = cursor_type & 0x1f;
    u16 cheight = GET_BDA(char_height);
    if (cheight <= 8 || end >= 8 || start >= 0x20)
        return cursor_type;
    if (end != (start + 1))
        start = ((start + 1) * cheight / 8) - 1;
    else
        start = ((end + 1) * cheight / 8) - 2;
    end = ((end + 1) * cheight / 8) - 1;
    return (start << 8) | end;
}

static void
set_cursor_shape(u16 cursor_type)
{
    vgafb_set_swcursor(0);
    SET_BDA(cursor_type, cursor_type);
    if (CONFIG_VGA_STDVGA_PORTS)
        stdvga_set_cursor_shape(get_cursor_shape());
}

static void
set_cursor_pos(struct cursorpos cp)
{
    u8 page = cp.page, x = cp.x, y = cp.y;

    // Should not happen...
    if (page > 7)
        return;

    vgafb_set_swcursor(0);

    // Bios cursor pos
    SET_BDA(cursor_pos[page], (y << 8) | x);

    if (!CONFIG_VGA_STDVGA_PORTS)
        return;

    // Set the hardware cursor
    u8 current = GET_BDA(video_page);
    if (cp.page != current)
        return;

    // Calculate the memory address
    stdvga_set_cursor_pos((int)text_address(cp));
}

struct cursorpos
get_cursor_pos(u8 page)
{
    if (page == 0xff)
        // special case - use current page
        page = GET_BDA(video_page);
    if (page > 7) {
        struct cursorpos cp = { 0, 0, 0xfe };
        return cp;
    }
    u16 xy = GET_BDA(cursor_pos[page]);
    struct cursorpos cp = {xy, xy>>8, page};
    return cp;
}

static void
set_active_page(u8 page)
{
    if (page > 7)
        return;

    // Get the mode
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return;

    vgafb_set_swcursor(0);

    // Calculate memory address of start of page
    struct cursorpos cp = {0, 0, page};
    int address = (int)text_address(cp);
    vgahw_set_displaystart(vmode_g, address);

    // And change the BIOS page
    SET_BDA(video_pagestart, address);
    SET_BDA(video_page, page);

    dprintf(1, "Set active page %02x address %04x\n", page, address);

    // Display the cursor, now the page is active
    set_cursor_pos(get_cursor_pos(page));
}

static void
set_scan_lines(u8 lines)
{
    stdvga_set_scan_lines(lines);
    SET_BDA(char_height, lines);
    u16 vde = stdvga_get_vde();
    u8 rows = vde / lines;
    SET_BDA(video_rows, rows - 1);
    u16 cols = GET_BDA(video_cols);
    SET_BDA(video_pagesize, calc_page_size(MM_TEXT, cols, rows));
    if (lines == 8)
        set_cursor_shape(0x0607);
    else
        set_cursor_shape(((lines - 3) << 8) | (lines - 2));
}


/****************************************************************
 * Character writing
 ****************************************************************/

// Write a character to the screen and calculate new cursor position.
static void
write_char(struct cursorpos *pcp, struct carattr ca)
{
    vgafb_write_char(*pcp, ca);
    pcp->x++;
    // Do we need to wrap ?
    if (pcp->x == GET_BDA(video_cols)) {
        pcp->x = 0;
        pcp->y++;
    }
}

// Write a character to the screen at a given position.  Implement
// special characters and scroll the screen if necessary.
static void
write_teletype(struct cursorpos *pcp, struct carattr ca)
{
    switch (ca.car) {
    case 7:
        //FIXME should beep
        break;
    case 8:
        if (pcp->x > 0)
            pcp->x--;
        break;
    case '\r':
        pcp->x = 0;
        break;
    case '\n':
        pcp->y++;
        break;
    default:
        write_char(pcp, ca);
        break;
    }

    // Do we need to scroll ?
    u16 nbrows = GET_BDA(video_rows);
    if (pcp->y > nbrows) {
        pcp->y--;

        struct cursorpos dest = {0, 0, pcp->page};
        struct cursorpos src = {0, 1, pcp->page};
        struct cursorpos size = {GET_BDA(video_cols), nbrows};
        vgafb_move_chars(dest, src, size);

        struct cursorpos clr = {0, nbrows, pcp->page};
        struct carattr attr = {' ', 0, 0};
        struct cursorpos clrsize = {GET_BDA(video_cols), 1};
        vgafb_clear_chars(clr, attr, clrsize);
    }
}


/****************************************************************
 * Save and restore bda state
 ****************************************************************/

struct saveBDAstate {
    u8 bda_0x49[28];
    u8 bda_0x84[6];
    u16 vbe_mode;
    struct segoff_s font0;
    struct segoff_s font1;
};

int
bda_save_restore(int cmd, u16 seg, void *data)
{
    if (!(cmd & SR_BDA))
        return 0;
    struct saveBDAstate *info = data;
    if (cmd & SR_SAVE) {
        memcpy_far(seg, info->bda_0x49, SEG_BDA, (void*)0x49
                   , sizeof(info->bda_0x49));
        memcpy_far(seg, info->bda_0x84, SEG_BDA, (void*)0x84
                   , sizeof(info->bda_0x84));
        SET_FARVAR(seg, info->vbe_mode, GET_BDA_EXT(vbe_mode));
        SET_FARVAR(seg, info->font0, GET_IVT(0x1f));
        SET_FARVAR(seg, info->font1, GET_IVT(0x43));
    }
    if (cmd & SR_RESTORE) {
        memcpy_far(SEG_BDA, (void*)0x49, seg, info->bda_0x49
                   , sizeof(info->bda_0x49));
        memcpy_far(SEG_BDA, (void*)0x84, seg, info->bda_0x84
                   , sizeof(info->bda_0x84));
        u16 vbe_mode = GET_FARVAR(seg, info->vbe_mode);
        SET_BDA_EXT(vbe_mode, vbe_mode);
        struct vgamode_s *vmode_g = vgahw_find_mode(vbe_mode & ~MF_VBEFLAGS);
        SET_BDA_EXT(vgamode_offset, (u32)vmode_g);
        SET_IVT(0x1f, GET_FARVAR(seg, info->font0));
        SET_IVT(0x43, GET_FARVAR(seg, info->font1));
    }
    return sizeof(*info);
}


/****************************************************************
 * Mode setting
 ****************************************************************/

struct vgamode_s *
get_current_mode(void)
{
    return (void*)(GET_BDA_EXT(vgamode_offset)+0);
}

// Setup BDA after a mode switch.
int
vga_set_mode(int mode, int flags)
{
    dprintf(1, "set VGA mode %x\n", mode);
    struct vgamode_s *vmode_g = vgahw_find_mode(mode);
    if (!vmode_g)
        return VBE_RETURN_STATUS_FAILED;

    vgafb_set_swcursor(0);

    int ret = vgahw_set_mode(vmode_g, flags);
    if (ret)
        return ret;

    // Set the BIOS mem
    int width = GET_GLOBAL(vmode_g->width);
    int height = GET_GLOBAL(vmode_g->height);
    u8 memmodel = GET_GLOBAL(vmode_g->memmodel);
    int cheight = GET_GLOBAL(vmode_g->cheight);
    if (mode < 0x100)
        SET_BDA(video_mode, mode);
    else
        SET_BDA(video_mode, 0xff);
    SET_BDA_EXT(vbe_mode, mode | (flags & MF_VBEFLAGS));
    SET_BDA_EXT(vgamode_offset, (u32)vmode_g);
    if (memmodel == MM_TEXT) {
        SET_BDA(video_cols, width);
        SET_BDA(video_rows, height-1);
        SET_BDA(cursor_type, 0x0607);
    } else {
        int cwidth = GET_GLOBAL(vmode_g->cwidth);
        SET_BDA(video_cols, width / cwidth);
        SET_BDA(video_rows, (height / cheight) - 1);
        SET_BDA(cursor_type, vga_emulate_text() ? 0x0607 : 0x0000);
    }
    SET_BDA(video_pagesize, calc_page_size(memmodel, width, height));
    SET_BDA(crtc_address, CONFIG_VGA_STDVGA_PORTS ? stdvga_get_crtc() : 0);
    SET_BDA(char_height, cheight);
    SET_BDA(video_ctl, 0x60 | (flags & MF_NOCLEARMEM ? 0x80 : 0x00));
    SET_BDA(video_switches, 0xF9);
    SET_BDA(modeset_ctl, GET_BDA(modeset_ctl) & 0x7f);
    int i;
    for (i=0; i<8; i++)
        SET_BDA(cursor_pos[i], 0x0000);
    SET_BDA(video_pagestart, 0x0000);
    SET_BDA(video_page, 0x00);

    // Set the ints 0x1F and 0x43
    SET_IVT(0x1f, SEGOFF(get_global_seg(), (u32)&vgafont8[128 * 8]));

    switch (cheight) {
    case 8:
        SET_IVT(0x43, SEGOFF(get_global_seg(), (u32)vgafont8));
        break;
    case 14:
        SET_IVT(0x43, SEGOFF(get_global_seg(), (u32)vgafont14));
        break;
    case 16:
        SET_IVT(0x43, SEGOFF(get_global_seg(), (u32)vgafont16));
        break;
    }

    return 0;
}


/****************************************************************
 * VGA int 10 handler
 ****************************************************************/

static void
handle_1000(struct bregs *regs)
{
    int mode = regs->al & 0x7f;

    // Set regs->al
    if (mode > 7)
        regs->al = 0x20;
    else if (mode == 6)
        regs->al = 0x3f;
    else
        regs->al = 0x30;

    int flags = MF_LEGACY | (GET_BDA(modeset_ctl) & (MF_NOPALETTE|MF_GRAYSUM));
    if (regs->al & 0x80)
        flags |= MF_NOCLEARMEM;

    vga_set_mode(mode, flags);
}

static void
handle_1001(struct bregs *regs)
{
    set_cursor_shape(regs->cx);
}

static void
handle_1002(struct bregs *regs)
{
    struct cursorpos cp = {regs->dl, regs->dh, regs->bh};
    set_cursor_pos(cp);
}

static void
handle_1003(struct bregs *regs)
{
    regs->cx = GET_BDA(cursor_type);
    struct cursorpos cp = get_cursor_pos(regs->bh);
    regs->dl = cp.x;
    regs->dh = cp.y;
}

// Read light pen pos (unimplemented)
static void
handle_1004(struct bregs *regs)
{
    debug_stub(regs);
    regs->ax = regs->bx = regs->cx = regs->dx = 0;
}

static void
handle_1005(struct bregs *regs)
{
    set_active_page(regs->al);
}

static void
verify_scroll(struct bregs *regs, int dir)
{
    u8 ulx = regs->cl, uly = regs->ch, lrx = regs->dl, lry = regs->dh;
    u16 nbrows = GET_BDA(video_rows) + 1;
    if (lry >= nbrows)
        lry = nbrows - 1;
    u16 nbcols = GET_BDA(video_cols);
    if (lrx >= nbcols)
        lrx = nbcols - 1;
    int wincols = lrx - ulx + 1, winrows = lry - uly + 1;
    if (wincols <= 0 || winrows <= 0)
        return;

    u8 page = GET_BDA(video_page);
    int clearlines = regs->al, movelines = winrows - clearlines;
    if (!clearlines || movelines <= 0) {
        // Clear whole area.
        struct cursorpos clr = {ulx, uly, page};
        struct carattr attr = {' ', regs->bh, 1};
        struct cursorpos clrsize = {wincols, winrows};
        vgafb_clear_chars(clr, attr, clrsize);
        return;
    }

    if (dir > 0) {
        // Normal scroll
        struct cursorpos dest = {ulx, uly, page};
        struct cursorpos src = {ulx, uly + clearlines, page};
        struct cursorpos size = {wincols, movelines};
        vgafb_move_chars(dest, src, size);

        struct cursorpos clr = {ulx, uly + movelines, page};
        struct carattr attr = {' ', regs->bh, 1};
        struct cursorpos clrsize = {wincols, clearlines};
        vgafb_clear_chars(clr, attr, clrsize);
    } else {
        // Scroll down
        struct cursorpos dest = {ulx, uly + clearlines, page};
        struct cursorpos src = {ulx, uly, page};
        struct cursorpos size = {wincols, movelines};
        vgafb_move_chars(dest, src, size);

        struct cursorpos clr = {ulx, uly, page};
        struct carattr attr = {' ', regs->bh, 1};
        struct cursorpos clrsize = {wincols, clearlines};
        vgafb_clear_chars(clr, attr, clrsize);
    }
}

static void
handle_1006(struct bregs *regs)
{
    verify_scroll(regs, 1);
}

static void
handle_1007(struct bregs *regs)
{
    verify_scroll(regs, -1);
}

static void
handle_1008(struct bregs *regs)
{
    struct carattr ca = vgafb_read_char(get_cursor_pos(regs->bh));
    regs->al = ca.car;
    regs->ah = ca.attr;
}

static void noinline
handle_1009(struct bregs *regs)
{
    struct carattr ca = {regs->al, regs->bl, 1};
    struct cursorpos cp = get_cursor_pos(regs->bh);
    int count = regs->cx;
    while (count--)
        write_char(&cp, ca);
}

static void noinline
handle_100a(struct bregs *regs)
{
    struct carattr ca = {regs->al, regs->bl, 0};
    struct cursorpos cp = get_cursor_pos(regs->bh);
    int count = regs->cx;
    while (count--)
        write_char(&cp, ca);
}


static void
handle_100b00(struct bregs *regs)
{
    stdvga_set_border_color(regs->bl);
}

static void
handle_100b01(struct bregs *regs)
{
    stdvga_set_palette(regs->bl);
}

static void
handle_100bXX(struct bregs *regs)
{
    debug_stub(regs);
}

static void
handle_100b(struct bregs *regs)
{
    if (!CONFIG_VGA_STDVGA_PORTS) {
        handle_100bXX(regs);
        return;
    }
    switch (regs->bh) {
    case 0x00: handle_100b00(regs); break;
    case 0x01: handle_100b01(regs); break;
    default:   handle_100bXX(regs); break;
    }
}


static void
handle_100c(struct bregs *regs)
{
    // XXX - page (regs->bh) is unused
    vgafb_write_pixel(regs->al, regs->cx, regs->dx);
}

static void
handle_100d(struct bregs *regs)
{
    // XXX - page (regs->bh) is unused
    regs->al = vgafb_read_pixel(regs->cx, regs->dx);
}

static void noinline
handle_100e(struct bregs *regs)
{
    // Ralf Brown Interrupt list is WRONG on bh(page)
    // We do output only on the current page !
    struct carattr ca = {regs->al, regs->bl, 0};
    struct cursorpos cp = get_cursor_pos(0xff);
    write_teletype(&cp, ca);
    set_cursor_pos(cp);
}

static void
handle_100f(struct bregs *regs)
{
    regs->bh = GET_BDA(video_page);
    regs->al = GET_BDA(video_mode) | (GET_BDA(video_ctl) & 0x80);
    regs->ah = GET_BDA(video_cols);
}


static void
handle_101000(struct bregs *regs)
{
    if (regs->bl > 0x14)
        return;
    stdvga_attr_write(regs->bl, regs->bh);
}

static void
handle_101001(struct bregs *regs)
{
    stdvga_set_overscan_border_color(regs->bh);
}

static void
handle_101002(struct bregs *regs)
{
    stdvga_set_all_palette_reg(regs->es, (u8*)(regs->dx + 0));
}

static void
handle_101003(struct bregs *regs)
{
    stdvga_toggle_intensity(regs->bl);
}

static void
handle_101007(struct bregs *regs)
{
    if (regs->bl > 0x14)
        return;
    regs->bh = stdvga_attr_read(regs->bl);
}

static void
handle_101008(struct bregs *regs)
{
    regs->bh = stdvga_get_overscan_border_color();
}

static void
handle_101009(struct bregs *regs)
{
    stdvga_get_all_palette_reg(regs->es, (u8*)(regs->dx + 0));
}

static void noinline
handle_101010(struct bregs *regs)
{
    u8 rgb[3] = {regs->dh, regs->ch, regs->cl};
    stdvga_dac_write(GET_SEG(SS), rgb, regs->bx, 1);
}

static void
handle_101012(struct bregs *regs)
{
    stdvga_dac_write(regs->es, (u8*)(regs->dx + 0), regs->bx, regs->cx);
}

static void
handle_101013(struct bregs *regs)
{
    stdvga_select_video_dac_color_page(regs->bl, regs->bh);
}

static void noinline
handle_101015(struct bregs *regs)
{
    u8 rgb[3];
    stdvga_dac_read(GET_SEG(SS), rgb, regs->bx, 1);
    regs->dh = rgb[0];
    regs->ch = rgb[1];
    regs->cl = rgb[2];
}

static void
handle_101017(struct bregs *regs)
{
    stdvga_dac_read(regs->es, (u8*)(regs->dx + 0), regs->bx, regs->cx);
}

static void
handle_101018(struct bregs *regs)
{
    stdvga_pelmask_write(regs->bl);
}

static void
handle_101019(struct bregs *regs)
{
    regs->bl = stdvga_pelmask_read();
}

static void
handle_10101a(struct bregs *regs)
{
    stdvga_read_video_dac_state(&regs->bl, &regs->bh);
}

static void
handle_10101b(struct bregs *regs)
{
    stdvga_perform_gray_scale_summing(regs->bx, regs->cx);
}

static void
handle_1010XX(struct bregs *regs)
{
    debug_stub(regs);
}

static void
handle_1010(struct bregs *regs)
{
    if (!CONFIG_VGA_STDVGA_PORTS) {
        handle_1010XX(regs);
        return;
    }
    switch (regs->al) {
    case 0x00: handle_101000(regs); break;
    case 0x01: handle_101001(regs); break;
    case 0x02: handle_101002(regs); break;
    case 0x03: handle_101003(regs); break;
    case 0x07: handle_101007(regs); break;
    case 0x08: handle_101008(regs); break;
    case 0x09: handle_101009(regs); break;
    case 0x10: handle_101010(regs); break;
    case 0x12: handle_101012(regs); break;
    case 0x13: handle_101013(regs); break;
    case 0x15: handle_101015(regs); break;
    case 0x17: handle_101017(regs); break;
    case 0x18: handle_101018(regs); break;
    case 0x19: handle_101019(regs); break;
    case 0x1a: handle_10101a(regs); break;
    case 0x1b: handle_10101b(regs); break;
    default:   handle_1010XX(regs); break;
    }
}


static void
handle_101100(struct bregs *regs)
{
    stdvga_load_font(regs->es, (void*)(regs->bp+0), regs->cx
                     , regs->dx, regs->bl, regs->bh);
}

static void
handle_101101(struct bregs *regs)
{
    stdvga_load_font(get_global_seg(), vgafont14, 0x100, 0, regs->bl, 14);
}

static void
handle_101102(struct bregs *regs)
{
    stdvga_load_font(get_global_seg(), vgafont8, 0x100, 0, regs->bl, 8);
}

static void
handle_101103(struct bregs *regs)
{
    stdvga_set_text_block_specifier(regs->bl);
}

static void
handle_101104(struct bregs *regs)
{
    stdvga_load_font(get_global_seg(), vgafont16, 0x100, 0, regs->bl, 16);
}

static void
handle_101110(struct bregs *regs)
{
    stdvga_load_font(regs->es, (void*)(regs->bp+0), regs->cx
                     , regs->dx, regs->bl, regs->bh);
    set_scan_lines(regs->bh);
}

static void
handle_101111(struct bregs *regs)
{
    stdvga_load_font(get_global_seg(), vgafont14, 0x100, 0, regs->bl, 14);
    set_scan_lines(14);
}

static void
handle_101112(struct bregs *regs)
{
    stdvga_load_font(get_global_seg(), vgafont8, 0x100, 0, regs->bl, 8);
    set_scan_lines(8);
}

static void
handle_101114(struct bregs *regs)
{
    stdvga_load_font(get_global_seg(), vgafont16, 0x100, 0, regs->bl, 16);
    set_scan_lines(16);
}

static void
handle_101120(struct bregs *regs)
{
    SET_IVT(0x1f, SEGOFF(regs->es, regs->bp));
}

void
load_gfx_font(u16 seg, u16 off, u8 height, u8 bl, u8 dl)
{
    u8 rows;

    SET_IVT(0x43, SEGOFF(seg, off));
    switch(bl) {
    case 0:
        rows = dl;
        break;
    case 1:
        rows = 14;
        break;
    case 3:
        rows = 43;
        break;
    case 2:
    default:
        rows = 25;
        break;
    }
    SET_BDA(video_rows, rows - 1);
    SET_BDA(char_height, height);
}

static void
handle_101121(struct bregs *regs)
{
    load_gfx_font(regs->es, regs->bp, regs->cx, regs->bl, regs->dl);
}

static void
handle_101122(struct bregs *regs)
{
    load_gfx_font(get_global_seg(), (u32)vgafont14, 14, regs->bl, regs->dl);
}

static void
handle_101123(struct bregs *regs)
{
    load_gfx_font(get_global_seg(), (u32)vgafont8, 8, regs->bl, regs->dl);
}

static void
handle_101124(struct bregs *regs)
{
    load_gfx_font(get_global_seg(), (u32)vgafont16, 16, regs->bl, regs->dl);
}

static void
handle_101130(struct bregs *regs)
{
    switch (regs->bh) {
    case 0x00: {
        struct segoff_s so = GET_IVT(0x1f);
        regs->es = so.seg;
        regs->bp = so.offset;
        break;
    }
    case 0x01: {
        struct segoff_s so = GET_IVT(0x43);
        regs->es = so.seg;
        regs->bp = so.offset;
        break;
    }
    case 0x02:
        regs->es = get_global_seg();
        regs->bp = (u32)vgafont14;
        break;
    case 0x03:
        regs->es = get_global_seg();
        regs->bp = (u32)vgafont8;
        break;
    case 0x04:
        regs->es = get_global_seg();
        regs->bp = (u32)vgafont8 + 128 * 8;
        break;
    case 0x05:
        regs->es = get_global_seg();
        regs->bp = (u32)vgafont14alt;
        break;
    case 0x06:
        regs->es = get_global_seg();
        regs->bp = (u32)vgafont16;
        break;
    case 0x07:
        regs->es = get_global_seg();
        regs->bp = (u32)vgafont16alt;
        break;
    default:
        dprintf(1, "Get font info BH(%02x) was discarded\n", regs->bh);
        return;
    }
    // Set byte/char of on screen font
    regs->cx = GET_BDA(char_height) & 0xff;

    // Set Highest char row
    regs->dl = GET_BDA(video_rows);
}

static void
handle_1011XX(struct bregs *regs)
{
    debug_stub(regs);
}

static void
handle_1011(struct bregs *regs)
{
    if (CONFIG_VGA_STDVGA_PORTS) {
        switch (regs->al) {
        case 0x00: handle_101100(regs); return;
        case 0x01: handle_101101(regs); return;
        case 0x02: handle_101102(regs); return;
        case 0x03: handle_101103(regs); return;
        case 0x04: handle_101104(regs); return;
        case 0x10: handle_101110(regs); return;
        case 0x11: handle_101111(regs); return;
        case 0x12: handle_101112(regs); return;
        case 0x14: handle_101114(regs); return;
        }
    }
    switch (regs->al) {
    case 0x30: handle_101130(regs); break;
    case 0x20: handle_101120(regs); break;
    case 0x21: handle_101121(regs); break;
    case 0x22: handle_101122(regs); break;
    case 0x23: handle_101123(regs); break;
    case 0x24: handle_101124(regs); break;
    default:   handle_1011XX(regs); break;
    }
}


static void
handle_101210(struct bregs *regs)
{
    u16 crtc_addr = GET_BDA(crtc_address);
    if (crtc_addr == VGAREG_MDA_CRTC_ADDRESS)
        regs->bx = 0x0103;
    else
        regs->bx = 0x0003;
    regs->cx = GET_BDA(video_switches) & 0x0f;
}

static void
handle_101230(struct bregs *regs)
{
    u8 mctl = GET_BDA(modeset_ctl);
    u8 vswt = GET_BDA(video_switches);
    switch (regs->al) {
    case 0x00:
        // 200 lines
        mctl = (mctl & ~0x10) | 0x80;
        vswt = (vswt & ~0x0f) | 0x08;
        break;
    case 0x01:
        // 350 lines
        mctl &= ~0x90;
        vswt = (vswt & ~0x0f) | 0x09;
        break;
    case 0x02:
        // 400 lines
        mctl = (mctl & ~0x80) | 0x10;
        vswt = (vswt & ~0x0f) | 0x09;
        break;
    default:
        dprintf(1, "Select vert res (%02x) was discarded\n", regs->al);
        break;
    }
    SET_BDA(modeset_ctl, mctl);
    SET_BDA(video_switches, vswt);
    regs->al = 0x12;
}

static void
handle_101231(struct bregs *regs)
{
    u8 v = (regs->al & 0x01) << 3;
    u8 mctl = GET_BDA(video_ctl) & ~0x08;
    SET_BDA(video_ctl, mctl | v);
    regs->al = 0x12;
}

static void
handle_101232(struct bregs *regs)
{
    if (CONFIG_VGA_STDVGA_PORTS) {
        stdvga_enable_video_addressing(regs->al);
        regs->al = 0x12;
    }
}

static void
handle_101233(struct bregs *regs)
{
    u8 v = ((regs->al << 1) & 0x02) ^ 0x02;
    u8 v2 = GET_BDA(modeset_ctl) & ~0x02;
    SET_BDA(modeset_ctl, v | v2);
    regs->al = 0x12;
}

static void
handle_101234(struct bregs *regs)
{
    SET_BDA(video_ctl, (GET_BDA(video_ctl) & ~0x01) | (regs->al & 0x01));
    regs->al = 0x12;
}

static void
handle_101235(struct bregs *regs)
{
    debug_stub(regs);
    regs->al = 0x12;
}

static void
handle_101236(struct bregs *regs)
{
    debug_stub(regs);
    regs->al = 0x12;
}

static void
handle_1012XX(struct bregs *regs)
{
    debug_stub(regs);
}

static void
handle_1012(struct bregs *regs)
{
    if (CONFIG_VGA_CIRRUS && regs->bl >= 0x80) {
        clext_1012(regs);
        return;
    }

    switch (regs->bl) {
    case 0x10: handle_101210(regs); break;
    case 0x30: handle_101230(regs); break;
    case 0x31: handle_101231(regs); break;
    case 0x32: handle_101232(regs); break;
    case 0x33: handle_101233(regs); break;
    case 0x34: handle_101234(regs); break;
    case 0x35: handle_101235(regs); break;
    case 0x36: handle_101236(regs); break;
    default:   handle_1012XX(regs); break;
    }
}


// Write string
static void noinline
handle_1013(struct bregs *regs)
{
    struct cursorpos cp;
    if (regs->dh == 0xff)
        // if row=0xff special case : use current cursor position
        cp = get_cursor_pos(regs->bh);
    else
        cp = (struct cursorpos) {regs->dl, regs->dh, regs->bh};

    u16 count = regs->cx;
    u8 *offset_far = (void*)(regs->bp + 0);
    u8 attr = regs->bl;
    while (count--) {
        u8 car = GET_FARVAR(regs->es, *offset_far);
        offset_far++;
        if (regs->al & 2) {
            attr = GET_FARVAR(regs->es, *offset_far);
            offset_far++;
        }

        struct carattr ca = {car, attr, 1};
        write_teletype(&cp, ca);
    }

    if (regs->al & 1)
        set_cursor_pos(cp);
}


static void
handle_101a00(struct bregs *regs)
{
    regs->bx = GET_BDA(dcc_index);
    regs->al = 0x1a;
}

static void
handle_101a01(struct bregs *regs)
{
    SET_BDA(dcc_index, regs->bl);
    dprintf(1, "Alternate Display code (%02x) was discarded\n", regs->bh);
    regs->al = 0x1a;
}

static void
handle_101aXX(struct bregs *regs)
{
    debug_stub(regs);
}

static void
handle_101a(struct bregs *regs)
{
    switch (regs->al) {
    case 0x00: handle_101a00(regs); break;
    case 0x01: handle_101a01(regs); break;
    default:   handle_101aXX(regs); break;
    }
}


struct video_func_static static_functionality VAR16 = {
    .modes          = 0x00,   // Filled in by stdvga_build_video_param()
    .scanlines      = 0x07,   // 200, 350, 400 scan lines
    .cblocks        = 0x02,   // mamimum number of visible charsets in text mode
    .active_cblocks = 0x08,   // total number of charset blocks in text mode
    .misc_flags     = 0x0ce7,
};

static void
handle_101b(struct bregs *regs)
{
    u16 seg = regs->es;
    struct video_func_info *info = (void*)(regs->di+0);
    memset_far(seg, info, 0, sizeof(*info));
    // Address of static functionality table
    SET_FARVAR(seg, info->static_functionality
               , SEGOFF(get_global_seg(), (u32)&static_functionality));

    // Hard coded copy from BIOS area. Should it be cleaner ?
    memcpy_far(seg, info->bda_0x49, SEG_BDA, (void*)0x49
               , sizeof(info->bda_0x49));
    memcpy_far(seg, info->bda_0x84, SEG_BDA, (void*)0x84
               , sizeof(info->bda_0x84));

    SET_FARVAR(seg, info->dcc_index, GET_BDA(dcc_index));
    SET_FARVAR(seg, info->colors, 16);
    SET_FARVAR(seg, info->pages, 8);
    SET_FARVAR(seg, info->scan_lines, 2);
    SET_FARVAR(seg, info->video_mem, 3);
    regs->al = 0x1B;
}


static void
handle_101c(struct bregs *regs)
{
    u16 seg = regs->es;
    void *data = (void*)(regs->bx+0);
    u16 states = regs->cx;
    u8 cmd = regs->al;
    if (states & ~0x07 || cmd > 2)
        goto fail;
    int ret = vgahw_save_restore(states | (cmd<<8), seg, data);
    if (ret < 0)
        goto fail;
    if (cmd == 0)
        regs->bx = ret / 64;
    regs->al = 0x1c;
fail:
    return;
}

static void
handle_10XX(struct bregs *regs)
{
    debug_stub(regs);
}

// INT 10h Video Support Service Entry Point
void VISIBLE16
handle_10(struct bregs *regs)
{
    debug_enter(regs, DEBUG_VGA_10);
    switch (regs->ah) {
    case 0x00: handle_1000(regs); break;
    case 0x01: handle_1001(regs); break;
    case 0x02: handle_1002(regs); break;
    case 0x03: handle_1003(regs); break;
    case 0x04: handle_1004(regs); break;
    case 0x05: handle_1005(regs); break;
    case 0x06: handle_1006(regs); break;
    case 0x07: handle_1007(regs); break;
    case 0x08: handle_1008(regs); break;
    case 0x09: handle_1009(regs); break;
    case 0x0a: handle_100a(regs); break;
    case 0x0b: handle_100b(regs); break;
    case 0x0c: handle_100c(regs); break;
    case 0x0d: handle_100d(regs); break;
    case 0x0e: handle_100e(regs); break;
    case 0x0f: handle_100f(regs); break;
    case 0x10: handle_1010(regs); break;
    case 0x11: handle_1011(regs); break;
    case 0x12: handle_1012(regs); break;
    case 0x13: handle_1013(regs); break;
    case 0x1a: handle_101a(regs); break;
    case 0x1b: handle_101b(regs); break;
    case 0x1c: handle_101c(regs); break;
    case 0x4f: handle_104f(regs); break;
    default:   handle_10XX(regs); break;
    }
}
