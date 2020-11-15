// Simple framebuffer vgabios for use with coreboot native vga init.
//
// Copyright (C) 2014  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "cbvga.h" // cbvga_setup
#include "output.h" // dprintf
#include "stdvga.h" // SEG_CTEXT
#include "string.h" // memset16_far
#include "util.h" // find_cb_table
#include "vgabios.h" // VGAREG_*

static int CBmode VAR16;
static struct vgamode_s CBmodeinfo VAR16;
static struct vgamode_s CBemulinfo VAR16;
static u32 CBlinelength VAR16;

struct vgamode_s *cbvga_find_mode(int mode)
{
    if (mode == GET_GLOBAL(CBmode))
        return &CBmodeinfo;
    if (mode == 0x03)
        return &CBemulinfo;
    return NULL;
}

void
cbvga_list_modes(u16 seg, u16 *dest, u16 *last)
{
    if (dest<last) {
        SET_FARVAR(seg, *dest, GET_GLOBAL(CBmode));
        dest++;
    }
    SET_FARVAR(seg, *dest, 0xffff);
}

int
cbvga_get_window(struct vgamode_s *vmode_g, int window)
{
    return -1;
}

int
cbvga_set_window(struct vgamode_s *vmode_g, int window, int val)
{
    return -1;
}

int
cbvga_get_linelength(struct vgamode_s *vmode_g)
{
    return GET_GLOBAL(CBlinelength);
}

int
cbvga_set_linelength(struct vgamode_s *vmode_g, int val)
{
    return -1;
}

int
cbvga_get_displaystart(struct vgamode_s *vmode_g)
{
    return 0;
}

int
cbvga_set_displaystart(struct vgamode_s *vmode_g, int val)
{
    return -1;
}

int
cbvga_get_dacformat(struct vgamode_s *vmode_g)
{
    return -1;
}

int
cbvga_set_dacformat(struct vgamode_s *vmode_g, int val)
{
    return -1;
}

int
cbvga_save_restore(int cmd, u16 seg, void *data)
{
    if (cmd & (SR_HARDWARE|SR_DAC|SR_REGISTERS))
        return -1;
    return bda_save_restore(cmd, seg, data);
}

int
cbvga_set_mode(struct vgamode_s *vmode_g, int flags)
{
    u8 emul = vmode_g == &CBemulinfo || GET_GLOBAL(CBmode) == 0x03;
    MASK_BDA_EXT(flags, BF_EMULATE_TEXT, emul ? BF_EMULATE_TEXT : 0);
    if (!(flags & MF_NOCLEARMEM)) {
        if (GET_GLOBAL(CBmodeinfo.memmodel) == MM_TEXT) {
            memset16_far(SEG_CTEXT, (void*)0, 0x0720, 80*25*2);
            return 0;
        }
        struct gfx_op op;
        init_gfx_op(&op, vmode_g);
        op.x = op.y = 0;
        op.xlen = GET_GLOBAL(CBmodeinfo.width);
        op.ylen = GET_GLOBAL(CBmodeinfo.height);
        op.op = GO_MEMSET;
        handle_gfx_op(&op);
    }
    return 0;
}

#define CB_TAG_FRAMEBUFFER      0x0012
struct cb_framebuffer {
    u32 tag;
    u32 size;

    u64 physical_address;
    u32 x_resolution;
    u32 y_resolution;
    u32 bytes_per_line;
    u8 bits_per_pixel;
    u8 red_mask_pos;
    u8 red_mask_size;
    u8 green_mask_pos;
    u8 green_mask_size;
    u8 blue_mask_pos;
    u8 blue_mask_size;
    u8 reserved_mask_pos;
    u8 reserved_mask_size;
};

int
cbvga_setup(void)
{
    dprintf(1, "coreboot vga init\n");

    if (GET_GLOBAL(HaveRunInit))
        return 0;

    struct cb_header *cbh = find_cb_table();
    if (!cbh) {
        dprintf(1, "Unable to find coreboot table\n");
        return -1;
    }
    struct cb_framebuffer *cbfb = find_cb_subtable(cbh, CB_TAG_FRAMEBUFFER);
    if (!cbfb) {
        // Assume there is an EGA text framebuffer.
        dprintf(1, "Did not find coreboot framebuffer - assuming EGA text\n");
        SET_VGA(CBmode, 0x03);
        SET_VGA(CBlinelength, 80*2);
        SET_VGA(CBmodeinfo.memmodel, MM_TEXT);
        SET_VGA(CBmodeinfo.width, 80);
        SET_VGA(CBmodeinfo.height, 25);
        SET_VGA(CBmodeinfo.depth, 4);
        SET_VGA(CBmodeinfo.cwidth, 9);
        SET_VGA(CBmodeinfo.cheight, 16);
        SET_VGA(CBmodeinfo.sstart, SEG_CTEXT);
        return 0;
    }

    u64 addr = GET_FARVAR(0, cbfb->physical_address);
    u8 bpp = GET_FARVAR(0, cbfb->bits_per_pixel);
    u32 xlines = GET_FARVAR(0, cbfb->x_resolution);
    u32 ylines = GET_FARVAR(0, cbfb->y_resolution);
    u32 linelength = GET_FARVAR(0, cbfb->bytes_per_line);
    dprintf(1, "Found FB @ %llx %dx%d with %d bpp (%d stride)\n"
            , addr, xlines, ylines, bpp, linelength);

    if (!addr || addr > 0xffffffff
        || (bpp != 15 && bpp != 16 && bpp != 24 && bpp != 32)) {
        dprintf(1, "Unable to use FB\n");
        return -1;
    }

    SET_VGA(CBmode, 0x140);
    SET_VGA(VBE_framebuffer, addr);
    SET_VGA(VBE_total_memory, linelength * ylines);
    SET_VGA(CBlinelength, linelength);
    SET_VGA(CBmodeinfo.memmodel, MM_DIRECT);
    SET_VGA(CBmodeinfo.width, xlines);
    SET_VGA(CBmodeinfo.height, ylines);
    SET_VGA(CBmodeinfo.depth, bpp);
    SET_VGA(CBmodeinfo.cwidth, 8);
    SET_VGA(CBmodeinfo.cheight, 16);
    memcpy_far(get_global_seg(), &CBemulinfo
               , get_global_seg(), &CBmodeinfo, sizeof(CBemulinfo));

    return 0;
}
