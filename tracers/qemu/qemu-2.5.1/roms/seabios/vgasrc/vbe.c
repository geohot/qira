// Video Bios Extensions handlers
//
// Copyright (C) 2012  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2011  Julian Pidancet <julian.pidancet@citrix.com>
// Copyright (C) 2001-2008 the LGPL VGABios developers Team
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "bregs.h" // struct bregs
#include "config.h" // CONFIG_*
#include "output.h" // dprintf
#include "std/vbe.h" // struct vbe_info
#include "string.h" // memset_far
#include "vgabios.h" // handle_104f
#include "vgahw.h" // vgahw_set_mode

u32 VBE_total_memory VAR16 = 256 * 1024;
u32 VBE_capabilities VAR16;
u32 VBE_framebuffer VAR16;
u16 VBE_win_granularity VAR16;

static void
vbe_104f00(struct bregs *regs)
{
    u16 seg = regs->es;
    struct vbe_info *info = (void*)(regs->di+0);

    if (GET_FARVAR(seg, info->signature) == VBE2_SIGNATURE) {
        dprintf(4, "Get VBE Controller: VBE2 Signature found\n");
    } else if (GET_FARVAR(seg, info->signature) == VESA_SIGNATURE) {
        dprintf(4, "Get VBE Controller: VESA Signature found\n");
    } else {
        dprintf(4, "Get VBE Controller: Invalid Signature\n");
    }

    memset_far(seg, info, 0, sizeof(*info));

    SET_FARVAR(seg, info->signature, VESA_SIGNATURE);

    SET_FARVAR(seg, info->version, 0x0300);

    SET_FARVAR(seg, info->oem_string,
            SEGOFF(get_global_seg(), (u32)VBE_OEM_STRING));
    SET_FARVAR(seg, info->capabilities, GET_GLOBAL(VBE_capabilities));

    /* We generate our mode list in the reserved field of the info block */
    u16 *destmode = (void*)info->reserved;
    SET_FARVAR(seg, info->video_mode, SEGOFF(seg, (u32)destmode));

    /* Total memory (in 64k blocks) */
    SET_FARVAR(seg, info->total_memory
               , GET_GLOBAL(VBE_total_memory) / (64*1024));

    SET_FARVAR(seg, info->oem_vendor_string,
            SEGOFF(get_global_seg(), (u32)VBE_VENDOR_STRING));
    SET_FARVAR(seg, info->oem_product_string,
            SEGOFF(get_global_seg(), (u32)VBE_PRODUCT_STRING));
    SET_FARVAR(seg, info->oem_revision_string,
            SEGOFF(get_global_seg(), (u32)VBE_REVISION_STRING));

    /* Fill list of modes */
    u16 *last = (void*)&info->reserved[sizeof(info->reserved)];
    vgahw_list_modes(seg, destmode, last - 1);

    regs->ax = 0x004f;
}

static void
vbe_104f01(struct bregs *regs)
{
    u16 seg = regs->es;
    struct vbe_mode_info *info = (void*)(regs->di+0);
    u16 mode = regs->cx;

    dprintf(1, "VBE mode info request: %x\n", mode);

    struct vgamode_s *vmode_g = vgahw_find_mode(mode & ~MF_VBEFLAGS);
    if (! vmode_g) {
        dprintf(1, "VBE mode %x not found\n", mode);
        regs->ax = 0x014f;
        return;
    }

    memset_far(seg, info, 0, sizeof(*info));

    // Basic information about video controller.
    u32 win_granularity = GET_GLOBAL(VBE_win_granularity);
    SET_FARVAR(seg, info->winA_attributes,
               (win_granularity ? VBE_WINDOW_ATTRIBUTE_RELOCATABLE : 0) |
               VBE_WINDOW_ATTRIBUTE_READABLE |
               VBE_WINDOW_ATTRIBUTE_WRITEABLE);
    SET_FARVAR(seg, info->winB_attributes, 0);
    SET_FARVAR(seg, info->win_granularity, win_granularity);
    SET_FARVAR(seg, info->win_size, 64); /* Bank size 64K */
    SET_FARVAR(seg, info->winA_seg, GET_GLOBAL(vmode_g->sstart));
    SET_FARVAR(seg, info->winB_seg, 0x0);
    extern void entry_104f05(void);
    SET_FARVAR(seg, info->win_func_ptr
               , SEGOFF(get_global_seg(), (u32)entry_104f05));
    // Basic information about mode.
    int width = GET_GLOBAL(vmode_g->width);
    int height = GET_GLOBAL(vmode_g->height);
    int linesize = DIV_ROUND_UP(width * vga_bpp(vmode_g), 8);
    SET_FARVAR(seg, info->bytes_per_scanline, linesize);
    SET_FARVAR(seg, info->xres, width);
    SET_FARVAR(seg, info->yres, height);
    SET_FARVAR(seg, info->xcharsize, GET_GLOBAL(vmode_g->cwidth));
    SET_FARVAR(seg, info->ycharsize, GET_GLOBAL(vmode_g->cheight));
    int depth = GET_GLOBAL(vmode_g->depth);
    SET_FARVAR(seg, info->bits_per_pixel, depth);
    u8 memmodel = GET_GLOBAL(vmode_g->memmodel);
    SET_FARVAR(seg, info->mem_model, memmodel);
    SET_FARVAR(seg, info->reserved0, 1);

    // Mode specific info.
    u16 mode_attr = VBE_MODE_ATTRIBUTE_SUPPORTED |
                    VBE_MODE_ATTRIBUTE_EXTENDED_INFORMATION_AVAILABLE |
                    VBE_MODE_ATTRIBUTE_COLOR_MODE |
                    VBE_MODE_ATTRIBUTE_GRAPHICS_MODE |
                    VBE_MODE_ATTRIBUTE_NOT_VGA_COMPATIBLE;
    u32 framebuffer = 0;
    int planes = 1, banks = 1;
    u32 pages = GET_GLOBAL(VBE_total_memory) / ALIGN(height * linesize, 64*1024);
    switch (memmodel) {
    case MM_TEXT:
        mode_attr &= ~VBE_MODE_ATTRIBUTE_GRAPHICS_MODE;
        mode_attr |= VBE_MODE_ATTRIBUTE_TTY_BIOS_SUPPORT;
        if (GET_GLOBAL(vmode_g->sstart) == SEG_MTEXT)
            mode_attr &= ~VBE_MODE_ATTRIBUTE_COLOR_MODE;
        pages = 1;
        break;
    case MM_CGA:
        pages = 1;
        banks = 2;
        SET_FARVAR(seg, info->bank_size, 8);
        break;
    case MM_PLANAR:
        planes = 4;
        pages /= 4;
        break;
    default:
        framebuffer = GET_GLOBAL(VBE_framebuffer);
        if (framebuffer)
            mode_attr |= VBE_MODE_ATTRIBUTE_LINEAR_FRAME_BUFFER_MODE;
        break;
    }
    if (pages > 128)
        pages = 128;
    if (pages < 2)
        pages++;
    SET_FARVAR(seg, info->mode_attributes, mode_attr);
    SET_FARVAR(seg, info->planes, planes);
    SET_FARVAR(seg, info->pages, pages - 1);
    SET_FARVAR(seg, info->banks, banks);

    // Pixel color breakdown
    u8 r_size, r_pos, g_size, g_pos, b_size, b_pos, a_size, a_pos;
    switch (depth) {
    case 15: r_size = 5; r_pos = 10; g_size = 5; g_pos = 5;
             b_size = 5; b_pos = 0; a_size = 1; a_pos = 15; break;
    case 16: r_size = 5; r_pos = 11; g_size = 6; g_pos = 5;
             b_size = 5; b_pos = 0; a_size = 0; a_pos = 0; break;
    case 24: r_size = 8; r_pos = 16; g_size = 8; g_pos = 8;
             b_size = 8; b_pos = 0; a_size = 0; a_pos = 0; break;
    case 32: r_size = 8; r_pos = 16; g_size = 8; g_pos = 8;
             b_size = 8; b_pos = 0; a_size = 8; a_pos = 24;
             SET_FARVAR(seg, info->directcolor_info,
                        VBE_DIRECTCOLOR_RESERVED_BITS_AVAILABLE);
             break;
    default: r_size = 0; r_pos = 0; g_size = 0; g_pos = 0;
             b_size = 0; b_pos = 0; a_size = 0; a_pos = 0; break;
    }
    SET_FARVAR(seg, info->red_size, r_size);
    SET_FARVAR(seg, info->red_pos, r_pos);
    SET_FARVAR(seg, info->green_size, g_size);
    SET_FARVAR(seg, info->green_pos, g_pos);
    SET_FARVAR(seg, info->blue_size, b_size);
    SET_FARVAR(seg, info->blue_pos, b_pos);
    SET_FARVAR(seg, info->alpha_size, a_size);
    SET_FARVAR(seg, info->alpha_pos, a_pos);

    // Linear framebuffer info.
    if (framebuffer) {
        SET_FARVAR(seg, info->phys_base, framebuffer);

        SET_FARVAR(seg, info->reserved1, 0);
        SET_FARVAR(seg, info->reserved2, 0);
        SET_FARVAR(seg, info->linear_bytes_per_scanline, linesize);
        SET_FARVAR(seg, info->linear_pages, 0);
        SET_FARVAR(seg, info->linear_red_size, r_size);
        SET_FARVAR(seg, info->linear_red_pos, r_pos);
        SET_FARVAR(seg, info->linear_green_size, g_size);
        SET_FARVAR(seg, info->linear_green_pos, g_pos);
        SET_FARVAR(seg, info->linear_blue_size, b_size);
        SET_FARVAR(seg, info->linear_blue_pos, b_pos);
        SET_FARVAR(seg, info->linear_alpha_size, a_size);
        SET_FARVAR(seg, info->linear_alpha_pos, a_pos);
    }

    regs->ax = 0x004f;
}

static void
vbe_104f02(struct bregs *regs)
{
    dprintf(1, "VBE mode set: %x\n", regs->bx);

    int mode = regs->bx & ~MF_VBEFLAGS;
    int flags = regs->bx & MF_VBEFLAGS;
    int ret = vga_set_mode(mode, flags);

    regs->ah = ret;
    regs->al = 0x4f;
}

static void
vbe_104f03(struct bregs *regs)
{
    regs->bx = GET_BDA_EXT(vbe_mode);
    dprintf(1, "VBE current mode=%x\n", regs->bx);
    regs->ax = 0x004f;
}

static void
vbe_104f04(struct bregs *regs)
{
    u16 seg = regs->es;
    void *data = (void*)(regs->bx+0);
    u16 states = regs->cx;
    u8 cmd = regs->dl;
    if (states & ~0x0f || cmd > 2)
        goto fail;
    int ret = vgahw_save_restore(states | (cmd<<8), seg, data);
    if (ret < 0)
        goto fail;
    if (cmd == 0)
        regs->bx = ret / 64;
    regs->ax = 0x004f;
    return;
fail:
    regs->ax = 0x014f;
}

void VISIBLE16
vbe_104f05(struct bregs *regs)
{
    if (regs->bh > 1 || regs->bl > 1)
        goto fail;
    if (GET_BDA_EXT(vbe_mode) & MF_LINEARFB) {
        regs->ah = VBE_RETURN_STATUS_INVALID;
        return;
    }
    struct vgamode_s *vmode_g = get_current_mode();
    if (! vmode_g)
        goto fail;
    if (regs->bh) {
        int ret = vgahw_get_window(vmode_g, regs->bl);
        if (ret < 0)
            goto fail;
        regs->dx = ret;
        regs->ax = 0x004f;
        return;
    }
    int ret = vgahw_set_window(vmode_g, regs->bl, regs->dx);
    if (ret)
        goto fail;
    regs->ax = 0x004f;
    return;
fail:
    regs->ax = 0x014f;
}

static void
vbe_104f06(struct bregs *regs)
{
    if (regs->bl > 0x02)
        goto fail;
    struct vgamode_s *vmode_g = get_current_mode();
    if (! vmode_g)
        goto fail;
    int bpp = vga_bpp(vmode_g);

    if (regs->bl == 0x00) {
        int ret = vgahw_set_linelength(vmode_g, DIV_ROUND_UP(regs->cx * bpp, 8));
        if (ret)
            goto fail;
    } else if (regs->bl == 0x02) {
        int ret = vgahw_set_linelength(vmode_g, regs->cx);
        if (ret)
            goto fail;
    }
    int linelength = vgahw_get_linelength(vmode_g);
    if (linelength < 0)
        goto fail;

    regs->bx = linelength;
    regs->cx = (linelength * 8) / bpp;
    regs->dx = GET_GLOBAL(VBE_total_memory) / linelength;
    regs->ax = 0x004f;
    return;
fail:
    regs->ax = 0x014f;
}

static void
vbe_104f07(struct bregs *regs)
{
    struct vgamode_s *vmode_g = get_current_mode();
    if (! vmode_g)
        goto fail;
    int bpp = vga_bpp(vmode_g);
    int linelength = vgahw_get_linelength(vmode_g);
    if (linelength < 0)
        goto fail;

    int ret;
    switch (regs->bl) {
    case 0x80:
    case 0x00:
        ret = vgahw_set_displaystart(
            vmode_g, DIV_ROUND_UP(regs->cx * bpp, 8) + linelength * regs->dx);
        if (ret)
            goto fail;
        break;
    case 0x01:
        ret = vgahw_get_displaystart(vmode_g);
        if (ret < 0)
            goto fail;
        regs->dx = ret / linelength;
        regs->cx = (ret % linelength) * 8 / bpp;
        break;
    default:
        goto fail;
    }
    regs->ax = 0x004f;
    return;
fail:
    regs->ax = 0x014f;
}

static void
vbe_104f08(struct bregs *regs)
{
    struct vgamode_s *vmode_g = get_current_mode();
    if (! vmode_g)
        goto fail;
    u8 memmodel = GET_GLOBAL(vmode_g->memmodel);
    if (memmodel == MM_DIRECT || memmodel == MM_YUV) {
        regs->ax = 0x034f;
        return;
    }
    if (regs->bl > 1)
        goto fail;
    if (regs->bl == 0) {
        int ret = vgahw_set_dacformat(vmode_g, regs->bh);
        if (ret < 0)
            goto fail;
    }
    int ret = vgahw_get_dacformat(vmode_g);
    if (ret < 0)
        goto fail;
    regs->bh = ret;
    regs->ax = 0x004f;
    return;
fail:
    regs->ax = 0x014f;
}

static void
vbe_104f0a(struct bregs *regs)
{
    debug_stub(regs);
    regs->ax = 0x0100;
}

static void
vbe_104f10(struct bregs *regs)
{
    switch (regs->bl) {
    case 0x00:
        regs->bx = 0x0f30;
        break;
    case 0x01:
        MASK_BDA_EXT(flags, BF_PM_MASK, regs->bh & BF_PM_MASK);
        break;
    case 0x02:
        regs->bh = GET_BDA_EXT(flags) & BF_PM_MASK;
        break;
    default:
        regs->ax = 0x014f;
        return;
    }
    regs->ax = 0x004f;
}

static void
vbe_104fXX(struct bregs *regs)
{
    debug_stub(regs);
    regs->ax = 0x0100;
}

void noinline
handle_104f(struct bregs *regs)
{
    if (!CONFIG_VGA_VBE) {
        vbe_104fXX(regs);
        return;
    }

    switch (regs->al) {
    case 0x00: vbe_104f00(regs); break;
    case 0x01: vbe_104f01(regs); break;
    case 0x02: vbe_104f02(regs); break;
    case 0x03: vbe_104f03(regs); break;
    case 0x04: vbe_104f04(regs); break;
    case 0x05: vbe_104f05(regs); break;
    case 0x06: vbe_104f06(regs); break;
    case 0x07: vbe_104f07(regs); break;
    case 0x08: vbe_104f08(regs); break;
    case 0x0a: vbe_104f0a(regs); break;
    case 0x10: vbe_104f10(regs); break;
    default:   vbe_104fXX(regs); break;
    }
}
