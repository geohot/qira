// Code for manipulating VGA framebuffers.
//
// Copyright (C) 2009-2014  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2001-2008 the LGPL VGABios developers Team
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "byteorder.h" // cpu_to_be16
#include "output.h" // dprintf
#include "stdvga.h" // stdvga_planar4_plane
#include "string.h" // memset_far
#include "vgabios.h" // vgafb_scroll
#include "vgahw.h" // vgahw_get_linelength

static inline void
memmove_stride(u16 seg, void *dst, void *src, int copylen, int stride, int lines)
{
    if (src < dst) {
        dst += stride * (lines - 1);
        src += stride * (lines - 1);
        stride = -stride;
    }
    for (; lines; lines--, dst+=stride, src+=stride)
        memcpy_far(seg, dst, seg, src, copylen);
}

static inline void
memset_stride(u16 seg, void *dst, u8 val, int setlen, int stride, int lines)
{
    for (; lines; lines--, dst+=stride)
        memset_far(seg, dst, val, setlen);
}

static inline void
memset16_stride(u16 seg, void *dst, u16 val, int setlen, int stride, int lines)
{
    for (; lines; lines--, dst+=stride)
        memset16_far(seg, dst, val, setlen);
}


/****************************************************************
 * Basic stdvga graphic manipulation
 ****************************************************************/

static void
gfx_planar(struct gfx_op *op)
{
    if (!CONFIG_VGA_STDVGA_PORTS)
        return;
    void *dest_far = (void*)(op->y * op->linelength + op->x / 8);
    int plane;
    switch (op->op) {
    default:
    case GO_READ8:
        memset(op->pixels, 0, sizeof(op->pixels));
        for (plane = 0; plane < 4; plane++) {
            stdvga_planar4_plane(plane);
            u8 data = GET_FARVAR(SEG_GRAPH, *(u8*)dest_far);
            int pixel;
            for (pixel=0; pixel<8; pixel++)
                op->pixels[pixel] |= ((data>>(7-pixel)) & 1) << plane;
        }
        break;
    case GO_WRITE8:
        for (plane = 0; plane<4; plane++) {
            stdvga_planar4_plane(plane);
            u8 data = 0;
            int pixel;
            for (pixel=0; pixel<8; pixel++)
                data |= ((op->pixels[pixel]>>plane) & 1) << (7-pixel);
            SET_FARVAR(SEG_GRAPH, *(u8*)dest_far, data);
        }
        break;
    case GO_MEMSET:
        for (plane = 0; plane < 4; plane++) {
            stdvga_planar4_plane(plane);
            u8 data = (op->pixels[0] & (1<<plane)) ? 0xff : 0x00;
            memset_stride(SEG_GRAPH, dest_far, data
                          , op->xlen / 8, op->linelength, op->ylen);
        }
        break;
    case GO_MEMMOVE: ;
        void *src_far = (void*)(op->srcy * op->linelength + op->x / 8);
        for (plane = 0; plane < 4; plane++) {
            stdvga_planar4_plane(plane);
            memmove_stride(SEG_GRAPH, dest_far, src_far
                           , op->xlen / 8, op->linelength, op->ylen);
        }
        break;
    }
    stdvga_planar4_plane(-1);
}

static void
gfx_cga(struct gfx_op *op)
{
    int bpp = GET_GLOBAL(op->vmode_g->depth);
    void *dest_far = (void*)(op->y / 2 * op->linelength + op->x / 8 * bpp);
    switch (op->op) {
    default:
    case GO_READ8:
        if (op->y & 1)
            dest_far += 0x2000;
        if (bpp == 1) {
            u8 data = GET_FARVAR(SEG_CTEXT, *(u8*)dest_far);
            int pixel;
            for (pixel=0; pixel<8; pixel++)
                op->pixels[pixel] = (data >> (7-pixel)) & 1;
        } else {
            u16 data = GET_FARVAR(SEG_CTEXT, *(u16*)dest_far);
            data = be16_to_cpu(data);
            int pixel;
            for (pixel=0; pixel<8; pixel++)
                op->pixels[pixel] = (data >> ((7-pixel)*2)) & 3;
        }
        break;
    case GO_WRITE8:
        if (op->y & 1)
            dest_far += 0x2000;
        if (bpp == 1) {
            u8 data = 0;
            int pixel;
            for (pixel=0; pixel<8; pixel++)
                data |= (op->pixels[pixel] & 1) << (7-pixel);
            SET_FARVAR(SEG_CTEXT, *(u8*)dest_far, data);
        } else {
            u16 data = 0;
            int pixel;
            for (pixel=0; pixel<8; pixel++)
                data |= (op->pixels[pixel] & 3) << ((7-pixel) * 2);
            data = cpu_to_be16(data);
            SET_FARVAR(SEG_CTEXT, *(u16*)dest_far, data);
        }
        break;
    case GO_MEMSET: ;
        u8 data = op->pixels[0];
        if (bpp == 1)
            data = (data&1) | ((data&1)<<1);
        data &= 3;
        data |= (data<<2) | (data<<4) | (data<<6);
        memset_stride(SEG_CTEXT, dest_far, data
                      , op->xlen / 8 * bpp, op->linelength, op->ylen / 2);
        memset_stride(SEG_CTEXT, dest_far + 0x2000, data
                      , op->xlen / 8 * bpp, op->linelength, op->ylen / 2);
        break;
    case GO_MEMMOVE: ;
        void *src_far = (void*)(op->srcy / 2 * op->linelength + op->x / 8 * bpp);
        memmove_stride(SEG_CTEXT, dest_far, src_far
                       , op->xlen / 8 * bpp, op->linelength, op->ylen / 2);
        memmove_stride(SEG_CTEXT, dest_far + 0x2000, src_far + 0x2000
                       , op->xlen / 8 * bpp, op->linelength, op->ylen / 2);
        break;
    }
}

static void
gfx_packed(struct gfx_op *op)
{
    void *dest_far = (void*)(op->y * op->linelength + op->x);
    switch (op->op) {
    default:
    case GO_READ8:
        memcpy_far(GET_SEG(SS), op->pixels, SEG_GRAPH, dest_far, 8);
        break;
    case GO_WRITE8:
        memcpy_far(SEG_GRAPH, dest_far, GET_SEG(SS), op->pixels, 8);
        break;
    case GO_MEMSET:
        memset_stride(SEG_GRAPH, dest_far, op->pixels[0]
                      , op->xlen, op->linelength, op->ylen);
        break;
    case GO_MEMMOVE: ;
        void *src_far = (void*)(op->srcy * op->linelength + op->x);
        memmove_stride(SEG_GRAPH, dest_far, src_far
                       , op->xlen, op->linelength, op->ylen);
        break;
    }
}


/****************************************************************
 * Direct framebuffers in high mem
 ****************************************************************/

// Use int 1587 call to copy memory to/from the framebuffer.
static void
memcpy_high(void *dest, void *src, u32 len)
{
    u64 gdt[6];
    gdt[2] = GDT_DATA | GDT_LIMIT(0xfffff) | GDT_BASE((u32)src);
    gdt[3] = GDT_DATA | GDT_LIMIT(0xfffff) | GDT_BASE((u32)dest);

    // Call int 1587 to copy data.
    len/=2;
    u32 flags;
    u32 eax = 0x8700;
    u32 si = (u32)&gdt;
    SET_SEG(ES, GET_SEG(SS));
    asm volatile(
        "stc\n"
        "int $0x15\n"
        "cli\n"
        "cld\n"
        "pushfl\n"
        "popl %0\n"
        : "=r" (flags), "+a" (eax), "+S" (si), "+c" (len)
        : : "cc", "memory");
}

static void
memmove_stride_high(void *dst, void *src, int copylen, int stride, int lines)
{
    if (src < dst) {
        dst += stride * (lines - 1);
        src += stride * (lines - 1);
        stride = -stride;
    }
    for (; lines; lines--, dst+=stride, src+=stride)
        memcpy_high(dst, src, copylen);
}

// Map a CGA color to a "direct" mode rgb value.
static u32
get_color(int depth, u8 attr)
{
    int rbits, gbits, bbits;
    switch (depth) {
    case 15: rbits=5; gbits=5; bbits=5; break;
    case 16: rbits=5; gbits=6; bbits=5; break;
    default:
    case 24: rbits=8; gbits=8; bbits=8; break;
    }
    int h = (attr&8) ? 1 : 0;
    int r = (attr&4) ? 2 : 0, g = (attr&2) ? 2 : 0, b = (attr&1) ? 2 : 0;
    if ((attr & 0xf) == 6)
        g = 1;
    int rv = DIV_ROUND_CLOSEST(((1<<rbits) - 1) * (r + h), 3);
    int gv = DIV_ROUND_CLOSEST(((1<<gbits) - 1) * (g + h), 3);
    int bv = DIV_ROUND_CLOSEST(((1<<bbits) - 1) * (b + h), 3);
    return (rv << (gbits+bbits)) + (gv << bbits) + bv;
}

// Find the closest attribute for a given framebuffer color
static u8
reverse_color(int depth, u32 color)
{
    int rbits, gbits, bbits;
    switch (depth) {
    case 15: rbits=5; gbits=5; bbits=5; break;
    case 16: rbits=5; gbits=6; bbits=5; break;
    default:
    case 24: rbits=8; gbits=8; bbits=8; break;
    }
    int rv = (color >> (gbits+bbits)) & ((1<<rbits)-1);
    int gv = (color >> bbits) & ((1<<gbits)-1);
    int bv = color & ((1<<bbits)-1);
    int r = DIV_ROUND_CLOSEST(rv * 3, (1<<rbits) - 1);
    int g = DIV_ROUND_CLOSEST(gv * 3, (1<<gbits) - 1);
    int b = DIV_ROUND_CLOSEST(bv * 3, (1<<bbits) - 1);
    int h = r && g && b && (r != 2 || g != 2 || b != 2);
    return (h ? 8 : 0) | ((r-h) ? 4 : 0) | ((g-h) ? 2 : 0) | ((b-h) ? 1 : 0);
}

static void
gfx_direct(struct gfx_op *op)
{
    void *fb = (void*)GET_GLOBAL(VBE_framebuffer);
    if (!fb)
        return;
    int depth = GET_GLOBAL(op->vmode_g->depth);
    int bypp = DIV_ROUND_UP(depth, 8);
    void *dest_far = (fb + op->displaystart + op->y * op->linelength
                      + op->x * bypp);
    switch (op->op) {
    default:
    case GO_READ8: {
        u8 data[64];
        memcpy_high(MAKE_FLATPTR(GET_SEG(SS), data), dest_far, bypp * 8);
        int i;
        for (i=0; i<8; i++)
            op->pixels[i] = reverse_color(depth, *(u32*)&data[i*bypp]);
        break;
    }
    case GO_WRITE8: {
        u8 data[64];
        int i;
        for (i=0; i<8; i++)
            *(u32*)&data[i*bypp] = get_color(depth, op->pixels[i]);
        memcpy_high(dest_far, MAKE_FLATPTR(GET_SEG(SS), data), bypp * 8);
        break;
    }
    case GO_MEMSET: {
        u32 color = get_color(depth, op->pixels[0]);
        u8 data[64];
        int i;
        for (i=0; i<8; i++)
            *(u32*)&data[i*bypp] = color;
        memcpy_high(dest_far, MAKE_FLATPTR(GET_SEG(SS), data), bypp * 8);
        memcpy_high(dest_far + bypp * 8, dest_far, op->xlen * bypp - bypp * 8);
        for (i=1; i < op->ylen; i++)
            memcpy_high(dest_far + op->linelength * i
                        , dest_far, op->xlen * bypp);
        break;
    }
    case GO_MEMMOVE: ;
        void *src_far = (fb + op->displaystart + op->srcy * op->linelength
                         + op->x * bypp);
        memmove_stride_high(dest_far, src_far
                            , op->xlen * bypp, op->linelength, op->ylen);
        break;
    }
}


/****************************************************************
 * Gfx interface
 ****************************************************************/

// Prepare a struct gfx_op for use.
void
init_gfx_op(struct gfx_op *op, struct vgamode_s *vmode_g)
{
    memset(op, 0, sizeof(*op));
    op->vmode_g = vmode_g;
    op->linelength = vgahw_get_linelength(vmode_g);
    op->displaystart = vgahw_get_displaystart(vmode_g);
}

// Issue a graphics operation.
void
handle_gfx_op(struct gfx_op *op)
{
    switch (GET_GLOBAL(op->vmode_g->memmodel)) {
    case MM_PLANAR:
        gfx_planar(op);
        break;
    case MM_CGA:
        gfx_cga(op);
        break;
    case MM_PACKED:
        gfx_packed(op);
        break;
    case MM_DIRECT:
        gfx_direct(op);
        break;
    default:
        break;
    }
}

// Move characters when in graphics mode.
static void
gfx_move_chars(struct vgamode_s *vmode_g, struct cursorpos dest
               , struct cursorpos src, struct cursorpos movesize)
{
    struct gfx_op op;
    init_gfx_op(&op, vmode_g);
    op.x = dest.x * 8;
    op.xlen = movesize.x * 8;
    int cheight = GET_BDA(char_height);
    op.y = dest.y * cheight;
    op.ylen = movesize.y * cheight;
    op.srcy = src.y * cheight;
    op.op = GO_MEMMOVE;
    handle_gfx_op(&op);
}

// Clear area of screen in graphics mode.
static void
gfx_clear_chars(struct vgamode_s *vmode_g, struct cursorpos dest
                , struct carattr ca, struct cursorpos clearsize)
{
    struct gfx_op op;
    init_gfx_op(&op, vmode_g);
    op.x = dest.x * 8;
    op.xlen = clearsize.x * 8;
    int cheight = GET_BDA(char_height);
    op.y = dest.y * cheight;
    op.ylen = clearsize.y * cheight;
    op.pixels[0] = ca.attr;
    if (vga_emulate_text())
        op.pixels[0] = ca.attr >> 4;
    op.op = GO_MEMSET;
    handle_gfx_op(&op);
}

// Return the font for a given character
struct segoff_s
get_font_data(u8 c)
{
    int char_height = GET_BDA(char_height);
    struct segoff_s font;
    if (char_height == 8 && c >= 128) {
        font = GET_IVT(0x1f);
        c -= 128;
    } else {
        font = GET_IVT(0x43);
    }
    font.offset += c * char_height;
    return font;
}

// Write a character to the screen in graphics mode.
static void
gfx_write_char(struct vgamode_s *vmode_g
                , struct cursorpos cp, struct carattr ca)
{
    if (cp.x >= GET_BDA(video_cols))
        return;

    struct segoff_s font = get_font_data(ca.car);
    struct gfx_op op;
    init_gfx_op(&op, vmode_g);
    op.x = cp.x * 8;
    int cheight = GET_BDA(char_height);
    op.y = cp.y * cheight;
    u8 fgattr = ca.attr, bgattr = 0x00;
    int usexor = 0;
    if (vga_emulate_text()) {
        if (ca.use_attr) {
            bgattr = fgattr >> 4;
            fgattr = fgattr & 0x0f;
        } else {
            // Read bottom right pixel of the cell to guess bg color
            op.op = GO_READ8;
            op.y += cheight-1;
            handle_gfx_op(&op);
            op.y -= cheight-1;
            bgattr = op.pixels[7];
            fgattr = bgattr ^ 0x7;
        }
    } else if (fgattr & 0x80 && GET_GLOBAL(vmode_g->depth) < 8) {
        usexor = 1;
        fgattr &= 0x7f;
    }
    int i;
    for (i = 0; i < cheight; i++, op.y++) {
        u8 fontline = GET_FARVAR(font.seg, *(u8*)(font.offset+i));
        if (usexor) {
            op.op = GO_READ8;
            handle_gfx_op(&op);
            int j;
            for (j = 0; j < 8; j++)
                op.pixels[j] ^= (fontline & (0x80>>j)) ? fgattr : 0x00;
        } else {
            int j;
            for (j = 0; j < 8; j++)
                op.pixels[j] = (fontline & (0x80>>j)) ? fgattr : bgattr;
        }
        op.op = GO_WRITE8;
        handle_gfx_op(&op);
    }
}

// Read a character from the screen in graphics mode.
static struct carattr
gfx_read_char(struct vgamode_s *vmode_g, struct cursorpos cp)
{
    u8 lines[16];
    int cheight = GET_BDA(char_height);
    if (cp.x >= GET_BDA(video_cols) || cheight > ARRAY_SIZE(lines))
        goto fail;

    // Read cell from screen
    struct gfx_op op;
    init_gfx_op(&op, vmode_g);
    op.op = GO_READ8;
    op.x = cp.x * 8;
    op.y = cp.y * cheight;
    int car = 0;
    u8 fgattr = 0x00, bgattr = 0x00;
    if (vga_emulate_text()) {
        // Read bottom right pixel of the cell to guess bg color
        op.y += cheight-1;
        handle_gfx_op(&op);
        op.y -= cheight-1;
        bgattr = op.pixels[7];
        fgattr = bgattr ^ 0x7;
        // Report space character for blank cells (skip null character check)
        car = 1;
    }
    u8 i, j;
    for (i=0; i<cheight; i++, op.y++) {
        u8 line = 0;
        handle_gfx_op(&op);
        for (j=0; j<8; j++)
            if (op.pixels[j] != bgattr) {
                line |= 0x80 >> j;
                fgattr = op.pixels[j];
            }
        lines[i] = line;
    }

    // Determine font
    for (; car<256; car++) {
        struct segoff_s font = get_font_data(car);
        if (memcmp_far(GET_SEG(SS), lines
                       , font.seg, (void*)(font.offset+0), cheight) == 0)
            return (struct carattr){car, fgattr | (bgattr << 4), 0};
    }
fail:
    return (struct carattr){0, 0, 0};
}

// Draw/undraw a cursor on the framebuffer by xor'ing the cursor cell
void
gfx_set_swcursor(struct vgamode_s *vmode_g, int enable, struct cursorpos cp)
{
    u16 cursor_type = get_cursor_shape();
    u8 start = cursor_type >> 8, end = cursor_type & 0xff;
    struct gfx_op op;
    init_gfx_op(&op, vmode_g);
    op.x = cp.x * 8;
    int cheight = GET_BDA(char_height);
    op.y = cp.y * cheight + start;

    int i;
    for (i = start; i < cheight && i <= end; i++, op.y++) {
        op.op = GO_READ8;
        handle_gfx_op(&op);
        int j;
        for (j = 0; j < 8; j++)
            op.pixels[j] ^= 0x07;
        op.op = GO_WRITE8;
        handle_gfx_op(&op);
    }
}

// Set the pixel at the given position.
void
vgafb_write_pixel(u8 color, u16 x, u16 y)
{
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return;
    vgafb_set_swcursor(0);

    struct gfx_op op;
    init_gfx_op(&op, vmode_g);
    op.x = ALIGN_DOWN(x, 8);
    op.y = y;
    op.op = GO_READ8;
    handle_gfx_op(&op);

    int usexor = color & 0x80 && GET_GLOBAL(vmode_g->depth) < 8;
    if (usexor)
        op.pixels[x & 0x07] ^= color & 0x7f;
    else
        op.pixels[x & 0x07] = color;
    op.op = GO_WRITE8;
    handle_gfx_op(&op);
}

// Return the pixel at the given position.
u8
vgafb_read_pixel(u16 x, u16 y)
{
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return 0;
    vgafb_set_swcursor(0);

    struct gfx_op op;
    init_gfx_op(&op, vmode_g);
    op.x = ALIGN_DOWN(x, 8);
    op.y = y;
    op.op = GO_READ8;
    handle_gfx_op(&op);

    return op.pixels[x & 0x07];
}


/****************************************************************
 * Text ops
 ****************************************************************/

// Return the fb offset for the given character address when in text mode.
void *
text_address(struct cursorpos cp)
{
    int stride = GET_BDA(video_cols) * 2;
    u32 pageoffset = GET_BDA(video_pagesize) * cp.page;
    return (void*)pageoffset + cp.y * stride + cp.x * 2;
}

// Move characters on screen.
void
vgafb_move_chars(struct cursorpos dest
                 , struct cursorpos src, struct cursorpos movesize)
{
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return;
    vgafb_set_swcursor(0);

    if (GET_GLOBAL(vmode_g->memmodel) != MM_TEXT) {
        gfx_move_chars(vmode_g, dest, src, movesize);
        return;
    }

    int stride = GET_BDA(video_cols) * 2;
    memmove_stride(GET_GLOBAL(vmode_g->sstart)
                   , text_address(dest), text_address(src)
                   , movesize.x * 2, stride, movesize.y);
}

// Clear area of screen.
void
vgafb_clear_chars(struct cursorpos dest
                  , struct carattr ca, struct cursorpos clearsize)
{
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return;
    vgafb_set_swcursor(0);

    if (GET_GLOBAL(vmode_g->memmodel) != MM_TEXT) {
        gfx_clear_chars(vmode_g, dest, ca, clearsize);
        return;
    }

    int stride = GET_BDA(video_cols) * 2;
    u16 attr = ((ca.use_attr ? ca.attr : 0x07) << 8) | ca.car;
    memset16_stride(GET_GLOBAL(vmode_g->sstart), text_address(dest), attr
                    , clearsize.x * 2, stride, clearsize.y);
}

// Write a character to the screen.
void
vgafb_write_char(struct cursorpos cp, struct carattr ca)
{
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return;
    vgafb_set_swcursor(0);

    if (GET_GLOBAL(vmode_g->memmodel) != MM_TEXT) {
        gfx_write_char(vmode_g, cp, ca);
        return;
    }

    void *dest_far = text_address(cp);
    if (ca.use_attr) {
        u16 dummy = (ca.attr << 8) | ca.car;
        SET_FARVAR(GET_GLOBAL(vmode_g->sstart), *(u16*)dest_far, dummy);
    } else {
        SET_FARVAR(GET_GLOBAL(vmode_g->sstart), *(u8*)dest_far, ca.car);
    }
}

// Return the character at the given position on the screen.
struct carattr
vgafb_read_char(struct cursorpos cp)
{
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return (struct carattr){0, 0, 0};
    vgafb_set_swcursor(0);

    if (GET_GLOBAL(vmode_g->memmodel) != MM_TEXT)
        return gfx_read_char(vmode_g, cp);

    u16 *dest_far = text_address(cp);
    u16 v = GET_FARVAR(GET_GLOBAL(vmode_g->sstart), *dest_far);
    return (struct carattr){v, v>>8, 0};
}

// Draw/undraw a cursor on the screen
void
vgafb_set_swcursor(int enable)
{
    if (!vga_emulate_text())
        return;
    u8 flags = GET_BDA_EXT(flags);
    if (!!(flags & BF_SWCURSOR) == enable)
        // Already in requested mode.
        return;
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return;
    struct cursorpos cp = get_cursor_pos(0xff);
    if (cp.x >= GET_BDA(video_cols) || cp.y > GET_BDA(video_rows)
        || GET_BDA(cursor_type) >= 0x2000)
        // Cursor not visible
        return;

    SET_BDA_EXT(flags, (flags & ~BF_SWCURSOR) | (enable ? BF_SWCURSOR : 0));

    if (GET_GLOBAL(vmode_g->memmodel) != MM_TEXT) {
        gfx_set_swcursor(vmode_g, enable, cp);
        return;
    }

    // In text mode, swap foreground and background attributes for cursor
    void *dest_far = text_address(cp) + 1;
    u8 attr = GET_FARVAR(GET_GLOBAL(vmode_g->sstart), *(u8*)dest_far);
    attr = (attr >> 4) | (attr << 4);
    SET_FARVAR(GET_GLOBAL(vmode_g->sstart), *(u8*)dest_far, attr);
}
