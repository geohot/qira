/*
 *  Copyright (c) 2004-2005 Fabrice Bellard
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include "bios.h"

/* VGA init. We use the Bochs VESA VBE extensions  */
#define VBE_DISPI_INDEX_ID              0x0
#define VBE_DISPI_INDEX_XRES            0x1
#define VBE_DISPI_INDEX_YRES            0x2
#define VBE_DISPI_INDEX_BPP             0x3
#define VBE_DISPI_INDEX_ENABLE          0x4
#define VBE_DISPI_INDEX_BANK            0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH      0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT     0x7
#define VBE_DISPI_INDEX_X_OFFSET        0x8
#define VBE_DISPI_INDEX_Y_OFFSET        0x9
#define VBE_DISPI_INDEX_NB              0xa
      
#define VBE_DISPI_ID0                   0xB0C0
#define VBE_DISPI_ID1                   0xB0C1
#define VBE_DISPI_ID2                   0xB0C2
  
#define VBE_DISPI_DISABLED              0x00
#define VBE_DISPI_ENABLED               0x01
#define VBE_DISPI_LFB_ENABLED           0x40
#define VBE_DISPI_NOCLEARMEM            0x80
  
#define VBE_DISPI_LFB_PHYSICAL_ADDRESS  0xE0000000

static void vga_text_init(void);

unsigned long vga_fb_phys_addr;
int vga_fb_width;
int vga_fb_height;
int vga_fb_linesize;
int vga_fb_bpp;
int vga_fb_depth;
uint8_t rgb_to_index[256];

static void vbe_outw(int index, int val)
{
    outw(0x1ce, index);
    outw(0x1d0, val);
}

/* init VGA in standard state for PREP boot */
void vga_prep_init(void)
{
    outb(0x3c0, 0x00); /* set blanking */
    vbe_outw(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
}

/* build standard RGB palette */
void vga_build_rgb_palette(void)
{
    static const uint8_t pal_value[6] = { 0x00, 0x33, 0x66, 0x99, 0xcc, 0xff };
    int i, r, g, b;

    i = 0;
    for(r = 0; r < 6; r++) {
        for(g = 0; g < 6; g++) {
            for(b = 0; b < 6; b++) {
                vga_set_palette(i, RGB(pal_value[r], pal_value[g], 
                                       pal_value[b]));
                i++;
            }
        }
    }
    for(i = 0; i < 256; i++) {
        rgb_to_index[i] = ((i * 5) + 128) / 255;
    }
}

void vga_set_address (uint32_t address)
{
    vga_fb_phys_addr = address;
}

/* depth = 8, 15, 16 or 32 */
void vga_set_mode(int width, int height, int depth)
{
    vbe_outw(VBE_DISPI_INDEX_XRES, width);
    vbe_outw(VBE_DISPI_INDEX_YRES, height);
    vbe_outw(VBE_DISPI_INDEX_BPP, depth);
    vbe_outw(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED);
    outb(0x3c0, 0x20); /* disable blanking */

    if (vga_fb_phys_addr == 0x00000000)
        vga_fb_phys_addr = VBE_DISPI_LFB_PHYSICAL_ADDRESS;
    vga_fb_width = width;
    vga_fb_height = height;
    vga_fb_depth = depth;
    vga_fb_bpp = (depth + 7) >> 3;
    vga_fb_linesize = width * vga_fb_bpp;
    
    if (depth == 8)
        vga_build_rgb_palette();
    vga_text_init();
}

/* for depth = 8 mode, set a hardware palette entry */
void vga_set_palette(int i, unsigned int rgba)
{
    unsigned int r, g, b;

    r = (rgba >> 16) & 0xff;
    g = (rgba >> 8) & 0xff;
    b = (rgba) & 0xff;
    outb(0x3c8, i);
    outb(0x3c9, r >> 2);
    outb(0x3c9, g >> 2);
    outb(0x3c9, b >> 2);
}

/* convert a RGBA color to a color index usable in graphic primitives */
unsigned int vga_get_color(unsigned int rgba)
{
    unsigned int r, g, b, color;

    switch(vga_fb_depth) {
    case 8:
        r = (rgba >> 16) & 0xff;
        g = (rgba >> 8) & 0xff;
        b = (rgba) & 0xff;
        color = (rgb_to_index[r] * 6 * 6) + 
            (rgb_to_index[g] * 6) + 
            (rgb_to_index[b]);
        break;
    case 15:
        r = (rgba >> 16) & 0xff;
        g = (rgba >> 8) & 0xff;
        b = (rgba) & 0xff;
        color = ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3);
        break;
    case 16:
        r = (rgba >> 16) & 0xff;
        g = (rgba >> 8) & 0xff;
        b = (rgba) & 0xff;
        color = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
        break;
    case 32:
    default:
        color = rgba;
        break;
    }
    return color;
}

void vga_draw_buf (const void *buf, int buf_linesize,
                   int posx, int posy, int width, int height)
{
    const uint8_t *s;
    uint8_t *d;
    int y, wb;
    
    s = buf;
    d = (uint8_t *)vga_fb_phys_addr + 
        vga_fb_linesize * posy + vga_fb_bpp * posx;
    wb = width * vga_fb_bpp;
    for (y = 0; y < height; y++) {
        memcpy(d, s, wb);
        s += buf_linesize;
        d += vga_fb_linesize;
    }
}

void vga_fill_rect (int posx, int posy, int width, int height, uint32_t color)
{
    uint8_t *d, *d1;
    int x, y;
    
    d1 = (uint8_t *)vga_fb_phys_addr + 
        vga_fb_linesize * posy + vga_fb_bpp * posx;
    for (y = 0; y < height; y++) {
        d = d1;
        switch(vga_fb_bpp) {
        case 1:
            for (x = 0; x < width; x++) {
                *((uint8_t *)d) = color;
                d++;
            }
            break;
        case 2:
            for (x = 0; x < width; x++) {
                *((uint16_t *)d) = color;
                d += 2;
            }
            break;
        case 4:
            for (x = 0; x < width; x++) {
                *((uint32_t *)d) = color;
                d += 4;
            }
            break;
        }
        d1 += vga_fb_linesize;
    }
}

/* copy from (xs, ys) to (xd, yd) a rectangle of size (w, h) */
void vga_bitblt(int xs, int ys, int xd, int yd, int w, int h)
{
    const uint8_t *s;
    uint8_t *d;
    int wb, y;

    wb = w * vga_fb_bpp;
    if (yd <= ys) {
        s = (uint8_t *)vga_fb_phys_addr + 
            vga_fb_linesize * ys + vga_fb_bpp * xs;
        d = (uint8_t *)vga_fb_phys_addr + 
            vga_fb_linesize * yd + vga_fb_bpp * xd;
        for (y = 0; y < h; y++) {
            memmove(d, s, wb);
            d += vga_fb_linesize;
            s += vga_fb_linesize;
        }
    } else {
        s = (uint8_t *)vga_fb_phys_addr + 
            vga_fb_linesize * (ys + h - 1) + vga_fb_bpp * xs;
        d = (uint8_t *)vga_fb_phys_addr + 
            vga_fb_linesize * (yd + h - 1) + vga_fb_bpp * xd;
       for (y = 0; y < h; y++) {
            memmove(d, s, wb);
            d -= vga_fb_linesize;
            s -= vga_fb_linesize;
        }
    }
}

/***********************************************************/
/* basic char display */

#define FONT_HEIGHT 16
#define FONT_WIDTH 8

#include "vgafont.h"

#define cbswap_32(__x) \
((uint32_t)( \
		(((uint32_t)(__x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(__x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(__x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(__x) & (uint32_t)0xff000000UL) >> 24) ))

/* XXX: endianness */
#if 0
#define PAT(x) cbswap_32(x)
#else
#define PAT(x) x
#endif

static const uint32_t dmask16[16] = {
    PAT(0x00000000),
    PAT(0x000000ff),
    PAT(0x0000ff00),
    PAT(0x0000ffff),
    PAT(0x00ff0000),
    PAT(0x00ff00ff),
    PAT(0x00ffff00),
    PAT(0x00ffffff),
    PAT(0xff000000),
    PAT(0xff0000ff),
    PAT(0xff00ff00),
    PAT(0xff00ffff),
    PAT(0xffff0000),
    PAT(0xffff00ff),
    PAT(0xffffff00),
    PAT(0xffffffff),
};

static const uint32_t dmask4[4] = {
    PAT(0x00000000),
    PAT(0x0000ffff),
    PAT(0xffff0000),
    PAT(0xffffffff),
};

int text_width, text_height, text_fgcol, text_bgcol, text_x, text_y;

static void vga_text_init(void)
{
    text_width = vga_fb_width / FONT_WIDTH;
    text_height = vga_fb_height / FONT_HEIGHT;
    text_x = 0;
    text_y = 0;
    vga_text_set_fgcol(RGB(0xff, 0xff, 0xff));
    vga_text_set_bgcol(RGB(0x00, 0x00, 0x00));
}

static inline unsigned int col_expand(unsigned int col)
{
    switch(vga_fb_bpp) {
    case 1:
        col |= col << 8;
        col |= col << 16;
        break;
    case 2:
        col |= col << 16;
        break;
    default:
        text_fgcol = 0xffffff;
        break;
    }

    return col;
}

void vga_text_set_fgcol(unsigned int rgba)
{
    text_fgcol = col_expand(vga_get_color(rgba));
}

void vga_text_set_bgcol(unsigned int rgba)
{
    text_bgcol = col_expand(vga_get_color(rgba));
}

void vga_putcharxy(int x, int y, int ch, 
                   unsigned int fgcol, unsigned int bgcol)
{
    uint8_t *d;
    const uint8_t *font_ptr;
    unsigned int font_data, linesize, xorcol;
    int i;

    d = (uint8_t *)vga_fb_phys_addr + 
        vga_fb_linesize * y * FONT_HEIGHT + vga_fb_bpp * x * FONT_WIDTH;
    linesize = vga_fb_linesize;
    font_ptr = vgafont16 + FONT_HEIGHT * ch;
    xorcol = bgcol ^ fgcol;
    switch(vga_fb_depth) {
    case 8:
        for(i = 0; i < FONT_HEIGHT; i++) {
            font_data = *font_ptr++;
            ((uint32_t *)d)[0] = (dmask16[(font_data >> 4)] & xorcol) ^ bgcol;
            ((uint32_t *)d)[1] = (dmask16[(font_data >> 0) & 0xf] & xorcol) ^ bgcol;
            d += linesize;
        }
        break;
    case 16:
    case 15:
        for(i = 0; i < FONT_HEIGHT; i++) {
            font_data = *font_ptr++;
            ((uint32_t *)d)[0] = (dmask4[(font_data >> 6)] & xorcol) ^ bgcol;
            ((uint32_t *)d)[1] = (dmask4[(font_data >> 4) & 3] & xorcol) ^ bgcol;
            ((uint32_t *)d)[2] = (dmask4[(font_data >> 2) & 3] & xorcol) ^ bgcol;
            ((uint32_t *)d)[3] = (dmask4[(font_data >> 0) & 3] & xorcol) ^ bgcol;
            d += linesize;
        }
        break;
    case 32:
        for(i = 0; i < FONT_HEIGHT; i++) {
            font_data = *font_ptr++;
            ((uint32_t *)d)[0] = (-((font_data >> 7)) & xorcol) ^ bgcol;
            ((uint32_t *)d)[1] = (-((font_data >> 6) & 1) & xorcol) ^ bgcol;
            ((uint32_t *)d)[2] = (-((font_data >> 5) & 1) & xorcol) ^ bgcol;
            ((uint32_t *)d)[3] = (-((font_data >> 4) & 1) & xorcol) ^ bgcol;
            ((uint32_t *)d)[4] = (-((font_data >> 3) & 1) & xorcol) ^ bgcol;
            ((uint32_t *)d)[5] = (-((font_data >> 2) & 1) & xorcol) ^ bgcol;
            ((uint32_t *)d)[6] = (-((font_data >> 1) & 1) & xorcol) ^ bgcol;
            ((uint32_t *)d)[7] = (-((font_data >> 0) & 1) & xorcol) ^ bgcol;
            d += linesize;
        }
        break;
    }
}

static void vga_put_lf(void)
{
    text_x = 0;
    text_y++;
    if (text_y >= text_height) {
        text_y = text_height - 1;
        vga_bitblt(0, FONT_HEIGHT, 0, 0, 
                   text_width * FONT_WIDTH, 
                   (text_height - 1) * FONT_HEIGHT);
        vga_fill_rect(0, (text_height - 1) * FONT_HEIGHT,
                      text_width * FONT_WIDTH, FONT_HEIGHT, text_bgcol);
    }
}

void vga_putchar(int ch)
{
    if (ch == '\r') {
        text_x = 0;
    } else if (ch == '\n') {
        vga_put_lf();
    } else if (ch == '\b') {
        if (text_x == 0) {
            if (text_y != 0) {
                text_x = text_width;
                text_y--;
                goto eat_char;
            }
        } else {
        eat_char:
            vga_putcharxy(--text_x, text_y, ' ', text_fgcol, text_bgcol);
        }
    } else {
        vga_putcharxy(text_x, text_y, ch, text_fgcol, text_bgcol);
        text_x++;
        if (text_x >= text_width)
            vga_put_lf();
    }
}

void vga_puts(const char *s)
{
    while (*s) {
        vga_putchar(*(uint8_t *)s);
        s++;
    }
}
