#ifndef __VGABIOS_H
#define __VGABIOS_H

#include "config.h" // CONFIG_VGA_EMULATE_TEXT
#include "types.h" // u8
#include "farptr.h" // struct segoff_s
#include "std/vga.h" // struct video_param_s

// Save/Restore flags
#define SR_HARDWARE   0x0001
#define SR_BDA        0x0002
#define SR_DAC        0x0004
#define SR_REGISTERS  0x0008
#define SR_SAVE       0x0100
#define SR_RESTORE    0x0200

// Mode flags
#define MF_LEGACY     0x0001
#define MF_GRAYSUM    0x0002
#define MF_NOPALETTE  0x0008
#define MF_CUSTOMCRTC 0x0800
#define MF_LINEARFB   0x4000
#define MF_NOCLEARMEM 0x8000
#define MF_VBEFLAGS   0xfe00

// Memory model types
#define MM_TEXT            0x00
#define MM_CGA             0x01
#define MM_HERCULES        0x02
#define MM_PLANAR          0x03
#define MM_PACKED          0x04
#define MM_NON_CHAIN_4_256 0x05
#define MM_DIRECT          0x06
#define MM_YUV             0x07

struct vgamode_s {
    u8 memmodel;
    u16 width;
    u16 height;
    u8 depth;
    u8 cwidth;
    u8 cheight;
    u16 sstart;
};

// Graphics pixel operations.
struct gfx_op {
    struct vgamode_s *vmode_g;
    u32 linelength;
    u32 displaystart;

    u8 op;
    u16 x, y;

    u8 pixels[8];
    u16 xlen, ylen;
    u16 srcy;
};

#define GO_READ8   1
#define GO_WRITE8  2
#define GO_MEMSET  3
#define GO_MEMMOVE 4

// Custom internal storage in BDA
#define VGA_CUSTOM_BDA 0xb9

struct vga_bda_s {
    u8 flags;
    u16 vbe_mode;
    u16 vgamode_offset;
} PACKED;

#define BF_PM_MASK      0x0f
#define BF_EMULATE_TEXT 0x10
#define BF_SWCURSOR     0x20

#define GET_BDA_EXT(var) \
    GET_FARVAR(SEG_BDA, ((struct vga_bda_s *)VGA_CUSTOM_BDA)->var)
#define SET_BDA_EXT(var, val) \
    SET_FARVAR(SEG_BDA, ((struct vga_bda_s *)VGA_CUSTOM_BDA)->var, (val))
#define MASK_BDA_EXT(var, off, on)                                      \
    SET_BDA_EXT(var, (GET_BDA_EXT(var) & ~(off)) | (on))

static inline int vga_emulate_text(void) {
    return CONFIG_VGA_EMULATE_TEXT && GET_BDA_EXT(flags) & BF_EMULATE_TEXT;
}

// Debug settings
#define DEBUG_VGA_POST 1
#define DEBUG_VGA_10 3

// vgafonts.c
extern u8 vgafont8[];
extern u8 vgafont14[];
extern u8 vgafont16[];
extern u8 vgafont14alt[];
extern u8 vgafont16alt[];

// vgainit.c
extern struct video_save_pointer_s video_save_pointer_table;
extern struct video_param_s video_param_table[29];

// vgabios.c
extern int VgaBDF;
extern int HaveRunInit;
#define SET_VGA(var, val) SET_FARVAR(get_global_seg(), (var), (val))
struct carattr {
    u8 car, attr, use_attr, pad;
};
struct cursorpos {
    u8 x, y, page, pad;
};
int vga_bpp(struct vgamode_s *vmode_g);
u16 calc_page_size(u8 memmodel, u16 width, u16 height);
u16 get_cursor_shape(void);
struct cursorpos get_cursor_pos(u8 page);
int bda_save_restore(int cmd, u16 seg, void *data);
struct vgamode_s *get_current_mode(void);
int vga_set_mode(int mode, int flags);
extern struct video_func_static static_functionality;

// vgafb.c
void init_gfx_op(struct gfx_op *op, struct vgamode_s *vmode_g);
void handle_gfx_op(struct gfx_op *op);
void *text_address(struct cursorpos cp);
void vgafb_move_chars(struct cursorpos dest
                      , struct cursorpos src, struct cursorpos movesize);
void vgafb_clear_chars(struct cursorpos dest
                       , struct carattr ca, struct cursorpos movesize);
void vgafb_write_char(struct cursorpos cp, struct carattr ca);
struct carattr vgafb_read_char(struct cursorpos cp);
void vgafb_write_pixel(u8 color, u16 x, u16 y);
u8 vgafb_read_pixel(u16 x, u16 y);
void vgafb_set_swcursor(int enable);

// vbe.c
extern u32 VBE_total_memory;
extern u32 VBE_capabilities;
extern u32 VBE_framebuffer;
extern u16 VBE_win_granularity;
#define VBE_OEM_STRING "SeaBIOS VBE(C) 2011"
#define VBE_VENDOR_STRING "SeaBIOS Developers"
#define VBE_PRODUCT_STRING "SeaBIOS VBE Adapter"
#define VBE_REVISION_STRING "Rev. 1"
struct bregs;
void handle_104f(struct bregs *regs);

#endif // vgabios.h
