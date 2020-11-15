/* VGA register definitions

   This file is copied (somewhat) intact from SeaBIOS.
   It is covered by the GNU Lesser General Public License, v3.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

#ifndef VGATABLES_H
#define VGATABLES_H

typedef uint8_t u8;
typedef uint16_t u16;


/*
 *
 * VGA registers
 *
 */
#define VGAREG_ACTL_ADDRESS            0x3c0
#define VGAREG_ACTL_WRITE_DATA         0x3c0
#define VGAREG_ACTL_READ_DATA          0x3c1

#define VGAREG_INPUT_STATUS            0x3c2
#define VGAREG_WRITE_MISC_OUTPUT       0x3c2
#define VGAREG_VIDEO_ENABLE            0x3c3
#define VGAREG_SEQU_ADDRESS            0x3c4
#define VGAREG_SEQU_DATA               0x3c5

#define VGAREG_PEL_MASK                0x3c6
#define VGAREG_DAC_STATE               0x3c7
#define VGAREG_DAC_READ_ADDRESS        0x3c7
#define VGAREG_DAC_WRITE_ADDRESS       0x3c8
#define VGAREG_DAC_DATA                0x3c9

#define VGAREG_READ_FEATURE_CTL        0x3ca
#define VGAREG_READ_MISC_OUTPUT        0x3cc

#define VGAREG_GRDC_ADDRESS            0x3ce
#define VGAREG_GRDC_DATA               0x3cf

#define VGAREG_MDA_CRTC_ADDRESS        0x3b4
#define VGAREG_MDA_CRTC_DATA           0x3b5
#define VGAREG_VGA_CRTC_ADDRESS        0x3d4
#define VGAREG_VGA_CRTC_DATA           0x3d5

#define VGAREG_MDA_WRITE_FEATURE_CTL   0x3ba
#define VGAREG_VGA_WRITE_FEATURE_CTL   0x3da
#define VGAREG_ACTL_RESET              0x3da

#define VGAREG_MDA_MODECTL             0x3b8
#define VGAREG_CGA_MODECTL             0x3d8
#define VGAREG_CGA_PALETTE             0x3d9

/* Video memory */
#define SEG_GRAPH                      0xA000
#define SEG_CTEXT                      0xB800
#define SEG_MTEXT                      0xB000

/*
 * Tables of default values for each mode
 */
#define TEXT       0x80

#define CTEXT      (0x00 | TEXT)
#define MTEXT      (0x01 | TEXT)
#define CGA        0x02
#define PLANAR1    0x03
#define PLANAR4    0x04
#define LINEAR8    0x05

// for SVGA
#define LINEAR15   0x10
#define LINEAR16   0x11
#define LINEAR24   0x12
#define LINEAR32   0x13

#define SCREEN_IO_START(x,y,p) (((((x)*(y)) | 0x00ff) + 1) * (p))
#define SCREEN_MEM_START(x,y,p) SCREEN_IO_START(((x)*2),(y),(p))

/* standard BIOS Video Parameter Table */
struct __attribute__((packed)) VideoParam_s {
    u8 twidth;
    u8 theightm1;
    u8 cheight;
    u16 slength;
    u8 sequ_regs[4];
    u8 miscreg;
    u8 crtc_regs[25];
    u8 actl_regs[20];
    u8 grdc_regs[9];
};

struct vgamode_s {
    u8 svgamode;
    struct VideoParam_s *vparam;
    u8 memmodel;    /* CTEXT,MTEXT,CGA,PL1,PL2,PL4,P8,P15,P16,P24,P32 */
    u8 pixbits;
    u16 sstart;
    u8 pelmask;
    u8 *dac;
    u16 dacsize;
};

struct saveVideoHardware {
    u8 sequ_index;
    u8 crtc_index;
    u8 grdc_index;
    u8 actl_index;
    u8 feature;
    u8 sequ_regs[4];
    u8 sequ0;
    u8 crtc_regs[25];
    u8 actl_regs[20];
    u8 grdc_regs[9];
    u16 crtc_addr;
    u8 plane_latch[4];
};

struct saveBDAstate {
    u8 video_mode;
    u16 video_cols;
    u16 video_pagesize;
    u16 crtc_address;
    u8 video_rows;
    u16 char_height;
    u8 video_ctl;
    u8 video_switches;
    u8 modeset_ctl;
    u16 cursor_type;
    u16 cursor_pos[8];
    u16 video_pagestart;
    u8 video_page;
#if 0
    /* current font */
    struct segoff_s font0;
    struct segoff_s font1;
#endif
};

struct saveDACcolors {
    u8 rwmode;
    u8 peladdr;
    u8 pelmask;
    u8 dac[768];
    u8 color_select;
};

// vgatables.c
struct vgamode_s *find_vga_entry(u8 mode);
extern u16 video_save_pointer_table[];
extern struct VideoParam_s video_param_table[];
extern u8 static_functionality[];

// vgafonts.c
extern const u8 vgafont8[];
extern const u8 vgafont14[];
extern const u8 vgafont16[];
extern const u8 vgafont14alt[];
extern const u8 vgafont16alt[];

// vga.c
struct carattr {
    u8 car, attr, use_attr;
};
struct cursorpos {
    u8 x, y, page;
};

// vgafb.c
void clear_screen(struct vgamode_s *vmode_g);
void vgafb_scroll(int nblines, int attr
                  , struct cursorpos ul, struct cursorpos lr);
void vgafb_write_char(struct cursorpos cp, struct carattr ca);
struct carattr vgafb_read_char(struct cursorpos cp);
void vgafb_write_pixel(u8 color, u16 x, u16 y);
u8 vgafb_read_pixel(u16 x, u16 y);
void vgafb_load_font(u16 seg, void *src_far, u16 count
                     , u16 start, u8 destflags, u8 fontsize);

// vgaio.c
void vgahw_screen_disable(void);
void vgahw_screen_enable(void);
void vgahw_set_border_color(u8 color);
void vgahw_set_overscan_border_color(u8 color);
u8 vgahw_get_overscan_border_color(void);
void vgahw_set_palette(u8 palid);
void vgahw_set_single_palette_reg(u8 reg, u8 val);
u8 vgahw_get_single_palette_reg(u8 reg);
void vgahw_set_all_palette_reg(u8 *data);
void vgahw_get_all_palette_reg(u8 *data);
void vgahw_toggle_intensity(u8 flag);
void vgahw_select_video_dac_color_page(u8 flag, u8 data);
void vgahw_read_video_dac_state(u8 *pmode, u8 *curpage);
void vgahw_set_dac_regs(u8 *data, u8 start, int count);
void vgahw_get_dac_regs(u8 *data, u8 start, int count);
void vgahw_set_pel_mask(u8 val);
u8 vgahw_get_pel_mask(void);
void vgahw_save_dac_state(struct saveDACcolors *info);
void vgahw_restore_dac_state(struct saveDACcolors *info);
void vgahw_sequ_write(u8 index, u8 value);
void vgahw_grdc_write(u8 index, u8 value);
void vgahw_set_text_block_specifier(u8 spec);
void get_font_access(void);
void release_font_access(void);
void vgahw_set_cursor_shape(u8 start, u8 end);
void vgahw_set_active_page(u16 address);
void vgahw_set_cursor_pos(u16 address);
void vgahw_set_scan_lines(u8 lines);
u16 vgahw_get_vde(void);
void vgahw_save_state(struct saveVideoHardware *info);
void vgahw_restore_state(struct saveVideoHardware *info);
void vgahw_set_mode(struct VideoParam_s *vparam_g);
void vgahw_enable_video_addressing(u8 disable);
void vgahw_init(void);

// clext.c
void cirrus_set_video_mode(u8 mode);
void cirrus_init(void);

#endif // vgatables.h
