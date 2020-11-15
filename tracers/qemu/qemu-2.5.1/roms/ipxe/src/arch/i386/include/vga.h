/*
 *
 * modified
 * by Steve M. Gehlbach <steve@kesa.com>
 *
 * Originally  from linux/drivers/video/vga16.c by
 * Ben Pfaff <pfaffben@debian.org> and Petr Vandrovec <VANDROVE@vc.cvut.cz>
 * Copyright 1999 Ben Pfaff <pfaffben@debian.org> and Petr Vandrovec <VANDROVE@vc.cvut.cz>
 * Based on VGA info at http://www.goodnet.com/~tinara/FreeVGA/home.htm
 * Based on VESA framebuffer (c) 1998 Gerd Knorr <kraxel@goldbach.in-berlin.de>
 *
 */ 

#ifndef VGA_H_INCL
#define VGA_H_INCL 1

//#include <cpu/p5/io.h>

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define __u32 u32

#define VERROR -1
#define CHAR_HEIGHT 16
#define LINES 25
#define COLS 80

// macros for writing to vga regs
#define write_crtc(data,addr) outb(addr,CRT_IC); outb(data,CRT_DC)
#define write_att(data,addr) inb(IS1_RC); inb(0x80); outb(addr,ATT_IW); inb(0x80); outb(data,ATT_IW); inb(0x80)
#define write_seq(data,addr) outb(addr,SEQ_I); outb(data,SEQ_D)
#define write_gra(data,addr) outb(addr,GRA_I); outb(data,GRA_D)
u8 read_seq_b(u16 addr);
u8 read_gra_b(u16 addr);
u8 read_crtc_b(u16 addr);
u8 read_att_b(u16 addr);


#ifdef VGA_HARDWARE_FIXUP
void vga_hardware_fixup(void);
#else
#define vga_hardware_fixup() do{} while(0)
#endif

#define SYNC_HOR_HIGH_ACT    1       /* horizontal sync high active  */
#define SYNC_VERT_HIGH_ACT   2       /* vertical sync high active    */
#define SYNC_EXT             4       /* external sync                */
#define SYNC_COMP_HIGH_ACT   8       /* composite sync high active   */
#define SYNC_BROADCAST       16      /* broadcast video timings      */
                                        /* vtotal = 144d/288n/576i => PAL  */
                                        /* vtotal = 121d/242n/484i => NTSC */

#define SYNC_ON_GREEN        32      /* sync on green */

#define VMODE_NONINTERLACED  0       /* non interlaced */
#define VMODE_INTERLACED     1       /* interlaced   */
#define VMODE_DOUBLE         2       /* double scan */
#define VMODE_MASK           255

#define VMODE_YWRAP          256     /* ywrap instead of panning     */
#define VMODE_SMOOTH_XPAN    512     /* smooth xpan possible (internally used) */
#define VMODE_CONUPDATE      512     /* don't update x/yoffset       */

/* VGA data register ports */
#define CRT_DC  0x3D5           /* CRT Controller Data Register - color emulation */
#define CRT_DM  0x3B5           /* CRT Controller Data Register - mono emulation */
#define ATT_R   0x3C1           /* Attribute Controller Data Read Register */
#define GRA_D   0x3CF           /* Graphics Controller Data Register */
#define SEQ_D   0x3C5           /* Sequencer Data Register */

#define MIS_R   0x3CC           // Misc Output Read Register
#define MIS_W   0x3C2           // Misc Output Write Register

#define IS1_RC  0x3DA           /* Input Status Register 1 - color emulation */
#define IS1_RM  0x3BA           /* Input Status Register 1 - mono emulation */
#define PEL_D   0x3C9           /* PEL Data Register */
#define PEL_MSK 0x3C6           /* PEL mask register */

/* EGA-specific registers */
#define GRA_E0  0x3CC           /* Graphics enable processor 0 */
#define GRA_E1  0x3CA           /* Graphics enable processor 1 */


/* VGA index register ports */
#define CRT_IC  0x3D4           /* CRT Controller Index - color emulation */
#define CRT_IM  0x3B4           /* CRT Controller Index - mono emulation */
#define ATT_IW  0x3C0           /* Attribute Controller Index & Data Write Register */
#define GRA_I   0x3CE           /* Graphics Controller Index */
#define SEQ_I   0x3C4           /* Sequencer Index */
#define PEL_IW  0x3C8           /* PEL Write Index */
#define PEL_IR  0x3C7           /* PEL Read Index */

/* standard VGA indexes max counts */
#define CRTC_C   25              /* 25 CRT Controller Registers sequentially set*/
								 // the remainder are not in the par array
#define ATT_C   21              /* 21 Attribute Controller Registers */
#define GRA_C   9               /* 9  Graphics Controller Registers */
#define SEQ_C   5               /* 5  Sequencer Registers */
#define MIS_C   1               /* 1  Misc Output Register */

#define CRTC_H_TOTAL            0
#define CRTC_H_DISP             1
#define CRTC_H_BLANK_START      2
#define CRTC_H_BLANK_END        3
#define CRTC_H_SYNC_START       4
#define CRTC_H_SYNC_END         5
#define CRTC_V_TOTAL            6
#define CRTC_OVERFLOW           7
#define CRTC_PRESET_ROW         8
#define CRTC_MAX_SCAN           9
#define CRTC_CURSOR_START       0x0A
#define CRTC_CURSOR_END         0x0B
#define CRTC_START_HI           0x0C
#define CRTC_START_LO           0x0D
#define CRTC_CURSOR_HI          0x0E
#define CRTC_CURSOR_LO          0x0F
#define CRTC_V_SYNC_START       0x10
#define CRTC_V_SYNC_END         0x11
#define CRTC_V_DISP_END         0x12
#define CRTC_OFFSET             0x13
#define CRTC_UNDERLINE          0x14
#define CRTC_V_BLANK_START      0x15
#define CRTC_V_BLANK_END        0x16
#define CRTC_MODE               0x17
#define CRTC_LINE_COMPARE       0x18

#define ATC_MODE                0x10
#define ATC_OVERSCAN            0x11
#define ATC_PLANE_ENABLE        0x12
#define ATC_PEL                 0x13
#define ATC_COLOR_PAGE          0x14

#define SEQ_CLOCK_MODE          0x01
#define SEQ_PLANE_WRITE         0x02
#define SEQ_CHARACTER_MAP       0x03
#define SEQ_MEMORY_MODE         0x04

#define GDC_SR_VALUE            0x00
#define GDC_SR_ENABLE           0x01
#define GDC_COMPARE_VALUE       0x02
#define GDC_DATA_ROTATE         0x03
#define GDC_PLANE_READ          0x04
#define GDC_MODE                0x05
#define GDC_MISC                0x06
#define GDC_COMPARE_MASK        0x07
#define GDC_BIT_MASK            0x08

// text attributes
#define VGA_ATTR_CLR_RED 0x4
#define VGA_ATTR_CLR_GRN 0x2
#define VGA_ATTR_CLR_BLU 0x1
#define VGA_ATTR_CLR_YEL (VGA_ATTR_CLR_RED | VGA_ATTR_CLR_GRN)
#define VGA_ATTR_CLR_CYN (VGA_ATTR_CLR_GRN | VGA_ATTR_CLR_BLU)
#define VGA_ATTR_CLR_MAG (VGA_ATTR_CLR_BLU | VGA_ATTR_CLR_RED)
#define VGA_ATTR_CLR_BLK 0
#define VGA_ATTR_CLR_WHT (VGA_ATTR_CLR_RED | VGA_ATTR_CLR_GRN | VGA_ATTR_CLR_BLU)
#define VGA_ATTR_BNK     0x80
#define VGA_ATTR_ITN     0x08

/*
 * vga register parameters
 * these are copied to the 
 * registers.
 *
 */
struct vga_par {
        u8 crtc[CRTC_C];
        u8 atc[ATT_C];
        u8 gdc[GRA_C];
        u8 seq[SEQ_C];
        u8 misc; // the misc register, MIS_W
        u8 vss;
};


/* Interpretation of offset for color fields: All offsets are from the right,
 * inside a "pixel" value, which is exactly 'bits_per_pixel' wide (means: you
 * can use the offset as right argument to <<). A pixel afterwards is a bit
 * stream and is written to video memory as that unmodified. This implies
 * big-endian byte order if bits_per_pixel is greater than 8.
 */
struct fb_bitfield {
        __u32 offset;                   /* beginning of bitfield        */
        __u32 length;                   /* length of bitfield           */
        __u32 msb_right;                /* != 0 : Most significant bit is */ 
                                        /* right */ 
};

struct screeninfo {
        __u32 xres;                     /* visible resolution           */
        __u32 yres;
        __u32 xres_virtual;             /* virtual resolution           */
        __u32 yres_virtual;
        __u32 xoffset;                  /* offset from virtual to visible */
        __u32 yoffset;                  /* resolution                   */

        __u32 bits_per_pixel;           /* guess what                   */
        __u32 grayscale;                /* != 0 Graylevels instead of colors */

        struct fb_bitfield red;         /* bitfield in fb mem if true color, */
        struct fb_bitfield green;       /* else only length is significant */
        struct fb_bitfield blue;
        struct fb_bitfield transp;      /* transparency                 */      

        __u32 nonstd;                   /* != 0 Non standard pixel format */

        __u32 activate;                 /* see FB_ACTIVATE_*            */

        __u32 height;                   /* height of picture in mm    */
        __u32 width;                    /* width of picture in mm     */

        __u32 accel_flags;              /* acceleration flags (hints)   */

        /* Timing: All values in pixclocks, except pixclock (of course) */
        __u32 pixclock;                 /* pixel clock in ps (pico seconds) */
        __u32 left_margin;              /* time from sync to picture    */
        __u32 right_margin;             /* time from picture to sync    */
        __u32 upper_margin;             /* time from sync to picture    */
        __u32 lower_margin;
        __u32 hsync_len;                /* length of horizontal sync    */
        __u32 vsync_len;                /* length of vertical sync      */
        __u32 sync;                     /* sync polarity                */
        __u32 vmode;                    /* interlaced etc				*/
        __u32 reserved[6];              /* Reserved for future compatibility */
};

#endif
