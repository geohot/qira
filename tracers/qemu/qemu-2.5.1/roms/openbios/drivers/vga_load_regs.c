#include "asm/io.h"
#include "drivers/vga.h"
#include "vga.h"

/*
 * $Id$
 * $Source$
 *
 * from the Linux kernel code base.
 * orig by  Ben Pfaff and Petr Vandrovec.
 *
 * modified by
 * Steve M. Gehlbach <steve@kesa.com>
 *
 * NOTE: to change the horiz and vertical pixels,
 *       change the xres,yres,xres_virt,yres_virt setting
 *       in the screeninfo structure below.  You may also need
 *       to change the border settings as well.
 *
 * Convert the screeninfo structure to data for
 * writing to the vga registers
 *
 */

// prototypes
static int vga_decode_var(const struct screeninfo *var, struct vga_par *par);
static int vga_set_regs(const struct vga_par *par);

u8 read_seq_b(u16 addr) {
	outb(addr,SEQ_I);
	return inb(SEQ_D);
}
u8 read_gra_b(u16 addr) {
	outb(addr,GRA_I);
	return inb(GRA_D);
}
u8 read_crtc_b(u16 addr) {
	outb(addr,CRT_IC);
	return inb(CRT_DC);
}
u8 read_att_b(u16 addr) {
	inb(IS1_RC);
	inb(0x80);
	outb(addr,ATT_IW);
	return inb(ATT_R);
}


/*
From: The Frame Buffer Device
by Geert Uytterhoeven <geert@linux-m68k.org>
in the linux kernel docs.

The following picture summarizes all timings. The horizontal retrace time is
the sum of the left margin, the right margin and the hsync length, while the
vertical retrace time is the sum of the upper margin, the lower margin and the
vsync length.

  +----------+---------------------------------------------+----------+-------+
  |          |                ^                            |          |       |
  |          |                |upper_margin                |          |       |
  |          |                |                            |          |       |
  +----------###############################################----------+-------+
  |          #                ^                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |   left   #                |                            #  right   | hsync |
  |  margin  #                |       xres                 #  margin  |  len  |
  |<-------->#<---------------+--------------------------->#<-------->|<----->|
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |yres                        #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  |          #                |                            #          |       |
  +----------###############################################----------+-------+
  |          |                ^                            |          |       |
  |          |                |lower_margin                |          |       |
  |          |                |                            |          |       |
  +----------+---------------------------------------------+----------+-------+
  |          |                ^                            |          |       |
  |          |                |vsync_len                   |          |       |
  |          |                |                            |          |       |
  +----------+---------------------------------------------+----------+-------+

All horizontal timings are in number of dotclocks
(in picoseconds, 1E-12 s), and vertical timings in number of scanlines.

The vga uses the following fields:

  - pixclock: pixel clock in ps (pico seconds)
  - xres,yres,xres_v,yres_v
  - left_margin: time from sync to picture
  - right_margin: time from picture to sync
  - upper_margin: time from sync to picture
  - lower_margin: time from picture to sync
  - hsync_len: length of horizontal sync
  - vsync_len: length of vertical sync

*/

/* our display parameters per the above */

static const struct screeninfo vga_settings = {
        640,400,640,400,/* xres,yres,xres_virt,yres_virt */
        0,0,            /* xoffset,yoffset */
        4,              /* bits_per_pixel NOT USED*/
        0,              /* greyscale ? */
        {0,0,0},        /* R */
        {0,0,0},        /* G */
        {0,0,0},        /* B */
        {0,0,0},        /* transparency */
        0,              /* standard pixel format */
        0,				// activate now
        -1,-1,	// height and width in mm
        0,	// accel flags
        39721, 	// pixclock: 79442 -> 12.587 Mhz (NOT USED)
		//  70616 -> 14.161
		//  39721 -> 25.175
		//  35308 -> 28.322

	48, 16, 39, 8, 	// margins left,right,upper,lower
        96, 	// hsync length
	2,	// vsync length
	0,      // sync polarity
        0,	// non interlaced, single mode
        {0,0,0,0,0,0}	// compatibility
};

// ALPHA-MODE
// Hard coded to BIOS VGA mode 3 (alpha color text)
// screen size settable in screeninfo structure

static int vga_decode_var(const struct screeninfo *var,
                              struct vga_par *par)
{
	u8 VgaAttributeTable[16] =
	{ 0x000, 0x001, 0x002, 0x003, 0x004, 0x005, 0x014, 0x007, 0x038, 0x039, 0x03A, 0x03B, 0x03C, 0x03D, 0x03E, 0x03F};

        u32 xres, right, hslen, left, xtotal;
        u32 yres, lower, vslen, upper, ytotal;
        u32 vxres, xoffset, vyres, yoffset;
        u32 pos;
        u8 r7, rMode;
        int i;

        xres = (var->xres + 7) & ~7;
        vxres = (var->xres_virtual + 0xF) & ~0xF;
        xoffset = (var->xoffset + 7) & ~7;
        left = (var->left_margin + 7) & ~7;
        right = (var->right_margin + 7) & ~7;
        hslen = (var->hsync_len + 7) & ~7;

        if (vxres < xres)
                vxres = xres;
        if (xres + xoffset > vxres)
                xoffset = vxres - xres;

        xres >>= 3;
        right >>= 3;
        hslen >>= 3;
        left >>= 3;
        vxres >>= 3;
        xtotal = xres + right + hslen + left;
        if (xtotal >= 256)
                return VERROR; //xtotal too big
        if (hslen > 32)
                return VERROR; //hslen too big
        if (right + hslen + left > 64)
                return VERROR; //hblank too big
        par->crtc[CRTC_H_TOTAL] = xtotal - 5;
        par->crtc[CRTC_H_BLANK_START] = xres - 1;
        par->crtc[CRTC_H_DISP] = xres - 1;
        pos = xres + right;
        par->crtc[CRTC_H_SYNC_START] = pos;
        pos += hslen;
        par->crtc[CRTC_H_SYNC_END] = (pos & 0x1F) | 0x20 ; //<--- stpc text mode p178
        pos += left - 2; /* blank_end + 2 <= total + 5 */
        par->crtc[CRTC_H_BLANK_END] = (pos & 0x1F) | 0x80;
        if (pos & 0x20)
                par->crtc[CRTC_H_SYNC_END] |= 0x80;

        yres = var->yres;
        lower = var->lower_margin;
        vslen = var->vsync_len;
        upper = var->upper_margin;
        vyres = var->yres_virtual;
        yoffset = var->yoffset;

        if (yres > vyres)
                vyres = yres;
        if (vxres * vyres > 65536) {
                vyres = 65536 / vxres;
                if (vyres < yres)
                        return VERROR;  // out of memory
        }
        if (yoffset + yres > vyres)
                yoffset = vyres - yres;

        if (var->vmode & VMODE_DOUBLE) {
                yres <<= 1;
                lower <<= 1;
                vslen <<= 1;
                upper <<= 1;
        }
        ytotal = yres + lower + vslen + upper;
        if (ytotal > 1024) {
                ytotal >>= 1;
                yres >>= 1;
                lower >>= 1;
                vslen >>= 1;
                upper >>= 1;
                rMode = 0x04;
        } else
                rMode = 0x00;
        if (ytotal > 1024)
                return VERROR; //ytotal too big
        if (vslen > 16)
                return VERROR;  //vslen too big
        par->crtc[CRTC_V_TOTAL] = ytotal - 2;
        r7 = 0x10;      /* disable linecompare */
        if (ytotal & 0x100) r7 |= 0x01;
        if (ytotal & 0x200) r7 |= 0x20;
        par->crtc[CRTC_PRESET_ROW] = 0;


// GMODE <--> ALPHA-MODE
// default using alpha mode so we need to set char rows= CHAR_HEIGHT-1
        par->crtc[CRTC_MAX_SCAN] = 0x40 | (CHAR_HEIGHT-1);        /* 16 scanlines, linecmp max*/

        if (var->vmode & VMODE_DOUBLE)
                par->crtc[CRTC_MAX_SCAN] |= 0x80;
        par->crtc[CRTC_CURSOR_START] = 0x00; // curs enabled, start line = 0
        par->crtc[CRTC_CURSOR_END]   = CHAR_HEIGHT-1; // end line = 12
        pos = yoffset * vxres + (xoffset >> 3);
        par->crtc[CRTC_START_HI]     = pos >> 8;
        par->crtc[CRTC_START_LO]     = pos & 0xFF;
        par->crtc[CRTC_CURSOR_HI]    = 0x00;
        par->crtc[CRTC_CURSOR_LO]    = 0x00;
        pos = yres - 1;
        par->crtc[CRTC_V_DISP_END] = pos & 0xFF;
        par->crtc[CRTC_V_BLANK_START] = pos & 0xFF;
        if (pos & 0x100)
                r7 |= 0x0A;     /* 0x02 -> DISP_END, 0x08 -> BLANK_START */
        if (pos & 0x200) {
                r7 |= 0x40;     /* 0x40 -> DISP_END */
                par->crtc[CRTC_MAX_SCAN] |= 0x20; /* BLANK_START */
        }
        pos += lower;
        par->crtc[CRTC_V_SYNC_START] = pos & 0xFF;
        if (pos & 0x100)
                r7 |= 0x04;
        if (pos & 0x200)
                r7 |= 0x80;
        pos += vslen;
        par->crtc[CRTC_V_SYNC_END] = (pos & 0x0F) & ~0x10; /* disabled reg write prot, IRQ */
        pos += upper - 1; /* blank_end + 1 <= ytotal + 2 */
        par->crtc[CRTC_V_BLANK_END] = pos & 0xFF; /* 0x7F for original VGA,
                     but some SVGA chips requires all 8 bits to set */
        if (vxres >= 512)
                return VERROR;  //vxres too long
        par->crtc[CRTC_OFFSET] = vxres >> 1;

	// put the underline off of the character, necessary in alpha color mode
        par->crtc[CRTC_UNDERLINE] = 0x1f;

        par->crtc[CRTC_MODE] = rMode | 0xA3; // word mode
        par->crtc[CRTC_LINE_COMPARE] = 0xFF;
        par->crtc[CRTC_OVERFLOW] = r7;


		// not used ??
        par->vss = 0x00;        /* 3DA */

        for (i = 0x00; i < 0x10; i++) {
                par->atc[i] = VgaAttributeTable[i];
		}
		// GMODE <--> ALPHA-MODE
        par->atc[ATC_MODE] = 0x0c; // text mode

        par->atc[ATC_OVERSCAN] = 0x00;  // no border
        par->atc[ATC_PLANE_ENABLE] = 0x0F;
        par->atc[ATC_PEL] = xoffset & 7;
        par->atc[ATC_COLOR_PAGE] = 0x00;

        par->misc = 0x67;       /* enable CPU, ports 0x3Dx, positive sync*/
        if (var->sync & SYNC_HOR_HIGH_ACT)
                par->misc &= ~0x40;
        if (var->sync & SYNC_VERT_HIGH_ACT)
                par->misc &= ~0x80;

        par->seq[SEQ_CLOCK_MODE] = 0x01; //8-bit char; 0x01=alpha mode
        par->seq[SEQ_PLANE_WRITE] = 0x03; // just char/attr plane
        par->seq[SEQ_CHARACTER_MAP] = 0x00;
	par->seq[SEQ_MEMORY_MODE] = 0x02; // A/G bit not used in stpc; O/E on, C4 off

        par->gdc[GDC_SR_VALUE] = 0x00;
		// bits set in the SR_EN regs will enable set/reset action
		// based on the bit settings in the SR_VAL register
        par->gdc[GDC_SR_ENABLE] = 0x00;
        par->gdc[GDC_COMPARE_VALUE] = 0x00;
        par->gdc[GDC_DATA_ROTATE] = 0x00;
        par->gdc[GDC_PLANE_READ] = 0;
        par->gdc[GDC_MODE] = 0x10; //Okay

		// GMODE <--> ALPHA-MMODE
        par->gdc[GDC_MISC] = 0x0e; // b0=0 ->alpha mode; memory at 0xb8000

        par->gdc[GDC_COMPARE_MASK] = 0x00;
        par->gdc[GDC_BIT_MASK] = 0xFF;

        return 0;
}

//
// originally from the stpc web site
//
static const unsigned char VgaLookupTable[3 * 0x3f + 3] = {
    //	Red   Green Blue
    0x000, 0x000, 0x000, // 00h
    0x000, 0x000, 0x02A, // 01h
    0x000, 0x02A, 0x000, // 02h
    0x000, 0x02A, 0x02A, // 03h
    0x02A, 0x000, 0x000, // 04h
    0x02A, 0x000, 0x02A, // 05h
    0x02A, 0x02A, 0x000, // 06h
    0x02A, 0x02A, 0x02A, // 07h
    0x000, 0x000, 0x015, // 08h
    0x000, 0x000, 0x03F, // 09h
    0x000, 0x02A, 0x015, // 0Ah
    0x000, 0x02A, 0x03F, // 0Bh
    0x02A, 0x000, 0x015, // 0Ch
    0x02A, 0x000, 0x03F, // 0Dh
    0x02A, 0x02A, 0x015, // 0Eh
    0x02A, 0x02A, 0x03F, // 0Fh
    0x000, 0x015, 0x000, // 10h
    0x000, 0x015, 0x02A, // 11h
    0x000, 0x03F, 0x000, // 12h
    0x000, 0x03F, 0x02A, // 13h
    0x02A, 0x015, 0x000, // 14h
    0x02A, 0x015, 0x02A, // 15h
    0x02A, 0x03F, 0x000, // 16h
    0x02A, 0x03F, 0x02A, // 17h
    0x000, 0x015, 0x015, // 18h
    0x000, 0x015, 0x03F, // 19h
    0x000, 0x03F, 0x015, // 1Ah
    0x000, 0x03F, 0x03F, // 1Bh
    0x02A, 0x015, 0x015, // 1Ch
    0x02A, 0x015, 0x03F, // 1Dh
    0x02A, 0x03F, 0x015, // 1Eh
    0x02A, 0x03F, 0x03F, // 1Fh
    0x015, 0x000, 0x000, // 20h
    0x015, 0x000, 0x02A, // 21h
    0x015, 0x02A, 0x000, // 22h
    0x015, 0x02A, 0x02A, // 23h
    0x03F, 0x000, 0x000, // 24h
    0x03F, 0x000, 0x02A, // 25h
    0x03F, 0x02A, 0x000, // 26h
    0x03F, 0x02A, 0x02A, // 27h
    0x015, 0x000, 0x015, // 28h
    0x015, 0x000, 0x03F, // 29h
    0x015, 0x02A, 0x015, // 2Ah
    0x015, 0x02A, 0x03F, // 2Bh
    0x03F, 0x000, 0x015, // 2Ch
    0x03F, 0x000, 0x03F, // 2Dh
    0x03F, 0x02A, 0x015, // 2Eh
    0x03F, 0x02A, 0x03F, // 2Fh
    0x015, 0x015, 0x000, // 30h
    0x015, 0x015, 0x02A, // 31h
    0x015, 0x03F, 0x000, // 32h
    0x015, 0x03F, 0x02A, // 33h
    0x03F, 0x015, 0x000, // 34h
    0x03F, 0x015, 0x02A, // 35h
    0x03F, 0x03F, 0x000, // 36h
    0x03F, 0x03F, 0x02A, // 37h
    0x015, 0x015, 0x015, // 38h
    0x015, 0x015, 0x03F, // 39h
    0x015, 0x03F, 0x015, // 3Ah
    0x015, 0x03F, 0x03F, // 3Bh
    0x03F, 0x015, 0x015, // 3Ch
    0x03F, 0x015, 0x03F, // 3Dh
    0x03F, 0x03F, 0x015, // 3Eh
    0x03F, 0x03F, 0x03F, // 3Fh
};

/*
 * From the Linux kernel.
 * orig by  Ben Pfaff and Petr Vandrovec.
 * see the note in the vga.h for attribution.
 *
 * modified by
 * Steve M. Gehlbach <steve@kesa.com>
 * for the linuxbios project
 *
 * Write the data in the vga parameter structure
 * to the vga registers, along with other default
 * settings.
 *
 */
static int vga_set_regs(const struct vga_par *par)
{
        int i;

        /* update misc output register */
        outb(par->misc, MIS_W);

	/* synchronous reset on */
	outb(0x00, SEQ_I);
	outb(0x00, SEQ_D);

        /* write sequencer registers */
	outb(1, SEQ_I);
	outb(par->seq[1] | 0x20, SEQ_D); // blank display
	for (i = 2; i < SEQ_C; i++) {
		outb(i, SEQ_I);
		outb(par->seq[i], SEQ_D);
	}

	/* synchronous reset off */
	outb(0x00, SEQ_I);
	outb(0x03, SEQ_D);

	/* deprotect CRT registers 0-7 */
	outb(0x11, CRT_IC);
	outb(par->crtc[0x11], CRT_DC);

	/* write CRT registers */
	for (i = 0; i < CRTC_C; i++) {
		outb(i, CRT_IC);
		outb(par->crtc[i], CRT_DC);
	}
	/* write graphics controller registers */
	for (i = 0; i < GRA_C; i++) {
		outb(i, GRA_I);
		outb(par->gdc[i], GRA_D);
	}

	/* write attribute controller registers */
	for (i = 0; i < ATT_C; i++) {
		inb(IS1_RC);          /* reset flip-flop */
		inb(0x80); //delay
		outb(i, ATT_IW);
		inb(0x80); //delay

		outb(par->atc[i], ATT_IW);
		inb(0x80); //delay
	}

	// initialize the color table
	outb(0, PEL_IW);
	i = 0;
	// length is a magic number right now
	while ( i < (0x3f*3 + 3) ) {
		outb(VgaLookupTable[i++], PEL_D);
		outb(VgaLookupTable[i++], PEL_D);
		outb(VgaLookupTable[i++], PEL_D);
	}

	outb(0x0ff, PEL_MSK); // palette mask

	// very important
	// turn on video, disable palette access
	inb(IS1_RC);          /* reset flip-flop */
	inb(0x80); //delay
	outb(0x20, ATT_IW);

	/* Wait for screen to stabilize. */
	//for(i=0;i<1000;i++) { inb(0x80); }

	outb(0x01, SEQ_I); // unblank display
	outb(par->seq[1], SEQ_D);

// turn on display, disable access to attr palette
	inb(IS1_RC);
	outb(0x20, ATT_IW);

return 0;
}

void
vga_load_regs(void)
{
    struct vga_par par;

    if (vga_decode_var(&vga_settings, &par) == 0) {
        vga_set_regs(&par);
    }
}
