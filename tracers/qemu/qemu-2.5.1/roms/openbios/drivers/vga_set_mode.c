/*
 * $Id$
 * $Source$
 *
 *  by
 *  Steve M. Gehlbach <steve@kesa.com>
 *
 *  These routines set graphics mode and alpha mode
 *  for switching back and forth.
 *
 *  Register settings are
 *  more or less as follows:
 *
 *  Register             Graphics      Alpha
 *                       16 color
 *  ------------------------------------------------
 *  GDC_MODE              0x00          0x10
 *  GDC_MISC              0x05          0x0e
 *  SEQ_MEMORY_MODE       0x06          0x02
 *  SEQ_PLANE_WRITE       0x0f          0x03
 *  CRTC_CURSOR_START     0x20          0x00
 *  CRTC_CURSOR_END       0x00          CHAR_HEIGHT-1
 *  CRTC_MODE             0xe3          0xa3
 *  CRTC_MAX_SCAN         0x40          0x40 | CHAR_HEIGHT-1
 *  ATC_MODE              0x01          0x0c
 *
 */

#include "asm/io.h"
#include "vga.h"

void vga_set_gmode (void) {
	u8 byte;

	byte = read_att_b(ATC_MODE) & ~0x0f;
	write_att(byte|0x1, ATC_MODE);
//
// display is off at this point

	byte = read_seq_b(SEQ_PLANE_WRITE) & ~0xf;
	write_seq(byte|0xf,SEQ_PLANE_WRITE); // all planes
	byte = read_seq_b(SEQ_MEMORY_MODE);
	write_seq(byte|4,SEQ_MEMORY_MODE);

	byte = read_gra_b(GDC_MODE) & ~0x10;
	write_gra(byte,GDC_MODE);
	write_gra(0x05, GDC_MISC);

	write_crtc(0x20, CRTC_CURSOR_START);
	write_crtc(0x00, CRTC_CURSOR_END);
	byte = read_crtc_b(CRTC_MODE) & ~0xe0;
	write_crtc(byte|0xe0, CRTC_MODE);
	byte = read_crtc_b(CRTC_MAX_SCAN) & ~0x01f;
	write_crtc(byte, CRTC_MAX_SCAN);

	byte = inb(MIS_R); // get 3c2 value by reading 3cc
	outb(byte & ~0xc,MIS_W); // clear last bits to set 25Mhz clock and low page


// turn on display, disable access to attr palette
	inb(IS1_RC);
	outb(0x20, ATT_IW);
}

void vga_set_amode (void) {
	u8 byte;
	write_att(0x0c, ATC_MODE);

	//reset palette to normal in the case it was changed
	write_att(0x0, ATC_COLOR_PAGE);
//
// display is off at this point

	write_seq(0x3,SEQ_PLANE_WRITE); // planes 0 & 1
	byte = read_seq_b(SEQ_MEMORY_MODE) & ~0x04;
	write_seq(byte,SEQ_MEMORY_MODE);

	byte = read_gra_b(GDC_MODE) & ~0x60;
	write_gra(byte|0x10,GDC_MODE);

	write_gra(0x0e, GDC_MISC);

	write_crtc(0x00, CRTC_CURSOR_START);
	write_crtc(CHAR_HEIGHT-1, CRTC_CURSOR_END);

	byte = read_crtc_b(CRTC_MODE) & ~0xe0;
	write_crtc(byte|0xa0, CRTC_MODE);
	byte = read_crtc_b(CRTC_MAX_SCAN) & ~0x01f;
	write_crtc(byte | (CHAR_HEIGHT-1), CRTC_MAX_SCAN);


// turn on display, disable access to attr palette
	inb(IS1_RC);
	outb(0x20, ATT_IW);
}

/*
 * by Steve M. Gehlbach, Ph.D. <steve@kesa.com>
 *
 * vga_font_load loads a font into font memory.  It
 * assumes alpha mode has been set.
 *
 * The font load code follows technique used
 * in the tiara project, which came from
 * the Universal Talkware Boot Loader,
 * http://www.talkware.net.
 */

void vga_font_load(unsigned char *vidmem, const unsigned char *font, int height, int num_chars) {

/* Note: the font table is 'height' long but the font storage area
 * is 32 bytes long.
 */

	int i,j;
	u8 byte;

	// set sequencer map 2, odd/even off
	byte = read_seq_b(SEQ_PLANE_WRITE) & ~0xf;
	write_seq(byte|4,SEQ_PLANE_WRITE);
	byte = read_seq_b(SEQ_MEMORY_MODE);
	write_seq(byte|4,SEQ_MEMORY_MODE);

	// select graphics map 2, odd/even off, map starts at 0xa0000
	write_gra(2,GDC_PLANE_READ);
	byte = read_gra_b(GDC_MODE) & ~0x10;
	write_gra(byte,GDC_MODE);
	write_gra(0,GDC_MISC);

	for (i = 0 ; i < num_chars ; i++) {
		for (j = 0 ; j < height ; j++) {
			vidmem[i*32+j] = font[i*16+j];
		}
	}

	// set sequencer back to maps 0,1, odd/even on
	byte = read_seq_b(SEQ_PLANE_WRITE) & ~0xf;
	write_seq(byte|3,SEQ_PLANE_WRITE);
	byte = read_seq_b(SEQ_MEMORY_MODE) & ~0x4;
	write_seq(byte,SEQ_MEMORY_MODE);

	// select graphics back to map 0,1, odd/even on
	write_gra(0,GDC_PLANE_READ);
	byte = read_gra_b(GDC_MODE);
	write_gra(byte|0x10,GDC_MODE);
	write_gra(0xe,GDC_MISC);

}
