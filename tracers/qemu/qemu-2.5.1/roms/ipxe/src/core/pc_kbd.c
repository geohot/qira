/* Minimal polling PC keyboard driver
 * - No interrupt
 * - No LED
 * - No special keys
 *
 * still Enough For Me to type a filename.
 *
 * 2003-07 by SONE Takesh
 * 2004-04 moved by LYH From filo to Etherboot
 *		yhlu@tyan.com
 */

#include <ipxe/io.h>
#include <ipxe/console.h>

static char key_map[][128] = {
    {
	"\0\x1b""1234567890-=\b\t"
	"qwertyuiop[]\r\0as"
	"dfghjkl;'`\0\\zxcv"
	"bnm,./\0*\0 \0\0\0\0\0\0"
	"\0\0\0\0\0\0\0""789-456+1"
	"230."
    },{
	"\0\x1b""!@#$%^&*()_+\b\t"
	"QWERTYUIOP{}\r\0AS"
	"DFGHJKL:\"~\0|ZXCV"
	"BNM<>?\0\0\0 \0\0\0\0\0\0"
	"\0\0\0\0\0\0\0""789-456+1"
	"230."
    }
};

static int cur_scan;
static unsigned int shift_state;
#define SHIFT 1
#define CONTROL 2
#define CAPS 4

static int get_scancode(void)
{
    int scan;

    if ((inb(0x64) & 1) == 0)
	return 0;
    scan = inb(0x60);

    switch (scan) {
    case 0x2a:
    case 0x36:
	shift_state |= SHIFT;
	break;
    case 0xaa:
    case 0xb6:
	shift_state &= ~SHIFT;
	break;
    case 0x1d:
	shift_state |= CONTROL;
	break;
    case 0x9d:
	shift_state &= ~CONTROL;
	break;
    case 0x3a:
	shift_state ^= CAPS;
	break;
    }

    if (scan & 0x80)
	return 0; /* ignore break code or 0xe0 etc! */
    return scan;
}

static int kbd_havekey(void)
{
    if (!cur_scan)
	cur_scan = get_scancode();
    return cur_scan != 0;
}

static int kbd_ischar(void)
{
    if (!kbd_havekey())
	return 0;
    if (!key_map[shift_state & SHIFT][cur_scan]) {
	cur_scan = 0;
	return 0;
    }
    return 1;
}

static int kbd_getc(void)
{
    int c;

    while (!kbd_ischar())
	;
    c = key_map[shift_state & SHIFT][cur_scan];
    if (shift_state & (CONTROL | CAPS)) {
	if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
	    if (shift_state & CONTROL)
		c &= 0x1f;
	    else if (shift_state & CAPS)
		c ^= ('A' ^ 'a');
	}
    }
    cur_scan = 0;
    return c;
}

struct console_driver pc_kbd_console __console_driver = {
	.getchar = kbd_getc,
};
