#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#include "drivers/drivers.h"
#include "libopenbios/ofmem.h"

#include "escc.h"

/* ******************************************************************
 *                       serial console functions
 * ****************************************************************** */

static volatile unsigned char *escc_serial_dev;

#define CTRL(addr) (*(volatile unsigned char *)(uintptr_t)(addr))
#ifdef CONFIG_DRIVER_ESCC_SUN
#define DATA(addr) (*(volatile unsigned char *)(uintptr_t)(addr + 2))
#else
#define DATA(addr) (*(volatile unsigned char *)(uintptr_t)(addr + 16))
#endif

/* Conversion routines to/from brg time constants from/to bits
 * per second.
 */
#define BPS_TO_BRG(bps, freq) ((((freq) + (bps)) / (2 * (bps))) - 2)

#ifdef CONFIG_DRIVER_ESCC_SUN
#define ESCC_CLOCK              4915200 /* Zilog input clock rate. */
#else
#define ESCC_CLOCK              3686400
#endif
#define ESCC_CLOCK_DIVISOR      16      /* Divisor this driver uses. */

/* Write Register 3 */
#define RxENAB          0x1     /* Rx Enable */
#define Rx8             0xc0    /* Rx 8 Bits/Character */

/* Write Register 4 */
#define SB1             0x4     /* 1 stop bit/char */
#define X16CLK          0x40    /* x16 clock mode */

/* Write Register 5 */
#define RTS             0x2     /* RTS */
#define TxENAB          0x8     /* Tx Enable */
#define Tx8             0x60    /* Tx 8 bits/character */
#define DTR             0x80    /* DTR */

/* Write Register 14 (Misc control bits) */
#define BRENAB  1       /* Baud rate generator enable */
#define BRSRC   2       /* Baud rate generator source */

/* Read Register 0 */
#define Rx_CH_AV        0x1     /* Rx Character Available */
#define Tx_BUF_EMP      0x4     /* Tx Buffer empty */

int escc_uart_charav(uintptr_t port)
{
    return (CTRL(port) & Rx_CH_AV) != 0;
}

char escc_uart_getchar(uintptr_t port)
{
    while (!escc_uart_charav(port))
        ;
    return DATA(port) & 0177;
}

static void escc_uart_port_putchar(uintptr_t port, unsigned char c)
{
    if (!escc_serial_dev)
        return;

    if (c == '\n')
        escc_uart_port_putchar(port, '\r');
    while (!(CTRL(port) & Tx_BUF_EMP))
        ;
    DATA(port) = c;
}

static void uart_init_line(volatile unsigned char *port, unsigned long baud)
{
    CTRL(port) = 4; // reg 4
    CTRL(port) = SB1 | X16CLK; // no parity, async, 1 stop bit, 16x
                               // clock

    baud = BPS_TO_BRG(baud, ESCC_CLOCK / ESCC_CLOCK_DIVISOR);

    CTRL(port) = 12; // reg 12
    CTRL(port) = baud & 0xff;
    CTRL(port) = 13; // reg 13
    CTRL(port) = (baud >> 8) & 0xff;
    CTRL(port) = 14; // reg 14
    CTRL(port) = BRSRC | BRENAB;

    CTRL(port) = 3; // reg 3
    CTRL(port) = RxENAB | Rx8; // enable rx, 8 bits/char

    CTRL(port) = 5; // reg 5
    CTRL(port) = RTS | TxENAB | Tx8 | DTR; // enable tx, 8 bits/char,
                                           // set RTS & DTR

}

int escc_uart_init(phys_addr_t port, unsigned long speed)
{
#ifdef CONFIG_DRIVER_ESCC_SUN
    escc_serial_dev = (unsigned char *)ofmem_map_io(port & ~7ULL, ZS_REGS);
    escc_serial_dev += port & 7ULL;
#else
    escc_serial_dev = (unsigned char *)(uintptr_t)port;
#endif
    uart_init_line(escc_serial_dev, speed);
    return -1;
}

void escc_uart_putchar(int c)
{
    escc_uart_port_putchar((uintptr_t)escc_serial_dev, (unsigned char) (c & 0xff));
}

void serial_cls(void)
{
    escc_uart_putchar(27);
    escc_uart_putchar('[');
    escc_uart_putchar('H');
    escc_uart_putchar(27);
    escc_uart_putchar('[');
    escc_uart_putchar('J');
}

/* ( addr len -- actual ) */
static void
escc_read(ucell *address)
{
    char *addr;
    int len;

    len = POP();
    addr = (char *)cell2pointer(POP());

    if (len < 1)
        printk("escc_read: bad len, addr %p len %x\n", addr, len);

    if (escc_uart_charav(*address)) {
        *addr = (char)escc_uart_getchar(*address);
        PUSH(1);
    } else {
        PUSH(0);
    }
}

/* ( addr len -- actual ) */
static void
escc_write(ucell *address)
{
    unsigned char *addr;
    int i, len;

    len = POP();
    addr = (unsigned char *)cell2pointer(POP());

    for (i = 0; i < len; i++) {
        escc_uart_port_putchar(*address, addr[i]);
    }
    PUSH(len);
}

static void
escc_close(void)
{
}

static void
escc_open(ucell *address)
{
#ifdef CONFIG_DRIVER_ESCC_SUN
    int len;
    phandle_t ph;
    unsigned long *prop;
    char *args;

    fword("my-self");
    fword("ihandle>phandle");
    ph = (phandle_t)POP();
    prop = (unsigned long *)get_property(ph, "address", &len);
    *address = *prop;
    fword("my-args");
    args = pop_fstr_copy();
    if (args) {
        if (args[0] == 'a')
            *address += 4;
        //printk("escc_open: address %lx, args %s\n", *address, args);
        free(args);
    }
#else
    *address = (unsigned long)escc_serial_dev; // XXX
#endif
    RET ( -1 );
}

DECLARE_UNNAMED_NODE(escc, INSTALL_OPEN, sizeof(ucell));

NODE_METHODS(escc) = {
    { "open",               escc_open              },
    { "close",              escc_close             },
    { "read",               escc_read              },
    { "write",              escc_write             },
};

#ifdef CONFIG_DRIVER_ESCC_SUN
static volatile unsigned char *kbd_dev;

void kbd_init(phys_addr_t base)
{
    kbd_dev = (unsigned char *)ofmem_map_io(base, 2 * 4);
    kbd_dev += 4;
}

static const unsigned char sunkbd_keycode[128] = {
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 0, 8,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '\\', 13,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ' ',
};

static const unsigned char sunkbd_keycode_shifted[128] = {
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 0, 8,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '|', 13,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ' ',
};

static int shiftstate;

int
keyboard_dataready(void)
{
    return ((kbd_dev[0] & 1) == 1);
}

unsigned char
keyboard_readdata(void)
{
    unsigned char ch;

    while (!keyboard_dataready()) { }

    do {
        ch = kbd_dev[2] & 0xff;
        if (ch == 99)
            shiftstate |= 1;
        else if (ch == 110)
            shiftstate |= 2;
        else if (ch == 227)
            shiftstate &= ~1;
        else if (ch == 238)
            shiftstate &= ~2;
        //printk("getch: %d\n", ch);
    } // If release, wait for key press
    while ((ch & 0x80) == 0x80 || ch == 238 || ch == 227);
    //printk("getch rel: %d\n", ch);
    ch &= 0x7f;
    if (shiftstate)
        ch = sunkbd_keycode_shifted[ch];
    else
        ch = sunkbd_keycode[ch];
    //printk("getch xlate: %d\n", ch);

    return ch;
}

/* ( addr len -- actual ) */
static void
escc_read_keyboard(void)
{
    unsigned char *addr;
    int len;

    len = POP();
    addr = (unsigned char *)POP();

    if (len < 1)
        printk("escc_read: bad len, addr %p len %x\n", addr, len);

    if (keyboard_dataready()) {
        *addr = keyboard_readdata();
        PUSH(1);
    } else {
        PUSH(0);
    }
}

DECLARE_UNNAMED_NODE(escc_keyboard, INSTALL_OPEN, sizeof(ucell));

NODE_METHODS(escc_keyboard) = {
    { "open",               escc_open              },
    { "close",              escc_close             },
    { "read",               escc_read_keyboard     },
};

void
ob_zs_init(phys_addr_t base, uint64_t offset, int intr, int slave, int keyboard)
{
    char nodebuff[256];
    phandle_t aliases;

    ob_new_obio_device("zs", "serial");

    ob_reg(base, offset, ZS_REGS, 1);

    PUSH(slave);
    fword("encode-int");
    push_str("slave");
    fword("property");

    if (keyboard) {
        PUSH(0);
        PUSH(0);
        push_str("keyboard");
        fword("property");

        PUSH(0);
        PUSH(0);
        push_str("mouse");
        fword("property");
    }

    ob_intr(intr);

    PUSH(0);
    PUSH(0);
    push_str("port-a-ignore-cd");
    fword("property");

    PUSH(0);
    PUSH(0);
    push_str("port-b-ignore-cd");
    fword("property");

    fword("finish-device");

    snprintf(nodebuff, sizeof(nodebuff), "/obio/zs@0,%x",
             (int)offset & 0xffffffff);
    if (keyboard) {
        REGISTER_NODE_METHODS(escc_keyboard, nodebuff);

        aliases = find_dev("/aliases");
        set_property(aliases, "keyboard", nodebuff, strlen(nodebuff) + 1);
    } else {
        REGISTER_NODE_METHODS(escc, nodebuff);

        aliases = find_dev("/aliases");
        snprintf(nodebuff, sizeof(nodebuff), "/obio/zs@0,%x:a",
                 (int)offset & 0xffffffff);
        set_property(aliases, "ttya", nodebuff, strlen(nodebuff) + 1);

        snprintf(nodebuff, sizeof(nodebuff), "/obio/zs@0,%x:b",
                 (int)offset & 0xffffffff);
        set_property(aliases, "ttyb", nodebuff, strlen(nodebuff) + 1);

    }
}

#else

static void
escc_add_channel(const char *path, const char *node, phys_addr_t addr,
                 int esnum)
{
    char buf[64], tty[32];
    phandle_t dnode, aliases;

    cell props[10];
    int offset;
    int legacy;

    switch (esnum) {
    case 2: offset = 1; legacy = 0; break;
    case 3: offset = 0; legacy = 0; break;
    case 4: offset = 1; legacy = 1; break;
    case 5: offset = 0; legacy = 1; break;
    default: return;
    }

    /* add device */

    snprintf(buf, sizeof(buf), "%s/ch-%s", path, node);

    REGISTER_NAMED_NODE(escc, buf);

    activate_device(buf);

    /* add aliases */

    aliases = find_dev("/aliases");

    snprintf(buf, sizeof(buf), "%s/ch-%s", path, node);
    OLDWORLD(snprintf(tty, sizeof(tty), "tty%s", node));
    OLDWORLD(set_property(aliases, tty, buf, strlen(buf) + 1));
    snprintf(tty, sizeof(tty), "scc%s", node);
    set_property(aliases, tty, buf, strlen(buf) + 1);

    /* add properties */

    dnode = find_dev(buf);
    set_property(dnode, "device_type", "serial",
                 strlen("serial") + 1);

    snprintf(buf, sizeof(buf), "chrp,es%d", esnum);
    set_property(dnode, "compatible", buf, 9);

    if (legacy) {
        props[0] = IO_ESCC_LEGACY_OFFSET + offset * 0x4;
        props[1] = 0x00000001;
        props[2] = IO_ESCC_LEGACY_OFFSET + offset * 0x4 + 2;
        props[3] = 0x00000001;
        props[4] = IO_ESCC_LEGACY_OFFSET + offset * 0x4 + 6;
        props[5] = 0x00000001;
        set_property(dnode, "reg", (char *)&props, 6 * sizeof(cell));
    } else {
        props[0] = IO_ESCC_OFFSET + offset * 0x20;
        props[1] = 0x00000020;
        set_property(dnode, "reg", (char *)&props, 2 * sizeof(cell));
    }

    if (legacy) {
        props[0] = addr + IO_ESCC_LEGACY_OFFSET + offset * 0x4;
    } else {
        props[0] = addr + IO_ESCC_OFFSET + offset * 0x20;
    }
    OLDWORLD(set_property(dnode, "AAPL,address",
            (char *)&props, 1 * sizeof(cell)));

    props[0] = 0x00000010 - offset;
    OLDWORLD(set_property(dnode, "AAPL,interrupts",
            (char *)&props, 1 * sizeof(cell)));

    props[0] = (0x24) + offset;
    props[1] = 0;
    props[2] = 0;
    NEWWORLD(set_property(dnode, "interrupts",
             (char *)&props, 3 * sizeof(cell)));

    device_end();

    if (legacy) {
        uart_init_line(
                (unsigned char*)addr + IO_ESCC_LEGACY_OFFSET + offset * 0x4,
                CONFIG_SERIAL_SPEED);
    } else {
        uart_init_line(
                (unsigned char*)addr + IO_ESCC_OFFSET + offset * 0x20,
                CONFIG_SERIAL_SPEED);
    }
}

void
escc_init(const char *path, phys_addr_t addr)
{
    char buf[64];
    int props[2];
    phandle_t dnode;

    push_str(path);
    fword("find-device");
    fword("new-device");

    push_str("escc");
    fword("device-name");

    snprintf(buf, sizeof(buf), "%s/escc", path);

    dnode = find_dev(buf);

    set_int_property(dnode, "#address-cells", 1);
    props[0] = __cpu_to_be32(IO_ESCC_OFFSET);
    props[1] = __cpu_to_be32(IO_ESCC_SIZE);
    set_property(dnode, "reg", (char *)&props, sizeof(props));
    set_property(dnode, "device_type", "escc",
                 strlen("escc") + 1);
    set_property(dnode, "compatible", "escc\0CHRP,es0", 14);

    fword("finish-device");

    escc_add_channel(buf, "a", addr, 2);
    escc_add_channel(buf, "b", addr, 3);

    escc_serial_dev = (unsigned char *)addr + IO_ESCC_OFFSET +
                 (CONFIG_SERIAL_PORT ? 0 : 0x20);

    push_str(path);
    fword("find-device");
    fword("new-device");

    push_str("escc-legacy");
    fword("device-name");

    snprintf(buf, sizeof(buf), "%s/escc-legacy", path);

    dnode = find_dev(buf);

    set_int_property(dnode, "#address-cells", 1);
    props[0] = __cpu_to_be32(IO_ESCC_LEGACY_OFFSET);
    props[1] = __cpu_to_be32(IO_ESCC_LEGACY_SIZE);
    set_property(dnode, "reg", (char *)&props, sizeof(props));
    set_property(dnode, "device_type", "escc-legacy",
                 strlen("escc-legacy") + 1);
    set_property(dnode, "compatible", "chrp,es1", 9);

    fword("finish-device");

    escc_add_channel(buf, "a", addr, 4);
    escc_add_channel(buf, "b", addr, 5);
}
#endif
