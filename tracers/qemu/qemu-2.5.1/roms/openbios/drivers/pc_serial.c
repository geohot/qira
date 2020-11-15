/*
 * Copyright (C) 2003, 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "kernel/kernel.h"
#include "drivers/drivers.h"
#include "libc/vsprintf.h"

/* ******************************************************************
 *                       serial console functions
 * ****************************************************************** */

#define SER_SIZE 8

#define RBR(x)  x==2?0x2f8:0x3f8
#define THR(x)  x==2?0x2f8:0x3f8
#define IER(x)  x==2?0x2f9:0x3f9
#define IIR(x)  x==2?0x2fa:0x3fa
#define LCR(x)  x==2?0x2fb:0x3fb
#define MCR(x)  x==2?0x2fc:0x3fc
#define LSR(x)  x==2?0x2fd:0x3fd
#define MSR(x)  x==2?0x2fe:0x3fe
#define SCR(x)  x==2?0x2ff:0x3ff
#define DLL(x)  x==2?0x2f8:0x3f8
#define DLM(x)  x==2?0x2f9:0x3f9

int uart_charav(int port)
{
	return ((inb(LSR(port)) & 1) != 0);
}

char uart_getchar(int port)
{
	while (!uart_charav(port));
	return ((char) inb(RBR(port)) & 0177);
}

static void uart_port_putchar(int port, unsigned char c)
{
	if (c == '\n')
		uart_port_putchar(port, '\r');
	while (!(inb(LSR(port)) & 0x20));
	outb(c, THR(port));
}

static void uart_init_line(int port, unsigned long baud)
{
	int i, baudconst;

	switch (baud) {
	case 115200:
		baudconst = 1;
		break;
	case 57600:
		baudconst = 2;
		break;
	case 38400:
		baudconst = 3;
		break;
	case 19200:
		baudconst = 6;
		break;
	case 9600:
	default:
		baudconst = 12;
		break;
	}

	outb(0x87, LCR(port));
	outb(0x00, DLM(port));
	outb(baudconst, DLL(port));
	outb(0x07, LCR(port));
	outb(0x0f, MCR(port));

	for (i = 10; i > 0; i--) {
		if (inb(LSR(port)) == (unsigned int) 0)
			break;
		inb(RBR(port));
	}
}

#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
int uart_init(int port, unsigned long speed)
{
        uart_init_line(port, speed);
	return -1;
}

void uart_putchar(int c)
{
	uart_port_putchar(CONFIG_SERIAL_PORT, (unsigned char) (c & 0xff));
}
#endif

/* ( addr len -- actual ) */
static void
pc_serial_read(unsigned long *address)
{
    char *addr;
    int len;

    len = POP();
    addr = (char *)POP();

    if (len != 1)
        printk("pc_serial_read: bad len, addr %lx len %x\n", (unsigned long)addr, len);

    if (uart_charav(*address)) {
        *addr = (char)uart_getchar(*address);
        PUSH(1);
    } else {
        PUSH(0);
    }
}

/* ( addr len -- actual ) */
static void
pc_serial_write(unsigned long *address)
{
    unsigned char *addr;
    int i, len;

    len = POP();
    addr = (unsigned char *)POP();

     for (i = 0; i < len; i++) {
        uart_port_putchar(*address, addr[i]);
    }
    PUSH(len);
}

static void
pc_serial_close(void)
{
}

static void
pc_serial_open(unsigned long *address)
{
    RET ( -1 );
}

static void
pc_serial_init(unsigned long *address)
{
    *address = POP();
}

DECLARE_UNNAMED_NODE(pc_serial, INSTALL_OPEN, sizeof(unsigned long));

NODE_METHODS(pc_serial) = {
    { "init",               pc_serial_init              },
    { "open",               pc_serial_open              },
    { "close",              pc_serial_close             },
    { "read",               pc_serial_read              },
    { "write",              pc_serial_write             },
};

void
ob_pc_serial_init(const char *path, const char *dev_name, uint64_t base,
                  uint64_t offset, int intr)
{
    phandle_t aliases;
    char nodebuff[128];

    snprintf(nodebuff, sizeof(nodebuff), "%s/%s", path, dev_name);
    REGISTER_NAMED_NODE(pc_serial, nodebuff);

    push_str(nodebuff);
    fword("find-device");

    PUSH(offset);
    PUSH(find_package_method("init", get_cur_dev()));
    fword("execute");

    push_str("serial");
    fword("device-type");

    PUSH((base + offset) >> 32);
    fword("encode-int");
    PUSH((base + offset) & 0xffffffff);
    fword("encode-int");
    fword("encode+");
    PUSH(SER_SIZE);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");
    
#if !defined(CONFIG_SPARC64)
    PUSH(offset);
    fword("encode-int");
    push_str("address");
    fword("property");
#endif
    
#if defined(CONFIG_SPARC64)
    set_int_property(get_cur_dev(), "interrupts", 1);
#endif

    aliases = find_dev("/aliases");
    set_property(aliases, "ttya", nodebuff, strlen(nodebuff) + 1);
}
