/*
 * <char.c>
 *
 * Open Hack'Ware BIOS character devices drivers.
 * 
 *  Copyright (c) 2004-2005 Jocelyn Mayer
 *
 *  cuda driver: Copyright (c) 2004-2005 Fabrice Bellard
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
#include <stdio.h>
#include "bios.h"
#include "adb.h"

//#define DEBUG_CHARDEV
//#define DEBUG_CUDA
//#define DEBUG_ADB

#ifdef DEBUG_CHARDEV
#define CHARDEV_DPRINTF(fmt, args...) \
do { dprintf("CHARDEV - %s: " fmt, __func__ , ##args); } while (0)
#else
#define CHARDEV_DPRINTF(fmt, args...) do { } while (0)
#endif

/* Generic character device API */
struct chardev_t {
    chardev_t *next;
    int type;
    cops_t *ops;
    void *private;
};

static chardev_t *char_devices;

int chardev_register (int type, cops_t *ops, void *private)
{
    chardev_t *dev, **cur;

    CHARDEV_DPRINTF("Register char device of type %d\n", type);
    if (type > CHARDEV_LAST)
        return -1;
    dev = malloc(sizeof(chardev_t));
    if (dev == NULL)
        return -1;
    dev->type = type;
    dev->ops = ops;
    dev->private = private;
    for (cur = &char_devices; *cur != NULL; cur = &((*cur)->next))
        continue;
    *cur = dev;

    return 0;
}

int chardev_open (chardev_t *dev)
{
    if (dev->ops == NULL)
        return -1;
    if (dev->ops->open == NULL)
        return 0;

    return (*dev->ops->open)(dev->private);
}

int chardev_close (chardev_t *dev)
{
    if (dev->ops == NULL)
        return -1;
    if (dev->ops->close == NULL)
        return 0;

    return (*dev->ops->close)(dev->private);
}

int chardev_read (chardev_t *dev, void *buffer, int maxlen)
{
    unsigned char *p;
    int len;
    int c;

    if (dev->ops == NULL || dev->ops->read == NULL)
        return -1;

    p = buffer;
    for (len = 0; len < maxlen; len++) {
        c = (*dev->ops->read)(dev->private);
        if (c < 0)
            break;
        *p++ = c;
    }

    return len;
}

int chardev_write (chardev_t *dev, const void *buffer, int maxlen)
{
    const unsigned char *p;
    int len;
    int c;

    if (dev->ops == NULL || dev->ops->write == NULL)
        return -1;

    p = buffer;
    for (len = 0; len < maxlen; len++) {
        c = *p++;
        if ((*dev->ops->write)(dev->private, c) < 0)
            break;
    }

    return len;
}

int chardev_type (chardev_t *dev)
{
    return dev->type;
}

/* Console driver */
static chardev_t *console_in_devs[17], *console_out_devs[17];
static int console_last_in;

int console_open (void)
{
    chardev_t *cur;
    int i, j, n, register_outd;

    i = 0;
    j = 0;
    n = 0;
    /* Check all character devices and register those which are usable
     * as IO for the console
     */
    CHARDEV_DPRINTF("enter\n");
    for (cur = char_devices; cur != NULL; cur = cur->next, n++) {
        register_outd = 0;
        switch (cur->type) {
        case  CHARDEV_SERIAL:
            CHARDEV_DPRINTF("one serial port\n");
            register_outd = 1;
            /* No break here */
        case CHARDEV_KBD:
            CHARDEV_DPRINTF("one input port %d %d\n", n, i);
            if (i < 16 && chardev_open(cur) == 0) {
                console_in_devs[i++] = cur;
            }
            if (!register_outd)
                break;
            /* No break here */
        case CHARDEV_DISPLAY:
            CHARDEV_DPRINTF("one output port %d %d\n", n, j);
            if (j < 16 && chardev_open(cur) == 0) {
                console_out_devs[j++] = cur;
            }
            break;
        default:
            CHARDEV_DPRINTF("Skip device %d\n", n);
            break;
        }
    }
    
    return 0;
}

int console_read (void *buffer, int maxlen)
{
    chardev_t *cur;
    int i, in;

    CHARDEV_DPRINTF("enter\n");
    /* Get data from the first in device responding to us */
    cur = console_in_devs[console_last_in];
    for (i = console_last_in;;) {
        CHARDEV_DPRINTF("read from device %d\n", i);
        in = chardev_read(cur, buffer, maxlen);
        if (in > 0) {
            console_last_in = i;
#if 0
            printf("Read %d chars '%c'...\n", in, *((char *)buffer));
#endif
            return in;
        }
        cur = console_in_devs[++i];
        if (cur == NULL) {
            i = 0;
            cur = console_in_devs[0];
        }
        if (i == console_last_in || cur == NULL)
            break;
    }
    console_last_in = i;
    CHARDEV_DPRINTF("out\n");

    return 0;
}

int console_write (const void *buffer, int len)
{
    chardev_t *cur;
    int i, out, max;

    /* Write data to all devices */
    max = 0;
    for (i = 0; i < 16; i++) {
        cur = console_out_devs[i];
        if (cur == NULL)
            break;
        out = chardev_write(cur, buffer, len);
        if (out > max)
            max = out;
    }

    return max;
}

void console_close (void)
{
    chardev_t *cur;
    int i;

    for (i = 0; i < 16; i++) {
        cur = console_out_devs[i];
        if (cur == NULL)
            break;
        chardev_close(cur);
        console_out_devs[i] = NULL;
    }
}

/* PC serial port "driver" */
#define PC_SERIAL_LSR_OFFSET (5)
typedef struct pc_serial_t {
    uint16_t base;
} pc_serial_t;

static int pc_serial_open (unused void *private)
{
    return 0;
}

static int pc_serial_writeb (void *private, int data)
{
    pc_serial_t *serial = private;

    /* Wait for the FIFO to be ready to accept more chars.
     * Note: this is completely buggy and would never work on real hardware,
     *       as the serial port (especialy the FIFO) has not been programmed
     *       anywhere before !
     */
    if (!(inb(serial->base + PC_SERIAL_LSR_OFFSET) & 0x20))
        usleep(100);
    outb(serial->base, data);

    return 0;
}

static int pc_serial_readb (void *private)
{
    pc_serial_t *serial = private;

    if (!(inb(serial->base + PC_SERIAL_LSR_OFFSET) & 0x01))
        return -1;

    return inb(serial->base);
}

static int pc_serial_close (unused void *private)
{
    return 0;
}

static cops_t pc_serial_ops = {
    .open = &pc_serial_open,
    .read = &pc_serial_readb,
    .write = &pc_serial_writeb,
    .close = &pc_serial_close,
};

/* XXX: debug stuff only ! (TOFIX with a generic debug console) */
int serial_write (const void *buffer, int len)
{
    const char *p;

    for (p = buffer; len > 0; len--) {
        if (!(inb(0x3F8 + PC_SERIAL_LSR_OFFSET) & 0x20))
            usleep(100);
        outb(0x3F8, *p++);
    }

    return 0;
}

int pc_serial_register (uint16_t base)
{
    pc_serial_t *serial;
    
    serial = malloc(sizeof(pc_serial_t));
    if (serial == NULL)
        return -1;
    serial->base = base;
    /* XXX: TODO: initialize the serial port (FIFO, speed, ...) */
    
    return chardev_register(CHARDEV_SERIAL, &pc_serial_ops, serial);
}

/* VGA console device */
static int vga_cons_open (unused void *private)
{
    return 0;
}

static int vga_cons_writeb (unused void *private, int data)
{
    vga_putchar(data);

    return 0;
}

static int vga_cons_close (unused void *private)
{
    return 0;
}

static cops_t vga_cons_ops = {
    .open = &vga_cons_open,
    .read = NULL,
    .write = &vga_cons_writeb,
    .close = &vga_cons_close,
};

int vga_console_register (void)
{
    return chardev_register(CHARDEV_DISPLAY, &vga_cons_ops, NULL);
}

/* Macintosh via-cuda driver */
#ifdef DEBUG_CUDA
#define CUDA_DPRINTF(fmt, args...) \
do { dprintf("CUDA - %s: " fmt, __func__ , ##args); } while (0)
#else
#define CUDA_DPRINTF(fmt, args...) do { } while (0)
#endif

/* VIA registers - spaced 0x200 bytes apart */
#define RS		0x200		/* skip between registers */
#define B		0		/* B-side data */
#define A		RS		/* A-side data */
#define DIRB		(2*RS)		/* B-side direction (1=output) */
#define DIRA		(3*RS)		/* A-side direction (1=output) */
#define T1CL		(4*RS)		/* Timer 1 ctr/latch (low 8 bits) */
#define T1CH		(5*RS)		/* Timer 1 counter (high 8 bits) */
#define T1LL		(6*RS)		/* Timer 1 latch (low 8 bits) */
#define T1LH		(7*RS)		/* Timer 1 latch (high 8 bits) */
#define T2CL		(8*RS)		/* Timer 2 ctr/latch (low 8 bits) */
#define T2CH		(9*RS)		/* Timer 2 counter (high 8 bits) */
#define SR		(10*RS)		/* Shift register */
#define ACR		(11*RS)		/* Auxiliary control register */
#define PCR		(12*RS)		/* Peripheral control register */
#define IFR		(13*RS)		/* Interrupt flag register */
#define IER		(14*RS)		/* Interrupt enable register */
#define ANH		(15*RS)		/* A-side data, no handshake */

/* Bits in B data register: all active low */
#define TREQ		0x08		/* Transfer request (input) */
#define TACK		0x10		/* Transfer acknowledge (output) */
#define TIP		0x20		/* Transfer in progress (output) */

/* Bits in ACR */
#define SR_CTRL		0x1c		/* Shift register control bits */
#define SR_EXT		0x0c		/* Shift on external clock */
#define SR_OUT		0x10		/* Shift out if 1 */

/* Bits in IFR and IER */
#define IER_SET		0x80		/* set bits in IER */
#define IER_CLR		0		/* clear bits in IER */
#define SR_INT		0x04		/* Shift register full/empty */

#define CUDA_BUF_SIZE 16

#define ADB_PACKET	0
#define CUDA_PACKET	1

struct cuda_t {
    uint32_t base;
    adb_bus_t *adb_bus;
};

static uint8_t cuda_readb (cuda_t *dev, int reg)
{
    return *(volatile uint8_t *)(dev->base + reg);
}

static void cuda_writeb (cuda_t *dev, int reg, uint8_t val)
{
    *(volatile uint8_t *)(dev->base + reg) = val;
}

static void cuda_wait_irq (cuda_t *dev)
{
    int val;

    CUDA_DPRINTF("\n");
    for(;;) {
        val = cuda_readb(dev, IFR);
        cuda_writeb(dev, IFR, val & 0x7f);
        if (val & SR_INT)
            break;
    }
}

static int cuda_request (cuda_t *dev, uint8_t pkt_type, const uint8_t *buf,
                         int buf_len, uint8_t *obuf)
{
    int i, obuf_len, val;

    cuda_writeb(dev, ACR, cuda_readb(dev, ACR) | SR_OUT);
    cuda_writeb(dev, SR, pkt_type);
    cuda_writeb(dev, B, cuda_readb(dev, B) & ~TIP);
    if (buf) {
        CUDA_DPRINTF("Send buf len: %d\n", buf_len);
        /* send 'buf' */
        for(i = 0; i < buf_len; i++) {
            cuda_wait_irq(dev);
            cuda_writeb(dev, SR, buf[i]);
            cuda_writeb(dev, B, cuda_readb(dev, B) ^ TACK);
        }
    }
    cuda_wait_irq(dev);
    cuda_writeb(dev, ACR, cuda_readb(dev, ACR) & ~SR_OUT);
    cuda_readb(dev, SR);
    cuda_writeb(dev, B, cuda_readb(dev, B) | TIP | TACK);
    
    obuf_len = 0;
    if (obuf) {
        cuda_wait_irq(dev);
        cuda_readb(dev, SR);
        cuda_writeb(dev, B, cuda_readb(dev, B) & ~TIP);
        for(;;) {
            cuda_wait_irq(dev);
            val = cuda_readb(dev, SR);
            if (obuf_len < CUDA_BUF_SIZE)
                obuf[obuf_len++] = val;
            if (cuda_readb(dev, B) & TREQ)
                break;
            cuda_writeb(dev, B, cuda_readb(dev, B) ^ TACK);
        }
        cuda_writeb(dev, B, cuda_readb(dev, B) | TIP | TACK);

        cuda_wait_irq(dev);
        cuda_readb(dev, SR);
    }
    CUDA_DPRINTF("Got len: %d\n", obuf_len);

    return obuf_len;
}

#if 0
void cuda_test(void)
{
    int keycode;
    printf("cuda test:\n");
    cuda_init(0x80400000 + 0x16000);
    for(;;) {
        keycode = adb_read_key();
        if (keycode >= 0)
            printf("keycode=%x\n", keycode);
    }
}
#endif

/* Cuda ADB glue */
static int cuda_adb_req (void *host, const uint8_t *snd_buf, int len,
                         uint8_t *rcv_buf)
{
    uint8_t buffer[CUDA_BUF_SIZE], *pos;

    CUDA_DPRINTF("len: %d %02x\n", len, snd_buf[0]);
    len = cuda_request(host, ADB_PACKET, snd_buf, len, buffer);
    if (len > 1 && buffer[0] == ADB_PACKET) {
        pos = buffer + 2;
        len -= 2;
    } else {
        pos = buffer + 1;
        len = -1;
    }
    memcpy(rcv_buf, pos, len);

    return len;
}

cuda_t *cuda_init (uint32_t base)
{
    cuda_t *cuda;

    CUDA_DPRINTF(" base=%08x\n", base);
    cuda = malloc(sizeof(cuda_t));
    if (cuda == NULL)
        return NULL;
    cuda->base = base;
    cuda_writeb(cuda, B, cuda_readb(cuda, B) | TREQ | TIP);
#if 0
    {
        int len;

        /* enable auto poll */
        buf[0] = 0x01;
        buf[1] = 1;
        len = cuda_request(cuda, CUDA_PACKET, buf, 2, obuf);
        if (len != 2 || obuf[0] != CUDA_PACKET || obuf[1] != 1) {
            printf("cuda: invalid reply for auto poll request");
            free(cuda);
            return NULL;
        }
    }
#endif
    cuda->adb_bus = adb_bus_new(cuda, &cuda_adb_req);
    if (cuda->adb_bus == NULL) {
        free(cuda);
        return NULL;
    }
    adb_bus_init(cuda->adb_bus);

    return cuda;
}

void cuda_reset (cuda_t *cuda)
{
    adb_bus_reset(cuda->adb_bus);
}

/* ADB generic driver */
#ifdef DEBUG_ADB
#define ADB_DPRINTF(fmt, args...) \
do { dprintf("ADB - %s: " fmt, __func__ , ##args); } while (0)
#else
#define ADB_DPRINTF(fmt, args...) do { } while (0)
#endif

int adb_cmd (adb_dev_t *dev, uint8_t cmd, uint8_t reg,
             uint8_t *buf, int len)
{
    uint8_t adb_send[ADB_BUF_SIZE], adb_rcv[ADB_BUF_SIZE];
    
    ADB_DPRINTF("cmd: %d reg: %d len: %d\n", cmd, reg, len);
    if (dev->bus == NULL || dev->bus->req == NULL) {
        ADB_DPRINTF("ERROR: invalid bus !\n");
        bug();
    }
    /* Sanity checks */
    if (cmd != ADB_LISTEN && len != 0) {
        /* No buffer transmitted but for LISTEN command */
        ADB_DPRINTF("in buffer for cmd %d\n", cmd);
        return -1;
    }
    if (cmd == ADB_LISTEN && ((len < 2 || len > 8) || buf == NULL)) {
        /* Need a buffer with a regular register size for LISTEN command */
        ADB_DPRINTF("no/invalid buffer for ADB_LISTEN (%d)\n", len);
        return -1;
    }
    if ((cmd == ADB_TALK || cmd == ADB_LISTEN) && reg > 3) {
        /* Need a valid register number for LISTEN and TALK commands */
        ADB_DPRINTF("invalid reg for TALK/LISTEN command (%d %d)\n", cmd, reg);
        return -1;
    }
    switch (cmd) {
    case ADB_SEND_RESET:
        adb_send[0] = ADB_SEND_RESET;
        break;
    case ADB_FLUSH:
        adb_send[0] = (dev->addr << 4) | ADB_FLUSH;
        break;
    case ADB_LISTEN:
        memcpy(adb_send + 1, buf, len);
        /* No break here */
    case ADB_TALK:
        adb_send[0] = (dev->addr << 4) | cmd | reg;
        break;
    }
    memset(adb_rcv, 0, ADB_BUF_SIZE);
    len = (*dev->bus->req)(dev->bus->host, adb_send, len + 1, adb_rcv);
#ifdef DEBUG_ADB
    printf("%x %x %x %x\n", adb_rcv[0], adb_rcv[1], adb_rcv[2], adb_rcv[3]);
#endif
    switch (len) {
    case 0:
        /* No data */
        break;
    case 2 ... 8:
        /* Register transmitted */
        if (buf != NULL)
            memcpy(buf, adb_rcv, len);
        break;
    default:
        /* Should never happen */
        ADB_DPRINTF("Cmd %d returned %d bytes !\n", cmd, len);
        return -1;
    }
    ADB_DPRINTF("retlen: %d\n", len);
    
    return len;
}

void adb_bus_reset (adb_bus_t *bus)
{
    adb_reset(bus);
}

adb_bus_t *adb_bus_new (void *host,
                        int (*req)(void *host, const uint8_t *snd_buf,
                                   int len, uint8_t *rcv_buf))
{
    adb_bus_t *new;

    new = malloc(sizeof(adb_bus_t));
    if (new == NULL)
        return NULL;
    new->host = host;
    new->req = req;

    return new;
}

/* ADB */
void *adb_kbd_new (void *private);

static int adb_mouse_open (void *private);
static int adb_mouse_close (void *private);
static int adb_mouse_read (void *private);

static cops_t adb_mouse_ops = {
    &adb_mouse_open,
    &adb_mouse_close,
    &adb_mouse_read,
    NULL,
};

/* Check and relocate all ADB devices as suggested in
 * ADB_manager Apple documentation
 */
int adb_bus_init (adb_bus_t *bus)
{
    uint8_t buffer[ADB_BUF_SIZE];
    uint8_t adb_addresses[16] =
        { 8, 9, 10, 11, 12, 13, 14, -1, -1, -1, -1, -1, -1, -1, 0, };
    adb_dev_t tmp_device, **cur;
    int address;
    int reloc = 0, next_free = 7;
    int keep;

    /* Reset the bus */
    ADB_DPRINTF("\n");
    adb_reset(bus);
    cur = &bus->devices;
    memset(&tmp_device, 0, sizeof(adb_dev_t));
    tmp_device.bus = bus;
    for (address = 1; address < 8 && adb_addresses[reloc] > 0;) {
        if (address == ADB_RES) {
            /* Reserved */
            address++;
            continue;
        }
        ADB_DPRINTF("Check device on ADB address %d\n", address);
        tmp_device.addr = address;
        switch (adb_reg_get(&tmp_device, 3, buffer)) {
        case 0:
            ADB_DPRINTF("No device on ADB address %d\n", address);
            /* Register this address as free */
            if (adb_addresses[next_free] != 0)
                adb_addresses[next_free++] = address;
            /* Check next ADB address */
            address++;
            break;
        case 2:
            /* One device answered :
             * make it available and relocate it to a free address
             */
            if (buffer[0] == ADB_CHADDR) {
                /* device self test failed */
                ADB_DPRINTF("device on ADB address %d self-test failed "
                            "%02x %02x %02x\n", address,
                            buffer[0], buffer[1], buffer[2]);
                keep = 0;
            } else {
                ADB_DPRINTF("device on ADB address %d self-test OK\n",
                            address);
                keep = 1;
            }
            ADB_DPRINTF("Relocate device on ADB address %d to %d (%d)\n",
                        address, adb_addresses[reloc], reloc);
            buffer[0] = ((buffer[0] & 0x40) & ~0x90) | adb_addresses[reloc];
            if (keep == 1)
                buffer[0] |= 0x20;
            buffer[1] = ADB_CHADDR_NOCOLL;
            if (adb_reg_set(&tmp_device, 3, buffer, 2) < 0) {
                ADB_DPRINTF("ADB device relocation failed\n");
                return -1;
            }
            if (keep == 1) {
                *cur = malloc(sizeof(adb_dev_t));
                if (*cur == NULL) {
                    return -1;
                }
                (*cur)->type = address;
                (*cur)->bus = bus;
                (*cur)->addr = adb_addresses[reloc++];
                /* Flush buffers */
                adb_flush(*cur);
                switch ((*cur)->type) {
                case ADB_PROTECT:
                    ADB_DPRINTF("Found one protected device\n");
                    break;
                case ADB_KEYBD:
                    ADB_DPRINTF("Found one keyboard\n");
                    adb_kbd_new(*cur);
                    break;
                case ADB_MOUSE:
                    ADB_DPRINTF("Found one mouse\n");
                    chardev_register(CHARDEV_MOUSE, &adb_mouse_ops, *cur);
                    break;
                case ADB_ABS:
                    ADB_DPRINTF("Found one absolute positioning device\n");
                    break;
                case ADB_MODEM:
                    ADB_DPRINTF("Found one modem\n");
                    break;
                case ADB_RES:
                    ADB_DPRINTF("Found one ADB res device\n");
                    break;
                case ADB_MISC:
                    ADB_DPRINTF("Found one ADB misc device\n");
                    break;
                }
                cur = &((*cur)->next);
            }
            break;
        case 1:
        case 3 ... 7:
            /* SHOULD NOT HAPPEN : register 3 is always two bytes long */
            ADB_DPRINTF("Invalid returned len for ADB register 3\n");
            return -1;
        case -1:
            /* ADB ERROR */
            ADB_DPRINTF("error gettting ADB register 3\n");
            return -1;
        }
    }

    return 0;
}

/* ADB mouse chardev interface (TODO) */
static int adb_mouse_open (unused void *private)
{
    return 0;
}

static int adb_mouse_close (unused void *private)
{
    return 0;
}

static int adb_mouse_read (unused void *private)
{
    return -1;
}
