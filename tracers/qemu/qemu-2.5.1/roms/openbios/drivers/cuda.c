#include "config.h"
#include "libopenbios/bindings.h"
#include "drivers/drivers.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "macio.h"
#include "cuda.h"

//#define DEBUG_CUDA
#ifdef DEBUG_CUDA
#define CUDA_DPRINTF(fmt, args...) \
	do { printk("CUDA - %s: " fmt, __func__ , ##args); } while (0)
#else
#define CUDA_DPRINTF(fmt, args...) do { } while (0)
#endif

#define IO_CUDA_OFFSET	0x00016000
#define IO_CUDA_SIZE	0x00002000

/* VIA registers - spaced 0x200 bytes apart */
#define RS              0x200           /* skip between registers */
#define B               0               /* B-side data */
#define A               RS              /* A-side data */
#define DIRB            (2*RS)          /* B-side direction (1=output) */
#define DIRA            (3*RS)          /* A-side direction (1=output) */
#define T1CL            (4*RS)          /* Timer 1 ctr/latch (low 8 bits) */
#define T1CH            (5*RS)          /* Timer 1 counter (high 8 bits) */
#define T1LL            (6*RS)          /* Timer 1 latch (low 8 bits) */
#define T1LH            (7*RS)          /* Timer 1 latch (high 8 bits) */
#define T2CL            (8*RS)          /* Timer 2 ctr/latch (low 8 bits) */
#define T2CH            (9*RS)          /* Timer 2 counter (high 8 bits) */
#define SR              (10*RS)         /* Shift register */
#define ACR             (11*RS)         /* Auxiliary control register */
#define PCR             (12*RS)         /* Peripheral control register */
#define IFR             (13*RS)         /* Interrupt flag register */
#define IER             (14*RS)         /* Interrupt enable register */
#define ANH             (15*RS)         /* A-side data, no handshake */

/* Bits in B data register: all active low */
#define TREQ            0x08            /* Transfer request (input) */
#define TACK            0x10            /* Transfer acknowledge (output) */
#define TIP             0x20            /* Transfer in progress (output) */

/* Bits in ACR */
#define SR_CTRL         0x1c            /* Shift register control bits */
#define SR_EXT          0x0c            /* Shift on external clock */
#define SR_OUT          0x10            /* Shift out if 1 */

/* Bits in IFR and IER */
#define IER_SET         0x80            /* set bits in IER */
#define IER_CLR         0               /* clear bits in IER */
#define SR_INT          0x04            /* Shift register full/empty */

#define CUDA_BUF_SIZE 16

#define ADB_PACKET      0
#define CUDA_PACKET     1

/* CUDA commands (2nd byte) */
#define CUDA_GET_TIME			0x03
#define CUDA_SET_TIME			0x09
#define CUDA_POWERDOWN                  0x0a
#define CUDA_RESET_SYSTEM               0x11

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

//    CUDA_DPRINTF("\n");
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
        //CUDA_DPRINTF("Send buf len: %d\n", buf_len);
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
//    CUDA_DPRINTF("Got len: %d\n", obuf_len);

    return obuf_len;
}



static int cuda_adb_req (void *host, const uint8_t *snd_buf, int len,
                         uint8_t *rcv_buf)
{
    uint8_t buffer[CUDA_BUF_SIZE], *pos;

 //   CUDA_DPRINTF("len: %d %02x\n", len, snd_buf[0]);
    len = cuda_request(host, ADB_PACKET, snd_buf, len, buffer);
    if (len > 1 && buffer[0] == ADB_PACKET) {
        /* We handle 2 types of ADB packet here:
               Normal: <type> <status> <data> ...
               Error : <type> <status> <cmd> (<data> ...)
           Ideally we should use buffer[1] (status) to determine whether this
           is a normal or error packet but this requires a corresponding fix
           in QEMU <= 2.4. Hence we temporarily handle it this way to ease
           the transition. */
        if (len > 2 && buffer[2] == snd_buf[0]) {
            /* Error */
            pos = buffer + 3;
            len -= 3;
        } else {
            /* Normal */
            pos = buffer + 2;
            len -= 2;
        }
    } else {
        pos = buffer + 1;
        len = -1;
    }
    memcpy(rcv_buf, pos, len);

    return len;
}


DECLARE_UNNAMED_NODE(ob_cuda, INSTALL_OPEN, sizeof(int));

static cuda_t *main_cuda;

static void
ppc32_reset_all(void)
{
        uint8_t cmdbuf[2], obuf[64];

        cmdbuf[0] = CUDA_RESET_SYSTEM;
        cuda_request(main_cuda, CUDA_PACKET, cmdbuf, sizeof(cmdbuf), obuf);
}

static void
ppc32_poweroff(void)
{
        uint8_t cmdbuf[2], obuf[64];

        cmdbuf[0] = CUDA_POWERDOWN;
        cuda_request(main_cuda, CUDA_PACKET, cmdbuf, sizeof(cmdbuf), obuf);
}

static void
ob_cuda_initialize (int *idx)
{
	phandle_t ph=get_cur_dev();
	int props[2];

	push_str("via-cuda");
	fword("device-type");

	set_int_property(ph, "#address-cells", 1);
        set_int_property(ph, "#size-cells", 0);

	set_property(ph, "compatible", "cuda", 5);

	props[0] = __cpu_to_be32(IO_CUDA_OFFSET);
	props[1] = __cpu_to_be32(IO_CUDA_SIZE);

	set_property(ph, "reg", (char *)&props, sizeof(props));

	/* on newworld machines the cuda is on interrupt 0x19 */

	props[0] = 0x19;
	props[1] = 0;
	NEWWORLD(set_property(ph, "interrupts", (char *)props, sizeof(props)));
	NEWWORLD(set_int_property(ph, "#interrupt-cells", 2));

	/* we emulate an oldworld hardware, so we must use
	 * non-standard oldworld property (needed by linux 2.6.18)
	 */

	OLDWORLD(set_int_property(ph, "AAPL,interrupts", 0x12));

        bind_func("ppc32-reset-all", ppc32_reset_all);
        push_str("' ppc32-reset-all to reset-all");
        fword("eval");
}

static void
ob_cuda_open(int *idx)
{
	RET(-1);
}

static void
ob_cuda_close(int *idx)
{
}

NODE_METHODS(ob_cuda) = {
	{ NULL,			ob_cuda_initialize	},
	{ "open",		ob_cuda_open		},
	{ "close",		ob_cuda_close		},
};

DECLARE_UNNAMED_NODE(rtc, INSTALL_OPEN, sizeof(int));

static void
rtc_open(int *idx)
{
	RET(-1);
}

/*
 * get-time ( -- second minute hour day month year )
 *
 */

static const int days_month[12] =
	{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static const int days_month_leap[12] =
	{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static inline int is_leap(int year)
{
	return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

static  void
rtc_get_time(int *idx)
{
        uint8_t cmdbuf[2], obuf[64];
	ucell second, minute, hour, day, month, year;
	uint32_t now;
	int current;
	const int *days;

        cmdbuf[0] = CUDA_GET_TIME;
        cuda_request(main_cuda, CUDA_PACKET, cmdbuf, sizeof(cmdbuf), obuf);

	/* seconds since 01/01/1904 */

	now = (obuf[3] << 24) + (obuf[4] << 16) + (obuf[5] << 8) + obuf[6];

	second =  now % 60;
	now /= 60;

	minute = now % 60;
	now /= 60;

	hour = now % 24;
	now /= 24;

	year = now * 100 / 36525;
	now -= year * 36525 / 100;
	year += 1904;

	days = is_leap(year) ?  days_month_leap : days_month;

	current = 0;
	month = 0;
	while (month < 12) {
		if (now <= current + days[month]) {
			break;
		}
		current += days[month];
		month++;
	}
	month++;

	day = now - current;

	PUSH(second);
	PUSH(minute);
	PUSH(hour);
	PUSH(day);
	PUSH(month);
	PUSH(year);
}

/*
 * set-time ( second minute hour day month year -- )
 *
 */

static  void
rtc_set_time(int *idx)
{
        uint8_t cmdbuf[5], obuf[3];
	ucell second, minute, hour, day, month, year;
	const int *days;
	uint32_t now;
	unsigned int nb_days;
	int i;

	year = POP();
	month = POP();
	day = POP();
	hour = POP();
	minute = POP();
	second = POP();

	days = is_leap(year) ?  days_month_leap : days_month;
	nb_days = (year - 1904) * 36525 / 100 + day;
	for (i = 0; i < month - 1; i++)
		nb_days += days[i];

	now = (((nb_days * 24) + hour) * 60 + minute) * 60 + second;

        cmdbuf[0] = CUDA_SET_TIME;
	cmdbuf[1] = now >> 24;
	cmdbuf[2] = now >> 16;
	cmdbuf[3] = now >> 8;
	cmdbuf[4] = now;

        cuda_request(main_cuda, CUDA_PACKET, cmdbuf, sizeof(cmdbuf), obuf);
}

NODE_METHODS(rtc) = {
	{ "open",		rtc_open		},
	{ "get-time",		rtc_get_time		},
	{ "set-time",		rtc_set_time		},
};

static void
rtc_init(char *path)
{
	phandle_t ph, aliases;
	char buf[64];

        snprintf(buf, sizeof(buf), "%s/rtc", path);
	REGISTER_NAMED_NODE(rtc, buf);

	ph = find_dev(buf);
	set_property(ph, "device_type", "rtc", 4);
	set_property(ph, "compatible", "rtc", 4);

	aliases = find_dev("/aliases");
	set_property(aliases, "rtc", buf, strlen(buf) + 1);

}

static void
powermgt_init(char *path)
{
	phandle_t ph;
	char buf[64];

        snprintf(buf, sizeof(buf), "%s/power-mgt", path);
	REGISTER_NAMED_NODE(rtc, buf);

	ph = find_dev(buf);
	set_property(ph, "device_type", "power-mgt", 10);
	set_property(ph, "mgt-kind", "min-consumption-pwm-led", strlen("min-consumption-pwm-led") + 1);
	set_property(ph, "compatible", "cuda", strlen("cuda") + 1);
}

cuda_t *cuda_init (const char *path, phys_addr_t base)
{
	cuda_t *cuda;
	char buf[64];
	phandle_t aliases;

	base += IO_CUDA_OFFSET;
	CUDA_DPRINTF(" base=" FMT_plx "\n", base);
	cuda = malloc(sizeof(cuda_t));
	if (cuda == NULL)
	    return NULL;

	snprintf(buf, sizeof(buf), "%s/via-cuda", path);
	REGISTER_NAMED_NODE(ob_cuda, buf);

	aliases = find_dev("/aliases");
	set_property(aliases, "via-cuda", buf, strlen(buf) + 1);

	cuda->base = base;
	cuda_writeb(cuda, B, cuda_readb(cuda, B) | TREQ | TIP);
#ifdef CONFIG_DRIVER_ADB
	cuda->adb_bus = adb_bus_new(cuda, &cuda_adb_req);
	if (cuda->adb_bus == NULL) {
	    free(cuda);
	    return NULL;
	}
	adb_bus_init(buf, cuda->adb_bus);
#endif

	rtc_init(buf);
	powermgt_init(buf);

        main_cuda = cuda;

	device_end();
	bind_func("poweroff", ppc32_poweroff);

	return cuda;
}
