// Support for handling the PS/2 mouse/keyboard ports.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Several ideas taken from code Copyright (c) 1999-2004 Vojtech Pavlik
//
// This file may be distributed under the terms of the GNU LGPLv3 license.
//
// This file is copied (mostly) intact from SeaBIOS.

#include "protos.h"
#include "ioport.h"
#include "ps2port.h"

typedef uint64_t u64;

#define dprintf(lvl, fmt, ...)
#define warn_timeout()

static inline u64
calc_future_tsc(int timeout)
{
  return get_wall_time() + timeout;
}

static inline bool
check_tsc(u64 end)
{
  return get_wall_time() > end;
}

static inline void
yield(void)
{
  udelay(1);
}

static struct {
  u8 ps2ctr;
} ebda;

#define GET_EBDA(VAR)		ebda.VAR
#define SET_EBDA(VAR, VAL)	(ebda.VAR = (VAL))

#define ASSERT32FLAT()
#define CONFIG_PS2PORT 1

#define enable_hwirq(level, func)
#define run_thread(func, val)	func(val)

/****************************************************************
 * Low level i8042 commands.
 ****************************************************************/

// Timeout value.
#define I8042_CTL_TIMEOUT       10000

#define I8042_BUFFER_SIZE       16

static int
i8042_wait_read(void)
{
    dprintf(7, "i8042_wait_read\n");
    int i;
    for (i=0; i<I8042_CTL_TIMEOUT; i++) {
        u8 status = inb(PORT_PS2_STATUS);
        if (status & I8042_STR_OBF)
            return 0;
        udelay(50);
    }
    warn_timeout();
    return -1;
}

static int
i8042_wait_write(void)
{
    dprintf(7, "i8042_wait_write\n");
    int i;
    for (i=0; i<I8042_CTL_TIMEOUT; i++) {
        u8 status = inb(PORT_PS2_STATUS);
        if (! (status & I8042_STR_IBF))
            return 0;
        udelay(50);
    }
    warn_timeout();
    return -1;
}

static int
i8042_flush(void)
{
    dprintf(7, "i8042_flush\n");
    int i;
    for (i=0; i<I8042_BUFFER_SIZE; i++) {
        u8 status = inb(PORT_PS2_STATUS);
        if (! (status & I8042_STR_OBF))
            return 0;
        udelay(50);
	inb(PORT_PS2_DATA);
    }

    warn_timeout();
    return -1;
}

static int
__i8042_command(int command, u8 *param)
{
    int receive = (command >> 8) & 0xf;
    int send = (command >> 12) & 0xf;

    // Send the command.
    int ret = i8042_wait_write();
    if (ret)
        return ret;
    outb(command, PORT_PS2_STATUS);

    // Send parameters (if any).
    int i;
    for (i = 0; i < send; i++) {
        ret = i8042_wait_write();
        if (ret)
            return ret;
        outb(param[i], PORT_PS2_DATA);
    }

    // Receive parameters (if any).
    for (i = 0; i < receive; i++) {
        ret = i8042_wait_read();
        if (ret)
            return ret;
        param[i] = inb(PORT_PS2_DATA);
        dprintf(7, "i8042 param=%x\n", param[i]);
    }

    return 0;
}

static int
i8042_command(int command, u8 *param)
{
    dprintf(7, "i8042_command cmd=%x\n", command);
    int ret = __i8042_command(command, param);
    if (ret)
        dprintf(2, "i8042 command %x failed\n", command);
    return ret;
}

static int
i8042_kbd_write(u8 c)
{
    dprintf(7, "i8042_kbd_write c=%d\n", c);
    int ret = i8042_wait_write();
    if (! ret)
        outb(c, PORT_PS2_DATA);
    return ret;
}

static int
i8042_aux_write(u8 c)
{
    return i8042_command(I8042_CMD_AUX_SEND, &c);
}

void
i8042_reboot(void)
{
    int i;
    for (i=0; i<10; i++) {
        i8042_wait_write();
        udelay(50);
        outb(0xfe, PORT_PS2_STATUS); /* pulse reset low */
        udelay(50);
    }
}


/****************************************************************
 * Device commands.
 ****************************************************************/

#define PS2_RET_ACK             0xfa
#define PS2_RET_NAK             0xfe

static int
ps2_recvbyte(int aux, int needack, int timeout)
{
    u64 end = calc_future_tsc(timeout);
    for (;;) {
        u8 status = inb(PORT_PS2_STATUS);
        if (status & I8042_STR_OBF) {
            u8 data = inb(PORT_PS2_DATA);
            dprintf(7, "ps2 read %x\n", data);

            if (!!(status & I8042_STR_AUXDATA) == aux) {
                if (!needack)
                    return data;
                if (data == PS2_RET_ACK)
                    return data;
                if (data == PS2_RET_NAK) {
                    dprintf(1, "Got ps2 nak (status=%x)\n", status);
                    return data;
                }
            }

            // This data not part of command - just discard it.
            dprintf(1, "Discarding ps2 data %02x (status=%02x)\n", data, status);
        }

        if (check_tsc(end)) {
            // Don't warn on second byte of a reset
            if (timeout > 100)
                warn_timeout();
            return -1;
        }
        yield();
    }
}

static int
ps2_sendbyte(int aux, u8 command, int timeout)
{
    dprintf(7, "ps2_sendbyte aux=%d cmd=%x\n", aux, command);
    int ret;
    if (aux)
        ret = i8042_aux_write(command);
    else
        ret = i8042_kbd_write(command);
    if (ret)
        return ret;

    // Read ack.
    ret = ps2_recvbyte(aux, 1, timeout);
    if (ret < 0)
        return ret;
    if (ret != PS2_RET_ACK)
        return -1;

    return 0;
}

static int
__ps2_command(int aux, int command, u8 *param)
{
    int ret2;
    int receive = (command >> 8) & 0xf;
    int send = (command >> 12) & 0xf;

    // Disable interrupts and keyboard/mouse.
    u8 ps2ctr = GET_EBDA(ps2ctr);
    u8 newctr = ((ps2ctr | I8042_CTR_AUXDIS | I8042_CTR_KBDDIS)
                 & ~(I8042_CTR_KBDINT|I8042_CTR_AUXINT));
    dprintf(6, "i8042 ctr old=%x new=%x\n", ps2ctr, newctr);
    int ret = i8042_command(I8042_CMD_CTL_WCTR, &newctr);
    if (ret)
        return ret;

    // Flush any interrupts already pending.
    yield();

    // Enable port command is being sent to.
    if (aux)
        newctr &= ~I8042_CTR_AUXDIS;
    else
        newctr &= ~I8042_CTR_KBDDIS;
    ret = i8042_command(I8042_CMD_CTL_WCTR, &newctr);
    if (ret)
        goto fail;

    if (command == ATKBD_CMD_RESET_BAT) {
        // Reset is special wrt timeouts and bytes received.

        // Send command.
        ret = ps2_sendbyte(aux, command, 1000);
        if (ret)
            goto fail;

        // Receive parameters.
        ret = ps2_recvbyte(aux, 0, 4000);
        if (ret < 0)
            goto fail;
        param[0] = ret;
        ret = ps2_recvbyte(aux, 0, 100);
        if (ret < 0)
            // Some devices only respond with one byte on reset.
            ret = 0;
        param[1] = ret;
    } else if (command == ATKBD_CMD_GETID) {
        // Getid is special wrt bytes received.

        // Send command.
        ret = ps2_sendbyte(aux, command, 200);
        if (ret)
            goto fail;

        // Receive parameters.
        ret = ps2_recvbyte(aux, 0, 500);
        if (ret < 0)
            goto fail;
        param[0] = ret;
        if (ret == 0xab || ret == 0xac || ret == 0x2b || ret == 0x5d
            || ret == 0x60 || ret == 0x47) {
            // These ids (keyboards) return two bytes.
            ret = ps2_recvbyte(aux, 0, 500);
            if (ret < 0)
                goto fail;
            param[1] = ret;
        } else {
            param[1] = 0;
        }
    } else {
        // Send command.
        ret = ps2_sendbyte(aux, command, 200);
        if (ret)
            goto fail;

        // Send parameters (if any).
        int i;
        for (i = 0; i < send; i++) {
            ret = ps2_sendbyte(aux, param[i], 200);
            if (ret)
                goto fail;
        }

        // Receive parameters (if any).
        for (i = 0; i < receive; i++) {
            ret = ps2_recvbyte(aux, 0, 500);
            if (ret < 0)
                goto fail;
            param[i] = ret;
        }
    }

    ret = 0;

fail:
    // Restore interrupts and keyboard/mouse.
    ret2 = i8042_command(I8042_CMD_CTL_WCTR, &ps2ctr);
    if (ret2)
        return ret2;

    return ret;
}

static int
ps2_command(int aux, int command, u8 *param)
{
    dprintf(7, "ps2_command aux=%d cmd=%x\n", aux, command);
    int ret = __ps2_command(aux, command, param);
    if (ret)
        dprintf(2, "ps2 command %x failed (aux=%d)\n", command, aux);
    return ret;
}

int
ps2_kbd_command(int command, u8 *param)
{
    return ps2_command(0, command, param);
}

int
ps2_mouse_command(int command, u8 *param)
{
    return ps2_command(1, command, param);
}


/****************************************************************
 * IRQ handlers
 ****************************************************************/
#if 0

// INT74h : PS/2 mouse hardware interrupt
void VISIBLE16
handle_74(void)
{
    if (! CONFIG_PS2PORT)
        return;

    debug_isr(DEBUG_ISR_74);

    u8 v = inb(PORT_PS2_STATUS);
    if ((v & (I8042_STR_OBF|I8042_STR_AUXDATA))
        != (I8042_STR_OBF|I8042_STR_AUXDATA)) {
        dprintf(1, "ps2 mouse irq but no mouse data.\n");
        goto done;
    }
    v = inb(PORT_PS2_DATA);

    if (!(GET_EBDA(ps2ctr) & I8042_CTR_AUXINT))
        // Interrupts not enabled.
        goto done;

    process_mouse(v);

done:
    eoi_pic2();
}

// INT09h : Keyboard Hardware Service Entry Point
void VISIBLE16
handle_09(void)
{
    if (! CONFIG_PS2PORT)
        return;

    debug_isr(DEBUG_ISR_09);

    // read key from keyboard controller
    u8 v = inb(PORT_PS2_STATUS);
    if (v & I8042_STR_AUXDATA) {
        dprintf(1, "ps2 keyboard irq but found mouse data?!\n");
        goto done;
    }
    v = inb(PORT_PS2_DATA);

    if (!(GET_EBDA(ps2ctr) & I8042_CTR_KBDINT))
        // Interrupts not enabled.
        goto done;

    process_key(v);

done:
    eoi_pic1();
}

#endif
/****************************************************************
 * Setup
 ****************************************************************/

static void
keyboard_init(void *data)
{
    /* flush incoming keys */
    int ret = i8042_flush();
    if (ret)
        return;

    // Controller self-test.
    u8 param[2];
    ret = i8042_command(I8042_CMD_CTL_TEST, param);
    if (ret)
        return;
    if (param[0] != 0x55) {
        dprintf(1, "i8042 self test failed (got %x not 0x55)\n", param[0]);
        return;
    }

    // Controller keyboard test.
    ret = i8042_command(I8042_CMD_KBD_TEST, param);
    if (ret)
        return;
    if (param[0] != 0x00) {
        dprintf(1, "i8042 keyboard test failed (got %x not 0x00)\n", param[0]);
        return;
    }

    // Disable keyboard and mouse events.
    SET_EBDA(ps2ctr, I8042_CTR_KBDDIS | I8042_CTR_AUXDIS);


    /* ------------------- keyboard side ------------------------*/
    /* reset keyboard and self test  (keyboard side) */
    ret = ps2_kbd_command(ATKBD_CMD_RESET_BAT, param);
    if (ret)
        return;
    if (param[0] != 0xaa) {
        dprintf(1, "keyboard self test failed (got %x not 0xaa)\n", param[0]);
        return;
    }

    /* Disable keyboard */
    ret = ps2_kbd_command(ATKBD_CMD_RESET_DIS, NULL);
    if (ret)
        return;

    // Set scancode command (mode 2)
    param[0] = 0x02;
    ret = ps2_kbd_command(ATKBD_CMD_SSCANSET, param);
    if (ret)
        return;

    // Keyboard Mode: disable mouse, scan code convert, enable kbd IRQ
    SET_EBDA(ps2ctr, I8042_CTR_AUXDIS | I8042_CTR_XLATE | I8042_CTR_KBDINT);

    /* Enable keyboard */
    ret = ps2_kbd_command(ATKBD_CMD_ENABLE, NULL);
    if (ret)
        return;

    dprintf(1, "PS2 keyboard initialized\n");
}

void
ps2port_setup(void)
{
    ASSERT32FLAT();
    if (! CONFIG_PS2PORT)
        return;
    dprintf(3, "init ps2port\n");

    enable_hwirq(1, FUNC16(entry_09));
    enable_hwirq(12, FUNC16(entry_74));

    run_thread(keyboard_init, NULL);
}
