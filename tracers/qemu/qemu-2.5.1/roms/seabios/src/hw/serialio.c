// Low-level serial (and serial-like) device access.
//
// Copyright (C) 2008-1013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // CONFIG_DEBUG_SERIAL
#include "fw/paravirt.h" // RunningOnQEMU
#include "output.h" // dprintf
#include "serialio.h" // serial_debug_preinit
#include "x86.h" // outb


/****************************************************************
 * Serial port debug output
 ****************************************************************/

#define DEBUG_TIMEOUT 100000

// Setup the debug serial port for output.
void
serial_debug_preinit(void)
{
    if (!CONFIG_DEBUG_SERIAL)
        return;
    // setup for serial logging: 8N1
    u8 oldparam, newparam = 0x03;
    oldparam = inb(CONFIG_DEBUG_SERIAL_PORT+SEROFF_LCR);
    outb(newparam, CONFIG_DEBUG_SERIAL_PORT+SEROFF_LCR);
    // Disable irqs
    u8 oldier, newier = 0;
    oldier = inb(CONFIG_DEBUG_SERIAL_PORT+SEROFF_IER);
    outb(newier, CONFIG_DEBUG_SERIAL_PORT+SEROFF_IER);

    if (oldparam != newparam || oldier != newier)
        dprintf(1, "Changing serial settings was %x/%x now %x/%x\n"
                , oldparam, oldier, newparam, newier);
}

// Write a character to the serial port.
static void
serial_debug(char c)
{
    if (!CONFIG_DEBUG_SERIAL)
        return;
    int timeout = DEBUG_TIMEOUT;
    while ((inb(CONFIG_DEBUG_SERIAL_PORT+SEROFF_LSR) & 0x20) != 0x20)
        if (!timeout--)
            // Ran out of time.
            return;
    outb(c, CONFIG_DEBUG_SERIAL_PORT+SEROFF_DATA);
}

void
serial_debug_putc(char c)
{
    if (c == '\n')
        serial_debug('\r');
    serial_debug(c);
}

// Make sure all serial port writes have been completely sent.
void
serial_debug_flush(void)
{
    if (!CONFIG_DEBUG_SERIAL)
        return;
    int timeout = DEBUG_TIMEOUT;
    while ((inb(CONFIG_DEBUG_SERIAL_PORT+SEROFF_LSR) & 0x60) != 0x60)
        if (!timeout--)
            // Ran out of time.
            return;
}


/****************************************************************
 * QEMU debug port
 ****************************************************************/

u16 DebugOutputPort VARFSEG = 0x402;

// Write a character to the special debugging port.
void
qemu_debug_putc(char c)
{
    if (CONFIG_DEBUG_IO && runningOnQEMU())
        // Send character to debug port.
        outb(c, GET_GLOBAL(DebugOutputPort));
}
