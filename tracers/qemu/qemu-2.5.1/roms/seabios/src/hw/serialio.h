#ifndef __SERIALIO_H
#define __SERIALIO_H

#include "types.h" // u16

#define PORT_LPT2              0x0278
#define PORT_SERIAL4           0x02e8
#define PORT_SERIAL2           0x02f8
#define PORT_LPT1              0x0378
#define PORT_SERIAL3           0x03e8
#define PORT_SERIAL1           0x03f8

// Serial port offsets
#define SEROFF_DATA    0
#define SEROFF_DLL     0
#define SEROFF_IER     1
#define SEROFF_DLH     1
#define SEROFF_IIR     2
#define SEROFF_LCR     3
#define SEROFF_LSR     5
#define SEROFF_MSR     6

void serial_debug_preinit(void);
void serial_debug_putc(char c);
void serial_debug_flush(void);
extern u16 DebugOutputPort;
void qemu_debug_putc(char c);

#endif // serialio.h
