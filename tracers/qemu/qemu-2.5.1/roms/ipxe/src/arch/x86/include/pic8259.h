/*
 * Basic support for controlling the 8259 Programmable Interrupt Controllers.
 *
 * Initially written by Michael Brown (mcb30).
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifndef PIC8259_H
#define PIC8259_H

#include <ipxe/io.h>

#define IRQ_PIC_CUTOFF 8

/* 8259 register locations */
#define PIC1_ICW1 0x20
#define PIC1_OCW2 0x20
#define PIC1_OCW3 0x20
#define PIC1_ICR 0x20
#define PIC1_IRR 0x20
#define PIC1_ISR 0x20
#define PIC1_ICW2 0x21
#define PIC1_ICW3 0x21
#define PIC1_ICW4 0x21
#define PIC1_IMR 0x21
#define PIC2_ICW1 0xa0
#define PIC2_OCW2 0xa0
#define PIC2_OCW3 0xa0
#define PIC2_ICR 0xa0
#define PIC2_IRR 0xa0
#define PIC2_ISR 0xa0
#define PIC2_ICW2 0xa1
#define PIC2_ICW3 0xa1
#define PIC2_ICW4 0xa1
#define PIC2_IMR 0xa1

/* Register command values */
#define OCW3_ID 0x08
#define OCW3_READ_IRR 0x03
#define OCW3_READ_ISR 0x02
#define ICR_EOI_NON_SPECIFIC 0x20
#define ICR_EOI_NOP 0x40
#define ICR_EOI_SPECIFIC 0x60
#define ICR_EOI_SET_PRIORITY 0xc0

/* Macros to enable/disable IRQs */
#define IMR_REG(x) ( (x) < IRQ_PIC_CUTOFF ? PIC1_IMR : PIC2_IMR )
#define IMR_BIT(x) ( 1 << ( (x) % IRQ_PIC_CUTOFF ) )
#define irq_enabled(x) ( ( inb ( IMR_REG(x) ) & IMR_BIT(x) ) == 0 )
#define enable_irq(x) outb ( inb( IMR_REG(x) ) & ~IMR_BIT(x), IMR_REG(x) )
#define disable_irq(x) outb ( inb( IMR_REG(x) ) | IMR_BIT(x), IMR_REG(x) )

/* Macros for acknowledging IRQs */
#define ICR_REG( irq ) ( (irq) < IRQ_PIC_CUTOFF ? PIC1_ICR : PIC2_ICR )
#define ICR_VALUE( irq ) ( (irq) % IRQ_PIC_CUTOFF )
#define CHAINED_IRQ 2

/* Utility macros to convert IRQ numbers to INT numbers and INT vectors  */
#define IRQ_INT( irq ) ( ( ( (irq) - IRQ_PIC_CUTOFF ) ^ 0x70 ) & 0x7f )

/* Other constants */
#define IRQ_MAX 15
#define IRQ_NONE -1U

/* Function prototypes
 */
void send_eoi ( unsigned int irq );

#endif /* PIC8259_H */
