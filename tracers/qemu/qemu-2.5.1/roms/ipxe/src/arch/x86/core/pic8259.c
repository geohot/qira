/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/io.h>
#include <pic8259.h>

/** @file
 *
 * Minimal support for the 8259 Programmable Interrupt Controller
 *
 */

/**
 * Send non-specific EOI(s)
 *
 * @v irq		IRQ number
 *
 * This seems to be inherently unsafe.
 */
static inline void send_nonspecific_eoi ( unsigned int irq ) {
	DBG ( "Sending non-specific EOI for IRQ %d\n", irq );
	if ( irq >= IRQ_PIC_CUTOFF ) {
		outb ( ICR_EOI_NON_SPECIFIC, PIC2_ICR );
	}		
	outb ( ICR_EOI_NON_SPECIFIC, PIC1_ICR );
}

/**
 * Send specific EOI(s)
 *
 * @v irq		IRQ number
 */
static inline void send_specific_eoi ( unsigned int irq ) {
	DBG ( "Sending specific EOI for IRQ %d\n", irq );
	if ( irq >= IRQ_PIC_CUTOFF ) {
		outb ( ( ICR_EOI_SPECIFIC | ICR_VALUE ( CHAINED_IRQ ) ),
		       ICR_REG ( CHAINED_IRQ ) );
	}
	outb ( ( ICR_EOI_SPECIFIC | ICR_VALUE ( irq ) ), ICR_REG ( irq ) );
}

/**
 * Send End-Of-Interrupt to the PIC
 *
 * @v irq		IRQ number
 */
void send_eoi ( unsigned int irq ) {
	send_specific_eoi ( irq );
}
