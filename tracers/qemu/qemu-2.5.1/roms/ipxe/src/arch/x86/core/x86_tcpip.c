/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * TCP/IP checksum
 *
 */

#include <limits.h>
#include <ipxe/tcpip.h>

extern char x86_tcpip_loop_end[];

/**
 * Calculate continued TCP/IP checkum
 *
 * @v partial		Checksum of already-summed data, in network byte order
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret cksum		Updated checksum, in network byte order
 */
uint16_t x86_tcpip_continue_chksum ( uint16_t partial,
				     const void *data, size_t len ) {
	unsigned long sum = ( ( ~partial ) & 0xffff );
	unsigned long initial_word_count;
	unsigned long loop_count;
	unsigned long loop_partial_count;
	unsigned long final_word_count;
	unsigned long final_byte;
	unsigned long discard_S;
	unsigned long discard_c;
	unsigned long discard_a;
	unsigned long discard_r1;
	unsigned long discard_r2;

	/* Calculate number of initial 16-bit words required to bring
	 * the main loop into alignment.  (We don't care about the
	 * speed for data aligned to less than 16 bits, since this
	 * situation won't occur in practice.)
	 */
	if ( len >= sizeof ( sum ) ) {
		initial_word_count = ( ( -( ( intptr_t ) data ) &
					 ( sizeof ( sum ) - 1 ) ) >> 1 );
	} else {
		initial_word_count = 0;
	}
	len -= ( initial_word_count * 2 );

	/* Calculate number of iterations of the main loop.  This loop
	 * processes native machine words (32-bit or 64-bit), and is
	 * unrolled 16 times.  We calculate an overall iteration
	 * count, and a starting point for the first iteration.
	 */
	loop_count = ( len / ( sizeof ( sum ) * 16 ) );
	loop_partial_count =
		( ( len % ( sizeof ( sum ) * 16 ) ) / sizeof ( sum ) );

	/* Calculate number of 16-bit words remaining after the main
	 * loop completes.
	 */
	final_word_count = ( ( len % sizeof ( sum ) ) / 2 );

	/* Calculate whether or not a final byte remains at the end */
	final_byte = ( len & 1 );

	/* Calculate the checksum */
	__asm__ ( /* Calculate position at which to jump into the
		   * unrolled loop.
		   */
		  "imul $( -x86_tcpip_loop_step_size ), %4\n\t"
		  "add %5, %4\n\t"

		  /* Clear carry flag before starting checksumming */
		  "clc\n\t"

		  /* Checksum initial words */
		  "jmp 2f\n\t"
		  "\n1:\n\t"
		  "lodsw\n\t"
		  "adcw %w2, %w0\n\t"
		  "\n2:\n\t"
		  "loop 1b\n\t"

		  /* Main "lods;adc" loop, unrolled x16 */
		  "mov %12, %3\n\t"
		  "jmp *%4\n\t"
		  "\nx86_tcpip_loop_start:\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "lods%z2\n\tadc %2, %0\n\t"
		  "\nx86_tcpip_loop_end:\n\t"
		  "loop x86_tcpip_loop_start\n\t"
		  ".equ x86_tcpip_loop_step_size, "
		  "  ( ( x86_tcpip_loop_end - x86_tcpip_loop_start ) >> 4 )\n\t"

		  /* Checksum remaining whole words */
		  "mov %13, %3\n\t"
		  "jmp 2f\n\t"
		  "\n1:\n\t"
		  "lodsw\n\t"
		  "adcw %w2, %w0\n\t"
		  "\n2:\n\t"
		  "loop 1b\n\t"

		  /* Checksum final byte if applicable */
		  "mov %14, %3\n\t"
		  "loop 1f\n\t"
		  "adcb (%1), %b0\n\t"
		  "adcb $0, %h0\n\t"
		  "\n1:\n\t"

		  /* Fold down to a uint16_t */
		  "push %0\n\t"
		  "popw %w0\n\t"
		  "popw %w2\n\t"
		  "adcw %w2, %w0\n\t"
#if ULONG_MAX > 0xffffffffUL /* 64-bit only */
		  "popw %w2\n\t"
		  "adcw %w2, %w0\n\t"
		  "popw %w2\n\t"
		  "adcw %w2, %w0\n\t"
#endif /* 64-bit only */

		  /* Consume CF */
		  "adcw $0, %w0\n\t"
		  "adcw $0, %w0\n\t"

		  : "=&Q" ( sum ), "=&S" ( discard_S ), "=&a" ( discard_a ),
		    "=&c" ( discard_c ), "=&r" ( discard_r1 ),
		    "=&r" ( discard_r2 )
		  : "0" ( sum ), "1" ( data ), "2" ( 0 ),
		    "3" ( initial_word_count + 1 ), "4" ( loop_partial_count ),
		    "5" ( x86_tcpip_loop_end ), "g" ( loop_count + 1 ),
		    "g" ( final_word_count + 1 ), "g" ( final_byte ) );

	return ( ~sum & 0xffff );
}
