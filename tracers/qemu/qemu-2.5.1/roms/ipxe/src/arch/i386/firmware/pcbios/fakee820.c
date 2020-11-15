/* Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <realmode.h>
#include <biosint.h>

/** Assembly routine in inline asm */
extern void int15_fakee820();

/** Original INT 15 handler */
static struct segoff __text16 ( real_int15_vector );
#define real_int15_vector __use_text16 ( real_int15_vector )

/** An INT 15,e820 memory map entry */
struct e820_entry {
	/** Start of region */
	uint64_t start;
	/** Length of region */
	uint64_t len;
	/** Type of region */
	uint32_t type;
} __attribute__ (( packed ));

#define E820_TYPE_RAM		1 /**< Normal memory */
#define E820_TYPE_RSVD		2 /**< Reserved and unavailable */
#define E820_TYPE_ACPI		3 /**< ACPI reclaim memory */
#define E820_TYPE_NVS		4 /**< ACPI NVS memory */

/** Fake e820 map */
static struct e820_entry __text16_array ( e820map, [] ) __used = {
	{ 0x00000000ULL, ( 0x000a0000ULL - 0x00000000ULL ), E820_TYPE_RAM },
	{ 0x00100000ULL, ( 0xcfb50000ULL - 0x00100000ULL ), E820_TYPE_RAM },
	{ 0xcfb50000ULL, ( 0xcfb64000ULL - 0xcfb50000ULL ), E820_TYPE_RSVD },
	{ 0xcfb64000ULL, ( 0xcfb66000ULL - 0xcfb64000ULL ), E820_TYPE_RSVD },
	{ 0xcfb66000ULL, ( 0xcfb85c00ULL - 0xcfb66000ULL ), E820_TYPE_ACPI },
	{ 0xcfb85c00ULL, ( 0xd0000000ULL - 0xcfb85c00ULL ), E820_TYPE_RSVD },
	{ 0xe0000000ULL, ( 0xf0000000ULL - 0xe0000000ULL ), E820_TYPE_RSVD },
	{ 0xfe000000ULL, (0x100000000ULL - 0xfe000000ULL ), E820_TYPE_RSVD },
	{0x100000000ULL, (0x230000000ULL -0x100000000ULL ), E820_TYPE_RAM },
};
#define e820map __use_text16 ( e820map )

void fake_e820 ( void ) {
	__asm__ __volatile__ (
		TEXT16_CODE ( "\nint15_fakee820:\n\t"
			      "pushfw\n\t"
			      "cmpl $0xe820, %%eax\n\t"
			      "jne 99f\n\t"
			      "cmpl $0x534d4150, %%edx\n\t"
			      "jne 99f\n\t"
			      "pushaw\n\t"
			      "movw %%sp, %%bp\n\t"
			      "andb $~0x01, 22(%%bp)\n\t" /* Clear return CF */
			      "leaw e820map(%%bx), %%si\n\t"
			      "cs rep movsb\n\t"
			      "popaw\n\t"
			      "movl %%edx, %%eax\n\t"
			      "addl $20, %%ebx\n\t"
			      "cmpl %0, %%ebx\n\t"
			      "jne 1f\n\t"
			      "xorl %%ebx,%%ebx\n\t"
			      "\n1:\n\t"
			      "popfw\n\t"
			      "iret\n\t"
			      "\n99:\n\t"
			      "popfw\n\t"
			      "ljmp *%%cs:real_int15_vector\n\t" )
		: : "i" ( sizeof ( e820map ) ) );

	hook_bios_interrupt ( 0x15, ( unsigned int ) int15_fakee820,
			      &real_int15_vector );
}

void unfake_e820 ( void ) {
	unhook_bios_interrupt ( 0x15, ( unsigned int ) int15_fakee820,
				&real_int15_vector );
}
