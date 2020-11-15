/*
 * Copyright (C) 2013 Marin Hannache <ipxe@mareo.fr>.
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

/**
 * @file
 *
 * Advanced Power Management
 *
 */

#include <errno.h>
#include <realmode.h>
#include <ipxe/reboot.h>

/**
 * Power off the computer using APM
 *
 * @ret rc		Return status code
 */
static int apm_poweroff ( void ) {
	uint16_t apm_version;
	uint16_t apm_signature;
	uint16_t apm_flags;
	uint16_t carry;

	/* APM check */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x15\n\t"
	                                   "adc %%edx,0\n\t" )
	                       : "=a" ( apm_version ), "=b" ( apm_signature ),
                                 "=c" ( apm_flags ), "=d" ( carry )
	                       : "a" ( 0x5300 ), "b" ( 0x0000 ),
				 "d" ( 0x0000 ) );
	if ( carry ) {
		DBG ( "APM not present\n" );
		return -ENOTSUP;
	}
	if ( apm_signature != 0x504d ) { /* signature 'PM' */
		DBG ( "APM not present\n" );
		return -ENOTSUP;
	}
	if ( apm_version < 0x0101 ) { /* Need version 1.1+ */
		DBG ( "APM 1.1+ not supported\n" );
		return -ENOTSUP;
	}
	if ( ( apm_flags & 0x8 ) == 0x8 ) {
		DBG ( "APM power management disabled\n" );
		return -EPERM;
	}
	DBG2 ( "APM check completed\n" );

	/* APM initialisation */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x15\n\t"
	                                   "adc %%edx,0\n\t" )
	                       : "=d" ( carry )
	                       : "a" ( 0x5301 ), "b" ( 0x0000 ),
	                         "d" ( 0x0000 ) );
	if ( carry ) {
		DBG ( "APM initialisation failed\n" );
		return -EIO;
	}
	DBG2 ( "APM initialisation completed\n" );

	/* Set APM driver version */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x15\n\t"
	                                   "adc %%edx,0\n\t" )
	                       : "=d" ( carry )
	                       : "a" ( 0x530e ), "b" ( 0x0000 ),
	                         "c" ( 0x0101 ), "d" ( 0x0000 ) );
	if ( carry ) {
		DBG ( "APM setting driver version failed\n" );
		return -EIO;
	}
	DBG2 ( "APM driver version set\n" );

	/* Setting power state to off */
	__asm__ __volatile__ ( REAL_CODE ( "int $0x15\n\t"
	                                   "adc %%edx,0\n\t" )
	                       : "=d" ( carry )
	                       : "a" ( 0x5307 ), "b" ( 0x0001 ),
	                         "c" ( 0x0003 ), "d" ( 0x0000) );
	if ( carry ) {
		DBG ( "APM setting power state failed\n" );
		return -ENOTTY;
	}

	/* Should never happen */
	return -ECANCELED;
}

PROVIDE_REBOOT ( pcbios, poweroff, apm_poweroff );
