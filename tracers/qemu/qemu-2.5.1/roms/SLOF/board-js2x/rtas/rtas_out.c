/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <cpu.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <rtas.h>
#include <hw.h>
#include "rtas_board.h"

volatile unsigned char *uart;
volatile unsigned char u4Flag;

void io_init(void);
unsigned long check_flash_image(unsigned long rombase, unsigned long length,
				unsigned long start_crc);

void
io_init(void)
{
	// read ID register: only if it is a PC87427, enable serial2
	store8_ci(0xf400002e, 0x20);
	if (load8_ci(0xf400002f) != 0xf2) {
		uart = (volatile unsigned char *) 0xf40003f8;
		u4Flag = 0;
	} else {
		uart = (volatile unsigned char *) 0xf40002f8;
		u4Flag = 1;
	}
}

static void
display_char(char ch)
{
	volatile int i = 0;
	volatile unsigned char *uart = (volatile unsigned char *) 0xf40002f8;
	int cnt = 2;
	while (cnt--) {
		set_ci();
		while (!(uart[5] & 0x20)) {
			i++;
		}
		uart[0] = ch;
		clr_ci();
		uart += 0x100;
	}
}

ssize_t
write(int fd __attribute((unused)), const void *buf, size_t cnt)
{
	while (cnt--) {
		display_char(*(char *) buf);
		if (*(char *) buf++ == '\n')
			display_char('\r');
	}
	return 0;
}

void *
sbrk(int incr __attribute((unused)))
{
	return (void *) -1;
}



void
rtas_display_character(rtas_args_t * pArgs)
{
	int retVal = 0;
	display_char((char) pArgs->args[0]);
	pArgs->args[1] = retVal;
}

unsigned long
check_flash_image(unsigned long rombase, unsigned long length,
		  unsigned long start_crc)
{
	const uint32_t CrcTableHigh[16] = {
		0x00000000, 0x4C11DB70, 0x9823B6E0, 0xD4326D90,
		0x34867077, 0x7897AB07, 0xACA5C697, 0xE0B41DE7,
		0x690CE0EE, 0x251D3B9E, 0xF12F560E, 0xBD3E8D7E,
		0x5D8A9099, 0x119B4BE9, 0xC5A92679, 0x89B8FD09
	};
	const uint32_t CrcTableLow[16] = {
		0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9,
		0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
		0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61,
		0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD
	};

	char *Buffer = (char *) rombase;
	uint32_t AccumCRC = start_crc;
	char val;
	uint32_t Temp;
	while (length-- > 0) {
		set_ci();
		val = *Buffer;
		clr_ci();
		Temp = ((AccumCRC >> 24) ^ val) & 0x000000ff;
		AccumCRC <<= 8;
		AccumCRC ^= CrcTableHigh[Temp / 16];
		AccumCRC ^= CrcTableLow[Temp % 16];
		++Buffer;
	}
	return AccumCRC;
}
