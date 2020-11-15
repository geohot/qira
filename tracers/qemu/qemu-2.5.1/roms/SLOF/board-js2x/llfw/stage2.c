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

#include <stdint.h>
#include <xvect.h>
#include <hw.h>
#include <stdio.h>
#include <romfs.h>
#include "memmap.h"
#include "stage2.h"
#include <termctrl.h>
#include "product.h"
#include "calculatecrc.h"
#include <cpu.h>
#include <libelf.h>
#include <string.h>

uint64_t uart;
uint64_t gVecNum;
uint8_t u4Flag;

uint64_t exception_stack_frame;

typedef void (*pInterruptFunc_t) (void);

pInterruptFunc_t vectorTable[0x2E << 1];

extern void proceedInterrupt(void);

/* Prototypes for functions in this file: */
void c_interrupt(uint64_t vecNum);
void set_exceptionVector(int num, void *func);
int io_getchar(char *ch);
void early_c_entry(uint64_t start_addr);


static void
exception_forward(void)
{
	uint64_t val;

	if (*(uint64_t *) XVECT_M_HANDLER) {
		proceedInterrupt();
	}

	printf("\r\n exception %llx ", gVecNum);
	asm volatile ("mfsrr0	%0":"=r" (val):);
	printf("\r\nSRR0 = %08llx%08llx ", val >> 32, val);
	asm volatile ("mfsrr1	%0":"=r" (val):);
	printf(" SRR1 = %08llx%08llx ", val >> 32, val);

	asm volatile ("mfsprg	%0,2":"=r" (val):);
	printf("\r\nSPRG2 = %08llx%08llx ", val >> 32, val);
	asm volatile ("mfsprg	%0,3":"=r" (val):);
	printf(" SPRG3 = %08llx%08llx \r\n", val >> 32, val);
	while (1);
}

void
c_interrupt(uint64_t vecNum)
{
	gVecNum = vecNum;
	if (vectorTable[vecNum >> 7]) {
		vectorTable[vecNum >> 7] ();
	} else {
		exception_forward();
	}
}

void
set_exceptionVector(int num, void *func)
{
	vectorTable[num >> 7] = (pInterruptFunc_t) func;
}

static void
io_init(void)
{
	// read ID register: only if it is a PC87427, enable serial2
	store8_ci(0xf400002e, 0x20);
	if (load8_ci(0xf400002f) != 0xf2) {
		uart = 0xf40003f8;
		u4Flag = 0;
	} else {
		uart = 0xf40002f8;
		u4Flag = 1;
	}
}

int
io_getchar(char *ch)
{
	int retVal = 0;
	if ((load8_ci(uart + 5) & 0x01)) {
		*ch = load8_ci(uart);
		retVal = 1;
	}
	return retVal;
}


void copy_from_flash(uint64_t cnt, uint64_t src, uint64_t dest);

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

static unsigned long
check_flash_image(unsigned long rombase, unsigned long length,
		  unsigned long start_crc)
{

	uint32_t AccumCRC = start_crc;
	char val;
	uint32_t Temp;
	while (length-- > 0) {
		val = load8_ci(rombase++);
		Temp = ((AccumCRC >> 24) ^ val) & 0x000000ff;
		AccumCRC <<= 8;
		AccumCRC ^= CrcTableHigh[Temp / 16];
		AccumCRC ^= CrcTableLow[Temp % 16];
	}

	return AccumCRC;
}

static void
load_file(uint64_t destAddr, char *name, uint64_t maxSize, uint64_t romfs_base)
{
	uint64_t *src, *dest, cnt;
	struct romfs_lookup_t fileInfo;
	c_romfs_lookup(name, romfs_base, &fileInfo);
	if (maxSize) {
		cnt = maxSize / 8;
	} else {
		cnt = (fileInfo.size_data + 7) / 8;
	}
	dest = (uint64_t *) destAddr;
	src = (uint64_t *) fileInfo.addr_data;
	while (cnt--) {
		store64_ci((uint64_t) dest, *src);
		dest++;
		src++;
	}
	flush_cache((void *) destAddr, fileInfo.size_data);
}

/***************************************************************************
 * Function: early_c_entry
 * Input   : start_addr
 *
 * Description:
 **************************************************************************/
void
early_c_entry(uint64_t start_addr)
{
	struct romfs_lookup_t fileInfo;
	uint32_t crc;
	void (*ofw_start) (uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
	uint64_t *boot_info;
	exception_stack_frame = 0;
	/* destination for the flash image; we copy it to RAM
	 * because from flash it is much too slow
	 * the flash is copied at 224MB - 4MB (max flash size)
	 * at 224MB starts SLOF
	 * at 256MB is the SLOF load-base */
	uint64_t romfs_base = 0xe000000 - 0x400000;
	// romfs header values
	struct stH *header = (struct stH *) (start_addr + 0x28);
	//since we cannot read the fh_magic directly from flash as a string, we need to copy it to memory
	uint64_t magic_val = 0;
	uint64_t startVal = 0;
	uint64_t flashlen = 0;
	unsigned long ofw_addr;

	io_init();

	flashlen = load64_ci((uint64_t) (&header->flashlen));

	//copy fh_magic to magic_val since, we cannot use it as a string from flash
	magic_val = load64_ci((uint64_t) (header->magic));

	printf(" Check ROM  = ");
	if (strncmp((char *) &magic_val, FLASHFS_MAGIC, 8) == 0) {
		// somehow, the first 8 bytes in flashfs are overwritten, if booting from drone...
		// so if we find "IMG1" in the first 4 bytes, we skip the CRC check...
		startVal = load64_ci((uint64_t) start_addr);
		if (strncmp((char *) &startVal, "IMG1", 4) == 0) {
			printf
			    ("start from RAM detected, skipping CRC check!\r\n");
			// for romfs accesses (c_romfs_lookup) to work, we must fix the first uint64_t to the value we expect...
			store64_ci((uint64_t) start_addr, 0xd8);
		} else {
			//checking CRC in flash, we must use cache_inhibit
			// since the crc is included as the last 32 bits in the image, the resulting crc should be 0
			crc =
			    check_flash_image((uint64_t) start_addr,
					      load64_ci((uint64_t)
							(&header->flashlen)),
					      0);
			if (crc == 0) {
				printf("OK\r\n");
			} else {
				printf("failed!\r\n");
				while (1);
			}
		}
	} else {
		printf
		    ("failed (magic string is \"%.8s\" should be \"%.8s\")\r\n",
		     (char *) &magic_val, FLASHFS_MAGIC);
		while (1);
	}

	printf(" Press \"s\" to enter Open Firmware.\r\n\r\n");

	if ((start_addr > 0xF0000000) && u4Flag)
		u4memInit();

	/* here we have real ram avail -> hopefully
	 * copy flash to ram; size is in 64 byte blocks */
	flashlen /= 64;
	/* align it a bit */
	flashlen += 7;
	flashlen &= ~7;
	copy_from_flash(flashlen, start_addr, romfs_base);
	/* takeover sometimes fails if the image running on the system
	 * has a different size; flushing the cache helps, because it is
	 * the right thing to do anyway */
	flush_cache((void *) romfs_base, flashlen * 64);

	c_romfs_lookup("bootinfo", romfs_base, &fileInfo);
	boot_info = (uint64_t *) fileInfo.addr_data;
	boot_info[1] = start_addr;
	load_file(0x100, "xvect", 0, romfs_base);
	load_file(SLAVELOOP_LOADBASE, "stageS", 0, romfs_base);
	c_romfs_lookup("ofw_main", romfs_base, &fileInfo);

	elf_load_file((void *) fileInfo.addr_data, &ofw_addr,
		      NULL, flush_cache);
	ofw_start =
	    (void (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))
	    &ofw_addr;
	// re-enable the cursor
	printf("%s%s", TERM_CTRL_RESET, TERM_CTRL_CRSON);
	/* ePAPR 0.5
	 * r3 = R3 Effective address of the device tree image. Note: this
	 *      address must be 8-byte aligned in memory.
	 * r4 = implementation dependent
	 * r5 = 0
	 * r6 = 0x65504150 -- ePAPR magic value-to distinguish from
	 *      non-ePAPR-compliant firmware
	 * r7 = implementation dependent
	 */
	asm volatile("isync; sync;" : : : "memory");
	ofw_start(0, romfs_base, 0, 0, 0);
	// never return
}
