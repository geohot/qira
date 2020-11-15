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
#include <stdint.h>
#include <hw.h>
#include <rtas.h>
#include "rtas_board.h"
#include <bmc.h>
#include "rtas_flash.h"
#include <flash/block_lists.h>
#include "product.h"
#include "calculatecrc.h"

#undef DEBUG

#ifdef DEBUG
#define dprintf(_x ...) printf(_x)
#else
#define dprintf(_x ...)
#endif

static uint64_t size;
static uint64_t flashOffset;

unsigned char manage_flash_buffer[BUFSIZE*2];
unsigned long check_flash_image(unsigned long rombase, unsigned long length,
				unsigned long start_crc);

#ifdef DEBUG
static void
dump_blocklist(uint64_t *bl, int version)
{
	uint64_t bl_size;
	uint8_t *addr = (uint8_t *)bl;

	if (version == 1) {
		/* version 1 blocklist */
		bl_size = *bl & 0x00FFFFFFFFFFFFFFUL;

	} else {
		bl_size = *bl;
	}

	printf("\n\rblocklist_dump %lx", bl_size);
	while (bl_size) {
		unsigned int tmpCnt = bl_size;
		unsigned char x;
		if (tmpCnt > 8)
			tmpCnt = 8;
		printf("\n\r%08x: ", addr);
		/* print hex */
		while (tmpCnt--) {
			set_ci();
			x = *addr++;
			clr_ci();
			printf("%02x ", x);
		}
		tmpCnt = bl_size;
		if (tmpCnt > 8)
			tmpCnt = 8;
		bl_size -= tmpCnt;
		/* reset addr ptr to print ascii */
		addr = addr - tmpCnt;
		/* print ascii */
		while (tmpCnt--) {
			set_ci();
			x = *addr++;
			clr_ci();
			if ((x < 32) || (x >= 127)) {
				/* non-printable char */
				x = '.';
			}
			printf("%c", x);
		}
	}
	printf("\r\n");
}
#endif

void
rtas_dump_flash(rtas_args_t *rtas_args)
{
	int retVal = 0;
	unsigned int size = rtas_args->args[0];
	unsigned int offset = rtas_args->args[1];
	volatile unsigned char *flash = (volatile unsigned char *)FLASH;

	printf("\n\rflash_dump %x %x", size, offset);
	flash += offset;
	while (size) {
		unsigned int tmpCnt = size;
		unsigned char x;
		if (tmpCnt > 16)
			tmpCnt = 16;
		printf("\n\r%p: ", flash);
		/* print hex */
		while (tmpCnt--) {
			set_ci();
			x = *flash++;
			clr_ci();
			printf("%02x ", x);
		}
		tmpCnt = size;
		if (tmpCnt > 16)
			tmpCnt = 16;
		size -= tmpCnt;
		/* reset flash ptr to print ascii */
		flash = flash - tmpCnt;
		/* print ascii */
		while (tmpCnt--) {
			set_ci();
			x = *flash++;
			clr_ci();
			if ((x < 32) || (x >= 127)) {
				/* non-printable char */
				x = '.';
			}
			printf("%c", x);
		}
	}
	printf("\r\n");
	rtas_args->args[rtas_args->nargs] = retVal;
}


static void
print_block(int i)
{
	int counter = 8;

	while (counter--)
		printf("\b");
	printf("%08x", i);
}



/* To enter data mode after flash has been in programming mode
 * a 0xFF has to be written */
static void
enter_data_mode(void)
{
	volatile unsigned char *flash = (volatile unsigned char *)FLASH;

	set_ci();
	*flash = 0xFF;
	eieio();
	clr_ci();
}


static void
erase_flash_block(unsigned long offset)
{
	volatile unsigned char *flash = (volatile unsigned char *)FLASH;

	flash += offset;
	set_ci();
	*flash = 0x20;
	eieio();
	*flash = 0xd0;
	eieio();
	while (!(*flash & 0x80)) ;
	clr_ci();
}


void
write_flash(unsigned long offset, unsigned char *data)
{
	int cnt = 32;
	volatile unsigned char *flash = (volatile unsigned char *)FLASH;

	flash += (offset + flashOffset);
	set_ci();
	while (cnt) {
		if (!((uint64_t)flash & 0x1F)) {
			while (cnt) {
				uint64_t tmpcnt = cnt;
				if (tmpcnt > 0x20)
					tmpcnt = 0x20;
				do {
					*flash = 0xE8;
					eieio();
				} while (!(*flash & 0x80));
				cnt -= tmpcnt;
				*flash = tmpcnt - 1;
				while (tmpcnt--) {
					*flash++ = *data++;
				}
				*flash = 0xD0;
				eieio();
				while (!(*flash & 0x80)) ;
			}
			break;
		}
		*flash = 0x40;
		eieio();
		*flash++ = *data++;
		eieio();
		while (!(*flash & 0x80)) ;
		cnt--;
	}
	clr_ci();
}

static void
write_flash_page(unsigned long offset, unsigned short *data)
{
	int i = 0;

	for (i = 0; i < BUFSIZE; i += 32, offset += 32) {
		write_flash(offset, ((unsigned char *)data + i));
	}
}

/*
 * 0 reject temporary image
 * 1 commit temporary image
 * */
static int
copy_flash(short mode)
{
	volatile unsigned char *flash = (volatile unsigned char *)FLASH;
	uint64_t blockCnt;
	uint64_t hash = 0;
	short notmode = mode ^ 0x1;

	if (bmc_set_flashside(notmode) != notmode) {
		return -1;
	}
	printf("\r\nErasing Flash: 0x        ");

	for (blockCnt = 0; blockCnt <= FLASHSIZE; blockCnt += FLASH_BLOCK_SIZE) {
		print_block(blockCnt);
		erase_flash_block(blockCnt);
	}
	enter_data_mode();
	progress = FLASHSIZE / 38;
	print_writing();

	for (blockCnt = 0; blockCnt <= FLASHSIZE; blockCnt += BUFSIZE) {
		uint64_t *srcPtr = (uint64_t *)(flash + blockCnt);
		uint64_t *destPtr = (uint64_t *)manage_flash_buffer;
		uint64_t cnt = BUFSIZE / 8;
		if (bmc_set_flashside(mode) != mode) {
			return -1;
		}
		enter_data_mode();
		set_ci();
		while (cnt--) {
			*destPtr++ = *srcPtr++;
		}
		clr_ci();

		if (bmc_set_flashside(notmode) != notmode) {
			return -1;
		}
		write_flash_page(blockCnt,
				 (unsigned short *)manage_flash_buffer);

		/* progress output... */
		print_progress();
		if (blockCnt > hash * progress) {
			print_hash();
			hash++;
		}
	}
	enter_data_mode();
	if (bmc_set_flashside(mode) != mode) {
		return -1;
	}
	printf("\b#\n");
	return 0;
}

/*
 * Function: ibm_manage_flash_image
 *	Input:
 *		r3:   rtas parm structure
 *			token:  46
 *			in:     1
 *			out:    1
 *			parm0:  0 reject temporary image
 *				1 commit temporary image
 *	Output:
 *			parm1:  Status (hw -1, busy -2, parameter error -3
 *					-9001 cannot overwrite the active firmware image)
 *
 */

void
rtas_ibm_manage_flash_image(rtas_args_t *rtas_args)
{
	int side;
	int result = 0;
	short mode = rtas_args->args[0];

	if (mode < 0 || mode > 1) {
		rtas_args->args[rtas_args->nargs] = -3;
		return;
	}
	side = bmc_get_flashside();
	if (side == 0) {
		/* we are on the permanent side */
		if (mode != 0) {
			rtas_args->args[rtas_args->nargs] = -9001;
			return;
		}
	} else if (side == 1) {
		/* we are on the temporary side */
		if (mode != 1) {
			rtas_args->args[rtas_args->nargs] = -9001;
			return;
		}
	} else {
		rtas_args->args[rtas_args->nargs] = -1;
		return;
	}

	result = copy_flash(mode);
	bmc_set_flashside(mode);
	enter_data_mode();
	rtas_args->args[rtas_args->nargs] = result;
}

/**
 * check, if we find the FLASHFS_MAGIC token in bl
 **/
static uint8_t
check_magic(uint64_t *bl, int version)
{
	struct stH *pHeader;

	if (version == 1) {
		/* version 1 blocklist */
		/* if block list size <= 0x10, it is only block list header */
		/* and address of block list extension, so look at the extension... */
		while ((*bl & 0x00FFFFFFFFFFFFFFUL) <= 0x10)
			bl = (uint64_t *)bl[1];

		/* block list item 2 _should_ be the address of our flashfs image */
		pHeader = (struct stH *)(bl[2] + 0x28);
		/* printf("FlashFS Magic: \"%#s\"\r\n", pHeader->magic); */
		return strncmp(pHeader->magic, FLASHFS_MAGIC, 8);
	} else {
		/* block list item 1 _should_ be the address of our flashfs image */
		pHeader = (struct stH *)(bl[1] + 0x28);
		/* printf("FlashFS Magic: \"%#s\"\r\n", pHeader->magic); */
		return strncmp(pHeader->magic, FLASHFS_MAGIC, 8);
	}
}

static void
get_image_name(char *buffer, int maxsize)
{
	volatile struct stH *flash_header = (volatile struct stH *)(SB_FLASH_adr + 0x28);
	/* since we cannot read the fh_magic directly from flash as a string, we need to copy it to memory */
	uint64_t magic_val = 0;
	uint64_t addr;

	/* copy fh_magic to magic_val since, we cannot use it as a string from flash */
	magic_val = load64_ci((uint64_t)(flash_header->magic));
	if (strncmp((char *)&magic_val, FLASHFS_MAGIC, 8)) {
		/* magic does not match */
		sprintf(buffer, "Unknown");
		buffer[maxsize - 1] = '\0';
		return;
	}
	addr = (uint64_t)flash_header->version;
	while (--maxsize) {
		*buffer = load8_ci(addr++);
		if (!*buffer++)
			return;
	}
	*buffer = '\0';
}

/**
 * validate_flash_image
 * this function checks if the flash will be updated with the given image
 * @param args[0] - buffer with minimum 4K of the image to flash
 * @param args[1] - size of the buffer
 * @param args[2] - status:
 *                           0    success
 *                          -1    hw
 *                          -2    busy
 *                          -3    parameter error
 * @param args[3] - update result token
 */
void
rtas_ibm_validate_flash_image(rtas_args_t *rtas_args)
{
	dprintf("\nrtas_ibm_validate_flash_image\n");
	unsigned long new_image = rtas_args->args[0];
	char *ret_str = (char *)new_image;
	struct stH *flash_header = (struct stH *)(new_image + 0x28);
	char current_temp_version[16];
	char current_perm_version[16];
	char new_version[16];
	int side = bmc_get_flashside();

	/* fill args[0] with the current values which is needed
	 * in an error case */

	bmc_set_flashside(0);
	get_image_name(current_perm_version, sizeof(current_perm_version));
	bmc_set_flashside(1);
	get_image_name(current_temp_version, sizeof(current_temp_version));
	bmc_set_flashside(side);

	/* check if the candidate image if valid for this platform */
	if (strncmp(flash_header->magic, FLASHFS_MAGIC, 8)) {
		/* magic does not match */
		rtas_args->args[rtas_args->nargs] = 0;
		/* No update done, the candidate image is
		 * not valid for this platform */
		rtas_args->args[rtas_args->nargs + 1] = 2;
		sprintf(ret_str, "MI %s %s\xaMI %s %s",
			current_temp_version, current_perm_version,
			current_temp_version, current_perm_version);
		return;
	}

	if (strncmp(flash_header->platform_name, (char *)sig_org, 32)) {
		/* this image if for a different board */
		rtas_args->args[rtas_args->nargs] = 0;
		/* No update done, the candidate image is
		 * not valid for this platform */
		rtas_args->args[rtas_args->nargs + 1] = 2;
		sprintf(ret_str, "MI %s %s\xaMI %s %s",
			current_temp_version, current_perm_version,
			current_temp_version, current_perm_version);
		return;
	}

	/* check header crc */
	if (check_flash_image(rtas_args->args[0], 0x88, 0)) {
		/* header crc failed */
		rtas_args->args[rtas_args->nargs] = 0;
		/* No update done, the candidate image is
		 * not valid for this platform */
		rtas_args->args[rtas_args->nargs + 1] = 2;
		sprintf(ret_str, "MI %s %s\xaMI %s %s",
			current_temp_version, current_perm_version,
			current_temp_version, current_perm_version);
		return;
	}
	memcpy(new_version, flash_header->version, 16);
	sprintf(ret_str, "MI %s %s\xaMI %s %s", current_temp_version,
		current_perm_version, new_version, current_perm_version);
	rtas_args->args[rtas_args->nargs] = 0;

	if (strncmp(new_version, current_temp_version, 16) >= 0)
		rtas_args->args[rtas_args->nargs + 1] = 0;
	else
		rtas_args->args[rtas_args->nargs + 1] = 6;
}

/*
 * Function: ibm_update_flash_64
 *	Input:
 *		r3:   rtas parm structure
 *			token:  7
 *			in:     1
 *			out:    1
 *			parm0:  A real pointer to a block list
 *	Output:
 *			parm1:  Status (hw -1, bad image -3, programming failed -4)
 *
 *   Description: flash if addresses above 4GB have to be addressed
 */
void
rtas_update_flash(rtas_args_t *rtas_args)
{
	void *bl = (void *)(uint64_t)rtas_args->args[0];
	int version = get_block_list_version((unsigned char *)bl);
	uint64_t erase_size;
	unsigned int i;
	int perm_check = 1;

#ifdef DEBUG
	dump_blocklist(bl, version);
#endif

	/* from SLOF we pass a second (unofficial) parameter, if this parameter is 1, we do not
	 * check wether we are on permanent side. Needed for update-flash -c to work! */
	if ((rtas_args->nargs > 1) && (rtas_args->args[1] == 1))
		perm_check = 0;

	/* check magic string */
	printf("\r\nChecking magic string : ");
	if (check_magic(bl, version) != 0) {
		printf("failed!\n");
		rtas_args->args[rtas_args->nargs] = -3; /* bad image */
		return;
	}
	printf("succeeded!\n");

	/* check platform */
	printf("Checking platform : ");
	if (check_platform(bl, 0x48, version) == -1) {
		printf("failed!\n");
		rtas_args->args[rtas_args->nargs] = -3; /* bad image */
		return;
	}
	printf("succeeded!\n");

	/* checkcrc */
	printf("Checking CRC : ");
	/* the actual CRC is included at the end of the flash image, thus the resulting CRC must be 0! */
	if (image_check_crc(bl, version) != 0) {
		printf("failed!\n");
		rtas_args->args[1] = -3;        /* bad image */
		return;
	}
	printf("succeeded!\n");

	/* check if we are running on P
	 * if so, let's switch to temp and flash temp */
	if (bmc_get_flashside() == 0  && perm_check) {
		printf("Set flashside: ");
		bmc_set_flashside(1);
		printf("Temp!\n");
	}

#ifdef DEBUG
	rtas_args_t ra;
	ra.args[0] = 0x100;     /* size; */
	ra.args[1] = flashOffset;
	ra.nargs = 2;

	rtas_dump_flash(&ra);
	printf("\n");
#endif

	size = get_size(bl, version);
	erase_size = (size + (FLASH_BLOCK_SIZE - 1)) & ~(FLASH_BLOCK_SIZE - 1);
	dprintf("Erasing: size: %#x, erase_size: %#x, FLASH_BLOCK_SIZE: %#x\n",
		size, erase_size, FLASH_BLOCK_SIZE);

	progress = size / 39;
	printf("Erasing : 0x%08x", 0);
	for (i = 0; i < erase_size; i += FLASH_BLOCK_SIZE) {
		print_block(i);
		erase_flash_block(i);
	}

	enter_data_mode();
#ifdef DEBUG
	rtas_dump_flash(&ra);
	printf("\n");
#endif
	print_writing();
	write_block_list(bl, version);
	printf("\b#\n");
	enter_data_mode();

#ifdef DEBUG
	rtas_dump_flash(&ra);
	printf("\n");
#endif

	/* checkcrc */
	printf("Recheck CRC : ");
	if (check_flash_image(FLASH + flashOffset, size, 0) != 0) {
		/* failed */
		printf("failed!\n\r");
		dprintf("flash_addr: %#x, flashOffset: %#x, size: %#x\n", FLASH,
			flashOffset, size);
		dprintf("crc: %#x\n",
			check_flash_image(FLASH + flashOffset, size, 0));
		rtas_args->args[rtas_args->nargs] = -4; /* programming failed */
		return;
	}
	printf("succeeded!\n");
	rtas_args->args[rtas_args->nargs] = 0;
}

/*
 * Function: ibm_update_flash_64_and_reboot
 *	Input:
 *		r3:   rtas parm structure
 *			token:  27
 *			in:     1
 *			out:    1
 *			parm0:  A real pointer to a block list
 *	Output:
 *			parm1:  Status (hw -1, bad image -3, programming failed -4)
 *				Currently -4 and -1 are not returned
 *
 *  Description: flash and reboot if addresses above 4GB have to be addressed
 */
void
rtas_ibm_update_flash_64_and_reboot(rtas_args_t *rtas_args)
{
	rtas_update_flash(rtas_args);
	dprintf("rc: %#d\n", rtas_args->args[rtas_args->nargs]);
	if (rtas_args->args[rtas_args->nargs] == 0) {
		rtas_system_reboot(rtas_args);
	}
}
