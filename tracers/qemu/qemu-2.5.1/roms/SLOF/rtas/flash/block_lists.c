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

#include <product.h>
#include <stdio.h>
#include "block_lists.h"

unsigned char sig_org[] = FLASHFS_PLATFORM_MAGIC;

/* this function is part of the crc_lib assembler code */
unsigned long check_flash_image(unsigned long, unsigned long, unsigned long);

/* this functions needs to be implemented by the board specific flash code
 * the functions always get 32 bytes and needs to deal with the data */
void write_flash(unsigned long, unsigned short *);

int progress = 0;

int
print_progress(void)
{
	static int i = 3;
	switch (i--) {
	case 3:
		printf("\b|");
		break;
	case 2:
		printf("\b/");
		break;
	case 1:
		printf("\b-");
		break;
	case 0:
		printf("\b\\");
	default:
		i = 3;
	}
	return 0;
}

void
print_hash(void)
{
	printf("\b# ");
}

void
print_writing(void)
{
	int counter = 42;
	printf("\nWriting Flash: |");
	while (counter--)
		printf(" ");
	printf("|");
	counter = 41;
	while (counter--)
		printf("\b");

}

int
get_block_list_version(unsigned char *data)
{
	if (data[0] == 0x01)
		return 1;
	return 0;
}

static long
get_image_size(unsigned long *data, unsigned long length)
{
	long size = 0;
	unsigned long i;
	for (i = 0; i < length / 8; i += 2) {
		size += data[1 + i];
	}
	return size;
}

static long
get_image_size_v0(unsigned long *data)
{
	unsigned long bl_size = data[0];
	return get_image_size(data + 1, bl_size - 8);
}

static long
get_image_size_v1(unsigned long *data)
{
	unsigned long *bl_addr = data;
	unsigned long bl_size;
	unsigned long *next;
	long size = 0;
	while (bl_addr) {
		bl_size = bl_addr[0];
		next = (unsigned long *) bl_addr[1];
		bl_size = bl_size & 0x00FFFFFFFFFFFFFFUL;
		size += get_image_size(bl_addr + 2, bl_size - 0x10);
		bl_addr = next;
	}
	return size;
}

long
get_size(unsigned long *data, int version)
{
	if (version == 1)
		return get_image_size_v1(data);
	return get_image_size_v0(data);
}

static unsigned long
write_one_block(unsigned long *block, unsigned long length,
		unsigned long offset)
{
	unsigned long block_addr = (unsigned long) block;
	unsigned long i = 0;
	static unsigned int hash;
	if (offset == 0)
		hash = 0;

	for (i = 0; i < length; i += 32, offset += 32, block_addr += 32) {
		write_flash(offset, (unsigned short *) block_addr);
		if (offset % 10 == 0) {
			print_progress();
		}
		if (offset > hash * progress) {
			print_hash();
			hash++;
		}
	}

	return offset;
}

static unsigned long
write_one_list(unsigned long *bl, unsigned long length, unsigned long offset)
{
	unsigned long i;
	// 0x10: /8 for pointer /2 it has to be done in steps of 2
	for (i = 0; i < length / 0x10; i++) {
		offset =
		    write_one_block((unsigned long *) *bl, *(bl + 1), offset);
		bl += 2;
	}
	return offset;
}

void
write_block_list(unsigned long *bl, int version)
{
	unsigned long offset = 0;
	unsigned long *bl_addr = bl;
	unsigned long bl_size;
	unsigned long *next;

	if (version == 0) {
		// -8 = removed header length
		write_one_list(bl + 1, *(bl) - 8, offset);
		return;
	}

	while (bl_addr) {
		bl_size = bl_addr[0];
		next = (unsigned long *) bl_addr[1];
		bl_size = bl_size & 0x00FFFFFFFFFFFFFFUL;
		// -0x10 = removed header length
		offset = write_one_list(bl_addr + 2, bl_size - 0x10, offset);
		bl_addr = next;
	}

}

static int
check_one_list(unsigned long *bl, unsigned long length, unsigned long crc)
{
	unsigned long i;
	// 0x10: /8 for pointer /2 it has to be done in steps of 2
	for (i = 0; i < length / 0x10; i++) {
		crc = check_flash_image((unsigned long) *bl, *(bl + 1), crc);
		bl += 2;
	}
	return crc;
}

int
image_check_crc(unsigned long *bl, int version)
{
	unsigned long *bl_addr = bl;
	unsigned long bl_size;
	unsigned long *next;
	unsigned long crc = 0;

	if (version == 0) {
		// -8 = removed header length
		return check_one_list(bl + 1, *(bl) - 8, crc);
	}

	while (bl_addr) {
		bl_size = bl_addr[0];
		next = (unsigned long *) bl_addr[1];
		bl_size = bl_size & 0x00FFFFFFFFFFFFFFUL;
		// -0x10 = removed header length
		crc = check_one_list(bl_addr + 2, bl_size - 0x10, crc);
		bl_addr = next;
	}
	return crc;
}

static int
check_platform_one_list(unsigned long *bl, unsigned long bytesec)
{
	unsigned long pos = bytesec;
	unsigned char *sig_tmp, *sig;
	unsigned long size = 0;
	sig = sig_org;

	while (size < bytesec) {
		size += bl[1];

		while (size > pos) {	// 32 == FLASHFS_PLATFORM_MAGIC length
			sig_tmp = (unsigned char *) (bl[0] + pos);
			if (*sig++ != *sig_tmp)
				return -1;
			if (*sig_tmp == '\0' || (pos == bytesec + 32)) {
				pos = bytesec + 32;
				break;
			}
			pos++;
		}
		if (pos == (bytesec + 32))
			return 0;
		bl += 2;
	}
	return 0;
}

int
check_platform(unsigned long *bl, unsigned int bytesec, int version)
{
	unsigned long *bl_addr = bl;
	unsigned long bl_size;
	unsigned long *next;
	unsigned long *ptr;
	ptr = bl;

	if (version == 0) {
		ptr += 1;	// -8 = removed header length
		return check_platform_one_list(ptr, bytesec);
	}
	while (bl_addr) {
		ptr = bl_addr + 2;	// -0x10 = removed header length
		bl_size = bl_addr[0];
		next = (unsigned long *) bl_addr[1];
		bl_size = bl_size & 0x00FFFFFFFFFFFFFFUL;
		if ((bl_size - 0x10) == 0) {
			bl_addr = next;
			continue;
		}
		if (check_platform_one_list(ptr, bytesec) == 0)
			return 0;

		bl_addr = next;
	}
	return -1;
}
