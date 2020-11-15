/******************************************************************************
 * Copyright (c) 2004, 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

/*
 * ELF loader
 */

#include <string.h>
#include <cache.h>
#include <libelf.h>
#include <byteorder.h>

/**
 * elf_check_file tests if the file at file_addr is
 * a correct endian, ELF PPC executable
 * @param file_addr  pointer to the start of the ELF file
 * @return           the class (1 for 32 bit, 2 for 64 bit)
 *                   -1 if it is not an ELF file
 *                   -2 if it has the wrong endianness
 *                   -3 if it is not an ELF executable
 *                   -4 if it is not for PPC
 */
static int
elf_check_file(unsigned long *file_addr)
{
	struct ehdr *ehdr = (struct ehdr *) file_addr;
	uint8_t native_endian;

	/* check if it is an ELF image at all */
	if (cpu_to_be32(ehdr->ei_ident) != 0x7f454c46)
		return -1;

#ifdef __BIG_ENDIAN__
	native_endian = ELFDATA2MSB;
#else
	native_endian = ELFDATA2LSB;
#endif

	if (native_endian != ehdr->ei_data) {
		switch (ehdr->ei_class) {
		case 1:
			elf_byteswap_header32(file_addr);
			break;
		case 2:
			elf_byteswap_header64(file_addr);
			break;
		}
	}

	/* check if it is an ELF executable ... and also
	 * allow DYN files, since this is specified by ePAPR */
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		return -3;

	/* check if it is a PPC ELF executable */
	if (ehdr->e_machine != 0x14 && ehdr->e_machine != 0x15)
		return -4;

	return ehdr->ei_class;
}

/**
 * load_elf_file tries to load the ELF file specified in file_addr
 *
 * it first checks if the file is a PPC ELF executable and then loads
 * the segments depending if it is a 64bit or 32 bit ELF file
 *
 * @param file_addr  pointer to the start of the elf file
 * @param entry      pointer where the ELF loader will store
 *                   the entry point
 * @param pre_load   handler that is called before copying a segment
 * @param post_load  handler that is called after copying a segment
 * @return           1 for a 32 bit file
 *                   2 for a 64 bit BE file
 *                   3 for a 64 bit LE ABIv1 file
 *                   4 for a 64 bit LE ABIv2 file
 *                   5 for a 32 bit LE ABIv1 file
 *                   anything else means an error during load
 */
int
elf_load_file(void *file_addr, unsigned long *entry,
              int (*pre_load)(void*, long),
              void (*post_load)(void*, long))
{
	int type = elf_check_file(file_addr);
	struct ehdr *ehdr = (struct ehdr *) file_addr;

	switch (type) {
	case 1:
		*entry = elf_load_segments32(file_addr, 0, pre_load, post_load);
		if (ehdr->ei_data != ELFDATA2MSB) {
			type = 5; /* LE32 ABIv1 */
		}
		break;
	case 2:
		*entry = elf_load_segments64(file_addr, 0, pre_load, post_load);
		if (ehdr->ei_data != ELFDATA2MSB) {
			uint32_t flags = elf_get_eflags_64(file_addr);
			if ((flags & 0x3) == 2)
				type = 4; /* LE64 ABIv2 */
			else
				type = 3; /* LE64 ABIv1 */
		}
		break;
	}
	if (*entry == 0)
		type = 0;

	return type;
}


/**
 * load_elf_file_to_addr loads an ELF file to given address.
 * This is useful for 64-bit vmlinux images that use the virtual entry
 * point address in their headers, and thereby need a special treatment.
 *
 * @param file_addr  pointer to the start of the elf file
 * @param entry      pointer where the ELF loader will store
 *                   the entry point
 * @param pre_load   handler that is called before copying a segment
 * @param post_load  handler that is called after copying a segment
 * @return           1 for a 32 bit file
 *                   2 for a 64 bit file
 *                   anything else means an error during load
 */
int
elf_load_file_to_addr(void *file_addr, void *addr, unsigned long *entry,
                      int (*pre_load)(void*, long),
                      void (*post_load)(void*, long))
{
	int type;
	long offset;

	type = elf_check_file(file_addr);

	switch (type) {
	case 1:
		/* Parse 32-bit image */
		offset = (long)addr - elf_get_base_addr32(file_addr);
		*entry = elf_load_segments32(file_addr, offset, pre_load,
		                             post_load) + offset;
		// TODO: elf_relocate32(...)
		break;
	case 2:
		/* Parse 64-bit image */
		offset = (long)addr - elf_get_base_addr64(file_addr);
		*entry = elf_load_segments64(file_addr, offset, pre_load,
		                             post_load) + offset;
		elf_relocate64(file_addr, offset);
		break;
	}

	return type;
}


/**
 * Get the base load address of the ELF image
 * @return  The base address or -1 for error
 */
long
elf_get_base_addr(void *file_addr)
{
	int type;

	type = elf_check_file(file_addr);

	switch (type) {
	case 1:
		/* Return 32-bit image base address */
		return elf_get_base_addr32(file_addr);
		break;
	case 2:
		/* Return 64-bit image base address */
		return elf_get_base_addr64(file_addr);
		break;
	}

	return -1;
}
