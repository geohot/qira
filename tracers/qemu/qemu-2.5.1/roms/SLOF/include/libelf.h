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
 * ELF loader library
 */

#ifndef __LIBELF_H
#define __LIBELF_H

#include <stdint.h>

/* ELF object file types */
#define ET_NONE		0	/* No file type */
#define ET_REL		1	/* Relocatable file */
#define ET_EXEC		2	/* Executable file */
#define ET_DYN		3	/* Shared object file */
#define ET_CORE		4	/* Core file */

/* ELF object endian */
#define ELFDATA2LSB	1	/* 2's complement, little endian */
#define ELFDATA2MSB	2	/* 2's complement, big endian */

/* Generic ELF header */
struct ehdr {
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
};

/* Section types (sh_type) */
#define SHT_NULL	0	/* Unused section header */
#define SHT_PROGBITS	1	/* Information defined by the program */
#define SHT_SYMTAB	2	/* Linker symbol table */
#define SHT_STRTAB	3	/* String table */
#define SHT_RELA	4	/* "Rela" type relocation entries */
#define SHT_HASH	5	/* Symbol hash table */
#define SHT_DYNAMIC	6	/* Dynamic linking tables */
#define SHT_NOTE	7	/* Note information */
#define SHT_NOBITS	8	/* Uninitialized space */
#define SHT_REL 	9	/* "Rel" type relocation entries */
#define SHT_SHLIB	10	/* Reserved */
#define SHT_DYNSYM	11	/* Dynamic loader symbol table */

/* Section attributs (sh_flags) */
#define SHF_WRITE	0x1
#define SHF_ALLOC	0x2
#define SHF_EXECINSTR	0x4

/* Segment types (p_type) */
#define PT_NULL 	0	/* Unused entry */
#define PT_LOAD 	1	/* Loadable segment */
#define PT_DYNAMIC	2	/* Dynamic linking tables */
#define PT_INTERP	3	/* Program interpreter path name */
#define PT_NOTE 	4	/* Note sections */


int elf_load_file(void *file_addr, unsigned long *entry,
                  int (*pre_load)(void*, long),
                  void (*post_load)(void*, long));
int elf_load_file_to_addr(void *file_addr, void *addr, unsigned long *entry,
                          int (*pre_load)(void*, long),
                          void (*post_load)(void*, long));

void elf_byteswap_header32(void *file_addr);
void elf_byteswap_header64(void *file_addr);

unsigned int elf_load_segments32(void *file_addr, signed long offset,
                                 int (*pre_load)(void*, long),
                                 void (*post_load)(void*, long));
unsigned long elf_load_segments64(void *file_addr, signed long offset,
                                  int (*pre_load)(void*, long),
                                  void (*post_load)(void*, long));

long elf_get_base_addr(void *file_addr);
long elf_get_base_addr32(void *file_addr);
long elf_get_base_addr64(void *file_addr);
uint32_t elf_get_eflags_32(void *file_addr);
uint32_t elf_get_eflags_64(void *file_addr);

void elf_relocate64(void *file_addr, signed long offset);

int elf_forth_claim(void *addr, long size);

#endif				/* __LIBELF_H */
