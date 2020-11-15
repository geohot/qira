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
 * 64-bit ELF loader for PowerPC.
 * See the "64-bit PowerPC ELF Application Binary Interface Supplement" and
 * the "ELF-64 Object File Format" documentation for details.
 */
 
#include <string.h>
#include <stdio.h>
#include <libelf.h>
#include <byteorder.h>

struct ehdr64
{
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct phdr64
{
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

struct shdr64
{
	uint32_t sh_name;	/* Section name */
	uint32_t sh_type;	/* Section type */
	uint64_t sh_flags; 	/* Section attributes */
	uint64_t sh_addr;	/* Virtual address in memory */
	uint64_t sh_offset;	/* Offset in file */
	uint64_t sh_size;	/* Size of section */
	uint32_t sh_link;	/* Link to other section */
	uint32_t sh_info;	/* Miscellaneous information */
	uint64_t sh_addralign;	/* Address alignment boundary */
	uint64_t sh_entsize;	/* Size of entries, if section has table */
};

struct rela			/* RelA relocation table entry */
{
	uint64_t r_offset;	/* Address of reference */
	uint64_t r_info;	/* Symbol index and type of relocation */
	int64_t  r_addend;	/* Constant part of expression */
};

struct sym64
{
	uint32_t st_name;	/* Symbol name */
	uint8_t st_info;	/* Type and Binding attributes */
	uint8_t st_other;	/* Reserved */
	uint16_t st_shndx;	/* Section table index */
	uint64_t st_value;	/* Symbol value */
	uint64_t st_size;	/* Size of object (e.g., common) */
};


/* For relocations */
#define	ELF_R_SYM(i)	((i)>>32)
#define	ELF_R_TYPE(i)	((uint32_t)(i) & 0xFFFFFFFF)
#define	ELF_R_INFO(s,t)	((((uint64_t) (s)) << 32) + (t))

/*
 * Relocation types for PowerPC64.
 */
#define	R_PPC64_NONE			0
#define	R_PPC64_ADDR32			1
#define	R_PPC64_ADDR24			2
#define	R_PPC64_ADDR16			3
#define	R_PPC64_ADDR16_LO		4
#define	R_PPC64_ADDR16_HI		5
#define	R_PPC64_ADDR16_HA		6
#define	R_PPC64_ADDR14			7
#define	R_PPC64_ADDR14_BRTAKEN		8
#define	R_PPC64_ADDR14_BRNTAKEN		9
#define	R_PPC64_REL24			10
#define	R_PPC64_REL14			11
#define	R_PPC64_REL14_BRTAKEN		12
#define	R_PPC64_REL14_BRNTAKEN		13
#define	R_PPC64_GOT16			14
#define	R_PPC64_GOT16_LO		15
#define	R_PPC64_GOT16_HI		16
#define	R_PPC64_GOT16_HA		17
#define	R_PPC64_COPY			19
#define	R_PPC64_GLOB_DAT		20
#define	R_PPC64_JMP_SLOT		21
#define	R_PPC64_RELATIVE		22
#define	R_PPC64_UADDR32			24
#define	R_PPC64_UADDR16			25
#define	R_PPC64_REL32			26
#define	R_PPC64_PLT32			27
#define	R_PPC64_PLTREL32		28
#define	R_PPC64_PLT16_LO		29
#define	R_PPC64_PLT16_HI		30
#define	R_PPC64_PLT16_HA		31
#define	R_PPC64_SECTOFF			33
#define	R_PPC64_SECTOFF_LO		34
#define	R_PPC64_SECTOFF_HI		35
#define	R_PPC64_SECTOFF_HA		36
#define	R_PPC64_ADDR30			37
#define	R_PPC64_ADDR64			38
#define	R_PPC64_ADDR16_HIGHER		39
#define	R_PPC64_ADDR16_HIGHERA		40
#define	R_PPC64_ADDR16_HIGHEST		41
#define	R_PPC64_ADDR16_HIGHESTA		42
#define	R_PPC64_UADDR64			43
#define	R_PPC64_REL64			44
#define	R_PPC64_PLT64			45
#define	R_PPC64_PLTREL64		46
#define	R_PPC64_TOC16			47
#define	R_PPC64_TOC16_LO		48
#define	R_PPC64_TOC16_HI		49
#define	R_PPC64_TOC16_HA		50
#define	R_PPC64_TOC			51
#define	R_PPC64_PLTGOT16		52
#define	R_PPC64_PLTGOT16_LO		53
#define	R_PPC64_PLTGOT16_HI		54
#define	R_PPC64_PLTGOT16_HA		55
#define	R_PPC64_ADDR16_DS		56
#define	R_PPC64_ADDR16_LO_DS		57
#define	R_PPC64_GOT16_DS		58
#define	R_PPC64_GOT16_LO_DS		59
#define	R_PPC64_PLT16_LO_DS		60
#define	R_PPC64_SECTOFF_DS		61
#define	R_PPC64_SECTOFF_LO_DS		62
#define	R_PPC64_TOC16_DS		63
#define	R_PPC64_TOC16_LO_DS		64
#define	R_PPC64_PLTGOT16_DS		65
#define	R_PPC64_PLTGOT16_LO_DS		66
#define	R_PPC64_TLS			67
#define	R_PPC64_DTPMOD64		68
#define	R_PPC64_TPREL16			69
#define	R_PPC64_TPREL16_LO		60
#define	R_PPC64_TPREL16_HI		71
#define	R_PPC64_TPREL16_HA		72
#define	R_PPC64_TPREL64			73
#define	R_PPC64_DTPREL16		74
#define	R_PPC64_DTPREL16_LO		75
#define	R_PPC64_DTPREL16_HI		76
#define	R_PPC64_DTPREL16_HA		77
#define	R_PPC64_DTPREL64		78
#define	R_PPC64_GOT_TLSGD16		79
#define	R_PPC64_GOT_TLSGD16_LO		80
#define	R_PPC64_GOT_TLSGD16_HI		81
#define	R_PPC64_GOT_TLSGD16_HA		82
#define	R_PPC64_GOT_TLSLD16		83
#define	R_PPC64_GOT_TLSLD16_LO		84
#define	R_PPC64_GOT_TLSLD16_HI		85
#define	R_PPC64_GOT_TLSLD16_HA		86
#define	R_PPC64_GOT_TPREL16_DS		87
#define	R_PPC64_GOT_TPREL16_LO_	DS	88
#define	R_PPC64_GOT_TPREL16_HI		89
#define	R_PPC64_GOT_TPREL16_HA		90
#define	R_PPC64_GOT_DTPREL16_DS		91
#define	R_PPC64_GOT_DTPREL16_LO_DS	92
#define	R_PPC64_GOT_DTPREL16_HI		93
#define	R_PPC64_GOT_DTPREL16_HA		94
#define	R_PPC64_TPREL16_DS		95
#define	R_PPC64_TPREL16_LO_DS		96
#define	R_PPC64_TPREL16_HIGHER		97
#define	R_PPC64_TPREL16_HIGHERA		98
#define	R_PPC64_TPREL16_HIGHEST		99
#define	R_PPC64_TPREL16_HIGHESTA	100
#define	R_PPC64_DTPREL16_DS		101
#define	R_PPC64_DTPREL16_LO_DS		102
#define	R_PPC64_DTPREL16_HIGHER		103
#define	R_PPC64_DTPREL16_HIGHERA	104
#define	R_PPC64_DTPREL16_HIGHEST	105
#define	R_PPC64_DTPREL16_HIGHESTA	106


static struct phdr64*
get_phdr64(unsigned long *file_addr)
{
	return (struct phdr64 *) (((unsigned char *) file_addr)
		+ ((struct ehdr64 *)file_addr)->e_phoff);
}

static void
load_segment64(unsigned long *file_addr, struct phdr64 *phdr, signed long offset,
               int (*pre_load)(void*, long),
               void (*post_load)(void*, long))
{
	unsigned long src = phdr->p_offset + (unsigned long) file_addr;
	unsigned long destaddr;

	destaddr = phdr->p_paddr + offset;

	/* check if we're allowed to copy */
	if (pre_load != NULL) {
		if (pre_load((void*)destaddr, phdr->p_memsz) != 0)
			return;
	}

	/* copy into storage */
	memmove((void*)destaddr, (void*)src, phdr->p_filesz);

	/* clear bss */
	memset((void*)(destaddr + phdr->p_filesz), 0,
	       phdr->p_memsz - phdr->p_filesz);

	if (phdr->p_memsz && post_load != NULL) {
		post_load((void*)destaddr, phdr->p_memsz);
	}
}

unsigned long
elf_load_segments64(void *file_addr, signed long offset,
                    int (*pre_load)(void*, long),
                    void (*post_load)(void*, long))
{
	struct ehdr64 *ehdr = (struct ehdr64 *) file_addr;
	/* Calculate program header address */
	struct phdr64 *phdr = get_phdr64(file_addr);
	int i;

	/* loop e_phnum times */
	for (i = 0; i <= ehdr->e_phnum; i++) {
		/* PT_LOAD ? */
		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_paddr != phdr->p_vaddr) {
				printf("ELF64: VirtAddr(%lx) != PhysAddr(%lx) not supported, aborting\n",
					(long)phdr->p_vaddr, (long)phdr->p_paddr);
				return 0;
			}

			/* copy segment */
			load_segment64(file_addr, phdr, offset, pre_load, post_load);
		}
		/* step to next header */
		phdr = (struct phdr64 *)(((uint8_t *)phdr) + ehdr->e_phentsize);
	}

	/* Entry point is always a virtual address, so translate it
	 * to physical before returning it */
	return ehdr->e_entry;
}

/**
 * Return the base address for loading (i.e. the address of the first PT_LOAD
 * segment)
 * @param  file_addr	pointer to the ELF file in memory
 * @return		the base address
 */
long
elf_get_base_addr64(void *file_addr)
{
	struct ehdr64 *ehdr = (struct ehdr64 *) file_addr;
	/* Calculate program header address */
	struct phdr64 *phdr = get_phdr64(file_addr);
	int i;

	/* loop e_phnum times */
	for (i = 0; i <= ehdr->e_phnum; i++) {
		/* PT_LOAD ? */
		if (phdr->p_type == PT_LOAD) {
			/* Return base address */
			return phdr->p_paddr;
		}
		/* step to next header */
		phdr = (struct phdr64 *)(((uint8_t *)phdr) + ehdr->e_phentsize);
	}

	return 0;
}


/**
 * Apply one relocation entry.
 */
static void
elf_apply_rela64(void *file_addr, signed long offset, struct rela *relaentry,
		 struct sym64 *symtabentry)
{
	void *addr;
	unsigned long s_a;
	unsigned long base_addr;

	base_addr = elf_get_base_addr64(file_addr);

	/* Sanity check */
	if (relaentry->r_offset < base_addr) {
		printf("\nELF relocation out of bounds!\n");
		return;
	}

	base_addr += offset;

	/* Actual address where the relocation will be applied at. */
	addr = (void*)(relaentry->r_offset + offset);

	/* Symbol value (S) + Addend (A) */
	s_a = symtabentry->st_value + offset + relaentry->r_addend;

	switch (ELF_R_TYPE(relaentry->r_info)) {
	 case R_PPC64_ADDR32:		/* S + A */
		*(uint32_t *)addr = (uint32_t) s_a;
		break;
	 case R_PPC64_ADDR64:		/* S + A */
		*(uint64_t *)addr = (uint64_t) s_a;
		break;
	 case R_PPC64_TOC:		/* .TOC */
		*(uint64_t *)addr += offset;
		break;
	 case R_PPC64_ADDR16_HIGHEST:	/* #highest(S + A) */
		*(uint16_t *)addr = ((s_a >> 48) & 0xffff);
		break;
	 case R_PPC64_ADDR16_HIGHER:	/* #higher(S + A) */
		*(uint16_t *)addr = ((s_a >> 32) & 0xffff);
		break;
	 case R_PPC64_ADDR16_HI:	/* #hi(S + A) */
		*(uint16_t *)addr = ((s_a >> 16) & 0xffff);
		break;
	 case R_PPC64_ADDR16_LO:	/* #lo(S + A) */
		*(uint16_t *)addr = s_a & 0xffff;
		break;
	 case R_PPC64_ADDR16_LO_DS:
		*(uint16_t *)addr = (s_a & 0xfffc);
		break;
	 case R_PPC64_ADDR16_HA:	/* #ha(S + A) */
		*(uint16_t *)addr = (((s_a >> 16) + ((s_a & 0x8000) ? 1 : 0))
				     & 0xffff);
		break;

	 case R_PPC64_TOC16:		/* half16* S + A - .TOC. */
	 case R_PPC64_TOC16_LO_DS:
	 case R_PPC64_TOC16_LO: 	/* #lo(S + A - .TOC.) */
	 case R_PPC64_TOC16_HI: 	/* #hi(S + A - .TOC.) */
	 case R_PPC64_TOC16_HA:
	 case R_PPC64_TOC16_DS: 	/* (S + A - .TOC) >> 2 */
	 case R_PPC64_REL14:
	 case R_PPC64_REL24:		/* (S + A - P) >> 2 */
	 case R_PPC64_REL64:		/* S + A - P */
	 case R_PPC64_GOT16_DS:
	 case R_PPC64_GOT16_LO_DS:
		// printf("\t\tignoring relocation type %i\n",
		//	  ELF_R_TYPE(relaentry->r_info));
		break;
	 default:
		printf("ERROR: Unhandled relocation (A) type %i\n",
			ELF_R_TYPE(relaentry->r_info));
	}
}


/**
 * Step through all relocation entries and apply them one by one.
 */
static void
elf_apply_all_rela64(void *file_addr, signed long offset, struct shdr64 *shdrs, int idx)
{
	struct shdr64 *rela_shdr = &shdrs[idx];
	struct shdr64 *dst_shdr = &shdrs[rela_shdr->sh_info];
	struct shdr64 *sym_shdr = &shdrs[rela_shdr->sh_link];
	struct rela *relaentry;
	struct sym64 *symtabentry;
	uint32_t symbolidx;
	int i;

	/* If the referenced section has not been allocated, then it has
	 * not been loaded and thus does not need to be relocated. */
	if ((dst_shdr->sh_flags & SHF_ALLOC) != SHF_ALLOC)
		return;

	for (i = 0; i < rela_shdr->sh_size; i += rela_shdr->sh_entsize) {
		relaentry = (struct rela *)(file_addr + rela_shdr->sh_offset + i);

		symbolidx = ELF_R_SYM(relaentry->r_info);
		symtabentry = (struct sym64*)(file_addr + sym_shdr->sh_offset) + symbolidx;

		elf_apply_rela64(file_addr, offset, relaentry, symtabentry);
	}
}


/**
 * Apply ELF relocations
 */
void
elf_relocate64(void *file_addr, signed long offset)
{
	struct ehdr64 *ehdr = (struct ehdr64 *) file_addr;
	/* Calculate section header address */
	struct shdr64 *shdrs = (struct shdr64 *)
			(((unsigned char *) file_addr) + ehdr->e_shoff);
	int i;

	/* loop over all segments */
	for (i = 0; i <= ehdr->e_shnum; i++) {
		/* Skip if it is not a relocation segment */
		if (shdrs[i].sh_type == SHT_RELA) {
			elf_apply_all_rela64(file_addr, offset, shdrs, i);
		}
	}
}

void
elf_byteswap_header64(void *file_addr)
{
	struct ehdr64 *ehdr = (struct ehdr64 *) file_addr;
	struct phdr64 *phdr;
	int i;

	bswap_16p(&ehdr->e_type);
	bswap_16p(&ehdr->e_machine);
	bswap_32p(&ehdr->e_version);
	bswap_64p(&ehdr->e_entry);
	bswap_64p(&ehdr->e_phoff);
	bswap_64p(&ehdr->e_shoff);
	bswap_32p(&ehdr->e_flags);
	bswap_16p(&ehdr->e_ehsize);
	bswap_16p(&ehdr->e_phentsize);
	bswap_16p(&ehdr->e_phnum);
	bswap_16p(&ehdr->e_shentsize);
	bswap_16p(&ehdr->e_shnum);
	bswap_16p(&ehdr->e_shstrndx);

	phdr = get_phdr64(file_addr);

	/* loop e_phnum times */
	for (i = 0; i <= ehdr->e_phnum; i++) {
		bswap_32p(&phdr->p_type);
		bswap_32p(&phdr->p_flags);
		bswap_64p(&phdr->p_offset);
		bswap_64p(&phdr->p_vaddr);
		bswap_64p(&phdr->p_paddr);
		bswap_64p(&phdr->p_filesz);
		bswap_64p(&phdr->p_memsz);
		bswap_64p(&phdr->p_align);

		/* step to next header */
		phdr = (struct phdr64 *)(((uint8_t *)phdr) + ehdr->e_phentsize);
	}
}

uint32_t elf_get_eflags_64(void *file_addr)
{
	struct ehdr64 *ehdr = (struct ehdr64 *) file_addr;

	return ehdr->e_flags;
}
