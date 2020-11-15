/*
 * <elf.c>
 *
 * Open Hack'Ware BIOS ELF executable file loader
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"
#include "exec.h"

uint32_t fs_inode_get_size (inode_t *inode);

/* ELF executable loader */
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Off;
typedef uint32_t Elf32_Addr;

#define EI_NIDENT	16

typedef struct elf32_hdr_t {
  unsigned char	e_ident[EI_NIDENT];
  Elf32_Half	e_type;
  Elf32_Half	e_machine;
  Elf32_Word	e_version;
  Elf32_Addr	e_entry;  /* Entry point */
  Elf32_Off	e_phoff;
  Elf32_Off	e_shoff;
  Elf32_Word	e_flags;
  Elf32_Half	e_ehsize;
  Elf32_Half	e_phentsize;
  Elf32_Half	e_phnum;
  Elf32_Half	e_shentsize;
  Elf32_Half	e_shnum;
  Elf32_Half	e_shstrndx;
} Elf32_Ehdr_t;

typedef struct elf32_phdr_t {
  Elf32_Word	p_type;
  Elf32_Off	p_offset;
  Elf32_Addr	p_vaddr;
  Elf32_Addr	p_paddr;
  Elf32_Word	p_filesz;
  Elf32_Word	p_memsz;
  Elf32_Word	p_flags;
  Elf32_Word	p_align;
} Elf32_Phdr_t;

#define	EI_MAG0		0		/* e_ident[] indexes */
#define	EI_MAG1		1
#define	EI_MAG2		2
#define	EI_MAG3		3
#define	EI_CLASS	4
#define	EI_DATA		5
#define	EI_VERSION	6
#define	EI_OSABI	7
#define	EI_PAD		8

#define	ELFMAG0		0x7f		/* EI_MAG */
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'

#define	ELFCLASSNONE	0		/* EI_CLASS */
#define	ELFCLASS32	1
#define	ELFCLASS64	2
#define	ELFCLASSNUM	3

#define ELFDATANONE	0		/* e_ident[EI_DATA] */
#define ELFDATA2LSB	1
#define ELFDATA2MSB	2

#define EV_NONE		0		/* e_version, EI_VERSION */
#define EV_CURRENT	1
#define EV_NUM		2

/* These constants define the different elf file types */
#define ET_NONE   0
#define ET_REL    1
#define ET_EXEC   2
#define ET_DYN    3
#define ET_CORE   4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

/* These constants define the various ELF target machines */
#define EM_NONE  0
#define EM_M32   1
#define EM_SPARC 2
#define EM_386   3
#define EM_68K   4
#define EM_88K   5
#define EM_486   6   /* Perhaps disused */
#define EM_860   7
#define EM_MIPS		8	/* MIPS R3000 (officially, big-endian only) */
#define EM_MIPS_RS4_BE 10	/* MIPS R4000 big-endian */
#define EM_PARISC      15	/* HPPA */
#define EM_SPARC32PLUS 18	/* Sun's "v8plus" */
#define EM_PPC	       20	/* PowerPC */
#define EM_PPC64       21       /* PowerPC64 */
#define EM_SH	       42	/* SuperH */
#define EM_SPARCV9     43	/* SPARC v9 64-bit */
#define EM_IA_64	50	/* HP/Intel IA-64 */
#define EM_X86_64	62	/* AMD x86-64 */
#define EM_S390		22	/* IBM S/390 */
#define EM_CRIS         76      /* Axis Communications 32-bit embedded processor */
#define EM_V850		87	/* NEC v850 */
#define EM_H8_300H      47      /* Hitachi H8/300H */
#define EM_H8S          48      /* Hitachi H8S     */
/*
 * This is an interim value that we will use until the committee comes
 * up with a final number.
 */
#define EM_ALPHA	0x9026
/* Bogus old v850 magic number, used by old tools.  */
#define EM_CYGNUS_V850	0x9080
/*
 * This is the old interim value for S/390 architecture
 */
#define EM_S390_OLD     0xA390

int exec_load_elf (inode_t *file, void **dest, void **entry, void **end,
                   uint32_t loffset)
{
    Elf32_Ehdr_t ehdr;
    Elf32_Phdr_t phdr;
    void *address, *first, *last;
    uint32_t offset, fsize, msize;
    int i;

    file_seek(file, loffset);
    if (fs_read(file, &ehdr, sizeof(Elf32_Ehdr_t)) < 0) {
        ERROR("Cannot load first bloc of file...\n");
        return -1;
    }
    DPRINTF("Check ELF file\n");
    /* Check ident */
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        DPRINTF("Not an ELF file %0x\n", *(uint32_t *)ehdr.e_ident);
        return -2;
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
        ERROR("Not a 32 bits ELF file\n");
        return -2;
    }
    if (ehdr.e_ident[EI_DATA] != ELFDATA2MSB) {
        ERROR("Not a big-endian ELF file\n");
        return -2;
    }
    if (ehdr.e_ident[EI_VERSION] != EV_CURRENT /*||
        ehdr->e_version != EV_CURRENT*/) {
        ERROR("Invalid ELF executable version %d %08x\n",
              ehdr.e_ident[EI_VERSION], ehdr.e_version);
        return -2;
    }
    if (ehdr.e_type != ET_EXEC) {
        ERROR("Not an executable ELF file\n");
        return -2;
    }
    if (ehdr.e_machine != EM_PPC) {
        ERROR("Not a PPC ELF executable\n");
        return -2;
    }
    /* All right, seems to be a regular ELF program for PPC */
    *entry = (void *)ehdr.e_entry;
    DPRINTF("ELF file found entry = %p\n", *entry);
    last = NULL;
    first = last - 4;
    fsize = msize = 0;
    offset = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
#if 0
        if (offset > fs_inode_get_size(file)) {
            ERROR("ELF program header %d offset > file size %d %d\n", i,
                  offset, fs_inode_get_size(file));
            return -1;
        }
#endif
        DPRINTF("Load program header %d from %08x\n", i, offset);
        file_seek(file, offset + loffset);
        if (fs_read(file, &phdr, sizeof(Elf32_Phdr_t)) < 0) {
            ERROR("Cannot load ELF program header %d...\n", i);
            return -1;
        }
        DPRINTF("Load program header %d %08x %08x %08x %08x\n", i,
                phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz);
#if 0
        if (phdr.p_offset > fs_inode_get_size(file)) {
            ERROR("ELF program %d offset > file size %d %d\n",
                  i, phdr.p_offset, fs_inode_get_size(file));
            return -1;
        }
#endif
        /* As we won't remap memory, load it at it's virtual address (!) */
        address = (void *)phdr.p_vaddr;
        if (address < first)
            first = address;
        fsize = phdr.p_filesz;
        msize = phdr.p_memsz;
        if (address + msize > last)
            last = address + msize;
        file_seek(file, phdr.p_offset + loffset);
        set_loadinfo((void *)first, last - first);
        if (fs_read(file, address, fsize) < 0) {
            ERROR("Cannot load ELF program %d...\n", i);
            return -1;
        }
        if (msize > fsize) {
            memset(address + fsize, 0, msize - fsize);
        }
        offset += ehdr.e_phentsize;
    }
    *dest = (void *)first;
    *end = (void *)last;
    DPRINTF("ELF file loaded at %p => %p fsize %08x msize %08x "
            "(%08x %08x)\n", *dest, *entry, fsize, msize,
            *(uint32_t *)entry, *((uint32_t *)entry + 1));

    return 0;
}
