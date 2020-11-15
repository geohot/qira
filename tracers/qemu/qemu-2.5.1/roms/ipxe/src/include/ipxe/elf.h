#ifndef _IPXE_ELF_H
#define _IPXE_ELF_H

/**
 * @file
 *
 * ELF image format
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/image.h>
#include <elf.h>

typedef Elf32_Ehdr	Elf_Ehdr;
typedef Elf32_Phdr	Elf_Phdr;
typedef Elf32_Off	Elf_Off;
#define ELFCLASS	ELFCLASS32

extern int elf_segments ( struct image *image, Elf_Ehdr *ehdr,
			  int ( * process ) ( struct image *image,
					      Elf_Phdr *phdr, physaddr_t dest ),
			  physaddr_t *entry, physaddr_t *max );
extern int elf_load ( struct image *image, physaddr_t *entry, physaddr_t *max );

#endif /* _IPXE_ELF_H */
