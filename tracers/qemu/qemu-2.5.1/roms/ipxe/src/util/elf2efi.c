/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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
 */

#define _GNU_SOURCE
#define PACKAGE "elf2efi"
#define PACKAGE_VERSION "1"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <bfd.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/IndustryStandard/PeImage.h>
#include <libgen.h>

#define eprintf(...) fprintf ( stderr, __VA_ARGS__ )

#define EFI_FILE_ALIGN 0x20

struct pe_section {
	struct pe_section *next;
	EFI_IMAGE_SECTION_HEADER hdr;
	uint8_t contents[0];
};

struct pe_relocs {
	struct pe_relocs *next;
	unsigned long start_rva;
	unsigned int used_relocs;
	unsigned int total_relocs;
	uint16_t *relocs;
};

struct pe_header {
	EFI_IMAGE_DOS_HEADER dos;
	uint8_t padding[128];
#if defined(EFI_TARGET_IA32)
	EFI_IMAGE_NT_HEADERS32 nt;
#elif defined(EFI_TARGET_X64)
	EFI_IMAGE_NT_HEADERS64 nt;
#endif
};

static struct pe_header efi_pe_header = {
	.dos = {
		.e_magic = EFI_IMAGE_DOS_SIGNATURE,
		.e_lfanew = offsetof ( typeof ( efi_pe_header ), nt ),
	},
	.nt = {
		.Signature = EFI_IMAGE_NT_SIGNATURE,
		.FileHeader = {
#if defined(EFI_TARGET_IA32)
			.Machine = EFI_IMAGE_MACHINE_IA32,
#elif defined(EFI_TARGET_X64)
			.Machine = EFI_IMAGE_MACHINE_X64,
#endif
			.TimeDateStamp = 0x10d1a884,
			.SizeOfOptionalHeader =
				sizeof ( efi_pe_header.nt.OptionalHeader ),
			.Characteristics = ( EFI_IMAGE_FILE_DLL |
#if defined(EFI_TARGET_IA32)
					     EFI_IMAGE_FILE_32BIT_MACHINE |
#endif
					     EFI_IMAGE_FILE_EXECUTABLE_IMAGE ),
		},
		.OptionalHeader = {
#if defined(EFI_TARGET_IA32)
			.Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC,
#elif defined(EFI_TARGET_X64)
			.Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC,
#endif
			.SectionAlignment = EFI_FILE_ALIGN,
			.FileAlignment = EFI_FILE_ALIGN,
			.SizeOfImage = sizeof ( efi_pe_header ),
			.SizeOfHeaders = sizeof ( efi_pe_header ),
			.NumberOfRvaAndSizes =
				EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES,
		},
	},
};

/** Command-line options */
struct options {
	unsigned int subsystem;
};

/**
 * Allocate memory
 *
 * @v len		Length of memory to allocate
 * @ret ptr		Pointer to allocated memory
 */
static void * xmalloc ( size_t len ) {
	void *ptr;

	ptr = malloc ( len );
	if ( ! ptr ) {
		eprintf ( "Could not allocate %zd bytes\n", len );
		exit ( 1 );
	}

	return ptr;
}

/**
 * Align section within PE file
 *
 * @v offset		Unaligned offset
 * @ret aligned_offset	Aligned offset
 */
static unsigned long efi_file_align ( unsigned long offset ) {
	return ( ( offset + EFI_FILE_ALIGN - 1 ) & ~( EFI_FILE_ALIGN - 1 ) );
}

/**
 * Generate entry in PE relocation table
 *
 * @v pe_reltab		PE relocation table
 * @v rva		RVA
 * @v size		Size of relocation entry
 */
static void generate_pe_reloc ( struct pe_relocs **pe_reltab,
				unsigned long rva, size_t size ) {
	unsigned long start_rva;
	uint16_t reloc;
	struct pe_relocs *pe_rel;
	uint16_t *relocs;

	/* Construct */
	start_rva = ( rva & ~0xfff );
	reloc = ( rva & 0xfff );
	switch ( size ) {
	case 8:
		reloc |= 0xa000;
		break;
	case 4:
		reloc |= 0x3000;
		break;
	case 2:
		reloc |= 0x2000;
		break;
	default:
		eprintf ( "Unsupported relocation size %zd\n", size );
		exit ( 1 );
	}

	/* Locate or create PE relocation table */
	for ( pe_rel = *pe_reltab ; pe_rel ; pe_rel = pe_rel->next ) {
		if ( pe_rel->start_rva == start_rva )
			break;
	}
	if ( ! pe_rel ) {
		pe_rel = xmalloc ( sizeof ( *pe_rel ) );
		memset ( pe_rel, 0, sizeof ( *pe_rel ) );
		pe_rel->next = *pe_reltab;
		*pe_reltab = pe_rel;
		pe_rel->start_rva = start_rva;
	}

	/* Expand relocation list if necessary */
	if ( pe_rel->used_relocs < pe_rel->total_relocs ) {
		relocs = pe_rel->relocs;
	} else {
		pe_rel->total_relocs = ( pe_rel->total_relocs ?
					 ( pe_rel->total_relocs * 2 ) : 256 );
		relocs = xmalloc ( pe_rel->total_relocs *
				   sizeof ( pe_rel->relocs[0] ) );
		memset ( relocs, 0,
			 pe_rel->total_relocs * sizeof ( pe_rel->relocs[0] ) );
		memcpy ( relocs, pe_rel->relocs,
			 pe_rel->used_relocs * sizeof ( pe_rel->relocs[0] ) );
		free ( pe_rel->relocs );
		pe_rel->relocs = relocs;
	}

	/* Store relocation */
	pe_rel->relocs[ pe_rel->used_relocs++ ] = reloc;
}

/**
 * Calculate size of binary PE relocation table
 *
 * @v pe_reltab		PE relocation table
 * @v buffer		Buffer to contain binary table, or NULL
 * @ret size		Size of binary table
 */
static size_t output_pe_reltab ( struct pe_relocs *pe_reltab,
				 void *buffer ) {
	struct pe_relocs *pe_rel;
	unsigned int num_relocs;
	size_t size;
	size_t total_size = 0;

	for ( pe_rel = pe_reltab ; pe_rel ; pe_rel = pe_rel->next ) {
		num_relocs = ( ( pe_rel->used_relocs + 1 ) & ~1 );
		size = ( sizeof ( uint32_t ) /* VirtualAddress */ +
			 sizeof ( uint32_t ) /* SizeOfBlock */ +
			 ( num_relocs * sizeof ( uint16_t ) ) );
		if ( buffer ) {
			*( (uint32_t *) ( buffer + total_size + 0 ) )
				= pe_rel->start_rva;
			*( (uint32_t *) ( buffer + total_size + 4 ) ) = size;
			memcpy ( ( buffer + total_size + 8 ), pe_rel->relocs,
				 ( num_relocs * sizeof ( uint16_t ) ) );
		}
		total_size += size;
	}

	return total_size;
}

/**
 * Open input BFD file
 *
 * @v filename		File name
 * @ret ibfd		BFD file
 */
static bfd * open_input_bfd ( const char *filename ) {
	bfd *bfd;

	/* Open the file */
	bfd = bfd_openr ( filename, NULL );
	if ( ! bfd ) {
		eprintf ( "Cannot open %s: ", filename );
		bfd_perror ( NULL );
		exit ( 1 );
	}

	/* The call to bfd_check_format() must be present, otherwise
	 * we get a segfault from later BFD calls.
	 */
	if ( ! bfd_check_format ( bfd, bfd_object ) ) {
		eprintf ( "%s is not an object file: ", filename );
		bfd_perror ( NULL );
		exit ( 1 );
	}

	return bfd;
}

/**
 * Read symbol table
 *
 * @v bfd		BFD file
 */
static asymbol ** read_symtab ( bfd *bfd ) {
	long symtab_size;
	asymbol **symtab;
	long symcount;

	/* Get symbol table size */
	symtab_size = bfd_get_symtab_upper_bound ( bfd );
	if ( symtab_size < 0 ) {
		bfd_perror ( "Could not get symbol table upper bound" );
		exit ( 1 );
	}

	/* Allocate and read symbol table */
	symtab = xmalloc ( symtab_size );
	symcount = bfd_canonicalize_symtab ( bfd, symtab );
	if ( symcount < 0 ) {
		bfd_perror ( "Cannot read symbol table" );
		exit ( 1 );
	}

	return symtab;
}

/**
 * Read relocation table
 *
 * @v bfd		BFD file
 * @v symtab		Symbol table
 * @v section		Section
 * @v symtab		Symbol table
 * @ret reltab		Relocation table
 */
static arelent ** read_reltab ( bfd *bfd, asymbol **symtab,
				asection *section ) {
	long reltab_size;
	arelent **reltab;
	long numrels;

	/* Get relocation table size */
	reltab_size = bfd_get_reloc_upper_bound ( bfd, section );
	if ( reltab_size < 0 ) {
		bfd_perror ( "Could not get relocation table upper bound" );
		exit ( 1 );
	}

	/* Allocate and read relocation table */
	reltab = xmalloc ( reltab_size );
	numrels = bfd_canonicalize_reloc ( bfd, section, reltab, symtab );
	if ( numrels < 0 ) {
		bfd_perror ( "Cannot read relocation table" );
		exit ( 1 );
	}

	return reltab;
}

/**
 * Process section
 *
 * @v bfd		BFD file
 * @v pe_header		PE file header
 * @v section		Section
 * @ret new		New PE section
 */
static struct pe_section * process_section ( bfd *bfd,
					     struct pe_header *pe_header,
					     asection *section ) {
	struct pe_section *new;
	size_t section_memsz;
	size_t section_filesz;
	unsigned long flags = bfd_get_section_flags ( bfd, section );
	unsigned long code_start;
	unsigned long code_end;
	unsigned long data_start;
	unsigned long data_mid;
	unsigned long data_end;
	unsigned long start;
	unsigned long end;
	unsigned long *applicable_start;
	unsigned long *applicable_end;

	/* Extract current RVA limits from file header */
	code_start = pe_header->nt.OptionalHeader.BaseOfCode;
	code_end = ( code_start + pe_header->nt.OptionalHeader.SizeOfCode );
#if defined(EFI_TARGET_IA32)
	data_start = pe_header->nt.OptionalHeader.BaseOfData;
#elif defined(EFI_TARGET_X64)
	data_start = code_end;
#endif
	data_mid = ( data_start +
		     pe_header->nt.OptionalHeader.SizeOfInitializedData );
	data_end = ( data_mid +
		     pe_header->nt.OptionalHeader.SizeOfUninitializedData );

	/* Allocate PE section */
	section_memsz = bfd_section_size ( bfd, section );
	section_filesz = ( ( flags & SEC_LOAD ) ?
			   efi_file_align ( section_memsz ) : 0 );
	new = xmalloc ( sizeof ( *new ) + section_filesz );
	memset ( new, 0, sizeof ( *new ) + section_filesz );

	/* Fill in section header details */
	strncpy ( ( char * ) new->hdr.Name, section->name,
		  sizeof ( new->hdr.Name ) );
	new->hdr.Misc.VirtualSize = section_memsz;
	new->hdr.VirtualAddress = bfd_get_section_vma ( bfd, section );
	new->hdr.SizeOfRawData = section_filesz;

	/* Fill in section characteristics and update RVA limits */
	if ( flags & SEC_CODE ) {
		/* .text-type section */
		new->hdr.Characteristics =
			( EFI_IMAGE_SCN_CNT_CODE |
			  EFI_IMAGE_SCN_MEM_NOT_PAGED |
			  EFI_IMAGE_SCN_MEM_EXECUTE |
			  EFI_IMAGE_SCN_MEM_READ );
		applicable_start = &code_start;
		applicable_end = &code_end;
	} else if ( flags & SEC_DATA ) {
		/* .data-type section */
		new->hdr.Characteristics =
			( EFI_IMAGE_SCN_CNT_INITIALIZED_DATA |
			  EFI_IMAGE_SCN_MEM_NOT_PAGED |
			  EFI_IMAGE_SCN_MEM_READ |
			  EFI_IMAGE_SCN_MEM_WRITE );
		applicable_start = &data_start;
		applicable_end = &data_mid;
	} else if ( flags & SEC_READONLY ) {
		/* .rodata-type section */
		new->hdr.Characteristics =
			( EFI_IMAGE_SCN_CNT_INITIALIZED_DATA |
			  EFI_IMAGE_SCN_MEM_NOT_PAGED |
			  EFI_IMAGE_SCN_MEM_READ );
		applicable_start = &data_start;
		applicable_end = &data_mid;
	} else if ( ! ( flags & SEC_LOAD ) ) {
		/* .bss-type section */
		new->hdr.Characteristics =
			( EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA |
			  EFI_IMAGE_SCN_MEM_NOT_PAGED |
			  EFI_IMAGE_SCN_MEM_READ |
			  EFI_IMAGE_SCN_MEM_WRITE );
		applicable_start = &data_mid;
		applicable_end = &data_end;
	} else {
		eprintf ( "Unrecognised characteristics %#lx for section %s\n",
			  flags, section->name );
		exit ( 1 );
	}

	/* Copy in section contents */
	if ( flags & SEC_LOAD ) {
		if ( ! bfd_get_section_contents ( bfd, section, new->contents,
						  0, section_memsz ) ) {
			eprintf ( "Cannot read section %s: ", section->name );
			bfd_perror ( NULL );
			exit ( 1 );
		}
	}

	/* Update RVA limits */
	start = new->hdr.VirtualAddress;
	end = ( start + new->hdr.Misc.VirtualSize );
	if ( ( ! *applicable_start ) || ( *applicable_start >= start ) )
		*applicable_start = start;
	if ( *applicable_end < end )
		*applicable_end = end;
	if ( data_start < code_end )
		data_start = code_end;
	if ( data_mid < data_start )
		data_mid = data_start;
	if ( data_end < data_mid )
		data_end = data_mid;

	/* Write RVA limits back to file header */
	pe_header->nt.OptionalHeader.BaseOfCode = code_start;
	pe_header->nt.OptionalHeader.SizeOfCode = ( code_end - code_start );
#if defined(EFI_TARGET_IA32)
	pe_header->nt.OptionalHeader.BaseOfData = data_start;
#endif
	pe_header->nt.OptionalHeader.SizeOfInitializedData =
		( data_mid - data_start );
	pe_header->nt.OptionalHeader.SizeOfUninitializedData =
		( data_end - data_mid );

	/* Update remaining file header fields */
	pe_header->nt.FileHeader.NumberOfSections++;
	pe_header->nt.OptionalHeader.SizeOfHeaders += sizeof ( new->hdr );
	pe_header->nt.OptionalHeader.SizeOfImage =
		efi_file_align ( data_end );

	return new;
}

/**
 * Process relocation record
 *
 * @v bfd		BFD file
 * @v section		Section
 * @v rel		Relocation entry
 * @v pe_reltab		PE relocation table to fill in
 */
static void process_reloc ( bfd *bfd __attribute__ (( unused )),
			    asection *section, arelent *rel,
			    struct pe_relocs **pe_reltab ) {
	reloc_howto_type *howto = rel->howto;
	asymbol *sym = *(rel->sym_ptr_ptr);
	unsigned long offset = ( bfd_get_section_vma ( bfd, section ) +
				 rel->address );

	if ( bfd_is_abs_section ( sym->section ) ) {
		/* Skip absolute symbols; the symbol value won't
		 * change when the object is loaded.
		 */
	} else if ( ( strcmp ( howto->name, "R_386_NONE" ) == 0 ) ||
		    ( strcmp ( howto->name, "R_X86_64_NONE" ) == 0 ) ) {
		/* Ignore dummy relocations used by REQUIRE_SYMBOL() */
	} else if ( strcmp ( howto->name, "R_X86_64_64" ) == 0 ) {
		/* Generate an 8-byte PE relocation */
		generate_pe_reloc ( pe_reltab, offset, 8 );
	} else if ( strcmp ( howto->name, "R_386_32" ) == 0 ) {
		/* Generate a 4-byte PE relocation */
		generate_pe_reloc ( pe_reltab, offset, 4 );
	} else if ( strcmp ( howto->name, "R_386_16" ) == 0 ) {
		/* Generate a 2-byte PE relocation */
		generate_pe_reloc ( pe_reltab, offset, 2 );
	} else if ( ( strcmp ( howto->name, "R_386_PC32" ) == 0 ) ||
		    ( strcmp ( howto->name, "R_X86_64_PC32" ) == 0 ) ) {
		/* Skip PC-relative relocations; all relative offsets
		 * remain unaltered when the object is loaded.
		 */
	} else {
		eprintf ( "Unrecognised relocation type %s\n", howto->name );
		exit ( 1 );
	}
}

/**
 * Create relocations section
 *
 * @v pe_header		PE file header
 * @v pe_reltab		PE relocation table
 * @ret section		Relocation section
 */
static struct pe_section *
create_reloc_section ( struct pe_header *pe_header,
		       struct pe_relocs *pe_reltab ) {
	struct pe_section *reloc;
	size_t section_memsz;
	size_t section_filesz;
	EFI_IMAGE_DATA_DIRECTORY *relocdir;

	/* Allocate PE section */
	section_memsz = output_pe_reltab ( pe_reltab, NULL );
	section_filesz = efi_file_align ( section_memsz );
	reloc = xmalloc ( sizeof ( *reloc ) + section_filesz );
	memset ( reloc, 0, sizeof ( *reloc ) + section_filesz );

	/* Fill in section header details */
	strncpy ( ( char * ) reloc->hdr.Name, ".reloc",
		  sizeof ( reloc->hdr.Name ) );
	reloc->hdr.Misc.VirtualSize = section_memsz;
	reloc->hdr.VirtualAddress = pe_header->nt.OptionalHeader.SizeOfImage;
	reloc->hdr.SizeOfRawData = section_filesz;
	reloc->hdr.Characteristics = ( EFI_IMAGE_SCN_CNT_INITIALIZED_DATA |
				       EFI_IMAGE_SCN_MEM_NOT_PAGED |
				       EFI_IMAGE_SCN_MEM_READ );

	/* Copy in section contents */
	output_pe_reltab ( pe_reltab, reloc->contents );

	/* Update file header details */
	pe_header->nt.FileHeader.NumberOfSections++;
	pe_header->nt.OptionalHeader.SizeOfHeaders += sizeof ( reloc->hdr );
	pe_header->nt.OptionalHeader.SizeOfImage += section_filesz;
	relocdir = &(pe_header->nt.OptionalHeader.DataDirectory
		     [EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	relocdir->VirtualAddress = reloc->hdr.VirtualAddress;
	relocdir->Size = reloc->hdr.Misc.VirtualSize;

	return reloc;
}

/**
 * Create debug section
 *
 * @v pe_header		PE file header
 * @ret section		Debug section
 */
static struct pe_section *
create_debug_section ( struct pe_header *pe_header, const char *filename ) {
	struct pe_section *debug;
	size_t section_memsz;
	size_t section_filesz;
	EFI_IMAGE_DATA_DIRECTORY *debugdir;
	struct {
		EFI_IMAGE_DEBUG_DIRECTORY_ENTRY debug;
		EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY rsds;
		char name[ strlen ( filename ) + 1 ];
	} *contents;

	/* Allocate PE section */
	section_memsz = sizeof ( *contents );
	section_filesz = efi_file_align ( section_memsz );
	debug = xmalloc ( sizeof ( *debug ) + section_filesz );
	memset ( debug, 0, sizeof ( *debug ) + section_filesz );
	contents = ( void * ) debug->contents;

	/* Fill in section header details */
	strncpy ( ( char * ) debug->hdr.Name, ".debug",
		  sizeof ( debug->hdr.Name ) );
	debug->hdr.Misc.VirtualSize = section_memsz;
	debug->hdr.VirtualAddress = pe_header->nt.OptionalHeader.SizeOfImage;
	debug->hdr.SizeOfRawData = section_filesz;
	debug->hdr.Characteristics = ( EFI_IMAGE_SCN_CNT_INITIALIZED_DATA |
				       EFI_IMAGE_SCN_MEM_NOT_PAGED |
				       EFI_IMAGE_SCN_MEM_READ );

	/* Create section contents */
	contents->debug.TimeDateStamp = 0x10d1a884;
	contents->debug.Type = EFI_IMAGE_DEBUG_TYPE_CODEVIEW;
	contents->debug.SizeOfData =
		( sizeof ( *contents ) - sizeof ( contents->debug ) );
	contents->debug.RVA = ( debug->hdr.VirtualAddress +
				offsetof ( typeof ( *contents ), rsds ) );
	contents->rsds.Signature = CODEVIEW_SIGNATURE_RSDS;
	snprintf ( contents->name, sizeof ( contents->name ), "%s",
		   filename );

	/* Update file header details */
	pe_header->nt.FileHeader.NumberOfSections++;
	pe_header->nt.OptionalHeader.SizeOfHeaders += sizeof ( debug->hdr );
	pe_header->nt.OptionalHeader.SizeOfImage += section_filesz;
	debugdir = &(pe_header->nt.OptionalHeader.DataDirectory
		     [EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]);
	debugdir->VirtualAddress = debug->hdr.VirtualAddress;
	debugdir->Size = debug->hdr.Misc.VirtualSize;

	return debug;
}

/**
 * Write out PE file
 *
 * @v pe_header		PE file header
 * @v pe_sections	List of PE sections
 * @v pe		Output file
 */
static void write_pe_file ( struct pe_header *pe_header,
			    struct pe_section *pe_sections,
			    FILE *pe ) {
	struct pe_section *section;
	unsigned long fpos = 0;

	/* Align length of headers */
	fpos = pe_header->nt.OptionalHeader.SizeOfHeaders =
		efi_file_align ( pe_header->nt.OptionalHeader.SizeOfHeaders );

	/* Assign raw data pointers */
	for ( section = pe_sections ; section ; section = section->next ) {
		if ( section->hdr.SizeOfRawData ) {
			section->hdr.PointerToRawData = fpos;
			fpos += section->hdr.SizeOfRawData;
			fpos = efi_file_align ( fpos );
		}
	}

	/* Write file header */
	if ( fwrite ( pe_header, sizeof ( *pe_header ), 1, pe ) != 1 ) {
		perror ( "Could not write PE header" );
		exit ( 1 );
	}

	/* Write section headers */
	for ( section = pe_sections ; section ; section = section->next ) {
		if ( fwrite ( &section->hdr, sizeof ( section->hdr ),
			      1, pe ) != 1 ) {
			perror ( "Could not write section header" );
			exit ( 1 );
		}
	}

	/* Write sections */
	for ( section = pe_sections ; section ; section = section->next ) {
		if ( fseek ( pe, section->hdr.PointerToRawData,
			     SEEK_SET ) != 0 ) {
			eprintf ( "Could not seek to %x: %s\n",
				  section->hdr.PointerToRawData,
				  strerror ( errno ) );
			exit ( 1 );
		}
		if ( section->hdr.SizeOfRawData &&
		     ( fwrite ( section->contents, section->hdr.SizeOfRawData,
				1, pe ) != 1 ) ) {
			eprintf ( "Could not write section %.8s: %s\n",
				  section->hdr.Name, strerror ( errno ) );
			exit ( 1 );
		}
	}
}

/**
 * Convert ELF to PE
 *
 * @v elf_name		ELF file name
 * @v pe_name		PE file name
 */
static void elf2pe ( const char *elf_name, const char *pe_name,
		     struct options *opts ) {
	char pe_name_tmp[ strlen ( pe_name ) + 1 ];
	bfd *bfd;
	asymbol **symtab;
	asection *section;
	arelent **reltab;
	arelent **rel;
	struct pe_relocs *pe_reltab = NULL;
	struct pe_section *pe_sections = NULL;
	struct pe_section **next_pe_section = &pe_sections;
	struct pe_header pe_header;
	FILE *pe;

	/* Create a modifiable copy of the PE name */
	memcpy ( pe_name_tmp, pe_name, sizeof ( pe_name_tmp ) );

	/* Open the file */
	bfd = open_input_bfd ( elf_name );
	symtab = read_symtab ( bfd );

	/* Initialise the PE header */
	memcpy ( &pe_header, &efi_pe_header, sizeof ( pe_header ) );
	pe_header.nt.OptionalHeader.AddressOfEntryPoint =
		bfd_get_start_address ( bfd );
	pe_header.nt.OptionalHeader.Subsystem = opts->subsystem;

	/* For each input section, build an output section and create
	 * the appropriate relocation records
	 */
	for ( section = bfd->sections ; section ; section = section->next ) {
		/* Discard non-allocatable sections */
		if ( ! ( bfd_get_section_flags ( bfd, section ) & SEC_ALLOC ) )
			continue;
		/* Create output section */
		*(next_pe_section) = process_section ( bfd, &pe_header,
						       section );
		next_pe_section = &(*next_pe_section)->next;
		/* Add relocations from this section */
		reltab = read_reltab ( bfd, symtab, section );
		for ( rel = reltab ; *rel ; rel++ )
			process_reloc ( bfd, section, *rel, &pe_reltab );
		free ( reltab );
	}

	/* Create the .reloc section */
	*(next_pe_section) = create_reloc_section ( &pe_header, pe_reltab );
	next_pe_section = &(*next_pe_section)->next;

	/* Create the .reloc section */
	*(next_pe_section) = create_debug_section ( &pe_header,
						    basename ( pe_name_tmp ) );
	next_pe_section = &(*next_pe_section)->next;

	/* Write out PE file */
	pe = fopen ( pe_name, "w" );
	if ( ! pe ) {
		eprintf ( "Could not open %s for writing: %s\n",
			  pe_name, strerror ( errno ) );
		exit ( 1 );
	}
	write_pe_file ( &pe_header, pe_sections, pe );
	fclose ( pe );

	/* Close BFD file */
	bfd_close ( bfd );
}

/**
 * Print help
 *
 * @v program_name	Program name
 */
static void print_help ( const char *program_name ) {
	eprintf ( "Syntax: %s [--subsystem=<number>] infile outfile\n",
		  program_name );
}

/**
 * Parse command-line options
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v opts		Options structure to populate
 */
static int parse_options ( const int argc, char **argv,
			   struct options *opts ) {
	char *end;
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{ "subsystem", required_argument, NULL, 's' },
			{ "help", 0, NULL, 'h' },
			{ 0, 0, 0, 0 }
		};

		if ( ( c = getopt_long ( argc, argv, "s:h",
					 long_options,
					 &option_index ) ) == -1 ) {
			break;
		}

		switch ( c ) {
		case 's':
			opts->subsystem = strtoul ( optarg, &end, 0 );
			if ( *end ) {
				eprintf ( "Invalid subsytem \"%s\"\n",
					  optarg );
				exit ( 2 );
			}
			break;
		case 'h':
			print_help ( argv[0] );
			exit ( 0 );
		case '?':
		default:
			exit ( 2 );
		}
	}
	return optind;
}

int main ( int argc, char **argv ) {
	struct options opts = {
		.subsystem = EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION,
	};
	int infile_index;
	const char *infile;
	const char *outfile;

	/* Initialise libbfd */
	bfd_init();

	/* Parse command-line arguments */
	infile_index = parse_options ( argc, argv, &opts );
	if ( argc != ( infile_index + 2 ) ) {
		print_help ( argv[0] );
		exit ( 2 );
	}
	infile = argv[infile_index];
	outfile = argv[infile_index + 1];

	/* Convert file */
	elf2pe ( infile, outfile, &opts );

	return 0;
}
