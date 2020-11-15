#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <ipxe/tables.h>

#define DEBUG 0

#define eprintf(...) fprintf ( stderr, __VA_ARGS__ )

#define dprintf(...) do {						\
	if ( DEBUG )							\
		fprintf ( stderr, __VA_ARGS__ );			\
	} while ( 0 )

#ifdef SELF_INCLUDED

/**
 * Fix up ICC alignments
 *
 * @v elf		ELF header
 * @ret rc		Return status code
 *
 * See comments in tables.h for an explanation of why this monstrosity
 * is necessary.
 */
static int ICCFIX ( void *elf ) {
	ELF_EHDR *ehdr = elf;
	ELF_SHDR *shdr = ( elf + ehdr->e_shoff );
	size_t shentsize = ehdr->e_shentsize;
	unsigned int shnum = ehdr->e_shnum;
	ELF_SHDR *strtab = ( ( ( void * ) shdr ) +
			     ( ehdr->e_shstrndx * shentsize ) );
	char *strings = ( elf + strtab->sh_offset );

	for ( ; shnum-- ; shdr = ( ( ( void * ) shdr ) + shentsize ) ) {
		char *name = ( strings + shdr->sh_name );
		unsigned long align = shdr->sh_addralign;
		unsigned long new_align;

		if ( ( strncmp ( name, ".tbl.", 5 ) == 0 ) &&
		     ( align >= ICC_ALIGN_HACK_FACTOR ) ) {
			new_align = ( align / ICC_ALIGN_HACK_FACTOR );
			shdr->sh_addralign = new_align;
			dprintf ( "Section \"%s\": alignment %ld->%ld\n",
				  name, align, new_align );
		}
	}
	return 0;
}

#else /* SELF_INCLUDED */

#define SELF_INCLUDED

/* Include iccfix32() function */
#define ELF_EHDR Elf32_Ehdr
#define ELF_SHDR Elf32_Shdr
#define ICCFIX iccfix32
#include "iccfix.c"
#undef ELF_EHDR
#undef ELF_SHDR
#undef ICCFIX

/* Include iccfix64() function */
#define ELF_EHDR Elf64_Ehdr
#define ELF_SHDR Elf64_Shdr
#define ICCFIX iccfix64
#include "iccfix.c"
#undef ELF_EHDR
#undef ELF_SHDR
#undef ICCFIX

static int iccfix ( const char *filename ) {
	int fd;
	struct stat stat;
	void *elf;
	unsigned char *eident;
	int rc;

	/* Open and mmap file */
	fd = open ( filename, O_RDWR );
	if ( fd < 0 ) {
		eprintf ( "Could not open %s: %s\n",
			  filename, strerror ( errno ) );
		rc = -1;
		goto err_open;
	}
	if ( fstat ( fd, &stat ) < 0 ) {
		eprintf ( "Could not determine size of %s: %s\n",
			  filename, strerror ( errno ) );
		rc = -1;
		goto err_fstat;
	}
	elf = mmap ( NULL, stat.st_size, ( PROT_READ | PROT_WRITE ),
		     MAP_SHARED, fd, 0 );
	if ( elf == MAP_FAILED ) {
		eprintf ( "Could not map %s: %s\n",
			  filename, strerror ( errno ) );
		rc = -1;
		goto err_mmap;
	}

	/* Perform fixups */
	eident = elf;
	switch ( eident[EI_CLASS] ) {
	case ELFCLASS32:
		rc = iccfix32 ( elf );
		break;
	case ELFCLASS64:
		rc = iccfix64 ( elf );
		break;
	default:
		eprintf ( "Unknown ELF class %d in %s\n",
			  eident[EI_CLASS], filename );
		rc = -1;
		break;
	}

	munmap ( elf, stat.st_size );
 err_mmap:
 err_fstat:
	close ( fd );
 err_open:
	return rc;
}

int main ( int argc, char **argv ) {
	int i;
	int rc;

	/* Parse command line */
	if ( argc < 2 ) {
		eprintf ( "Syntax: %s <object_file>...\n", argv[0] );
		exit ( 1 );
	}

	/* Process each object in turn */
	for ( i = 1 ; i < argc ; i++ ) {
		if ( ( rc = iccfix ( argv[i] ) ) != 0 ) {
			eprintf ( "Could not fix up %s\n", argv[i] );
			exit ( 1 );
		}
	}

	return 0;
}

#endif /* SELF_INCLUDED */
