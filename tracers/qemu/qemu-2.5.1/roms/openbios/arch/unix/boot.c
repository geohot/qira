/*
 *
 */
#undef BOOTSTRAP
#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/elf_load.h"
#include "arch/common/nvram.h"
#include "libc/diskio.h"

void boot(void);
void *load_elf(char *spec);

void
*load_elf(char *spec)
{
#if 0
	int fd;
	void *entry=NULL;
	int i, lszz_offs, elf_offs;
	char buf[128]; // , *addr;
	Elf_ehdr ehdr;
	Elf_phdr *phdr;
	size_t s;

	if( (fd=open_io(spec)) == -1 )
		return NULL;

	if( (elf_offs=find_elf(fd)) < 0 ) {
		printk("----> %s is not an ELF image\n", buf );
		return NULL;
	}

	if( !(phdr=elf_readhdrs(fd, 0, &ehdr)) ) {
		printk("elf32_readhdrs failed\n");
		return NULL;
	}

	(unsigned long long *)entry = ehdr.e_entry;

	lszz_offs = elf_offs;
	for( i=0; i<ehdr.e_phnum; i++ ) {
		s = MIN( phdr[i].p_filesz, phdr[i].p_memsz );
		seek_io( fd, elf_offs + phdr[i].p_offset );
		/* printk("filesz: %08lX memsz: %08lX p_offset: %08lX p_vaddr %08lX\n",
		   phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_offset,
		   phdr[i].p_vaddr ); */
		if( phdr[i].p_vaddr != phdr[i].p_paddr )
			printk("WARNING: ELF segment virtual addr != physical addr\n");
		lszz_offs = MAX( lszz_offs, elf_offs + phdr[i].p_offset + phdr[i].p_filesz );
		if( !s )
			continue;

		 printk("ELF ROM-section loaded at %08lX (size %08lX)\n",
				 (unsigned long)phdr[i].p_vaddr, (unsigned long)phdr[i].p_memsz);
	}
	free( phdr );
	return entry;
#else
	return NULL;
#endif
}

void
boot( void )
{
	char *path;
	void *entry;

        /* Copy the incoming path */
        fword("2dup");
        path = pop_fstr_copy();

	if(!path) {
		printk("[unix] Booting default not supported.\n");
		return;
	}
	printk("[unix] Booting '%s'\n",path);
	entry=load_elf(path);
	if(entry)
                printk("successfully loaded client at %llx.\n", (unsigned long long)(ucell)entry);
	else
		printk("failed.\n");
}
