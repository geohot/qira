#define ARCH_ELF_CLASS ELFCLASS32
#define ARCH_ELF_DATA ELFDATA2LSB
#define ARCH_ELF_MACHINE_OK(x) ((x)==EM_386 || (x)==EM_486)
typedef Elf32_Ehdr Elf_ehdr;
typedef Elf32_Phdr Elf_phdr;
