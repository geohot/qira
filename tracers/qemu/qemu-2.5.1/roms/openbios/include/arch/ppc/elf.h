#define ARCH_ELF_CLASS ELFCLASS32
#define ARCH_ELF_DATA ELFDATA2MSB
#define ARCH_ELF_MACHINE_OK(x) ((x)==EM_PPC)
typedef Elf32_Ehdr Elf_ehdr;
typedef Elf32_Phdr Elf_phdr;
