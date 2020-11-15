#define ARCH_ELF_CLASS ELFCLASS64
#define ARCH_ELF_DATA ELFDATA2LSB
#define ARCH_ELF_MACHINE_OK(x) ((x)==EM_IA64)
typedef Elf64_Ehdr Elf_ehdr;
typedef Elf64_Phdr Elf_phdr;
