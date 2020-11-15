#define ARCH_ELF_CLASS ELFCLASS64
#define ARCH_ELF_DATA ELFDATA2MSB
#define ARCH_ELF_MACHINE_OK(x) ((x)==EM_SPARCV9)
typedef Elf64_Ehdr Elf_ehdr;
typedef Elf64_Phdr Elf_phdr;
