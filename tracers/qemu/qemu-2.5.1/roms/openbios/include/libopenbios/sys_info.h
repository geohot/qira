#ifndef SYS_INFO_H
#define SYS_INFO_H

/* Information collected from firmware/bootloader */

struct sys_info {
    /* Values passed by bootloader */
    unsigned long boot_type;
    unsigned long boot_data;
    unsigned long boot_arg;

    const char *firmware; /* "PCBIOS", "LinuxBIOS", etc. */
    const char *command_line; /* command line given to us */

    /* memory map */
    int n_memranges;
    struct memrange {
	unsigned long long base;
	unsigned long long size;
    } *memrange;
    unsigned long *dict_start;
    unsigned long *dict_end;
    cell dict_limit;
    ucell *dict_last;
};

extern void *elf_boot_notes;
extern struct sys_info sys_info;

void collect_elfboot_info(struct sys_info *info);
void collect_linuxbios_info(struct sys_info *info);

/* Our name and version. I want to see single instance of these in the image */
extern const char *program_name, *program_version;

#define LOADER_NOT_SUPPORT 0xbadf11e

#endif /* SYS_INFO_H */
