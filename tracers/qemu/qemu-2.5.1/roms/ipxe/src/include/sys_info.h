#ifndef SYS_INFO_H
#define SYS_INFO_H

/* Information collected from firmware/bootloader */

struct sys_info {
    /* Values passed by bootloader */
    unsigned long boot_type;
    unsigned long boot_data;
    unsigned long boot_arg;

    char *firmware; /* "PCBIOS", "LinuxBIOS", etc. */
    char *command_line; /* command line given to us */
#if 0
//By LYH
//Will use meminfo in Etherboot 
    /* memory map */
    int n_memranges;
    struct memrange {
	unsigned long long base;
	unsigned long long size;
    } *memrange;
#endif
};

void collect_sys_info(struct sys_info *info);
void collect_elfboot_info(struct sys_info *info);
void collect_linuxbios_info(struct sys_info *info);

/* Our name and version. I want to see single instance of these in the image */
extern const char *program_name, *program_version;

#endif /* SYS_INFO_H */
