/* tag: openbios loader prototypes for sparc32
 *
 * Copyright (C) 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

// linux_load.c
int linux_load(struct sys_info *info, const char *file, const char *cmdline);

// context.c
extern struct context *__context;
unsigned int start_elf(unsigned long entry_point, unsigned long param);

// boot.c
extern const char *bootpath;
extern void boot(void);
extern void go(void);

// sys_info.c
extern unsigned int qemu_mem_size;
extern void collect_sys_info(struct sys_info *info);

// romvec.c
extern struct linux_arguments_v0 obp_arg;
extern const void *romvec;
extern const char *obp_stdin_path, *obp_stdout_path;
extern char obp_stdin, obp_stdout;

// openbios.c
extern int qemu_machine_type;

// arch/sparc32/lib.c
struct linux_mlist_v0;
extern struct linux_mlist_v0 *ptphys;
extern struct linux_mlist_v0 *ptmap;
extern struct linux_mlist_v0 *ptavail;

void ob_init_mmu(void);
void init_mmu_swift(void);
