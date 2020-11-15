/* multiboot.h
 * tag: header for multiboot
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

/* magic number for multiboot header */
#define MULTIBOOT_HEADER_MAGIC		0x1BADB002

/* flags for multiboot header */
#define MULTIBOOT_HEADER_FLAGS		0x00010003

/* magic number passed by multiboot-compliant boot loader.  */
#define MULTIBOOT_BOOTLOADER_MAGIC	0x2BADB002

/* The size of our stack (8KB).  */
#define STACK_SIZE			0x2000

/* C symbol format. HAVE_ASM_USCORE is defined by configure.  */
#ifdef HAVE_ASM_USCORE
# define EXT_C(sym)			_ ## sym
#else
# define EXT_C(sym)			sym
#endif

#ifndef ASM
/* We don't want these declarations in boot.S  */

/* multiboot header */
typedef struct multiboot_header {
	unsigned long magic;
	unsigned long flags;
	unsigned long checksum;
	unsigned long header_addr;
	unsigned long load_addr;
	unsigned long load_end_addr;
	unsigned long bss_end_addr;
	unsigned long entry_addr;
} multiboot_header_t;

/* symbol table for a.out */
typedef struct aout_symbol_table {
	unsigned long tabsize;
	unsigned long strsize;
	unsigned long addr;
	unsigned long reserved;
} aout_symbol_table_t;

/* section header table for ELF */
typedef struct elf_section_header_table {
	unsigned long num;
	unsigned long size;
	unsigned long addr;
	unsigned long shndx;
} elf_section_header_table_t;

/* multiboot information */
typedef struct multiboot_info {
	unsigned long flags;
	unsigned long mem_lower;
	unsigned long mem_upper;
	unsigned long boot_device;
	unsigned long cmdline;
	unsigned long mods_count;
	unsigned long mods_addr;
	union {
		aout_symbol_table_t aout_sym;
		elf_section_header_table_t elf_sec;
	} u;
	unsigned long mmap_length;
	unsigned long mmap_addr;
} multiboot_info_t;

/* module structure */
typedef struct module {
	unsigned long mod_start;
	unsigned long mod_end;
	unsigned long string;
	unsigned long reserved;
} module_t;

/* memory map. Be careful that the offset 0 is base_addr_low
   but no size.  */
typedef struct memory_map {
	unsigned long size;
	unsigned long base_addr_low;
	unsigned long base_addr_high;
	unsigned long length_low;
	unsigned long length_high;
	unsigned long type;
} memory_map_t;

#endif				/* ! ASM */
