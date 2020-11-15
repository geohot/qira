#ifndef _MULTIBOOT_H
#define _MULTIBOOT_H

/**
 * @file
 *
 * Multiboot operating systems
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/** The magic number for the Multiboot header */
#define MULTIBOOT_HEADER_MAGIC 0x1BADB002

/** Boot modules must be page aligned */
#define MB_FLAG_PGALIGN 0x00000001

/** Memory map must be provided */
#define MB_FLAG_MEMMAP 0x00000002

/** Video mode information must be provided */
#define MB_FLAG_VIDMODE 0x00000004

/** Image is a raw multiboot image (not ELF) */
#define MB_FLAG_RAW 0x00010000

/**
 * The magic number passed by a Multiboot-compliant boot loader
 *
 * Must be passed in register %eax when jumping to the Multiboot OS
 * image.
 */
#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

/** Multiboot information structure mem_* fields are valid */
#define MBI_FLAG_MEM 0x00000001

/** Multiboot information structure boot_device field is valid */
#define MBI_FLAG_BOOTDEV 0x00000002

/** Multiboot information structure cmdline field is valid */
#define MBI_FLAG_CMDLINE 0x00000004

/** Multiboot information structure module fields are valid */
#define MBI_FLAG_MODS 0x00000008

/** Multiboot information structure a.out symbol table is valid */
#define MBI_FLAG_AOUT 0x00000010

/** Multiboot information struture ELF section header table is valid */
#define MBI_FLAG_ELF 0x00000020

/** Multiboot information structure memory map is valid */
#define MBI_FLAG_MMAP 0x00000040

/** Multiboot information structure drive list is valid */
#define MBI_FLAG_DRIVES 0x00000080

/** Multiboot information structure ROM configuration field is valid */
#define MBI_FLAG_CFGTBL 0x00000100

/** Multiboot information structure boot loader name field is valid */
#define MBI_FLAG_LOADER 0x00000200

/** Multiboot information structure APM table is valid */
#define MBI_FLAG_APM 0x00000400

/** Multiboot information structure video information is valid */
#define MBI_FLAG_VBE 0x00000800

/** A multiboot header */
struct multiboot_header {
	uint32_t magic;
	uint32_t flags;
	uint32_t checksum;
	uint32_t header_addr;
	uint32_t load_addr;
	uint32_t load_end_addr;
	uint32_t bss_end_addr;
	uint32_t entry_addr;
} __attribute__ (( packed, may_alias ));

/** A multiboot a.out symbol table */
struct multiboot_aout_symbol_table {
	uint32_t tabsize;
	uint32_t strsize;
	uint32_t addr;
	uint32_t reserved;
} __attribute__ (( packed, may_alias ));

/** A multiboot ELF section header table */
struct multiboot_elf_section_header_table {
	uint32_t num;
	uint32_t size;
	uint32_t addr;
	uint32_t shndx;
} __attribute__ (( packed, may_alias ));

/** A multiboot information structure */
struct multiboot_info {
	uint32_t flags;
	uint32_t mem_lower;
	uint32_t mem_upper;
	uint32_t boot_device;
	uint32_t cmdline;
	uint32_t mods_count;
	uint32_t mods_addr;
	union {
		struct multiboot_aout_symbol_table aout_syms;
		struct multiboot_elf_section_header_table elf_sections;
	} syms;
	uint32_t mmap_length;
	uint32_t mmap_addr;
	uint32_t drives_length;
	uint32_t drives_addr;
	uint32_t config_table;
	uint32_t boot_loader_name;
	uint32_t apm_table;
	uint32_t vbe_control_info;
	uint32_t vbe_mode_info;
	uint16_t vbe_mode;
	uint16_t vbe_interface_seg;
	uint16_t vbe_interface_off;
	uint16_t vbe_interface_len;
} __attribute__ (( packed, may_alias ));

/** A multiboot module structure */
struct multiboot_module {
	uint32_t mod_start;
	uint32_t mod_end;
	uint32_t string;
	uint32_t reserved;
} __attribute__ (( packed, may_alias ));

/** A multiboot memory map entry */
struct multiboot_memory_map {
	uint32_t size;
	uint64_t base_addr;
	uint64_t length;
	uint32_t type;
} __attribute__ (( packed, may_alias ));

/** Usable RAM */
#define MBMEM_RAM 1

#endif /* _MULTIBOOT_H */
