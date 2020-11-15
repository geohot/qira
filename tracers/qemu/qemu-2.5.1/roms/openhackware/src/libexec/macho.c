/*
 * <macho.c>
 *
 * Open Hack'Ware BIOS MACH-O executable file loader
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"
#include "exec.h"

/* MACH-O executable loader */
/* FAT definitions */
/* CPU type definitions */
typedef enum cpu_type_t {
    CPU_TYPE_ANY     = -1,
    CPU_TYPE_VAX     = 1,
    CPU_TYPE_MC680x0 = 6,
    CPU_TYPE_I386    = 7,
    CPU_TYPE_MIPS    = 8,
    CPU_TYPE_MC98000 = 10,
    CPU_TYPE_HPPA    = 11,
    CPU_TYPE_ARM     = 12,
    CPU_TYPE_MC88000 = 13,
    CPU_TYPE_SPARC   = 14,
    CPU_TYPE_I860    = 15,
    CPU_TYPE_ALPHA   = 16,
    CPU_TYPE_POWERPC = 18,
} cpu_type_t;

/* Any CPU */
typedef enum cpu_subtype_any_t {
    CPU_SUBTYPE_MULTIPLE      = -1,
    CPU_SUBTYPE_LITTLE_ENDIAN = 0,
    CPU_SUBTYPE_BIG_ENDIAN    = 1,
} cpu_subtype_any_t;

/* PowerPC */
typedef enum cpu_subtype_ppc_t {
    CPU_SUBTYPE_PPC_ALL   = 0,
    CPU_SUBTYPE_PPC_601   = 1,
    CPU_SUBTYPE_PPC_602   = 2,
    CPU_SUBTYPE_PPC_603   = 3,
    CPU_SUBTYPE_PPC_603e  = 4,
    CPU_SUBTYPE_PPC_603ev = 5,
    CPU_SUBTYPE_PPC_604   = 6,
    CPU_SUBTYPE_PPC_604e  = 7,
    CPU_SUBTYPE_PPC_620   = 8,
    CPU_SUBTYPE_PPC_750   = 9,
    CPU_SUBTYPE_PPC_7400  = 10,
    CPU_SUBTYPE_PPC_7450  = 11,
} cpu_subtype_ppc_t;

/* Fat header definition */
#define FAT_MAGIC 0xCAFEBABE

typedef struct fat_head_t {
    uint32_t magic;
    uint32_t nfat_arch;
} fat_head_t;

typedef struct fat_arch_t {
    cpu_type_t    cpu_type;
    cpu_subtype_ppc_t cpu_subtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} fat_arch_t;

/* Mach-O binary definitions */
#define MACH_O_MAGIC 0xFEEDFACE

typedef enum filetype_t {
    MH_OBJECT     = 0x1,
    MH_EXECUTE    = 0x2,
    MH_FVMLIB     = 0x3,
    MH_CORE       = 0x4,
    MH_PRELOAD    = 0x5,
    MH_DYLIB      = 0x6,
    MH_DYLINKER   = 0x7,
    MH_BUNDLE     = 0x8,
} filetype_t;

enum {
    MH_NOUNDEFS   = 0x01,
    MH_INCRLINK   = 0x02,
    MH_DYLDLINK   = 0x04,
    MH_BINDATLOAD = 0x08,
    MH_PREBOUND   = 0x10,
};

typedef struct mach_head_t {
    uint32_t magic;
    cpu_type_t cpu_type;
    cpu_subtype_ppc_t subtype;
    filetype_t file_type;
    uint32_t nb_cmds;
    uint32_t cmds_size;
    uint32_t flags;
} mach_head_t;

typedef enum load_cmd_t {
    LC_SEGMENT        = 0x01,
    LC_SYMTAB         = 0x02,
    LC_SYMSEG         = 0x03,
    LC_THREAD         = 0x04,
    LC_UNIXTHREAD     = 0x05,
    LC_LOADFVMLIB     = 0x06,
    LC_IDFVMLIB       = 0x07,
    LC_IDENT          = 0x08,
    LC_FVMFILE        = 0x09,
    LC_PREPAGE        = 0x0A,
    LC_DYSYMTAB       = 0x0B,
    LC_LOAD_DYLIB     = 0x0C,
    LC_ID_DYLIB       = 0x0D,
    LC_LOAD_DYLINKER  = 0x0E,
    LC_ID_DYLINKER    = 0x0F,
    LC_PREBOUND_DYLIB = 0x10,
    LC_0x17           = 0x17,
} load_cmd_t;

typedef struct mach_load_cmd_t {
    load_cmd_t cmd;
    uint32_t cmd_size;
} mach_load_cmd_t;

typedef struct mach_string_t {
    uint32_t offset;
} mach_string_t;

enum {
    SG_HIGHVM  = 0x1,
    SG_FVMLIB  = 0x2,
    SG_NORELOC = 0x4,
};

typedef struct mach_segment_t {
    unsigned char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t file_offset;
    uint32_t file_size;
    uint32_t max_prot;
    uint32_t init_prot;
    uint32_t nsects;
    uint32_t flags;
} mach_segment_t;

enum {
    SECTION_TYPE               = 0xFF,
    S_REGULAR                  = 0x0,
    S_ZEROFILL                 = 0x1,
    S_CSTRING_LITERALS         = 0x2,
    S_4BYTE_LITERALS           = 0x3,
    S_8BYTE_LITERALS           = 0x4,
    S_LITERAL_POINTERS         = 0x5,
    S_NON_LAZY_SYMBOL_POINTERS = 0x6,
    S_LAZY_SYMBOL_POINTERS     = 0x7,
    S_SYMBOL_STUBS             = 0x8,
    S_MOD_INIT_FUNC_POINTERS   = 0x9,
};

enum {
    S_ATTR_PURE_INSTRUCTIONS   = 0x80000000,
    S_ATTR_SOME_INSTRUCTIONS   = 0x00000400,
    S_ATTR_EXT_RELOC           = 0x00000200,
    S_ATTR_LOC_RELOC           = 0x00000100,
};

typedef struct mach_section_t {
    unsigned char sectname[16];
    unsigned char segname[16];
    uint32_t vmaddr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloc_offset;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t res1;
    uint32_t res2;
} mach_section_t;

typedef struct mach_symtab_t {
    uint32_t offset;
    uint32_t nsyms;
    uint32_t str_offset;
    uint32_t str_size;
} mach_symtab_t;

typedef struct mach_symseg_t {
    uint32_t offset;
    uint32_t size;
} mach_symseg_t;

typedef struct mach_unixth_t {
    uint32_t flavor;
    uint32_t count;
    /* This is supposed to be a stack.
     * Let's assume it's less than 1kB (arbitrary !)
     */
    uint32_t data[256];
} mach_unixth_t;

typedef struct mach_fvmlib_t {
    uint32_t str_offset;
    uint32_t minor_version;
    uint32_t header_addr;
} mach_fvmlib_t;

typedef struct mach_fvmfile_t {
    uint32_t str_offset;
    uint32_t vmaddr;
} mach_fvmfile_t;

typedef struct mach_dysymtab_t {
    uint32_t ilocal_syms;
    uint32_t nlocal_syms;
    uint32_t iext_syms;
    uint32_t next_syms;
    uint32_t iundef_syms;
    uint32_t nundef_syms;
    uint32_t toc_offset;
    uint32_t ntoc;
    uint32_t modtab_offset;
    uint32_t nmodtab;
    uint32_t extsym_offset;
    uint32_t nextsym;
    uint32_t indirect_offset;
    uint32_t nindirect;
    uint32_t ext_reloc_offset;
    uint32_t next_reloc;
    uint32_t local_reloc_offset;
    uint32_t nlocal_reloc;
} mach_dysymtab_t;

typedef struct mach_dylib_t {
    uint32_t str_offset;
    uint32_t timestamp;
    uint32_t cur_version;
    uint32_t compat_version;
} mach_dylib_t;

typedef struct mach_prebound_t {
    uint32_t str_offset;
    uint32_t nb_modules;
    unsigned char linked_modules[256];
} mach_prebound_t;

int exec_load_macho (inode_t *file, void **dest, void **entry, void **end,
                     uint32_t loffset)
{
    mach_head_t mhdr;
    mach_load_cmd_t lcmd;
    fat_head_t fhdr;
    fat_arch_t fahdr;
    void *address, *first, *last;
    uint32_t k, j, best, offset;
    int entry_set;

    /* Probe FAT */
    file_seek(file, loffset);
    if (fs_read(file, &fhdr, sizeof(fat_head_t)) < 0) {
        ERROR("Cannot load fat header...\n");
        return -1;
    }
    fhdr.magic = get_be32(&fhdr.magic);
    if (fhdr.magic != FAT_MAGIC)
        goto macho_probe;
    fhdr.nfat_arch = get_be32(&fhdr.nfat_arch);
    DPRINTF("FAT file: %d archs\n", fhdr.nfat_arch);
    /* Find the best architecture */
    best = -1;
    offset = 0;
    for (k = 0; k < fhdr.nfat_arch; k++) {
        if (fs_read(file, &fahdr, sizeof(fat_arch_t)) < 0) {
            ERROR("Cannot load fat arch header\n");
            return -1;
        }
        fahdr.cpu_type = get_be32(&fahdr.cpu_type);
        if (fahdr.cpu_type != CPU_TYPE_POWERPC)
            continue;
        fahdr.cpu_subtype = get_be32(&fahdr.cpu_subtype);
        fahdr.offset = get_be32(&fahdr.offset);
        fahdr.size = get_be32(&fahdr.size);
        fahdr.align = get_be32(&fahdr.align);
        switch (fahdr.cpu_subtype) {
        case CPU_SUBTYPE_PPC_750:
            best = k;
            offset = fahdr.offset;
            goto fat_cpu_ok;
        case CPU_SUBTYPE_PPC_ALL:
            if (best == (uint32_t)-1) {
                offset = fahdr.offset;
                best = k;
            }
            break;
        case CPU_SUBTYPE_PPC_603:
        case CPU_SUBTYPE_PPC_603e:
        case CPU_SUBTYPE_PPC_603ev:
        case CPU_SUBTYPE_PPC_604:
        case CPU_SUBTYPE_PPC_604e:
            best = k;
            offset = fahdr.offset;
            break;
        default:
            break;
        }
    }
    if (best == (uint32_t)-1) {
        ERROR("No matching PPC FAT arch\n");
        return -1;
    }
    DPRINTF("Use FAT arch %d at %08x %08x\n", best, offset, loffset);
 fat_cpu_ok:
    loffset += offset;

    /* Probe macho */
 macho_probe:
    file_seek(file, loffset);
    if (fs_read(file, &mhdr, sizeof(mach_head_t)) < 0) {
        ERROR("Cannot load MACH-O header...\n");
        return -1;
    }
    mhdr.magic = get_be32(&mhdr.magic);
    if (mhdr.magic != MACH_O_MAGIC) {
        ERROR("Not a MACH-O file\n");
        return -2;
    }
    mhdr.cpu_type = get_be32(&mhdr.cpu_type);
    mhdr.subtype = get_be32(&mhdr.subtype);
    mhdr.file_type = get_be32(&mhdr.file_type);
    mhdr.nb_cmds = get_be32(&mhdr.nb_cmds);
    mhdr.cmds_size = get_be32(&mhdr.cmds_size);
    mhdr.flags = get_be32(&mhdr.flags);
    DPRINTF("MACHO-O file cpu %d %d file type %08x %d cmds size %08x flags "
            "%08x\n", mhdr.cpu_type, mhdr.subtype, mhdr.file_type,
            mhdr.nb_cmds, mhdr.cmds_size, mhdr.flags);
    offset = sizeof(mach_head_t);
    first = (void *)-1;
    last = NULL;
    entry_set = 0;
    for (k = 0; k < mhdr.nb_cmds; k++) {
        file_seek(file, loffset + offset);
        if (fs_read(file, &lcmd, sizeof(mach_load_cmd_t)) < 0) {
            ERROR("Unable to load MACH-O cmd %d\n", k);
            return -1;
        }
        lcmd.cmd = get_be32(&lcmd.cmd);
        lcmd.cmd_size = get_be32(&lcmd.cmd_size);
        DPRINTF("Cmd %d : %08x size %08x (%08x %08x)\n", k, lcmd.cmd,
                lcmd.cmd_size, offset, offset + loffset);
        switch (lcmd.cmd) {
        case LC_SEGMENT:
            /* To be loaded for execution */
            {
                mach_segment_t segment;
                mach_section_t section;
                uint32_t pos;
                
                pos = offset + sizeof(mach_load_cmd_t);
                if (fs_read(file, &segment, sizeof(mach_segment_t)) < 0) {
                    ERROR("Cannot load MACH-O segment\n");
                    return -1;
                }
                pos += sizeof(mach_segment_t);
                segment.vmaddr = get_be32(&segment.vmaddr);
                segment.vmsize = get_be32(&segment.vmsize);
                segment.file_offset = get_be32(&segment.file_offset);
                segment.file_size = get_be32(&segment.file_size);
                segment.max_prot = get_be32(&segment.max_prot);
                segment.init_prot = get_be32(&segment.init_prot);
                segment.nsects = get_be32(&segment.nsects);
                segment.flags = get_be32(&segment.flags);
                DPRINTF("MACH-O segment addr %08x size %08x off %08x fsize "
                        "%08x ns %d fl %08x\n", segment.vmaddr, segment.vmsize,
                        segment.file_offset, segment.file_size,
                        segment.nsects, segment.flags);
                for (j = 0; j < segment.nsects; j++) {
                    file_seek(file, loffset + pos);
                    if (fs_read(file, &section, sizeof(mach_section_t)) < 0) {
                        ERROR("Cannot load MACH-O section\n");
                        return -1;
                    }
                    pos += sizeof(mach_section_t);
                    section.vmaddr = get_be32(&section.vmaddr);
                    section.size = get_be32(&section.size);
                    section.offset = get_be32(&section.offset);
                    section.align = get_be32(&section.align);
                    section.reloc_offset = get_be32(&section.reloc_offset);
                    section.nreloc = get_be32(&section.nreloc);
                    section.flags = get_be32(&section.flags);
                    section.res1 = get_be32(&section.res1);
                    section.res2 = get_be32(&section.res2);
                    DPRINTF("MACH-O section vmaddr %08x size %08x off %08x "
                            "flags %08x\n", section.vmaddr, section.size,
                            section.offset, section.flags);
                    switch (section.flags & SECTION_TYPE) {
                    case S_REGULAR:
                    case S_CSTRING_LITERALS:
                    case S_4BYTE_LITERALS:
                    case S_8BYTE_LITERALS:
                    case S_LITERAL_POINTERS:
                    case S_NON_LAZY_SYMBOL_POINTERS:
                    case S_LAZY_SYMBOL_POINTERS:
                    case S_SYMBOL_STUBS:
                    case S_MOD_INIT_FUNC_POINTERS:
                        DPRINTF("Load section of type %d from %08x to %08x"
                                " %08x\n", section.flags, section.offset,
                                section.vmaddr, section.size);
                        file_seek(file, section.offset + loffset);
                        address = (void *)section.vmaddr;
                        if (address < first && address != NULL)
                            first = address;
                        if (address + section.size > last)
                            last = address + section.size;
                        if (fs_read(file, address, section.size) < 0) {
                            ERROR("Cannot load MACH-O section %d %d...\n",
                                  k, j);
                            return -1;
                        }
                        break;
                    case S_ZEROFILL:
                        DPRINTF("Fill zero section to %08x %08x\n",
                                section.vmaddr, section.size);
                        address = (void *)section.vmaddr;
                        if (address < first && address != NULL)
                            first = address;
                        if (address + section.size > last)
                            last = address + section.size;
                        memset(address, 0, section.size);
                        break;
                    default:
                        ERROR("Unknown MACH-O section type: %d\n",
                              section.flags);
                        return -1;
                    }
                }
            }
            break;
        case LC_SYMTAB:
            /* Don't care */
            break;
        case LC_SYMSEG:
            /* Don't care */
            break;
        case LC_UNIXTHREAD:
            /* To be loaded for execution */
            {
                mach_unixth_t unixth;

                if (fs_read(file, &unixth, sizeof(mach_unixth_t)) < 0) {
                    ERROR("Cannot load MACH-O UNIX thread\n");
                    return -1;
                }
                DPRINTF("Set entry point to %08x\n", unixth.data[0]);
                *entry = (void *)unixth.data[0];
                entry_set = 1;
            }
            break;
        case LC_THREAD:
            break;
        case LC_LOADFVMLIB:
            break;
        case LC_IDFVMLIB:
            break;
        case LC_IDENT:
            break;
        case LC_FVMFILE:
            break;
        case LC_PREPAGE:
            printf("Prepage command\n");
            break;
        case LC_DYSYMTAB:
            break;
        case LC_LOAD_DYLIB:
            break;
        case LC_ID_DYLIB:
            break;
        case LC_LOAD_DYLINKER:
            /* To be loaded for execution */
            break;
        case LC_ID_DYLINKER:
            break;
        case LC_PREBOUND_DYLIB:
            break;
        case LC_0x17:
            /* ? */
            break;
        default:
            printf("unknown MACH-O command (%d %d)\n", k, lcmd.cmd);
            return -1;
        }
        offset += lcmd.cmd_size;
    }
    *dest = first;
    *end = last;
    //    if (entry_set == 0)
        *entry = *dest;

    return 0;
}
