/*
 * <pef.c>
 *
 * Open Hack'Ware BIOS Classic MacOS executable file loader
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

/* PEF (old MacOS executable format) */
typedef struct PEF_container_t PEF_container_t;
struct PEF_container_t {
    uint32_t tag1;
    uint32_t tag2;
    uint32_t arch;
    uint32_t version;
    uint32_t timestamp;
    uint32_t oldDefVersion;
    uint32_t oldImpVersion;
    uint32_t currentVersion;
    uint16_t nb_sections;
    uint16_t nb_inst_sections;
    uint32_t pad;
} __attribute__ (( packed ));

typedef struct PEF_section_t PEF_section_t;
struct PEF_section_t {
    int32_t name_offset;
    uint32_t address;
    uint32_t total_size;
    uint32_t unpacked_size;
    uint32_t packed_size;
    uint32_t container_offset;
    uint8_t  section_kind;
    uint8_t  share_kind;
    uint8_t  align;
    uint8_t  pad;
} __attribute__ (( packed ));

typedef struct PEF_loader_t PEF_loader_t;
struct PEF_loader_t {
    int32_t  main_section;
    uint32_t main_offset;
    int32_t  init_section;
    uint32_t init_offset;
    int32_t  term_section;
    uint32_t term_offset;
    uint32_t nb_import_libs;
    uint32_t nb_import_symbols;
    uint32_t nb_reloc_sections;
    uint32_t reloc_instr_offset;
    uint32_t loader_strings_offset;
    uint32_t export_hash_offset;
    uint32_t export_hashtable_power;
    uint32_t nb_export_symbols;
} __attribute__ (( packed ));

enum {
    PEF_SECTION_CODE     = 0,
    PEF_SECTION_UNPDATA  = 1,
    PEF_SECTION_INIDATA  = 2,
    PEF_SECTION_CONSTANT = 3,
    PEF_SECTION_LOADER   = 4,
    PEF_SECTION_DEBUG    = 5,
    PEF_SECTION_EXEC     = 6,
    PEF_SECTION_EXCP     = 7,
    PEF_SECTION_TRACE    = 8,
};

enum {
    PEF_SHARE_PROCESS    = 1,
    PEF_SHARE_GLOBAL     = 4,
    PEF_SHARE_PROTECTED  = 5,
};

int exec_load_pef (inode_t *file, void **dest, void **entry, void **end,
                   uint32_t loffset)
{
    PEF_container_t container;
    PEF_section_t section;
    PEF_loader_t loader;
    void *first, *last, *addr, **sections;
    uint32_t pos, padsize, size, lpos, main_offset;
    uint8_t opcode;
    int nb_sections, nb_inst_sections, main_section, i, n;

    file_seek(file, loffset);
    if (fs_read(file, &container, sizeof(PEF_container_t)) < 0) {
        ERROR("Cannot load container header\n");
        return -1;
    }
    pos = sizeof(PEF_container_t);
    /* Check tags and architecture */
    if (memcmp(&container.tag1, "Joy!", 4) != 0) {
        DPRINTF("No joy, no PEF\n");
        return -2;
    }
    if (memcmp(&container.tag2, "peff", 4) != 0) {
        DPRINTF("No PEFF file\n");
        return -2;
    }
    if (memcmp(&container.arch, "pwpc", 4) != 0) {
        DPRINTF("PEFF file not for PPC\n");
        return -2;
    }
    if (get_be32(&container.version) != 1) {
        DPRINTF("Unknown PEFF container version\n");
        return -2;
    }
    nb_sections = get_be32(&container.nb_sections);
    sections = malloc(nb_sections * sizeof(void *));
    if (sections == NULL) {
        ERROR("Cannot allocate sections\n");
        return -1;
    }
    nb_inst_sections = get_be32(&container.nb_inst_sections);
    first = (void *)0xFFFFFFFF;
    last = NULL;
    main_section = -1;
    main_offset = 0;
    for (i = 0, n = 0; i < nb_sections; i++) {
        file_seek(file, loffset + pos);
        if (fs_read(file, &section, sizeof(PEF_section_t)) < 0) {
            ERROR("Cannot read section %d\n", i);
            return -1;
        }
        pos += sizeof(PEF_section_t);
        addr = (void *)get_be32(&section.address);
        sections[i] = addr;
        if (addr < first)
            first = addr;
        size = get_be32(&section.total_size);
        lpos = get_be32(&section.container_offset);
        file_seek(file, loffset + lpos);
        switch (section.section_kind) {
        case PEF_SECTION_CODE:
        case PEF_SECTION_UNPDATA:
            /* Load as raw data */
            padsize = get_be32(&section.unpacked_size) - size;
            file_seek(file, loffset + lpos);
            if (fs_read(file, addr, size) < 0) {
                ERROR("Cannot load section %d\n", i);
                return -1;
            }
            addr = (char *)addr + size;
            memset(addr, 0, padsize);
            addr = (char *)addr + padsize;
            break;
        case PEF_SECTION_INIDATA:
        case PEF_SECTION_CONSTANT:
        case PEF_SECTION_EXEC:
            /* Load as compressed data */
            for (;;) {
                void *ref;
                uint32_t total;
                uint8_t bsize, csize, count, j;

                if (fs_read(file, &opcode, 1) < 0) {
                    ERROR("Cannot get opcode\n");
                    return -1;
                }
                bsize = opcode & 0x1F;
                switch (opcode >> 5) {
                case 0x0:
                    /* Initialize size bytes to zero */
                    memset(addr, 0, bsize);
                    addr = (char *)addr + bsize;
                    total = bsize;
                    break;
                case 0x1:
                    /* Copy bloc */
                    if (fs_read(file, addr, bsize) < 0) {
                        ERROR("Cannot copy bloc\n");
                        return -1;
                    }
                    addr = (char *)addr + bsize;
                    total = bsize;
                    break;
                case 0x2:
                    /* Repeat bloc */
                    if (fs_read(file, &count, 1) < 0) {
                        ERROR("Cannot read bloc size\n");
                        return -1;
                    }
                    total = 0;
                    if (count == 0) {
                        break;
                    }
                    if (fs_read(file, addr, bsize) < 0) {
                        ERROR("Cannot read repeat bloc\n");
                        return -1;
                    }
                    ref = addr;
                    addr = (char *)addr + bsize;
                    for (j = 1; j < count; j++) {
                        memcpy(addr, ref, bsize);
                        total += bsize;
                        addr = (char *)addr + bsize;
                    }
                    break;
                case 0x3:
                    /* Interleave repeat bloc with bloc copy */
                    if (fs_read(file, &csize, 1) < 0 ||
                        fs_read(file, &count, 1) < 0) {
                        ERROR("Cannot read repeat params\n");
                        return -1;
                    }
                    ref = addr;
                    if (fs_read(file, addr, bsize) < 0) {
                        ERROR("Cannot read common data\n");
                        return -1;
                    }
                    addr = (char *)addr + bsize;
                    total = bsize;
                    for (j = 0; j < count; j++) {
                        if (fs_read(file, addr, csize) < 0) {
                            ERROR("Cannot read custom data\n");
                            return -1;
                        }
                        addr = (char *)addr + csize;
                        memcpy(addr, ref, bsize);
                        addr = (char *)addr + bsize;
                        total += csize + bsize;
                    }
                    break;
                case 0x4:
                    /* Interleave repeat bloc with zero */
                    if (fs_read(file, &csize, 1) < 0 ||
                        fs_read(file, &count, 1) < 0) {
                        ERROR("Cannot read repeat params\n");
                        return -1;
                    }
                    total = 0;
                    for (j = 0; j < count; j++) {
                        memset(addr, 0, bsize);
                        addr = (char *)addr + bsize;
                        if (fs_read(file, addr, csize) < 0) {
                            ERROR("Cannot read repeat data\n");
                            return -1;
                        }
                        addr = (char *)addr + csize;
                        total += csize + bsize;
                    }
                    memset(addr, 0, bsize);
                    addr = (char *)addr + bsize;
                    total += bsize;
                    break;
                default:
                    ERROR("Unknown opcode\n");
                    return -1;
                }
                if (addr > last)
                    last = addr;
                if (total >= size)
                    break;
                size -= total;
            }
            break;
        case PEF_SECTION_LOADER:
            /* find entry point */
            if (fs_read(file, &loader, sizeof(PEF_loader_t)) < 0) {
                ERROR("Cannot read loader header\n");
                return -1;
            }
            main_section = get_be32(&loader.main_section);
            main_offset = get_be32(&loader.main_offset);
            if (main_section >= nb_sections) {
                ERROR("Invalid main section\n");
                return -1;
            }
            break;
        case PEF_SECTION_DEBUG:
        case PEF_SECTION_EXCP:
        case PEF_SECTION_TRACE:
            break;
        default:
            return -2;
        }
    }
    *dest = first;
    *end = last;
    if (main_section == -1) {
        *entry = first;
    } else {
        *entry = (char *)sections[main_section] + main_offset;
    }
    free(sections);

    return 0;
}
