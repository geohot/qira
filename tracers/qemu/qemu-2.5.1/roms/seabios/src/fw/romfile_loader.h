#ifndef __ROMFILE_LOADER_H
#define __ROMFILE_LOADER_H

#include "types.h" // u8
#include "util.h" // romfile_s

#define ROMFILE_LOADER_FILESZ 56

/* ROM file linker/loader interface. Linker uses little endian format */
struct romfile_loader_entry_s {
    u32 command;
    union {
        /*
         * COMMAND_ALLOCATE - allocate a table from @alloc_file
         * subject to @alloc_align alignment (must be power of 2)
         * and @alloc_zone (can be HIGH or FSEG) requirements.
         *
         * Must appear exactly once for each file, and before
         * this file is referenced by any other command.
         */
        struct {
            char alloc_file[ROMFILE_LOADER_FILESZ];
            u32 alloc_align;
            u8 alloc_zone;
        };

        /*
         * COMMAND_ADD_POINTER - patch the table (originating from
         * @dest_file) at @pointer_offset, by adding a pointer to the table
         * originating from @src_file. 1,2,4 or 8 byte unsigned
         * addition is used depending on @pointer_size.
         */
        struct {
            char pointer_dest_file[ROMFILE_LOADER_FILESZ];
            char pointer_src_file[ROMFILE_LOADER_FILESZ];
            u32 pointer_offset;
            u8 pointer_size;
        };

        /*
         * COMMAND_ADD_CHECKSUM - calculate checksum of the range specified by
         * @cksum_start and @cksum_length fields,
         * and then add the value at @cksum_offset.
         * Checksum simply sums -X for each byte X in the range
         * using 8-bit math.
         */
        struct {
            char cksum_file[ROMFILE_LOADER_FILESZ];
            u32 cksum_offset;
            u32 cksum_start;
            u32 cksum_length;
        };

        /* padding */
        char pad[124];
    };
};

enum {
    ROMFILE_LOADER_COMMAND_ALLOCATE     = 0x1,
    ROMFILE_LOADER_COMMAND_ADD_POINTER  = 0x2,
    ROMFILE_LOADER_COMMAND_ADD_CHECKSUM = 0x3,
};

enum {
    ROMFILE_LOADER_ALLOC_ZONE_HIGH = 0x1,
    ROMFILE_LOADER_ALLOC_ZONE_FSEG = 0x2,
};

int romfile_loader_execute(const char *name);

#endif
