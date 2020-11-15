// Support for building memory maps suitable for int 15 e820 calls.
//
// Copyright (C) 2008,2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // BUILD_MAX_E820
#include "memmap.h" // struct e820entry
#include "output.h" // dprintf
#include "string.h" // memmove


/****************************************************************
 * e820 memory map
 ****************************************************************/

// Info on e820 map location and size.
struct e820entry e820_list[BUILD_MAX_E820] VARFSEG;
int e820_count VARFSEG;

// Remove an entry from the e820_list.
static void
remove_e820(int i)
{
    e820_count--;
    memmove(&e820_list[i], &e820_list[i+1]
            , sizeof(e820_list[0]) * (e820_count - i));
}

// Insert an entry in the e820_list at the given position.
static void
insert_e820(int i, u64 start, u64 size, u32 type)
{
    if (e820_count >= BUILD_MAX_E820) {
        warn_noalloc();
        return;
    }

    memmove(&e820_list[i+1], &e820_list[i]
            , sizeof(e820_list[0]) * (e820_count - i));
    e820_count++;
    struct e820entry *e = &e820_list[i];
    e->start = start;
    e->size = size;
    e->type = type;
}

static const char *
e820_type_name(u32 type)
{
    switch (type) {
    case E820_RAM:      return "RAM";
    case E820_RESERVED: return "RESERVED";
    case E820_ACPI:     return "ACPI";
    case E820_NVS:      return "NVS";
    case E820_UNUSABLE: return "UNUSABLE";
    case E820_HOLE:     return "HOLE";
    default:            return "UNKNOWN";
    }
}

// Show the current e820_list.
static void
dump_map(void)
{
    dprintf(1, "e820 map has %d items:\n", e820_count);
    int i;
    for (i=0; i<e820_count; i++) {
        struct e820entry *e = &e820_list[i];
        u64 e_end = e->start + e->size;
        dprintf(1, "  %d: %016llx - %016llx = %d %s\n", i
                , e->start, e_end, e->type, e820_type_name(e->type));
    }
}

// Add a new entry to the list.  This scans for overlaps and keeps the
// list sorted.
void
add_e820(u64 start, u64 size, u32 type)
{
    dprintf(8, "Add to e820 map: %08x %08x %d\n", (u32)start, (u32)size, type);

    if (! size)
        // Huh?  Nothing to do.
        return;

    // Find position of new item (splitting existing item if needed).
    u64 end = start + size;
    int i;
    for (i=0; i<e820_count; i++) {
        struct e820entry *e = &e820_list[i];
        u64 e_end = e->start + e->size;
        if (start > e_end)
            continue;
        // Found position - check if an existing item needs to be split.
        if (start > e->start) {
            if (type == e->type) {
                // Same type - merge them.
                size += start - e->start;
                start = e->start;
            } else {
                // Split existing item.
                e->size = start - e->start;
                i++;
                if (e_end > end)
                    insert_e820(i, end, e_end - end, e->type);
            }
        }
        break;
    }
    // Remove/adjust existing items that are overlapping.
    while (i<e820_count) {
        struct e820entry *e = &e820_list[i];
        if (end < e->start)
            // No overlap - done.
            break;
        u64 e_end = e->start + e->size;
        if (end >= e_end) {
            // Existing item completely overlapped - remove it.
            remove_e820(i);
            continue;
        }
        // Not completely overlapped - adjust its start.
        e->start = end;
        e->size = e_end - end;
        if (type == e->type) {
            // Same type - merge them.
            size += e->size;
            remove_e820(i);
        }
        break;
    }
    // Insert new item.
    if (type != E820_HOLE)
        insert_e820(i, start, size, type);
    //dump_map();
}

// Report on final memory locations.
void
memmap_prepboot(void)
{
    dump_map();
}
