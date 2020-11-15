// Access to pseudo "file" interface for configuration information.
//
// Copyright (C) 2012  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // CONFIG_*
#include "malloc.h" // free
#include "output.h" // dprintf
#include "romfile.h" // struct romfile_s
#include "string.h" // memcmp

static struct romfile_s *RomfileRoot VARVERIFY32INIT;

void
romfile_add(struct romfile_s *file)
{
    dprintf(3, "Add romfile: %s (size=%d)\n", file->name, file->size);
    file->next = RomfileRoot;
    RomfileRoot = file;
}

// Search for the specified file.
static struct romfile_s *
__romfile_findprefix(const char *prefix, int prefixlen, struct romfile_s *prev)
{
    struct romfile_s *cur = RomfileRoot;
    if (prev)
        cur = prev->next;
    while (cur) {
        if (memcmp(prefix, cur->name, prefixlen) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

struct romfile_s *
romfile_findprefix(const char *prefix, struct romfile_s *prev)
{
    return __romfile_findprefix(prefix, strlen(prefix), prev);
}

struct romfile_s *
romfile_find(const char *name)
{
    return __romfile_findprefix(name, strlen(name) + 1, NULL);
}

// Helper function to find, malloc_tmphigh, and copy a romfile.  This
// function adds a trailing zero to the malloc'd copy.
void *
romfile_loadfile(const char *name, int *psize)
{
    struct romfile_s *file = romfile_find(name);
    if (!file)
        return NULL;

    int filesize = file->size;
    if (!filesize)
        return NULL;

    char *data = malloc_tmphigh(filesize+1);
    if (!data) {
        warn_noalloc();
        return NULL;
    }

    dprintf(5, "Copying romfile '%s' (len %d)\n", name, filesize);
    int ret = file->copy(file, data, filesize);
    if (ret < 0) {
        free(data);
        return NULL;
    }
    if (psize)
        *psize = filesize;
    data[filesize] = '\0';
    return data;
}

// Attempt to load an integer from the given file - return 'defval'
// if unsuccessful.
u64
romfile_loadint(const char *name, u64 defval)
{
    struct romfile_s *file = romfile_find(name);
    if (!file)
        return defval;

    int filesize = file->size;
    if (!filesize || filesize > sizeof(u64) || (filesize & (filesize-1)))
        // Doesn't look like a valid integer.
        return defval;

    u64 val = 0;
    int ret = file->copy(file, &val, sizeof(val));
    if (ret < 0)
        return defval;
    return val;
}
