#ifndef __ROMFILE_H
#define __ROMFILE_H

#include "types.h" // u32

// romfile.c
struct romfile_s {
    struct romfile_s *next;
    char name[128];
    u32 size;
    int (*copy)(struct romfile_s *file, void *dest, u32 maxlen);
};
void romfile_add(struct romfile_s *file);
struct romfile_s *romfile_findprefix(const char *prefix, struct romfile_s *prev);
struct romfile_s *romfile_find(const char *name);
void *romfile_loadfile(const char *name, int *psize);
u64 romfile_loadint(const char *name, u64 defval);

#endif // romfile.h
