// String manipulation function defs.
#ifndef __STRING_H
#define __STRING_H

#include "types.h" // u32

// string.c
u8 checksum_far(u16 buf_seg, void *buf_far, u32 len);
u8 checksum(void *buf, u32 len);
size_t strlen(const char *s);
int memcmp_far(u16 s1seg, const void *s1, u16 s2seg, const void *s2, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
int strcmp(const char *s1, const char *s2);
inline void memset_far(u16 d_seg, void *d_far, u8 c, size_t len);
inline void memset16_far(u16 d_seg, void *d_far, u16 c, size_t len);
void *memset(void *s, int c, size_t n);
void memset_fl(void *ptr, u8 val, size_t size);
inline void memcpy_far(u16 d_seg, void *d_far
                       , u16 s_seg, const void *s_far, size_t len);
void memcpy_fl(void *d_fl, const void *s_fl, size_t len);
void *memcpy(void *d1, const void *s1, size_t len);
#if MODESEGMENT == 0
#define memcpy __builtin_memcpy
#endif
void iomemcpy(void *d, const void *s, u32 len);
void *memmove(void *d, const void *s, size_t len);
char *strtcpy(char *dest, const char *src, size_t len);
char *strchr(const char *s, int c);
char *nullTrailingSpace(char *buf);

#endif // string.h
