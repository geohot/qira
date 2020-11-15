#ifndef __OUTPUT_H
#define __OUTPUT_H

#include "config.h" // CONFIG_DEBUG_LEVEL
#include "types.h" // u32

// output.c
void debug_banner(void);
void panic(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2))) __noreturn;
void printf(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));
int snprintf(char *str, size_t size, const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)));
char * znprintf(size_t size, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));
void __dprintf(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));
struct bregs;
void __debug_enter(struct bregs *regs, const char *fname);
void __debug_isr(const char *fname);
void __debug_stub(struct bregs *regs, int lineno, const char *fname);
void __warn_invalid(struct bregs *regs, int lineno, const char *fname);
void __warn_unimplemented(struct bregs *regs, int lineno, const char *fname);
void __warn_internalerror(int lineno, const char *fname);
void __warn_noalloc(int lineno, const char *fname);
void __warn_timeout(int lineno, const char *fname);
void __set_invalid(struct bregs *regs, int lineno, const char *fname);
void __set_unimplemented(struct bregs *regs, int lineno, const char *fname);
void __set_code_invalid(struct bregs *regs, u32 linecode, const char *fname);
void __set_code_unimplemented(struct bregs *regs, u32 linecode
                              , const char *fname);
void hexdump(const void *d, int len);

#define dprintf(lvl, fmt, args...) do {                         \
        if (CONFIG_DEBUG_LEVEL && (lvl) <= CONFIG_DEBUG_LEVEL)  \
            __dprintf((fmt) , ##args );                         \
    } while (0)
#define debug_enter(regs, lvl) do {                     \
        if ((lvl) && (lvl) <= CONFIG_DEBUG_LEVEL)       \
            __debug_enter((regs), __func__);            \
    } while (0)
#define debug_isr(lvl) do {                             \
        if ((lvl) && (lvl) <= CONFIG_DEBUG_LEVEL)       \
            __debug_isr(__func__);                      \
    } while (0)
#define debug_stub(regs)                        \
    __debug_stub((regs), __LINE__, __func__)
#define warn_invalid(regs)                      \
    __warn_invalid((regs), __LINE__, __func__)
#define warn_unimplemented(regs)                        \
    __warn_unimplemented((regs), __LINE__, __func__)
#define warn_internalerror()                    \
    __warn_internalerror(__LINE__, __func__)
#define warn_noalloc()                          \
    __warn_noalloc(__LINE__, __func__)
#define warn_timeout()                          \
    __warn_timeout(__LINE__, __func__)
#define set_invalid(regs)                       \
    __set_invalid((regs), __LINE__, __func__)
#define set_code_invalid(regs, code)                                    \
    __set_code_invalid((regs), (code) | (__LINE__ << 8), __func__)
#define set_unimplemented(regs)                         \
    __set_unimplemented((regs), __LINE__, __func__)
#define set_code_unimplemented(regs, code)                              \
    __set_code_unimplemented((regs), (code) | (__LINE__ << 8), __func__)

#endif // output.h
