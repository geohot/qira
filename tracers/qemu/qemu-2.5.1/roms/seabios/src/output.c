// Raw screen writing and debug output code.
//
// Copyright (C) 2008-2013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include <stdarg.h> // va_list

#include "farptr.h" // GET_VAR
#include "bregs.h" // struct bregs
#include "config.h" // CONFIG_*
#include "biosvar.h" // GET_GLOBAL
#include "hw/serialio.h" // serial_debug_putc
#include "malloc.h" // malloc_tmp
#include "output.h" // dprintf
#include "stacks.h" // call16_int
#include "string.h" // memset
#include "util.h" // ScreenAndDebug

struct putcinfo {
    void (*func)(struct putcinfo *info, char c);
};


/****************************************************************
 * Debug output
 ****************************************************************/

void
debug_banner(void)
{
    dprintf(1, "SeaBIOS (version %s)\n", VERSION);
}

// Write a character to debug port(s).
static void
debug_putc(struct putcinfo *action, char c)
{
    if (! CONFIG_DEBUG_LEVEL)
        return;
    qemu_debug_putc(c);
    if (!MODESEGMENT)
        coreboot_debug_putc(c);
    serial_debug_putc(c);
}

// Flush any pending output to debug port(s).
static void
debug_flush(void)
{
    serial_debug_flush();
}

// In segmented mode just need a dummy variable (debug_putc is always
// used anyway), and in 32bit flat mode need a pointer to the 32bit
// instance of debug_putc().
#if MODE16
static struct putcinfo debuginfo VAR16;
#elif MODESEGMENT
static struct putcinfo debuginfo VAR32SEG;
#else
static struct putcinfo debuginfo = { debug_putc };
#endif


/****************************************************************
 * Screen writing
 ****************************************************************/

// Show a character on the screen.
static void
screenc(char c)
{
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.flags = F_IF;
    br.ah = 0x0e;
    br.al = c;
    br.bl = 0x07;
    call16_int(0x10, &br);
}

// Handle a character from a printf request.
static void
screen_putc(struct putcinfo *action, char c)
{
    if (ScreenAndDebug)
        debug_putc(&debuginfo, c);
    if (c == '\n')
        screenc('\r');
    screenc(c);
}

static struct putcinfo screeninfo = { screen_putc };


/****************************************************************
 * Xprintf code
 ****************************************************************/

// Output a character.
static void
putc(struct putcinfo *action, char c)
{
    if (MODESEGMENT) {
        // Only debugging output supported in segmented mode.
        debug_putc(action, c);
        return;
    }

    void (*func)(struct putcinfo *info, char c) = GET_GLOBAL(action->func);
    func(action, c);
}

// Ouptut a string.
static void
puts(struct putcinfo *action, const char *s)
{
    if (!MODESEGMENT && !s)
        s = "(NULL)";
    for (; *s; s++)
        putc(action, *s);
}

// Output a string that is in the CS segment.
static void
puts_cs(struct putcinfo *action, const char *s)
{
    char *vs = (char*)s;
    for (;; vs++) {
        char c = GET_GLOBAL(*vs);
        if (!c)
            break;
        putc(action, c);
    }
}

// Output an unsigned integer.
static void
putuint(struct putcinfo *action, u32 val)
{
    char buf[12];
    char *d = &buf[sizeof(buf) - 1];
    *d-- = '\0';
    for (;;) {
        *d = (val % 10) + '0';
        val /= 10;
        if (!val)
            break;
        d--;
    }
    puts(action, d);
}

// Output a single digit hex character.
static inline void
putsinglehex(struct putcinfo *action, u32 val)
{
    if (val <= 9)
        val = '0' + val;
    else
        val = 'a' + val - 10;
    putc(action, val);
}

// Output an integer in hexadecimal with a specified width.
static void
puthex(struct putcinfo *action, u32 val, int width)
{
    switch (width) {
    default: putsinglehex(action, (val >> 28) & 0xf);
    case 7:  putsinglehex(action, (val >> 24) & 0xf);
    case 6:  putsinglehex(action, (val >> 20) & 0xf);
    case 5:  putsinglehex(action, (val >> 16) & 0xf);
    case 4:  putsinglehex(action, (val >> 12) & 0xf);
    case 3:  putsinglehex(action, (val >> 8) & 0xf);
    case 2:  putsinglehex(action, (val >> 4) & 0xf);
    case 1:  putsinglehex(action, (val >> 0) & 0xf);
    }
}

// Output an integer in hexadecimal with a minimum width.
static void
putprettyhex(struct putcinfo *action, u32 val, int width, char padchar)
{
    u32 tmp = val;
    int count = 1;
    while (tmp >>= 4)
        count++;
    width -= count;
    while (width-- > 0)
        putc(action, padchar);
    puthex(action, val, count);
}

static inline int
isdigit(u8 c)
{
    return ((u8)(c - '0')) < 10;
}

static void
bvprintf(struct putcinfo *action, const char *fmt, va_list args)
{
    const char *s = fmt;
    for (;; s++) {
        char c = GET_GLOBAL(*(u8*)s);
        if (!c)
            break;
        if (c != '%') {
            putc(action, c);
            continue;
        }
        const char *n = s+1;
        int field_width = 0;
        char padchar = ' ';
        u8 is64 = 0;
        for (;;) {
            c = GET_GLOBAL(*(u8*)n);
            if (!isdigit(c))
                break;
            if (!field_width && (c == '0'))
                padchar = '0';
            else
                field_width = field_width * 10 + c - '0';
            n++;
        }
        if (c == 'l') {
            // Ignore long format indicator
            n++;
            c = GET_GLOBAL(*(u8*)n);
        }
        if (c == 'l') {
            is64 = 1;
            n++;
            c = GET_GLOBAL(*(u8*)n);
        }
        s32 val;
        const char *sarg;
        switch (c) {
        case '%':
            putc(action, '%');
            break;
        case 'd':
            val = va_arg(args, s32);
            if (is64)
                va_arg(args, s32);
            if (val < 0) {
                putc(action, '-');
                val = -val;
            }
            putuint(action, val);
            break;
        case 'u':
            val = va_arg(args, s32);
            if (is64)
                va_arg(args, s32);
            putuint(action, val);
            break;
        case 'p':
            val = va_arg(args, s32);
            putc(action, '0');
            putc(action, 'x');
            puthex(action, val, 8);
            break;
        case 'x':
            val = va_arg(args, s32);
            if (is64) {
                u32 upper = va_arg(args, s32);
                if (upper) {
                    putprettyhex(action, upper, field_width - 8, padchar);
                    puthex(action, val, 8);
                    break;
                }
            }
            putprettyhex(action, val, field_width, padchar);
            break;
        case 'c':
            val = va_arg(args, int);
            putc(action, val);
            break;
        case '.':
            // Hack to support "%.s" - meaning string on stack.
            if (GET_GLOBAL(*(u8*)(n+1)) != 's')
                break;
            n++;
            sarg = va_arg(args, const char *);
            puts(action, sarg);
            break;
        case 's':
            sarg = va_arg(args, const char *);
            puts_cs(action, sarg);
            break;
        default:
            putc(action, '%');
            n = s;
        }
        s = n;
    }
}

void
panic(const char *fmt, ...)
{
    if (CONFIG_DEBUG_LEVEL) {
        va_list args;
        va_start(args, fmt);
        bvprintf(&debuginfo, fmt, args);
        va_end(args);
        debug_flush();
    }

    // XXX - use PANIC PORT.
    irq_disable();
    for (;;)
        hlt();
}

void
__dprintf(const char *fmt, ...)
{
    if (!MODESEGMENT && CONFIG_THREADS && CONFIG_DEBUG_LEVEL >= DEBUG_thread
        && *fmt != '\\' && *fmt != '/') {
        struct thread_info *cur = getCurThread();
        if (cur != &MainThread) {
            // Show "thread id" for this debug message.
            debug_putc(&debuginfo, '|');
            puthex(&debuginfo, (u32)cur, 8);
            debug_putc(&debuginfo, '|');
            debug_putc(&debuginfo, ' ');
        }
    }

    va_list args;
    va_start(args, fmt);
    bvprintf(&debuginfo, fmt, args);
    va_end(args);
    debug_flush();
}

void
printf(const char *fmt, ...)
{
    ASSERT32FLAT();
    va_list args;
    va_start(args, fmt);
    bvprintf(&screeninfo, fmt, args);
    va_end(args);
    if (ScreenAndDebug)
        debug_flush();
}


/****************************************************************
 * snprintf
 ****************************************************************/

struct snprintfinfo {
    struct putcinfo info;
    char *str, *end;
};

static void
putc_str(struct putcinfo *info, char c)
{
    struct snprintfinfo *sinfo = container_of(info, struct snprintfinfo, info);
    if (sinfo->str >= sinfo->end)
        return;
    *sinfo->str = c;
    sinfo->str++;
}

// Build a formatted string.  Note, this function returns the actual
// number of bytes used (not including null) even in the overflow
// case.
int
snprintf(char *str, size_t size, const char *fmt, ...)
{
    ASSERT32FLAT();
    if (!size)
        return 0;
    struct snprintfinfo sinfo = { { putc_str }, str, str + size };
    va_list args;
    va_start(args, fmt);
    bvprintf(&sinfo.info, fmt, args);
    va_end(args);
    char *end = sinfo.str;
    if (end >= sinfo.end)
        end = sinfo.end - 1;
    *end = '\0';
    return end - str;
}

// Build a formatted string - malloc'ing the memory.
char *
znprintf(size_t size, const char *fmt, ...)
{
    ASSERT32FLAT();
    if (!size)
        return NULL;
    char *str = malloc_tmp(size);
    if (!str) {
        warn_noalloc();
        return NULL;
    }
    struct snprintfinfo sinfo = { { putc_str }, str, str + size };
    va_list args;
    va_start(args, fmt);
    bvprintf(&sinfo.info, fmt, args);
    va_end(args);
    char *end = sinfo.str;
    if (end >= sinfo.end)
        end = sinfo.end - 1;
    *end = '\0';
    return str;
}


/****************************************************************
 * Misc helpers
 ****************************************************************/

void
hexdump(const void *d, int len)
{
    int count=0;
    while (len > 0) {
        if (count % 8 == 0) {
            putc(&debuginfo, '\n');
            puthex(&debuginfo, count*4, 8);
            putc(&debuginfo, ':');
        } else {
            putc(&debuginfo, ' ');
        }
        puthex(&debuginfo, *(u32*)d, 8);
        count++;
        len-=4;
        d+=4;
    }
    putc(&debuginfo, '\n');
    debug_flush();
}

static void
dump_regs(struct bregs *regs)
{
    if (!regs) {
        dprintf(1, "  NULL\n");
        return;
    }
    dprintf(1, "   a=%08x  b=%08x  c=%08x  d=%08x ds=%04x es=%04x ss=%04x\n"
            , regs->eax, regs->ebx, regs->ecx, regs->edx
            , regs->ds, regs->es, GET_SEG(SS));
    dprintf(1, "  si=%08x di=%08x bp=%08x sp=%08x cs=%04x ip=%04x  f=%04x\n"
            , regs->esi, regs->edi, regs->ebp, (u32)&regs[1]
            , regs->code.seg, regs->code.offset, regs->flags);
}

// Report entry to an Interrupt Service Routine (ISR).
void
__debug_isr(const char *fname)
{
    puts_cs(&debuginfo, fname);
    putc(&debuginfo, '\n');
    debug_flush();
}

// Function called on handler startup.
void
__debug_enter(struct bregs *regs, const char *fname)
{
    dprintf(1, "enter %s:\n", fname);
    dump_regs(regs);
}

// Send debugging output info.
void
__debug_stub(struct bregs *regs, int lineno, const char *fname)
{
    dprintf(1, "stub %s:%d:\n", fname, lineno);
    dump_regs(regs);
}

// Report on an invalid parameter.
void
__warn_invalid(struct bregs *regs, int lineno, const char *fname)
{
    if (CONFIG_DEBUG_LEVEL >= DEBUG_invalid) {
        dprintf(1, "invalid %s:%d:\n", fname, lineno);
        dump_regs(regs);
    }
}

// Report on an unimplemented feature.
void
__warn_unimplemented(struct bregs *regs, int lineno, const char *fname)
{
    if (CONFIG_DEBUG_LEVEL >= DEBUG_unimplemented) {
        dprintf(1, "unimplemented %s:%d:\n", fname, lineno);
        dump_regs(regs);
    }
}

// Report a detected internal inconsistency.
void
__warn_internalerror(int lineno, const char *fname)
{
    dprintf(1, "WARNING - internal error detected at %s:%d!\n"
            , fname, lineno);
}

// Report on an allocation failure.
void
__warn_noalloc(int lineno, const char *fname)
{
    dprintf(1, "WARNING - Unable to allocate resource at %s:%d!\n"
            , fname, lineno);
}

// Report on a timeout exceeded.
void
__warn_timeout(int lineno, const char *fname)
{
    dprintf(1, "WARNING - Timeout at %s:%d!\n", fname, lineno);
}

// Report a handler reporting an invalid parameter to the caller.
void
__set_invalid(struct bregs *regs, int lineno, const char *fname)
{
    __warn_invalid(regs, lineno, fname);
    set_invalid_silent(regs);
}

// Report a call of an unimplemented function.
void
__set_unimplemented(struct bregs *regs, int lineno, const char *fname)
{
    __warn_unimplemented(regs, lineno, fname);
    set_invalid_silent(regs);
}

// Report a handler reporting an invalid parameter code to the
// caller.  Note, the lineno and return code are encoded in the same
// parameter as gcc does a better job of scheduling function calls
// when there are 3 or less parameters.
void
__set_code_invalid(struct bregs *regs, u32 linecode, const char *fname)
{
    u8 code = linecode;
    u32 lineno = linecode >> 8;
    __warn_invalid(regs, lineno, fname);
    set_code_invalid_silent(regs, code);
}

// Report a call of an unimplemented function.
void
__set_code_unimplemented(struct bregs *regs, u32 linecode, const char *fname)
{
    u8 code = linecode;
    u32 lineno = linecode >> 8;
    __warn_unimplemented(regs, lineno, fname);
    set_code_invalid_silent(regs, code);
}
