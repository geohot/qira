// Basic type definitions for X86 cpus.
//
// Copyright (C) 2008-2010  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.
#ifndef __TYPES_H
#define __TYPES_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned long long u64;
typedef signed long long s64;
typedef u32 size_t;

union u64_u32_u {
    struct { u32 lo, hi; };
    u64 val;
};

// Definition for common 16bit segment/offset pointers.
struct segoff_s {
    union {
        struct {
            u16 offset;
            u16 seg;
        };
        u32 segoff;
    };
};

#ifdef MANUAL_NO_JUMP_TABLE
# define default case 775324556: asm(""); default
#endif

#ifdef WHOLE_PROGRAM
# define __VISIBLE __attribute__((externally_visible))
#else
# define __VISIBLE
#endif

#define UNIQSEC __FILE__ "." __stringify(__LINE__)

#define __noreturn __attribute__((noreturn))
extern void __force_link_error__only_in_32bit_flat(void) __noreturn;
extern void __force_link_error__only_in_32bit_segmented(void) __noreturn;
extern void __force_link_error__only_in_16bit(void) __noreturn;

#define __ASM(code) asm(".section .text.asm." UNIQSEC "\n\t" code)

#if MODE16 == 1
// Notes a function as externally visible in the 16bit code chunk.
# define VISIBLE16 __VISIBLE
// Notes a function as externally visible in the 32bit flat code chunk.
# define VISIBLE32FLAT
// Notes a 32bit flat function that will only be called during init.
# define VISIBLE32INIT
// Notes a function as externally visible in the 32bit segmented code chunk.
# define VISIBLE32SEG
// Designate a variable as (only) visible to 16bit code.
# define VAR16 __section(".data16." UNIQSEC)
// Designate a variable as (only) visible to 32bit segmented code.
# define VAR32SEG __section(".discard.var32seg." UNIQSEC)
// Designate a variable as visible and located in the e-segment.
# define VARLOW __section(".discard.varlow." UNIQSEC) __VISIBLE __weak
// Designate a variable as visible and located in the f-segment.
# define VARFSEG __section(".discard.varfseg." UNIQSEC) __VISIBLE __weak
// Designate a variable at a specific address in the f-segment.
# define VARFSEGFIXED(addr) __section(".discard.varfixed." UNIQSEC) __VISIBLE __weak
// Verify a variable is only accessable via 32bit "init" functions
# define VARVERIFY32INIT __section(".discard.varinit." UNIQSEC)
// Designate top-level assembler as 16bit only.
# define ASM16(code) __ASM(code)
// Designate top-level assembler as 32bit flat only.
# define ASM32FLAT(code)
// Compile time check for a given mode.
# define ASSERT16() do { } while (0)
# define ASSERT32SEG() __force_link_error__only_in_32bit_segmented()
# define ASSERT32FLAT() __force_link_error__only_in_32bit_flat()
#elif MODESEGMENT == 1
# define VISIBLE16
# define VISIBLE32FLAT
# define VISIBLE32INIT
# define VISIBLE32SEG __VISIBLE
# define VAR16 __section(".discard.var16." UNIQSEC)
# define VAR32SEG __section(".data32seg." UNIQSEC)
# define VARLOW __section(".discard.varlow." UNIQSEC) __VISIBLE __weak
# define VARFSEG __section(".discard.varfseg." UNIQSEC) __VISIBLE __weak
# define VARFSEGFIXED(addr) __section(".discard.varfixed." UNIQSEC) __VISIBLE __weak
# define VARVERIFY32INIT __section(".discard.varinit." UNIQSEC)
# define ASM16(code)
# define ASM32FLAT(code)
# define ASSERT16() __force_link_error__only_in_16bit()
# define ASSERT32SEG() do { } while (0)
# define ASSERT32FLAT() __force_link_error__only_in_32bit_flat()
#else
# define VISIBLE16
# define VISIBLE32FLAT __section(".text.runtime." UNIQSEC) __VISIBLE
# define VISIBLE32INIT __section(".text.init." UNIQSEC) __VISIBLE
# define VISIBLE32SEG
# define VAR16 __section(".discard.var16." UNIQSEC)
# define VAR32SEG __section(".discard.var32seg." UNIQSEC)
# define VARLOW __section(".data.varlow." UNIQSEC) __VISIBLE __weak
# define VARFSEG __section(".data.varfseg." UNIQSEC) __VISIBLE
# define VARFSEGFIXED(addr) __section(".fixedaddr." __stringify(addr)) __VISIBLE __aligned(1)
# define VARVERIFY32INIT __section(".data.varinit." UNIQSEC)
# define ASM16(code)
# define ASM32FLAT(code) __ASM(code)
# define ASSERT16() __force_link_error__only_in_16bit()
# define ASSERT32SEG() __force_link_error__only_in_32bit_segmented()
# define ASSERT32FLAT() do { } while (0)
#endif

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_CLOSEST(x, divisor)({                 \
            typeof(divisor) __divisor = divisor;        \
            (((x) + ((__divisor) / 2)) / (__divisor));  \
        })
#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))
#define ALIGN_DOWN(x,a)         ((x) & ~((typeof(x))(a)-1))
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#define container_of_or_null(ptr, type, member) ({              \
        const typeof( ((type *)0)->member ) *___mptr = (ptr);   \
        ___mptr ? container_of(___mptr, type, member) : NULL; })

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define NULL ((void*)0)

#define __weak __attribute__((weak))
#define __section(S) __attribute__((section(S)))

#define PACKED __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))

#define barrier() __asm__ __volatile__("": : :"memory")

#define noinline __attribute__((noinline))
#define __always_inline inline __attribute__((always_inline))
#define __malloc __attribute__((__malloc__))
#define __attribute_const __attribute__((__const__))

#define __stringify_1(x)        #x
#define __stringify(x)          __stringify_1(x)

#endif // types.h
