// Basic x86 asm functions.
#ifndef __X86_H
#define __X86_H

// CPU flag bitdefs
#define F_CF (1<<0)
#define F_ZF (1<<6)
#define F_IF (1<<9)
#define F_ID (1<<21)

// CR0 flags
#define CR0_PG (1<<31) // Paging
#define CR0_CD (1<<30) // Cache disable
#define CR0_NW (1<<29) // Not Write-through
#define CR0_PE (1<<0)  // Protection enable

// PORT_A20 bitdefs
#define PORT_A20 0x0092
#define A20_ENABLE_BIT 0x02

#ifndef __ASSEMBLY__

#include "types.h" // u32

static inline void irq_disable(void)
{
    asm volatile("cli": : :"memory");
}

static inline void irq_enable(void)
{
    asm volatile("sti": : :"memory");
}

static inline u32 save_flags(void)
{
    u32 flags;
    asm volatile("pushfl ; popl %0" : "=rm" (flags));
    return flags;
}

static inline void restore_flags(u32 flags)
{
    asm volatile("pushl %0 ; popfl" : : "g" (flags) : "memory", "cc");
}

static inline void cpu_relax(void)
{
    asm volatile("rep ; nop": : :"memory");
}

static inline void nop(void)
{
    asm volatile("nop");
}

static inline void hlt(void)
{
    asm volatile("hlt": : :"memory");
}

static inline void wbinvd(void)
{
    asm volatile("wbinvd": : :"memory");
}

#define CPUID_TSC (1 << 4)
#define CPUID_MSR (1 << 5)
#define CPUID_APIC (1 << 9)
#define CPUID_MTRR (1 << 12)
static inline void __cpuid(u32 index, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
    asm("cpuid"
        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
        : "0" (index));
}

static inline u32 getcr0(void) {
    u32 cr0;
    asm("movl %%cr0, %0" : "=r"(cr0));
    return cr0;
}
static inline void setcr0(u32 cr0) {
    asm("movl %0, %%cr0" : : "r"(cr0));
}

static inline u64 rdmsr(u32 index)
{
    u64 ret;
    asm ("rdmsr" : "=A"(ret) : "c"(index));
    return ret;
}

static inline void wrmsr(u32 index, u64 val)
{
    asm volatile ("wrmsr" : : "c"(index), "A"(val));
}

static inline u64 rdtscll(void)
{
    u64 val;
    asm volatile("rdtsc" : "=A" (val));
    return val;
}

static inline u32 __ffs(u32 word)
{
    asm("bsf %1,%0"
        : "=r" (word)
        : "rm" (word));
    return word;
}
static inline u32 __fls(u32 word)
{
    asm("bsr %1,%0"
        : "=r" (word)
        : "rm" (word));
    return word;
}

static inline u32 getesp(void) {
    u32 esp;
    asm("movl %%esp, %0" : "=rm"(esp));
    return esp;
}

static inline void outb(u8 value, u16 port) {
    __asm__ __volatile__("outb %b0, %w1" : : "a"(value), "Nd"(port));
}
static inline void outw(u16 value, u16 port) {
    __asm__ __volatile__("outw %w0, %w1" : : "a"(value), "Nd"(port));
}
static inline void outl(u32 value, u16 port) {
    __asm__ __volatile__("outl %0, %w1" : : "a"(value), "Nd"(port));
}
static inline u8 inb(u16 port) {
    u8 value;
    __asm__ __volatile__("inb %w1, %b0" : "=a"(value) : "Nd"(port));
    return value;
}
static inline u16 inw(u16 port) {
    u16 value;
    __asm__ __volatile__("inw %w1, %w0" : "=a"(value) : "Nd"(port));
    return value;
}
static inline u32 inl(u16 port) {
    u32 value;
    __asm__ __volatile__("inl %w1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void insb(u16 port, u8 *data, u32 count) {
    asm volatile("rep insb (%%dx), %%es:(%%edi)"
                 : "+c"(count), "+D"(data) : "d"(port) : "memory");
}
static inline void insw(u16 port, u16 *data, u32 count) {
    asm volatile("rep insw (%%dx), %%es:(%%edi)"
                 : "+c"(count), "+D"(data) : "d"(port) : "memory");
}
static inline void insl(u16 port, u32 *data, u32 count) {
    asm volatile("rep insl (%%dx), %%es:(%%edi)"
                 : "+c"(count), "+D"(data) : "d"(port) : "memory");
}
// XXX - outs not limited to es segment
static inline void outsb(u16 port, u8 *data, u32 count) {
    asm volatile("rep outsb %%es:(%%esi), (%%dx)"
                 : "+c"(count), "+S"(data) : "d"(port) : "memory");
}
static inline void outsw(u16 port, u16 *data, u32 count) {
    asm volatile("rep outsw %%es:(%%esi), (%%dx)"
                 : "+c"(count), "+S"(data) : "d"(port) : "memory");
}
static inline void outsl(u16 port, u32 *data, u32 count) {
    asm volatile("rep outsl %%es:(%%esi), (%%dx)"
                 : "+c"(count), "+S"(data) : "d"(port) : "memory");
}

static inline void writel(void *addr, u32 val) {
    barrier();
    *(volatile u32 *)addr = val;
}
static inline void writew(void *addr, u16 val) {
    barrier();
    *(volatile u16 *)addr = val;
}
static inline void writeb(void *addr, u8 val) {
    barrier();
    *(volatile u8 *)addr = val;
}
static inline u32 readl(const void *addr) {
    u32 val = *(volatile const u32 *)addr;
    barrier();
    return val;
}
static inline u16 readw(const void *addr) {
    u16 val = *(volatile const u16 *)addr;
    barrier();
    return val;
}
static inline u8 readb(const void *addr) {
    u8 val = *(volatile const u8 *)addr;
    barrier();
    return val;
}

// GDT bits
#define GDT_CODE     (0x9bULL << 40) // Code segment - P,R,A bits also set
#define GDT_DATA     (0x93ULL << 40) // Data segment - W,A bits also set
#define GDT_B        (0x1ULL << 54)  // Big flag
#define GDT_G        (0x1ULL << 55)  // Granularity flag
// GDT bits for segment base
#define GDT_BASE(v)  ((((u64)(v) & 0xff000000) << 32)           \
                      | (((u64)(v) & 0x00ffffff) << 16))
// GDT bits for segment limit (0-1Meg)
#define GDT_LIMIT(v) ((((u64)(v) & 0x000f0000) << 32)   \
                      | (((u64)(v) & 0x0000ffff) << 0))
// GDT bits for segment limit (0-4Gig in 4K chunks)
#define GDT_GRANLIMIT(v) (GDT_G | GDT_LIMIT((v) >> 12))

struct descloc_s {
    u16 length;
    u32 addr;
} PACKED;

static inline void sgdt(struct descloc_s *desc) {
    asm("sgdtl %0" : "=m"(*desc));
}
static inline void lgdt(struct descloc_s *desc) {
    asm("lgdtl %0" : : "m"(*desc) : "memory");
}

static inline u8 get_a20(void) {
    return (inb(PORT_A20) & A20_ENABLE_BIT) != 0;
}

static inline u8 set_a20(u8 cond) {
    u8 val = inb(PORT_A20);
    outb((val & ~A20_ENABLE_BIT) | (cond ? A20_ENABLE_BIT : 0), PORT_A20);
    return (val & A20_ENABLE_BIT) != 0;
}

// x86.c
void cpuid(u32 index, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx);

#endif // !__ASSEMBLY__

#endif // x86.h
