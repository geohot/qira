#ifndef _ASM_IO_H
#define _ASM_IO_H

extern char _start, _end;
extern unsigned long virt_offset;

#define phys_to_virt(phys) ((void *) ((unsigned long) (phys) - virt_offset))
#define virt_to_phys(virt) ((unsigned long) (virt) + virt_offset)

#ifndef BOOTSTRAP

#define __SLOW_DOWN_IO "outb %%al,$0x80;"
static inline void slow_down_io(void)
{
	__asm__ __volatile__(
		__SLOW_DOWN_IO
#ifdef REALLY_SLOW_IO
		__SLOW_DOWN_IO __SLOW_DOWN_IO __SLOW_DOWN_IO
#endif
		: : );
}

#define BUILDIO(bwl,bw,type) \
static inline void out##bwl(unsigned type value, int port) { \
	__asm__ __volatile__("out" #bwl " %" #bw "0, %w1" : : "a"(value), "Nd"(port)); \
} \
static inline unsigned type in##bwl(int port) { \
	unsigned type value; \
	__asm__ __volatile__("in" #bwl " %w1, %" #bw "0" : "=a"(value) : "Nd"(port)); \
	return value; \
} \
static inline void out##bwl##_p(unsigned type value, int port) { \
	out##bwl(value, port); \
	slow_down_io(); \
} \
static inline unsigned type in##bwl##_p(int port) { \
	unsigned type value = in##bwl(port); \
	slow_down_io(); \
	return value; \
} \
static inline void outs##bwl(int port, const void *addr, unsigned long count) { \
	__asm__ __volatile__("rep; outs" #bwl : "+S"(addr), "+c"(count) : "d"(port)); \
} \
static inline void ins##bwl(int port, void *addr, unsigned long count) { \
	__asm__ __volatile__("rep; ins" #bwl : "+D"(addr), "+c"(count) : "d"(port)); \
}

BUILDIO(b,b,char)
BUILDIO(w,w,short)
BUILDIO(l,,int)

#else /* BOOTSTRAP */
#ifdef FCOMPILER
#define inb(reg) ((u8)0xff)
#define inw(reg) ((u16)0xffff)
#define inl(reg) ((u32)0xffffffff)
#define outb(reg, val) do{} while(0)
#define outw(reg, val) do{} while(0)
#define outl(reg, val) do{} while(0)
#else
extern u8 inb(u32 reg);
extern u16 inw(u32 reg);
extern u32 inl(u32 reg);
extern void insw(u32 reg, void *addr, unsigned long count);
extern void outb(u32 reg, u8 val);
extern void outw(u32 reg, u16 val);
extern void outl(u32 reg, u32 val);
extern void outsw(u32 reg, const void *addr, unsigned long count);
#endif
#endif
#endif
