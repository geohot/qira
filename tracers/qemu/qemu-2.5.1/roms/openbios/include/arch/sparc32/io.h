#ifndef _ASM_IO_H
#define _ASM_IO_H

#include "asm/types.h"

extern unsigned int va_shift; // Set in entry.S

// Defined in ldscript
extern char _start, _data, _stack, _estack, _end, _vmem, _evmem, _iomem;

// XXX check use and merge
#define phys_to_virt(phys) ((void *) ((unsigned long) (phys)))
#define virt_to_phys(virt) ((unsigned long) (virt))

#ifndef BOOTSTRAP

#ifndef _IO_BASE
#define _IO_BASE	0
#endif

/*
 * The insw/outsw/insl/outsl macros don't do byte-swapping.
 * They are only used in practice for transferring buffers which
 * are arrays of bytes, and byte-swapping is not appropriate in
 * that case.  - paulus
 */
#define insw(port, buf, ns)	_insw_ns((uint16_t *)((port)+_IO_BASE), (buf), (ns))
#define outsw(port, buf, ns)	_outsw_ns((uint16_t *)((port)+_IO_BASE), (buf), (ns))

#define inb(port)		in_8((uint8_t *)((port)+_IO_BASE))
#define outb(val, port)		out_8((uint8_t *)((port)+_IO_BASE), (val))
#define inw(port)		in_le16((uint16_t *)((port)+_IO_BASE))
#define outw(val, port)		out_le16((uint16_t *)((port)+_IO_BASE), (val))
#define inl(port)		in_le32((uint32_t *)((port)+_IO_BASE))
#define outl(val, port)		out_le32((uint32_t *)((port)+_IO_BASE), (val))

/*
 * 8, 16 and 32 bit, big and little endian I/O operations, with barrier.
 */
static inline int in_8(volatile unsigned char *addr)
{
    int ret;

    __asm__ __volatile__("ldub [%1], %0\n\t"
                         "stbar\n\t"
                         :"=r"(ret):"r"(addr):"memory");

    return ret;
}

static inline void out_8(volatile unsigned char *addr, int val)
{
    __asm__ __volatile__("stb %0, [%1]\n\t"
                         "stbar\n\t"
                         : : "r"(val), "r"(addr):"memory");
}

static inline int in_le16(volatile unsigned short *addr)
{
    int ret;

    // XXX
    __asm__ __volatile__("lduh [%1], %0\n\t"
                         "stbar\n\t"
                         :"=r"(ret):"r"(addr):"memory");

    return ret;
}

static inline int in_be16(volatile unsigned short *addr)
{
    int ret;

    __asm__ __volatile__("lduh [%1], %0\n\t"
                         "stbar\n\t"
                         :"=r"(ret):"r"(addr):"memory");

    return ret;
}

static inline void out_le16(volatile unsigned short *addr, int val)
{
    // XXX
    __asm__ __volatile__("sth %0, [%1]\n\t"
                         "stbar\n\t"
                         : : "r"(val), "r"(addr):"memory");
}

static inline void out_be16(volatile unsigned short *addr, int val)
{
    __asm__ __volatile__("sth %0, [%1]\n\t"
                         "stbar\n\t"
                         : : "r"(val), "r"(addr):"memory");
}

static inline unsigned in_le32(volatile unsigned *addr)
{
    unsigned ret;

    // XXX
    __asm__ __volatile__("ld [%1], %0\n\t"
                         "stbar\n\t"
                         :"=r"(ret):"r"(addr):"memory");

    return ret;
}

static inline unsigned in_be32(volatile unsigned *addr)
{
    unsigned ret;

    __asm__ __volatile__("ld [%1], %0\n\t"
                         "stbar\n\t"
                         :"=r"(ret):"r"(addr):"memory");

    return ret;
}

static inline void out_le32(volatile unsigned *addr, int val)
{
    // XXX
    __asm__ __volatile__("st %0, [%1]\n\t"
                         "stbar\n\t"
                         : : "r"(val), "r"(addr):"memory");
}

static inline void out_be32(volatile unsigned *addr, int val)
{
    __asm__ __volatile__("st %0, [%1]\n\t"
                         "stbar\n\t"
                         : : "r"(val), "r"(addr):"memory");
}

static inline void _insw_ns(volatile uint16_t * port, void *buf, int ns)
{
	uint16_t *b = (uint16_t *) buf;

	while (ns > 0) {
		*b++ = in_le16(port);
		ns--;
	}
}

static inline void _outsw_ns(volatile uint16_t * port, const void *buf,
			     int ns)
{
	uint16_t *b = (uint16_t *) buf;

	while (ns > 0) {
		out_le16(port, *b++);
		ns--;
	}
}

static inline void _insw(volatile uint16_t * port, void *buf, int ns)
{
	uint16_t *b = (uint16_t *) buf;

	while (ns > 0) {
		*b++ = in_be16(port);
		ns--;
	}
}

static inline void _outsw(volatile uint16_t * port, const void *buf,
			  int ns)
{
	uint16_t *b = (uint16_t *) buf;

	while (ns > 0) {
		out_be16(port, *b++);
		ns--;
	}
}
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

#if defined(CONFIG_QEMU)
#define FW_CFG_ARCH_DEPTH        (FW_CFG_ARCH_LOCAL + 0x00)
#define FW_CFG_ARCH_WIDTH        (FW_CFG_ARCH_LOCAL + 0x01)
#define FW_CFG_ARCH_HEIGHT       (FW_CFG_ARCH_LOCAL + 0x02)
#endif

#endif /* _ASM_IO_H */
