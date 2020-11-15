#ifndef _ASM_IO_H
#define _ASM_IO_H

#include "asm/types.h"

#define NO_QEMU_PROTOS
#include "arch/common/fw_cfg.h"

extern char _start, _end;
extern unsigned long virt_offset;

#define phys_to_virt(phys) ((void *) ((unsigned long) (phys) - virt_offset))
#define virt_to_phys(virt) ((unsigned long) (virt) + virt_offset)

#ifndef BOOTSTRAP

extern unsigned long isa_io_base;

/*
 * 8, 16 and 32 bit, big and little endian I/O operations, with barrier.
 */
static inline uint8_t in_8(volatile uint8_t *addr)
{
	uint8_t ret;

	__asm__ __volatile__("lbz%U1%X1 %0,%1; eieio":"=r"(ret):"m"(*addr));
	return ret;
}

static inline void out_8(volatile uint8_t *addr, uint8_t val)
{
	__asm__ __volatile__("stb%U0%X0 %1,%0; eieio":"=m"(*addr):"r"(val));
}

static inline uint16_t in_le16(volatile uint16_t *addr)
{
	uint16_t ret;

	__asm__ __volatile__("lhbrx %0,0,%1; eieio":"=r"(ret):
			     "r"(addr), "m"(*addr));
	return ret;
}

static inline uint16_t in_be16(volatile uint16_t *addr)
{
	uint16_t ret;

	__asm__ __volatile__("lhz%U1%X1 %0,%1; eieio":"=r"(ret):"m"(*addr));
	return ret;
}

static inline void out_le16(volatile uint16_t *addr, uint16_t val)
{
	__asm__ __volatile__("sthbrx %1,0,%2; eieio":"=m"(*addr):"r"(val),
			     "r"(addr));
}

static inline void out_be16(volatile uint16_t *addr, uint16_t val)
{
	__asm__ __volatile__("sth%U0%X0 %1,%0; eieio":"=m"(*addr):"r"(val));
}

static inline uint32_t in_le32(volatile uint32_t *addr)
{
	uint32_t ret;

	__asm__ __volatile__("lwbrx %0,0,%1; eieio":"=r"(ret):
			     "r"(addr), "m"(*addr));
	return ret;
}

static inline uint32_t in_be32(volatile uint32_t *addr)
{
	uint32_t ret;

	__asm__ __volatile__("lwz%U1%X1 %0,%1; eieio":"=r"(ret):"m"(*addr));
	return ret;
}

static inline void out_le32(volatile uint32_t *addr, uint32_t val)
{
	__asm__ __volatile__("stwbrx %1,0,%2; eieio":"=m"(*addr):"r"(val),
			     "r"(addr));
}

static inline void out_be32(volatile unsigned *addr, uint32_t val)
{
	__asm__ __volatile__("stw%U0%X0 %1,%0; eieio":"=m"(*addr):"r"(val));
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


/*
 * The insw/outsw/insl/outsl functions don't do byte-swapping.
 * They are only used in practice for transferring buffers which
 * are arrays of bytes, and byte-swapping is not appropriate in
 * that case.  - paulus
 */

static inline void insw(uint16_t port, void *buf, int ns)
{
	_insw((uint16_t *)(port + isa_io_base), buf, ns);
}

static inline void outsw(uint16_t port, void *buf, int ns)
{
	_outsw((uint16_t *)(port + isa_io_base), buf, ns);
}


static inline uint8_t inb(uint16_t port)
{
	return in_8((uint8_t *)(port + isa_io_base));
}

static inline void outb(uint8_t val, uint16_t port)
{
	out_8((uint8_t *)(port + isa_io_base), val);
}

static inline uint16_t inw(uint16_t port)
{
	return in_le16((uint16_t *)(port + isa_io_base));
}

static inline void outw(uint16_t val, uint16_t port)
{
	out_le16((uint16_t *)(port + isa_io_base), val);
}

static inline uint32_t inl(uint16_t port)
{
	return in_le32((uint32_t *)(port + isa_io_base));
}

static inline void outl(uint32_t val, uint16_t port)
{
	out_le32((uint32_t *)(port + isa_io_base), val);
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
#define FW_CFG_ARCH_WIDTH        (FW_CFG_ARCH_LOCAL + 0x00)
#define FW_CFG_ARCH_HEIGHT       (FW_CFG_ARCH_LOCAL + 0x01)
#define FW_CFG_ARCH_DEPTH        (FW_CFG_ARCH_LOCAL + 0x02)
#endif

#endif /* _ASM_IO_H */
