#ifndef _IPXE_X86_IO_H
#define _IPXE_X86_IO_H

/** @file
 *
 * iPXE I/O API for x86
 *
 * x86 uses direct pointer dereferences for accesses to memory-mapped
 * I/O space, and the inX/outX instructions for accesses to
 * port-mapped I/O space.
 *
 * 64-bit atomic accesses (readq() and writeq()) use MMX instructions
 * under i386, and will crash original Pentium and earlier CPUs.
 * Fortunately, no hardware that requires atomic 64-bit accesses will
 * physically fit into a machine with such an old CPU anyway.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef IOAPI_X86
#define IOAPI_PREFIX_x86
#else
#define IOAPI_PREFIX_x86 __x86_
#endif

/*
 * Memory space mappings
 *
 */

/** Page shift */
#define PAGE_SHIFT 12

/*
 * Physical<->Bus and Bus<->I/O address mappings
 *
 */

static inline __always_inline unsigned long
IOAPI_INLINE ( x86, phys_to_bus ) ( unsigned long phys_addr ) {
	return phys_addr;
}

static inline __always_inline unsigned long
IOAPI_INLINE ( x86, bus_to_phys ) ( unsigned long bus_addr ) {
	return bus_addr;
}

static inline __always_inline void *
IOAPI_INLINE ( x86, ioremap ) ( unsigned long bus_addr, size_t len __unused ) {
	return ( bus_addr ? phys_to_virt ( bus_addr ) : NULL );
}

static inline __always_inline void
IOAPI_INLINE ( x86, iounmap ) ( volatile const void *io_addr __unused ) {
	/* Nothing to do */
}

static inline __always_inline unsigned long
IOAPI_INLINE ( x86, io_to_bus ) ( volatile const void *io_addr ) {
	return virt_to_phys ( io_addr );
}

/*
 * MMIO reads and writes up to native word size
 *
 */

#define X86_READX( _api_func, _type )					      \
static inline __always_inline _type					      \
IOAPI_INLINE ( x86, _api_func ) ( volatile _type *io_addr ) {		      \
	return *io_addr;						      \
}
X86_READX ( readb, uint8_t );
X86_READX ( readw, uint16_t );
X86_READX ( readl, uint32_t );
#ifdef __x86_64__
X86_READX ( readq, uint64_t );
#endif

#define X86_WRITEX( _api_func, _type )					      \
static inline __always_inline void					      \
IOAPI_INLINE ( x86, _api_func ) ( _type data,				      \
				  volatile _type *io_addr ) {		      \
	*io_addr = data;						      \
}
X86_WRITEX ( writeb, uint8_t );
X86_WRITEX ( writew, uint16_t );
X86_WRITEX ( writel, uint32_t );
#ifdef __x86_64__
X86_WRITEX ( writeq, uint64_t );
#endif

/*
 * PIO reads and writes up to 32 bits
 *
 */

#define X86_INX( _insn_suffix, _type, _reg_prefix )			      \
static inline __always_inline _type					      \
IOAPI_INLINE ( x86, in ## _insn_suffix ) ( volatile _type *io_addr ) {	      \
	_type data;							      \
	__asm__ __volatile__ ( "in" #_insn_suffix " %w1, %" _reg_prefix "0"   \
			       : "=a" ( data ) : "Nd" ( io_addr ) );	      \
	return data;							      \
}									      \
static inline __always_inline void					      \
IOAPI_INLINE ( x86, ins ## _insn_suffix ) ( volatile _type *io_addr,	      \
					    _type *data,		      \
					    unsigned int count ) {	      \
	unsigned int discard_D;						      \
	__asm__ __volatile__ ( "rep ins" #_insn_suffix			      \
			       : "=D" ( discard_D )			      \
			       : "d" ( io_addr ), "c" ( count ),	      \
				 "0" ( data ) );			      \
}
X86_INX ( b, uint8_t, "b" );
X86_INX ( w, uint16_t, "w" );
X86_INX ( l, uint32_t, "k" );

#define X86_OUTX( _insn_suffix, _type, _reg_prefix )			      \
static inline __always_inline void					      \
IOAPI_INLINE ( x86, out ## _insn_suffix ) ( _type data,			      \
					    volatile _type *io_addr ) {	      \
	__asm__ __volatile__ ( "out" #_insn_suffix " %" _reg_prefix "0, %w1"  \
			       : : "a" ( data ), "Nd" ( io_addr ) );	      \
}									      \
static inline __always_inline void					      \
IOAPI_INLINE ( x86, outs ## _insn_suffix ) ( volatile _type *io_addr,	      \
					     const _type *data,		      \
					     unsigned int count ) {	      \
	unsigned int discard_S;						      \
	__asm__ __volatile__ ( "rep outs" #_insn_suffix			      \
			       : "=S" ( discard_S )			      \
			       : "d" ( io_addr ), "c" ( count ),	      \
				 "0" ( data ) );			      \
}
X86_OUTX ( b, uint8_t, "b" );
X86_OUTX ( w, uint16_t, "w" );
X86_OUTX ( l, uint32_t, "k" );

/*
 * Slow down I/O
 *
 */

static inline __always_inline void
IOAPI_INLINE ( x86, iodelay ) ( void ) {
	__asm__ __volatile__ ( "outb %al, $0x80" );
}

/*
 * Memory barrier
 *
 */

static inline __always_inline void
IOAPI_INLINE ( x86, mb ) ( void ) {
	__asm__ __volatile__ ( "lock; addl $0, 0(%%esp)" : : : "memory" );
}

#endif /* _IPXE_X86_IO_H */
