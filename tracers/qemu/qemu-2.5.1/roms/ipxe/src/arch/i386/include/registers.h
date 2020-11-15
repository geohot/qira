#ifndef REGISTERS_H
#define REGISTERS_H

/** @file
 *
 * i386 registers.
 *
 * This file defines data structures that allow easy access to i386
 * register dumps.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/**
 * A 16-bit general register.
 *
 * This type encapsulates a 16-bit register such as %ax, %bx, %cx,
 * %dx, %si, %di, %bp or %sp.
 *
 */
typedef union {
	struct {
		union {
			uint8_t l;
			uint8_t byte;
		};
		uint8_t h;
	} __attribute__ (( packed ));
	uint16_t word;
} __attribute__ (( packed )) reg16_t;

/**
 * A 32-bit general register.
 *
 * This type encapsulates a 32-bit register such as %eax, %ebx, %ecx,
 * %edx, %esi, %edi, %ebp or %esp.
 *
 */
typedef union {
	struct {
		union {
			uint8_t l;
			uint8_t byte;
		};
		uint8_t h;
	} __attribute__ (( packed ));
	uint16_t word;
	uint32_t dword;
} __attribute__ (( packed )) reg32_t;

/**
 * A 32-bit general register dump.
 *
 * This is the data structure that is created on the stack by the @c
 * pushal instruction, and can be read back using the @c popal
 * instruction.
 *
 */
struct i386_regs {
	union {
		uint16_t di;
		uint32_t edi;
	};
	union {
		uint16_t si;
		uint32_t esi;
	};
	union {
		uint16_t bp;
		uint32_t ebp;
	};
	union {
		uint16_t sp;
		uint32_t esp;
	};
	union {
		struct {
			uint8_t bl;
			uint8_t bh;
		} __attribute__ (( packed ));
		uint16_t bx;
		uint32_t ebx;
	};
	union {
		struct {
			uint8_t dl;
			uint8_t dh;
		} __attribute__ (( packed ));
		uint16_t dx;
		uint32_t edx;
	};
	union {
		struct {
			uint8_t cl;
			uint8_t ch;
		} __attribute__ (( packed ));
		uint16_t cx;
		uint32_t ecx;
	};
	union {
		struct {
			uint8_t al;
			uint8_t ah;
		} __attribute__ (( packed ));
		uint16_t ax;
		uint32_t eax;
	};
} __attribute__ (( packed ));

/**
 * A segment register dump.
 *
 * The i386 has no equivalent of the @c pushal or @c popal
 * instructions for the segment registers.  We adopt the convention of
 * always using the sequences
 *
 * @code
 *
 *   pushw %gs ; pushw %fs ; pushw %es ; pushw %ds ; pushw %ss ; pushw %cs
 *
 * @endcode
 *
 * and
 *
 * @code
 *
 *   addw $4, %sp ; popw %ds ; popw %es ; popw %fs ; popw %gs
 *
 * @endcode
 *
 * This is the data structure that is created and read back by these
 * instruction sequences.
 *
 */
struct i386_seg_regs {
	uint16_t cs;
	uint16_t ss;
	uint16_t ds;
	uint16_t es;
	uint16_t fs;
	uint16_t gs;
} __attribute__ (( packed ));

/**
 * A full register dump.
 *
 * This data structure is created by the instructions
 *
 * @code
 *
 *   pushfl
 *   pushal
 *   pushw %gs ; pushw %fs ; pushw %es ; pushw %ds ; pushw %ss ; pushw %cs
 *
 * @endcode
 *
 * and can be read back using the instructions
 *
 * @code
 *
 *   addw $4, %sp ; popw %ds ; popw %es ; popw %fs ; popw %gs
 *   popal
 *   popfl
 *
 * @endcode
 *
 * prot_call() and kir_call() create this data structure on the stack
 * and pass in a pointer to this structure.
 *
 */
struct i386_all_regs {
	struct i386_seg_regs segs;
	struct i386_regs regs;
	uint32_t flags;
} __attribute__ (( packed ));

/* Flags */
#define CF ( 1 <<  0 )
#define PF ( 1 <<  2 )
#define AF ( 1 <<  4 )
#define ZF ( 1 <<  6 )
#define SF ( 1 <<  7 )
#define OF ( 1 << 11 )

/* Segment:offset structure.  Note that the order within the structure
 * is offset:segment.
 */
struct segoff {
	uint16_t offset;
	uint16_t segment;
} __attribute__ (( packed ));

typedef struct segoff segoff_t;

#endif /* REGISTERS_H */
