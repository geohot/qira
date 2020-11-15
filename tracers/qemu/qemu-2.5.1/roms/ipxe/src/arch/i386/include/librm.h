#ifndef LIBRM_H
#define LIBRM_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/* Segment selectors as used in our protected-mode GDTs.
 *
 * Don't change these unless you really know what you're doing.
 */

#define VIRTUAL_CS 0x08
#define VIRTUAL_DS 0x10
#define PHYSICAL_CS 0x18
#define PHYSICAL_DS 0x20
#define REAL_CS 0x28
#define REAL_DS 0x30
#if 0
#define LONG_CS 0x38
#define LONG_DS 0x40
#endif

#ifndef ASSEMBLY

#ifdef UACCESS_LIBRM
#define UACCESS_PREFIX_librm
#else
#define UACCESS_PREFIX_librm __librm_
#endif

/* Variables in librm.S */
extern unsigned long virt_offset;

/**
 * Convert physical address to user pointer
 *
 * @v phys_addr		Physical address
 * @ret userptr		User pointer
 */
static inline __always_inline userptr_t
UACCESS_INLINE ( librm, phys_to_user ) ( unsigned long phys_addr ) {
	return ( phys_addr - virt_offset );
}

/**
 * Convert user buffer to physical address
 *
 * @v userptr		User pointer
 * @v offset		Offset from user pointer
 * @ret phys_addr	Physical address
 */
static inline __always_inline unsigned long
UACCESS_INLINE ( librm, user_to_phys ) ( userptr_t userptr, off_t offset ) {
	return ( userptr + offset + virt_offset );
}

static inline __always_inline userptr_t
UACCESS_INLINE ( librm, virt_to_user ) ( volatile const void *addr ) {
	return trivial_virt_to_user ( addr );
}

static inline __always_inline void *
UACCESS_INLINE ( librm, user_to_virt ) ( userptr_t userptr, off_t offset ) {
	return trivial_user_to_virt ( userptr, offset );
}

static inline __always_inline userptr_t
UACCESS_INLINE ( librm, userptr_add ) ( userptr_t userptr, off_t offset ) {
	return trivial_userptr_add ( userptr, offset );
}

static inline __always_inline off_t
UACCESS_INLINE ( librm, userptr_sub ) ( userptr_t userptr,
					userptr_t subtrahend ) {
	return trivial_userptr_sub ( userptr, subtrahend );
}

static inline __always_inline void
UACCESS_INLINE ( librm, memcpy_user ) ( userptr_t dest, off_t dest_off,
					userptr_t src, off_t src_off,
					size_t len ) {
	trivial_memcpy_user ( dest, dest_off, src, src_off, len );
}

static inline __always_inline void
UACCESS_INLINE ( librm, memmove_user ) ( userptr_t dest, off_t dest_off,
					 userptr_t src, off_t src_off,
					 size_t len ) {
	trivial_memmove_user ( dest, dest_off, src, src_off, len );
}

static inline __always_inline int
UACCESS_INLINE ( librm, memcmp_user ) ( userptr_t first, off_t first_off,
					userptr_t second, off_t second_off,
					size_t len ) {
	return trivial_memcmp_user ( first, first_off, second, second_off, len);
}

static inline __always_inline void
UACCESS_INLINE ( librm, memset_user ) ( userptr_t buffer, off_t offset,
					int c, size_t len ) {
	trivial_memset_user ( buffer, offset, c, len );
}

static inline __always_inline size_t
UACCESS_INLINE ( librm, strlen_user ) ( userptr_t buffer, off_t offset ) {
	return trivial_strlen_user ( buffer, offset );
}

static inline __always_inline off_t
UACCESS_INLINE ( librm, memchr_user ) ( userptr_t buffer, off_t offset,
					int c, size_t len ) {
	return trivial_memchr_user ( buffer, offset, c, len );
}


/******************************************************************************
 *
 * Access to variables in .data16 and .text16
 *
 */

extern char *data16;
extern char *text16;

#define __data16( variable )						\
	__attribute__ (( section ( ".data16" ) ))			\
	_data16_ ## variable __asm__ ( #variable )

#define __data16_array( variable, array )				\
	__attribute__ (( section ( ".data16" ) ))			\
	_data16_ ## variable array __asm__ ( #variable )

#define __bss16( variable )						\
	__attribute__ (( section ( ".bss16" ) ))			\
	_data16_ ## variable __asm__ ( #variable )

#define __bss16_array( variable, array )				\
	__attribute__ (( section ( ".bss16" ) ))			\
	_data16_ ## variable array __asm__ ( #variable )

#define __text16( variable )						\
	__attribute__ (( section ( ".text16.data" ) ))			\
	_text16_ ## variable __asm__ ( #variable )

#define __text16_array( variable, array )				\
	__attribute__ (( section ( ".text16.data" ) ))			\
	_text16_ ## variable array __asm__ ( #variable )

#define __use_data16( variable )					\
	( * ( ( typeof ( _data16_ ## variable ) * )			\
	      & ( data16 [ ( size_t ) & ( _data16_ ## variable ) ] ) ) )

#define __use_text16( variable )					\
	( * ( ( typeof ( _text16_ ## variable ) * )			\
	      & ( text16 [ ( size_t ) & ( _text16_ ## variable ) ] ) ) )

#define __from_data16( pointer )					\
	( ( unsigned int )						\
	  ( ( ( void * ) (pointer) ) - ( ( void * ) data16 ) ) )

#define __from_text16( pointer )					\
	( ( unsigned int )						\
	  ( ( ( void * ) (pointer) ) - ( ( void * ) text16 ) ) )

/* Variables in librm.S, present in the normal data segment */
extern uint16_t rm_sp;
extern uint16_t rm_ss;
extern uint16_t __text16 ( rm_cs );
#define rm_cs __use_text16 ( rm_cs )
extern uint16_t __text16 ( rm_ds );
#define rm_ds __use_text16 ( rm_ds )

extern uint16_t copy_user_to_rm_stack ( userptr_t data, size_t size );
extern void remove_user_from_rm_stack ( userptr_t data, size_t size );

/* TEXT16_CODE: declare a fragment of code that resides in .text16 */
#define TEXT16_CODE( asm_code_str )			\
	".section \".text16\", \"ax\", @progbits\n\t"	\
	".code16\n\t"					\
	asm_code_str "\n\t"				\
	".code32\n\t"					\
	".previous\n\t"

/* REAL_CODE: declare a fragment of code that executes in real mode */
#define REAL_CODE( asm_code_str )			\
	"pushl $1f\n\t"					\
	"call real_call\n\t"				\
	"addl $4, %%esp\n\t"				\
	TEXT16_CODE ( "\n1:\n\t"			\
		      asm_code_str			\
		      "\n\t"				\
		      "ret\n\t" )

/* PHYS_CODE: declare a fragment of code that executes in flat physical mode */
#define PHYS_CODE( asm_code_str )			\
	"call _virt_to_phys\n\t"			\
	asm_code_str					\
	"call _phys_to_virt\n\t"

/** Number of interrupts */
#define NUM_INT 256

/** An interrupt descriptor table register */
struct idtr {
	/** Limit */
	uint16_t limit;
	/** Base */
	uint32_t base;
} __attribute__ (( packed ));

/** An interrupt descriptor table entry */
struct interrupt_descriptor {
	/** Low 16 bits of address */
	uint16_t low;
	/** Code segment */
	uint16_t segment;
	/** Unused */
	uint8_t unused;
	/** Type and attributes */
	uint8_t attr;
	/** High 16 bits of address */
	uint16_t high;
} __attribute__ (( packed ));

/** Interrupt descriptor is present */
#define IDTE_PRESENT 0x80

/** Interrupt descriptor 32-bit interrupt gate type */
#define IDTE_TYPE_IRQ32 0x0e

/** An interrupt vector
 *
 * Each interrupt vector comprises an eight-byte fragment of code:
 *
 *   60			pushal
 *   b0 xx		movb $INT, %al
 *   e9 xx xx xx xx	jmp interrupt_wrapper
 */
struct interrupt_vector {
	/** "pushal" instruction */
	uint8_t pushal;
	/** "movb" instruction */
	uint8_t movb;
	/** Interrupt number */
	uint8_t intr;
	/** "jmp" instruction */
	uint8_t jmp;
	/** Interrupt wrapper address offset */
	uint32_t offset;
	/** Next instruction after jump */
	uint8_t next[0];
} __attribute__ (( packed ));

/** "pushal" instruction */
#define PUSHAL_INSN 0x60

/** "movb" instruction */
#define MOVB_INSN 0xb0

/** "jmp" instruction */
#define JMP_INSN 0xe9

extern void set_interrupt_vector ( unsigned int intr, void *vector );

#endif /* ASSEMBLY */

#endif /* LIBRM_H */
