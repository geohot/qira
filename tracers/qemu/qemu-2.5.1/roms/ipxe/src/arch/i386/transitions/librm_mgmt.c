/*
 * librm: a library for interfacing to real-mode code
 *
 * Michael Brown <mbrown@fensystems.co.uk>
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/profile.h>
#include <realmode.h>
#include <pic8259.h>

/*
 * This file provides functions for managing librm.
 *
 */

/** The interrupt wrapper */
extern char interrupt_wrapper[];

/** The interrupt vectors */
static struct interrupt_vector intr_vec[NUM_INT];

/** The interrupt descriptor table */
struct interrupt_descriptor idt[NUM_INT] __attribute__ (( aligned ( 16 ) ));

/** The interrupt descriptor table register */
struct idtr idtr = {
	.limit = ( sizeof ( idt ) - 1 ),
};

/** Timer interrupt profiler */
static struct profiler timer_irq_profiler __profiler = { .name = "irq.timer" };

/** Other interrupt profiler */
static struct profiler other_irq_profiler __profiler = { .name = "irq.other" };

/**
 * Allocate space on the real-mode stack and copy data there from a
 * user buffer
 *
 * @v data		User buffer
 * @v size		Size of stack data
 * @ret sp		New value of real-mode stack pointer
 */
uint16_t copy_user_to_rm_stack ( userptr_t data, size_t size ) {
	userptr_t rm_stack;
	rm_sp -= size;
	rm_stack = real_to_user ( rm_ss, rm_sp );
	memcpy_user ( rm_stack, 0, data, 0, size );
	return rm_sp;
};

/**
 * Deallocate space on the real-mode stack, optionally copying back
 * data to a user buffer.
 *
 * @v data		User buffer
 * @v size		Size of stack data
 */
void remove_user_from_rm_stack ( userptr_t data, size_t size ) {
	if ( data ) {
		userptr_t rm_stack = real_to_user ( rm_ss, rm_sp );
		memcpy_user ( rm_stack, 0, data, 0, size );
	}
	rm_sp += size;
};

/**
 * Set interrupt vector
 *
 * @v intr		Interrupt number
 * @v vector		Interrupt vector, or NULL to disable
 */
void set_interrupt_vector ( unsigned int intr, void *vector ) {
	struct interrupt_descriptor *idte;

	idte = &idt[intr];
	idte->segment = VIRTUAL_CS;
	idte->attr = ( vector ? ( IDTE_PRESENT | IDTE_TYPE_IRQ32 ) : 0 );
	idte->low = ( ( ( uint32_t ) vector ) & 0xffff );
	idte->high = ( ( ( uint32_t ) vector ) >> 16 );
}

/**
 * Initialise interrupt descriptor table
 *
 */
void init_idt ( void ) {
	struct interrupt_vector *vec;
	unsigned int intr;

	/* Initialise the interrupt descriptor table and interrupt vectors */
	for ( intr = 0 ; intr < NUM_INT ; intr++ ) {
		vec = &intr_vec[intr];
		vec->pushal = PUSHAL_INSN;
		vec->movb = MOVB_INSN;
		vec->intr = intr;
		vec->jmp = JMP_INSN;
		vec->offset = ( ( uint32_t ) interrupt_wrapper -
				( uint32_t ) vec->next );
		set_interrupt_vector ( intr, vec );
	}
	DBGC ( &intr_vec[0], "INTn vector at %p+%zxn (phys %#lx+%zxn)\n",
	       intr_vec, sizeof ( intr_vec[0] ),
	       virt_to_phys ( intr_vec ), sizeof ( intr_vec[0] ) );

	/* Initialise the interrupt descriptor table register */
	idtr.base = virt_to_phys ( idt );
}

/**
 * Determine interrupt profiler (for debugging)
 *
 * @v intr		Interrupt number
 * @ret profiler	Profiler
 */
static struct profiler * interrupt_profiler ( int intr ) {

	switch ( intr ) {
	case IRQ_INT ( 0 ) :
		return &timer_irq_profiler;
	default:
		return &other_irq_profiler;
	}
}

/**
 * Interrupt handler
 *
 * @v intr		Interrupt number
 */
void __attribute__ (( cdecl, regparm ( 1 ) )) interrupt ( int intr ) {
	struct profiler *profiler = interrupt_profiler ( intr );
	uint32_t discard_eax;

	/* Reissue interrupt in real mode */
	profile_start ( profiler );
	__asm__ __volatile__ ( REAL_CODE ( "movb %%al, %%cs:(1f + 1)\n\t"
					   "\n1:\n\t"
					   "int $0x00\n\t" )
			       : "=a" ( discard_eax ) : "0" ( intr ) );
	profile_stop ( profiler );
	profile_exclude ( profiler );
}

PROVIDE_UACCESS_INLINE ( librm, phys_to_user );
PROVIDE_UACCESS_INLINE ( librm, user_to_phys );
PROVIDE_UACCESS_INLINE ( librm, virt_to_user );
PROVIDE_UACCESS_INLINE ( librm, user_to_virt );
PROVIDE_UACCESS_INLINE ( librm, userptr_add );
PROVIDE_UACCESS_INLINE ( librm, memcpy_user );
PROVIDE_UACCESS_INLINE ( librm, memmove_user );
PROVIDE_UACCESS_INLINE ( librm, memset_user );
PROVIDE_UACCESS_INLINE ( librm, strlen_user );
PROVIDE_UACCESS_INLINE ( librm, memchr_user );
