#include <errno.h>
#include <realmode.h>
#include <biosint.h>

/**
 * @file BIOS interrupts
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Hook INT vector
 *
 * @v interrupt		INT number
 * @v handler		Offset within .text16 to interrupt handler
 * @v chain_vector	Vector for chaining to previous handler
 *
 * Hooks in an i386 INT handler.  The handler itself must reside
 * within the .text16 segment.  @c chain_vector will be filled in with
 * the address of the previously-installed handler for this interrupt;
 * the handler should probably exit by ljmping via this vector.
 */
void hook_bios_interrupt ( unsigned int interrupt, unsigned int handler,
			   struct segoff *chain_vector ) {
	struct segoff vector = {
		.segment = rm_cs,
		.offset = handler,
	};

	DBG ( "Hooking INT %#02x to %04x:%04x\n",
	      interrupt, rm_cs, handler );

	if ( ( chain_vector->segment != 0 ) ||
	     ( chain_vector->offset != 0 ) ) {
		/* Already hooked; do nothing */
		DBG ( "...already hooked\n" );
		return;
	}

	copy_from_real ( chain_vector, 0, ( interrupt * 4 ),
			 sizeof ( *chain_vector ) );
	DBG ( "...chaining to %04x:%04x\n",
	      chain_vector->segment, chain_vector->offset );
	if ( DBG_LOG ) {
		char code[64];
		copy_from_real ( code, chain_vector->segment,
				 chain_vector->offset, sizeof ( code ) );
		DBG_HDA ( *chain_vector, code, sizeof ( code ) );
	}

	copy_to_real ( 0, ( interrupt * 4 ), &vector, sizeof ( vector ) );
	hooked_bios_interrupts++;
}

/**
 * Unhook INT vector
 *
 * @v interrupt		INT number
 * @v handler		Offset within .text16 to interrupt handler
 * @v chain_vector	Vector containing address of previous handler
 *
 * Unhooks an i386 interrupt handler hooked by hook_i386_vector().
 * Note that this operation may fail, if some external code has hooked
 * the vector since we hooked in our handler.  If it fails, it means
 * that it is not possible to unhook our handler, and we must leave it
 * (and its chaining vector) resident in memory.
 */
int unhook_bios_interrupt ( unsigned int interrupt, unsigned int handler,
			    struct segoff *chain_vector ) {
	struct segoff vector;

	DBG ( "Unhooking INT %#02x from %04x:%04x\n",
	      interrupt, rm_cs, handler );

	copy_from_real ( &vector, 0, ( interrupt * 4 ), sizeof ( vector ) );
	if ( ( vector.segment != rm_cs ) || ( vector.offset != handler ) ) {
		DBG ( "...cannot unhook; vector points to %04x:%04x\n",
		      vector.segment, vector.offset );
		return -EBUSY;
	}

	DBG ( "...restoring to %04x:%04x\n",
	      chain_vector->segment, chain_vector->offset );
	copy_to_real ( 0, ( interrupt * 4 ), chain_vector,
		       sizeof ( *chain_vector ) );

	chain_vector->segment = 0;
	chain_vector->offset = 0;
	hooked_bios_interrupts--;
	return 0;
}
