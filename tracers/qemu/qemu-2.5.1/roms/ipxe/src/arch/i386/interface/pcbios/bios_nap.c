#include <ipxe/nap.h>
#include <realmode.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Save power by halting the CPU until the next interrupt
 *
 */
static void bios_cpu_nap ( void ) {
	__asm__ __volatile__ ( "sti\n\t"
			       "hlt\n\t"
			       "cli\n\t" );
}

PROVIDE_NAP ( pcbios, cpu_nap, bios_cpu_nap );
