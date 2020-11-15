#include <stdint.h>
#include <stdio.h>

__attribute__ (( noreturn, section ( ".text.null_trap" ) ))
void null_function_trap ( void ) {
	void *stack;

	/* 128 bytes of NOPs; the idea of this is that if something
	 * dereferences a NULL pointer and overwrites us, we at least
	 * have some chance of still getting to execute the printf()
	 * statement.
	 */
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );
	__asm__ __volatile__ ( "nop ; nop ; nop ; nop" );

	__asm__ __volatile__ ( "movl %%esp, %0" : "=r" ( stack ) );
	printf ( "NULL method called from %p (stack %p)\n", 
		 __builtin_return_address ( 0 ), stack );
	DBG_HD ( stack, 256 );
	while ( 1 ) {}
}
