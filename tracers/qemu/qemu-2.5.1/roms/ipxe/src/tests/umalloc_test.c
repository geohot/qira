#include <stdio.h>
#include <ipxe/uaccess.h>
#include <ipxe/umalloc.h>
#include <ipxe/io.h>

void umalloc_test ( void ) {
	struct memory_map memmap;
	userptr_t bob;
	userptr_t fred;

	printf ( "Before allocation:\n" );
	get_memmap ( &memmap );

	bob = umalloc ( 1234 );
	bob = urealloc ( bob, 12345 );
	fred = umalloc ( 999 );

	printf ( "After allocation:\n" );
	get_memmap ( &memmap );

	ufree ( bob );
	ufree ( fred );

	printf ( "After freeing:\n" );
	get_memmap ( &memmap );
}
