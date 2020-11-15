#ifndef STDDEF_H
#define STDDEF_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/** EFI headers also define NULL */
#undef NULL

/** Null pointer */
#define NULL ( ( void * ) 0 )

/**
 * Get offset of a field within a structure
 *
 * @v type		Structure type
 * @v field		Field within structure
 * @ret offset		Offset within structure
 */
#if defined ( __GNUC__ ) && ( __GNUC__ > 3 )
#define offsetof( type, field ) __builtin_offsetof ( type, field )
#else
#define offsetof( type, field ) ( ( size_t ) &( ( ( type * ) NULL )->field ) )
#endif

/**
 * Get containing structure
 *
 * @v ptr		Pointer to contained field
 * @v type		Containing structure type
 * @v field		Field within containing structure
 * @ret container	Pointer to containing structure
 */
#define container_of( ptr, type, field ) ( {				\
	type *__container;						\
	const typeof ( __container->field ) *__field = (ptr);		\
	__container = ( ( ( void * ) __field ) -			\
			offsetof ( type, field ) );			\
	__container; } )

/* __WCHAR_TYPE__ is defined by gcc and will change if -fshort-wchar is used */
#ifndef __WCHAR_TYPE__
#define __WCHAR_TYPE__ uint16_t
#endif
#ifndef __WINT_TYPE__
#define __WINT_TYPE__ int
#endif
typedef __WCHAR_TYPE__ wchar_t;
typedef __WINT_TYPE__ wint_t;

#endif /* STDDEF_H */
