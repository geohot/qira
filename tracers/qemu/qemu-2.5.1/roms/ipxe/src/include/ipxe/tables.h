#ifndef _IPXE_TABLES_H
#define _IPXE_TABLES_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @page ifdef_harmful #ifdef considered harmful
 *
 * Overuse of @c #ifdef has long been a problem in Etherboot.
 * Etherboot provides a rich array of features, but all these features
 * take up valuable space in a ROM image.  The traditional solution to
 * this problem has been for each feature to have its own @c #ifdef
 * option, allowing the feature to be compiled in only if desired.
 *
 * The problem with this is that it becomes impossible to compile, let
 * alone test, all possible versions of Etherboot.  Code that is not
 * typically used tends to suffer from bit-rot over time.  It becomes
 * extremely difficult to predict which combinations of compile-time
 * options will result in code that can even compile and link
 * correctly.
 *
 * To solve this problem, we have adopted a new approach from
 * Etherboot 5.5 onwards.  @c #ifdef is now "considered harmful", and
 * its use should be minimised.  Separate features should be
 * implemented in separate @c .c files, and should \b always be
 * compiled (i.e. they should \b not be guarded with a @c #ifdef @c
 * MY_PET_FEATURE statement).  By making (almost) all code always
 * compile, we avoid the problem of bit-rot in rarely-used code.
 *
 * The file config.h, in combination with the @c make command line,
 * specifies the objects that will be included in any particular build
 * of Etherboot.  For example, suppose that config.h includes the line
 *
 * @code
 *
 *   #define CONSOLE_SERIAL
 *   #define DOWNLOAD_PROTO_TFTP
 *
 * @endcode
 *
 * When a particular Etherboot image (e.g. @c bin/rtl8139.zdsk) is
 * built, the options specified in config.h are used to drag in the
 * relevant objects at link-time.  For the above example, serial.o and
 * tftp.o would be linked in.
 *
 * There remains one problem to solve: how do these objects get used?
 * Traditionally, we had code such as
 *
 * @code
 *
 *    #ifdef CONSOLE_SERIAL
 *      serial_init();
 *    #endif
 *
 * @endcode
 *
 * in main.c, but this reintroduces @c #ifdef and so is a Bad Idea.
 * We cannot simply remove the @c #ifdef and make it
 *
 * @code
 *
 *   serial_init();
 *
 * @endcode
 *
 * because then serial.o would end up always being linked in.
 *
 * The solution is to use @link tables.h linker tables @endlink.
 *
 */

/** @file
 *
 * Linker tables
 *
 * Read @ref ifdef_harmful first for some background on the motivation
 * for using linker tables.
 *
 * This file provides macros for dealing with linker-generated tables
 * of fixed-size symbols.  We make fairly extensive use of these in
 * order to avoid @c #ifdef spaghetti and/or linker symbol pollution.
 * For example, instead of having code such as
 *
 * @code
 *
 *    #ifdef CONSOLE_SERIAL
 *      serial_init();
 *    #endif
 *
 * @endcode
 *
 * we make serial.c generate an entry in the initialisation function
 * table, and then have a function call_init_fns() that simply calls
 * all functions present in this table.  If and only if serial.o gets
 * linked in, then its initialisation function will be called.  We
 * avoid linker symbol pollution (i.e. always dragging in serial.o
 * just because of a call to serial_init()) and we also avoid @c
 * #ifdef spaghetti (having to conditionalise every reference to
 * functions in serial.c).
 *
 * The linker script takes care of assembling the tables for us.  All
 * our table sections have names of the format @c .tbl.NAME.NN where
 * @c NAME designates the data structure stored in the table (e.g. @c
 * init_fns) and @c NN is a two-digit decimal number used to impose an
 * ordering upon the tables if required.  @c NN=00 is reserved for the
 * symbol indicating "table start", and @c NN=99 is reserved for the
 * symbol indicating "table end".
 *
 * As an example, suppose that we want to create a "frobnicator"
 * feature framework, and allow for several independent modules to
 * provide frobnicating services.  Then we would create a frob.h
 * header file containing e.g.
 *
 * @code
 *
 *   struct frobnicator {
 *      const char *name;		// Name of the frobnicator
 *	void ( *frob ) ( void ); 	// The frobnicating function itself
 *   };
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *
 *   #define __frobnicator __table_entry ( FROBNICATORS, 01 )
 *
 * @endcode
 *
 * Any module providing frobnicating services would look something
 * like
 *
 * @code
 *
 *   #include "frob.h"
 *
 *   static void my_frob ( void ) {
 *	// Do my frobnicating
 *	...
 *   }
 *
 *   struct frob my_frobnicator __frobnicator = {
 *	.name = "my_frob",
 *	.frob = my_frob,
 *   };
 *
 * @endcode
 *
 * The central frobnicator code (frob.c) would use the frobnicating
 * modules as follows
 *
 * @code
 *
 *   #include "frob.h"
 *
 *   // Call all linked-in frobnicators
 *   void frob_all ( void ) {
 *	struct frob *frob;
 *
 *	for_each_table ( frob, FROBNICATORS ) {
 *         printf ( "Calling frobnicator \"%s\"\n", frob->name );
 *	   frob->frob ();
 *	}
 *   }
 *
 * @endcode
 *
 * See init.h and init.c for a real-life example.
 *
 */

#ifdef DOXYGEN
#define __attribute__( x )
#endif

/**
 * Declare a linker table
 *
 * @v type		Data type
 * @v name		Table name
 * @ret table		Linker table
 */
#define __table( type, name ) ( type, name )

/**
 * Get linker table data type
 *
 * @v table		Linker table
 * @ret type		Data type
 */
#define __table_type( table ) __table_extract_type table
#define __table_extract_type( type, name ) type

/**
 * Get linker table name
 *
 * @v table		Linker table
 * @ret name		Table name
 */
#define __table_name( table ) __table_extract_name table
#define __table_extract_name( type, name ) name

/**
 * Get linker table section name
 *
 * @v table		Linker table
 * @v idx		Sub-table index
 * @ret section		Section name
 */
#define __table_section( table, idx ) \
	".tbl." __table_name ( table ) "." __table_str ( idx )
#define __table_str( x ) #x

/**
 * Get linker table alignment
 *
 * @v table		Linker table
 * @ret align		Alignment
 */
#define __table_alignment( table ) __alignof__ ( __table_type ( table ) )

/**
 * Declare a linker table entry
 *
 * @v table		Linker table
 * @v idx		Sub-table index
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *
 *   #define __frobnicator __table_entry ( FROBNICATORS, 01 )
 *
 *   struct frobnicator my_frob __frobnicator = {
 *      ...
 *   };
 *
 * @endcode
 */
#define __table_entry( table, idx )					\
	__attribute__ (( __section__ ( __table_section ( table, idx ) ),\
			 __aligned__ ( __table_alignment ( table ) ) ))

/**
 * Get start of linker table entries
 *
 * @v table		Linker table
 * @v idx		Sub-table index
 * @ret entries		Start of entries
 */
#define __table_entries( table, idx ) ( {				\
	static __table_type ( table ) __table_entries[0]		\
		__table_entry ( table, idx ) 				\
		__attribute__ (( unused ));				\
	__table_entries; } )

/**
 * Get start of linker table
 *
 * @v table		Linker table
 * @ret start		Start of linker table
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *
 *   struct frobnicator *frobs = table_start ( FROBNICATORS );
 *
 * @endcode
 */
#define table_start( table ) __table_entries ( table, 00 )

/**
 * Get end of linker table
 *
 * @v table		Linker table
 * @ret end		End of linker table
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *
 *   struct frobnicator *frobs_end = table_end ( FROBNICATORS );
 *
 * @endcode
 */
#define table_end( table ) __table_entries ( table, 99 )

/**
 * Get number of entries in linker table
 *
 * @v table		Linker table
 * @ret num_entries	Number of entries in linker table
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *
 *   unsigned int num_frobs = table_num_entries ( FROBNICATORS );
 *
 * @endcode
 *
 */
#define table_num_entries( table )					\
	( ( unsigned int ) ( table_end ( table ) -			\
			     table_start ( table ) ) )

/**
 * Get index of entry within linker table
 *
 * @v table		Linker table
 * @v entry		Table entry
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *
 *   #define __frobnicator __table_entry ( FROBNICATORS, 01 )
 *
 *   struct frobnicator my_frob __frobnicator = {
 *      ...
 *   };
 *
 *   unsigned int my_frob_idx = table_index ( FROBNICATORS, &my_frob );
 *
 * @endcode
 */
#define table_index( table, entry )					\
	( ( unsigned int ) ( (entry) - table_start ( table ) ) )

/**
 * Iterate through all entries within a linker table
 *
 * @v pointer		Entry pointer
 * @v table		Linker table
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *
 *   struct frobnicator *frob;
 *
 *   for_each_table_entry ( frob, FROBNICATORS ) {
 *     ...
 *   }
 *
 * @endcode
 *
 */
#define for_each_table_entry( pointer, table )				\
	for ( pointer = table_start ( table ) ;				\
	      pointer < table_end ( table ) ;				\
	      pointer++ )

/**
 * Iterate through all remaining entries within a linker table
 *
 * @v pointer		Entry pointer, preset to most recent entry
 * @v table		Linker table
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *   #define __frobnicator __table_entry ( FROBNICATORS, 01 )
 *
 *   struct frob my_frobnicator __frobnicator;
 *   struct frobnicator *frob;
 *
 *   frob = &my_frobnicator;
 *   for_each_table_entry_continue ( frob, FROBNICATORS ) {
 *     ...
 *   }
 *
 * @endcode
 *
 */
#define for_each_table_entry_continue( pointer, table )			\
	for ( pointer++ ;						\
	      pointer < table_end ( table ) ;				\
	      pointer++ )

/**
 * Iterate through all entries within a linker table in reverse order
 *
 * @v pointer		Entry pointer
 * @v table		Linker table
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *
 *   struct frobnicator *frob;
 *
 *   for_each_table_entry_reverse ( frob, FROBNICATORS ) {
 *     ...
 *   }
 *
 * @endcode
 *
 */
#define for_each_table_entry_reverse( pointer, table )			\
	for ( pointer = ( table_end ( table ) - 1 ) ;			\
	      pointer >= table_start ( table ) ;			\
	      pointer-- )

/**
 * Iterate through all remaining entries within a linker table in reverse order
 *
 * @v pointer		Entry pointer, preset to most recent entry
 * @v table		Linker table
 *
 * Example usage:
 *
 * @code
 *
 *   #define FROBNICATORS __table ( struct frobnicator, "frobnicators" )
 *   #define __frobnicator __table_entry ( FROBNICATORS, 01 )
 *
 *   struct frob my_frobnicator __frobnicator;
 *   struct frobnicator *frob;
 *
 *   frob = &my_frobnicator;
 *   for_each_table_entry_continue_reverse ( frob, FROBNICATORS ) {
 *     ...
 *   }
 *
 * @endcode
 *
 */
#define for_each_table_entry_continue_reverse( pointer, table )		\
	for ( pointer-- ;						\
	      pointer >= table_start ( table ) ;			\
	      pointer-- )

/******************************************************************************
 *
 * Intel's C compiler chokes on several of the constructs used in this
 * file.  The workarounds are ugly, so we use them only for an icc
 * build.
 *
 */
#define ICC_ALIGN_HACK_FACTOR 128
#ifdef __ICC

/*
 * icc miscompiles zero-length arrays by inserting padding to a length
 * of two array elements.  We therefore have to generate the
 * __table_entries() symbols by hand in asm.
 *
 */
#undef __table_entries
#define __table_entries( table, idx ) ( {				\
	extern __table_type ( table )					\
		__table_temp_sym ( idx, __LINE__ ) []			\
		__table_entry ( table, idx ) 				\
		asm ( __table_entries_sym ( table, idx ) );		\
	__asm__ ( ".ifndef %c0\n\t"					\
		  ".section " __table_section ( table, idx ) "\n\t"	\
		  ".align %c1\n\t"					\
	          "\n%c0:\n\t"						\
		  ".previous\n\t" 					\
		  ".endif\n\t"						\
		  : : "i" ( __table_temp_sym ( idx, __LINE__ ) ),	\
		      "i" ( __table_alignment ( table ) ) );		\
	__table_temp_sym ( idx, __LINE__ ); } )
#define __table_entries_sym( table, idx )				\
	"__tbl_" __table_name ( table ) "_" #idx
#define __table_temp_sym( a, b )					\
	___table_temp_sym( __table_, a, _, b )
#define ___table_temp_sym( a, b, c, d ) a ## b ## c ## d

/*
 * icc ignores __attribute__ (( aligned (x) )) when it is used to
 * decrease the compiler's default choice of alignment (which may be
 * higher than the alignment actually required by the structure).  We
 * work around this by forcing the alignment to a large multiple of
 * the required value (so that we are never attempting to decrease the
 * default alignment) and then postprocessing the object file to
 * reduce the alignment back down to the "real" value.
 *
 */
#undef __table_alignment
#define __table_alignment( table ) \
	( ICC_ALIGN_HACK_FACTOR * __alignof__ ( __table_type ( table ) ) )

/*
 * Because of the alignment hack, we must ensure that the compiler
 * never tries to place multiple objects within the same section,
 * otherwise the assembler will insert padding to the (incorrect)
 * alignment boundary.  Do this by appending the line number to table
 * section names.
 *
 * Note that we don't need to worry about padding between array
 * elements, since the alignment is declared on the variable (i.e. the
 * whole array) rather than on the type (i.e. on all individual array
 * elements).
 */
#undef __table_section
#define __table_section( table, idx ) \
	".tbl." __table_name ( table ) "." __table_str ( idx ) \
	"." __table_xstr ( __LINE__ )
#define __table_xstr( x ) __table_str ( x )

#endif /* __ICC */

#endif /* _IPXE_TABLES_H */
