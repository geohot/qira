#ifndef _BITS_COMPILER_H
#define _BITS_COMPILER_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Dummy relocation type */
#define RELOC_TYPE_NONE R_386_NONE

#ifndef ASSEMBLY

/** Declare a function with standard calling conventions */
#define __asmcall __attribute__ (( cdecl, regparm(0) ))

/**
 * Declare a function with libgcc implicit linkage
 *
 * It seems as though gcc expects its implicit arithmetic functions to
 * be cdecl, even if -mrtd is specified.  This is somewhat
 * inconsistent; for example, if -mregparm=3 is used then the implicit
 * functions do become regparm(3).
 *
 * The implicit calls to memcpy() and memset() which gcc can generate
 * do not seem to have this inconsistency; -mregparm and -mrtd affect
 * them in the same way as any other function.
 *
 * Update (25/4/14): it appears that more recent gcc versions do allow
 * -mrtd to affect calls to the implicit arithmetic functions.  There
 * is nothing obvious in the gcc changelogs to indicate precisely when
 * this happened.  From experimentation with available gcc versions,
 * the change occurred sometime between v4.6.3 and v4.7.2.  We assume
 * that only versions up to v4.6.x require the special treatment.
 */
#if ( __GNUC__ < 4 ) || ( ( __GNUC__ == 4 ) && ( __GNUC_MINOR__ <= 6 ) )
#define __libgcc __attribute__ (( cdecl ))
#else
#define __libgcc
#endif

#endif /* ASSEMBLY */

#endif /* _BITS_COMPILER_H */
