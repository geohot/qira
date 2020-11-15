#ifndef _BITS_COMPILER_H
#define _BITS_COMPILER_H

/** Dummy relocation type */
#define RELOC_TYPE_NONE R_X86_64_NONE

#ifndef ASSEMBLY

/** Declare a function with standard calling conventions */
#define __asmcall __attribute__ (( regparm(0) ))

/** Declare a function with libgcc implicit linkage */
#define __libgcc

#endif /* ASSEMBLY */

#endif /* _BITS_COMPILER_H */
