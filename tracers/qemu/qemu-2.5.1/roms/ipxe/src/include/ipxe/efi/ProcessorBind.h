#ifndef _IPXE_EFI_PROCESSOR_BIND_H
#define _IPXE_EFI_PROCESSOR_BIND_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/*
 * EFI header files rely on having the CPU architecture directory
 * present in the search path in order to pick up ProcessorBind.h.  We
 * use this header file as a quick indirection layer.
 *  - mcb30
 */

#if __i386__
#include <ipxe/efi/Ia32/ProcessorBind.h>
#endif

#if __x86_64__
#include <ipxe/efi/X64/ProcessorBind.h>
#endif

#endif /* _IPXE_EFI_PROCESSOR_BIND_H */
