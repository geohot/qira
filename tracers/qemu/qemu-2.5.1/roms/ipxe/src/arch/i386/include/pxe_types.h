#ifndef PXE_TYPES_H
#define PXE_TYPES_H

/** @file
 *
 * PXE data types
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <errno.h> /* PXE status codes */

/** @addtogroup pxe Preboot eXecution Environment (PXE) API
 *  @{
 */

/** @defgroup pxe_types PXE data types
 *
 * Basic PXE data types such as #UINT16_t, #ADDR32_t, #SEGSEL_t etc.
 *
 * These definitions are based on Table 1-1 ("Data Type Definitions")
 * in the Intel PXE specification version 2.1.  They have been
 * generalised to non-x86 architectures where possible.
 *
 * @{
 */

/** An 8-bit unsigned integer */
typedef uint8_t UINT8_t;

/** A 16-bit unsigned integer */
typedef uint16_t UINT16_t;

/** A 32-bit unsigned integer */
typedef uint32_t UINT32_t;

/** A PXE exit code.
 *
 * Permitted values are #PXENV_EXIT_SUCCESS and #PXENV_EXIT_FAILURE.
 *
 */
typedef UINT16_t PXENV_EXIT_t;
#define PXENV_EXIT_SUCCESS	0x0000	/**< No error occurred */
#define PXENV_EXIT_FAILURE	0x0001	/**< An error occurred */

/** A PXE status code.
 *
 * Status codes are defined in errno.h.
 *
 */
typedef UINT16_t PXENV_STATUS_t;

/** An IPv4 address.
 *
 * @note This data type is in network (big-endian) byte order.
 *
 */
typedef UINT32_t IP4_t;

/** A UDP port.
 *
 * @note This data type is in network (big-endian) byte order.
 *
 */
typedef UINT16_t UDP_PORT_t;

/** Maximum length of a MAC address */
#define MAC_ADDR_LEN 16

/** A MAC address */
typedef UINT8_t MAC_ADDR_t[MAC_ADDR_LEN];

#ifndef HAVE_ARCH_ADDR32
/** A physical address.
 *
 * For x86, this is a 32-bit physical address, and is therefore
 * limited to the low 4GB.
 *
 */
typedef UINT32_t ADDR32_t;
#endif

#ifndef HAVE_ARCH_SEGSEL
/** A segment selector.
 *
 * For x86, this is a real mode segment (0x0000-0xffff), or a
 * protected-mode segment selector, such as could be loaded into a
 * segment register.
 *
 */
typedef UINT16_t SEGSEL_t;
#endif

#ifndef HAVE_ARCH_OFF16
/** An offset within a segment identified by #SEGSEL
 *
 * For x86, this is a 16-bit offset.
 *
 */
typedef UINT16_t OFF16_t;
#endif

/** A segment:offset address
 *
 * For x86, this is a 16-bit real-mode or protected-mode
 * segment:offset address.
 *
 */
typedef struct s_SEGOFF16 {
	OFF16_t		offset;		/**< Offset within the segment */
	SEGSEL_t	segment;	/**< Segment selector */
} __attribute__ (( packed )) SEGOFF16_t;

/** A segment descriptor */
typedef struct s_SEGDESC {
	SEGSEL_t	segment_address;	/**< Segment selector */
	ADDR32_t	Physical_address;	/**< Segment base address */
	OFF16_t		Seg_size;		/**< Size of the segment */
} __attribute__ (( packed )) SEGDESC_t;

/** @} */ /* pxe_types */

/** @} */ /* pxe */

#endif /* PXE_TYPES_H */
