#ifndef _IPXE_VALIDATOR_H
#define _IPXE_VALIDATOR_H

/** @file
 *
 * Certificate validator
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/interface.h>
#include <ipxe/x509.h>

extern int create_validator ( struct interface *job, struct x509_chain *chain );

#endif /* _IPXE_VALIDATOR_H */
