#ifndef _IPXE_CERTSTORE_H
#define _IPXE_CERTSTORE_H

/** @file
 *
 * Certificate store
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/asn1.h>
#include <ipxe/x509.h>

extern struct x509_chain certstore;

extern struct x509_certificate * certstore_find ( struct asn1_cursor *raw );
extern struct x509_certificate * certstore_find_key ( struct asn1_cursor *key );
extern void certstore_add ( struct x509_certificate *cert );

#endif /* _IPXE_CERTSTORE_H */
