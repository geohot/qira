/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <string.h>
#include <stdlib.h>
#include <ipxe/init.h>
#include <ipxe/dhcp.h>
#include <ipxe/settings.h>
#include <ipxe/malloc.h>
#include <ipxe/crypto.h>
#include <ipxe/asn1.h>
#include <ipxe/x509.h>
#include <ipxe/certstore.h>

/** @file
 *
 * Certificate store
 *
 */

/** Raw certificate data for all permanent stored certificates */
#undef CERT
#define CERT( _index, _path )						\
	extern char stored_cert_ ## _index ## _data[];			\
	extern char stored_cert_ ## _index ## _len[];			\
	__asm__ ( ".section \".rodata\", \"a\", @progbits\n\t"		\
		  "\nstored_cert_" #_index "_data:\n\t"			\
		  ".incbin \"" _path "\"\n\t"				\
		  "\nstored_cert_" #_index "_end:\n\t"			\
		  ".equ stored_cert_" #_index "_len, "			\
			"( stored_cert_" #_index "_end - "		\
			"  stored_cert_" #_index "_data )\n\t"		\
		  ".previous\n\t" );
CERT_ALL

/** Raw certificate cursors for all permanent stored certificates */
#undef CERT
#define CERT( _index, _path ) {						\
	.data = stored_cert_ ## _index ## _data,			\
	.len = ( size_t ) stored_cert_ ## _index ## _len, 		\
},
static struct asn1_cursor certstore_raw[] = {
	CERT_ALL
};

/** X.509 certificate structures for all permanent stored certificates */
static struct x509_certificate certstore_certs[ sizeof ( certstore_raw ) /
						sizeof ( certstore_raw[0] ) ];

/** Certificate store */
struct x509_chain certstore = {
	.refcnt = REF_INIT ( ref_no_free ),
	.links = LIST_HEAD_INIT ( certstore.links ),
};

/**
 * Mark stored certificate as most recently used
 *
 * @v cert		X.509 certificate
 * @ret cert		X.509 certificate
 */
static struct x509_certificate *
certstore_found ( struct x509_certificate *cert ) {

	/* Mark as most recently used */
	list_del ( &cert->store.list );
	list_add ( &cert->store.list, &certstore.links );
	DBGC2 ( &certstore, "CERTSTORE found certificate %s\n",
		x509_name ( cert ) );

	return cert;
}

/**
 * Find certificate in store
 *
 * @v raw		Raw certificate data
 * @ret cert		X.509 certificate, or NULL if not found
 */
struct x509_certificate * certstore_find ( struct asn1_cursor *raw ) {
	struct x509_certificate *cert;

	/* Search for certificate within store */
	list_for_each_entry ( cert, &certstore.links, store.list ) {
		if ( asn1_compare ( raw, &cert->raw ) == 0 )
			return certstore_found ( cert );
	}
	return NULL;
}

/**
 * Find certificate in store corresponding to a private key
 *
 * @v key		Private key
 * @ret cert		X.509 certificate, or NULL if not found
 */
struct x509_certificate * certstore_find_key ( struct asn1_cursor *key ) {
	struct x509_certificate *cert;

	/* Search for certificate within store */
	list_for_each_entry ( cert, &certstore.links, store.list ) {
		if ( pubkey_match ( cert->signature_algorithm->pubkey,
				    key->data, key->len,
				    cert->subject.public_key.raw.data,
				    cert->subject.public_key.raw.len ) == 0 )
			return certstore_found ( cert );
	}
	return NULL;
}

/**
 * Add certificate to store
 *
 * @v cert		X.509 certificate
 */
void certstore_add ( struct x509_certificate *cert ) {

	/* Add certificate to store */
	cert->store.cert = cert;
	x509_get ( cert );
	list_add ( &cert->store.list, &certstore.links );
	DBGC ( &certstore, "CERTSTORE added certificate %s\n",
	       x509_name ( cert ) );
}

/**
 * Discard a stored certificate
 *
 * @ret discarded	Number of cached items discarded
 */
static unsigned int certstore_discard ( void ) {
	struct x509_certificate *cert;

	/* Discard the least recently used certificate for which the
	 * only reference is held by the store itself.
	 */
	list_for_each_entry_reverse ( cert, &certstore.links, store.list ) {
		if ( cert->refcnt.count == 0 ) {
			DBGC ( &certstore, "CERTSTORE discarded certificate "
			       "%s\n", x509_name ( cert ) );
			list_del ( &cert->store.list );
			x509_put ( cert );
			return 1;
		}
	}
	return 0;
}

/** Certificate store cache discarder */
struct cache_discarder certstore_discarder __cache_discarder ( CACHE_NORMAL ) ={
	.discard = certstore_discard,
};

/**
 * Construct permanent certificate store
 *
 */
static void certstore_init ( void ) {
	struct asn1_cursor *raw;
	struct x509_certificate *cert;
	int i;
	int rc;

	/* Skip if we have no permanent stored certificates */
	if ( ! sizeof ( certstore_raw ) )
		return;

	/* Add certificates */
	for ( i = 0 ; i < ( int ) ( sizeof ( certstore_raw ) /
				    sizeof ( certstore_raw[0] ) ) ; i++ ) {

		/* Skip if certificate already present in store */
		raw = &certstore_raw[i];
		if ( ( cert = certstore_find ( raw ) ) != NULL ) {
			DBGC ( &certstore, "CERTSTORE permanent certificate %d "
			       "is a duplicate of %s\n", i, x509_name ( cert ));
			continue;
		}

		/* Parse certificate */
		cert = &certstore_certs[i];
		ref_init ( &cert->refcnt, ref_no_free );
		if ( ( rc = x509_parse ( cert, raw ) ) != 0 ) {
			DBGC ( &certstore, "CERTSTORE could not parse "
			       "permanent certificate %d: %s\n",
			       i, strerror ( rc ) );
			continue;
		}

		/* Add certificate to store.  Certificate will never
		 * be discarded from the store, since we retain a
		 * permanent reference to it.
		 */
		certstore_add ( cert );
		DBGC ( &certstore, "CERTSTORE permanent certificate %d is %s\n",
		       i, x509_name ( cert ) );
	}
}

/** Certificate store initialisation function */
struct init_fn certstore_init_fn __init_fn ( INIT_LATE ) = {
	.initialise = certstore_init,
};

/** Additional certificate setting */
static struct setting cert_setting __setting ( SETTING_CRYPTO, cert ) = {
	.name = "cert",
	.description = "Certificate",
	.tag = DHCP_EB_CERT,
	.type = &setting_type_hex,
};

/**
 * Apply certificate store configuration settings
 *
 * @ret rc		Return status code
 */
static int certstore_apply_settings ( void ) {
	static struct x509_certificate *cert = NULL;
	struct x509_certificate *old_cert;
	void *cert_data;
	int len;
	int rc;

	/* Record any existing additional certificate */
	old_cert = cert;
	cert = NULL;

	/* Add additional certificate, if any */
	if ( ( len = fetch_raw_setting_copy ( NULL, &cert_setting,
					      &cert_data ) ) >= 0 ) {
		if ( ( rc = x509_certificate ( cert_data, len, &cert ) ) == 0 ){
			DBGC ( &certstore, "CERTSTORE added additional "
			       "certificate %s\n", x509_name ( cert ) );
		} else {
			DBGC ( &certstore, "CERTSTORE could not parse "
			       "additional certificate: %s\n",
			       strerror ( rc ) );
			/* Do not fail; leave as an unusable certificate */
		}
		free ( cert_data );
	}

	/* Free old additional certificiate.  Do this after reparsing
	 * the additional certificate; in the common case that the
	 * certificate has not changed, this will allow the stored
	 * certificate to be reused.
	 */
	x509_put ( old_cert );

	return 0;
}

/** Certificate store settings applicator */
struct settings_applicator certstore_applicator __settings_applicator = {
	.apply = certstore_apply_settings,
};
