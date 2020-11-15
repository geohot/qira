#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ipxe/errortab.h>
#include <config/branding.h>

/** @file
 *
 * Error descriptions.
 *
 * The error numbers used by Etherboot are a superset of those defined
 * by the PXE specification version 2.1.  See errno.h for a listing of
 * the error values.
 *
 * To save space in ROM images, error string tables are optional.  Use
 * the ERRORMSG_XXX options in config.h to select which error string
 * tables you want to include.  If an error string table is omitted,
 * strerror() will simply return the text "Error 0x<errno>".
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Find error description
 *
 * @v errno		Error number
 * @ret errortab	Error description, or NULL
 */
static struct errortab * find_error ( int errno ) {
	struct errortab *errortab;

	for_each_table_entry ( errortab, ERRORTAB ) {
		if ( errortab->errno == errno )
			return errortab;
	}

	return NULL;
}

/**
 * Find closest error description
 *
 * @v errno		Error number
 * @ret errortab	Error description, or NULL
 *
 * 
 */
static struct errortab * find_closest_error ( int errno ) {
	struct errortab *errortab;

	/* First, look for an exact match */
	if ( ( errortab = find_error ( errno ) ) != NULL )
		return errortab;

	/* Second, try masking off the iPXE-specific bit and seeing if
	 * we have an entry for the generic POSIX error message.
	 */
	if ( ( errortab = find_error ( errno & 0x7f0000ff ) ) != NULL )
		return errortab;

	return NULL;
}

/**
 * Retrieve string representation of error number.
 *
 * @v errno/rc		Error number or return status code
 * @ret strerror	Pointer to error text
 *
 * If the error is not found in the linked-in error tables, generates
 * a generic "Error 0x<errno>" message.
 *
 * The pointer returned by strerror() is valid only until the next
 * call to strerror().
 *
 */
char * strerror ( int errno ) {
	static char errbuf[64];
	struct errortab *errortab;

	/* Allow for strerror(rc) as well as strerror(errno) */
	if ( errno < 0 )
		errno = -errno;

	/* Find the error description, if one exists */
	errortab = find_closest_error ( errno );

	/* Construct the error message */
	if ( errortab ) {
		snprintf ( errbuf, sizeof ( errbuf ),
			   "%s (" PRODUCT_ERROR_URI ")",
			   errortab->text, errno );
	} else {
		snprintf ( errbuf, sizeof ( errbuf ),
			   "Error %#08x (" PRODUCT_ERROR_URI ")",
			   errno, errno );
	}

	return errbuf;
}

/* Do not include ERRFILE portion in the numbers in the error table */
#undef ERRFILE
#define ERRFILE 0

/** The most common errors */
struct errortab common_errors[] __errortab = {
	__einfo_errortab ( EINFO_ENOERR ),
	__einfo_errortab ( EINFO_EACCES ),
	__einfo_errortab ( EINFO_ECANCELED ),
	__einfo_errortab ( EINFO_ECONNRESET ),
	__einfo_errortab ( EINFO_EINVAL ),
	__einfo_errortab ( EINFO_EIO ),
	__einfo_errortab ( EINFO_ENETUNREACH ),
	__einfo_errortab ( EINFO_ENODEV ),
	__einfo_errortab ( EINFO_ENOENT ),
	__einfo_errortab ( EINFO_ENOEXEC ),
	__einfo_errortab ( EINFO_ENOMEM ),
	__einfo_errortab ( EINFO_ENOSPC ),
	__einfo_errortab ( EINFO_ENOTCONN ),
	__einfo_errortab ( EINFO_ENOTSUP ),
	__einfo_errortab ( EINFO_EPERM ),
	__einfo_errortab ( EINFO_ERANGE ),
	__einfo_errortab ( EINFO_ETIMEDOUT ),
};
