/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

#ifndef ERRNO_H
#define ERRNO_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * Error codes
 *
 * Return status codes as used within iPXE are designed to allow for
 * maximum visibility into the source of an error even in an end-user
 * build with no debugging.  They are constructed as follows:
 *
 * Bits 7-0 : Platform-specific error code
 *
 * This is a losslessly compressed representation of the closest
 * equivalent error code defined by the platform (e.g. BIOS/PXE or
 * EFI).  It is used to generate errors to be returned to external
 * code.
 *
 * Bits 12-8 : Per-file disambiguator
 *
 * When the same error code can be generated from multiple points
 * within a file, this field can be used to identify the unique
 * instance.
 *
 * Bits 23-13 : File identifier
 *
 * This is a unique identifier for the file generating the error
 * (e.g. ERRFILE_tcp for tcp.c).
 *
 * Bits 30-24 : POSIX error code
 *
 * This is the closest equivalent POSIX error code (e.g. ENOMEM).
 *
 * Bit 31 : Reserved
 *
 * Errors are usually return as negative error codes (e.g. -EINVAL);
 * bit 31 is therefore unusable.
 *
 *
 * The convention within the code is that errors are negative and
 * expressed using the POSIX error, e.g.
 *
 *     return -EINVAL;
 *
 * By various bits of preprocessor magic, the platform-specific error
 * code and file identifier are already incorporated into the
 * definition of the POSIX error macro, which keeps the code
 * relatively clean.
 *
 *
 * Functions that wish to return failures should be declared as
 * returning an integer @c rc "Return status code".  A return value of
 * zero indicates success, a non-zero value indicates failure.  The
 * return value can be passed directly to strerror() in order to
 * generate a human-readable error message, e.g.
 *
 *     if ( ( rc = some_function ( ... ) ) != 0 ) {
 *         DBG ( "Whatever I was trying to do failed: %s\n", strerror ( rc ) );
 *         return rc;
 *     }
 *
 * As illustrated in the above example, error returns should generally
 * be directly propagated upward to the calling function.
 *
 *
 * Individual files may declare localised errors using
 * __einfo_uniqify().  For example, iscsi.c declares a localised
 * version of EACCES for the error of "access denied due to incorrect
 * target username":
 *
 *     #define EACCES_INCORRECT_TARGET_USERNAME	\
 *         __einfo_error ( EINFO_EACCES_INCORRECT_TARGET_USERNAME )
 *     #define EINFO_EACCES_INCORRECT_TARGET_USERNAME \
 *         __einfo_uniqify ( EINFO_EACCESS, 0x01, "Incorrect target username" )
 *
 * which can then be used as:
 *
 *     return -EACCES_INCORRECT_TARGET_USERNAME;
 *
 */

/* Get definitions for platform-specific error codes */
#define PLATFORM_ERRNO(_platform) <ipxe/errno/_platform.h>
#include PLATFORM_ERRNO(PLATFORM)

/* Get definitions for file identifiers */
#include <ipxe/errfile.h>

/* If we do not have a valid file identifier, generate a compiler
 * warning upon usage of any error codes.  (Don't just use a #warning,
 * because some files include errno.h but don't ever actually use any
 * error codes.)
 */
#if ! ERRFILE
extern char missing_errfile_declaration[] __attribute__ (( deprecated ));
#undef ERRFILE
#define ERRFILE ( ( int ) ( 0 * ( ( intptr_t ) missing_errfile_declaration ) ) )
#endif

/**
 * Declare error information
 *
 * @v platform		Platform error code (uncompressed)
 * @v posix		POSIX error code (0x00-0x7f)
 * @v uniq		Error disambiguator (0x00-0x1f)
 * @v desc		Error description
 * @ret einfo		Error information
 */
#define __einfo( platform, posix, uniq, desc ) ( platform, posix, uniq, desc )

/**
 * Get platform error code
 *
 * @v einfo		Error information
 * @ret platform	Platform error code (uncompressed)
 */
#define __einfo_platform( einfo ) __einfo_extract_platform einfo
#define __einfo_extract_platform( platform, posix, uniq, desc ) platform

/**
 * Get POSIX error code
 *
 * @v einfo		Error information
 * @ret posix		POSIX error code
 */
#define __einfo_posix( einfo ) __einfo_extract_posix einfo
#define __einfo_extract_posix( platform, posix, uniq, desc ) posix

/**
 * Get error disambiguator
 *
 * @v einfo		Error information
 * @ret uniq		Error disambiguator
 */
#define __einfo_uniq( einfo ) __einfo_extract_uniq einfo
#define __einfo_extract_uniq( platform, posix, uniq, desc ) uniq

/**
 * Get error description
 *
 * @v einfo		Error information
 * @ret desc		Error description
 */
#define __einfo_desc( einfo ) __einfo_extract_desc einfo
#define __einfo_extract_desc( platform, posix, uniq, desc ) desc

/**
 * Declare disambiguated error
 *
 * @v einfo_base	Base error information
 * @v uniq		Error disambiguator (0x00-0x1f)
 * @v desc		Error description
 * @ret einfo		Error information
 */
#define __einfo_uniqify( einfo_base, uniq, desc )			\
	__einfo ( __einfo_platform ( einfo_base ),			\
		  __einfo_posix ( einfo_base ),				\
		  uniq, desc )

/**
 * Declare platform-generated error
 *
 * @v einfo_base	Base error information
 * @v platform		Platform error code (uncompressed)
 * @v desc		Error description
 * @ret einfo		Error information
 */
#define __einfo_platformify( einfo_base, platform, desc )		\
	__einfo ( platform, __einfo_posix ( einfo_base ),		\
		  __einfo_uniq ( einfo_base ), desc )

/**
 * Get error code
 *
 * @v einfo		Error information
 * @ret errno		Error code
 */
#define __einfo_errno( einfo )						\
	( ( int )							\
	  ( ( __einfo_posix ( einfo ) << 24 ) | ( ERRFILE ) |		\
	    ( __einfo_uniq ( einfo ) << 8 ) |				\
	    ( PLATFORM_TO_ERRNO ( __einfo_platform ( einfo ) ) << 0 ) ) )

/**
 * Disambiguate a base error based on non-constant information
 *
 * @v einfo_base	Base error information
 * @v uniq		Error disambiguator (0x00-0x1f)
 * @v ...		List of expected possible disambiguated errors
 * @ret error		Error
 *
 * EUNIQ() should be used when information from an external source is
 * being incorporated into an error.  For example, the 802.11 stack
 * uses EUNIQ() to incorporate 802.11 status codes returned by an
 * access point into an error.
 *
 * EUNIQ() should not be used for constant error disambiguators; use
 * __einfo_uniqify() instead.
 */
#define EUNIQ( einfo_base, uniq, ... ) ( {				\
	euniq_discard ( 0, ##__VA_ARGS__ );				\
	( ( int ) ( __einfo_error ( einfo_base ) |			\
		    ( (uniq) << 8 ) ) ); } )
static inline void euniq_discard ( int dummy __unused, ... ) {}

/**
 * Generate an error based on an external platform error code
 *
 * @v einfo_base	Base error information
 * @v platform		Platform error code (uncompressed)
 * @v ...		List of expected possible platform-generated errors
 * @ret error		Error
 *
 * EPLATFORM() should be used when a platform error code resulting
 * from an external platform API call is being incorporated into an
 * error.  For example, EFI code uses EPLATFORM() to generate errors
 * resulting from calls to EFI APIs such as
 * InstallMultipleProtocolInterfaces().
 *
 * EPLATFORM() should not be used for constant platform-generated
 * errors; use __einfo_platformify() instead.
 */
#define EPLATFORM( einfo_base, platform, ... ) ( {			\
	eplatform_discard ( 0, ##__VA_ARGS__ );				\
	( ( int ) ( __einfo_error ( einfo_base ) |			\
		    PLATFORM_TO_ERRNO ( platform ) ) ); } )
static inline void eplatform_discard ( int dummy __unused, ... ) {}

/**
 * Declare error
 *
 * @v einfo		Error information
 * @ret error		Error
 */
#define __einfo_error( einfo ) ( {					\
	__asm__ ( ".section \".einfo\", \"\", @progbits\n\t"		\
		  ".align 8\n\t"					\
		  "\n1:\n\t"						\
		  ".long ( 4f - 1b )\n\t"				\
		  ".long %c0\n\t"					\
		  ".long ( 2f - 1b )\n\t"				\
		  ".long ( 3f - 1b )\n\t"				\
		  ".long %c1\n\t"					\
		  "\n2:\t.asciz \"" __einfo_desc ( einfo ) "\"\n\t"	\
		  "\n3:\t.asciz \"" __FILE__ "\"\n\t"			\
		  ".align 8\n\t"					\
		  "\n4:\n\t"						\
		  ".previous\n\t" : :					\
		  "i" ( __einfo_errno ( einfo ) ),			\
		  "i" ( __LINE__ ) );					\
	__einfo_errno ( einfo ); } )

/**
 * @defgroup posixerrors POSIX error codes
 *
 * The names and meanings (but not the values) of these error codes
 * are defined by POSIX.
 *
 * @{
 */

/** Operation completed successfully */
#define ENOERR __einfo_error ( EINFO_ENOERR )
#define EINFO_ENOERR __einfo ( PLATFORM_ENOERR, 0x00, 0, \
			       "Operation completed successfully" )

/** Argument list too long */
#define E2BIG __einfo_error ( EINFO_E2BIG )
#define EINFO_E2BIG __einfo ( PLATFORM_E2BIG, 0x01, 0, \
			      "Argument list too long" )

/** Permission denied */
#define EACCES __einfo_error ( EINFO_EACCES )
#define EINFO_EACCES __einfo ( PLATFORM_EACCES, 0x02, 0, \
			       "Permission denied" )

/** Address already in use */
#define EADDRINUSE __einfo_error ( EINFO_EADDRINUSE )
#define EINFO_EADDRINUSE __einfo ( PLATFORM_EADDRINUSE, 0x03, 0, \
				   "Address already in use" )

/** Address not available */
#define EADDRNOTAVAIL __einfo_error ( EINFO_EADDRNOTAVAIL )
#define EINFO_EADDRNOTAVAIL __einfo ( PLATFORM_EADDRNOTAVAIL, 0x04, 0, \
				      "Address not available" )

/** Address family not supported */
#define EAFNOSUPPORT __einfo_error ( EINFO_EAFNOSUPPORT )
#define EINFO_EAFNOSUPPORT __einfo ( PLATFORM_EAFNOSUPPORT, 0x05, 0, \
				     "Address family not supported" )

/** Resource temporarily unavailable */
#define EAGAIN __einfo_error ( EINFO_EAGAIN )
#define EINFO_EAGAIN __einfo ( PLATFORM_EAGAIN, 0x06, 0, \
			       "Resource temporarily unavailable" )

/** Connection already in progress */
#define EALREADY __einfo_error ( EINFO_EALREADY )
#define EINFO_EALREADY __einfo ( PLATFORM_EALREADY, 0x07, 0, \
				 "Connection already in progress" )

/** Bad file descriptor */
#define EBADF __einfo_error ( EINFO_EBADF )
#define EINFO_EBADF __einfo ( PLATFORM_EBADF, 0x08, 0, \
			      "Bad file descriptor" )

/** Bad message */
#define EBADMSG __einfo_error ( EINFO_EBADMSG )
#define EINFO_EBADMSG __einfo ( PLATFORM_EBADMSG, 0x09, 0, \
				"Bad message" )

/** Device or resource busy */
#define EBUSY __einfo_error ( EINFO_EBUSY )
#define EINFO_EBUSY __einfo ( PLATFORM_EBUSY, 0x0a, 0, \
			      "Device or resource busy" )

/** Operation canceled */
#define ECANCELED __einfo_error ( EINFO_ECANCELED )
#define EINFO_ECANCELED __einfo ( PLATFORM_ECANCELED, 0x0b, 0, \
				  "Operation canceled" )

/** No child processes */
#define ECHILD __einfo_error ( EINFO_ECHILD )
#define EINFO_ECHILD __einfo ( PLATFORM_ECHILD, 0x0c, 0, \
			       "No child processes" )

/** Connection aborted */
#define ECONNABORTED __einfo_error ( EINFO_ECONNABORTED )
#define EINFO_ECONNABORTED __einfo ( PLATFORM_ECONNABORTED, 0x0d, 0, \
				     "Connection aborted" )

/** Connection refused */
#define ECONNREFUSED __einfo_error ( EINFO_ECONNREFUSED )
#define EINFO_ECONNREFUSED __einfo ( PLATFORM_ECONNREFUSED, 0x0e, 0, \
				     "Connection refused" )

/** Connection reset */
#define ECONNRESET __einfo_error ( EINFO_ECONNRESET )
#define EINFO_ECONNRESET __einfo ( PLATFORM_ECONNRESET, 0x0f, 0, \
				   "Connection reset" )

/** Resource deadlock avoided */
#define EDEADLK __einfo_error ( EINFO_EDEADLK )
#define EINFO_EDEADLK __einfo ( PLATFORM_EDEADLK, 0x10, 0, \
				"Resource deadlock avoided" )

/** Destination address required */
#define EDESTADDRREQ __einfo_error ( EINFO_EDESTADDRREQ )
#define EINFO_EDESTADDRREQ __einfo ( PLATFORM_EDESTADDRREQ, 0x11, 0, \
				     "Destination address required" )

/** Mathematics argument out of domain of function */
#define EDOM __einfo_error ( EINFO_EDOM )
#define EINFO_EDOM __einfo ( PLATFORM_EDOM, 0x12, 0, \
			     "Mathematics argument out of domain of function" )

/** Disk quota exceeded */
#define EDQUOT __einfo_error ( EINFO_EDQUOT )
#define EINFO_EDQUOT __einfo ( PLATFORM_EDQUOT, 0x13, 0, \
			       "Disk quote exceeded" )

/** File exists */
#define EEXIST __einfo_error ( EINFO_EEXIST )
#define EINFO_EEXIST __einfo ( PLATFORM_EEXIST, 0x14, 0, \
			       "File exists" )

/** Bad address */
#define EFAULT __einfo_error ( EINFO_EFAULT )
#define EINFO_EFAULT __einfo ( PLATFORM_EFAULT, 0x15, 0, \
			       "Bad address" )

/** File too large */
#define EFBIG __einfo_error ( EINFO_EFBIG )
#define EINFO_EFBIG __einfo ( PLATFORM_EFBIG, 0x16, 0, \
			      "File too large" )

/** Host is unreachable */
#define EHOSTUNREACH __einfo_error ( EINFO_EHOSTUNREACH )
#define EINFO_EHOSTUNREACH __einfo ( PLATFORM_EHOSTUNREACH, 0x17, 0, \
				     "Host is unreachable" )

/** Identifier removed */
#define EIDRM __einfo_error ( EINFO_EIDRM )
#define EINFO_EIDRM __einfo ( PLATFORM_EIDRM, 0x18, 0, \
			      "Identifier removed" )

/** Illegal byte sequence */
#define EILSEQ __einfo_error ( EINFO_EILSEQ )
#define EINFO_EILSEQ __einfo ( PLATFORM_EILSEQ, 0x19, 0, \
			       "Illegal byte sequence" )

/** Operation in progress */
#define EINPROGRESS __einfo_error ( EINFO_EINPROGRESS )
#define EINFO_EINPROGRESS __einfo ( PLATFORM_EINPROGRESS, 0x1a, 0, \
				    "Operation in progress" )

/** Interrupted function call */
#define EINTR __einfo_error ( EINFO_EINTR )
#define EINFO_EINTR __einfo ( PLATFORM_EINTR, 0x1b, 0, \
			      "Interrupted function call" )

/** Invalid argument */
#define EINVAL __einfo_error ( EINFO_EINVAL )
#define EINFO_EINVAL __einfo ( PLATFORM_EINVAL, 0x1c, 0, \
			       "Invalid argument" )

/** Input/output error */
#define EIO __einfo_error ( EINFO_EIO )
#define EINFO_EIO __einfo ( PLATFORM_EIO, 0x1d, 0, \
			    "Input/output error" )

/** Socket is connected */
#define EISCONN __einfo_error ( EINFO_EISCONN )
#define EINFO_EISCONN __einfo ( PLATFORM_EISCONN, 0x1e, 0, \
				"Socket is connected" )

/** Is a directory */
#define EISDIR __einfo_error ( EINFO_EISDIR )
#define EINFO_EISDIR __einfo ( PLATFORM_EISDIR, 0x1f, 0, \
			       "Is a directory" )

/** Too many levels of symbolic links */
#define ELOOP __einfo_error ( EINFO_ELOOP )
#define EINFO_ELOOP __einfo ( PLATFORM_ELOOP, 0x20, 0, \
			      "Too many levels of symbolic links" )

/** Too many open files */
#define EMFILE __einfo_error ( EINFO_EMFILE )
#define EINFO_EMFILE __einfo ( PLATFORM_EMFILE, 0x21, 0, \
			       "Too many open files" )

/** Too many links */
#define EMLINK __einfo_error ( EINFO_EMLINK )
#define EINFO_EMLINK __einfo ( PLATFORM_EMLINK, 0x22, 0, \
			       "Too many links" )

/** Message too long */
#define EMSGSIZE __einfo_error ( EINFO_EMSGSIZE )
#define EINFO_EMSGSIZE __einfo ( PLATFORM_EMSGSIZE, 0x23, 0, \
				 "Message too long" )

/** Multihop attempted */
#define EMULTIHOP __einfo_error ( EINFO_EMULTIHOP )
#define EINFO_EMULTIHOP __einfo ( PLATFORM_EMULTIHOP, 0x24, 0, \
				  "Multihop attempted" )

/** Filename too long */
#define ENAMETOOLONG __einfo_error ( EINFO_ENAMETOOLONG )
#define EINFO_ENAMETOOLONG __einfo ( PLATFORM_ENAMETOOLONG, 0x25, 0, \
				     "Filename too long" )

/** Network is down */
#define ENETDOWN __einfo_error ( EINFO_ENETDOWN )
#define EINFO_ENETDOWN __einfo ( PLATFORM_ENETDOWN, 0x26, 0, \
				 "Network is down" )

/** Connection aborted by network */
#define ENETRESET __einfo_error ( EINFO_ENETRESET )
#define EINFO_ENETRESET __einfo ( PLATFORM_ENETRESET, 0x27, 0, \
				  "Connection aborted by network" )

/** Network unreachable */
#define ENETUNREACH __einfo_error ( EINFO_ENETUNREACH )
#define EINFO_ENETUNREACH __einfo ( PLATFORM_ENETUNREACH, 0x28, 0, \
				    "Network unreachable" )

/** Too many open files in system */
#define ENFILE __einfo_error ( EINFO_ENFILE )
#define EINFO_ENFILE __einfo ( PLATFORM_ENFILE, 0x29, 0, \
			       "Too many open files in system" )

/** No buffer space available */
#define ENOBUFS __einfo_error ( EINFO_ENOBUFS )
#define EINFO_ENOBUFS __einfo ( PLATFORM_ENOBUFS, 0x2a, 0, \
				"No buffer space available" )

/** No message is available on the STREAM head read queue */
#define ENODATA __einfo_error ( EINFO_ENODATA )
#define EINFO_ENODATA __einfo ( PLATFORM_ENODATA, 0x2b, 0, \
				"No message is available on the STREAM " \
				"head read queue" )

/** No such device */
#define ENODEV __einfo_error ( EINFO_ENODEV )
#define EINFO_ENODEV __einfo ( PLATFORM_ENODEV, 0x2c, 0, \
			       "No such device" )

/** No such file or directory */
#define ENOENT __einfo_error ( EINFO_ENOENT )
#define EINFO_ENOENT __einfo ( PLATFORM_ENOENT, 0x2d, 0, \
			       "No such file or directory" )

/** Exec format error */
#define ENOEXEC __einfo_error ( EINFO_ENOEXEC )
#define EINFO_ENOEXEC __einfo ( PLATFORM_ENOEXEC, 0x2e, 0, \
				"Exec format error" )

/** No locks available */
#define ENOLCK __einfo_error ( EINFO_ENOLCK )
#define EINFO_ENOLCK __einfo ( PLATFORM_ENOLCK, 0x2f, 0, \
			       "No locks available" )

/** Link has been severed */
#define ENOLINK __einfo_error ( EINFO_ENOLINK )
#define EINFO_ENOLINK __einfo ( PLATFORM_ENOLINK, 0x30, 0, \
				"Link has been severed" )

/** Not enough space */
#define ENOMEM __einfo_error ( EINFO_ENOMEM )
#define EINFO_ENOMEM __einfo ( PLATFORM_ENOMEM, 0x31, 0, \
			       "Not enough space" )

/** No message of the desired type */
#define ENOMSG __einfo_error ( EINFO_ENOMSG )
#define EINFO_ENOMSG __einfo ( PLATFORM_ENOMSG, 0x32, 0, \
			       "No message of the desired type" )

/** Protocol not available */
#define ENOPROTOOPT __einfo_error ( EINFO_ENOPROTOOPT )
#define EINFO_ENOPROTOOPT __einfo ( PLATFORM_ENOPROTOOPT, 0x33, 0, \
				    "Protocol not available" )

/** No space left on device */
#define ENOSPC __einfo_error ( EINFO_ENOSPC )
#define EINFO_ENOSPC __einfo ( PLATFORM_ENOSPC, 0x34, 0, \
			       "No space left on device" )

/** No STREAM resources */
#define ENOSR __einfo_error ( EINFO_ENOSR )
#define EINFO_ENOSR __einfo ( PLATFORM_ENOSR, 0x35, 0, \
			      "No STREAM resources" )

/** Not a STREAM */
#define ENOSTR __einfo_error ( EINFO_ENOSTR )
#define EINFO_ENOSTR __einfo ( PLATFORM_ENOSTR, 0x36, 0, \
			       "Not a STREAM" )

/** Function not implemented */
#define ENOSYS __einfo_error ( EINFO_ENOSYS )
#define EINFO_ENOSYS __einfo ( PLATFORM_ENOSYS, 0x37, 0, \
			       "Function not implemented" )

/** The socket is not connected */
#define ENOTCONN __einfo_error ( EINFO_ENOTCONN )
#define EINFO_ENOTCONN __einfo ( PLATFORM_ENOTCONN, 0x38, 0, \
				 "The socket is not connected" )

/** Not a directory */
#define ENOTDIR __einfo_error ( EINFO_ENOTDIR )
#define EINFO_ENOTDIR __einfo ( PLATFORM_ENOTDIR, 0x39, 0, \
				"Not a directory" )

/** Directory not empty */
#define ENOTEMPTY __einfo_error ( EINFO_ENOTEMPTY )
#define EINFO_ENOTEMPTY __einfo ( PLATFORM_ENOTEMPTY, 0x3a, 0, \
				  "Directory not empty" )

/** Not a socket */
#define ENOTSOCK __einfo_error ( EINFO_ENOTSOCK )
#define EINFO_ENOTSOCK __einfo ( PLATFORM_ENOTSOCK, 0x3b, 0, \
				 "Not a socket" )

/** Operation not supported */
#define ENOTSUP __einfo_error ( EINFO_ENOTSUP )
#define EINFO_ENOTSUP __einfo ( PLATFORM_ENOTSUP, 0x3c, 0, \
				"Operation not supported" )

/** Inappropriate I/O control operation */
#define ENOTTY __einfo_error ( EINFO_ENOTTY )
#define EINFO_ENOTTY __einfo ( PLATFORM_ENOTTY, 0x3d, 0, \
			       "Inappropriate I/O control operation" )

/** No such device or address */
#define ENXIO __einfo_error ( EINFO_ENXIO )
#define EINFO_ENXIO __einfo ( PLATFORM_ENXIO, 0x3e, 0, \
			      "No such device or address" )

/** Operation not supported on socket */
#define EOPNOTSUPP __einfo_error ( EINFO_EOPNOTSUPP )
#define EINFO_EOPNOTSUPP __einfo ( PLATFORM_EOPNOTSUPP, 0x3f, 0, \
				   "Operation not supported on socket" )

/** Value too large to be stored in data type */
#define EOVERFLOW __einfo_error ( EINFO_EOVERFLOW )
#define EINFO_EOVERFLOW __einfo ( PLATFORM_EOVERFLOW, 0x40, 0, \
				  "Value too large to be stored in data type" )

/** Operation not permitted */
#define EPERM __einfo_error ( EINFO_EPERM )
#define EINFO_EPERM __einfo ( PLATFORM_EPERM, 0x41, 0, \
			      "Operation not permitted" )

/** Broken pipe */
#define EPIPE __einfo_error ( EINFO_EPIPE )
#define EINFO_EPIPE __einfo ( PLATFORM_EPIPE, 0x42, 0, \
			      "Broken pipe" )

/** Protocol error */
#define EPROTO __einfo_error ( EINFO_EPROTO )
#define EINFO_EPROTO __einfo ( PLATFORM_EPROTO, 0x43, 0, \
			       "Protocol error" )

/** Protocol not supported */
#define EPROTONOSUPPORT __einfo_error ( EINFO_EPROTONOSUPPORT )
#define EINFO_EPROTONOSUPPORT __einfo ( PLATFORM_EPROTONOSUPPORT, 0x44, 0, \
					"Protocol not supported" )

/** Protocol wrong type for socket */
#define EPROTOTYPE __einfo_error ( EINFO_EPROTOTYPE )
#define EINFO_EPROTOTYPE __einfo ( PLATFORM_EPROTOTYPE, 0x45, 0, \
				   "Protocol wrong type for socket" )

/** Result too large */
#define ERANGE __einfo_error ( EINFO_ERANGE )
#define EINFO_ERANGE __einfo ( PLATFORM_ERANGE, 0x46, 0, \
			       "Result too large" )

/** Read-only file system */
#define EROFS __einfo_error ( EINFO_EROFS )
#define EINFO_EROFS __einfo ( PLATFORM_EROFS, 0x47, 0, \
			      "Read-only file system" )

/** Invalid seek */
#define ESPIPE __einfo_error ( EINFO_ESPIPE )
#define EINFO_ESPIPE __einfo ( PLATFORM_ESPIPE, 0x48, 0, \
			       "Invalid seek" )

/** No such process */
#define ESRCH __einfo_error ( EINFO_ESRCH )
#define EINFO_ESRCH __einfo ( PLATFORM_ESRCH, 0x49, 0, \
			      "No such process" )

/** Stale file handle */
#define ESTALE __einfo_error ( EINFO_ESTALE )
#define EINFO_ESTALE __einfo ( PLATFORM_ESTALE, 0x4a, 0, \
			       "Stale file handle" )

/** Timer expired */
#define ETIME __einfo_error ( EINFO_ETIME )
#define EINFO_ETIME __einfo ( PLATFORM_ETIME, 0x4b, 0, \
			      "Timer expired" )

/** Connection timed out */
#define ETIMEDOUT __einfo_error ( EINFO_ETIMEDOUT )
#define EINFO_ETIMEDOUT __einfo ( PLATFORM_ETIMEDOUT, 0x4c, 0, \
				  "Connection timed out" )

/** Text file busy */
#define ETXTBSY __einfo_error ( EINFO_ETXTBSY )
#define EINFO_ETXTBSY __einfo ( PLATFORM_ETXTBSY, 0x4d, 0, \
				"Text file busy" )

/** Operation would block */
#define EWOULDBLOCK __einfo_error ( EINFO_EWOULDBLOCK )
#define EINFO_EWOULDBLOCK __einfo ( PLATFORM_EWOULDBLOCK, 0x4e, 0, \
				    "Operation would block" )

/** Improper link */
#define EXDEV __einfo_error ( EINFO_EXDEV )
#define EINFO_EXDEV __einfo ( PLATFORM_EXDEV, 0x4f, 0, \
			      "Improper link" )

/** @} */

/** Platform-generated base error */
#define EINFO_EPLATFORM __einfo ( 0, 0x7f, 0, "Platform-generated error" )

extern int errno;

#endif /* ERRNO_H */
