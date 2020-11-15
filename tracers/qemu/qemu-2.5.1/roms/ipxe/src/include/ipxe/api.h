#ifndef _IPXE_API_H
#define _IPXE_API_H

/** @file
 *
 * iPXE internal APIs
 *
 * There are various formally-defined APIs internal to iPXE, with
 * several differing implementations specific to particular execution
 * environments (e.g. PC BIOS, EFI, LinuxBIOS).
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @defgroup Single-implementation APIs
 *
 * These are APIs for which only a single implementation may be
 * compiled in at any given time.
 *
 * @{
 */

/**
 * Calculate function implementation name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 *
 * The subsystem prefix should be an empty string for the currently
 * selected subsystem, and should be a subsystem-unique string for all
 * other subsystems.
 */
#define SINGLE_API_NAME( _prefix, _api_func ) _prefix ## _api_func

/**
 * Calculate static inline function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define SINGLE_API_INLINE( _prefix, _api_func )	\
	SINGLE_API_NAME ( _prefix, _api_func )

/**
 * Provide an API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_SINGLE_API( _prefix, _api_func, _func )			      \
	/* Ensure that _api_func exists */				      \
	typeof ( _api_func ) _api_func;					      \
	/* Ensure that _func exists */					      \
	typeof ( _func ) _func;						      \
	/* Ensure that _func is type-compatible with _api_func */	      \
	typeof ( _api_func ) _func;					      \
	/* Ensure that _subsys_func is non-static */			      \
	extern typeof ( _api_func ) SINGLE_API_NAME ( _prefix, _api_func );   \
	/* Provide symbol alias from _subsys_func to _func */		      \
	typeof ( _api_func ) SINGLE_API_NAME ( _prefix, _api_func )	      \
		__attribute__ (( alias ( #_func ) ));

/**
 * Provide a static inline API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_SINGLE_API_INLINE( _prefix, _api_func )			      \
	/* Ensure that _api_func exists */				      \
	typeof ( _api_func ) _api_func;					      \
	/* Ensure that _subsys_func exists and is static */		      \
	static typeof ( SINGLE_API_INLINE ( _prefix, _api_func ) )	      \
		SINGLE_API_INLINE ( _prefix, _api_func );		      \
	/* Ensure that _subsys_func is type-compatible with _api_func */      \
	typeof ( _api_func ) SINGLE_API_INLINE ( _prefix, _api_func );

/** @} */

#endif /* _IPXE_API_H */
