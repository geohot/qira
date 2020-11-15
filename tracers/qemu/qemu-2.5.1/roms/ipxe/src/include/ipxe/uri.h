#ifndef _IPXE_URI_H
#define _IPXE_URI_H

/** @file
 *
 * Uniform Resource Identifiers
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <stdlib.h>
#include <ipxe/refcnt.h>
#include <ipxe/in.h>

struct parameters;

/** A Uniform Resource Identifier
 *
 * Terminology for this data structure is as per uri(7), except that
 * "path" is defined to include the leading '/' for an absolute path.
 *
 * Note that all fields within a URI are optional and may be NULL.
 *
 * The pointers to the various fields are packed together so they can
 * be accessed in array fashion in some places in uri.c where doing so
 * saves significant code size.
 *
 * Some examples are probably helpful:
 *
 *   http://www.ipxe.org/wiki :
 *
 *   scheme = "http", host = "www.ipxe.org", path = "/wiki"
 *
 *   /var/lib/tftpboot :
 *
 *   path = "/var/lib/tftpboot"
 *
 *   mailto:bob@nowhere.com :
 *
 *   scheme = "mailto", opaque = "bob@nowhere.com"
 *
 *   ftp://joe:secret@insecure.org:8081/hidden/path/to?what=is#this
 *
 *   scheme = "ftp", user = "joe", password = "secret",
 *   host = "insecure.org", port = "8081", path = "/hidden/path/to",
 *   query = "what=is", fragment = "this"
 */
struct uri {
	/** Reference count */
	struct refcnt refcnt;
	/** Scheme */
	const char *scheme;
	/** Opaque part */
	const char *opaque;
	/** User name */
	const char *user;
	/** Password */
	const char *password;
	/** Host name */
	const char *host;
	/** Port number */
	const char *port;
	/** Path */
	const char *path;
	/** Query */
	const char *query;
	/** Fragment */
	const char *fragment;
	/** Form parameters */
	struct parameters *params;
} __attribute__ (( packed ));

/**
 * Access URI field
 *
 * @v uri		URI
 * @v field		URI field index
 * @ret field		URI field (as an lvalue)
 */
#define uri_field( uri, field ) (&uri->scheme)[field]

/**
 * Calculate index of a URI field
 *
 * @v name		URI field name
 * @ret field		URI field index
 */
#define URI_FIELD( name )						\
	( ( offsetof ( struct uri, name ) -				\
	    offsetof ( struct uri, scheme ) ) / sizeof ( void * ) )

/** URI fields */
enum uri_fields {
	URI_SCHEME = URI_FIELD ( scheme ),
	URI_OPAQUE = URI_FIELD ( opaque ),
	URI_USER = URI_FIELD ( user ),
	URI_PASSWORD = URI_FIELD ( password ),
	URI_HOST = URI_FIELD ( host ),
	URI_PORT = URI_FIELD ( port ),
	URI_PATH = URI_FIELD ( path ),
	URI_QUERY = URI_FIELD ( query ),
	URI_FRAGMENT = URI_FIELD ( fragment ),
	URI_FIELDS
};

/**
 * URI is an absolute URI
 *
 * @v uri			URI
 * @ret is_absolute		URI is absolute
 *
 * An absolute URI begins with a scheme, e.g. "http:" or "mailto:".
 * Note that this is a separate concept from a URI with an absolute
 * path.
 */
static inline int uri_is_absolute ( const struct uri *uri ) {
	return ( uri->scheme != NULL );
}

/**
 * URI has an opaque part
 *
 * @v uri			URI
 * @ret has_opaque		URI has an opaque part
 */
static inline int uri_has_opaque ( const struct uri *uri ) {
	return ( uri->opaque && ( uri->opaque[0] != '\0' ) );
}

/**
 * URI has a path
 *
 * @v uri			URI
 * @ret has_path		URI has a path
 */
static inline int uri_has_path ( const struct uri *uri ) {
	return ( uri->path && ( uri->path[0] != '\0' ) );
}

/**
 * URI has an absolute path
 *
 * @v uri			URI
 * @ret has_absolute_path	URI has an absolute path
 *
 * An absolute path begins with a '/'.  Note that this is a separate
 * concept from an absolute URI.  Note also that a URI may not have a
 * path at all.
 */
static inline int uri_has_absolute_path ( const struct uri *uri ) {
	return ( uri->path && ( uri->path[0] == '/' ) );
}

/**
 * URI has a relative path
 *
 * @v uri			URI
 * @ret has_relative_path	URI has a relative path
 *
 * A relative path begins with something other than a '/'.  Note that
 * this is a separate concept from a relative URI.  Note also that a
 * URI may not have a path at all.
 */
static inline int uri_has_relative_path ( const struct uri *uri ) {
	return ( uri->path && ( uri->path[0] != '/' ) );
}

/**
 * Increment URI reference count
 *
 * @v uri		URI, or NULL
 * @ret uri		URI as passed in
 */
static inline __attribute__ (( always_inline )) struct uri *
uri_get ( struct uri *uri ) {
	ref_get ( &uri->refcnt );
	return uri;
}

/**
 * Decrement URI reference count
 *
 * @v uri		URI, or NULL
 */
static inline __attribute__ (( always_inline )) void
uri_put ( struct uri *uri ) {
	ref_put ( &uri->refcnt );
}

extern struct uri *cwuri;

extern size_t uri_encode ( const char *string, unsigned int field,
			   char *buf, ssize_t len );
extern struct uri * parse_uri ( const char *uri_string );
extern size_t format_uri ( const struct uri *uri, char *buf, size_t len );
extern char * format_uri_alloc ( const struct uri *uri );
extern unsigned int uri_port ( const struct uri *uri,
			       unsigned int default_port );
extern struct uri * uri_dup ( const struct uri *uri );
extern char * resolve_path ( const char *base_path,
			     const char *relative_path );
extern struct uri * resolve_uri ( const struct uri *base_uri,
				  struct uri *relative_uri );
extern struct uri * tftp_uri ( struct in_addr next_server, unsigned int port,
			       const char *filename );
extern void churi ( struct uri *uri );

#endif /* _IPXE_URI_H */
