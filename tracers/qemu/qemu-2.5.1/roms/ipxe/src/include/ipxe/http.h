#ifndef _IPXE_HTTP_H
#define _IPXE_HTTP_H

/** @file
 *
 * Hyper Text Transport Protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/refcnt.h>
#include <ipxe/interface.h>
#include <ipxe/iobuf.h>
#include <ipxe/process.h>
#include <ipxe/retry.h>
#include <ipxe/linebuf.h>
#include <ipxe/pool.h>
#include <ipxe/tables.h>

struct http_transaction;

/******************************************************************************
 *
 * HTTP URI schemes
 *
 ******************************************************************************
 */

/** HTTP default port */
#define HTTP_PORT 80

/** HTTPS default port */
#define HTTPS_PORT 443

/** An HTTP URI scheme */
struct http_scheme {
	/** Scheme name (e.g. "http" or "https") */
	const char *name;
	/** Default port */
	unsigned int port;
	/** Transport-layer filter (if any)
	 *
	 * @v xfer		Data transfer interface
	 * @v name		Host name
	 * @v next		Next interface
	 * @ret rc		Return status code
	 */
	int ( * filter ) ( struct interface *xfer, const char *name,
			   struct interface **next );
};

/** HTTP scheme table */
#define HTTP_SCHEMES __table ( struct http_scheme, "http_schemes" )

/** Declare an HTTP scheme */
#define __http_scheme __table_entry ( HTTP_SCHEMES, 01 )

/******************************************************************************
 *
 * Connections
 *
 ******************************************************************************
 */

/** An HTTP connection
 *
 * This represents a potentially reusable connection to an HTTP
 * server.
 */
struct http_connection {
	/** Reference count */
	struct refcnt refcnt;
	/** Connection URI
	 *
	 * This encapsulates the server (and protocol) used for the
	 * connection.  This may be the origin server or a proxy
	 * server.
	 */
	struct uri *uri;
	/** HTTP scheme */
	struct http_scheme *scheme;
	/** Transport layer interface */
	struct interface socket;
	/** Data transfer interface */
	struct interface xfer;
	/** Pooled connection */
	struct pooled_connection pool;
};

/******************************************************************************
 *
 * HTTP methods
 *
 ******************************************************************************
 */

/** An HTTP method */
struct http_method {
	/** Method name (e.g. "GET" or "POST") */
	const char *name;
};

extern struct http_method http_head;
extern struct http_method http_get;
extern struct http_method http_post;

/******************************************************************************
 *
 * Requests
 *
 ******************************************************************************
 */

/** HTTP Digest authentication client nonce count
 *
 * We choose to generate a new client nonce each time.
 */
#define HTTP_DIGEST_NC "00000001"

/** HTTP Digest authentication client nonce length
 *
 * We choose to use a 32-bit hex client nonce.
 */
#define HTTP_DIGEST_CNONCE_LEN 8

/** HTTP Digest authentication response length
 *
 * The Digest authentication response is a Base16-encoded 16-byte MD5
 * checksum.
 */
#define HTTP_DIGEST_RESPONSE_LEN 32

/** HTTP request range descriptor */
struct http_request_range {
	/** Range start */
	size_t start;
	/** Range length, or zero for no range request */
	size_t len;
};

/** HTTP request content descriptor */
struct http_request_content {
	/** Content type (if any) */
	const char *type;
	/** Content data (if any) */
	const void *data;
	/** Content length */
	size_t len;
};

/** HTTP request authentication descriptor */
struct http_request_auth {
	/** Authentication scheme (if any) */
	struct http_authentication *auth;
	/** Username */
	const char *username;
	/** Password */
	const char *password;
	/** Quality of protection */
	const char *qop;
	/** Algorithm */
	const char *algorithm;
	/** Client nonce */
	char cnonce[ HTTP_DIGEST_CNONCE_LEN + 1 /* NUL */ ];
	/** Response */
	char response[ HTTP_DIGEST_RESPONSE_LEN + 1 /* NUL */ ];
};

/** An HTTP request
 *
 * This represents a single request to be sent to a server, including
 * the values required to construct all headers.
 *
 * Pointers within this structure must point to storage which is
 * guaranteed to remain valid for the lifetime of the containing HTTP
 * transaction.
 */
struct http_request {
	/** Method */
	struct http_method *method;
	/** Request URI string */
	const char *uri;
	/** Server host name */
	const char *host;
	/** Range descriptor */
	struct http_request_range range;
	/** Content descriptor */
	struct http_request_content content;
	/** Authentication descriptor */
	struct http_request_auth auth;
};

/** An HTTP request header */
struct http_request_header {
	/** Header name (e.g. "User-Agent") */
	const char *name;
	/** Construct remaining header line
	 *
	 * @v http		HTTP transaction
	 * @v buf		Buffer
	 * @v len		Length of buffer
	 * @ret len		Header length if present, or negative error
	 */
	int ( * format ) ( struct http_transaction *http, char *buf,
			   size_t len );
};

/** HTTP request header table */
#define HTTP_REQUEST_HEADERS \
	__table ( struct http_request_header, "http_request_headers" )

/** Declare an HTTP request header */
#define __http_request_header __table_entry ( HTTP_REQUEST_HEADERS, 01 )

/******************************************************************************
 *
 * Responses
 *
 ******************************************************************************
 */

/** HTTP response transfer descriptor */
struct http_response_transfer {
	/** Transfer encoding */
	struct http_transfer_encoding *encoding;
};

/** HTTP response content descriptor */
struct http_response_content {
	/** Content length (may be zero) */
	size_t len;
	/** Content encoding */
	struct http_content_encoding *encoding;
};

/** HTTP response authorization descriptor */
struct http_response_auth {
	/** Authentication scheme (if any) */
	struct http_authentication *auth;
	/** Realm */
	const char *realm;
	/** Quality of protection */
	const char *qop;
	/** Algorithm */
	const char *algorithm;
	/** Nonce */
	const char *nonce;
	/** Opaque */
	const char *opaque;
};

/** An HTTP response
 *
 * This represents a single response received from the server,
 * including all values parsed from headers.
 *
 * Pointers within this structure may point into the raw response
 * buffer, and so should be invalidated when the response buffer is
 * modified or discarded.
 */
struct http_response {
	/** Raw response header lines
	 *
	 * This is the raw response data received from the server, up
	 * to and including the terminating empty line.  String
	 * pointers within the response may point into this data
	 * buffer; NUL terminators will be added (overwriting the
	 * original terminating characters) as needed.
	 */
	struct line_buffer headers;
	/** Status code
	 *
	 * This is the raw HTTP numeric status code (e.g. 404).
	 */
	unsigned int status;
	/** Return status code
	 *
	 * This is the iPXE return status code corresponding to the
	 * HTTP status code (e.g. -ENOENT).
	 */
	int rc;
	/** Redirection location */
	const char *location;
	/** Transfer descriptor */
	struct http_response_transfer transfer;
	/** Content descriptor */
	struct http_response_content content;
	/** Authorization descriptor */
	struct http_response_auth auth;
	/** Retry delay (in seconds) */
	unsigned int retry_after;
	/** Flags */
	unsigned int flags;
};

/** HTTP response flags */
enum http_response_flags {
	/** Keep connection alive after close */
	HTTP_RESPONSE_KEEPALIVE = 0x0001,
	/** Content length specified */
	HTTP_RESPONSE_CONTENT_LEN = 0x0002,
	/** Transaction may be retried on failure */
	HTTP_RESPONSE_RETRY = 0x0004,
};

/** An HTTP response header */
struct http_response_header {
	/** Header name (e.g. "Transfer-Encoding") */
	const char *name;
	/** Parse header line
	 *
	 * @v http		HTTP transaction
	 * @v line		Remaining header line
	 * @ret rc		Return status code
	 */
	int ( * parse ) ( struct http_transaction *http, char *line );
};

/** HTTP response header table */
#define HTTP_RESPONSE_HEADERS \
	__table ( struct http_response_header, "http_response_headers" )

/** Declare an HTTP response header */
#define __http_response_header __table_entry ( HTTP_RESPONSE_HEADERS, 01 )

/******************************************************************************
 *
 * Transactions
 *
 ******************************************************************************
 */

/** HTTP transaction state */
struct http_state {
	/** Transmit data
	 *
	 * @v http		HTTP transaction
	 * @ret rc		Return status code
	 */
	int ( * tx ) ( struct http_transaction *http );
	/** Receive data
	 *
	 * @v http		HTTP transaction
	 * @v iobuf		I/O buffer (may be claimed)
	 * @ret rc		Return status code
	 */
	int ( * rx ) ( struct http_transaction *http,
		       struct io_buffer **iobuf );
	/** Server connection closed
	 *
	 * @v http		HTTP transaction
	 * @v rc		Reason for close
	 */
	void ( * close ) ( struct http_transaction *http, int rc );
};

/** An HTTP transaction */
struct http_transaction {
	/** Reference count */
	struct refcnt refcnt;
	/** Data transfer interface */
	struct interface xfer;
	/** Content-decoded interface */
	struct interface content;
	/** Transfer-decoded interface */
	struct interface transfer;
	/** Server connection */
	struct interface conn;
	/** Transmit process */
	struct process process;
	/** Reconnection timer */
	struct retry_timer timer;

	/** Request URI */
	struct uri *uri;
	/** Request */
	struct http_request request;
	/** Response */
	struct http_response response;
	/** Temporary line buffer */
	struct line_buffer linebuf;

	/** Transaction state */
	struct http_state *state;
	/** Accumulated transfer-decoded length */
	size_t len;
	/** Chunk length remaining */
	size_t remaining;
};

/******************************************************************************
 *
 * Transfer encoding
 *
 ******************************************************************************
 */

/** An HTTP transfer encoding */
struct http_transfer_encoding {
	/** Name */
	const char *name;
	/** Initialise transfer encoding
	 *
	 * @v http		HTTP transaction
	 * @ret rc		Return status code
	 */
	int ( * init ) ( struct http_transaction *http );
	/** Receive data state */
	struct http_state state;
};

/** HTTP transfer encoding table */
#define HTTP_TRANSFER_ENCODINGS \
	__table ( struct http_transfer_encoding, "http_transfer_encodings" )

/** Declare an HTTP transfer encoding */
#define __http_transfer_encoding __table_entry ( HTTP_TRANSFER_ENCODINGS, 01 )

/******************************************************************************
 *
 * Content encoding
 *
 ******************************************************************************
 */

/** An HTTP content encoding */
struct http_content_encoding {
	/** Name */
	const char *name;
	/** Check if content encoding is supported for this request
	 *
	 * @v http		HTTP transaction
	 * @ret supported	Content encoding is supported for this request
	 */
	int ( * supported ) ( struct http_transaction *http );
	/** Initialise content encoding
	 *
	 * @v http		HTTP transaction
	 * @ret rc		Return status code
	 */
	int ( * init ) ( struct http_transaction *http );
};

/** HTTP content encoding table */
#define HTTP_CONTENT_ENCODINGS \
	__table ( struct http_content_encoding, "http_content_encodings" )

/** Declare an HTTP content encoding */
#define __http_content_encoding __table_entry ( HTTP_CONTENT_ENCODINGS, 01 )

/******************************************************************************
 *
 * Authentication
 *
 ******************************************************************************
 */

/** An HTTP authentication scheme */
struct http_authentication {
	/** Name (e.g. "Digest") */
	const char *name;
	/** Perform authentication
	 *
	 * @v http		HTTP transaction
	 * @ret rc		Return status code
	 */
	int ( * authenticate ) ( struct http_transaction *http );
	/** Construct remaining "Authorization" header line
	 *
	 * @v http		HTTP transaction
	 * @v buf		Buffer
	 * @v len		Length of buffer
	 * @ret len		Header length if present, or negative error
	 */
	int ( * format ) ( struct http_transaction *http, char *buf,
			   size_t len );
};

/** HTTP authentication scheme table */
#define HTTP_AUTHENTICATIONS \
	__table ( struct http_authentication, "http_authentications" )

/** Declare an HTTP authentication scheme */
#define __http_authentication __table_entry ( HTTP_AUTHENTICATIONS, 01 )

/******************************************************************************
 *
 * General
 *
 ******************************************************************************
 */

extern char * http_token ( char **line, char **value );
extern int http_connect ( struct interface *xfer, struct uri *uri );
extern int http_open ( struct interface *xfer, struct http_method *method,
		       struct uri *uri, struct http_request_range *range,
		       struct http_request_content *content );
extern int http_open_uri ( struct interface *xfer, struct uri *uri );

#endif /* _IPXE_HTTP_H */
