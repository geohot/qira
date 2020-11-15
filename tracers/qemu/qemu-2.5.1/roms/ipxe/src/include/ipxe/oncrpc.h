#ifndef _IPXE_ONCRPC_H
#define _IPXE_ONCRPC_H

#include <stdint.h>
#include <ipxe/interface.h>
#include <ipxe/iobuf.h>

/** @file
 *
 * SUN ONC RPC protocol.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** ONC RCP Version */
#define ONCRPC_VERS 2

/** ONC RPC Null Authentication */
#define ONCRPC_AUTH_NONE 0

/** ONC RPC System Authentication (also called UNIX Authentication) */
#define ONCRPC_AUTH_SYS  1

/** Size of an ONC RPC header */
#define ONCRPC_HEADER_SIZE ( 11 * sizeof ( uint32_t ) )

#define ONCRPC_FIELD( type, value ) { oncrpc_ ## type, { .type = value } }
#define ONCRPC_SUBFIELD( type, args... ) \
	{ oncrpc_ ## type, { .type = { args } } }

#define ONCRPC_FIELD_END { oncrpc_none, { } }

/** Enusure that size is a multiple of four */
#define oncrpc_align( size ) ( ( (size) + 3 ) & ~3 )

/**
 * Calculate the length of a string, including padding bytes.
 *
 * @v str               String
 * @ret size            Length of the padded string
 */
#define oncrpc_strlen( str ) ( oncrpc_align ( strlen ( str ) ) + \
                               sizeof ( uint32_t ) )

struct oncrpc_cred {
	uint32_t               flavor;
	uint32_t               length;
};

struct oncrpc_cred_sys {
	struct oncrpc_cred     credential;
	uint32_t               stamp;
	char                   *hostname;
	uint32_t               uid;
	uint32_t               gid;
	uint32_t               aux_gid_len;
	uint32_t               aux_gid[16];
};

struct oncrpc_reply
{
	struct oncrpc_cred      *verifier;
	uint32_t                rpc_id;
	uint32_t                reply_state;
	uint32_t                accept_state;
	uint32_t                frame_size;
	struct io_buffer        *data;
};

struct oncrpc_session {
	struct oncrpc_reply     pending_reply;
	struct oncrpc_cred      *credential;
	struct oncrpc_cred      *verifier;
	uint32_t                rpc_id;
	uint32_t                prog_name;
	uint32_t                prog_vers;
};

enum oncrpc_field_type {
	oncrpc_none = 0,
	oncrpc_int32,
	oncrpc_int64,
	oncrpc_str,
	oncrpc_array,
	oncrpc_intarray,
	oncrpc_cred,
};

union oncrpc_field_value {
	struct {
		size_t           length;
		const void       *ptr;
	}                        array;

	struct {
		size_t           length;
		const uint32_t   *ptr;
	}                        intarray;

	int64_t                  int64;
	int32_t                  int32;
	const char               *str;
	const struct oncrpc_cred *cred;
};

struct oncrpc_field {
	enum oncrpc_field_type       type;
	union oncrpc_field_value     value;
};

extern struct oncrpc_cred oncrpc_auth_none;

int oncrpc_init_cred_sys ( struct oncrpc_cred_sys *auth_sys );
void oncrpc_init_session ( struct oncrpc_session *session,
                           struct oncrpc_cred *credential,
                           struct oncrpc_cred *verifier, uint32_t prog_name,
                           uint32_t prog_vers );

int oncrpc_call ( struct interface *intf, struct oncrpc_session *session,
                  uint32_t proc_name, const struct oncrpc_field fields[] );

size_t oncrpc_compute_size ( const struct oncrpc_field fields[] );

int oncrpc_get_reply ( struct oncrpc_session *session,
                       struct oncrpc_reply *reply, struct io_buffer *io_buf );

#endif /* _IPXE_ONCRPC_H */
