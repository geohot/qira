#ifndef _IPXE_PORTMAP_H
#define _IPXE_PORTMAP_H

#include <stdint.h>
#include <ipxe/oncrpc.h>

/** @file
 *
 * SUN ONC RPC protocol.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** PORTMAP default port */
#define PORTMAP_PORT   111

/** PORTMAP protocol number */
#define ONCRPC_PORTMAP 100000

/** PORTMAP version */
#define PORTMAP_VERS   2


/** TCP protocol number */
#define PORTMAP_PROTO_TCP 6
/** UDB protocol number */
#define PORTMAP_PROTO_UDP 17


/**
 * A PORTMAP GETPORT reply
 *
 */
struct portmap_getport_reply {
	/** Port returned */
	uint32_t        port;
};


/**
 * Prepare an ONC RPC session to be used as a PORTMAP session
 *
 * @v session           ONC RPC session
 * @v credential        ONC RPC credential
 *
 * The credential parameter must not be NULL, use 'oncrpc_auth_none' if you
 * don't want a particular scheme to be used.
 */
static inline void portmap_init_session ( struct oncrpc_session *session,
                                          struct oncrpc_cred *credential) {
	oncrpc_init_session ( session, credential, &oncrpc_auth_none,
	                      ONCRPC_PORTMAP, PORTMAP_VERS );
}


int portmap_getport ( struct interface *intf, struct oncrpc_session *session,
                      uint32_t prog, uint32_t vers, uint32_t proto );
int portmap_get_getport_reply ( struct portmap_getport_reply *getport_reply,
                                struct oncrpc_reply *reply );


#endif /* _IPXE_PORTMAP_H */
