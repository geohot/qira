#include <errno.h>
#include <comboot.h>
#include <ipxe/in.h>
#include <ipxe/list.h>
#include <ipxe/process.h>
#include <ipxe/resolv.h>

FILE_LICENCE ( GPL2_OR_LATER );

struct comboot_resolver {
	struct interface intf;
	int rc;
	struct in_addr addr;
};

static void comboot_resolv_close ( struct comboot_resolver *comboot_resolver,
				   int rc ) {
	comboot_resolver->rc = rc;
	intf_shutdown ( &comboot_resolver->intf, rc );
}

static void comboot_resolv_done ( struct comboot_resolver *comboot_resolver,
				  struct sockaddr *sa ) {
	struct sockaddr_in *sin;

	if ( sa->sa_family == AF_INET ) {
		sin = ( ( struct sockaddr_in * ) sa );
		comboot_resolver->addr = sin->sin_addr;
	}
}

static struct interface_operation comboot_resolv_op[] = {
	INTF_OP ( intf_close, struct comboot_resolver *, comboot_resolv_close ),
	INTF_OP ( resolv_done, struct comboot_resolver *, comboot_resolv_done ),
};

static struct interface_descriptor comboot_resolv_desc =
	INTF_DESC ( struct comboot_resolver, intf, comboot_resolv_op );

static struct comboot_resolver comboot_resolver = {
	.intf = INTF_INIT ( comboot_resolv_desc ),
};

int comboot_resolv ( const char *name, struct in_addr *address ) {
	int rc;

	comboot_resolver.rc = -EINPROGRESS;
	comboot_resolver.addr.s_addr = 0;

	if ( ( rc = resolv ( &comboot_resolver.intf, name, NULL ) ) != 0 )
		return rc;

	while ( comboot_resolver.rc == -EINPROGRESS )
		step();

	if ( ! comboot_resolver.addr.s_addr )
		return -EAFNOSUPPORT;

	*address = comboot_resolver.addr;
	return comboot_resolver.rc;
}
