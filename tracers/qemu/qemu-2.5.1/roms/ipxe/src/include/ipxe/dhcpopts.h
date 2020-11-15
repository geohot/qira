#ifndef _IPXE_DHCPOPTS_H
#define _IPXE_DHCPOPTS_H

/** @file
 *
 * DHCP options
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/** A DHCP options block */
struct dhcp_options {
	/** Option block raw data */
	void *data;
	/** Option block used length */
	size_t used_len;
	/** Option block allocated length */
	size_t alloc_len;
	/** Reallocate option block raw data
	 *
	 * @v options		DHCP option block
	 * @v len		New length
	 * @ret rc		Return status code
	 */
	int ( * realloc ) ( struct dhcp_options *options, size_t len );
};

extern int dhcpopt_applies ( unsigned int tag );
extern int dhcpopt_store ( struct dhcp_options *options, unsigned int tag,
			   const void *data, size_t len );
extern int dhcpopt_fetch ( struct dhcp_options *options, unsigned int tag,
			   void *data, size_t len );
extern void dhcpopt_init ( struct dhcp_options *options,
			   void *data, size_t alloc_len,
			   int ( * realloc ) ( struct dhcp_options *options,
					       size_t len ) );
extern void dhcpopt_update_used_len ( struct dhcp_options *options );
extern int dhcpopt_no_realloc ( struct dhcp_options *options, size_t len );

#endif /* _IPXE_DHCPOPTS_H */
