/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

/** @file
 *
 * Hyper-V virtual machine bus
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/nap.h>
#include <ipxe/malloc.h>
#include <ipxe/iobuf.h>
#include <ipxe/hyperv.h>
#include <ipxe/vmbus.h>

/** VMBus initial GPADL ID
 *
 * This is an opaque value with no meaning.  The Linux kernel uses
 * 0xe1e10.
 */
#define VMBUS_GPADL_MAGIC 0x18ae0000

/**
 * Post message
 *
 * @v hv		Hyper-V hypervisor
 * @v header		Message header
 * @v len		Length of message (including header)
 * @ret rc		Return status code
 */
static int vmbus_post_message ( struct hv_hypervisor *hv,
				const struct vmbus_message_header *header,
				size_t len ) {
	struct vmbus *vmbus = hv->vmbus;
	int rc;

	/* Post message */
	if ( ( rc = hv_post_message ( hv, VMBUS_MESSAGE_ID, VMBUS_MESSAGE_TYPE,
				      header, len ) ) != 0 ) {
		DBGC ( vmbus, "VMBUS %p could not post message: %s\n",
		       vmbus, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Post empty message
 *
 * @v hv		Hyper-V hypervisor
 * @v type		Message type
 * @ret rc		Return status code
 */
static int vmbus_post_empty_message ( struct hv_hypervisor *hv,
				      unsigned int type ) {
	struct vmbus_message_header header = { .type = cpu_to_le32 ( type ) };

	return vmbus_post_message ( hv, &header, sizeof ( header ) );
}

/**
 * Wait for received message
 *
 * @v hv		Hyper-V hypervisor
 * @ret rc		Return status code
 */
static int vmbus_wait_for_message ( struct hv_hypervisor *hv ) {
	struct vmbus *vmbus = hv->vmbus;
	int rc;

	/* Wait for message */
	if ( ( rc = hv_wait_for_message ( hv, VMBUS_MESSAGE_SINT ) ) != 0 ) {
		DBGC ( vmbus, "VMBUS %p failed waiting for message: %s\n",
		       vmbus, strerror ( rc ) );
		return rc;
	}

	/* Sanity check */
	if ( hv->message->received.type != cpu_to_le32 ( VMBUS_MESSAGE_TYPE ) ){
		DBGC ( vmbus, "VMBUS %p invalid message type %d\n",
		       vmbus, le32_to_cpu ( hv->message->received.type ) );
		return -EINVAL;
	}

	return 0;
}

/**
 * Initiate contact
 *
 * @v hv		Hyper-V hypervisor
 * @v raw		VMBus protocol (raw) version
 * @ret rc		Return status code
 */
static int vmbus_initiate_contact ( struct hv_hypervisor *hv,
				    unsigned int raw ) {
	struct vmbus *vmbus = hv->vmbus;
	const struct vmbus_version_response *version = &vmbus->message->version;
	struct vmbus_initiate_contact initiate;
	int rc;

	/* Construct message */
	memset ( &initiate, 0, sizeof ( initiate ) );
	initiate.header.type = cpu_to_le32 ( VMBUS_INITIATE_CONTACT );
	initiate.version.raw = cpu_to_le32 ( raw );
	initiate.intr = virt_to_phys ( vmbus->intr );
	initiate.monitor_in = virt_to_phys ( vmbus->monitor_in );
	initiate.monitor_out = virt_to_phys ( vmbus->monitor_out );

	/* Post message */
	if ( ( rc = vmbus_post_message ( hv, &initiate.header,
					 sizeof ( initiate ) ) ) != 0 )
		return rc;

	/* Wait for response */
	if ( ( rc = vmbus_wait_for_message ( hv ) ) != 0 )
		return rc;

	/* Check response */
	if ( version->header.type != cpu_to_le32 ( VMBUS_VERSION_RESPONSE ) ) {
		DBGC ( vmbus, "VMBUS %p unexpected version response type %d\n",
		       vmbus, le32_to_cpu ( version->header.type ) );
		return -EPROTO;
	}
	if ( ! version->supported ) {
		DBGC ( vmbus, "VMBUS %p requested version not supported\n",
		       vmbus );
		return -ENOTSUP;
	}
	if ( version->version.raw != cpu_to_le32 ( raw ) ) {
		DBGC ( vmbus, "VMBUS %p unexpected version %d.%d\n",
		       vmbus, le16_to_cpu ( version->version.major ),
		       le16_to_cpu ( version->version.minor ) );
		return -EPROTO;
	}

	DBGC ( vmbus, "VMBUS %p initiated contact using version %d.%d\n",
	       vmbus, le16_to_cpu ( version->version.major ),
	       le16_to_cpu ( version->version.minor ) );
	return 0;
}

/**
 * Terminate contact
 *
 * @v hv		Hyper-V hypervisor
 * @ret rc		Return status code
 */
static int vmbus_unload ( struct hv_hypervisor *hv ) {
	struct vmbus *vmbus = hv->vmbus;
	const struct vmbus_message_header *header = &vmbus->message->header;
	int rc;

	/* Post message */
	if ( ( rc = vmbus_post_empty_message ( hv, VMBUS_UNLOAD ) ) != 0 )
		return rc;

	/* Wait for response */
	if ( ( rc = vmbus_wait_for_message ( hv ) ) != 0 )
		return rc;

	/* Check response */
	if ( header->type != cpu_to_le32 ( VMBUS_UNLOAD_RESPONSE ) ) {
		DBGC ( vmbus, "VMBUS %p unexpected unload response type %d\n",
		       vmbus, le32_to_cpu ( header->type ) );
		return -EPROTO;
	}

	return 0;
}

/**
 * Negotiate protocol version
 *
 * @v hv		Hyper-V hypervisor
 * @ret rc		Return status code
 */
static int vmbus_negotiate_version ( struct hv_hypervisor *hv ) {
	int rc;

	/* We require the ability to disconnect from and reconnect to
	 * VMBus; if we don't have this then there is no (viable) way
	 * for a loaded operating system to continue to use any VMBus
	 * devices.  (There is also a small but non-zero risk that the
	 * host will continue to write to our interrupt and monitor
	 * pages, since the VMBUS_UNLOAD message in earlier versions
	 * is essentially a no-op.)
	 *
	 * This requires us to ensure that the host supports protocol
	 * version 3.0 (VMBUS_VERSION_WIN8_1).  However, we can't
	 * actually _use_ protocol version 3.0, since doing so causes
	 * an iSCSI-booted Windows Server 2012 R2 VM to crash due to a
	 * NULL pointer dereference in vmbus.sys.
	 *
	 * To work around this problem, we first ensure that we can
	 * connect using protocol v3.0, then disconnect and reconnect
	 * using the oldest known protocol.
	 */

	/* Initiate contact to check for required protocol support */
	if ( ( rc = vmbus_initiate_contact ( hv, VMBUS_VERSION_WIN8_1 ) ) != 0 )
		return rc;

	/* Terminate contact */
	if ( ( rc = vmbus_unload ( hv ) ) != 0 )
		return rc;

	/* Reinitiate contact using the oldest known protocol version */
	if ( ( rc = vmbus_initiate_contact ( hv, VMBUS_VERSION_WS2008 ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Establish GPA descriptor list
 *
 * @v vmdev		VMBus device
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret gpadl		GPADL ID, or negative error
 */
int vmbus_establish_gpadl ( struct vmbus_device *vmdev, userptr_t data,
			    size_t len ) {
	struct hv_hypervisor *hv = vmdev->hv;
	struct vmbus *vmbus = hv->vmbus;
	physaddr_t addr = user_to_phys ( data, 0 );
	unsigned int pfn_count = hv_pfn_count ( addr, len );
	struct {
		struct vmbus_gpadl_header gpadlhdr;
		struct vmbus_gpa_range range;
		uint64_t pfn[pfn_count];
	} __attribute__ (( packed )) gpadlhdr;
	const struct vmbus_gpadl_created *created = &vmbus->message->created;
	static unsigned int gpadl = VMBUS_GPADL_MAGIC;
	unsigned int i;
	int rc;

	/* Allocate GPADL ID */
	gpadl++;

	/* Construct message */
	memset ( &gpadlhdr, 0, sizeof ( gpadlhdr ) );
	gpadlhdr.gpadlhdr.header.type = cpu_to_le32 ( VMBUS_GPADL_HEADER );
	gpadlhdr.gpadlhdr.channel = cpu_to_le32 ( vmdev->channel );
	gpadlhdr.gpadlhdr.gpadl = cpu_to_le32 ( gpadl );
	gpadlhdr.gpadlhdr.range_len =
		cpu_to_le16 ( ( sizeof ( gpadlhdr.range ) +
				sizeof ( gpadlhdr.pfn ) ) );
	gpadlhdr.gpadlhdr.range_count = cpu_to_le16 ( 1 );
	gpadlhdr.range.len = cpu_to_le32 ( len );
	gpadlhdr.range.offset = cpu_to_le32 ( addr & ( PAGE_SIZE - 1 ) );
	for ( i = 0 ; i < pfn_count ; i++ )
		gpadlhdr.pfn[i] = ( ( addr / PAGE_SIZE ) + i );

	/* Post message */
	if ( ( rc = vmbus_post_message ( hv, &gpadlhdr.gpadlhdr.header,
					 sizeof ( gpadlhdr ) ) ) != 0 )
		return rc;

	/* Wait for response */
	if ( ( rc = vmbus_wait_for_message ( hv ) ) != 0 )
		return rc;

	/* Check response */
	if ( created->header.type != cpu_to_le32 ( VMBUS_GPADL_CREATED ) ) {
		DBGC ( vmdev, "VMBUS %s unexpected GPADL response type %d\n",
		       vmdev->dev.name, le32_to_cpu ( created->header.type ) );
		return -EPROTO;
	}
	if ( created->channel != cpu_to_le32 ( vmdev->channel ) ) {
		DBGC ( vmdev, "VMBUS %s unexpected GPADL channel %d\n",
		       vmdev->dev.name, le32_to_cpu ( created->channel ) );
		return -EPROTO;
	}
	if ( created->gpadl != cpu_to_le32 ( gpadl ) ) {
		DBGC ( vmdev, "VMBUS %s unexpected GPADL ID %#08x\n",
		       vmdev->dev.name, le32_to_cpu ( created->gpadl ) );
		return -EPROTO;
	}
	if ( created->status != 0 ) {
		DBGC ( vmdev, "VMBUS %s GPADL creation failed: %#08x\n",
		       vmdev->dev.name, le32_to_cpu ( created->status ) );
		return -EPROTO;
	}

	DBGC ( vmdev, "VMBUS %s GPADL %#08x is [%08lx,%08lx)\n",
	       vmdev->dev.name, gpadl, addr, ( addr + len ) );
	return gpadl;
}

/**
 * Tear down GPA descriptor list
 *
 * @v vmdev		VMBus device
 * @v gpadl		GPADL ID
 * @ret rc		Return status code
 */
int vmbus_gpadl_teardown ( struct vmbus_device *vmdev, unsigned int gpadl ) {
	struct hv_hypervisor *hv = vmdev->hv;
	struct vmbus *vmbus = hv->vmbus;
	struct vmbus_gpadl_teardown teardown;
	const struct vmbus_gpadl_torndown *torndown = &vmbus->message->torndown;
	int rc;

	/* Construct message */
	memset ( &teardown, 0, sizeof ( teardown ) );
	teardown.header.type = cpu_to_le32 ( VMBUS_GPADL_TEARDOWN );
	teardown.channel = cpu_to_le32 ( vmdev->channel );
	teardown.gpadl = cpu_to_le32 ( gpadl );

	/* Post message */
	if ( ( rc = vmbus_post_message ( hv, &teardown.header,
					 sizeof ( teardown ) ) ) != 0 )
		return rc;

	/* Wait for response */
	if ( ( rc = vmbus_wait_for_message ( hv ) ) != 0 )
		return rc;

	/* Check response */
	if ( torndown->header.type != cpu_to_le32 ( VMBUS_GPADL_TORNDOWN ) ) {
		DBGC ( vmdev, "VMBUS %s unexpected GPADL response type %d\n",
		       vmdev->dev.name, le32_to_cpu ( torndown->header.type ) );
		return -EPROTO;
	}
	if ( torndown->gpadl != cpu_to_le32 ( gpadl ) ) {
		DBGC ( vmdev, "VMBUS %s unexpected GPADL ID %#08x\n",
		       vmdev->dev.name, le32_to_cpu ( torndown->gpadl ) );
		return -EPROTO;
	}

	return 0;
}

/**
 * Open VMBus channel
 *
 * @v vmdev		VMBus device
 * @v op		Channel operations
 * @v out_len		Outbound ring buffer length
 * @v in_len		Inbound ring buffer length
 * @v mtu		Maximum expected data packet length (including headers)
 * @ret rc		Return status code
 *
 * Both outbound and inbound ring buffer lengths must be a power of
 * two and a multiple of PAGE_SIZE.  The requirement to be a power of
 * two is a policy decision taken to simplify the ring buffer indexing
 * logic.
 */
int vmbus_open ( struct vmbus_device *vmdev,
		 struct vmbus_channel_operations *op,
		 size_t out_len, size_t in_len, size_t mtu ) {
	struct hv_hypervisor *hv = vmdev->hv;
	struct vmbus *vmbus = hv->vmbus;
	struct vmbus_open_channel open;
	const struct vmbus_open_channel_result *opened =
		&vmbus->message->opened;
	size_t len;
	void *ring;
	void *packet;
	int gpadl;
	uint32_t open_id;
	int rc;

	/* Sanity checks */
	assert ( ( out_len % PAGE_SIZE ) == 0 );
	assert ( ( out_len & ( out_len - 1 ) ) == 0 );
	assert ( ( in_len % PAGE_SIZE ) == 0 );
	assert ( ( in_len & ( in_len - 1 ) ) == 0 );
	assert ( mtu >= ( sizeof ( struct vmbus_packet_header ) +
			  sizeof ( struct vmbus_packet_footer ) ) );

	/* Allocate packet buffer */
	packet = malloc ( mtu );
	if ( ! packet ) {
		rc = -ENOMEM;
		goto err_alloc_packet;
	}

	/* Allocate ring buffer */
	len = ( sizeof ( *vmdev->out ) + out_len +
		sizeof ( *vmdev->in ) + in_len );
	assert ( ( len % PAGE_SIZE ) == 0 );
	ring = malloc_dma ( len, PAGE_SIZE );
	if ( ! ring ) {
		rc = -ENOMEM;
		goto err_alloc_ring;
	}
	memset ( ring, 0, len );

	/* Establish GPADL for ring buffer */
	gpadl = vmbus_establish_gpadl ( vmdev, virt_to_user ( ring ), len );
	if ( gpadl < 0 ) {
		rc = gpadl;
		goto err_establish;
	}

	/* Construct message */
	memset ( &open, 0, sizeof ( open ) );
	open.header.type = cpu_to_le32 ( VMBUS_OPEN_CHANNEL );
	open.channel = cpu_to_le32 ( vmdev->channel );
	open_id = random();
	open.id = open_id; /* Opaque random value: endianness irrelevant */
	open.gpadl = cpu_to_le32 ( gpadl );
	open.out_pages = ( ( sizeof ( *vmdev->out ) / PAGE_SIZE ) +
			   ( out_len / PAGE_SIZE ) );

	/* Post message */
	if ( ( rc = vmbus_post_message ( hv, &open.header,
					 sizeof ( open ) ) ) != 0 )
		return rc;

	/* Wait for response */
	if ( ( rc = vmbus_wait_for_message ( hv ) ) != 0 )
		return rc;

	/* Check response */
	if ( opened->header.type != cpu_to_le32 ( VMBUS_OPEN_CHANNEL_RESULT ) ){
		DBGC ( vmdev, "VMBUS %s unexpected open response type %d\n",
		       vmdev->dev.name, le32_to_cpu ( opened->header.type ) );
		return -EPROTO;
	}
	if ( opened->channel != cpu_to_le32 ( vmdev->channel ) ) {
		DBGC ( vmdev, "VMBUS %s unexpected opened channel %#08x\n",
		       vmdev->dev.name, le32_to_cpu ( opened->channel ) );
		return -EPROTO;
	}
	if ( opened->id != open_id /* Non-endian */ ) {
		DBGC ( vmdev, "VMBUS %s unexpected open ID %#08x\n",
		       vmdev->dev.name, le32_to_cpu ( opened->id ) );
		return -EPROTO;
	}
	if ( opened->status != 0 ) {
		DBGC ( vmdev, "VMBUS %s open failed: %#08x\n",
		       vmdev->dev.name, le32_to_cpu ( opened->status ) );
		return -EPROTO;
	}

	/* Store channel parameters */
	vmdev->out_len = out_len;
	vmdev->in_len = in_len;
	vmdev->out = ring;
	vmdev->in = ( ring + sizeof ( *vmdev->out ) + out_len );
	vmdev->gpadl = gpadl;
	vmdev->op = op;
	vmdev->mtu = mtu;
	vmdev->packet = packet;

	DBGC ( vmdev, "VMBUS %s channel GPADL %#08x ring "
		"[%#08lx,%#08lx,%#08lx)\n", vmdev->dev.name, vmdev->gpadl,
		virt_to_phys ( vmdev->out ), virt_to_phys ( vmdev->in ),
		( virt_to_phys ( vmdev->out ) + len ) );
	return 0;

	vmbus_gpadl_teardown ( vmdev, vmdev->gpadl );
 err_establish:
	free_dma ( ring, len );
 err_alloc_ring:
	free ( packet );
 err_alloc_packet:
	return rc;
}

/**
 * Close VMBus channel
 *
 * @v vmdev		VMBus device
 */
void vmbus_close ( struct vmbus_device *vmdev ) {
	struct hv_hypervisor *hv = vmdev->hv;
	struct vmbus_close_channel close;
	size_t len;
	int rc;

	/* Construct message */
	memset ( &close, 0, sizeof ( close ) );
	close.header.type = cpu_to_le32 ( VMBUS_CLOSE_CHANNEL );
	close.channel = cpu_to_le32 ( vmdev->channel );

	/* Post message */
	if ( ( rc = vmbus_post_message ( hv, &close.header,
					 sizeof ( close ) ) ) != 0 ) {
		DBGC ( vmdev, "VMBUS %s failed to close: %s\n",
		       vmdev->dev.name, strerror ( rc ) );
		/* Continue to attempt to tear down GPADL, so that our
		 * memory is no longer accessible by the remote VM.
		 */
	}

	/* Tear down GPADL */
	if ( ( rc = vmbus_gpadl_teardown ( vmdev,
					   vmdev->gpadl ) ) != 0 ) {
		DBGC ( vmdev, "VMBUS %s failed to tear down channel GPADL: "
		       "%s\n", vmdev->dev.name, strerror ( rc ) );
		/* We can't prevent the remote VM from continuing to
		 * access this memory, so leak it.
		 */
		return;
	}

	/* Free ring buffer */
	len = ( sizeof ( *vmdev->out ) + vmdev->out_len +
		sizeof ( *vmdev->in ) + vmdev->in_len );
	free_dma ( vmdev->out, len );
	vmdev->out = NULL;
	vmdev->in = NULL;

	/* Free packet buffer */
	free ( vmdev->packet );
	vmdev->packet = NULL;

	DBGC ( vmdev, "VMBUS %s closed\n", vmdev->dev.name );
}

/**
 * Signal channel via monitor page
 *
 * @v vmdev		VMBus device
 */
static void vmbus_signal_monitor ( struct vmbus_device *vmdev ) {
	struct hv_hypervisor *hv = vmdev->hv;
	struct vmbus *vmbus = hv->vmbus;
	struct hv_monitor_trigger *trigger;
	unsigned int group;
	unsigned int bit;

	/* Set bit in monitor trigger group */
	group = ( vmdev->monitor / ( 8 * sizeof ( trigger->pending ) ));
	bit = ( vmdev->monitor % ( 8 * sizeof ( trigger->pending ) ) );
	trigger = &vmbus->monitor_out->trigger[group];
	hv_set_bit ( trigger, bit );
}

/**
 * Signal channel via hypervisor event
 *
 * @v vmdev		VMBus device
 */
static void vmbus_signal_event ( struct vmbus_device *vmdev ) {
	struct hv_hypervisor *hv = vmdev->hv;
	int rc;

	/* Signal hypervisor event */
	if ( ( rc = hv_signal_event ( hv, VMBUS_EVENT_ID, 0 ) ) != 0 ) {
		DBGC ( vmdev, "VMBUS %s could not signal event: %s\n",
		       vmdev->dev.name, strerror ( rc ) );
		return;
	}
}

/**
 * Fill outbound ring buffer
 *
 * @v vmdev		VMBus device
 * @v prod		Producer index
 * @v data		Data
 * @v len		Length
 * @ret prod		New producer index
 *
 * The caller must ensure that there is sufficient space in the ring
 * buffer.
 */
static size_t vmbus_produce ( struct vmbus_device *vmdev, size_t prod,
			      const void *data, size_t len ) {
	size_t first;
	size_t second;

	/* Determine fragment lengths */
	first = ( vmdev->out_len - prod );
	if ( first > len )
		first = len;
	second = ( len - first );

	/* Copy fragment(s) */
	memcpy ( &vmdev->out->data[prod], data, first );
	if ( second )
		memcpy ( &vmdev->out->data[0], ( data + first ), second );

	return ( ( prod + len ) & ( vmdev->out_len - 1 ) );
}

/**
 * Consume inbound ring buffer
 *
 * @v vmdev		VMBus device
 * @v cons		Consumer index
 * @v data		Data buffer, or NULL
 * @v len		Length to consume
 * @ret cons		New consumer index
 */
static size_t vmbus_consume ( struct vmbus_device *vmdev, size_t cons,
			      void *data, size_t len ) {
	size_t first;
	size_t second;

	/* Determine fragment lengths */
	first = ( vmdev->in_len - cons );
	if ( first > len )
		first = len;
	second = ( len - first );

	/* Copy fragment(s) */
	memcpy ( data, &vmdev->in->data[cons], first );
	if ( second )
		memcpy ( ( data + first ), &vmdev->in->data[0], second );

	return ( ( cons + len ) & ( vmdev->in_len - 1 ) );
}

/**
 * Send packet via ring buffer
 *
 * @v vmdev		VMBus device
 * @v header		Packet header
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 *
 * Send a packet via the outbound ring buffer.  All fields in the
 * packet header must be filled in, with the exception of the total
 * packet length.
 */
static int vmbus_send ( struct vmbus_device *vmdev,
			struct vmbus_packet_header *header,
			const void *data, size_t len ) {
	struct hv_hypervisor *hv = vmdev->hv;
	struct vmbus *vmbus = hv->vmbus;
	static uint8_t padding[ 8 - 1 ];
	struct vmbus_packet_footer footer;
	size_t header_len;
	size_t pad_len;
	size_t footer_len;
	size_t ring_len;
	size_t cons;
	size_t prod;
	size_t old_prod;
	size_t fill;

	/* Sanity check */
	assert ( vmdev->out != NULL );

	/* Calculate lengths */
	header_len = ( le16_to_cpu ( header->hdr_qlen ) * 8 );
	pad_len = ( ( -len ) & ( 8 - 1 ) );
	footer_len = sizeof ( footer );
	ring_len = ( header_len + len + pad_len + footer_len );

	/* Check that we have enough room in the outbound ring buffer */
	cons = le32_to_cpu ( vmdev->out->cons );
	prod = le32_to_cpu ( vmdev->out->prod );
	old_prod = prod;
	fill = ( ( prod - cons ) & ( vmdev->out_len - 1 ) );
	if ( ( fill + ring_len ) >= vmdev->out_len ) {
		DBGC ( vmdev, "VMBUS %s ring buffer full\n", vmdev->dev.name );
		return -ENOBUFS;
	}

	/* Complete header */
	header->qlen = cpu_to_le16 ( ( ring_len - footer_len ) / 8 );

	/* Construct footer */
	footer.reserved = 0;
	footer.prod = vmdev->out->prod;

	/* Copy packet to buffer */
	DBGC2 ( vmdev, "VMBUS %s sending:\n", vmdev->dev.name );
	DBGC2_HDA ( vmdev, prod, header, header_len );
	prod = vmbus_produce ( vmdev, prod, header, header_len );
	DBGC2_HDA ( vmdev, prod, data, len );
	prod = vmbus_produce ( vmdev, prod, data, len );
	prod = vmbus_produce ( vmdev, prod, padding, pad_len );
	DBGC2_HDA ( vmdev, prod, &footer, sizeof ( footer ) );
	prod = vmbus_produce ( vmdev, prod, &footer, sizeof ( footer ) );
	assert ( ( ( prod - old_prod ) & ( vmdev->out_len - 1 ) ) == ring_len );

	/* Update producer index */
	wmb();
	vmdev->out->prod = cpu_to_le32 ( prod );

	/* Return if we do not need to signal the host.  This follows
	 * the logic of hv_need_to_signal() in the Linux driver.
	 */
	mb();
	if ( vmdev->out->intr_mask )
		return 0;
	rmb();
	cons = le32_to_cpu ( vmdev->out->cons );
	if ( cons != old_prod )
		return 0;

	/* Set channel bit in interrupt page */
	hv_set_bit ( vmbus->intr->out, vmdev->channel );

	/* Signal the host */
	vmdev->signal ( vmdev );

	return 0;
}

/**
 * Send control packet via ring buffer
 *
 * @v vmdev		VMBus device
 * @v xid		Transaction ID (or zero to not request completion)
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 *
 * Send data using a VMBUS_DATA_INBAND packet.
 */
int vmbus_send_control ( struct vmbus_device *vmdev, uint64_t xid,
			 const void *data, size_t len ) {
	struct vmbus_packet_header *header = vmdev->packet;

	/* Construct header in packet buffer */
	assert ( header != NULL );
	header->type = cpu_to_le16 ( VMBUS_DATA_INBAND );
	header->hdr_qlen = cpu_to_le16 ( sizeof ( *header ) / 8 );
	header->flags = ( xid ?
			  cpu_to_le16 ( VMBUS_COMPLETION_REQUESTED ) : 0 );
	header->xid = xid; /* Non-endian */

	return vmbus_send ( vmdev, header, data, len );
}

/**
 * Send data packet via ring buffer
 *
 * @v vmdev		VMBus device
 * @v xid		Transaction ID
 * @v data		Data
 * @v len		Length of data
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 *
 * Send data using a VMBUS_DATA_GPA_DIRECT packet.  The caller is
 * responsible for ensuring that the I/O buffer remains untouched
 * until the corresponding completion has been received.
 */
int vmbus_send_data ( struct vmbus_device *vmdev, uint64_t xid,
		      const void *data, size_t len, struct io_buffer *iobuf ) {
	physaddr_t addr = virt_to_phys ( iobuf->data );
	unsigned int pfn_count = hv_pfn_count ( addr, iob_len ( iobuf ) );
	struct {
		struct vmbus_gpa_direct_header gpa;
		struct vmbus_gpa_range range;
		uint64_t pfn[pfn_count];
	} __attribute__ (( packed )) *header = vmdev->packet;
	unsigned int i;

	/* Sanity check */
	assert ( header != NULL );
	assert ( sizeof ( *header ) <= vmdev->mtu );

	/* Construct header in packet buffer */
	header->gpa.header.type = cpu_to_le16 ( VMBUS_DATA_GPA_DIRECT );
	header->gpa.header.hdr_qlen = cpu_to_le16 ( sizeof ( *header ) / 8 );
	header->gpa.header.flags = cpu_to_le16 ( VMBUS_COMPLETION_REQUESTED );
	header->gpa.header.xid = xid; /* Non-endian */
	header->gpa.range_count = 1;
	header->range.len = cpu_to_le32 ( iob_len ( iobuf ) );
	header->range.offset = cpu_to_le32 ( addr & ( PAGE_SIZE - 1 ) );
	for ( i = 0 ; i < pfn_count ; i++ )
		header->pfn[i] = ( ( addr / PAGE_SIZE ) + i );

	return vmbus_send ( vmdev, &header->gpa.header, data, len );
}

/**
 * Send completion packet via ring buffer
 *
 * @v vmdev		VMBus device
 * @v xid		Transaction ID
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 *
 * Send data using a VMBUS_COMPLETION packet.
 */
int vmbus_send_completion ( struct vmbus_device *vmdev, uint64_t xid,
			    const void *data, size_t len ) {
	struct vmbus_packet_header *header = vmdev->packet;

	/* Construct header in packet buffer */
	assert ( header != NULL );
	header->type = cpu_to_le16 ( VMBUS_COMPLETION );
	header->hdr_qlen = cpu_to_le16 ( sizeof ( *header ) / 8 );
	header->flags = 0;
	header->xid = xid; /* Non-endian */

	return vmbus_send ( vmdev, header, data, len );
}

/**
 * Send cancellation packet via ring buffer
 *
 * @v vmdev		VMBus device
 * @v xid		Transaction ID
 * @ret rc		Return status code
 *
 * Send data using a VMBUS_CANCELLATION packet.
 */
int vmbus_send_cancellation ( struct vmbus_device *vmdev, uint64_t xid ) {
	struct vmbus_packet_header *header = vmdev->packet;

	/* Construct header in packet buffer */
	assert ( header != NULL );
	header->type = cpu_to_le16 ( VMBUS_CANCELLATION );
	header->hdr_qlen = cpu_to_le16 ( sizeof ( *header ) / 8 );
	header->flags = 0;
	header->xid = xid; /* Non-endian */

	return vmbus_send ( vmdev, header, NULL, 0 );
}

/**
 * Get transfer page set from pageset ID
 *
 * @v vmdev		VMBus device
 * @v pageset		Page set ID (in protocol byte order)
 * @ret pages		Page set, or NULL if not found
 */
static struct vmbus_xfer_pages * vmbus_xfer_pages ( struct vmbus_device *vmdev,
						    uint16_t pageset ) {
	struct vmbus_xfer_pages *pages;

	/* Locate page set */
	list_for_each_entry ( pages, &vmdev->pages, list ) {
		if ( pages->pageset == pageset )
			return pages;
	}

	DBGC ( vmdev, "VMBUS %s unrecognised page set ID %#04x\n",
	       vmdev->dev.name, le16_to_cpu ( pageset ) );
	return NULL;
}

/**
 * Construct I/O buffer list from transfer pages
 *
 * @v vmdev		VMBus device
 * @v header		Transfer page header
 * @v list		I/O buffer list to populate
 * @ret rc		Return status code
 */
static int vmbus_xfer_page_iobufs ( struct vmbus_device *vmdev,
				    struct vmbus_packet_header *header,
				    struct list_head *list ) {
	struct vmbus_xfer_page_header *page_header =
		container_of ( header, struct vmbus_xfer_page_header, header );
	struct vmbus_xfer_pages *pages;
	struct io_buffer *iobuf;
	struct io_buffer *tmp;
	size_t len;
	size_t offset;
	unsigned int range_count;
	unsigned int i;
	int rc;

	/* Sanity check */
	assert ( header->type == cpu_to_le16 ( VMBUS_DATA_XFER_PAGES ) );

	/* Locate page set */
	pages = vmbus_xfer_pages ( vmdev, page_header->pageset );
	if ( ! pages ) {
		rc = -ENOENT;
		goto err_pages;
	}

	/* Allocate and populate I/O buffers */
	range_count = le32_to_cpu ( page_header->range_count );
	for ( i = 0 ; i < range_count ; i++ ) {

		/* Parse header */
		len = le32_to_cpu ( page_header->range[i].len );
		offset = le32_to_cpu ( page_header->range[i].offset );

		/* Allocate I/O buffer */
		iobuf = alloc_iob ( len );
		if ( ! iobuf ) {
			DBGC ( vmdev, "VMBUS %s could not allocate %zd-byte "
			       "I/O buffer\n", vmdev->dev.name, len );
			rc = -ENOMEM;
			goto err_alloc;
		}

		/* Add I/O buffer to list */
		list_add ( &iobuf->list, list );

		/* Populate I/O buffer */
		if ( ( rc = pages->op->copy ( pages, iob_put ( iobuf, len ),
					      offset, len ) ) != 0 ) {
			DBGC ( vmdev, "VMBUS %s could not populate I/O buffer "
			       "range [%zd,%zd): %s\n",
			       vmdev->dev.name, offset, len, strerror ( rc ) );
			goto err_copy;
		}
	}

	return 0;

 err_copy:
 err_alloc:
	list_for_each_entry_safe ( iobuf, tmp, list, list ) {
		list_del ( &iobuf->list );
		free_iob ( iobuf );
	}
 err_pages:
	return rc;
}

/**
 * Poll ring buffer
 *
 * @v vmdev		VMBus device
 * @ret rc		Return status code
 */
int vmbus_poll ( struct vmbus_device *vmdev ) {
	struct vmbus_packet_header *header = vmdev->packet;
	struct list_head list;
	void *data;
	size_t header_len;
	size_t len;
	size_t footer_len;
	size_t ring_len;
	size_t cons;
	size_t old_cons;
	uint64_t xid;
	int rc;

	/* Sanity checks */
	assert ( vmdev->packet != NULL );
	assert ( vmdev->in != NULL );

	/* Return immediately if buffer is empty */
	if ( ! vmbus_has_data ( vmdev ) )
		return 0;
	cons = le32_to_cpu ( vmdev->in->cons );
	old_cons = cons;

	/* Consume (start of) header */
	cons = vmbus_consume ( vmdev, cons, header, sizeof ( *header ) );

	/* Parse and sanity check header */
	header_len = ( le16_to_cpu ( header->hdr_qlen ) * 8 );
	if ( header_len < sizeof ( *header ) ) {
		DBGC ( vmdev, "VMBUS %s received underlength header (%zd "
		       "bytes)\n", vmdev->dev.name, header_len );
		return -EINVAL;
	}
	len = ( ( le16_to_cpu ( header->qlen ) * 8 ) - header_len );
	footer_len = sizeof ( struct vmbus_packet_footer );
	ring_len = ( header_len + len + footer_len );
	if ( ring_len > vmdev->mtu ) {
		DBGC ( vmdev, "VMBUS %s received overlength packet (%zd "
		       "bytes)\n", vmdev->dev.name, ring_len );
		return -ERANGE;
	}
	xid = le64_to_cpu ( header->xid );

	/* Consume remainder of packet */
	cons = vmbus_consume ( vmdev, cons,
			       ( ( ( void * ) header ) + sizeof ( *header ) ),
			       ( ring_len - sizeof ( *header ) ) );
	DBGC2 ( vmdev, "VMBUS %s received:\n", vmdev->dev.name );
	DBGC2_HDA ( vmdev, old_cons, header, ring_len );
	assert ( ( ( cons - old_cons ) & ( vmdev->in_len - 1 ) ) == ring_len );

	/* Allocate I/O buffers, if applicable */
	INIT_LIST_HEAD ( &list );
	if ( header->type == cpu_to_le16 ( VMBUS_DATA_XFER_PAGES ) ) {
		if ( ( rc = vmbus_xfer_page_iobufs ( vmdev, header,
						     &list ) ) != 0 )
			return rc;
	}

	/* Update producer index */
	rmb();
	vmdev->in->cons = cpu_to_le32 ( cons );

	/* Handle packet */
	data = ( ( ( void * ) header ) + header_len );
	switch ( header->type ) {

	case cpu_to_le16 ( VMBUS_DATA_INBAND ) :
		if ( ( rc = vmdev->op->recv_control ( vmdev, xid, data,
						      len ) ) != 0 ) {
			DBGC ( vmdev, "VMBUS %s could not handle control "
			       "packet: %s\n",
			       vmdev->dev.name, strerror ( rc ) );
			return rc;
		}
		break;

	case cpu_to_le16 ( VMBUS_DATA_XFER_PAGES ) :
		if ( ( rc = vmdev->op->recv_data ( vmdev, xid, data, len,
						   &list ) ) != 0 ) {
			DBGC ( vmdev, "VMBUS %s could not handle data packet: "
			       "%s\n", vmdev->dev.name, strerror ( rc ) );
			return rc;
		}
		break;

	case cpu_to_le16 ( VMBUS_COMPLETION ) :
		if ( ( rc = vmdev->op->recv_completion ( vmdev, xid, data,
							 len ) ) != 0 ) {
			DBGC ( vmdev, "VMBUS %s could not handle completion: "
			       "%s\n", vmdev->dev.name, strerror ( rc ) );
			return rc;
		}
		break;

	case cpu_to_le16 ( VMBUS_CANCELLATION ) :
		if ( ( rc = vmdev->op->recv_cancellation ( vmdev, xid ) ) != 0){
			DBGC ( vmdev, "VMBUS %s could not handle cancellation: "
			       "%s\n", vmdev->dev.name, strerror ( rc ) );
			return rc;
		}
		break;

	default:
		DBGC ( vmdev, "VMBUS %s unknown packet type %d\n",
		       vmdev->dev.name, le16_to_cpu ( header->type ) );
		return -ENOTSUP;
	}

	return 0;
}

/**
 * Dump channel status (for debugging)
 *
 * @v vmdev		VMBus device
 */
void vmbus_dump_channel ( struct vmbus_device *vmdev ) {
	size_t out_prod = le32_to_cpu ( vmdev->out->prod );
	size_t out_cons = le32_to_cpu ( vmdev->out->cons );
	size_t in_prod = le32_to_cpu ( vmdev->in->prod );
	size_t in_cons = le32_to_cpu ( vmdev->in->cons );
	size_t in_len;
	size_t first;
	size_t second;

	/* Dump ring status */
	DBGC ( vmdev, "VMBUS %s out %03zx:%03zx%s in %03zx:%03zx%s\n",
	       vmdev->dev.name, out_prod, out_cons,
	       ( vmdev->out->intr_mask ? "(m)" : "" ), in_prod, in_cons,
	       ( vmdev->in->intr_mask ? "(m)" : "" ) );

	/* Dump inbound ring contents, if any */
	if ( in_prod != in_cons ) {
		in_len = ( ( in_prod - in_cons ) &
			   ( vmdev->in_len - 1 ) );
		first = ( vmdev->in_len - in_cons );
		if ( first > in_len )
			first = in_len;
		second = ( in_len - first );
		DBGC_HDA ( vmdev, in_cons, &vmdev->in->data[in_cons], first );
		DBGC_HDA ( vmdev, 0, &vmdev->in->data[0], second );
	}
}

/**
 * Find driver for VMBus device
 *
 * @v vmdev		VMBus device
 * @ret driver		Driver, or NULL
 */
static struct vmbus_driver * vmbus_find_driver ( const union uuid *type ) {
	struct vmbus_driver *vmdrv;

	for_each_table_entry ( vmdrv, VMBUS_DRIVERS ) {
		if ( memcmp ( &vmdrv->type, type, sizeof ( *type ) ) == 0 )
			return vmdrv;
	}
	return NULL;
}

/**
 * Probe channels
 *
 * @v hv		Hyper-V hypervisor
 * @v parent		Parent device
 * @ret rc		Return status code
 */
static int vmbus_probe_channels ( struct hv_hypervisor *hv,
				  struct device *parent ) {
	struct vmbus *vmbus = hv->vmbus;
	const struct vmbus_message_header *header = &vmbus->message->header;
	const struct vmbus_offer_channel *offer = &vmbus->message->offer;
	const union uuid *type;
	struct vmbus_driver *driver;
	struct vmbus_device *vmdev;
	struct vmbus_device *tmp;
	unsigned int channel;
	int rc;

	/* Post message */
	if ( ( rc = vmbus_post_empty_message ( hv, VMBUS_REQUEST_OFFERS ) ) !=0)
		goto err_post_message;

	/* Collect responses */
	while ( 1 ) {

		/* Wait for response */
		if ( ( rc = vmbus_wait_for_message ( hv ) ) != 0 )
			goto err_wait_for_message;

		/* Handle response */
		if ( header->type == cpu_to_le32 ( VMBUS_OFFER_CHANNEL ) ) {

			/* Parse offer */
			type = &offer->type;
			channel = le32_to_cpu ( offer->channel );
			DBGC2 ( vmbus, "VMBUS %p offer %d type %s",
				vmbus, channel, uuid_ntoa ( type ) );
			if ( offer->monitored )
				DBGC2 ( vmbus, " monitor %d", offer->monitor );
			DBGC2 ( vmbus, "\n" );

			/* Look for a driver */
			driver = vmbus_find_driver ( type );
			if ( ! driver ) {
				DBGC2 ( vmbus, "VMBUS %p has no driver for "
					"type %s\n", vmbus, uuid_ntoa ( type ));
				/* Not a fatal error */
				continue;
			}

			/* Allocate and initialise device */
			vmdev = zalloc ( sizeof ( *vmdev ) );
			if ( ! vmdev ) {
				rc = -ENOMEM;
				goto err_alloc_vmdev;
			}
			snprintf ( vmdev->dev.name, sizeof ( vmdev->dev.name ),
				   "vmbus:%02x", channel );
			vmdev->dev.desc.bus_type = BUS_TYPE_HV;
			INIT_LIST_HEAD ( &vmdev->dev.children );
			list_add_tail ( &vmdev->dev.siblings,
					&parent->children );
			vmdev->dev.parent = parent;
			vmdev->hv = hv;
			vmdev->channel = channel;
			vmdev->monitor = offer->monitor;
			vmdev->signal = ( offer->monitored ?
					  vmbus_signal_monitor :
					  vmbus_signal_event );
			INIT_LIST_HEAD ( &vmdev->pages );
			vmdev->driver = driver;
			vmdev->dev.driver_name = driver->name;
			DBGC ( vmdev, "VMBUS %s has driver \"%s\"\n",
			       vmdev->dev.name, vmdev->driver->name );

		} else if ( header->type ==
			    cpu_to_le32 ( VMBUS_ALL_OFFERS_DELIVERED ) ) {

			break;

		} else {
			DBGC ( vmbus, "VMBUS %p unexpected offer response type "
			       "%d\n", vmbus, le32_to_cpu ( header->type ) );
			rc = -EPROTO;
			goto err_unexpected_offer;
		}
	}

	/* Probe all devices.  We do this only after completing
	 * enumeration since devices will need to send and receive
	 * VMBus messages.
	 */
	list_for_each_entry ( vmdev, &parent->children, dev.siblings ) {
		if ( ( rc = vmdev->driver->probe ( vmdev ) ) != 0 ) {
			DBGC ( vmdev, "VMBUS %s could not probe: %s\n",
			       vmdev->dev.name, strerror ( rc ) );
			goto err_probe;
		}
	}

	return 0;

 err_probe:
	/* Remove driver from each device that was already probed */
	list_for_each_entry_continue_reverse ( vmdev, &parent->children,
					       dev.siblings ) {
		vmdev->driver->remove ( vmdev );
	}
 err_unexpected_offer:
 err_alloc_vmdev:
 err_wait_for_message:
	/* Free any devices allocated (but potentially not yet probed) */
	list_for_each_entry_safe ( vmdev, tmp, &parent->children,
				   dev.siblings ) {
		list_del ( &vmdev->dev.siblings );
		free ( vmdev );
	}
 err_post_message:
	return rc;
}

/**
 * Remove channels
 *
 * @v hv		Hyper-V hypervisor
 * @v parent		Parent device
 */
static void vmbus_remove_channels ( struct hv_hypervisor *hv __unused,
				    struct device *parent ) {
	struct vmbus_device *vmdev;
	struct vmbus_device *tmp;

	/* Remove devices */
	list_for_each_entry_safe ( vmdev, tmp, &parent->children,
				   dev.siblings ) {
		vmdev->driver->remove ( vmdev );
		assert ( list_empty ( &vmdev->dev.children ) );
		assert ( vmdev->out == NULL );
		assert ( vmdev->in == NULL );
		assert ( vmdev->packet == NULL );
		assert ( list_empty ( &vmdev->pages ) );
		list_del ( &vmdev->dev.siblings );
		free ( vmdev );
	}
}

/**
 * Probe Hyper-V virtual machine bus
 *
 * @v hv		Hyper-V hypervisor
 * @v parent		Parent device
 * @ret rc		Return status code
 */
int vmbus_probe ( struct hv_hypervisor *hv, struct device *parent ) {
	struct vmbus *vmbus;
	int rc;

	/* Allocate and initialise structure */
	vmbus = zalloc ( sizeof ( *vmbus ) );
	if ( ! vmbus ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	hv->vmbus = vmbus;

	/* Initialise message buffer pointer
	 *
	 * We use a pointer to the fixed-size Hyper-V received message
	 * buffer.  This allows us to access fields within received
	 * messages without first checking the message size: any
	 * fields beyond the end of the message will read as zero.
	 */
	vmbus->message = ( ( void * ) hv->message->received.data );
	assert ( sizeof ( *vmbus->message ) <=
		 sizeof ( hv->message->received.data ) );

	/* Allocate interrupt and monitor pages */
	if ( ( rc = hv_alloc_pages ( hv, &vmbus->intr, &vmbus->monitor_in,
				     &vmbus->monitor_out, NULL ) ) != 0 )
		goto err_alloc_pages;

	/* Enable message interrupt */
	hv_enable_sint ( hv, VMBUS_MESSAGE_SINT );

	/* Negotiate protocol version */
	if ( ( rc = vmbus_negotiate_version ( hv ) ) != 0 )
		goto err_negotiate_version;

	/* Enumerate channels */
	if ( ( rc = vmbus_probe_channels ( hv, parent ) ) != 0 )
		goto err_probe_channels;

	return 0;

	vmbus_remove_channels ( hv, parent );
 err_probe_channels:
	vmbus_unload ( hv );
 err_negotiate_version:
	hv_disable_sint ( hv, VMBUS_MESSAGE_SINT );
	hv_free_pages ( hv, vmbus->intr, vmbus->monitor_in, vmbus->monitor_out,
			NULL );
 err_alloc_pages:
	free ( vmbus );
 err_alloc:
	return rc;
}

/**
 * Remove Hyper-V virtual machine bus
 *
 * @v hv		Hyper-V hypervisor
 * @v parent		Parent device
 */
void vmbus_remove ( struct hv_hypervisor *hv, struct device *parent ) {
	struct vmbus *vmbus = hv->vmbus;

	vmbus_remove_channels ( hv, parent );
	vmbus_unload ( hv );
	hv_disable_sint ( hv, VMBUS_MESSAGE_SINT );
	hv_free_pages ( hv, vmbus->intr, vmbus->monitor_in, vmbus->monitor_out,
			NULL );
	free ( vmbus );
}
