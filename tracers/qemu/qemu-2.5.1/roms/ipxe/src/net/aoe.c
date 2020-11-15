/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/list.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/uaccess.h>
#include <ipxe/netdevice.h>
#include <ipxe/features.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/uri.h>
#include <ipxe/open.h>
#include <ipxe/ata.h>
#include <ipxe/device.h>
#include <ipxe/aoe.h>

/** @file
 *
 * AoE protocol
 *
 */

FEATURE ( FEATURE_PROTOCOL, "AoE", DHCP_EB_FEATURE_AOE, 1 );

struct net_protocol aoe_protocol __net_protocol;

/******************************************************************************
 *
 * AoE devices and commands
 *
 ******************************************************************************
 */

/** List of all AoE devices */
static LIST_HEAD ( aoe_devices );

/** List of active AoE commands */
static LIST_HEAD ( aoe_commands );

/** An AoE device */
struct aoe_device {
	/** Reference counter */
	struct refcnt refcnt;

	/** Network device */
	struct net_device *netdev;
	/** ATA command issuing interface */
	struct interface ata;

	/** Major number */
	uint16_t major;
	/** Minor number */
	uint8_t minor;
	/** Target MAC address */
	uint8_t target[MAX_LL_ADDR_LEN];

	/** Saved timeout value */
	unsigned long timeout;

	/** Configuration command interface */
	struct interface config;
	/** Device is configued */
	int configured;
};

/** An AoE command */
struct aoe_command {
	/** Reference count */
	struct refcnt refcnt;
	/** AOE device */
	struct aoe_device *aoedev;
	/** List of active commands */
	struct list_head list;

	/** ATA command interface */
	struct interface ata;

	/** ATA command */
	struct ata_cmd command;
	/** Command type */
	struct aoe_command_type *type;
	/** Command tag */
	uint32_t tag;

	/** Retransmission timer */
	struct retry_timer timer;
};

/** An AoE command type */
struct aoe_command_type {
	/**
	 * Calculate length of AoE command IU
	 *
	 * @v aoecmd		AoE command
	 * @ret len		Length of command IU
	 */
	size_t ( * cmd_len ) ( struct aoe_command *aoecmd );
	/**
	 * Build AoE command IU
	 *
	 * @v aoecmd		AoE command
	 * @v data		Command IU
	 * @v len		Length of command IU
	 */
	void ( * cmd ) ( struct aoe_command *aoecmd, void *data, size_t len );
	/**
	 * Handle AoE response IU
	 *
	 * @v aoecmd		AoE command
	 * @v data		Response IU
	 * @v len		Length of response IU
	 * @v ll_source		Link-layer source address
	 * @ret rc		Return status code
	 */
	int ( * rsp ) ( struct aoe_command *aoecmd, const void *data,
			size_t len, const void *ll_source );
};

/**
 * Get reference to AoE device
 *
 * @v aoedev		AoE device
 * @ret aoedev		AoE device
 */
static inline __attribute__ (( always_inline )) struct aoe_device *
aoedev_get ( struct aoe_device *aoedev ) {
	ref_get ( &aoedev->refcnt );
	return aoedev;
}

/**
 * Drop reference to AoE device
 *
 * @v aoedev		AoE device
 */
static inline __attribute__ (( always_inline )) void
aoedev_put ( struct aoe_device *aoedev ) {
	ref_put ( &aoedev->refcnt );
}

/**
 * Get reference to AoE command
 *
 * @v aoecmd		AoE command
 * @ret aoecmd		AoE command
 */
static inline __attribute__ (( always_inline )) struct aoe_command *
aoecmd_get ( struct aoe_command *aoecmd ) {
	ref_get ( &aoecmd->refcnt );
	return aoecmd;
}

/**
 * Drop reference to AoE command
 *
 * @v aoecmd		AoE command
 */
static inline __attribute__ (( always_inline )) void
aoecmd_put ( struct aoe_command *aoecmd ) {
	ref_put ( &aoecmd->refcnt );
}

/**
 * Name AoE device
 *
 * @v aoedev		AoE device
 * @ret name		AoE device name
 */
static const char * aoedev_name ( struct aoe_device *aoedev ) {
	static char buf[16];

	snprintf ( buf, sizeof ( buf ), "%s/e%d.%d", aoedev->netdev->name,
		   aoedev->major, aoedev->minor );
	return buf;
}

/**
 * Free AoE command
 *
 * @v refcnt		Reference counter
 */
static void aoecmd_free ( struct refcnt *refcnt ) {
	struct aoe_command *aoecmd =
		container_of ( refcnt, struct aoe_command, refcnt );

	assert ( ! timer_running ( &aoecmd->timer ) );
	assert ( list_empty ( &aoecmd->list ) );

	aoedev_put ( aoecmd->aoedev );
	free ( aoecmd );
}

/**
 * Close AoE command
 *
 * @v aoecmd		AoE command
 * @v rc		Reason for close
 */
static void aoecmd_close ( struct aoe_command *aoecmd, int rc ) {
	struct aoe_device *aoedev = aoecmd->aoedev;

	/* Stop timer */
	stop_timer ( &aoecmd->timer );

	/* Preserve the timeout value for subsequent commands */
	aoedev->timeout = aoecmd->timer.timeout;

	/* Remove from list of commands */
	if ( ! list_empty ( &aoecmd->list ) ) {
		list_del ( &aoecmd->list );
		INIT_LIST_HEAD ( &aoecmd->list );
		aoecmd_put ( aoecmd );
	}

	/* Shut down interfaces */
	intf_shutdown ( &aoecmd->ata, rc );
}

/**
 * Transmit AoE command request
 *
 * @v aoecmd		AoE command
 * @ret rc		Return status code
 */
static int aoecmd_tx ( struct aoe_command *aoecmd ) {
	struct aoe_device *aoedev = aoecmd->aoedev;
	struct net_device *netdev = aoedev->netdev;
	struct io_buffer *iobuf;
	struct aoehdr *aoehdr;
	size_t cmd_len;
	int rc;

	/* Sanity check */
	assert ( netdev != NULL );

	/* If we are transmitting anything that requires a response,
         * start the retransmission timer.  Do this before attempting
         * to allocate the I/O buffer, in case allocation itself
         * fails.
         */
	start_timer ( &aoecmd->timer );

	/* Create outgoing I/O buffer */
	cmd_len = aoecmd->type->cmd_len ( aoecmd );
	iobuf = alloc_iob ( MAX_LL_HEADER_LEN + cmd_len );
	if ( ! iobuf )
		return -ENOMEM;
	iob_reserve ( iobuf, MAX_LL_HEADER_LEN );
	aoehdr = iob_put ( iobuf, cmd_len );

	/* Fill AoE header */
	memset ( aoehdr, 0, sizeof ( *aoehdr ) );
	aoehdr->ver_flags = AOE_VERSION;
	aoehdr->major = htons ( aoedev->major );
	aoehdr->minor = aoedev->minor;
	aoehdr->tag = htonl ( aoecmd->tag );
	aoecmd->type->cmd ( aoecmd, iobuf->data, iob_len ( iobuf ) );

	/* Send packet */
	if ( ( rc = net_tx ( iobuf, netdev, &aoe_protocol, aoedev->target,
			     netdev->ll_addr ) ) != 0 ) {
		DBGC ( aoedev, "AoE %s/%08x could not transmit: %s\n",
		       aoedev_name ( aoedev ), aoecmd->tag,
		       strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Receive AoE command response
 *
 * @v aoecmd		AoE command
 * @v iobuf		I/O buffer
 * @v ll_source		Link-layer source address
 * @ret rc		Return status code
 */
static int aoecmd_rx ( struct aoe_command *aoecmd, struct io_buffer *iobuf,
		       const void *ll_source ) {
	struct aoe_device *aoedev = aoecmd->aoedev;
	struct aoehdr *aoehdr = iobuf->data;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *aoehdr ) ) {
		DBGC ( aoedev, "AoE %s/%08x received underlength response "
		       "(%zd bytes)\n", aoedev_name ( aoedev ),
		       aoecmd->tag, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto done;
	}
	if ( ( ntohs ( aoehdr->major ) != aoedev->major ) ||
	     ( aoehdr->minor != aoedev->minor ) ) {
		DBGC ( aoedev, "AoE %s/%08x received response for incorrect "
		       "device e%d.%d\n", aoedev_name ( aoedev ), aoecmd->tag,
		       ntohs ( aoehdr->major ), aoehdr->minor );
		rc = -EINVAL;
		goto done;
	}

	/* Catch command failures */
	if ( aoehdr->ver_flags & AOE_FL_ERROR ) {
		DBGC ( aoedev, "AoE %s/%08x terminated in error\n",
		       aoedev_name ( aoedev ), aoecmd->tag );
		aoecmd_close ( aoecmd, -EIO );
		rc = -EIO;
		goto done;
	}

	/* Hand off to command completion handler */
	if ( ( rc = aoecmd->type->rsp ( aoecmd, iobuf->data, iob_len ( iobuf ),
					ll_source ) ) != 0 )
		goto done;

 done:
	/* Free I/O buffer */
	free_iob ( iobuf );

	/* Terminate command */
	aoecmd_close ( aoecmd, rc );

	return rc;
}

/**
 * Handle AoE retry timer expiry
 *
 * @v timer		AoE retry timer
 * @v fail		Failure indicator
 */
static void aoecmd_expired ( struct retry_timer *timer, int fail ) {
	struct aoe_command *aoecmd =
		container_of ( timer, struct aoe_command, timer );

	if ( fail ) {
		aoecmd_close ( aoecmd, -ETIMEDOUT );
	} else {
		aoecmd_tx ( aoecmd );
	}
}

/**
 * Calculate length of AoE ATA command IU
 *
 * @v aoecmd		AoE command
 * @ret len		Length of command IU
 */
static size_t aoecmd_ata_cmd_len ( struct aoe_command *aoecmd ) {
	struct ata_cmd *command = &aoecmd->command;

	return ( sizeof ( struct aoehdr ) + sizeof ( struct aoeata ) +
		 command->data_out_len );
}

/**
 * Build AoE ATA command IU
 *
 * @v aoecmd		AoE command
 * @v data		Command IU
 * @v len		Length of command IU
 */
static void aoecmd_ata_cmd ( struct aoe_command *aoecmd,
			     void *data, size_t len ) {
	struct aoe_device *aoedev = aoecmd->aoedev;
	struct ata_cmd *command = &aoecmd->command;
	struct aoehdr *aoehdr = data;
	struct aoeata *aoeata = &aoehdr->payload[0].ata;

	/* Sanity check */
	linker_assert ( AOE_FL_DEV_HEAD	== ATA_DEV_SLAVE, __fix_ata_h__ );
	assert ( len == ( sizeof ( *aoehdr ) + sizeof ( *aoeata ) +
			  command->data_out_len ) );

	/* Build IU */
	aoehdr->command = AOE_CMD_ATA;
	memset ( aoeata, 0, sizeof ( *aoeata ) );
	aoeata->aflags = ( ( command->cb.lba48 ? AOE_FL_EXTENDED : 0 ) |
			   ( command->cb.device & ATA_DEV_SLAVE ) |
			   ( command->data_out_len ? AOE_FL_WRITE : 0 ) );
	aoeata->err_feat = command->cb.err_feat.bytes.cur;
	aoeata->count = command->cb.count.native;
	aoeata->cmd_stat = command->cb.cmd_stat;
	aoeata->lba.u64 = cpu_to_le64 ( command->cb.lba.native );
	if ( ! command->cb.lba48 )
		aoeata->lba.bytes[3] |=
			( command->cb.device & ATA_DEV_MASK );
	copy_from_user ( aoeata->data, command->data_out, 0,
			 command->data_out_len );

	DBGC2 ( aoedev, "AoE %s/%08x ATA cmd %02x:%02x:%02x:%02x:%08llx",
		aoedev_name ( aoedev ), aoecmd->tag, aoeata->aflags,
		aoeata->err_feat, aoeata->count, aoeata->cmd_stat,
		aoeata->lba.u64 );
	if ( command->data_out_len )
		DBGC2 ( aoedev, " out %04zx", command->data_out_len );
	if ( command->data_in_len )
		DBGC2 ( aoedev, " in %04zx", command->data_in_len );
	DBGC2 ( aoedev, "\n" );
}

/**
 * Handle AoE ATA response IU
 *
 * @v aoecmd		AoE command
 * @v data		Response IU
 * @v len		Length of response IU
 * @v ll_source		Link-layer source address
 * @ret rc		Return status code
 */
static int aoecmd_ata_rsp ( struct aoe_command *aoecmd, const void *data,
			    size_t len, const void *ll_source __unused ) {
	struct aoe_device *aoedev = aoecmd->aoedev;
	struct ata_cmd *command = &aoecmd->command;
	const struct aoehdr *aoehdr = data;
	const struct aoeata *aoeata = &aoehdr->payload[0].ata;
	size_t data_len;

	/* Sanity check */
	if ( len < ( sizeof ( *aoehdr ) + sizeof ( *aoeata ) ) ) {
		DBGC ( aoedev, "AoE %s/%08x received underlength ATA response "
		       "(%zd bytes)\n", aoedev_name ( aoedev ),
		       aoecmd->tag, len );
		return -EINVAL;
	}
	data_len = ( len - ( sizeof ( *aoehdr ) + sizeof ( *aoeata ) ) );
	DBGC2 ( aoedev, "AoE %s/%08x ATA rsp %02x in %04zx\n",
		aoedev_name ( aoedev ), aoecmd->tag, aoeata->cmd_stat,
		data_len );

	/* Check for command failure */
	if ( aoeata->cmd_stat & ATA_STAT_ERR ) {
		DBGC ( aoedev, "AoE %s/%08x status %02x\n",
		       aoedev_name ( aoedev ), aoecmd->tag, aoeata->cmd_stat );
		return -EIO;
	}

	/* Check data-in length is sufficient.  (There may be trailing
	 * garbage due to Ethernet minimum-frame-size padding.)
	 */
	if ( data_len < command->data_in_len ) {
		DBGC ( aoedev, "AoE %s/%08x data-in underrun (received %zd, "
		       "expected %zd)\n", aoedev_name ( aoedev ), aoecmd->tag,
		       data_len, command->data_in_len );
		return -ERANGE;
	}

	/* Copy out data payload */
	copy_to_user ( command->data_in, 0, aoeata->data,
		       command->data_in_len );

	return 0;
}

/** AoE ATA command */
static struct aoe_command_type aoecmd_ata = {
	.cmd_len = aoecmd_ata_cmd_len,
	.cmd = aoecmd_ata_cmd,
	.rsp = aoecmd_ata_rsp,
};

/**
 * Calculate length of AoE configuration command IU
 *
 * @v aoecmd		AoE command
 * @ret len		Length of command IU
 */
static size_t aoecmd_cfg_cmd_len ( struct aoe_command *aoecmd __unused ) {
	return ( sizeof ( struct aoehdr ) + sizeof ( struct aoecfg ) );
}

/**
 * Build AoE configuration command IU
 *
 * @v aoecmd		AoE command
 * @v data		Command IU
 * @v len		Length of command IU
 */
static void aoecmd_cfg_cmd ( struct aoe_command *aoecmd,
			     void *data, size_t len ) {
	struct aoe_device *aoedev = aoecmd->aoedev;
	struct aoehdr *aoehdr = data;
	struct aoecfg *aoecfg = &aoehdr->payload[0].cfg;

	/* Sanity check */
	assert ( len == ( sizeof ( *aoehdr ) + sizeof ( *aoecfg ) ) );

	/* Build IU */
	aoehdr->command = AOE_CMD_CONFIG;
	memset ( aoecfg, 0, sizeof ( *aoecfg ) );

	DBGC ( aoedev, "AoE %s/%08x CONFIG cmd\n",
	       aoedev_name ( aoedev ), aoecmd->tag );
}

/**
 * Handle AoE configuration response IU
 *
 * @v aoecmd		AoE command
 * @v data		Response IU
 * @v len		Length of response IU
 * @v ll_source		Link-layer source address
 * @ret rc		Return status code
 */
static int aoecmd_cfg_rsp ( struct aoe_command *aoecmd, const void *data,
			    size_t len, const void *ll_source ) {
	struct aoe_device *aoedev = aoecmd->aoedev;
	struct ll_protocol *ll_protocol = aoedev->netdev->ll_protocol;
	const struct aoehdr *aoehdr = data;
	const struct aoecfg *aoecfg = &aoehdr->payload[0].cfg;

	/* Sanity check */
	if ( len < ( sizeof ( *aoehdr ) + sizeof ( *aoecfg ) ) ) {
		DBGC ( aoedev, "AoE %s/%08x received underlength "
		       "configuration response (%zd bytes)\n",
		       aoedev_name ( aoedev ), aoecmd->tag, len );
		return -EINVAL;
	}
	DBGC ( aoedev, "AoE %s/%08x CONFIG rsp buf %04x fw %04x scnt %02x\n",
	       aoedev_name ( aoedev ), aoecmd->tag, ntohs ( aoecfg->bufcnt ),
	       aoecfg->fwver, aoecfg->scnt );

	/* Record target MAC address */
	memcpy ( aoedev->target, ll_source, ll_protocol->ll_addr_len );
	DBGC ( aoedev, "AoE %s has MAC address %s\n",
	       aoedev_name ( aoedev ), ll_protocol->ntoa ( aoedev->target ) );

	return 0;
}

/** AoE configuration command */
static struct aoe_command_type aoecmd_cfg = {
	.cmd_len = aoecmd_cfg_cmd_len,
	.cmd = aoecmd_cfg_cmd,
	.rsp = aoecmd_cfg_rsp,
};

/** AoE command ATA interface operations */
static struct interface_operation aoecmd_ata_op[] = {
	INTF_OP ( intf_close, struct aoe_command *, aoecmd_close ),
};

/** AoE command ATA interface descriptor */
static struct interface_descriptor aoecmd_ata_desc =
	INTF_DESC ( struct aoe_command, ata, aoecmd_ata_op );

/**
 * Identify AoE command by tag
 *
 * @v tag		Command tag
 * @ret aoecmd		AoE command, or NULL
 */
static struct aoe_command * aoecmd_find_tag ( uint32_t tag ) {
	struct aoe_command *aoecmd;

	list_for_each_entry ( aoecmd, &aoe_commands, list ) {
		if ( aoecmd->tag == tag )
			return aoecmd;
	}
	return NULL;
}

/**
 * Choose an AoE command tag
 *
 * @ret tag		New tag, or negative error
 */
static int aoecmd_new_tag ( void ) {
	static uint16_t tag_idx;
	unsigned int i;

	for ( i = 0 ; i < 65536 ; i++ ) {
		tag_idx++;
		if ( aoecmd_find_tag ( tag_idx ) == NULL )
			return ( AOE_TAG_MAGIC | tag_idx );
	}
	return -EADDRINUSE;
}

/**
 * Create AoE command
 *
 * @v aoedev		AoE device
 * @v type		AoE command type
 * @ret aoecmd		AoE command
 */
static struct aoe_command * aoecmd_create ( struct aoe_device *aoedev,
					    struct aoe_command_type *type ) {
	struct aoe_command *aoecmd;
	int tag;

	/* Allocate command tag */
	tag = aoecmd_new_tag();
	if ( tag < 0 )
		return NULL;

	/* Allocate and initialise structure */
	aoecmd = zalloc ( sizeof ( *aoecmd ) );
	if ( ! aoecmd )
		return NULL;
	ref_init ( &aoecmd->refcnt, aoecmd_free );
	list_add ( &aoecmd->list, &aoe_commands );
	intf_init ( &aoecmd->ata, &aoecmd_ata_desc, &aoecmd->refcnt );
	timer_init ( &aoecmd->timer, aoecmd_expired, &aoecmd->refcnt );
	aoecmd->aoedev = aoedev_get ( aoedev );
	aoecmd->type = type;
	aoecmd->tag = tag;

	/* Preserve timeout from last completed command */
	aoecmd->timer.timeout = aoedev->timeout;

	/* Return already mortalised.  (Reference is held by command list.) */
	return aoecmd;
}

/**
 * Issue AoE ATA command
 *
 * @v aoedev		AoE device
 * @v parent		Parent interface
 * @v command		ATA command
 * @ret tag		Command tag, or negative error
 */
static int aoedev_ata_command ( struct aoe_device *aoedev,
				struct interface *parent,
				struct ata_cmd *command ) {
	struct net_device *netdev = aoedev->netdev;
	struct aoe_command *aoecmd;

	/* Fail immediately if net device is closed */
	if ( ! netdev_is_open ( netdev ) ) {
		DBGC ( aoedev, "AoE %s cannot issue command while net device "
		       "is closed\n", aoedev_name ( aoedev ) );
		return -EWOULDBLOCK;
	}

	/* Create command */
	aoecmd = aoecmd_create ( aoedev, &aoecmd_ata );
	if ( ! aoecmd )
		return -ENOMEM;
	memcpy ( &aoecmd->command, command, sizeof ( aoecmd->command ) );

	/* Attempt to send command.  Allow failures to be handled by
	 * the retry timer.
	 */
	aoecmd_tx ( aoecmd );

	/* Attach to parent interface, leave reference with command
	 * list, and return.
	 */
	intf_plug_plug ( &aoecmd->ata, parent );
	return aoecmd->tag;
}

/**
 * Issue AoE configuration command
 *
 * @v aoedev		AoE device
 * @v parent		Parent interface
 * @ret tag		Command tag, or negative error
 */
static int aoedev_cfg_command ( struct aoe_device *aoedev,
				struct interface *parent ) {
	struct aoe_command *aoecmd;

	/* Create command */
	aoecmd = aoecmd_create ( aoedev, &aoecmd_cfg );
	if ( ! aoecmd )
		return -ENOMEM;

	/* Attempt to send command.  Allow failures to be handled by
	 * the retry timer.
	 */
	aoecmd_tx ( aoecmd );

	/* Attach to parent interface, leave reference with command
	 * list, and return.
	 */
	intf_plug_plug ( &aoecmd->ata, parent );
	return aoecmd->tag;
}

/**
 * Free AoE device
 *
 * @v refcnt		Reference count
 */
static void aoedev_free ( struct refcnt *refcnt ) {
	struct aoe_device *aoedev =
		container_of ( refcnt, struct aoe_device, refcnt );

	netdev_put ( aoedev->netdev );
	free ( aoedev );
}

/**
 * Close AoE device
 *
 * @v aoedev		AoE device
 * @v rc		Reason for close
 */
static void aoedev_close ( struct aoe_device *aoedev, int rc ) {
	struct aoe_command *aoecmd;
	struct aoe_command *tmp;

	/* Shut down interfaces */
	intf_shutdown ( &aoedev->ata, rc );
	intf_shutdown ( &aoedev->config, rc );

	/* Shut down any active commands */
	list_for_each_entry_safe ( aoecmd, tmp, &aoe_commands, list ) {
		if ( aoecmd->aoedev != aoedev )
			continue;
		aoecmd_get ( aoecmd );
		aoecmd_close ( aoecmd, rc );
		aoecmd_put ( aoecmd );
	}
}

/**
 * Check AoE device flow-control window
 *
 * @v aoedev		AoE device
 * @ret len		Length of window
 */
static size_t aoedev_window ( struct aoe_device *aoedev ) {
	return ( aoedev->configured ? ~( ( size_t ) 0 ) : 0 );
}

/**
 * Handle AoE device configuration completion
 *
 * @v aoedev		AoE device
 * @v rc		Reason for completion
 */
static void aoedev_config_done ( struct aoe_device *aoedev, int rc ) {

	/* Shut down interface */
	intf_shutdown ( &aoedev->config, rc );

	/* Close device on failure */
	if ( rc != 0 ) {
		aoedev_close ( aoedev, rc );
		return;
	}

	/* Mark device as configured */
	aoedev->configured = 1;
	xfer_window_changed ( &aoedev->ata );
}

/**
 * Identify device underlying AoE device
 *
 * @v aoedev		AoE device
 * @ret device		Underlying device
 */
static struct device * aoedev_identify_device ( struct aoe_device *aoedev ) {
	return aoedev->netdev->dev;
}

/**
 * Describe AoE device in an ACPI table
 *
 * @v aoedev		AoE device
 * @v acpi		ACPI table
 * @v len		Length of ACPI table
 * @ret rc		Return status code
 */
static int aoedev_describe ( struct aoe_device *aoedev,
			     struct acpi_description_header *acpi,
			     size_t len ) {
	struct abft_table *abft =
		container_of ( acpi, struct abft_table, acpi );

	/* Sanity check */
	if ( len < sizeof ( *abft ) )
		return -ENOBUFS;

	/* Populate table */
	abft->acpi.signature = cpu_to_le32 ( ABFT_SIG );
	abft->acpi.length = cpu_to_le32 ( sizeof ( *abft ) );
	abft->acpi.revision = 1;
	abft->shelf = cpu_to_le16 ( aoedev->major );
	abft->slot = aoedev->minor;
	memcpy ( abft->mac, aoedev->netdev->ll_addr, sizeof ( abft->mac ) );

	return 0;
}

/** AoE device ATA interface operations */
static struct interface_operation aoedev_ata_op[] = {
	INTF_OP ( ata_command, struct aoe_device *, aoedev_ata_command ),
	INTF_OP ( xfer_window, struct aoe_device *, aoedev_window ),
	INTF_OP ( intf_close, struct aoe_device *, aoedev_close ),
	INTF_OP ( acpi_describe, struct aoe_device *, aoedev_describe ),
	INTF_OP ( identify_device, struct aoe_device *,
		  aoedev_identify_device ),
};

/** AoE device ATA interface descriptor */
static struct interface_descriptor aoedev_ata_desc =
	INTF_DESC ( struct aoe_device, ata, aoedev_ata_op );

/** AoE device configuration interface operations */
static struct interface_operation aoedev_config_op[] = {
	INTF_OP ( intf_close, struct aoe_device *, aoedev_config_done ),
};

/** AoE device configuration interface descriptor */
static struct interface_descriptor aoedev_config_desc =
	INTF_DESC ( struct aoe_device, config, aoedev_config_op );

/**
 * Open AoE device
 *
 * @v parent		Parent interface
 * @v netdev		Network device
 * @v major		Device major number
 * @v minor		Device minor number
 * @ret rc		Return status code
 */
static int aoedev_open ( struct interface *parent, struct net_device *netdev,
			 unsigned int major, unsigned int minor ) {
	struct aoe_device *aoedev;
	int rc;

	/* Allocate and initialise structure */
	aoedev = zalloc ( sizeof ( *aoedev ) );
	if ( ! aoedev ) {
		rc = -ENOMEM;
		goto err_zalloc;
	}
	ref_init ( &aoedev->refcnt, aoedev_free );
	intf_init ( &aoedev->ata, &aoedev_ata_desc, &aoedev->refcnt );
	intf_init ( &aoedev->config, &aoedev_config_desc, &aoedev->refcnt );
	aoedev->netdev = netdev_get ( netdev );
	aoedev->major = major;
	aoedev->minor = minor;
	memcpy ( aoedev->target, netdev->ll_broadcast,
		 netdev->ll_protocol->ll_addr_len );

	/* Initiate configuration */
	if ( ( rc = aoedev_cfg_command ( aoedev, &aoedev->config ) ) < 0 ) {
		DBGC ( aoedev, "AoE %s could not initiate configuration: %s\n",
		       aoedev_name ( aoedev ), strerror ( rc ) );
		goto err_config;
	}

	/* Attach ATA device to parent interface */
	if ( ( rc = ata_open ( parent, &aoedev->ata, ATA_DEV_MASTER,
			       AOE_MAX_COUNT ) ) != 0 ) {
		DBGC ( aoedev, "AoE %s could not create ATA device: %s\n",
		       aoedev_name ( aoedev ), strerror ( rc ) );
		goto err_ata_open;
	}

	/* Mortalise self and return */
	ref_put ( &aoedev->refcnt );
	return 0;

 err_ata_open:
 err_config:
	aoedev_close ( aoedev, rc );
	ref_put ( &aoedev->refcnt );
 err_zalloc:
	return rc;
}

/******************************************************************************
 *
 * AoE network protocol
 *
 ******************************************************************************
 */

/**
 * Process incoming AoE packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
static int aoe_rx ( struct io_buffer *iobuf,
		    struct net_device *netdev __unused,
		    const void *ll_dest __unused,
		    const void *ll_source,
		    unsigned int flags __unused ) {
	struct aoehdr *aoehdr = iobuf->data;
	struct aoe_command *aoecmd;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *aoehdr ) ) {
		DBG ( "AoE received underlength packet (%zd bytes)\n",
		      iob_len ( iobuf ) );
		rc = -EINVAL;
		goto err_sanity;
	}
	if ( ( aoehdr->ver_flags & AOE_VERSION_MASK ) != AOE_VERSION ) {
		DBG ( "AoE received packet for unsupported protocol version "
		      "%02x\n", ( aoehdr->ver_flags & AOE_VERSION_MASK ) );
		rc = -EPROTONOSUPPORT;
		goto err_sanity;
	}
	if ( ! ( aoehdr->ver_flags & AOE_FL_RESPONSE ) ) {
		DBG ( "AoE received request packet\n" );
		rc = -EOPNOTSUPP;
		goto err_sanity;
	}

	/* Demultiplex amongst active AoE commands */
	aoecmd = aoecmd_find_tag ( ntohl ( aoehdr->tag ) );
	if ( ! aoecmd ) {
		DBG ( "AoE received packet for unused tag %08x\n",
		      ntohl ( aoehdr->tag ) );
		rc = -ENOENT;
		goto err_demux;
	}

	/* Pass received frame to command */
	aoecmd_get ( aoecmd );
	if ( ( rc = aoecmd_rx ( aoecmd, iob_disown ( iobuf ),
				ll_source ) ) != 0 )
		goto err_rx;

 err_rx:
	aoecmd_put ( aoecmd );
 err_demux:
 err_sanity:
	free_iob ( iobuf );
	return rc;
}

/** AoE protocol */
struct net_protocol aoe_protocol __net_protocol = {
	.name = "AoE",
	.net_proto = htons ( ETH_P_AOE ),
	.rx = aoe_rx,
};

/******************************************************************************
 *
 * AoE URIs
 *
 ******************************************************************************
 */

/**
 * Parse AoE URI
 *
 * @v uri		URI
 * @ret major		Major device number
 * @ret minor		Minor device number
 * @ret rc		Return status code
 *
 * An AoE URI has the form "aoe:e<major>.<minor>".
 */
static int aoe_parse_uri ( struct uri *uri, unsigned int *major,
			   unsigned int *minor ) {
	const char *ptr;
	char *end;

	/* Check for URI with opaque portion */
	if ( ! uri->opaque )
		return -EINVAL;
	ptr = uri->opaque;

	/* Check for initial 'e' */
	if ( *ptr != 'e' )
		return -EINVAL;
	ptr++;

	/* Parse major device number */
	*major = strtoul ( ptr, &end, 10 );
	if ( *end != '.' )
		return -EINVAL;
	ptr = ( end + 1 );

	/* Parse minor device number */
	*minor = strtoul ( ptr, &end, 10 );
	if ( *end )
		return -EINVAL;

	return 0;
}

/**
 * Open AoE URI
 *
 * @v parent		Parent interface
 * @v uri		URI
 * @ret rc		Return status code
 */
static int aoe_open ( struct interface *parent, struct uri *uri ) {
	struct net_device *netdev;
	unsigned int major;
	unsigned int minor;
	int rc;

	/* Identify network device.  This is something of a hack, but
	 * the AoE URI scheme that has been in use for some time now
	 * provides no way to specify a particular device.
	 */
	netdev = last_opened_netdev();
	if ( ! netdev ) {
		DBG ( "AoE cannot identify network device\n" );
		return -ENODEV;
	}

	/* Parse URI */
	if ( ( rc = aoe_parse_uri ( uri, &major, &minor ) ) != 0 ) {
		DBG ( "AoE cannot parse URI\n" );
		return rc;
	}

	/* Open AoE device */
	if ( ( rc = aoedev_open ( parent, netdev, major, minor ) ) != 0 )
		return rc;

	return 0;
}

/** AoE URI opener */
struct uri_opener aoe_uri_opener __uri_opener = {
	.scheme = "aoe",
	.open = aoe_open,
};
