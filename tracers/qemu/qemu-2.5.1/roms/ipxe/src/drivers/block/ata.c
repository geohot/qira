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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/list.h>
#include <ipxe/interface.h>
#include <ipxe/blockdev.h>
#include <ipxe/edd.h>
#include <ipxe/ata.h>

/** @file
 *
 * ATA block device
 *
 */

/******************************************************************************
 *
 * Interface methods
 *
 ******************************************************************************
 */

/**
 * Issue ATA command
 *
 * @v control		ATA control interface
 * @v data		ATA data interface
 * @v command		ATA command
 * @ret tag		Command tag, or negative error
 */
int ata_command ( struct interface *control, struct interface *data,
		  struct ata_cmd *command ) {
	struct interface *dest;
	ata_command_TYPE ( void * ) *op =
		intf_get_dest_op ( control, ata_command, &dest );
	void *object = intf_object ( dest );
	int tag;

	if ( op ) {
		tag = op ( object, data, command );
	} else {
		/* Default is to fail to issue the command */
		tag = -EOPNOTSUPP;
	}

	intf_put ( dest );
	return tag;
}

/******************************************************************************
 *
 * ATA devices and commands
 *
 ******************************************************************************
 */

/** List of all ATA commands */
static LIST_HEAD ( ata_commands );

/** An ATA device */
struct ata_device {
	/** Reference count */
	struct refcnt refcnt;
	/** Block control interface */
	struct interface block;
	/** ATA control interface */
	struct interface ata;

	/** Device number
	 *
	 * Must be ATA_DEV_MASTER or ATA_DEV_SLAVE.
	 */
	unsigned int device;
	/** Maximum number of blocks per single transfer */
	unsigned int max_count;
	/** Device uses LBA48 extended addressing */
	int lba48;
};

/** An ATA command */
struct ata_command {
	/** Reference count */
	struct refcnt refcnt;
	/** ATA device */
	struct ata_device *atadev;
	/** List of ATA commands */
	struct list_head list;

	/** Block data interface */
	struct interface block;
	/** ATA data interface */
	struct interface ata;

	/** Command type */
	struct ata_command_type *type;
	/** Command tag */
	uint32_t tag;

	/** Private data */
	uint8_t priv[0];
};

/** An ATA command type */
struct ata_command_type {
	/** Name */
	const char *name;
	/** Additional working space */
	size_t priv_len;
	/** Command for non-LBA48-capable devices */
	uint8_t cmd_lba;
	/** Command for LBA48-capable devices */
	uint8_t cmd_lba48;
	/**
	 * Calculate data-in buffer
	 *
	 * @v atacmd		ATA command
	 * @v buffer		Available buffer
	 * @v len		Available buffer length
	 * @ret data_in		Data-in buffer
	 * @ret data_in_len	Data-in buffer length
	 */
	void ( * data_in ) ( struct ata_command *atacmd, userptr_t buffer,
			     size_t len, userptr_t *data_in,
			     size_t *data_in_len );
	/**
	 * Calculate data-out buffer
	 *
	 *
	 * @v atacmd		ATA command
	 * @v buffer		Available buffer
	 * @v len		Available buffer length
	 * @ret data_out	Data-out buffer
	 * @ret data_out_len	Data-out buffer length
	 */
	void ( * data_out ) ( struct ata_command *atacmd, userptr_t buffer,
			      size_t len, userptr_t *data_out,
			      size_t *data_out_len );
	/**
	 * Handle ATA command completion
	 *
	 * @v atacmd		ATA command
	 * @v rc		Reason for completion
	 */
	void ( * done ) ( struct ata_command *atacmd, int rc );
};

/**
 * Get reference to ATA device
 *
 * @v atadev		ATA device
 * @ret atadev		ATA device
 */
static inline __attribute__ (( always_inline )) struct ata_device *
atadev_get ( struct ata_device *atadev ) {
	ref_get ( &atadev->refcnt );
	return atadev;
}

/**
 * Drop reference to ATA device
 *
 * @v atadev		ATA device
 */
static inline __attribute__ (( always_inline )) void
atadev_put ( struct ata_device *atadev ) {
	ref_put ( &atadev->refcnt );
}

/**
 * Get reference to ATA command
 *
 * @v atacmd		ATA command
 * @ret atacmd		ATA command
 */
static inline __attribute__ (( always_inline )) struct ata_command *
atacmd_get ( struct ata_command *atacmd ) {
	ref_get ( &atacmd->refcnt );
	return atacmd;
}

/**
 * Drop reference to ATA command
 *
 * @v atacmd		ATA command
 */
static inline __attribute__ (( always_inline )) void
atacmd_put ( struct ata_command *atacmd ) {
	ref_put ( &atacmd->refcnt );
}

/**
 * Get ATA command private data
 *
 * @v atacmd		ATA command
 * @ret priv		Private data
 */
static inline __attribute__ (( always_inline )) void *
atacmd_priv ( struct ata_command *atacmd ) {
	return atacmd->priv;
}

/**
 * Free ATA command
 *
 * @v refcnt		Reference count
 */
static void atacmd_free ( struct refcnt *refcnt ) {
	struct ata_command *atacmd =
		container_of ( refcnt, struct ata_command, refcnt );

	/* Remove from list of commands */
	list_del ( &atacmd->list );
	atadev_put ( atacmd->atadev );

	/* Free command */
	free ( atacmd );
}

/**
 * Close ATA command
 *
 * @v atacmd		ATA command
 * @v rc		Reason for close
 */
static void atacmd_close ( struct ata_command *atacmd, int rc ) {
	struct ata_device *atadev = atacmd->atadev;

	if ( rc != 0 ) {
		DBGC ( atadev, "ATA %p tag %08x closed: %s\n",
		       atadev, atacmd->tag, strerror ( rc ) );
	}

	/* Shut down interfaces */
	intf_shutdown ( &atacmd->ata, rc );
	intf_shutdown ( &atacmd->block, rc );
}

/**
 * Handle ATA command completion
 *
 * @v atacmd		ATA command
 * @v rc		Reason for close
 */
static void atacmd_done ( struct ata_command *atacmd, int rc ) {

	/* Hand over to the command completion handler */
	atacmd->type->done ( atacmd, rc );
}

/**
 * Use provided data buffer for ATA command
 *
 * @v atacmd		ATA command
 * @v buffer		Available buffer
 * @v len		Available buffer length
 * @ret data		Data buffer
 * @ret data_len	Data buffer length
 */
static void atacmd_data_buffer ( struct ata_command *atacmd __unused,
				 userptr_t buffer, size_t len,
				 userptr_t *data, size_t *data_len ) {
	*data = buffer;
	*data_len = len;
}

/**
 * Use no data buffer for ATA command
 *
 * @v atacmd		ATA command
 * @v buffer		Available buffer
 * @v len		Available buffer length
 * @ret data		Data buffer
 * @ret data_len	Data buffer length
 */
static void atacmd_data_none ( struct ata_command *atacmd __unused,
			       userptr_t buffer __unused, size_t len __unused,
			       userptr_t *data __unused,
			       size_t *data_len __unused ) {
	/* Nothing to do */
}

/**
 * Use private data buffer for ATA command
 *
 * @v atacmd		ATA command
 * @v buffer		Available buffer
 * @v len		Available buffer length
 * @ret data		Data buffer
 * @ret data_len	Data buffer length
 */
static void atacmd_data_priv ( struct ata_command *atacmd,
			       userptr_t buffer __unused, size_t len __unused,
			       userptr_t *data, size_t *data_len ) {
	*data = virt_to_user ( atacmd_priv ( atacmd ) );
	*data_len = atacmd->type->priv_len;
}

/** ATA READ command type */
static struct ata_command_type atacmd_read = {
	.name = "READ",
	.cmd_lba = ATA_CMD_READ,
	.cmd_lba48 = ATA_CMD_READ_EXT,
	.data_in = atacmd_data_buffer,
	.data_out = atacmd_data_none,
	.done = atacmd_close,
};

/** ATA WRITE command type */
static struct ata_command_type atacmd_write = {
	.name = "WRITE",
	.cmd_lba = ATA_CMD_WRITE,
	.cmd_lba48 = ATA_CMD_WRITE_EXT,
	.data_in = atacmd_data_none,
	.data_out = atacmd_data_buffer,
	.done = atacmd_close,
};

/** ATA IDENTIFY private data */
struct ata_identify_private {
	/** Identity data */
	struct ata_identity identity;
};

/**
 * Return ATA model string (for debugging)
 *
 * @v identify		ATA identity data
 * @ret model		Model string
 */
static const char * ata_model ( struct ata_identity *identity ) {
	static union {
		uint16_t words[ sizeof ( identity->model ) / 2 ];
		char text[ sizeof ( identity->model ) + 1 /* NUL */ ];
	} buf;
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( identity->model ) / 2 ) ; i++ )
		buf.words[i] = bswap_16 ( identity->model[i] );

	return buf.text;
}

/**
 * Handle ATA IDENTIFY command completion
 *
 * @v atacmd		ATA command
 * @v rc		Reason for completion
 */
static void atacmd_identify_done ( struct ata_command *atacmd, int rc ) {
	struct ata_device *atadev = atacmd->atadev;
	struct ata_identify_private *priv = atacmd_priv ( atacmd );
	struct ata_identity *identity = &priv->identity;
	struct block_device_capacity capacity;

	/* Close if command failed */
	if ( rc != 0 ) {
		atacmd_close ( atacmd, rc );
		return;
	}

	/* Extract capacity */
	if ( identity->supports_lba48 & cpu_to_le16 ( ATA_SUPPORTS_LBA48 ) ) {
		atadev->lba48 = 1;
		capacity.blocks = le64_to_cpu ( identity->lba48_sectors );
	} else {
		capacity.blocks = le32_to_cpu ( identity->lba_sectors );
	}
	capacity.blksize = ATA_SECTOR_SIZE;
	capacity.max_count = atadev->max_count;
	DBGC ( atadev, "ATA %p is a %s\n", atadev, ata_model ( identity ) );
	DBGC ( atadev, "ATA %p has %#llx blocks (%ld MB) and uses %s\n",
	       atadev, capacity.blocks,
	       ( ( signed long ) ( capacity.blocks >> 11 ) ),
	       ( atadev->lba48 ? "LBA48" : "LBA" ) );

	/* Return capacity to caller */
	block_capacity ( &atacmd->block, &capacity );

	/* Close command */
	atacmd_close ( atacmd, 0 );
}

/** ATA IDENTITY command type */
static struct ata_command_type atacmd_identify = {
	.name = "IDENTIFY",
	.priv_len = sizeof ( struct ata_identify_private ),
	.cmd_lba = ATA_CMD_IDENTIFY,
	.cmd_lba48 = ATA_CMD_IDENTIFY,
	.data_in = atacmd_data_priv,
	.data_out = atacmd_data_none,
	.done = atacmd_identify_done,
};

/** ATA command block interface operations */
static struct interface_operation atacmd_block_op[] = {
	INTF_OP ( intf_close, struct ata_command *, atacmd_close ),
};

/** ATA command block interface descriptor */
static struct interface_descriptor atacmd_block_desc =
	INTF_DESC_PASSTHRU ( struct ata_command, block,
			     atacmd_block_op, ata );

/** ATA command ATA interface operations */
static struct interface_operation atacmd_ata_op[] = {
	INTF_OP ( intf_close, struct ata_command *, atacmd_done ),
};

/** ATA command ATA interface descriptor */
static struct interface_descriptor atacmd_ata_desc =
	INTF_DESC_PASSTHRU ( struct ata_command, ata,
			     atacmd_ata_op, block );

/**
 * Create ATA command
 *
 * @v atadev		ATA device
 * @v block		Block data interface
 * @v type		ATA command type
 * @v lba		Starting logical block address
 * @v count		Number of blocks to transfer
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int atadev_command ( struct ata_device *atadev,
			    struct interface *block,
			    struct ata_command_type *type,
			    uint64_t lba, unsigned int count,
			    userptr_t buffer, size_t len ) {
	struct ata_command *atacmd;
	struct ata_cmd command;
	int tag;
	int rc;

	/* Allocate and initialise structure */
	atacmd = zalloc ( sizeof ( *atacmd ) + type->priv_len );
	if ( ! atacmd ) {
		rc = -ENOMEM;
		goto err_zalloc;
	}
	ref_init ( &atacmd->refcnt, atacmd_free );
	intf_init ( &atacmd->block, &atacmd_block_desc, &atacmd->refcnt );
	intf_init ( &atacmd->ata, &atacmd_ata_desc,
		    &atacmd->refcnt );
	atacmd->atadev = atadev_get ( atadev );
	list_add ( &atacmd->list, &ata_commands );
	atacmd->type = type;

	/* Sanity check */
	if ( len != ( count * ATA_SECTOR_SIZE ) ) {
		DBGC ( atadev, "ATA %p tag %08x buffer length mismatch (count "
		       "%d len %zd)\n", atadev, atacmd->tag, count, len );
		rc = -EINVAL;
		goto err_len;
	}

	/* Construct command */
	memset ( &command, 0, sizeof ( command ) );
	command.cb.lba.native = lba;
	command.cb.count.native = count;
	command.cb.device = ( atadev->device | ATA_DEV_OBSOLETE | ATA_DEV_LBA );
	command.cb.lba48 = atadev->lba48;
	if ( ! atadev->lba48 )
		command.cb.device |= command.cb.lba.bytes.low_prev;
	command.cb.cmd_stat =
		( atadev->lba48 ? type->cmd_lba48 : type->cmd_lba );
	type->data_in ( atacmd, buffer, len,
			&command.data_in, &command.data_in_len );
	type->data_out ( atacmd, buffer, len,
			 &command.data_out, &command.data_out_len );

	/* Issue command */
	if ( ( tag = ata_command ( &atadev->ata, &atacmd->ata,
				   &command ) ) < 0 ) {
		rc = tag;
		DBGC ( atadev, "ATA %p tag %08x could not issue command: %s\n",
		       atadev, atacmd->tag, strerror ( rc ) );
		goto err_command;
	}
	atacmd->tag = tag;

	DBGC2 ( atadev, "ATA %p tag %08x %s cmd %02x dev %02x LBA%s %08llx "
		"count %04x\n", atadev, atacmd->tag, atacmd->type->name,
		command.cb.cmd_stat, command.cb.device,
		( command.cb.lba48 ? "48" : "" ),
		( unsigned long long ) command.cb.lba.native,
		command.cb.count.native );

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( &atacmd->block, block );
	ref_put ( &atacmd->refcnt );
	return 0;

 err_command:
 err_len:
	atacmd_close ( atacmd, rc );
	ref_put ( &atacmd->refcnt );
 err_zalloc:
	return rc;
}

/**
 * Issue ATA block read
 *
 * @v atadev		ATA device
 * @v block		Block data interface
 * @v lba		Starting logical block address
 * @v count		Number of blocks to transfer
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code

 */
static int atadev_read ( struct ata_device *atadev,
			 struct interface *block,
			 uint64_t lba, unsigned int count,
			 userptr_t buffer, size_t len ) {
	return atadev_command ( atadev, block, &atacmd_read,
				lba, count, buffer, len );
}

/**
 * Issue ATA block write
 *
 * @v atadev		ATA device
 * @v block		Block data interface
 * @v lba		Starting logical block address
 * @v count		Number of blocks to transfer
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int atadev_write ( struct ata_device *atadev,
			  struct interface *block,
			  uint64_t lba, unsigned int count,
			  userptr_t buffer, size_t len ) {
	return atadev_command ( atadev, block, &atacmd_write,
				lba, count, buffer, len );
}

/**
 * Read ATA device capacity
 *
 * @v atadev		ATA device
 * @v block		Block data interface
 * @ret rc		Return status code
 */
static int atadev_read_capacity ( struct ata_device *atadev,
				  struct interface *block ) {
	struct ata_identity *identity;

	assert ( atacmd_identify.priv_len == sizeof ( *identity ) );
	assert ( atacmd_identify.priv_len == ATA_SECTOR_SIZE );
	return atadev_command ( atadev, block, &atacmd_identify,
				0, 1, UNULL, ATA_SECTOR_SIZE );
}

/**
 * Close ATA device
 *
 * @v atadev		ATA device
 * @v rc		Reason for close
 */
static void atadev_close ( struct ata_device *atadev, int rc ) {
	struct ata_command *atacmd;
	struct ata_command *tmp;

	/* Shut down interfaces */
	intf_shutdown ( &atadev->block, rc );
	intf_shutdown ( &atadev->ata, rc );

	/* Shut down any remaining commands */
	list_for_each_entry_safe ( atacmd, tmp, &ata_commands, list ) {
		if ( atacmd->atadev != atadev )
			continue;
		atacmd_get ( atacmd );
		atacmd_close ( atacmd, rc );
		atacmd_put ( atacmd );
	}
}

/**
 * Describe ATA device using EDD
 *
 * @v atadev		ATA device
 * @v type		EDD interface type
 * @v path		EDD device path
 * @ret rc		Return status code
 */
static int atadev_edd_describe ( struct ata_device *atadev,
				 struct edd_interface_type *type,
				 union edd_device_path *path ) {

	type->type = cpu_to_le64 ( EDD_INTF_TYPE_ATA );
	path->ata.slave = ( ( atadev->device == ATA_DEV_SLAVE ) ? 0x01 : 0x00 );
	return 0;
}

/** ATA device block interface operations */
static struct interface_operation atadev_block_op[] = {
	INTF_OP ( block_read, struct ata_device *, atadev_read ),
	INTF_OP ( block_write, struct ata_device *, atadev_write ),
	INTF_OP ( block_read_capacity, struct ata_device *,
		  atadev_read_capacity ),
	INTF_OP ( intf_close, struct ata_device *, atadev_close ),
	INTF_OP ( edd_describe, struct ata_device *, atadev_edd_describe ),
};

/** ATA device block interface descriptor */
static struct interface_descriptor atadev_block_desc =
	INTF_DESC_PASSTHRU ( struct ata_device, block,
			     atadev_block_op, ata );

/** ATA device ATA interface operations */
static struct interface_operation atadev_ata_op[] = {
	INTF_OP ( intf_close, struct ata_device *, atadev_close ),
};

/** ATA device ATA interface descriptor */
static struct interface_descriptor atadev_ata_desc =
	INTF_DESC_PASSTHRU ( struct ata_device, ata,
			     atadev_ata_op, block );

/**
 * Open ATA device
 *
 * @v block		Block control interface
 * @v ata		ATA control interface
 * @v device		ATA device number
 * @v max_count		Maximum number of blocks per single transfer
 * @ret rc		Return status code
 */
int ata_open ( struct interface *block, struct interface *ata,
	       unsigned int device, unsigned int max_count ) {
	struct ata_device *atadev;

	/* Allocate and initialise structure */
	atadev = zalloc ( sizeof ( *atadev ) );
	if ( ! atadev )
		return -ENOMEM;
	ref_init ( &atadev->refcnt, NULL );
	intf_init ( &atadev->block, &atadev_block_desc, &atadev->refcnt );
	intf_init ( &atadev->ata, &atadev_ata_desc, &atadev->refcnt );
	atadev->device = device;
	atadev->max_count = max_count;

	/* Attach to ATA and parent and interfaces, mortalise self,
	 * and return
	 */
	intf_plug_plug ( &atadev->ata, ata );
	intf_plug_plug ( &atadev->block, block );
	ref_put ( &atadev->refcnt );
	return 0;
}
