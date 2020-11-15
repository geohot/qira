/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/isapnp.h>
#include <ipxe/pcivpd.h>

/** @file
 *
 * PCI Vital Product Data
 *
 */

/**
 * Initialise PCI Vital Product Data
 *
 * @v vpd		PCI VPD
 * @v pci		PCI device
 * @ret rc		Return status code
 */
int pci_vpd_init ( struct pci_vpd *vpd, struct pci_device *pci ) {

	/* Initialise structure */
	vpd->pci = pci;
	pci_vpd_invalidate_cache ( vpd );

	/* Locate VPD capability */
	vpd->cap = pci_find_capability ( pci, PCI_CAP_ID_VPD );
	if ( ! vpd->cap ) {
		DBGC ( vpd, PCI_FMT " does not support VPD\n",
		       PCI_ARGS ( pci ) );
		return -ENOTTY;
	}

	DBGC ( vpd, PCI_FMT " VPD is at offset %02x\n",
	       PCI_ARGS ( pci ), vpd->cap );
	return 0;
}

/**
 * Read one dword of PCI Vital Product Data
 *
 * @v vpd		PCI VPD
 * @v address		Address to read
 * @ret data		Read data
 * @ret rc		Return status code
 */
static int pci_vpd_read_dword ( struct pci_vpd *vpd, int address,
				uint32_t *data ) {
	struct pci_device *pci = vpd->pci;
	unsigned int cap = vpd->cap;
	unsigned int retries;
	uint16_t flag;

	/* Fail if no VPD present */
	if ( ! cap )
		return -ENOTTY;

	/* Return cached value, if present */
	if ( pci_vpd_cache_is_valid ( vpd ) &&
	     ( vpd->cache.address == address ) ) {
		*data = vpd->cache.data;
		return 0;
	}

	/* Initiate read */
	pci_write_config_word ( pci, ( cap + PCI_VPD_ADDRESS ), address );

	/* Wait for read to complete */
	for ( retries = 0 ; retries < PCI_VPD_MAX_WAIT_MS ; retries++ ) {

		/* Check if data is ready */
		pci_read_config_word ( pci, ( cap + PCI_VPD_ADDRESS ), &flag );
		if ( flag & PCI_VPD_FLAG ) {

			/* Read data */
			pci_read_config_dword ( pci, ( cap + PCI_VPD_DATA ),
						data );
			DBGC2 ( vpd, PCI_FMT " VPD %04x => %08x\n",
				PCI_ARGS ( pci ), address, htonl ( *data ) );

			/* Populate cache */
			vpd->cache.address = address;
			vpd->cache.data = *data;

			return 0;
		}

		/* Wait 1ms before retrying */
		mdelay ( 1 );
	}

	DBGC ( vpd, PCI_FMT " VPD %04x read via %02x timed out\n",
	       PCI_ARGS ( pci ), address, cap );
	return -ETIMEDOUT;
}

/**
 * Write one dword of PCI Vital Product Data
 *
 * @v vpd		PCI VPD
 * @v address		Address to write
 * @v data		Data to write
 * @ret rc		Return status code
 */
static int pci_vpd_write_dword ( struct pci_vpd *vpd, int address,
				 uint32_t data ) {
	struct pci_device *pci = vpd->pci;
	unsigned int cap = vpd->cap;
	unsigned int retries;
	uint16_t flag;

	/* Fail if no VPD present */
	if ( ! cap )
		return -ENOTTY;

	/* Invalidate cache */
	pci_vpd_invalidate_cache ( vpd );

	DBGC2 ( vpd, PCI_FMT " VPD %04x <= %08x\n",
		PCI_ARGS ( pci ), address, htonl ( data ) );

	/* Write data */
	pci_write_config_dword ( pci, ( cap + PCI_VPD_DATA ), data );

	/* Initiate write */
	pci_write_config_word ( pci, ( cap + PCI_VPD_ADDRESS ),
				( address | PCI_VPD_FLAG ) );

	/* Wait for write to complete */
	for ( retries = 0 ; retries < PCI_VPD_MAX_WAIT_MS ; retries++ ) {

		/* Check if write has completed */
		pci_read_config_word ( pci, ( cap + PCI_VPD_ADDRESS ), &flag );
		if ( ! ( flag & PCI_VPD_FLAG ) )
			return 0;

		/* Wait 1ms before retrying */
		mdelay ( 1 );
	}

	DBGC ( vpd, PCI_FMT " VPD %04x write via %02x timed out\n",
	       PCI_ARGS ( pci ), address, cap );
	return -ETIMEDOUT;
}

/**
 * Read PCI VPD
 *
 * @v vpd		PCI VPD
 * @v address		Starting address
 * @v buf		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int pci_vpd_read ( struct pci_vpd *vpd, unsigned int address, void *buf,
		   size_t len ) {
	uint8_t *bytes = buf;
	uint32_t data;
	size_t skip_len;
	unsigned int i;
	int rc;

	/* Calculate length to skip at start of data */
	skip_len = ( address & 0x03 );

	/* Read data, a dword at a time */
	for ( address &= ~0x03 ; len ; address += 4 ) {

		/* Read whole dword */
		if ( ( rc = pci_vpd_read_dword ( vpd, address, &data ) ) != 0 )
			return rc;

		/* Copy data to buffer */
		for ( i = 4 ; i ; i-- ) {
			if ( skip_len ) {
				skip_len--;
			} else if ( len ) {
				*(bytes++) = data;
				len--;
			}
			data = ( ( data << 24 ) | ( data >> 8 ) );
		}
	}

	return 0;
}

/**
 * Write PCI VPD
 *
 * @v vpd		PCI VPD
 * @v address		Starting address
 * @v buf		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int pci_vpd_write ( struct pci_vpd *vpd, unsigned int address, const void *buf,
		    size_t len ) {
	const uint8_t *bytes = buf;
	uint32_t data;
	size_t skip_len;
	unsigned int i;
	int rc;

	/* Calculate length to skip at start of data */
	skip_len = ( address & 0x03 );

	/* Write data, a dword at a time */
	for ( address &= ~0x03 ; len ; address += 4 ) {

		/* Read existing dword, if necessary */
		if ( skip_len || ( len <= 0x03 ) ) {
			if ( ( rc = pci_vpd_read_dword ( vpd, address,
							 &data ) ) != 0 )
				return rc;
		}

		/* Copy data from buffer */
		for ( i = 4 ; i ; i-- ) {
			if ( skip_len ) {
				skip_len--;
			} else if ( len ) {
				data = ( ( data & ~0xff ) | *(bytes++) );
				len--;
			}
			data = ( ( data << 24 ) | ( data >> 8 ) );
		}

		/* Write whole dword */
		if ( ( rc = pci_vpd_write_dword ( vpd, address, data ) ) != 0 )
			return rc;
	}
	return 0;
}

/**
 * Dump PCI VPD region (for debugging)
 *
 * @v vpd		PCI VPD
 * @v address		Starting address
 * @v len		Length of data
 */
static void pci_vpd_dump ( struct pci_vpd *vpd, unsigned int address,
			   size_t len ) {
	int rc;

	/* Do nothing in non-debug builds */
	if ( ! DBG_LOG )
		return;

	/* Read data */
	{
		char buf[len];
		if ( ( rc = pci_vpd_read ( vpd, address, buf,
					   sizeof ( buf ) ) ) != 0 )
			return;
		DBGC_HDA ( vpd, address, buf, sizeof ( buf ) );
	}
}

/**
 * Locate PCI VPD tag
 *
 * @v vpd		PCI VPD
 * @v tag		ISAPnP tag
 * @ret address		Address of tag body
 * @ret len		Length of tag body
 * @ret rc		Return status code
 */
static int pci_vpd_find_tag ( struct pci_vpd *vpd, unsigned int tag,
			      unsigned int *address, size_t *len ) {
	uint8_t read_tag;
	uint16_t read_len;
	int rc;

	/* Scan through tags looking for a match */
	*address = 0;
	do {
		/* Read tag byte */
		if ( ( rc = pci_vpd_read ( vpd, (*address)++, &read_tag,
					   sizeof ( read_tag ) ) ) != 0 )
			return rc;

		/* Extract tag and length */
		if ( ISAPNP_IS_LARGE_TAG ( read_tag ) ) {
			if ( ( rc = pci_vpd_read ( vpd, *address, &read_len,
						   sizeof ( read_len ) ) ) != 0)
				return rc;
			*address += sizeof ( read_len );
			read_len = le16_to_cpu ( read_len );
			read_tag = ISAPNP_LARGE_TAG_NAME ( read_tag );
		} else {
			read_len = ISAPNP_SMALL_TAG_LEN ( read_tag );
			read_tag = ISAPNP_SMALL_TAG_NAME ( read_tag );
		}

		/* Check for tag match */
		if ( tag == read_tag ) {
			*len = read_len;
			DBGC ( vpd, PCI_FMT " VPD tag %02x is at "
			       "[%04x,%04zx)\n", PCI_ARGS ( vpd->pci ), tag,
			       *address, ( *address + *len ) );
			return 0;
		}

		/* Move to next tag */
		*address += read_len;

	} while ( read_tag != ISAPNP_TAG_END );

	DBGC ( vpd, PCI_FMT " VPD tag %02x not found\n",
	       PCI_ARGS ( vpd->pci ), tag );
	return -ENOENT;
}

/**
 * Locate PCI VPD field
 *
 * @v vpd		PCI VPD
 * @v field		VPD field descriptor
 * @ret address		Address of field body
 * @ret len		Length of field body
 * @ret rc		Return status code
 */
int pci_vpd_find ( struct pci_vpd *vpd, unsigned int field,
		   unsigned int *address, size_t *len ) {
	struct pci_vpd_field read_field;
	int rc;

	/* Locate containing tag */
	if ( ( rc = pci_vpd_find_tag ( vpd, PCI_VPD_TAG ( field ),
				       address, len ) ) != 0 )
		return rc;

	/* Return immediately if we are searching for a whole-tag field */
	if ( ! PCI_VPD_KEYWORD ( field ) ) {
		pci_vpd_dump ( vpd, *address, *len );
		return 0;
	}

	/* Scan through fields looking for a match */
	while ( *len >= sizeof ( read_field ) ) {

		/* Read field header */
		if ( ( rc = pci_vpd_read ( vpd, *address, &read_field,
					   sizeof ( read_field ) ) ) != 0 )
			return rc;
		*address += sizeof ( read_field );
		*len -= sizeof ( read_field );

		/* Check for keyword match */
		if ( read_field.keyword == PCI_VPD_KEYWORD ( field ) ) {
			*len = read_field.len;
			DBGC ( vpd, PCI_FMT " VPD field " PCI_VPD_FIELD_FMT
			       " is at [%04x,%04zx)\n", PCI_ARGS ( vpd->pci ),
			       PCI_VPD_FIELD_ARGS ( field ),
			       *address, ( *address + *len ) );
			pci_vpd_dump ( vpd, *address, *len );
			return 0;
		}

		/* Move to next field */
		if ( read_field.len > *len )
			break;
		*address += read_field.len;
		*len -= read_field.len;
	}

	DBGC ( vpd, PCI_FMT " VPD field " PCI_VPD_FIELD_FMT " not found\n",
	       PCI_ARGS ( vpd->pci ), PCI_VPD_FIELD_ARGS ( field ) );
	return -ENOENT;
}

/**
 * Resize VPD field
 *
 * @v vpd		PCI VPD
 * @v field		VPD field descriptor
 * @v len		New length of field body
 * @ret address		Address of field body
 * @ret rc		Return status code
 */
int pci_vpd_resize ( struct pci_vpd *vpd, unsigned int field, size_t len,
		     unsigned int *address ) {
	struct pci_vpd_field rw_field;
	struct pci_vpd_field old_field;
	struct pci_vpd_field new_field;
	unsigned int rw_address;
	unsigned int old_address;
	unsigned int copy_address;
	unsigned int dst_address;
	unsigned int dump_address;
	size_t rw_len;
	size_t old_len;
	size_t available_len;
	size_t copy_len;
	size_t dump_len;
	void *copy;
	int rc;

	/* Sanity checks */
	assert ( PCI_VPD_TAG ( field ) == PCI_VPD_TAG_RW );
	assert ( PCI_VPD_KEYWORD ( field ) != 0 );
	assert ( field != PCI_VPD_FIELD_RW );

	/* Locate 'RW' field */
	if ( ( rc = pci_vpd_find ( vpd, PCI_VPD_FIELD_RW, &rw_address,
				   &rw_len ) ) != 0 )
		goto err_no_rw;

	/* Locate old field, if any */
	if ( ( rc = pci_vpd_find ( vpd, field, &old_address,
				   &old_len ) ) == 0 ) {

		/* Field already exists */
		if ( old_address > rw_address ) {
			DBGC ( vpd, PCI_FMT " VPD field " PCI_VPD_FIELD_FMT
			       " at [%04x,%04zx) is after field "
			       PCI_VPD_FIELD_FMT " at [%04x,%04zx)\n",
			       PCI_ARGS ( vpd->pci ),
			       PCI_VPD_FIELD_ARGS ( field ),
			       old_address, ( old_address + old_len ),
			       PCI_VPD_FIELD_ARGS ( PCI_VPD_FIELD_RW ),
			       rw_address, ( rw_address + rw_len ) );
			rc = -ENXIO;
			goto err_after_rw;
		}
		dst_address = ( old_address - sizeof ( old_field ) );
		copy_address = ( old_address + old_len );
		copy_len = ( rw_address - sizeof ( rw_field ) - copy_address );

		/* Calculate available length */
		available_len = ( rw_len + old_len );

	} else {

		/* Field does not yet exist */
		dst_address = ( rw_address - sizeof ( rw_field ) );
		copy_address = dst_address;
		copy_len = 0;

		/* Calculate available length */
		available_len = ( ( rw_len > sizeof ( new_field ) ) ?
				  ( rw_len - sizeof ( new_field ) ) : 0 );
	}

	/* Dump region before changes */
	dump_address = dst_address;
	dump_len = ( rw_address + rw_len - dump_address );
	DBGC ( vpd, PCI_FMT " VPD before resizing field " PCI_VPD_FIELD_FMT
	       " to %zd bytes:\n", PCI_ARGS ( vpd->pci ),
	       PCI_VPD_FIELD_ARGS ( field ), len );
	pci_vpd_dump ( vpd, dump_address, dump_len );

	/* Check available length */
	if ( available_len > PCI_VPD_MAX_LEN )
		available_len = PCI_VPD_MAX_LEN;
	if ( len > available_len ) {
		DBGC ( vpd, PCI_FMT " VPD no space for field "
		       PCI_VPD_FIELD_FMT " (need %02zx, have %02zx)\n",
		       PCI_ARGS ( vpd->pci ), PCI_VPD_FIELD_ARGS ( field ),
		       len, available_len );
		rc = -ENOSPC;
		goto err_no_space;
	}

	/* Preserve intermediate fields, if any */
	copy = malloc ( copy_len );
	if ( ! copy ) {
		rc = -ENOMEM;
		goto err_copy_alloc;
	}
	if ( ( rc = pci_vpd_read ( vpd, copy_address, copy, copy_len ) ) != 0 )
		goto err_copy_read;

	/* Create new field, if applicable */
	if ( len ) {
		new_field.keyword = PCI_VPD_KEYWORD ( field );
		new_field.len = len;
		if ( ( rc = pci_vpd_write ( vpd, dst_address, &new_field,
					    sizeof ( new_field ) ) ) != 0 )
			goto err_new_write;
		dst_address += sizeof ( new_field );
		*address = dst_address;
		DBGC ( vpd, PCI_FMT " VPD field " PCI_VPD_FIELD_FMT " is now "
		       "at [%04x,%04x)\n", PCI_ARGS ( vpd->pci ),
		       PCI_VPD_FIELD_ARGS ( field ), dst_address,
		       ( dst_address + new_field.len ) );
		dst_address += len;
	} else {
		DBGC ( vpd, PCI_FMT " VPD field " PCI_VPD_FIELD_FMT
		       " no longer exists\n", PCI_ARGS ( vpd->pci ),
		       PCI_VPD_FIELD_ARGS ( field ) );
	}

	/* Restore intermediate fields, if any */
	if ( ( rc = pci_vpd_write ( vpd, dst_address, copy, copy_len ) ) != 0 )
		goto err_copy_write;
	dst_address += copy_len;

	/* Create 'RW' field */
	rw_field.keyword = PCI_VPD_KEYWORD ( PCI_VPD_FIELD_RW );
	rw_field.len = ( rw_len +
			 ( rw_address - sizeof ( rw_field ) ) - dst_address );
	if ( ( rc = pci_vpd_write ( vpd, dst_address, &rw_field,
				    sizeof ( rw_field ) ) ) != 0 )
		goto err_rw_write;
	dst_address += sizeof ( rw_field );
	DBGC ( vpd, PCI_FMT " VPD field " PCI_VPD_FIELD_FMT " is now "
	       "at [%04x,%04x)\n", PCI_ARGS ( vpd->pci ),
	       PCI_VPD_FIELD_ARGS ( PCI_VPD_FIELD_RW ), dst_address,
	       ( dst_address + rw_field.len ) );

	/* Dump region after changes */
	DBGC ( vpd, PCI_FMT " VPD after resizing field " PCI_VPD_FIELD_FMT
	       " to %zd bytes:\n", PCI_ARGS ( vpd->pci ),
	       PCI_VPD_FIELD_ARGS ( field ), len );
	pci_vpd_dump ( vpd, dump_address, dump_len );

	rc = 0;

 err_rw_write:
 err_new_write:
 err_copy_write:
 err_copy_read:
	free ( copy );
 err_copy_alloc:
 err_no_space:
 err_after_rw:
 err_no_rw:
	return rc;
}
