/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * PXE image format
 *
 */

#include <pxe.h>
#include <pxe_call.h>
#include <ipxe/uaccess.h>
#include <ipxe/image.h>
#include <ipxe/segment.h>
#include <ipxe/netdevice.h>
#include <ipxe/features.h>
#include <ipxe/console.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/IndustryStandard/PeImage.h>

FEATURE ( FEATURE_IMAGE, "PXE", DHCP_EB_FEATURE_PXE, 1 );

/** PXE command line */
const char *pxe_cmdline;

/**
 * Execute PXE image
 *
 * @v image		PXE image
 * @ret rc		Return status code
 */
static int pxe_exec ( struct image *image ) {
	userptr_t buffer = real_to_user ( 0, 0x7c00 );
	struct net_device *netdev;
	int rc;

	/* Verify and prepare segment */
	if ( ( rc = prep_segment ( buffer, image->len, image->len ) ) != 0 ) {
		DBGC ( image, "IMAGE %p could not prepare segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	/* Copy image to segment */
	memcpy_user ( buffer, 0, image->data, 0, image->len );

	/* Arbitrarily pick the most recently opened network device */
	if ( ( netdev = last_opened_netdev() ) == NULL ) {
		DBGC ( image, "IMAGE %p could not locate PXE net device\n",
		       image );
		return -ENODEV;
	}
	netdev_get ( netdev );

	/* Activate PXE */
	pxe_activate ( netdev );

	/* Set PXE command line */
	pxe_cmdline = image->cmdline;

	/* Reset console since PXE NBP will probably use it */
	console_reset();

	/* Start PXE NBP */
	rc = pxe_start_nbp();

	/* Clear PXE command line */
	pxe_cmdline = NULL;

	/* Deactivate PXE */
	pxe_deactivate();

	/* Try to reopen network device.  Ignore errors, since the NBP
	 * may have called PXENV_STOP_UNDI.
	 */
	netdev_open ( netdev );
	netdev_put ( netdev );

	return rc;
}

/**
 * Probe PXE image
 *
 * @v image		PXE file
 * @ret rc		Return status code
 */
int pxe_probe ( struct image *image ) {

	/* Images too large to fit in base memory cannot be PXE
	 * images.  We include this check to help prevent unrecognised
	 * images from being marked as PXE images, since PXE images
	 * have no signature we can check against.
	 */
	if ( image->len > ( 0xa0000 - 0x7c00 ) )
		return -ENOEXEC;

	/* Rejecting zero-length images is also useful, since these
	 * end up looking to the user like bugs in iPXE.
	 */
	if ( ! image->len )
		return -ENOEXEC;

	return 0;
}

/**
 * Probe PXE image (with rejection of potential EFI images)
 *
 * @v image		PXE file
 * @ret rc		Return status code
 */
int pxe_probe_no_mz ( struct image *image ) {
	uint16_t magic;
	int rc;

	/* Probe PXE image */
	if ( ( rc = pxe_probe ( image ) ) != 0 )
		return rc;

	/* Reject image with an "MZ" signature which may indicate an
	 * EFI image incorrectly handed out to a BIOS system.
	 */
	if ( image->len >= sizeof ( magic ) ) {
		copy_from_user ( &magic, image->data, 0, sizeof ( magic ) );
		if ( magic == cpu_to_le16 ( EFI_IMAGE_DOS_SIGNATURE ) ) {
			DBGC ( image, "IMAGE %p may be an EFI image\n",
			       image );
			return -ENOTTY;
		}
	}

	return 0;
}

/** PXE image type */
struct image_type pxe_image_type[] __image_type ( PROBE_PXE ) = {
	{
		.name = "PXE-NBP",
		.probe = pxe_probe_no_mz,
		.exec = pxe_exec,
	},
	{
		.name = "PXE-NBP (may be EFI?)",
		.probe = pxe_probe,
		.exec = pxe_exec,
	},
};
