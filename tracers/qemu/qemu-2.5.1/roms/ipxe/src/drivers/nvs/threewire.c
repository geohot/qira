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
#include <assert.h>
#include <unistd.h>
#include <ipxe/threewire.h>

/** @file
 *
 * Three-wire serial devices
 *
 */

/**
 * Read data from three-wire device
 *
 * @v nvs		NVS device
 * @v address		Address from which to read
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int threewire_read ( struct nvs_device *nvs, unsigned int address,
		     void *data, size_t len ) {
	struct spi_device *device = nvs_to_spi ( nvs );
	struct spi_bus *bus = device->bus;
	int rc;

	assert ( bus->mode == SPI_MODE_THREEWIRE );

	DBGC ( device, "3wire %p reading %zd bytes at %04x\n",
	       device, len, address );

	if ( ( rc = bus->rw ( bus, device, THREEWIRE_READ, address,
			      NULL, data, len ) ) != 0 ) {
		DBGC ( device, "3wire %p could not read: %s\n",
		       device, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Write data to three-wire device
 *
 * @v nvs		NVS device
 * @v address		Address from which to read
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int threewire_write ( struct nvs_device *nvs, unsigned int address,
		      const void *data, size_t len ) {
	struct spi_device *device = nvs_to_spi ( nvs );
	struct spi_bus *bus = device->bus;
	int rc;

	assert ( bus->mode == SPI_MODE_THREEWIRE );

	DBGC ( device, "3wire %p writing %zd bytes at %04x\n",
	       device, len, address );

	/* Enable device for writing */
	if ( ( rc = bus->rw ( bus, device, THREEWIRE_EWEN,
			      THREEWIRE_EWEN_ADDRESS, NULL, NULL, 0 ) ) != 0 ){
		DBGC ( device, "3wire %p could not enable writing: %s\n",
		       device, strerror ( rc ) );
		return rc;
	}

	/* Write data */
	if ( ( rc = bus->rw ( bus, device, THREEWIRE_WRITE, address,
			      data, NULL, len ) ) != 0 ) {
		DBGC ( device, "3wire %p could not write: %s\n",
		       device, strerror ( rc ) );
		return rc;
	}

	/* Our model of an SPI bus doesn't provide a mechanism for
	 * "assert CS, wait for MISO to become high, so just wait for
	 * long enough to ensure that the write has completed.
	 */
	mdelay ( THREEWIRE_WRITE_MDELAY );

	return 0;
}

/**
 * Autodetect device address length
 *
 * @v device		SPI device
 * @ret rc		Return status code
 */
int threewire_detect_address_len ( struct spi_device *device ) {
	struct nvs_device *nvs = &device->nvs;
	int rc;

	DBGC ( device, "3wire %p autodetecting address length\n", device );

	device->address_len = SPI_AUTODETECT_ADDRESS_LEN;
	if ( ( rc = threewire_read ( nvs, 0, NULL,
				     ( 1 << nvs->word_len_log2 ) ) ) != 0 ) {
		DBGC ( device, "3wire %p could not autodetect address "
		       "length: %s\n", device, strerror ( rc ) );
		return rc;
	}

	DBGC ( device, "3wire %p autodetected address length %d\n",
	       device, device->address_len );
	return 0;
}
