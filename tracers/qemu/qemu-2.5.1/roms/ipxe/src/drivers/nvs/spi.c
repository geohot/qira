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
#include <errno.h>
#include <unistd.h>
#include <ipxe/spi.h>

/** @file
 *
 * SPI devices
 *
 */

/**
 * Munge SPI device address into command
 *
 * @v command		SPI command
 * @v address		Address
 * @v munge_address	Device requires address munging
 * @ret command		Actual SPI command to use
 *
 * Some devices with 9-bit addresses (e.g. AT25040A EEPROM) use bit 3
 * of the command byte as address bit A8, rather than having a
 * two-byte address.  This function takes care of generating the
 * appropriate command.
 */
static inline unsigned int spi_command ( unsigned int command,
					 unsigned int address,
					 int munge_address ) {
	return ( command | ( ( ( address >> 8 ) & munge_address ) << 3 ) );
}

/**
 * Wait for SPI device to complete operation
 *
 * @v device		SPI device
 * @ret rc		Return status code
 */
static int spi_wait ( struct spi_device *device ) {
	struct spi_bus *bus = device->bus;
	uint8_t status;
	int i;
	int rc;

	for ( i = 0 ; i < 50 ; i++ ) {
		udelay ( 20 );
		if ( ( rc = bus->rw ( bus, device, SPI_RDSR, -1, NULL,
				      &status, sizeof ( status ) ) ) != 0 )
			return rc;
		if ( ! ( status & SPI_STATUS_NRDY ) )
			return 0;
	}
	DBG ( "SPI %p timed out\n", device );
	return -ETIMEDOUT;
}

/**
 * Read data from SPI device
 *
 * @v nvs		NVS device
 * @v address		Address from which to read
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int spi_read ( struct nvs_device *nvs, unsigned int address,
	       void *data, size_t len ) {
	struct spi_device *device = nvs_to_spi ( nvs );
	struct spi_bus *bus = device->bus;
	unsigned int command = spi_command ( SPI_READ, address,
					     device->munge_address );
	int rc;

	DBG ( "SPI %p reading %zd bytes from %#04x\n", device, len, address );
	if ( ( rc = bus->rw ( bus, device, command, address,
			      NULL, data, len ) ) != 0 ) {
		DBG ( "SPI %p failed to read data from device\n", device );
		return rc;
	}

	return 0;
}

/**
 * Write data to SPI device
 *
 * @v nvs		NVS device
 * @v address		Address from which to read
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int spi_write ( struct nvs_device *nvs, unsigned int address,
		const void *data, size_t len ) {
	struct spi_device *device = nvs_to_spi ( nvs );
	struct spi_bus *bus = device->bus;
	unsigned int command = spi_command ( SPI_WRITE, address,
					     device->munge_address );
	int rc;

	DBG ( "SPI %p writing %zd bytes to %#04x\n", device, len, address );

	if ( ( rc = bus->rw ( bus, device, SPI_WREN, -1,
			      NULL, NULL, 0 ) ) != 0 ) {
		DBG ( "SPI %p failed to write-enable device\n", device );
		return rc;
	}

	if ( ( rc = bus->rw ( bus, device, command, address,
			      data, NULL, len ) ) != 0 ) {
		DBG ( "SPI %p failed to write data to device\n", device );
		return rc;
	}
	
	if ( ( rc = spi_wait ( device ) ) != 0 ) {
		DBG ( "SPI %p failed to complete write operation\n", device );
		return rc;
	}

	return 0;
}

