#ifndef _IPXE_SPI_H
#define _IPXE_SPI_H

/** @file
 *
 * SPI interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/nvs.h>

/**
 * @defgroup spicmds SPI commands
 * @{
 */

/** Write status register */
#define SPI_WRSR 0x01

/** Write data to memory array */
#define SPI_WRITE 0x02

/** Read data from memory array */
#define SPI_READ 0x03

/** Reset write enable latch */
#define SPI_WRDI 0x04

/** Read status register */
#define SPI_RDSR 0x05

/** Set write enable latch */
#define SPI_WREN 0x06

/**
 * @defgroup atmelcmds Atmel-specific SPI commands
 * @{
 */

/** Erase one sector in memory array (Not supported on all devices) */
#define ATMEL_SECTOR_ERASE 0x52

/** Erase all sections in memory array (Not supported on all devices) */
#define ATMEL_CHIP_ERASE 0x62

/** Read manufacturer and product ID (Not supported on all devices) */
#define ATMEL_RDID 0x15

/** @} */

/** @} */

/**
 * @defgroup spistatus SPI status register bits (not present on all devices)
 * @{
 */

/** Write-protect pin enabled */
#define SPI_STATUS_WPEN 0x80

/** Block protection bit 2 */
#define SPI_STATUS_BP2 0x10

/** Block protection bit 1 */
#define SPI_STATUS_BP1 0x08

/** Block protection bit 0 */
#define SPI_STATUS_BP0 0x04

/** State of the write enable latch */
#define SPI_STATUS_WEN 0x02

/** Device busy flag */
#define SPI_STATUS_NRDY 0x01

/** @} */

/**
 * An SPI device
 *
 * This data structure represents a physical SPI device attached to an
 * SPI bus.
 */
struct spi_device {
	/** NVS device */
	struct nvs_device nvs;
	/** SPI bus to which device is attached */
	struct spi_bus *bus;
	/** Slave number */
	unsigned int slave;
	/** Command length, in bits */
	unsigned int command_len;
	/** Address length, in bits */
	unsigned int address_len;
	/** Address is munged
	 *
	 * Some devices with 9-bit addresses (e.g. AT25040A EEPROM)
	 * use bit 3 of the command byte as address bit A8, rather
	 * than having a two-byte address.  If this flag is set, then
	 * commands should be munged in this way.
	 */
	unsigned int munge_address : 1;
};

/**
 * SPI magic autodetection address length
 *
 * Set @c spi_device::address_len to @c SPI_AUTODETECT_ADDRESS_LEN if
 * the address length should be autodetected.
 */
#define SPI_AUTODETECT_ADDRESS_LEN 0

static inline __attribute__ (( always_inline )) struct spi_device *
nvs_to_spi ( struct nvs_device *nvs ) {
	return container_of ( nvs, struct spi_device, nvs );
}

/**
 * An SPI bus
 *
 * This data structure represents an SPI bus controller capable of
 * issuing commands to attached SPI devices.
 */
struct spi_bus {
	/** SPI interface mode
	 *
	 * This is the bitwise OR of zero or more of @c SPI_MODE_CPHA
	 * and @c SPI_MODE_CPOL.  It is also the number conventionally
	 * used to describe the SPI interface mode.  For example, SPI
	 * mode 1 is the mode in which CPOL=0 and CPHA=1, which
	 * therefore corresponds to a mode value of (0|SPI_MODE_CPHA)
	 * which, happily, equals 1.
	 */
	unsigned int mode;
	/**
	 * Read/write data via SPI bus
	 *
	 * @v bus		SPI bus
	 * @v device		SPI device
	 * @v command		Command
	 * @v address		Address to read/write (<0 for no address)
	 * @v data_out		TX data buffer (or NULL)
	 * @v data_in		RX data buffer (or NULL)
	 * @v len		Length of data buffer(s)
	 *
	 * This issues the specified command and optional address to
	 * the SPI device, then reads and/or writes data to/from the
	 * data buffers.
	 */
	int ( * rw ) ( struct spi_bus *bus, struct spi_device *device,
		       unsigned int command, int address,
		       const void *data_out, void *data_in, size_t len );
};

/** Clock phase (CPHA) mode bit
 *
 * Phase 0 is sample on rising edge, shift data on falling edge.
 *
 * Phase 1 is shift data on rising edge, sample data on falling edge.
 */
#define SPI_MODE_CPHA 0x01

/** Clock polarity (CPOL) mode bit
 *
 * This bit reflects the idle state of the clock line (SCLK).
 */
#define SPI_MODE_CPOL 0x02

/** Slave select polarity mode bit
 *
 * This bit reflects that active state of the slave select lines.  It
 * is not part of the normal SPI mode number (which covers only @c
 * SPI_MODE_CPOL and @c SPI_MODE_CPHA), but is included here for
 * convenience.
 */
#define SPI_MODE_SSPOL 0x10

/** Microwire-compatible mode
 *
 * This is SPI mode 1 (i.e. CPOL=0, CPHA=1), and is compatible with
 * the original Microwire protocol.
 */
#define SPI_MODE_MICROWIRE 1

/** Microwire/Plus-compatible mode
 *
 * This is SPI mode 0 (i.e. CPOL=0, CPHA=0), and is compatible with
 * the Microwire/Plus protocol
 */
#define SPI_MODE_MICROWIRE_PLUS 0

/** Threewire-compatible mode
 *
 * This mode is compatible with Atmel's series of "three-wire"
 * interfaces.
 */
#define SPI_MODE_THREEWIRE ( SPI_MODE_MICROWIRE_PLUS | SPI_MODE_SSPOL )

extern int spi_read ( struct nvs_device *nvs, unsigned int address,
		      void *data, size_t len );
extern int spi_write ( struct nvs_device *nvs, unsigned int address,
		       const void *data, size_t len );

/**
 * @defgroup spidevs SPI device types
 * @{
 */

static inline __attribute__ (( always_inline )) void
init_spi ( struct spi_device *device ) {
	device->nvs.word_len_log2 = 0;
	device->command_len = 8,
	device->nvs.read = spi_read;
	device->nvs.write = spi_write;	
}

/** Atmel AT25F1024 serial flash */
static inline __attribute__ (( always_inline )) void
init_at25f1024 ( struct spi_device *device ) {
	device->address_len = 24;
	device->nvs.size = ( 128 * 1024 );
	device->nvs.block_size = 256;
	init_spi ( device );
}

/** Atmel 25040 serial EEPROM */
static inline __attribute__ (( always_inline )) void
init_at25040 ( struct spi_device *device ) {
	device->address_len = 8;
	device->munge_address = 1;
	device->nvs.size = 512;
	device->nvs.block_size = 8;
	init_spi ( device );
}

/** ST M25P32 serial flash */
static inline __attribute__ (( always_inline )) void
init_m25p32 ( struct spi_device *device ) {
	device->address_len = 24;
	device->nvs.size = ( 4 * 1024 * 1024 );
	device->nvs.block_size = 256;
	init_spi ( device );
}

/** Microchip 25XX640 serial EEPROM */
static inline __attribute__ (( always_inline )) void
init_mc25xx640 ( struct spi_device *device ) {
	device->address_len = 16;
	device->nvs.size = ( 8 * 1024 );
	device->nvs.block_size = 32;
	init_spi ( device );
}

/** @} */

#endif /* _IPXE_SPI_H */
