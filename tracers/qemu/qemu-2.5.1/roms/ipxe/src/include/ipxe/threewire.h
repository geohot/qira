#ifndef _IPXE_THREEWIRE_H
#define _IPXE_THREEWIRE_H

/** @file
 *
 * Three-wire serial interface
 *
 * The Atmel three-wire interface is a subset of the (newer) SPI
 * interface, and is implemented here as a layer on top of the SPI
 * support.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/spi.h>
#include <limits.h>

/**
 * @defgroup tcmds Three-wire commands
 * @{
 */

/** Read data from memory array */
#define THREEWIRE_READ 0x6

/** Write data to memory array */
#define THREEWIRE_WRITE 0x5

/** Write enable */
#define THREEWIRE_EWEN 0x4

/** Address to be used for write enable command */
#define THREEWIRE_EWEN_ADDRESS INT_MAX

/** Time to wait for write cycles to complete
 *
 * This is sufficient for AT93C46/AT93C56 devices, but may need to be
 * increased in future when other devices are added.
 */
#define THREEWIRE_WRITE_MDELAY 10

/** @} */

extern int threewire_read ( struct nvs_device *nvs, unsigned int address,
			    void *data, size_t len );
extern int threewire_write ( struct nvs_device *nvs, unsigned int address,
			     const void *data, size_t len );
extern int threewire_detect_address_len ( struct spi_device *device );

/**
 * @defgroup tdevs Three-wire device types
 * @{
 */

static inline __attribute__ (( always_inline )) void
init_at93cx6 ( struct spi_device *device, unsigned int organisation ) {
	device->nvs.word_len_log2 = ( ( organisation == 8 ) ? 0 : 1 );
	device->nvs.block_size = 1;
	device->command_len = 3,
	device->nvs.read = threewire_read;
	device->nvs.write = threewire_write;
}

/**
 * Initialise Atmel AT93C06 serial EEPROM
 *
 * @v device		SPI device
 * @v organisation	Word organisation (8 or 16)
 */
static inline __attribute__ (( always_inline )) void
init_at93c06 ( struct spi_device *device, unsigned int organisation ) {
	device->nvs.size = ( 256 / organisation );
	device->address_len = ( ( organisation == 8 ) ? 7 : 6 );
	init_at93cx6 ( device, organisation );
}

/**
 * Initialise Atmel AT93C46 serial EEPROM
 *
 * @v device		SPI device
 * @v organisation	Word organisation (8 or 16)
 */
static inline __attribute__ (( always_inline )) void
init_at93c46 ( struct spi_device *device, unsigned int organisation ) {
	device->nvs.size = ( 1024 / organisation );
	device->address_len = ( ( organisation == 8 ) ? 7 : 6 );
	init_at93cx6 ( device, organisation );
}

/**
 * Initialise Atmel AT93C56 serial EEPROM
 *
 * @v device		SPI device
 * @v organisation	Word organisation (8 or 16)
 */
static inline __attribute__ (( always_inline )) void
init_at93c56 ( struct spi_device *device, unsigned int organisation ) {
	device->nvs.size = ( 2048 / organisation );
	device->address_len = ( ( organisation == 8 ) ? 9 : 8 );
	init_at93cx6 ( device, organisation );
}

/**
 * Initialise Atmel AT93C66 serial EEPROM
 *
 * @v device		SPI device
 * @v organisation	Word organisation (8 or 16)
 */
static inline __attribute__ (( always_inline )) void
init_at93c66 ( struct spi_device *device, unsigned int organisation ) {
	device->nvs.size = ( 4096 / organisation );
	device->address_len = ( ( organisation == 8 ) ? 9 : 8 );
	init_at93cx6 ( device, organisation );
}

/** @} */

#endif /* _IPXE_THREEWIRE_H */
