#ifndef _IPXE_I2C_H
#define _IPXE_I2C_H

/** @file
 *
 * I2C interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/bitbash.h>

/** An I2C device
 *
 * An I2C device represents a specific slave device on an I2C bus.  It
 * is accessed via an I2C interface.
 */
struct i2c_device {
	/** Address of this device
	 *
	 * The actual address sent on the bus will look like
	 *
	 *    <start> <device address> <word address overflow> <r/w>
	 *
	 * The "word address overflow" is any excess bits from the
	 * word address, i.e. any portion that does not fit within the
	 * defined word address length.
	 */
	unsigned int dev_addr;
	/** Device address length, in bytes
	 *
	 * This is the number of bytes that comprise the device
	 * address, defined to be the portion that terminates with the
	 * read/write bit.
	 */
	unsigned int dev_addr_len;
	/** Word adddress length, in bytes
	 *
	 * This is the number of bytes that comprise the word address,
	 * defined to be the portion that starts after the read/write
	 * bit and ends before the first data byte.
	 *
	 * For some devices, this length will be zero (i.e. the word
	 * address is contained entirely within the "word address
	 * overflow").
	 */
	unsigned int word_addr_len;
};

/** An I2C interface
 *
 * An I2C interface provides access to an I2C bus, via which I2C
 * devices may be reached.
 */
struct i2c_interface {
	/**
	 * Read data from I2C device
	 *
	 * @v i2c		I2C interface
	 * @v i2cdev		I2C device
	 * @v offset		Starting offset within the device
	 * @v data		Data buffer
	 * @v len		Length of data buffer
	 * @ret rc		Return status code
	 */
	int ( * read ) ( struct i2c_interface *i2c, struct i2c_device *i2cdev,
			 unsigned int offset, uint8_t *data,
			 unsigned int len );
	/**
	 * Write data to I2C device
	 *
	 * @v i2c		I2C interface
	 * @v i2cdev		I2C device
	 * @v offset		Starting offset within the device
	 * @v data		Data buffer
	 * @v len		Length of data buffer
	 * @ret rc		Return status code
	 */
	int ( * write ) ( struct i2c_interface *i2c, struct i2c_device *i2cdev,
			  unsigned int offset, const uint8_t *data,
			  unsigned int len );
};

/** A bit-bashing I2C interface
 *
 * This provides a standardised way to construct I2C buses via a
 * bit-bashing interface.
 */
struct i2c_bit_basher {
	/** I2C interface */
	struct i2c_interface i2c;
	/** Bit-bashing interface */
	struct bit_basher basher;
};

/** Ten-bit address marker
 *
 * This value is ORed with the I2C device address to indicate a
 * ten-bit address format on the bus.
 */
#define I2C_TENBIT_ADDRESS 0x7800

/** An I2C write command */
#define I2C_WRITE 0

/** An I2C read command */
#define I2C_READ 1

/** Bit indices used for I2C bit-bashing interface */
enum {
	/** Serial clock */
	I2C_BIT_SCL = 0,
	/** Serial data */
	I2C_BIT_SDA,
};

/** Delay required for bit-bashing operation */
#define I2C_UDELAY 5

/** Maximum number of cycles to use when attempting a bus reset */
#define I2C_RESET_MAX_CYCLES 32

/**
 * Check presence of I2C device
 *
 * @v i2c		I2C interface
 * @v i2cdev		I2C device
 * @ret rc		Return status code
 *
 * Checks for the presence of the device on the I2C bus by attempting
 * a zero-length write.
 */
static inline int i2c_check_presence ( struct i2c_interface *i2c,
				       struct i2c_device *i2cdev ) {
	return i2c->write ( i2c, i2cdev, 0, NULL, 0 );
}

extern int init_i2c_bit_basher ( struct i2c_bit_basher *i2cbit,
				 struct bit_basher_operations *bash_op );

/**
 * Initialise generic I2C EEPROM device
 *
 * @v i2cdev		I2C device
 */
static inline __always_inline void
init_i2c_eeprom ( struct i2c_device *i2cdev, unsigned int dev_addr ) {
	i2cdev->dev_addr = dev_addr;
	i2cdev->dev_addr_len = 1;
	i2cdev->word_addr_len = 1;
}

/**
 * Initialise Atmel AT24C11
 *
 * @v i2cdev		I2C device
 */
static inline __always_inline void
init_at24c11 ( struct i2c_device *i2cdev ) {
	/* This chip has no device address; it must be the only chip
	 * on the bus.  The word address is contained entirely within
	 * the device address field.
	 */
	i2cdev->dev_addr = 0;
	i2cdev->dev_addr_len = 1;
	i2cdev->word_addr_len = 0;
}

#endif /* _IPXE_I2C_H */
