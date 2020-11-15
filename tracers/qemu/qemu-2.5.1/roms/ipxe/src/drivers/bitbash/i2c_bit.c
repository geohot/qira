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
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <ipxe/bitbash.h>
#include <ipxe/i2c.h>

/** @file
 *
 * I2C bit-bashing interface
 *
 * This implements a simple I2C master via a bit-bashing interface
 * that provides two lines: SCL (clock) and SDA (data).
 */

/**
 * Delay between output state changes
 *
 * Max rated i2c speed (for the basic i2c protocol) is 100kbps,
 * i.e. 200k clock transitions per second.
 */
static void i2c_delay ( void ) {
	udelay ( I2C_UDELAY );
}

/**
 * Set state of I2C SCL line
 *
 * @v basher		Bit-bashing interface
 * @v state		New state of SCL
 */
static void setscl ( struct bit_basher *basher, int state ) {
	DBG2 ( "%c", ( state ? '/' : '\\' ) );
	write_bit ( basher, I2C_BIT_SCL, state );
	i2c_delay();
}

/**
 * Set state of I2C SDA line
 *
 * @v basher		Bit-bashing interface
 * @v state		New state of SDA
 */
static void setsda ( struct bit_basher *basher, int state ) {
	DBG2 ( "%c", ( state ? '1' : '0' ) );
	write_bit ( basher, I2C_BIT_SDA, state );
	i2c_delay();
}

/**
 * Get state of I2C SDA line
 *
 * @v basher		Bit-bashing interface
 * @ret state		State of SDA
 */
static int getsda ( struct bit_basher *basher ) {
	int state;
	state = read_bit ( basher, I2C_BIT_SDA );
	DBG2 ( "%c", ( state ? '+' : '-' ) );
	return state;
}

/**
 * Send an I2C start condition
 *
 * @v basher		Bit-bashing interface
 */
static void i2c_start ( struct bit_basher *basher ) {
	setscl ( basher, 1 );
	setsda ( basher, 0 );
	setscl ( basher, 0 );
	setsda ( basher, 1 );
}

/**
 * Send an I2C data bit
 *
 * @v basher		Bit-bashing interface
 * @v bit		Bit to send
 */
static void i2c_send_bit ( struct bit_basher *basher, int bit ) {
	setsda ( basher, bit );
	setscl ( basher, 1 );
	setscl ( basher, 0 );
	setsda ( basher, 1 );
}

/**
 * Receive an I2C data bit
 *
 * @v basher		Bit-bashing interface
 * @ret bit		Received bit
 */
static int i2c_recv_bit ( struct bit_basher *basher ) {
	int bit;

	setscl ( basher, 1 );
	bit = getsda ( basher );
	setscl ( basher, 0 );
	return bit;
}

/**
 * Send an I2C stop condition
 *
 * @v basher		Bit-bashing interface
 */
static void i2c_stop ( struct bit_basher *basher ) {
	setsda ( basher, 0 );
	setscl ( basher, 1 );
	setsda ( basher, 1 );
}

/**
 * Send byte via I2C bus and check for acknowledgement
 *
 * @v basher		Bit-bashing interface
 * @v byte		Byte to send
 * @ret rc		Return status code
 *
 * Sends a byte via the I2C bus and checks for an acknowledgement from
 * the slave device.
 */
static int i2c_send_byte ( struct bit_basher *basher, uint8_t byte ) {
	int i;
	int ack;

	/* Send byte */
	DBG2 ( "[send %02x]", byte );
	for ( i = 8 ; i ; i-- ) {
		i2c_send_bit ( basher, byte & 0x80 );
		byte <<= 1;
	}

	/* Check for acknowledgement from slave */
	ack = ( i2c_recv_bit ( basher ) == 0 );
	DBG2 ( "%s", ( ack ? "[acked]" : "[not acked]" ) );

	return ( ack ? 0 : -EIO );
}

/**
 * Receive byte via I2C bus
 *
 * @v basher		Bit-bashing interface
 * @ret byte		Received byte
 *
 * Receives a byte via the I2C bus and sends NACK to the slave device.
 */
static uint8_t i2c_recv_byte ( struct bit_basher *basher ) {
	uint8_t byte = 0;
	int i;

	/* Receive byte */
	for ( i = 8 ; i ; i-- ) {
		byte <<= 1;
		byte |= ( i2c_recv_bit ( basher ) & 0x1 );
	}

	/* Send NACK */
	i2c_send_bit ( basher, 1 );

	DBG2 ( "[rcvd %02x]", byte );
	return byte;
}

/**
 * Select I2C device for reading or writing
 *
 * @v basher		Bit-bashing interface
 * @v i2cdev		I2C device
 * @v offset		Starting offset within the device
 * @v direction		I2C_READ or I2C_WRITE
 * @ret rc		Return status code
 */
static int i2c_select ( struct bit_basher *basher, struct i2c_device *i2cdev,
			unsigned int offset, unsigned int direction ) {
	unsigned int address;
	int shift;
	unsigned int byte;
	int rc;

	i2c_start ( basher );

	/* Calculate address to appear on bus */
	address = ( ( ( i2cdev->dev_addr |
			( offset >> ( 8 * i2cdev->word_addr_len ) ) ) << 1 )
		    | direction );

	/* Send address a byte at a time */
	for ( shift = ( 8 * ( i2cdev->dev_addr_len - 1 ) ) ;
	      shift >= 0 ; shift -= 8 ) {
		byte = ( ( address >> shift ) & 0xff );
		if ( ( rc = i2c_send_byte ( basher, byte ) ) != 0 )
			return rc;
	}

	return 0;
}

/**
 * Reset I2C bus
 *
 * @v basher		Bit-bashing interface
 * @ret rc		Return status code
 *
 * i2c devices often don't have a reset line, so even a reboot or
 * system power cycle is sometimes not enough to bring them back to a
 * known state.
 */
static int i2c_reset ( struct bit_basher *basher ) {
	unsigned int i;
	int sda;

	/* Clock through several cycles, waiting for an opportunity to
	 * pull SDA low while SCL is high (which creates a start
	 * condition).
	 */
	open_bit ( basher );
	setscl ( basher, 0 );
	setsda ( basher, 1 );
	for ( i = 0 ; i < I2C_RESET_MAX_CYCLES ; i++ ) {
		setscl ( basher, 1 );
		sda = getsda ( basher );
		if ( sda ) {
			/* Now that the device will see a start, issue it */
			i2c_start ( basher );
			/* Stop the bus to leave it in a known good state */
			i2c_stop ( basher );
			DBGC ( basher, "I2CBIT %p reset after %d attempts\n",
			       basher, ( i + 1 ) );
			close_bit ( basher );
			return 0;
		}
		setscl ( basher, 0 );
	}

	DBGC ( basher, "I2CBIT %p could not reset after %d attempts\n",
	       basher, i );
	close_bit ( basher );
	return -ETIMEDOUT;
}

/**
 * Read data from I2C device via bit-bashing interface
 *
 * @v i2c		I2C interface
 * @v i2cdev		I2C device
 * @v offset		Starting offset within the device
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 *
 * Note that attempting to read zero bytes of data is a valid way to
 * check for I2C device presence.
 */
static int i2c_bit_read ( struct i2c_interface *i2c,
			  struct i2c_device *i2cdev, unsigned int offset,
			  uint8_t *data, unsigned int len ) {
	struct i2c_bit_basher *i2cbit
		= container_of ( i2c, struct i2c_bit_basher, i2c );
	struct bit_basher *basher = &i2cbit->basher;
	int rc = 0;

	DBGC ( basher, "I2CBIT %p reading from device %x: ",
	       basher, i2cdev->dev_addr );

	open_bit ( basher );

	for ( ; ; data++, offset++ ) {

		/* Select device for writing */
		if ( ( rc = i2c_select ( basher, i2cdev, offset,
					 I2C_WRITE ) ) != 0 )
			break;

		/* Abort at end of data */
		if ( ! ( len-- ) )
			break;

		/* Select offset */
		if ( ( rc = i2c_send_byte ( basher, offset ) ) != 0 )
			break;
		
		/* Select device for reading */
		if ( ( rc = i2c_select ( basher, i2cdev, offset,
					 I2C_READ ) ) != 0 )
			break;

		/* Read byte */
		*data = i2c_recv_byte ( basher );
		DBGC ( basher, "%02x ", *data );
	}
	
	DBGC ( basher, "%s\n", ( rc ? "failed" : "" ) );
	i2c_stop ( basher );
	close_bit ( basher );
	return rc;
}

/**
 * Write data to I2C device via bit-bashing interface
 *
 * @v i2c		I2C interface
 * @v i2cdev		I2C device
 * @v offset		Starting offset within the device
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 *
 * Note that attempting to write zero bytes of data is a valid way to
 * check for I2C device presence.
 */
static int i2c_bit_write ( struct i2c_interface *i2c,
			   struct i2c_device *i2cdev, unsigned int offset,
			   const uint8_t *data, unsigned int len ) {
	struct i2c_bit_basher *i2cbit
		= container_of ( i2c, struct i2c_bit_basher, i2c );
	struct bit_basher *basher = &i2cbit->basher;
	int rc = 0;

	DBGC ( basher, "I2CBIT %p writing to device %x: ",
	       basher, i2cdev->dev_addr );

	open_bit ( basher );

	for ( ; ; data++, offset++ ) {

		/* Select device for writing */
		if ( ( rc = i2c_select ( basher, i2cdev, offset,
					 I2C_WRITE ) ) != 0 )
			break;
		
		/* Abort at end of data */
		if ( ! ( len-- ) )
			break;

		/* Select offset */
		if ( ( rc = i2c_send_byte ( basher, offset ) ) != 0 )
			break;
		
		/* Write data to device */
		DBGC ( basher, "%02x ", *data );
		if ( ( rc = i2c_send_byte ( basher, *data ) ) != 0 )
			break;
	}

	DBGC ( basher, "%s\n", ( rc ? "failed" : "" ) );
	i2c_stop ( basher );
	close_bit ( basher );
	return rc;
}

/**
 * Initialise I2C bit-bashing interface
 *
 * @v i2cbit		I2C bit-bashing interface
 * @v bash_op		Bit-basher operations
 */
int init_i2c_bit_basher ( struct i2c_bit_basher *i2cbit,
			  struct bit_basher_operations *bash_op ) {
	struct bit_basher *basher = &i2cbit->basher;
	int rc;

	/* Initialise data structures */
	basher->op = bash_op;
	assert ( basher->op->read != NULL );
	assert ( basher->op->write != NULL );
	i2cbit->i2c.read = i2c_bit_read;
	i2cbit->i2c.write = i2c_bit_write;

	/* Reset I2C bus */
	if ( ( rc = i2c_reset ( basher ) ) != 0 ) {
		DBGC ( basher, "I2CBIT %p could not reset I2C bus: %s\n",
		       basher, strerror ( rc ) );
		return rc;
	}

	return 0;
}
