/************************************************* -*- linux-c -*-
 * Myricom 10Gb Network Interface Card Software
 * Copyright 2009, Myricom, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 ****************************************************************/

FILE_LICENCE ( GPL2_ONLY );

/*
 * Author: Glenn Brown <glenn@myri.com>
 */

/*
 * General Theory of Operation
 *
 * This is a minimal Myricom 10 gigabit Ethernet driver for network
 * boot.
 *
 * Initialization
 *
 * myri10ge_pci_probe() is called by iPXE during initialization.
 * Minimal NIC initialization is performed to minimize resources
 * consumed when the driver is resident but unused.
 *
 * Network Boot
 *
 * myri10ge_net_open() is called by iPXE before attempting to network
 * boot from the card.  Packet buffers are allocated and the NIC
 * interface is initialized.
 *
 * Transmit
 *
 * myri10ge_net_transmit() enqueues frames for transmission by writing
 * discriptors to the NIC's tx ring.  For simplicity and to avoid
 * copies, we always have the NIC DMA up the packet.  The sent I/O
 * buffer is released once the NIC signals myri10ge_interrupt_handler()
 * that the send has completed.
 *
 * Receive
 *
 * Receives are posted to the NIC's receive ring.  The NIC fills a
 * DMAable receive_completion ring with completion notifications.
 * myri10ge_net_poll() polls for these receive notifications, posts
 * replacement receive buffers to the NIC, and passes received frames
 * to netdev_rx().
 *
 * NonVolatile Storage
 *
 * This driver supports NonVolatile Storage (nvs) in the NIC EEPROM.
 * If the last EEPROM block is not otherwise filled, we tell
 * iPXE it may store NonVolatile Options (nvo) there.
 */

/*
 * Debugging levels:
 *	- DBG() is for any errors, i.e. failed alloc_iob(), malloc_dma(),
 *	  TX overflow, corrupted packets, ...
 *	- DBG2() is for successful events, like packet received,
 *	  packet transmitted, and other general notifications.
 *	- DBGP() prints the name of each called function on entry
 */

#include <stdint.h>

#include <byteswap.h>
#include <errno.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/netdevice.h>
#include <ipxe/nvo.h>
#include <ipxe/nvs.h>
#include <ipxe/pci.h>
#include <ipxe/timer.h>

#include "myri10ge_mcp.h"

/****************************************************************
 * Forward declarations
 ****************************************************************/

/* PCI driver entry points */

static int	myri10ge_pci_probe ( struct pci_device* );
static void	myri10ge_pci_remove ( struct pci_device* );

/* Network device operations */

static void	myri10ge_net_close ( struct net_device* );
static void	myri10ge_net_irq ( struct net_device*, int enable );
static int	myri10ge_net_open ( struct net_device* );
static void	myri10ge_net_poll ( struct net_device* );
static int	myri10ge_net_transmit ( struct net_device*, struct io_buffer* );

/****************************************************************
 * Constants
 ****************************************************************/

/* Maximum ring indices, used to wrap ring indices.  These must be 2**N-1. */

#define MYRI10GE_TRANSMIT_WRAP                  1U
#define MYRI10GE_RECEIVE_WRAP                   7U
#define MYRI10GE_RECEIVE_COMPLETION_WRAP        31U

/****************************************************************
 * Driver internal data types.
 ****************************************************************/

/* Structure holding all DMA buffers for a NIC, which we will
   allocated as contiguous read/write DMAable memory when the NIC is
   initialized. */

struct myri10ge_dma_buffers
{
	/* The NIC DMAs receive completion notifications into this ring */

	mcp_slot_t receive_completion[1+MYRI10GE_RECEIVE_COMPLETION_WRAP];

	/* Interrupt details are DMAd here before interrupting. */

	mcp_irq_data_t irq_data; /* 64B */

	/* NIC command completion status is DMAd here. */

	mcp_cmd_response_t command_response; /* 8B */
};

struct myri10ge_private
{
	/* Interrupt support */

	uint32	*irq_claim;	/* in NIC SRAM */
	uint32	*irq_deassert;	/* in NIC SRAM */

	/* DMA buffers. */

	struct myri10ge_dma_buffers	*dma;

	/*
	 * Transmit state.
	 *
	 * The counts here are uint32 for easy comparison with
	 * priv->dma->irq_data.send_done_count and with each other.
	 */

	mcp_kreq_ether_send_t	*transmit_ring;	/* in NIC SRAM */
	uint32                   transmit_ring_wrap;
	uint32                   transmits_posted;
	uint32                   transmits_done;
	struct io_buffer	*transmit_iob[1 + MYRI10GE_TRANSMIT_WRAP];

	/*
	 * Receive state.
	 */

	mcp_kreq_ether_recv_t	*receive_post_ring;	/* in NIC SRAM */
	unsigned int             receive_post_ring_wrap;
	unsigned int             receives_posted;
	unsigned int             receives_done;
	struct io_buffer	*receive_iob[1 + MYRI10GE_RECEIVE_WRAP];

	/* Address for writing commands to the firmware.
	   BEWARE: the value must be written 32 bits at a time. */

	mcp_cmd_t	*command;

	/*
	 * Nonvolatile Storage for configuration options.
	 */

	struct nvs_device	nvs;
	struct nvo_block	nvo;
	unsigned int		nvo_registered;

	/* Cached PCI capability locations. */

	uint8			pci_cap_vs;
};

/****************************************************************
 * Driver internal functions.
 ****************************************************************/

/* Print ring status when debugging.  Use this only after a printed
   value changes. */

#define DBG2_RINGS( priv ) 						\
	DBG2 ( "tx %x/%x rx %x/%x in %s() \n",				\
	       ( priv ) ->transmits_done, ( priv ) -> transmits_posted,	\
	       ( priv ) ->receives_done, ( priv ) -> receives_posted,	\
	       __FUNCTION__ )

/*
 * Return a pointer to the driver private data for a network device.
 *
 * @v netdev	Network device created by this driver.
 * @ret priv	The corresponding driver private data.
 */
static inline struct myri10ge_private *myri10ge_priv ( struct net_device *nd )
{
	/* Our private data always follows the network device in memory,
	   since we use alloc_netdev() to allocate the storage. */

	return ( struct myri10ge_private * ) ( nd + 1 );
}

/*
 * Convert a Myri10ge driver private data pointer to a netdev pointer.
 *
 * @v p		Myri10ge device private data.
 * @ret r	The corresponding network device.
 */
static inline struct net_device *myri10ge_netdev ( struct myri10ge_private *p )
{
	return ( ( struct net_device * ) p ) - 1;
}

/*
 * Convert a network device pointer to a PCI device pointer.
 *
 * @v netdev	A Network Device.
 * @ret r	The corresponding PCI device.
 */
static inline struct pci_device *myri10ge_pcidev ( struct net_device *netdev )
{
	return container_of (netdev->dev, struct pci_device, dev);
}

/*
 * Pass a receive buffer to the NIC to be filled.
 *
 * @v priv	The network device to receive the buffer.
 * @v iob	The I/O buffer to fill.
 *
 * Receive buffers are filled in FIFO order.
 */
static void myri10ge_post_receive ( struct myri10ge_private *priv,
				    struct io_buffer *iob )
{
	unsigned int		 receives_posted;
	mcp_kreq_ether_recv_t	*request;

	/* Record the posted I/O buffer, to be passed to netdev_rx() on
	   receive. */

	receives_posted = priv->receives_posted;
	priv->receive_iob[receives_posted & MYRI10GE_RECEIVE_WRAP] = iob;

	/* Post the receive. */

	request = &priv->receive_post_ring[receives_posted
					   & priv->receive_post_ring_wrap];
	request->addr_high = 0;
	wmb();
	request->addr_low = htonl ( virt_to_bus ( iob->data ) );
	priv->receives_posted = ++receives_posted;
}

/*
 * Execute a command on the NIC.
 *
 * @v priv	NIC to perform the command.
 * @v cmd	The command to perform.
 * @v data	I/O copy buffer for parameters/results
 * @ret rc	0 on success, else an error code.
 */
static int myri10ge_command ( struct myri10ge_private *priv,
			      uint32 cmd,
			      uint32 data[3] )
{
	int				 i;
	mcp_cmd_t			*command;
	uint32				 result;
	unsigned int			 slept_ms;
	volatile mcp_cmd_response_t	*response;

	DBGP ( "myri10ge_command ( ,%d, ) \n", cmd );
	command = priv->command;
	response = &priv->dma->command_response;

	/* Mark the command as incomplete. */

	response->result = 0xFFFFFFFF;

	/* Pass the command to the NIC. */

	command->cmd		    = htonl ( cmd );
	command->data0		    = htonl ( data[0] );
	command->data1		    = htonl ( data[1] );
	command->data2		    = htonl ( data[2] );
	command->response_addr.high = 0;
	command->response_addr.low
		= htonl ( virt_to_bus ( &priv->dma->command_response ) );
	for ( i=0; i<9; i++ )
		command->pad[i] = 0;
	wmb();
	command->pad[9] = 0;

	/* Wait up to 2 seconds for a response. */

	for ( slept_ms=0; slept_ms<2000; slept_ms++ ) {
		result = response->result;
		if ( result == 0 ) {
			data[0] = ntohl ( response->data );
			return 0;
		} else if ( result != 0xFFFFFFFF ) {
			DBG ( "cmd%d:0x%x\n",
			      cmd,
			      ntohl ( response->result ) );
			return -EIO;
		}
		udelay ( 1000 );
		rmb();
	}
	DBG ( "cmd%d:timed out\n", cmd );
	return -ETIMEDOUT;
}

/*
 * Handle any pending interrupt.
 *
 * @v netdev		Device being polled for interrupts.
 *
 * This is called periodically to let the driver check for interrupts.
 */
static void myri10ge_interrupt_handler ( struct net_device *netdev )
{
	struct myri10ge_private *priv;
	mcp_irq_data_t		*irq_data;
	uint8			 valid;

	priv = myri10ge_priv ( netdev );
	irq_data = &priv->dma->irq_data;

	/* Return if there was no interrupt. */

	rmb();
	valid = irq_data->valid;
	if ( !valid )
		return;
	DBG2 ( "irq " );

	/* Tell the NIC to deassert the interrupt and clear
	   irq_data->valid.*/

	*priv->irq_deassert = 0;	/* any value is OK. */
	mb();

	/* Handle any new receives. */

	if ( valid & 1 ) {

		/* Pass the receive interrupt token back to the NIC. */

		DBG2 ( "rx " );
		*priv->irq_claim = htonl ( 3 );
		wmb();
	}

	/* Handle any sent packet by freeing its I/O buffer, now that
	   we know it has been DMAd. */

	if ( valid & 2 ) {
		unsigned int nic_done_count;

		DBG2 ( "snt " );
		nic_done_count = ntohl ( priv->dma->irq_data.send_done_count );
		while ( priv->transmits_done != nic_done_count ) {
			struct io_buffer *iob;

			iob = priv->transmit_iob [priv->transmits_done
						  & MYRI10GE_TRANSMIT_WRAP];
			DBG2 ( "%p ", iob );
			netdev_tx_complete ( netdev, iob );
			++priv->transmits_done;
		}
	}

	/* Record any statistics update. */

	if ( irq_data->stats_updated ) {

		/* Update the link status. */

		DBG2 ( "stats " );
		if ( ntohl ( irq_data->link_up ) == MXGEFW_LINK_UP )
			netdev_link_up ( netdev );
		else
			netdev_link_down ( netdev );

		/* Ignore all error counters from the NIC. */
	}

	/* Wait for the interrupt to be deasserted, as indicated by
	   irq_data->valid, which is set by the NIC after the deassert. */

	DBG2 ( "wait " );
	do {
		mb();
	} while ( irq_data->valid );

	/* Claim the interrupt to enable future interrupt generation. */

	DBG2 ( "claim\n" );
	* ( priv->irq_claim + 1 ) = htonl ( 3 );
	mb();
}

/* Constants for reading the STRING_SPECS via the Myricom
   Vendor Specific PCI configuration space capability. */

#define VS_EEPROM_READ_ADDR ( vs + 0x04 )
#define VS_EEPROM_READ_DATA ( vs + 0x08 )
#define VS_EEPROM_WRITE     ( vs + 0x0C )
#define VS_ADDR ( vs + 0x18 )
#define VS_DATA ( vs + 0x14 )
#define VS_MODE ( vs + 0x10 )
#define 	VS_MODE_READ32 0x3
#define 	VS_MODE_LOCATE 0x8
#define 		VS_LOCATE_STRING_SPECS 0x3
#define		VS_MODE_EEPROM_STREAM_WRITE 0xB

/*
 * Read MAC address from its 'string specs' via the vendor-specific
 * capability.  (This capability allows NIC SRAM and ROM to be read
 * before it is mapped.)
 *
 * @v pci		The device.
 * @v vs		Offset of the PCI Vendor-Specific Capability.
 * @v mac		Buffer to store the MAC address.
 * @ret rc		Returns 0 on success, else an error code.
 */
static int mac_address_from_string_specs ( struct pci_device *pci,
					   unsigned int vs,
					   uint8 mac[ETH_ALEN] )
{
	char string_specs[256];
	char *ptr, *limit;
	char *to = string_specs;
	uint32 addr;
	uint32 len;
	int mac_set = 0;

	/* Locate the String specs in LANai SRAM. */

	pci_write_config_byte ( pci, VS_MODE, VS_MODE_LOCATE );
	pci_write_config_dword ( pci, VS_ADDR, VS_LOCATE_STRING_SPECS );
	pci_read_config_dword ( pci, VS_ADDR, &addr );
	pci_read_config_dword ( pci, VS_DATA, &len );
	DBG2 ( "ss@%x,%x\n", addr, len );

	/* Copy in the string specs.  Use 32-bit reads for performance. */

	if ( len > sizeof ( string_specs ) || ( len & 3 ) ) {
		pci_write_config_byte ( pci, VS_MODE, 0 );
		DBG ( "SS too big\n" );
		return -ENOTSUP;
	}

	pci_write_config_byte ( pci, VS_MODE, VS_MODE_READ32 );
	while ( len >= 4 ) {
		uint32 tmp;

		pci_write_config_byte ( pci, VS_ADDR, addr );
		pci_read_config_dword ( pci, VS_DATA, &tmp );
		tmp = ntohl ( tmp );
		memcpy ( to, &tmp, 4 );
		to += 4;
		addr += 4;
		len -= 4;
	}
	pci_write_config_byte ( pci, VS_MODE, 0 );

	/* Parse the string specs. */

	DBG2 ( "STRING_SPECS:\n" );
	ptr = string_specs;
	limit = string_specs + sizeof ( string_specs );
	while ( *ptr != '\0' && ptr < limit ) {
		DBG2 ( "%s\n", ptr );
		if ( memcmp ( ptr, "MAC=", 4 ) == 0 ) {
			unsigned int i;

			ptr += 4;
			for ( i=0; i<6; i++ ) {
				if ( ( ptr + 2 ) > limit ) {
					DBG ( "bad MAC addr\n" );
					return -ENOTSUP;
				}
				mac[i] = strtoul ( ptr, &ptr, 16 );
				ptr += 1;
			}
			mac_set = 1;
		}
		else
			while ( ptr < limit && *ptr++ );
	}

	/* Verify we parsed all we need. */

	if ( !mac_set ) {
		DBG ( "no MAC addr\n" );
		return -ENOTSUP;
	}

	DBG2 ( "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );

	return 0;
}

/****************************************************************
 * NonVolatile Storage support
 ****************************************************************/

/*
 * Fill a buffer with data read from nonvolatile storage.
 *
 * @v nvs	The NonVolatile Storage device to be read.
 * @v addr      The first NonVolatile Storage address to be read.
 * @v _buf	Pointer to the data buffer to be filled.
 * @v len	The number of bytes to copy.
 * @ret rc	0 on success, else nonzero.
 */
static int myri10ge_nvs_read ( struct nvs_device *nvs,
			       unsigned int addr,
			       void *_buf,
			       size_t len )
{
	struct myri10ge_private *priv =
		container_of (nvs, struct myri10ge_private, nvs);
	struct pci_device *pci = myri10ge_pcidev ( myri10ge_netdev ( priv ) );
	unsigned int vs = priv->pci_cap_vs;
	unsigned char *buf = (unsigned char *) _buf;
	unsigned int data;
	unsigned int i, j;

	DBGP ( "myri10ge_nvs_read\n" );

	/* Issue the first read address. */

	pci_write_config_byte ( pci, VS_EEPROM_READ_ADDR + 3, addr>>16 );
	pci_write_config_byte ( pci, VS_EEPROM_READ_ADDR + 2, addr>>8 );
	pci_write_config_byte ( pci, VS_EEPROM_READ_ADDR + 1, addr );
	addr++;

	/* Issue all the reads, and harvest the results every 4th issue. */

	for ( i=0; i<len; ++i,addr++ ) {

		/* Issue the next read address, updating only the
		   bytes that need updating.  We always update the
		   LSB, which triggers the read. */

		if ( ( addr & 0xff ) == 0 ) {
			if ( ( addr & 0xffff ) == 0 ) {
				pci_write_config_byte ( pci,
							VS_EEPROM_READ_ADDR + 3,
							addr >> 16 );
			}
			pci_write_config_byte ( pci,
					        VS_EEPROM_READ_ADDR + 2,
						addr >> 8 );
		}
		pci_write_config_byte ( pci, VS_EEPROM_READ_ADDR + 1, addr );

		/* If 4 data bytes are available, read them with a single read. */

		if ( ( i & 3 ) == 3 ) {
			pci_read_config_dword ( pci,
						VS_EEPROM_READ_DATA,
						&data );
			for ( j=0; j<4; j++ ) {
				buf[i-j] = data;
				data >>= 8;
			}
		}
	}

	/* Harvest any remaining results. */

	if ( ( i & 3 ) != 0 ) {
		pci_read_config_dword ( pci, VS_EEPROM_READ_DATA, &data );
		for ( j=1; j<=(i&3); j++ ) {
			buf[i-j] = data;
			data >>= 8;
		}
	}

	DBGP_HDA ( addr - len, _buf, len );
	return 0;
}

/*
 * Write a buffer into nonvolatile storage.
 *
 * @v nvs	The NonVolatile Storage device to be written.
 * @v address   The NonVolatile Storage address to be written.
 * @v _buf	Pointer to the data to be written.
 * @v len	Length of the buffer to be written.
 * @ret rc	0 on success, else nonzero.
 */
static int myri10ge_nvs_write ( struct nvs_device *nvs,
				unsigned int addr,
				const void *_buf,
				size_t len )
{
	struct myri10ge_private *priv =
		container_of (nvs, struct myri10ge_private, nvs);
	struct pci_device *pci = myri10ge_pcidev ( myri10ge_netdev ( priv ) );
	unsigned int vs = priv->pci_cap_vs;
	const unsigned char *buf = (const unsigned char *)_buf;
	unsigned int i;
	uint8 verify;

	DBGP ( "nvs_write " );
	DBGP_HDA ( addr, _buf, len );

	/* Start erase of the NonVolatile Options block. */

	DBGP ( "erasing " );
	pci_write_config_dword ( pci, VS_EEPROM_WRITE, ( addr << 8 ) | 0xff );

	/* Wait for erase to complete. */

	DBGP ( "waiting " );
	pci_read_config_byte ( pci, VS_EEPROM_READ_DATA, &verify );
	while ( verify != 0xff ) {
		pci_write_config_byte ( pci, VS_EEPROM_READ_ADDR + 1, addr );
		pci_read_config_byte ( pci, VS_EEPROM_READ_DATA, &verify );
	}

	/* Write the data one byte at a time. */

	DBGP ( "writing " );
	pci_write_config_byte ( pci, VS_MODE, VS_MODE_EEPROM_STREAM_WRITE );
	pci_write_config_dword ( pci, VS_ADDR, addr );
	for (i=0; i<len; i++, addr++)
		pci_write_config_byte ( pci, VS_DATA, buf[i] );
	pci_write_config_dword ( pci, VS_ADDR, 0xffffffff );
	pci_write_config_byte ( pci, VS_MODE, 0 );

	DBGP ( "done\n" );
	return 0;
}

/*
 * Initialize NonVolatile storage support for a device.
 *
 * @v priv	Device private data for the device.
 * @ret rc	0 on success, else an error code.
 */

static int myri10ge_nv_init ( struct myri10ge_private *priv )
{
	int rc;
	struct myri10ge_eeprom_header
	{
		uint8 __jump[8];
		uint32 eeprom_len;
		uint32 eeprom_segment_len;
		uint32 mcp1_offset;
		uint32 mcp2_offset;
		uint32 version;
	} hdr;
	uint32 mcp2_len;
	unsigned int nvo_fragment_pos;

	DBGP ( "myri10ge_nv_init\n" );

	/* Read the EEPROM header, and byteswap the fields we will use.
	   This is safe even though priv->nvs is not yet initialized. */

	rc = myri10ge_nvs_read ( &priv->nvs, 0, &hdr, sizeof ( hdr ) );
	if ( rc ) {
		DBG ( "EEPROM header unreadable\n" );
		return rc;
	}
	hdr.eeprom_len	       = ntohl ( hdr.eeprom_len );
	hdr.eeprom_segment_len = ntohl ( hdr.eeprom_segment_len );
	hdr.mcp2_offset	       = ntohl ( hdr.mcp2_offset );
	hdr.version	       = ntohl ( hdr.version );
	DBG2 ( "eelen:%xh seglen:%xh mcp2@%xh ver%d\n", hdr.eeprom_len,
	       hdr.eeprom_segment_len, hdr.mcp2_offset, hdr.version );

	/* If the firmware does not support EEPROM writes, simply return. */

	if ( hdr.version < 1 ) {
		DBG ( "No EEPROM write support\n" );
		return 0;
	}

	/* Read the length of MCP2. */

	rc = myri10ge_nvs_read ( &priv->nvs, hdr.mcp2_offset, &mcp2_len, 4 );
	mcp2_len = ntohl ( mcp2_len );
	DBG2 ( "mcp2len:%xh\n", mcp2_len );

	/* Determine the position of the NonVolatile Options fragment and
	   simply return if it overlaps other data. */

	nvo_fragment_pos = hdr.eeprom_len -  hdr.eeprom_segment_len;
	if ( hdr.mcp2_offset + mcp2_len > nvo_fragment_pos ) {
		DBG ( "EEPROM full\n" );
		return 0;
	}

	/* Initialize NonVolatile Storage state. */

	priv->nvs.word_len_log2 = 0;
	priv->nvs.size		= hdr.eeprom_len;
	priv->nvs.block_size	= hdr.eeprom_segment_len;
	priv->nvs.read		= myri10ge_nvs_read;
	priv->nvs.write		= myri10ge_nvs_write;

	/* Register the NonVolatile Options storage. */

	nvo_init ( &priv->nvo,
		   &priv->nvs,
		   nvo_fragment_pos, 0x200,
		   NULL,
		   & myri10ge_netdev (priv) -> refcnt );
	rc = register_nvo ( &priv->nvo,
			    netdev_settings ( myri10ge_netdev ( priv ) ) );
	if ( rc ) {
		DBG ("register_nvo failed");
		return rc;
	}

	priv->nvo_registered = 1;
	DBG2 ( "NVO supported\n" );
	return 0;
}

void
myri10ge_nv_fini ( struct myri10ge_private *priv )
{
	/* Simply return if nonvolatile access is not supported. */

	if ( 0 == priv->nvo_registered )
		return;

	unregister_nvo ( &priv->nvo );
}

/****************************************************************
 * iPXE PCI Device Driver API functions
 ****************************************************************/

/*
 * Initialize the PCI device.
 *
 * @v pci 		The device's associated pci_device structure.
 * @v id  		The PCI device + vendor id.
 * @ret rc		Returns zero if successfully initialized.
 *
 * This function is called very early on, while iPXE is initializing.
 * This is a iPXE PCI Device Driver API function.
 */
static int myri10ge_pci_probe ( struct pci_device *pci )
{
	static struct net_device_operations myri10ge_operations = {
		.open     = myri10ge_net_open,
		.close    = myri10ge_net_close,
		.transmit = myri10ge_net_transmit,
		.poll     = myri10ge_net_poll,
		.irq      = myri10ge_net_irq
	};

	const char *dbg;
	int rc;
	struct net_device *netdev;
	struct myri10ge_private *priv;

	DBGP ( "myri10ge_pci_probe: " );

	netdev = alloc_etherdev ( sizeof ( *priv ) );
	if ( !netdev ) {
		rc = -ENOMEM;
		dbg = "alloc_etherdev";
		goto abort_with_nothing;
	}

	netdev_init ( netdev, &myri10ge_operations );
	priv = myri10ge_priv ( netdev );

	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;

	/* Make sure interrupts are disabled. */

	myri10ge_net_irq ( netdev, 0 );

	/* Find the PCI Vendor-Specific capability. */

	priv->pci_cap_vs = pci_find_capability ( pci , PCI_CAP_ID_VNDR );
	if ( 0 == priv->pci_cap_vs ) {
		rc = -ENOTSUP;
		dbg = "no_vs";
		goto abort_with_netdev_init;
	}

	/* Read the NIC HW address. */

	rc = mac_address_from_string_specs ( pci,
					     priv->pci_cap_vs,
					     netdev->hw_addr );
	if ( rc ) {
		dbg = "mac_from_ss";
		goto abort_with_netdev_init;
	}
	DBGP ( "mac " );

	/* Enable bus master, etc. */

	adjust_pci_device ( pci );
	DBGP ( "pci " );

	/* Register the initialized network device. */

	rc = register_netdev ( netdev );
	if ( rc ) {
		dbg = "register_netdev";
		goto abort_with_netdev_init;
	}

	/* Initialize NonVolatile Storage support. */

	rc = myri10ge_nv_init ( priv );
	if ( rc ) {
		dbg = "myri10ge_nv_init";
		goto abort_with_registered_netdev;
	}

	DBGP ( "done\n" );

	return 0;

abort_with_registered_netdev:
	unregister_netdev ( netdev );
abort_with_netdev_init:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
abort_with_nothing:
	DBG ( "%s:%s\n", dbg, strerror ( rc ) );
	return rc;
}

/*
 * Remove a device from the PCI device list.
 *
 * @v pci		PCI device to remove.
 *
 * This is a PCI Device Driver API function.
 */
static void myri10ge_pci_remove ( struct pci_device *pci )
{
	struct net_device	*netdev;

	DBGP ( "myri10ge_pci_remove\n" );
	netdev = pci_get_drvdata ( pci );

	myri10ge_nv_fini ( myri10ge_priv ( netdev ) );
	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/****************************************************************
 * iPXE Network Device Driver Operations
 ****************************************************************/

/*
 * Close a network device.
 *
 * @v netdev		Device to close.
 *
 * This is a iPXE Network Device Driver API function.
 */
static void myri10ge_net_close ( struct net_device *netdev )
{
	struct myri10ge_private *priv;
	uint32			 data[3];

	DBGP ( "myri10ge_net_close\n" );
	priv = myri10ge_priv ( netdev );

	/* disable interrupts */

	myri10ge_net_irq ( netdev, 0 );

	/* Reset the NIC interface, so we won't get any more events from
	   the NIC. */

	myri10ge_command ( priv, MXGEFW_CMD_RESET, data );

	/* Free receive buffers that were never filled. */

	while ( priv->receives_done != priv->receives_posted ) {
		free_iob ( priv->receive_iob[priv->receives_done
					     & MYRI10GE_RECEIVE_WRAP] );
		++priv->receives_done;
	}

	/* Release DMAable memory. */

	free_dma ( priv->dma, sizeof ( *priv->dma ) );

	/* Erase all state from the open. */

	memset ( priv, 0, sizeof ( *priv ) );

	DBG2_RINGS ( priv );
}

/*
 * Enable or disable IRQ masking.
 *
 * @v netdev		Device to control.
 * @v enable		Zero to mask off IRQ, non-zero to enable IRQ.
 *
 * This is a iPXE Network Driver API function.
 */
static void myri10ge_net_irq ( struct net_device *netdev, int enable )
{
	struct pci_device	*pci_dev;
	uint16			 val;

	DBGP ( "myri10ge_net_irq\n" );
	pci_dev = ( struct pci_device * ) netdev->dev;

	/* Adjust the Interrupt Disable bit in the Command register of the
	   PCI Device. */

	pci_read_config_word ( pci_dev, PCI_COMMAND, &val );
	if ( enable )
		val &= ~PCI_COMMAND_INTX_DISABLE;
	else
		val |= PCI_COMMAND_INTX_DISABLE;
	pci_write_config_word ( pci_dev, PCI_COMMAND, val );
}

/*
 * Opens a network device.
 *
 * @v netdev		Device to be opened.
 * @ret rc  		Non-zero if failed to open.
 *
 * This enables tx and rx on the device.
 * This is a iPXE Network Device Driver API function.
 */
static int myri10ge_net_open ( struct net_device *netdev )
{
	const char		*dbg;	/* printed upon error return */
	int			 rc;
	struct io_buffer	*iob;
	struct myri10ge_private *priv;
	uint32			 data[3];
	struct pci_device	*pci_dev;
	void			*membase;

	DBGP ( "myri10ge_net_open\n" );
	priv	= myri10ge_priv ( netdev );
	pci_dev = ( struct pci_device * ) netdev->dev;
	membase = phys_to_virt ( pci_dev->membase );

	/* Compute address for passing commands to the firmware. */

	priv->command = membase + MXGEFW_ETH_CMD;

	/* Ensure interrupts are disabled. */

	myri10ge_net_irq ( netdev, 0 );

	/* Allocate cleared DMAable buffers. */

	priv->dma = malloc_dma ( sizeof ( *priv->dma ) , 128 );
	if ( !priv->dma ) {
		rc = -ENOMEM;
		dbg = "DMA";
		goto abort_with_nothing;
	}
	memset ( priv->dma, 0, sizeof ( *priv->dma ) );

	/* Simplify following code. */

#define TRY( prefix, base, suffix ) do {		\
		rc = myri10ge_command ( priv,		\
					MXGEFW_		\
					## prefix	\
					## base		\
					## suffix,	\
					data );		\
		if ( rc ) {				\
			dbg = #base;			\
			goto abort_with_dma;		\
		}					\
	} while ( 0 )

	/* Send a reset command to the card to see if it is alive,
	   and to reset its queue state. */

	TRY ( CMD_, RESET , );

	/* Set the interrupt queue size. */

	data[0] = ( (uint32_t)( sizeof ( priv->dma->receive_completion ) )
		    | MXGEFW_CMD_SET_INTRQ_SIZE_FLAG_NO_STRICT_SIZE_CHECK );
	TRY ( CMD_SET_ , INTRQ_SIZE , );

	/* Set the interrupt queue DMA address. */

	data[0] = virt_to_bus ( &priv->dma->receive_completion );
	data[1] = 0;
	TRY ( CMD_SET_, INTRQ_DMA, );

	/* Get the NIC interrupt claim address. */

	TRY ( CMD_GET_, IRQ_ACK, _OFFSET );
	priv->irq_claim = membase + data[0];

	/* Get the NIC interrupt assert address. */

	TRY ( CMD_GET_, IRQ_DEASSERT, _OFFSET );
	priv->irq_deassert = membase + data[0];

	/* Disable interrupt coalescing, which is inappropriate for the
	   minimal buffering we provide. */

	TRY ( CMD_GET_, INTR_COAL, _DELAY_OFFSET );
	* ( ( uint32 * ) ( membase + data[0] ) ) = 0;

	/* Set the NIC mac address. */

	data[0] = ( netdev->ll_addr[0] << 24
		    | netdev->ll_addr[1] << 16
		    | netdev->ll_addr[2] << 8
		    | netdev->ll_addr[3] );
	data[1] = ( ( netdev->ll_addr[4] << 8 )
		     | netdev->ll_addr[5] );
	TRY ( SET_ , MAC_ADDRESS , );

	/* Enable multicast receives, because some iPXE clients don't work
	   without multicast. . */

	TRY ( ENABLE_ , ALLMULTI , );

	/* Disable Ethernet flow control, so the NIC cannot deadlock the
	   network under any circumstances. */

	TRY ( DISABLE_ , FLOW , _CONTROL );

	/* Compute transmit ring sizes. */

	data[0] = 0;		/* slice 0 */
	TRY ( CMD_GET_, SEND_RING, _SIZE );
	priv->transmit_ring_wrap
		= data[0] / sizeof ( mcp_kreq_ether_send_t ) - 1;
	if ( priv->transmit_ring_wrap
	     & ( priv->transmit_ring_wrap + 1 ) ) {
		rc = -EPROTO;
		dbg = "TX_RING";
		goto abort_with_dma;
	}

	/* Compute receive ring sizes. */

	data[0] = 0;		/* slice 0 */
	TRY ( CMD_GET_ , RX_RING , _SIZE );
	priv->receive_post_ring_wrap = data[0] / sizeof ( mcp_dma_addr_t ) - 1;
	if ( priv->receive_post_ring_wrap
	     & ( priv->receive_post_ring_wrap + 1 ) ) {
		rc = -EPROTO;
		dbg = "RX_RING";
		goto abort_with_dma;
	}

	/* Get NIC transmit ring address. */

	data[0] = 0;		/* slice 0. */
	TRY ( CMD_GET_, SEND, _OFFSET );
	priv->transmit_ring = membase + data[0];

	/* Get the NIC receive ring address. */

	data[0] = 0;		/* slice 0. */
	TRY ( CMD_GET_, SMALL_RX, _OFFSET );
	priv->receive_post_ring = membase + data[0];

	/* Set the Nic MTU. */

	data[0] = ETH_FRAME_LEN;
	TRY ( CMD_SET_, MTU, );

	/* Tell the NIC our buffer sizes. ( We use only small buffers, so we
	   set both buffer sizes to the same value, which will force all
	   received frames to use small buffers. ) */

	data[0] = MXGEFW_PAD + ETH_FRAME_LEN;
	TRY ( CMD_SET_, SMALL_BUFFER, _SIZE );
	data[0] = MXGEFW_PAD + ETH_FRAME_LEN;
	TRY ( CMD_SET_, BIG_BUFFER, _SIZE );

        /* Tell firmware where to DMA IRQ data */

	data[0] = virt_to_bus ( &priv->dma->irq_data );
	data[1] = 0;
	data[2] = sizeof ( priv->dma->irq_data );
	TRY ( CMD_SET_, STATS_DMA_V2, );

	/* Post receives. */

	while ( priv->receives_posted <= MYRI10GE_RECEIVE_WRAP ) {

		/* Reserve 2 extra bytes at the start of packets, since
		   the firmware always skips the first 2 bytes of the buffer
		   so TCP headers will be aligned. */

		iob = alloc_iob ( MXGEFW_PAD + ETH_FRAME_LEN );
		if ( !iob ) {
			rc = -ENOMEM;
			dbg = "alloc_iob";
			goto abort_with_receives_posted;
		}
		iob_reserve ( iob, MXGEFW_PAD );
		myri10ge_post_receive ( priv, iob );
	}

	/* Bring up the link. */

	TRY ( CMD_, ETHERNET_UP, );

	DBG2_RINGS ( priv );
	return 0;

abort_with_receives_posted:
	while ( priv->receives_posted-- )
		free_iob ( priv->receive_iob[priv->receives_posted] );
abort_with_dma:
	/* Because the link is not up, we don't have to reset the NIC here. */
	free_dma ( priv->dma, sizeof ( *priv->dma ) );
abort_with_nothing:
	/* Erase all signs of the failed open. */
	memset ( priv, 0, sizeof ( *priv ) );
	DBG ( "%s: %s\n", dbg, strerror ( rc ) );
	return ( rc );
}

/*
 * This function allows a driver to process events during operation.
 *
 * @v netdev		Device being polled.
 *
 * This is called periodically by iPXE to let the driver check the status of
 * transmitted packets and to allow the driver to check for received packets.
 * This is a iPXE Network Device Driver API function.
 */
static void myri10ge_net_poll ( struct net_device *netdev )
{
	struct io_buffer		*iob;
	struct io_buffer		*replacement;
	struct myri10ge_dma_buffers	*dma;
	struct myri10ge_private		*priv;
	unsigned int			 length;
	unsigned int			 orig_receives_posted;

	DBGP ( "myri10ge_net_poll\n" );
	priv = myri10ge_priv ( netdev );
	dma  = priv->dma;

	/* Process any pending interrupt. */

	myri10ge_interrupt_handler ( netdev );

	/* Pass up received frames, but limit ourselves to receives posted
	   before this function was called, so we cannot livelock if
	   receives are arriving faster than we process them. */

	orig_receives_posted = priv->receives_posted;
	while ( priv->receives_done != orig_receives_posted ) {

		/* Stop if there is no pending receive. */

		length = ntohs ( dma->receive_completion
				 [priv->receives_done
				  & MYRI10GE_RECEIVE_COMPLETION_WRAP]
				 .length );
		if ( length == 0 )
			break;

		/* Allocate a replacement buffer.  If none is available,
		   stop passing up packets until a buffer is available.

		   Reserve 2 extra bytes at the start of packets, since
		   the firmware always skips the first 2 bytes of the buffer
		   so TCP headers will be aligned. */

		replacement = alloc_iob ( MXGEFW_PAD + ETH_FRAME_LEN );
		if ( !replacement ) {
			DBG ( "NO RX BUF\n" );
			break;
		}
		iob_reserve ( replacement, MXGEFW_PAD );

		/* Pass up the received frame. */

		iob = priv->receive_iob[priv->receives_done
					& MYRI10GE_RECEIVE_WRAP];
		iob_put ( iob, length );
		netdev_rx ( netdev, iob );

		/* We have consumed the packet, so clear the receive
		   notification. */

		dma->receive_completion [priv->receives_done
					 & MYRI10GE_RECEIVE_COMPLETION_WRAP]
			.length = 0;
		wmb();

		/* Replace the passed-up I/O buffer. */

		myri10ge_post_receive ( priv, replacement );
		++priv->receives_done;
		DBG2_RINGS ( priv );
	}
}

/*
 * This transmits a packet.
 *
 * @v netdev		Device to transmit from.
 * @v iobuf 		Data to transmit.
 * @ret rc  		Non-zero if failed to transmit.
 *
 * This is a iPXE Network Driver API function.
 */
static int myri10ge_net_transmit ( struct net_device *netdev,
				   struct io_buffer *iobuf )
{
	mcp_kreq_ether_send_t	*kreq;
	size_t			 len;
	struct myri10ge_private *priv;
	uint32			 transmits_posted;

	DBGP ( "myri10ge_net_transmit\n" );
	priv = myri10ge_priv ( netdev );

	/* Confirm space in the send ring. */

	transmits_posted = priv->transmits_posted;
	if ( transmits_posted - priv->transmits_done
	     > MYRI10GE_TRANSMIT_WRAP ) {
		DBG ( "TX ring full\n" );
		return -ENOBUFS;
	}

	DBG2 ( "TX %p+%zd ", iobuf->data, iob_len ( iobuf ) );
	DBG2_HD ( iobuf->data, 14 );

	/* Record the packet being transmitted, so we can later report
	   send completion. */

	priv->transmit_iob[transmits_posted & MYRI10GE_TRANSMIT_WRAP] = iobuf;

	/* Copy and pad undersized frames, because the NIC does not pad,
	   and we would rather copy small frames than do a gather. */

	len = iob_len ( iobuf );
	if ( len < ETH_ZLEN ) {
		iob_pad ( iobuf, ETH_ZLEN );
		len = ETH_ZLEN;
	}

	/* Enqueue the packet by writing a descriptor to the NIC.
	   This is a bit tricky because the HW requires 32-bit writes,
	   but the structure has smaller fields. */

	kreq = &priv->transmit_ring[transmits_posted
				    & priv->transmit_ring_wrap];
	kreq->addr_high = 0;
	kreq->addr_low = htonl ( virt_to_bus ( iobuf->data ) );
	( ( uint32 * ) kreq ) [2] = htonl (
		0x0000 << 16	 /* pseudo_header_offset */
		| ( len & 0xFFFF ) /* length */
		);
	wmb();
	( ( uint32 * ) kreq ) [3] = htonl (
		0x00 << 24	/* pad */
		| 0x01 << 16	/* rdma_count */
		| 0x00 << 8	/* cksum_offset */
		| ( MXGEFW_FLAGS_SMALL
		    | MXGEFW_FLAGS_FIRST
		    | MXGEFW_FLAGS_NO_TSO ) /* flags */
		);
	wmb();

	/* Mark the slot as consumed and return. */

	priv->transmits_posted = ++transmits_posted;
	DBG2_RINGS ( priv );
	return 0;
}

static struct pci_device_id myri10ge_nics[] = {
	/* Each of these macros must be a single line to satisfy a script. */
	PCI_ROM ( 0x14c1, 0x0008, "myri10ge", "Myricom 10Gb Ethernet Adapter", 0 ) ,
};

struct pci_driver myri10ge_driver __pci_driver = {
	.ids      = myri10ge_nics,
	.id_count = ( sizeof ( myri10ge_nics ) / sizeof ( myri10ge_nics[0] ) ) ,
	.probe    = myri10ge_pci_probe,
	.remove   = myri10ge_pci_remove
};

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
