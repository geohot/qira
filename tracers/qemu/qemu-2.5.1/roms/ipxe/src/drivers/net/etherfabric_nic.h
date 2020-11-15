/**************************************************************************
 *
 * Etherboot driver for Level 5 Etherfabric network cards
 *
 * Written by Michael Brown <mbrown@fensystems.co.uk>
 *
 * Copyright Fen Systems Ltd. 2005
 * Copyright Level 5 Networks Inc. 2005
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by
 * reference.  Drivers based on or derived from this code fall under
 * the GPL and must retain the authorship, copyright and license
 * notice.
 *
 **************************************************************************
 */

FILE_LICENCE ( GPL_ANY );

#ifndef EFAB_NIC_H
#define  EFAB_NIC_H
#include <ipxe/bitbash.h>
#include <ipxe/i2c.h>
#include <ipxe/spi.h>
#include <ipxe/nvo.h>
#include <ipxe/if_ether.h>
/**************************************************************************
 *
 * Constants and macros
 *
 **************************************************************************
 */
/* Board IDs. Early boards have no board_type, (e.g. EF1002 and 401/403)
 * But newer boards are getting bigger...
 */
typedef enum {
	EFAB_BOARD_INVALID = 0, /* Early boards do not have board rev. info. */
	EFAB_BOARD_SFE4001 = 1,
	EFAB_BOARD_SFE4002 = 2,
	EFAB_BOARD_SFE4003 = 3,
	/* Insert new types before here */
	EFAB_BOARD_MAX
} efab_board_type;

/* PHY types. */
typedef enum {
	PHY_TYPE_AUTO = 0, /* on development board detect between CX4 & alaska */
	PHY_TYPE_CX4_RTMR = 1,
	PHY_TYPE_1GIG_ALASKA = 2,
	PHY_TYPE_10XPRESS = 3,
	PHY_TYPE_XFP = 4,
	PHY_TYPE_CX4 = 5,
	PHY_TYPE_PM8358 = 6,
} phy_type_t;

/**************************************************************************
 *
 * Hardware data structures and sizing
 *
 **************************************************************************
 */

#define dma_addr_t unsigned long
typedef efab_qword_t falcon_rx_desc_t;
typedef efab_qword_t falcon_tx_desc_t;
typedef efab_qword_t falcon_event_t;

#define EFAB_BUF_ALIGN		4096
#define EFAB_RXD_SIZE		512
#define EFAB_TXD_SIZE		512
#define EFAB_EVQ_SIZE		512

#define EFAB_NUM_RX_DESC        16
#define EFAB_RX_BUF_SIZE	1600

/**************************************************************************
 *
 * Data structures
 *
 **************************************************************************
 */

struct efab_nic;

/* A buffer table allocation backing a tx dma, rx dma or eventq */
struct efab_special_buffer {
	dma_addr_t dma_addr;
	int id;
};

/* A TX queue */
struct efab_tx_queue {
	/* The hardware ring */
	falcon_tx_desc_t *ring;

	/* The software ring storing io_buffers. */
	struct io_buffer *buf[EFAB_TXD_SIZE];

	/* The buffer table reservation pushed to hardware */
	struct efab_special_buffer entry;

	/* Software descriptor write ptr */
	unsigned int write_ptr;

	/* Hardware descriptor read ptr */
	unsigned int read_ptr;
};

/* An RX queue */
struct efab_rx_queue {
	/* The hardware ring */
	falcon_rx_desc_t *ring;

	/* The software ring storing io_buffers */
	struct io_buffer *buf[EFAB_NUM_RX_DESC];

	/* The buffer table reservation pushed to hardware */
	struct efab_special_buffer entry;

	/* Descriptor write ptr, into both the hardware and software rings */
	unsigned int write_ptr;

	/* Hardware completion ptr */
	unsigned int read_ptr;
};

/* An event queue */
struct efab_ev_queue {
	/* The hardware ring to push to hardware.
	 * Must be the first entry in the structure */
	falcon_event_t *ring;

	/* The buffer table reservation pushed to hardware */
	struct efab_special_buffer entry;

	/* Pointers into the ring */
	unsigned int read_ptr;
};

struct efab_mac_operations {
	int ( * init ) ( struct efab_nic *efab );
};

struct efab_phy_operations {
	int ( * init ) ( struct efab_nic *efab );
	unsigned int mmds;
};

struct efab_board_operations {
	int ( * init ) ( struct efab_nic *efab );
	void ( * fini ) ( struct efab_nic *efab );
};

struct efab_nic {
	struct net_device *netdev;
	int pci_revision;
	int is_asic;

	/* I2C bit-bashed interface */
	struct i2c_bit_basher i2c_bb;

	/** SPI bus and devices, and the user visible NVO area */
	struct spi_bus spi_bus;
	struct spi_device spi_flash;
	struct spi_device spi_eeprom;
	struct spi_device *spi;
	struct nvo_block nvo;

	/** Board, MAC, and PHY operations tables */
	struct efab_board_operations *board_op;
	struct efab_mac_operations *mac_op;
	struct efab_phy_operations *phy_op;

	/* PHY and board types */
	int phy_addr;
	int phy_type;
	int phy_10g;
	int board_type;

	/** Memory and IO base */
	void *membase;
	unsigned int iobase;

	/* Buffer table allocation head */
	int buffer_head;

	/* Queues */
	struct efab_rx_queue rx_queue;
	struct efab_tx_queue tx_queue;
	struct efab_ev_queue ev_queue;

	/** MAC address */
	uint8_t mac_addr[ETH_ALEN];
	/** GMII link options */
	unsigned int link_options;
	/** Link status */
	int link_up;

	/** INT_REG_KER */
	efab_oword_t int_ker __attribute__ (( aligned ( 16 ) ));
};
#endif /* EFAB_NIC_H */

