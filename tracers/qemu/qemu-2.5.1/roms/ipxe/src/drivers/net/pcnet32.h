/*
 * Copyright (c) 2010 Andrei Faur <da3drus@gmail.com>
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#ifndef _PCNET32_H_
#define _PCNET32_H_

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Set the number of Tx and Rx buffers, using Log_2(# buffers).
 * Set default values to 16 Tx buffers and 32 Rx buffers.
 */
#define PCNET32_LOG_TX_BUFFERS		4
#define PCNET32_LOG_RX_BUFFERS		5

/* Maximum number of descriptor rings is 512 */
#define PCNET32_LOG_MAX_TX_BUFFERS	9
#define PCNET32_LOG_MAX_RX_BUFFERS	9

#define TX_RING_SIZE		( 1 << ( PCNET32_LOG_TX_BUFFERS ) )
#define TX_MAX_RING_SIZE	( 1 << ( PCNET32_LOG_MAX_TX_BUFFERS ) )

#define RX_RING_SIZE		( 1 << ( PCNET32_LOG_RX_BUFFERS ) )
#define RX_MAX_RING_SIZE	( 1 << ( PCNET32_LOG_MAX_RX_BUFFERS ) )

#define RX_RING_BYTES		( RX_RING_SIZE * sizeof(struct pcnet32_rx_desc ) )
#define TX_RING_BYTES		( TX_RING_SIZE * sizeof(struct pcnet32_tx_desc ) )

#define PKT_BUF_SIZE	1536

#define RX_RING_ALIGN		16
#define TX_RING_ALIGN		16

#define INIT_BLOCK_ALIGN	32

#define PCNET32_WIO_RDP		0x10
#define PCNET32_WIO_RAP		0x12
#define PCNET32_WIO_RESET	0x14
#define PCNET32_WIO_BDP		0x16

#define PCNET32_DWIO_RDP	0x10
#define PCNET32_DWIO_RAP	0x14
#define PCNET32_DWIO_RESET	0x18
#define PCNET32_DWIO_BDP	0x1C

#define PCNET32_PORT_AUI	0x00
#define PCNET32_PORT_10BT	0x01
#define PCNET32_PORT_GPSI	0x02
#define PCNET32_PORT_MII	0x03

#define PCNET32_PORT_PORTSEL	0x03
#define PCNET32_PORT_ASEL	0x04
#define PCNET32_PORT_100	0x40
#define PCNET32_PORT_FD		0x80

#define PCNET32_SWSTYLE_LANCE	0x00
#define PCNET32_SWSTYLE_ILACC	0x01
#define PCNET32_SWSTYLE_PCNET32	0x02

#define PCNET32_MAX_PHYS	32

#ifndef PCI_VENDOR_ID_AT
#define PCI_VENDOR_ID_AT	0x1259
#endif

#ifndef PCI_SUBDEVICE_ID_AT_2700FX
#define PCI_SUBDEVICE_ID_AT_2700FX	0x2701
#endif

#ifndef PCI_SUBDEVICE_ID_AT_2701FX
#define PCI_SUBDEVICE_ID_AT_2701FX	0x2703
#endif

struct pcnet32_rx_desc {
	u32 base;
	s16 buf_length;
	s16 status;
	u32 msg_length;
	u32 reserved;
};

struct pcnet32_tx_desc {
	u32 base;
	s16 length;
	s16 status;
	u32 misc;
	u32 reserved;
};

struct pcnet32_init_block {
	u16 mode;
	u16 tlen_rlen;
	u8 phys_addr[6];
	u16 reserved;
	u32 filter[2];
	u32 rx_ring;
	u32 tx_ring;
};

struct pcnet32_access {
	u16 ( *read_csr ) ( unsigned long, int );
	void ( *write_csr ) ( unsigned long, int, u16 );
	u16 ( *read_bcr ) ( unsigned long, int );
	void ( *write_bcr ) ( unsigned long, int, u16 );
	u16 ( *read_rap ) ( unsigned long );
	void ( *write_rap ) ( unsigned long, u16 );
	void ( *reset ) ( unsigned long );
};

struct pcnet32_private {
	struct pcnet32_init_block init_block __attribute__((aligned(32)));
	struct pci_device *pci_dev;
	struct net_device *netdev;

	struct io_buffer *rx_iobuf[RX_RING_SIZE];
	struct io_buffer *tx_iobuf[TX_RING_SIZE];

	struct pcnet32_rx_desc *rx_base;
	struct pcnet32_tx_desc *tx_base;
	uint32_t rx_curr;
	uint32_t tx_curr;
	uint32_t tx_tail;
	uint32_t tx_fill_ctr;

	struct pcnet32_access *a;
	int options;
	unsigned int	mii:1,
			full_duplex:1;

	unsigned short chip_version;

	char irq_enabled;
};

enum pcnet32_desc_status_bit {
	DescOwn		= (1 << 15),
	StartOfPacket	= (1 << 9),
	EndOfPacket	= (1 << 8)
};

enum pcnet32_register_content {
	/* CSR0 bits - Controller status register */
	RxInt		= (1 << 10),
	TxInt		= (1 << 9),
	InitDone	= (1 << 8),
	IntFlag		= (1 << 7),
	IntEnable	= (1 << 6),
	TxDemand	= (1 << 3),
	Stop		= (1 << 2),
	Strt		= (1 << 1),
	Init		= (1 << 0),

	/* CSR3 bits - Controller status register */
	BablMask	= (1 << 14),
	MissFrameMask	= (1 << 12),
	MemErrMask	= (1 << 11),
	RxIntMask	= (1 << 10),
	TxIntMask	= (1 << 9),
	InitDoneMask	= (1 << 8)

};

#endif /* _PCNET32_H_ */
