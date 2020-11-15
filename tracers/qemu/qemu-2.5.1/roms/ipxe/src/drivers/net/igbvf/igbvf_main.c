/*******************************************************************************

  Intel(R) 82576 Virtual Function Linux driver
  Copyright(c) 2009 Intel Corporation.

  Copyright(c) 2010 Eric Keller <ekeller@princeton.edu>
  Copyright(c) 2010 Red Hat Inc.
	Alex Williamson <alex.williamson@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

FILE_LICENCE ( GPL2_ONLY );

#include "igbvf.h"

/**
 * igbvf_setup_tx_resources - allocate Tx resources (Descriptors)
 *
 * @v adapter   e1000 private structure
 *
 * @ret rc       Returns 0 on success, negative on failure
 **/
int igbvf_setup_tx_resources ( struct igbvf_adapter *adapter )
{
	DBG ( "igbvf_setup_tx_resources\n" );

	/* Allocate transmit descriptor ring memory.
	   It must not cross a 64K boundary because of hardware errata #23
	   so we use malloc_dma() requesting a 128 byte block that is
	   128 byte aligned. This should guarantee that the memory
	   allocated will not cross a 64K boundary, because 128 is an
	   even multiple of 65536 ( 65536 / 128 == 512 ), so all possible
	   allocations of 128 bytes on a 128 byte boundary will not
	   cross 64K bytes.
	 */

	adapter->tx_base =
		malloc_dma ( adapter->tx_ring_size, adapter->tx_ring_size );

	if ( ! adapter->tx_base ) {
		return -ENOMEM;
	}

	memset ( adapter->tx_base, 0, adapter->tx_ring_size );

	DBG ( "adapter->tx_base = %#08lx\n", virt_to_bus ( adapter->tx_base ) );

	return 0;
}

/**
 * igbvf_free_tx_resources - Free Tx Resources per Queue
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
void igbvf_free_tx_resources ( struct igbvf_adapter *adapter )
{
	DBG ( "igbvf_free_tx_resources\n" );

	free_dma ( adapter->tx_base, adapter->tx_ring_size );
}

/**
 * igbvf_free_rx_resources - Free Rx Resources
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
void igbvf_free_rx_resources ( struct igbvf_adapter *adapter )
{
	int i;

	DBG ( "igbvf_free_rx_resources\n" );

	free_dma ( adapter->rx_base, adapter->rx_ring_size );

	for ( i = 0; i < NUM_RX_DESC; i++ ) {
		free_iob ( adapter->rx_iobuf[i] );
	}
}

/**
 * igbvf_refill_rx_ring - allocate Rx io_buffers
 *
 * @v adapter   e1000 private structure
 *
 * @ret rc       Returns 0 on success, negative on failure
 **/
static int igbvf_refill_rx_ring ( struct igbvf_adapter *adapter )
{
	int i, rx_curr;
	int rc = 0;
	union e1000_adv_rx_desc *rx_curr_desc;
	struct e1000_hw *hw = &adapter->hw;
	struct io_buffer *iob;

	DBGP ("igbvf_refill_rx_ring\n");

	for ( i = 0; i < NUM_RX_DESC; i++ ) {
		rx_curr = ( ( adapter->rx_curr + i ) % NUM_RX_DESC );
		rx_curr_desc = adapter->rx_base + rx_curr;

		if ( rx_curr_desc->wb.upper.status_error & E1000_RXD_STAT_DD )
			continue;

		if ( adapter->rx_iobuf[rx_curr] != NULL )
			continue;

		DBG2 ( "Refilling rx desc %d\n", rx_curr );

		iob = alloc_iob ( MAXIMUM_ETHERNET_VLAN_SIZE );
		adapter->rx_iobuf[rx_curr] = iob;

		rx_curr_desc->wb.upper.status_error = 0;

		if ( ! iob ) {
			DBG ( "alloc_iob failed\n" );
			rc = -ENOMEM;
			break;
		} else {
			rx_curr_desc->read.pkt_addr = virt_to_bus ( iob->data );
			rx_curr_desc->read.hdr_addr = 0;
			ew32 ( RDT(0), rx_curr );
		}
	}
	return rc;
}

/**
 * igbvf_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static void igbvf_irq_disable ( struct igbvf_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;

	ew32 ( EIMC, ~0 );
}

/**
 * igbvf_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/
static void igbvf_irq_enable ( struct igbvf_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;

	ew32 ( EIAC, IMS_ENABLE_MASK );
	ew32 ( EIAM, IMS_ENABLE_MASK );
	ew32 ( EIMS, IMS_ENABLE_MASK );
}

/**
 * igbvf_irq - enable or Disable interrupts
 *
 * @v adapter   e1000 adapter
 * @v action    requested interrupt action
 **/
static void igbvf_irq ( struct net_device *netdev, int enable )
{
	struct igbvf_adapter *adapter = netdev_priv ( netdev );

	DBG ( "igbvf_irq\n" );

	if ( enable ) {
		igbvf_irq_enable ( adapter );
	} else {
		igbvf_irq_disable ( adapter );
	}
}

/**
 * igbvf_process_tx_packets - process transmitted packets
 *
 * @v netdev    network interface device structure
 **/
static void igbvf_process_tx_packets ( struct net_device *netdev )
{
	struct igbvf_adapter *adapter = netdev_priv ( netdev );
	uint32_t i;
	uint32_t tx_status;
	union e1000_adv_tx_desc *tx_curr_desc;

	/* Check status of transmitted packets
	 */
	DBGP ( "process_tx_packets: tx_head = %d, tx_tail = %d\n", adapter->tx_head,
	      adapter->tx_tail );

	while ( ( i = adapter->tx_head ) != adapter->tx_tail ) {

		tx_curr_desc = ( void * )  ( adapter->tx_base ) +
					   ( i * sizeof ( *adapter->tx_base ) );

		tx_status = tx_curr_desc->wb.status;
		DBG ( "  tx_curr_desc = %#08lx\n", virt_to_bus ( tx_curr_desc ) );
		DBG ( "  tx_status = %#08x\n", tx_status );

		/* if the packet at tx_head is not owned by hardware it is for us */
		if ( ! ( tx_status & E1000_TXD_STAT_DD ) )
			break;

		DBG ( "Sent packet. tx_head: %d tx_tail: %d tx_status: %#08x\n",
		      adapter->tx_head, adapter->tx_tail, tx_status );

		netdev_tx_complete ( netdev, adapter->tx_iobuf[i] );
		DBG ( "Success transmitting packet, tx_status: %#08x\n",
		      tx_status );

		/* Decrement count of used descriptors, clear this descriptor
		 */
		adapter->tx_fill_ctr--;
		memset ( tx_curr_desc, 0, sizeof ( *tx_curr_desc ) );

		adapter->tx_head = ( adapter->tx_head + 1 ) % NUM_TX_DESC;
	}
}

/**
 * igbvf_process_rx_packets - process received packets
 *
 * @v netdev    network interface device structure
 **/
static void igbvf_process_rx_packets ( struct net_device *netdev )
{
	struct igbvf_adapter *adapter = netdev_priv ( netdev );
	struct e1000_hw *hw = &adapter->hw;
	uint32_t i;
	uint32_t rx_status;
	uint32_t rx_len;
	uint32_t rx_err;
	union e1000_adv_rx_desc *rx_curr_desc;

	DBGP ( "igbvf_process_rx_packets\n" );

	/* Process received packets
	 */
	while ( 1 ) {
		i = adapter->rx_curr;

		rx_curr_desc = ( void * )  ( adapter->rx_base ) +
				  ( i * sizeof ( *adapter->rx_base ) );
		rx_status = rx_curr_desc->wb.upper.status_error;

		DBG2 ( "Before DD Check RX_status: %#08x, rx_curr: %d\n",
		       rx_status, i );

		if ( ! ( rx_status & E1000_RXD_STAT_DD ) )
			break;

		if ( adapter->rx_iobuf[i] == NULL )
			break;

		DBG ( "E1000_RCTL = %#08x\n", er32 (RCTL) );

		rx_len = rx_curr_desc->wb.upper.length;

		DBG ( "Received packet, rx_curr: %d  rx_status: %#08x  rx_len: %d\n",
		      i, rx_status, rx_len );

		rx_err = rx_status;

		iob_put ( adapter->rx_iobuf[i], rx_len );

		if ( rx_err & E1000_RXDEXT_ERR_FRAME_ERR_MASK ) {

			netdev_rx_err ( netdev, adapter->rx_iobuf[i], -EINVAL );
			DBG ( "igbvf_process_rx_packets: Corrupted packet received!"
			      " rx_err: %#08x\n", rx_err );
		} else  {
			/* Add this packet to the receive queue. */
			netdev_rx ( netdev, adapter->rx_iobuf[i] );
		}
		adapter->rx_iobuf[i] = NULL;

		memset ( rx_curr_desc, 0, sizeof ( *rx_curr_desc ) );

		adapter->rx_curr = ( adapter->rx_curr + 1 ) % NUM_RX_DESC;
	}
}

/**
 * igbvf_poll - Poll for received packets
 *
 * @v netdev    Network device
 */
static void igbvf_poll ( struct net_device *netdev )
{
	struct igbvf_adapter *adapter = netdev_priv ( netdev );
	uint32_t rx_status;
	union e1000_adv_rx_desc *rx_curr_desc;

	DBGP ( "igbvf_poll\n" );

	rx_curr_desc = ( void * )  ( adapter->rx_base ) +
			( adapter->rx_curr * sizeof ( *adapter->rx_base ) );
	rx_status = rx_curr_desc->wb.upper.status_error;

	if ( ! ( rx_status & E1000_RXD_STAT_DD ) )
		return;

	igbvf_process_tx_packets ( netdev );

	igbvf_process_rx_packets ( netdev );

	igbvf_refill_rx_ring ( adapter );
}

/**
 *  igbvf_config_collision_dist_generic - Configure collision distance
 *  @hw: pointer to the HW structure
 *
 *  Configures the collision distance to the default value and is used
 *  during link setup. Currently no func pointer exists and all
 *  implementations are handled in the generic version of this function.
 **/
void igbvf_config_collision_dist ( struct e1000_hw *hw )
{
	u32 tctl;

	DBG ("igbvf_config_collision_dist");

	tctl = er32 (TCTL);

	tctl &= ~E1000_TCTL_COLD;
	tctl |= E1000_COLLISION_DISTANCE << E1000_COLD_SHIFT;

	ew32 (TCTL, tctl);
	e1e_flush();
}

/**
 * igbvf_configure_tx - Configure Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void igbvf_configure_tx ( struct igbvf_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	u32 tctl, txdctl;

	DBG ( "igbvf_configure_tx\n" );

	/* disable transmits while setting up the descriptors */
	tctl = er32 ( TCTL );
	ew32 ( TCTL, tctl & ~E1000_TCTL_EN );
	e1e_flush();
	mdelay (10);

	ew32 ( TDBAH(0), 0 );
	ew32 ( TDBAL(0), virt_to_bus ( adapter->tx_base ) );
	ew32 ( TDLEN(0), adapter->tx_ring_size );

	DBG ( "E1000_TDBAL(0): %#08x\n",  er32 ( TDBAL(0) ) );
	DBG ( "E1000_TDLEN(0): %d\n",     er32 ( TDLEN(0) ) );

	/* Setup the HW Tx Head and Tail descriptor pointers */
	ew32 ( TDH(0), 0 );
	ew32 ( TDT(0), 0 );

	adapter->tx_head = 0;
	adapter->tx_tail = 0;
	adapter->tx_fill_ctr = 0;

	txdctl = er32(TXDCTL(0));
	txdctl |= E1000_TXDCTL_QUEUE_ENABLE;
	ew32 ( TXDCTL(0), txdctl );

	txdctl = er32 ( TXDCTL(0) );
	txdctl |= E1000_TXDCTL_QUEUE_ENABLE;
	ew32 ( TXDCTL(0), txdctl );

	/* Setup Transmit Descriptor Settings for eop descriptor */
	adapter->txd_cmd  = E1000_ADVTXD_DCMD_EOP | E1000_ADVTXD_DCMD_IFCS;

	/* Advanced descriptor */
	adapter->txd_cmd |= E1000_ADVTXD_DCMD_DEXT;

	/* (not part of cmd, but in same 32 bit word...) */
	adapter->txd_cmd |= E1000_ADVTXD_DTYP_DATA;

	/* enable Report Status bit */
	adapter->txd_cmd |= E1000_ADVTXD_DCMD_RS;

	/* Program the Transmit Control Register */
	tctl &= ~E1000_TCTL_CT;
	tctl |= E1000_TCTL_PSP | E1000_TCTL_RTLC |
		(E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT);

	igbvf_config_collision_dist ( hw );

	/* Enable transmits */
	tctl |= E1000_TCTL_EN;
	ew32(TCTL, tctl);
	e1e_flush();
}

/* igbvf_reset - bring the hardware into a known good state
 *
 * This function boots the hardware and enables some settings that
 * require a configuration cycle of the hardware - those cannot be
 * set/changed during runtime. After reset the device needs to be
 * properly configured for Rx, Tx etc.
 */
void igbvf_reset ( struct igbvf_adapter *adapter )
{
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct net_device *netdev = adapter->netdev;
	struct e1000_hw *hw = &adapter->hw;

	/* Allow time for pending master requests to run */
	if ( mac->ops.reset_hw(hw) )
		DBG ("PF still resetting\n");

	mac->ops.init_hw ( hw );

	if ( is_valid_ether_addr(adapter->hw.mac.addr) ) {
		memcpy ( netdev->hw_addr, adapter->hw.mac.addr, ETH_ALEN );
	}
}

extern void igbvf_init_function_pointers_vf(struct e1000_hw *hw);

/**
 * igbvf_sw_init - Initialize general software structures (struct igbvf_adapter)
 * @adapter: board private structure to initialize
 *
 * igbvf_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int __devinit igbvf_sw_init ( struct igbvf_adapter *adapter )
{
        struct e1000_hw *hw = &adapter->hw;
        struct pci_device *pdev = adapter->pdev;
        int rc;

        /* PCI config space info */

        hw->vendor_id = pdev->vendor;
        hw->device_id = pdev->device;

        pci_read_config_byte ( pdev, PCI_REVISION, &hw->revision_id );

        pci_read_config_word ( pdev, PCI_COMMAND, &hw->bus.pci_cmd_word );

        adapter->max_frame_size = MAXIMUM_ETHERNET_VLAN_SIZE + ETH_HLEN + ETH_FCS_LEN;
        adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;

	/* Set various function pointers */
        igbvf_init_function_pointers_vf ( &adapter->hw );

	rc = adapter->hw.mac.ops.init_params ( &adapter->hw );
	if (rc) {
                DBG ("hw.mac.ops.init_params(&adapter->hw) Failure\n");
		return rc;
        }

	rc = adapter->hw.mbx.ops.init_params ( &adapter->hw );
	if (rc) {
                DBG ("hw.mbx.ops.init_params(&adapter->hw) Failure\n");
		return rc;
        }

	/* Explicitly disable IRQ since the NIC can be in any state. */
	igbvf_irq_disable ( adapter );

	return 0;
}

/**
 * igbvf_setup_srrctl - configure the receive control registers
 * @adapter: Board private structure
 **/
static void igbvf_setup_srrctl ( struct igbvf_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	u32 srrctl = 0;

	DBG ( "igbvf_setup_srrctl\n" );

	srrctl &= ~(E1000_SRRCTL_DESCTYPE_MASK |
		    E1000_SRRCTL_BSIZEHDR_MASK |
		    E1000_SRRCTL_BSIZEPKT_MASK);

	/* Enable queue drop to avoid head of line blocking */
	srrctl |= E1000_SRRCTL_DROP_EN;

	/* Setup buffer sizes */
        srrctl |= 2048 >> E1000_SRRCTL_BSIZEPKT_SHIFT;
	srrctl |= E1000_SRRCTL_DESCTYPE_ADV_ONEBUF;

	ew32 ( SRRCTL(0), srrctl );
}

/**
 * igbvf_configure_rx - Configure 8254x Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void igbvf_configure_rx ( struct igbvf_adapter *adapter )
{
        struct e1000_hw *hw = &adapter->hw;
        u32 rxdctl;

	DBG ( "igbvf_configure_rx\n" );

        /* disable receives */
        rxdctl = er32 ( RXDCTL(0) );
        ew32 ( RXDCTL(0), rxdctl & ~E1000_RXDCTL_QUEUE_ENABLE );
        msleep ( 10 );

        /*
         * Setup the HW Rx Head and Tail Descriptor Pointers and
         * the Base and Length of the Rx Descriptor Ring
         */
        ew32 ( RDBAL(0), virt_to_bus (adapter->rx_base) );
        ew32 ( RDBAH(0), 0 );
        ew32 ( RDLEN(0), adapter->rx_ring_size );
	adapter->rx_curr = 0;
        ew32 ( RDH(0), 0 );
        ew32 ( RDT(0), 0 );

        rxdctl |= E1000_RXDCTL_QUEUE_ENABLE;
        rxdctl &= 0xFFF00000;
        rxdctl |= IGBVF_RX_PTHRESH;
        rxdctl |= IGBVF_RX_HTHRESH << 8;
        rxdctl |= IGBVF_RX_WTHRESH << 16;

        igbvf_rlpml_set_vf ( hw, adapter->max_frame_size );

        /* enable receives */
        ew32 ( RXDCTL(0), rxdctl );
        ew32 ( RDT(0), NUM_RX_DESC );
}

/**
 * igbvf_setup_rx_resources - allocate Rx resources (Descriptors)
 *
 * @v adapter   e1000 private structure
 **/
int igbvf_setup_rx_resources ( struct igbvf_adapter *adapter )
{
	int i;
	union e1000_adv_rx_desc *rx_curr_desc;
        struct io_buffer *iob;

	DBG ( "igbvf_setup_rx_resources\n" );

	/* Allocate receive descriptor ring memory.
	   It must not cross a 64K boundary because of hardware errata
	 */

	adapter->rx_base =
		malloc_dma ( adapter->rx_ring_size, adapter->rx_ring_size );

	if ( ! adapter->rx_base ) {
		return -ENOMEM;
	}
	memset ( adapter->rx_base, 0, adapter->rx_ring_size );

	for ( i = 0; i < NUM_RX_DESC; i++ ) {
                rx_curr_desc = adapter->rx_base + i;
                iob = alloc_iob ( MAXIMUM_ETHERNET_VLAN_SIZE );
                adapter->rx_iobuf[i] = iob;
                rx_curr_desc->wb.upper.status_error = 0;
                if ( ! iob ) {
                        DBG ( "alloc_iob failed\n" );
                        return -ENOMEM;
                } else {
                        rx_curr_desc->read.pkt_addr = virt_to_bus ( iob->data );
                        rx_curr_desc->read.hdr_addr = 0;
                }
	}

	return 0;
}

/**
 * igbvf_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog timer is started,
 * and the stack is notified that the interface is ready.
 **/
static int igbvf_open ( struct net_device *netdev )
{
	struct igbvf_adapter *adapter = netdev_priv ( netdev );
	int err;

	DBG ("igbvf_open\n");

	/* Update MAC address */
	memcpy ( adapter->hw.mac.addr, netdev->ll_addr, ETH_ALEN );
	igbvf_reset( adapter );

	/* allocate transmit descriptors */
	err = igbvf_setup_tx_resources ( adapter );
	if (err) {
		DBG ( "Error setting up TX resources!\n" );
		goto err_setup_tx;
	}

	igbvf_configure_tx ( adapter );

	igbvf_setup_srrctl( adapter );

	err = igbvf_setup_rx_resources( adapter );
	if (err) {
		DBG ( "Error setting up RX resources!\n" );
		goto err_setup_rx;
	}

	igbvf_configure_rx ( adapter );

	return 0;

err_setup_rx:
	DBG ( "err_setup_rx\n" );
	igbvf_free_tx_resources ( adapter );
	return err;

err_setup_tx:
	DBG ( "err_setup_tx\n" );
	igbvf_reset ( adapter );

	return err;
}

/**
 * igbvf_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
static void igbvf_close ( struct net_device *netdev )
{
	struct igbvf_adapter *adapter = netdev_priv ( netdev );
        struct e1000_hw *hw = &adapter->hw;
        uint32_t rxdctl;

        DBG ( "igbvf_close\n" );

	/* Disable and acknowledge interrupts */
        igbvf_irq_disable ( adapter );
        er32(EICR);

        /* disable receives */
        rxdctl = er32 ( RXDCTL(0) );
        ew32 ( RXDCTL(0), rxdctl & ~E1000_RXDCTL_QUEUE_ENABLE );
        mdelay ( 10 );

        igbvf_reset ( adapter );

	igbvf_free_tx_resources( adapter );
	igbvf_free_rx_resources( adapter );
}

/**
 * igbvf_transmit - Transmit a packet
 *
 * @v netdev    Network device
 * @v iobuf     I/O buffer
 *
 * @ret rc       Returns 0 on success, negative on failure
 */
static int igbvf_transmit ( struct net_device *netdev, struct io_buffer *iobuf )
{
	struct igbvf_adapter *adapter = netdev_priv ( netdev );
	struct e1000_hw *hw = &adapter->hw;
	uint32_t tx_curr = adapter->tx_tail;
	union e1000_adv_tx_desc *tx_curr_desc;

	DBGP ("igbvf_transmit\n");

	if ( adapter->tx_fill_ctr == NUM_TX_DESC ) {
		DBG ("TX overflow\n");
		return -ENOBUFS;
	}

	/* Save pointer to iobuf we have been given to transmit,
	   netdev_tx_complete() will need it later
	 */
	adapter->tx_iobuf[tx_curr] = iobuf;

	tx_curr_desc = ( void * ) ( adapter->tx_base ) +
		       ( tx_curr * sizeof ( *adapter->tx_base ) );

	DBG ( "tx_curr_desc = %#08lx\n", virt_to_bus ( tx_curr_desc ) );
	DBG ( "tx_curr_desc + 16 = %#08lx\n", virt_to_bus ( tx_curr_desc ) + 16 );
	DBG ( "iobuf->data = %#08lx\n", virt_to_bus ( iobuf->data ) );

	/* Add the packet to TX ring
	 */
	tx_curr_desc->read.buffer_addr = virt_to_bus ( iobuf->data );
	tx_curr_desc->read.cmd_type_len = adapter->txd_cmd |(iob_len ( iobuf )) ;
	// minus hdr_len ????
	tx_curr_desc->read.olinfo_status = ((iob_len ( iobuf )) << E1000_ADVTXD_PAYLEN_SHIFT);

	DBG ( "TX fill: %d tx_curr: %d addr: %#08lx len: %zd\n", adapter->tx_fill_ctr,
	      tx_curr, virt_to_bus ( iobuf->data ), iob_len ( iobuf ) );

	/* Point to next free descriptor */
	adapter->tx_tail = ( adapter->tx_tail + 1 ) % NUM_TX_DESC;
	adapter->tx_fill_ctr++;

	/* Write new tail to NIC, making packet available for transmit
	 */
	ew32 ( TDT(0), adapter->tx_tail );
	e1e_flush ();

	return 0;
}

/** igbvf net device operations */
static struct net_device_operations igbvf_operations = {
	.open		= igbvf_open,
	.close		= igbvf_close,
	.transmit	= igbvf_transmit,
	.poll		= igbvf_poll,
	.irq		= igbvf_irq,
};

/**
 * igbvf_get_hw_control - get control of the h/w from f/w
 * @adapter: address of board private structure
 *
 * igb_get_hw_control sets CTRL_EXT:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means that
 * the driver is loaded.
 *
 **/
void igbvf_get_hw_control ( struct igbvf_adapter *adapter )
{
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl_ext;

	/* Let firmware know the driver has taken over */
	ctrl_ext = er32 ( CTRL_EXT );
	ew32 ( CTRL_EXT, ctrl_ext | E1000_CTRL_EXT_DRV_LOAD );
}

/**
 * igbvf_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in igbvf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * igbvf_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
int igbvf_probe ( struct pci_device *pdev )
{
	int err;
	struct net_device *netdev;
	struct igbvf_adapter *adapter;
	unsigned long mmio_start, mmio_len;
	struct e1000_hw *hw;

        DBG ( "igbvf_probe\n" );

	err = -ENOMEM;

	/* Allocate net device ( also allocates memory for netdev->priv
	  and makes netdev-priv point to it ) */
	netdev = alloc_etherdev ( sizeof ( struct igbvf_adapter ) );
	if ( ! netdev )
		goto err_alloc_etherdev;

	/* Associate igbvf-specific network operations operations with
	 * generic network device layer */
	netdev_init ( netdev, &igbvf_operations );

	/* Associate this network device with given PCI device */
	pci_set_drvdata ( pdev, netdev );
	netdev->dev = &pdev->dev;

	/* Initialize driver private storage */
	adapter = netdev_priv ( netdev );
	memset ( adapter, 0, ( sizeof ( *adapter ) ) );

	adapter->pdev = pdev;

	adapter->ioaddr = pdev->ioaddr;
	adapter->hw.io_base = pdev->ioaddr;

	hw = &adapter->hw;
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;

	adapter->irqno = pdev->irq;
	adapter->netdev = netdev;
	adapter->hw.back = adapter;

	adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;
	adapter->max_hw_frame_size = ETH_FRAME_LEN + ETH_FCS_LEN;

	adapter->tx_ring_size = sizeof ( *adapter->tx_base ) * NUM_TX_DESC;
	adapter->rx_ring_size = sizeof ( *adapter->rx_base ) * NUM_RX_DESC;

	/* Fix up PCI device */
	adjust_pci_device ( pdev );

	err = -EIO;

	mmio_start = pci_bar_start ( pdev, PCI_BASE_ADDRESS_0 );
	mmio_len   = pci_bar_size  ( pdev, PCI_BASE_ADDRESS_0 );

	DBG ( "mmio_start: %#08lx\n", mmio_start );
	DBG ( "mmio_len: %#08lx\n", mmio_len );

	adapter->hw.hw_addr = ioremap ( mmio_start, mmio_len );
	DBG ( "adapter->hw.hw_addr: %p\n", adapter->hw.hw_addr );

	if ( ! adapter->hw.hw_addr ) {
		DBG ( "err_ioremap\n" );
		goto err_ioremap;
	}

	/* setup adapter struct */
	err = igbvf_sw_init ( adapter );
	if (err) {
		DBG ( "err_sw_init\n" );
		goto err_sw_init;
	}

	/* reset the controller to put the device in a known good state */
	err = hw->mac.ops.reset_hw ( hw );
	if ( err ) {
		DBG ("PF still in reset state, assigning new address\n");
		netdev->hw_addr[0] = 0x21;
		netdev->hw_addr[1] = 0x21;
		netdev->hw_addr[2] = 0x21;
		netdev->hw_addr[3] = 0x21;
		netdev->hw_addr[4] = 0x21;
		netdev->hw_addr[5] = 0x21;
		netdev->hw_addr[6] = 0x21;
	} else {
		err = hw->mac.ops.read_mac_addr(hw);
		if (err) {
			DBG ("Error reading MAC address\n");
			goto err_hw_init;
		}
		if ( ! is_valid_ether_addr(adapter->hw.mac.addr) ) {
			/* Assign random MAC address */
			eth_random_addr(adapter->hw.mac.addr);
		}
	}

	memcpy ( netdev->hw_addr, adapter->hw.mac.addr, ETH_ALEN );

	/* reset the hardware with the new settings */
	igbvf_reset ( adapter );

	/* let the f/w know that the h/w is now under the control of the
	 * driver. */
	igbvf_get_hw_control ( adapter );

	/* Mark as link up; we don't yet handle link state */
	netdev_link_up ( netdev );

	if ( ( err = register_netdev ( netdev ) ) != 0) {
		DBG ( "err_register\n" );
		goto err_register;
	}

	DBG ("igbvf_probe_succeeded\n");

	return 0;

err_register:
err_hw_init:
err_sw_init:
	iounmap ( adapter->hw.hw_addr );
err_ioremap:
	netdev_put ( netdev );
err_alloc_etherdev:
	return err;
}

/**
 * igbvf_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * igbvf_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
void igbvf_remove ( struct pci_device *pdev )
{
	struct net_device *netdev = pci_get_drvdata ( pdev );
	struct igbvf_adapter *adapter = netdev_priv ( netdev );

	DBG ( "igbvf_remove\n" );

	if ( adapter->hw.flash_address )
		iounmap ( adapter->hw.flash_address );
	if  ( adapter->hw.hw_addr )
		iounmap ( adapter->hw.hw_addr );

	unregister_netdev ( netdev );
	igbvf_reset  ( adapter );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

static struct pci_device_id igbvf_pci_tbl[] = {
	PCI_ROM(0x8086, 0x10CA, "igbvf", "E1000_DEV_ID_82576_VF", 0),
	PCI_ROM(0x8086, 0x1520, "i350vf", "E1000_DEV_ID_I350_VF", 0),
};


struct pci_driver igbvf_driver __pci_driver = {
	.ids = igbvf_pci_tbl,
	.id_count = (sizeof(igbvf_pci_tbl) / sizeof(igbvf_pci_tbl[0])),
	.probe = igbvf_probe,
	.remove = igbvf_remove,
};
