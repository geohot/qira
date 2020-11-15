/*
 * Copyright(c) 2007 Atheros Corporation. All rights reserved.
 *
 * Derived from Intel e1000 driver
 * Copyright(c) 1999 - 2005 Intel Corporation. All rights reserved.
 *
 * Modified for iPXE, October 2009 by Joshua Oreman <oremanj@rwcr.net>.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include "atl1e.h"

/* User-tweakable parameters: */
#define TX_DESC_COUNT	32	/* TX descriptors, minimum 32 */
#define RX_MEM_SIZE	8192	/* RX area size, minimum 8kb */
#define MAX_FRAME_SIZE	1500	/* Maximum MTU supported, minimum 1500 */

/* Arcane parameters: */
#define PREAMBLE_LEN	7
#define RX_JUMBO_THRESH	((MAX_FRAME_SIZE + ETH_HLEN + \
			  VLAN_HLEN + ETH_FCS_LEN + 7) >> 3)
#define IMT_VAL		100	/* interrupt moderator timer, us */
#define ICT_VAL		50000	/* interrupt clear timer, us */
#define SMB_TIMER	200000
#define RRD_THRESH	1	/* packets to queue before interrupt */
#define TPD_BURST	5
#define TPD_THRESH	(TX_DESC_COUNT / 2)
#define RX_COUNT_DOWN	4
#define TX_COUNT_DOWN	(IMT_VAL * 4 / 3)
#define DMAR_DLY_CNT	15
#define DMAW_DLY_CNT	4

#define PCI_DEVICE_ID_ATTANSIC_L1E      0x1026

/*
 * atl1e_pci_tbl - PCI Device ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static struct pci_device_id atl1e_pci_tbl[] = {
	PCI_ROM(0x1969, 0x1026, "atl1e_26", "Attansic L1E 0x1026", 0),
	PCI_ROM(0x1969, 0x1066, "atl1e_66", "Attansic L1E 0x1066", 0),
};

static void atl1e_setup_mac_ctrl(struct atl1e_adapter *adapter);

static const u16
atl1e_rx_page_vld_regs[AT_PAGE_NUM_PER_QUEUE] =
{
	REG_HOST_RXF0_PAGE0_VLD, REG_HOST_RXF0_PAGE1_VLD
};

static const u16
atl1e_rx_page_lo_addr_regs[AT_PAGE_NUM_PER_QUEUE] =
{
	REG_HOST_RXF0_PAGE0_LO, REG_HOST_RXF0_PAGE1_LO
};

static const u16
atl1e_rx_page_write_offset_regs[AT_PAGE_NUM_PER_QUEUE] =
{
	REG_HOST_RXF0_MB0_LO,  REG_HOST_RXF0_MB1_LO
};

static const u16 atl1e_pay_load_size[] = {
	128, 256, 512, 1024, 2048, 4096,
};

/*
 * atl1e_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 */
static inline void atl1e_irq_enable(struct atl1e_adapter *adapter)
{
	AT_WRITE_REG(&adapter->hw, REG_ISR, 0);
	AT_WRITE_REG(&adapter->hw, REG_IMR, IMR_NORMAL_MASK);
	AT_WRITE_FLUSH(&adapter->hw);
}

/*
 * atl1e_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 */
static inline void atl1e_irq_disable(struct atl1e_adapter *adapter)
{
	AT_WRITE_REG(&adapter->hw, REG_IMR, 0);
	AT_WRITE_FLUSH(&adapter->hw);
}

/*
 * atl1e_irq_reset - reset interrupt confiure on the NIC
 * @adapter: board private structure
 */
static inline void atl1e_irq_reset(struct atl1e_adapter *adapter)
{
	AT_WRITE_REG(&adapter->hw, REG_ISR, 0);
	AT_WRITE_REG(&adapter->hw, REG_IMR, 0);
	AT_WRITE_FLUSH(&adapter->hw);
}

static void atl1e_reset(struct atl1e_adapter *adapter)
{
	atl1e_down(adapter);
	atl1e_up(adapter);
}

static int atl1e_check_link(struct atl1e_adapter *adapter)
{
	struct atl1e_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	int err = 0;
	u16 speed, duplex, phy_data;

	/* MII_BMSR must read twise */
	atl1e_read_phy_reg(hw, MII_BMSR, &phy_data);
	atl1e_read_phy_reg(hw, MII_BMSR, &phy_data);

	if ((phy_data & BMSR_LSTATUS) == 0) {
		/* link down */
		if (netdev_link_ok(netdev)) { /* old link state: Up */
			u32 value;
			/* disable rx */
			value = AT_READ_REG(hw, REG_MAC_CTRL);
			value &= ~MAC_CTRL_RX_EN;
			AT_WRITE_REG(hw, REG_MAC_CTRL, value);
			adapter->link_speed = SPEED_0;

			DBG("atl1e: %s link is down\n", netdev->name);
			netdev_link_down(netdev);
		}
	} else {
		/* Link Up */
		err = atl1e_get_speed_and_duplex(hw, &speed, &duplex);
		if (err)
			return err;

		/* link result is our setting */
		if (adapter->link_speed != speed ||
		    adapter->link_duplex != duplex) {
			adapter->link_speed  = speed;
			adapter->link_duplex = duplex;
			atl1e_setup_mac_ctrl(adapter);

			DBG("atl1e: %s link is up, %d Mbps, %s duplex\n",
			    netdev->name, adapter->link_speed,
			    adapter->link_duplex == FULL_DUPLEX ?
			    "full" : "half");
			netdev_link_up(netdev);
		}
	}
	return 0;
}

static int atl1e_mdio_read(struct net_device *netdev, int phy_id __unused,
			   int reg_num)
{
	struct atl1e_adapter *adapter = netdev_priv(netdev);
	u16 result;

	atl1e_read_phy_reg(&adapter->hw, reg_num & MDIO_REG_ADDR_MASK, &result);
	return result;
}

static void atl1e_mdio_write(struct net_device *netdev, int phy_id __unused,
			     int reg_num, int val)
{
	struct atl1e_adapter *adapter = netdev_priv(netdev);

	atl1e_write_phy_reg(&adapter->hw, reg_num & MDIO_REG_ADDR_MASK, val);
}

static void atl1e_setup_pcicmd(struct pci_device *pdev)
{
	u16 cmd;

	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	cmd |=  (PCI_COMMAND_MEM | PCI_COMMAND_MASTER);
	pci_write_config_word(pdev, PCI_COMMAND, cmd);

	/*
	 * some motherboards BIOS(PXE/EFI) driver may set PME
	 * while they transfer control to OS (Windows/Linux)
	 * so we should clear this bit before NIC work normally
	 */
	pci_write_config_dword(pdev, REG_PM_CTRLSTAT, 0);
	mdelay(1);
}

/*
 * atl1e_sw_init - Initialize general software structures (struct atl1e_adapter)
 * @adapter: board private structure to initialize
 *
 * atl1e_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 */
static int atl1e_sw_init(struct atl1e_adapter *adapter)
{
	struct atl1e_hw *hw = &adapter->hw;
	struct pci_device *pdev = adapter->pdev;
	u32 phy_status_data = 0;
	u8 rev_id = 0;

	adapter->link_speed = SPEED_0;   /* hardware init */
	adapter->link_duplex = FULL_DUPLEX;

	/* PCI config space info */
	pci_read_config_byte(pdev, PCI_REVISION, &rev_id);

	phy_status_data = AT_READ_REG(hw, REG_PHY_STATUS);
	/* nic type */
	if (rev_id >= 0xF0) {
		hw->nic_type = athr_l2e_revB;
	} else {
		if (phy_status_data & PHY_STATUS_100M)
			hw->nic_type = athr_l1e;
		else
			hw->nic_type = athr_l2e_revA;
	}

	phy_status_data = AT_READ_REG(hw, REG_PHY_STATUS);

	hw->emi_ca = !!(phy_status_data & PHY_STATUS_EMI_CA);

	hw->phy_configured = 0;

	/* need confirm */

	hw->dmar_block = atl1e_dma_req_1024;
	hw->dmaw_block = atl1e_dma_req_1024;

	return 0;
}

/*
 * atl1e_clean_tx_ring - free all Tx buffers for device close
 * @adapter: board private structure
 */
static void atl1e_clean_tx_ring(struct atl1e_adapter *adapter)
{
	struct atl1e_tx_ring *tx_ring = (struct atl1e_tx_ring *)
				&adapter->tx_ring;
	struct atl1e_tx_buffer *tx_buffer = NULL;
	u16 index, ring_count = tx_ring->count;

	if (tx_ring->desc == NULL || tx_ring->tx_buffer == NULL)
		return;

	for (index = 0; index < ring_count; index++) {
		tx_buffer = &tx_ring->tx_buffer[index];
		if (tx_buffer->iob) {
			netdev_tx_complete(adapter->netdev, tx_buffer->iob);
			tx_buffer->dma = 0;
			tx_buffer->iob = NULL;
		}
	}

	/* Zero out Tx-buffers */
	memset(tx_ring->desc, 0, sizeof(struct atl1e_tpd_desc) *
	       ring_count);
	memset(tx_ring->tx_buffer, 0, sizeof(struct atl1e_tx_buffer) *
	       ring_count);
}

/*
 * atl1e_clean_rx_ring - Free rx-reservation iobs
 * @adapter: board private structure
 */
static void atl1e_clean_rx_ring(struct atl1e_adapter *adapter)
{
	struct atl1e_rx_ring *rx_ring =
		(struct atl1e_rx_ring *)&adapter->rx_ring;
	struct atl1e_rx_page_desc *rx_page_desc = &rx_ring->rx_page_desc;
	u16 j;

	if (adapter->ring_vir_addr == NULL)
		return;

	/* Zero out the descriptor ring */
	for (j = 0; j < AT_PAGE_NUM_PER_QUEUE; j++) {
		if (rx_page_desc->rx_page[j].addr != NULL) {
			memset(rx_page_desc->rx_page[j].addr, 0,
			       rx_ring->real_page_size);
		}
	}
}

static void atl1e_cal_ring_size(struct atl1e_adapter *adapter, u32 *ring_size)
{
	*ring_size = ((u32)(adapter->tx_ring.count *
		     sizeof(struct atl1e_tpd_desc) + 7
			/* tx ring, qword align */
		     + adapter->rx_ring.real_page_size * AT_PAGE_NUM_PER_QUEUE
		     + 31
			/* rx ring,  32 bytes align */
		     + (1 + AT_PAGE_NUM_PER_QUEUE) *
			sizeof(u32) + 3));
			/* tx, rx cmd, dword align   */
}

static void atl1e_init_ring_resources(struct atl1e_adapter *adapter)
{
	struct atl1e_rx_ring *rx_ring = &adapter->rx_ring;

	rx_ring->real_page_size = adapter->rx_ring.page_size
				 + MAX_FRAME_SIZE
				 + ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN;
	rx_ring->real_page_size = (rx_ring->real_page_size + 31) & ~31;
	atl1e_cal_ring_size(adapter, &adapter->ring_size);

	adapter->ring_vir_addr = NULL;
	adapter->rx_ring.desc = NULL;

	return;
}

/*
 * Read / Write Ptr Initialize:
 */
static void atl1e_init_ring_ptrs(struct atl1e_adapter *adapter)
{
	struct atl1e_tx_ring *tx_ring = NULL;
	struct atl1e_rx_ring *rx_ring = NULL;
	struct atl1e_rx_page_desc *rx_page_desc = NULL;
	int j;

	tx_ring = &adapter->tx_ring;
	rx_ring = &adapter->rx_ring;
	rx_page_desc = &rx_ring->rx_page_desc;

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	rx_page_desc->rx_using  = 0;
	rx_page_desc->rx_nxseq = 0;
	for (j = 0; j < AT_PAGE_NUM_PER_QUEUE; j++) {
		*rx_page_desc->rx_page[j].write_offset_addr = 0;
		rx_page_desc->rx_page[j].read_offset = 0;
	}
}

/*
 * atl1e_free_ring_resources - Free Tx / RX descriptor Resources
 * @adapter: board private structure
 *
 * Free all transmit software resources
 */
static void atl1e_free_ring_resources(struct atl1e_adapter *adapter)
{
	atl1e_clean_tx_ring(adapter);
	atl1e_clean_rx_ring(adapter);

	if (adapter->ring_vir_addr) {
		free_dma(adapter->ring_vir_addr, adapter->ring_size);
		adapter->ring_vir_addr = NULL;
		adapter->ring_dma = 0;
	}

	if (adapter->tx_ring.tx_buffer) {
		free(adapter->tx_ring.tx_buffer);
		adapter->tx_ring.tx_buffer = NULL;
	}
}

/*
 * atl1e_setup_mem_resources - allocate Tx / RX descriptor resources
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 */
static int atl1e_setup_ring_resources(struct atl1e_adapter *adapter)
{
	struct atl1e_tx_ring *tx_ring;
	struct atl1e_rx_ring *rx_ring;
	struct atl1e_rx_page_desc  *rx_page_desc;
	int size, j;
	u32 offset = 0;
	int err = 0;

	if (adapter->ring_vir_addr != NULL)
		return 0; /* alloced already */

	tx_ring = &adapter->tx_ring;
	rx_ring = &adapter->rx_ring;

	/* real ring DMA buffer */

	size = adapter->ring_size;
	adapter->ring_vir_addr = malloc_dma(adapter->ring_size, 32);

	if (adapter->ring_vir_addr == NULL) {
		DBG("atl1e: out of memory allocating %d bytes for %s ring\n",
		    adapter->ring_size, adapter->netdev->name);
		return -ENOMEM;
	}

	adapter->ring_dma = virt_to_bus(adapter->ring_vir_addr);
	memset(adapter->ring_vir_addr, 0, adapter->ring_size);

	rx_page_desc = &rx_ring->rx_page_desc;

	/* Init TPD Ring */
	tx_ring->dma = (adapter->ring_dma + 7) & ~7;
	offset = tx_ring->dma - adapter->ring_dma;
	tx_ring->desc = (struct atl1e_tpd_desc *)
			(adapter->ring_vir_addr + offset);
	size = sizeof(struct atl1e_tx_buffer) * (tx_ring->count);
	tx_ring->tx_buffer = zalloc(size);
	if (tx_ring->tx_buffer == NULL) {
		DBG("atl1e: out of memory allocating %d bytes for %s txbuf\n",
		    size, adapter->netdev->name);
		err = -ENOMEM;
		goto failed;
	}

	/* Init RXF-Pages */
	offset += (sizeof(struct atl1e_tpd_desc) * tx_ring->count);
	offset = (offset + 31) & ~31;

	for (j = 0; j < AT_PAGE_NUM_PER_QUEUE; j++) {
		rx_page_desc->rx_page[j].dma =
			adapter->ring_dma + offset;
		rx_page_desc->rx_page[j].addr =
			adapter->ring_vir_addr + offset;
		offset += rx_ring->real_page_size;
	}

	/* Init CMB dma address */
	tx_ring->cmb_dma = adapter->ring_dma + offset;
	tx_ring->cmb     = (u32 *)(adapter->ring_vir_addr + offset);
	offset += sizeof(u32);

	for (j = 0; j < AT_PAGE_NUM_PER_QUEUE; j++) {
		rx_page_desc->rx_page[j].write_offset_dma =
			adapter->ring_dma + offset;
		rx_page_desc->rx_page[j].write_offset_addr =
			adapter->ring_vir_addr + offset;
		offset += sizeof(u32);
	}

	if (offset > adapter->ring_size) {
		DBG("atl1e: ring miscalculation! need %d > %d bytes\n",
		    offset, adapter->ring_size);
		err = -EINVAL;
		goto failed;
	}

	return 0;
failed:
	atl1e_free_ring_resources(adapter);
	return err;
}

static inline void atl1e_configure_des_ring(const struct atl1e_adapter *adapter)
{

	struct atl1e_hw *hw = (struct atl1e_hw *)&adapter->hw;
	struct atl1e_rx_ring *rx_ring =
			(struct atl1e_rx_ring *)&adapter->rx_ring;
	struct atl1e_tx_ring *tx_ring =
			(struct atl1e_tx_ring *)&adapter->tx_ring;
	struct atl1e_rx_page_desc *rx_page_desc = NULL;
	int j;

	AT_WRITE_REG(hw, REG_DESC_BASE_ADDR_HI, 0);
	AT_WRITE_REG(hw, REG_TPD_BASE_ADDR_LO, tx_ring->dma);
	AT_WRITE_REG(hw, REG_TPD_RING_SIZE, (u16)(tx_ring->count));
	AT_WRITE_REG(hw, REG_HOST_TX_CMB_LO, tx_ring->cmb_dma);

	rx_page_desc = &rx_ring->rx_page_desc;

	/* RXF Page Physical address / Page Length */
	AT_WRITE_REG(hw, REG_RXF0_BASE_ADDR_HI, 0);

	for (j = 0; j < AT_PAGE_NUM_PER_QUEUE; j++) {
		u32 page_phy_addr;
		u32 offset_phy_addr;

		page_phy_addr = rx_page_desc->rx_page[j].dma;
		offset_phy_addr = rx_page_desc->rx_page[j].write_offset_dma;

		AT_WRITE_REG(hw, atl1e_rx_page_lo_addr_regs[j], page_phy_addr);
		AT_WRITE_REG(hw, atl1e_rx_page_write_offset_regs[j],
			     offset_phy_addr);
		AT_WRITE_REGB(hw, atl1e_rx_page_vld_regs[j], 1);
	}

	/* Page Length */
	AT_WRITE_REG(hw, REG_HOST_RXFPAGE_SIZE, rx_ring->page_size);
	/* Load all of base address above */
	AT_WRITE_REG(hw, REG_LOAD_PTR, 1);

	return;
}

static inline void atl1e_configure_tx(struct atl1e_adapter *adapter)
{
	struct atl1e_hw *hw = (struct atl1e_hw *)&adapter->hw;
	u32 dev_ctrl_data = 0;
	u32 max_pay_load = 0;
	u32 jumbo_thresh = 0;
	u32 extra_size = 0;     /* Jumbo frame threshold in QWORD unit */

	/* configure TXQ param */
	if (hw->nic_type != athr_l2e_revB) {
		extra_size = ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN;
		jumbo_thresh = MAX_FRAME_SIZE + extra_size;
		AT_WRITE_REG(hw, REG_TX_EARLY_TH, (jumbo_thresh + 7) >> 3);
	}

	dev_ctrl_data = AT_READ_REG(hw, REG_DEVICE_CTRL);

	max_pay_load  = ((dev_ctrl_data >> DEVICE_CTRL_MAX_PAYLOAD_SHIFT)) &
			DEVICE_CTRL_MAX_PAYLOAD_MASK;
	if (max_pay_load < hw->dmaw_block)
		hw->dmaw_block = max_pay_load;

	max_pay_load  = ((dev_ctrl_data >> DEVICE_CTRL_MAX_RREQ_SZ_SHIFT)) &
			DEVICE_CTRL_MAX_RREQ_SZ_MASK;
	if (max_pay_load < hw->dmar_block)
		hw->dmar_block = max_pay_load;

	if (hw->nic_type != athr_l2e_revB)
		AT_WRITE_REGW(hw, REG_TXQ_CTRL + 2,
			      atl1e_pay_load_size[hw->dmar_block]);
	/* enable TXQ */
	AT_WRITE_REGW(hw, REG_TXQ_CTRL,
			((TPD_BURST & TXQ_CTRL_NUM_TPD_BURST_MASK)
			 << TXQ_CTRL_NUM_TPD_BURST_SHIFT)
			| TXQ_CTRL_ENH_MODE | TXQ_CTRL_EN);
	return;
}

static inline void atl1e_configure_rx(struct atl1e_adapter *adapter)
{
	struct atl1e_hw *hw = (struct atl1e_hw *)&adapter->hw;
	u32 rxf_len  = 0;
	u32 rxf_low  = 0;
	u32 rxf_high = 0;
	u32 rxf_thresh_data = 0;
	u32 rxq_ctrl_data = 0;

	if (hw->nic_type != athr_l2e_revB) {
		AT_WRITE_REGW(hw, REG_RXQ_JMBOSZ_RRDTIM,
			      (u16)((RX_JUMBO_THRESH & RXQ_JMBOSZ_TH_MASK) <<
			      RXQ_JMBOSZ_TH_SHIFT |
			      (1 & RXQ_JMBO_LKAH_MASK) <<
			      RXQ_JMBO_LKAH_SHIFT));

		rxf_len  = AT_READ_REG(hw, REG_SRAM_RXF_LEN);
		rxf_high = rxf_len * 4 / 5;
		rxf_low  = rxf_len / 5;
		rxf_thresh_data = ((rxf_high  & RXQ_RXF_PAUSE_TH_HI_MASK)
				  << RXQ_RXF_PAUSE_TH_HI_SHIFT) |
				  ((rxf_low & RXQ_RXF_PAUSE_TH_LO_MASK)
				  << RXQ_RXF_PAUSE_TH_LO_SHIFT);

		AT_WRITE_REG(hw, REG_RXQ_RXF_PAUSE_THRESH, rxf_thresh_data);
	}

	/* RRS */
	AT_WRITE_REG(hw, REG_IDT_TABLE, 0);
	AT_WRITE_REG(hw, REG_BASE_CPU_NUMBER, 0);

	rxq_ctrl_data |= RXQ_CTRL_PBA_ALIGN_32 |
			 RXQ_CTRL_CUT_THRU_EN | RXQ_CTRL_EN;

	AT_WRITE_REG(hw, REG_RXQ_CTRL, rxq_ctrl_data);
	return;
}

static inline void atl1e_configure_dma(struct atl1e_adapter *adapter)
{
	struct atl1e_hw *hw = &adapter->hw;
	u32 dma_ctrl_data = 0;

	dma_ctrl_data = DMA_CTRL_RXCMB_EN;
	dma_ctrl_data |= (((u32)hw->dmar_block) & DMA_CTRL_DMAR_BURST_LEN_MASK)
		<< DMA_CTRL_DMAR_BURST_LEN_SHIFT;
	dma_ctrl_data |= (((u32)hw->dmaw_block) & DMA_CTRL_DMAW_BURST_LEN_MASK)
		<< DMA_CTRL_DMAW_BURST_LEN_SHIFT;
	dma_ctrl_data |= DMA_CTRL_DMAR_REQ_PRI | DMA_CTRL_DMAR_OUT_ORDER;
	dma_ctrl_data |= (DMAR_DLY_CNT & DMA_CTRL_DMAR_DLY_CNT_MASK)
		<< DMA_CTRL_DMAR_DLY_CNT_SHIFT;
	dma_ctrl_data |= (DMAW_DLY_CNT & DMA_CTRL_DMAW_DLY_CNT_MASK)
		<< DMA_CTRL_DMAW_DLY_CNT_SHIFT;

	AT_WRITE_REG(hw, REG_DMA_CTRL, dma_ctrl_data);
	return;
}

static void atl1e_setup_mac_ctrl(struct atl1e_adapter *adapter)
{
	u32 value;
	struct atl1e_hw *hw = &adapter->hw;

	/* Config MAC CTRL Register */
	value = MAC_CTRL_TX_EN |
		MAC_CTRL_RX_EN ;

	if (FULL_DUPLEX == adapter->link_duplex)
		value |= MAC_CTRL_DUPLX;

	value |= ((u32)((SPEED_1000 == adapter->link_speed) ?
			  MAC_CTRL_SPEED_1000 : MAC_CTRL_SPEED_10_100) <<
			  MAC_CTRL_SPEED_SHIFT);
	value |= (MAC_CTRL_TX_FLOW | MAC_CTRL_RX_FLOW);

	value |= (MAC_CTRL_ADD_CRC | MAC_CTRL_PAD);
	value |= ((PREAMBLE_LEN & MAC_CTRL_PRMLEN_MASK) << MAC_CTRL_PRMLEN_SHIFT);

	value |= MAC_CTRL_BC_EN;
	value |= MAC_CTRL_MC_ALL_EN;

	AT_WRITE_REG(hw, REG_MAC_CTRL, value);
}

/*
 * atl1e_configure - Configure Transmit&Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx /Rx unit of the MAC after a reset.
 */
static int atl1e_configure(struct atl1e_adapter *adapter)
{
	struct atl1e_hw *hw = &adapter->hw;
	u32 intr_status_data = 0;

	/* clear interrupt status */
	AT_WRITE_REG(hw, REG_ISR, ~0);

	/* 1. set MAC Address */
	atl1e_hw_set_mac_addr(hw);

	/* 2. Init the Multicast HASH table (clear) */
	AT_WRITE_REG(hw, REG_RX_HASH_TABLE, 0);
	AT_WRITE_REG_ARRAY(hw, REG_RX_HASH_TABLE, 1, 0);

	/* 3. Clear any WOL status */
	AT_WRITE_REG(hw, REG_WOL_CTRL, 0);

	/* 4. Descripter Ring BaseMem/Length/Read ptr/Write ptr
	 *    TPD Ring/SMB/RXF0 Page CMBs, they use the same
	 *    High 32bits memory */
	atl1e_configure_des_ring(adapter);

	/* 5. set Interrupt Moderator Timer */
	AT_WRITE_REGW(hw, REG_IRQ_MODU_TIMER_INIT, IMT_VAL);
	AT_WRITE_REGW(hw, REG_IRQ_MODU_TIMER2_INIT, IMT_VAL);
	AT_WRITE_REG(hw, REG_MASTER_CTRL, MASTER_CTRL_LED_MODE |
			MASTER_CTRL_ITIMER_EN | MASTER_CTRL_ITIMER2_EN);

	/* 6. rx/tx threshold to trig interrupt */
	AT_WRITE_REGW(hw, REG_TRIG_RRD_THRESH, RRD_THRESH);
	AT_WRITE_REGW(hw, REG_TRIG_TPD_THRESH, TPD_THRESH);
	AT_WRITE_REGW(hw, REG_TRIG_RXTIMER, RX_COUNT_DOWN);
	AT_WRITE_REGW(hw, REG_TRIG_TXTIMER, TX_COUNT_DOWN);

	/* 7. set Interrupt Clear Timer */
	AT_WRITE_REGW(hw, REG_CMBDISDMA_TIMER, ICT_VAL);

	/* 8. set MTU */
	AT_WRITE_REG(hw, REG_MTU, MAX_FRAME_SIZE + ETH_HLEN +
			VLAN_HLEN + ETH_FCS_LEN);

	/* 9. config TXQ early tx threshold */
	atl1e_configure_tx(adapter);

	/* 10. config RXQ */
	atl1e_configure_rx(adapter);

	/* 11. config  DMA Engine */
	atl1e_configure_dma(adapter);

	/* 12. smb timer to trig interrupt */
	AT_WRITE_REG(hw, REG_SMB_STAT_TIMER, SMB_TIMER);

	intr_status_data = AT_READ_REG(hw, REG_ISR);
	if ((intr_status_data & ISR_PHY_LINKDOWN) != 0) {
		DBG("atl1e: configure failed, PCIE phy link down\n");
		return -1;
	}

	AT_WRITE_REG(hw, REG_ISR, 0x7fffffff);
	return 0;
}

static inline void atl1e_clear_phy_int(struct atl1e_adapter *adapter)
{
	u16 phy_data;

	atl1e_read_phy_reg(&adapter->hw, MII_INT_STATUS, &phy_data);
}

static int atl1e_clean_tx_irq(struct atl1e_adapter *adapter)
{
	struct atl1e_tx_ring *tx_ring = (struct atl1e_tx_ring *)
					&adapter->tx_ring;
	struct atl1e_tx_buffer *tx_buffer = NULL;
	u16 hw_next_to_clean = AT_READ_REGW(&adapter->hw, REG_TPD_CONS_IDX);
	u16 next_to_clean = tx_ring->next_to_clean;

	while (next_to_clean != hw_next_to_clean) {
		tx_buffer = &tx_ring->tx_buffer[next_to_clean];

		tx_buffer->dma = 0;
		if (tx_buffer->iob) {
			netdev_tx_complete(adapter->netdev, tx_buffer->iob);
			tx_buffer->iob = NULL;
		}

		if (++next_to_clean == tx_ring->count)
			next_to_clean = 0;
	}

	tx_ring->next_to_clean = next_to_clean;

	return 1;
}

static struct atl1e_rx_page *atl1e_get_rx_page(struct atl1e_adapter *adapter)
{
	struct atl1e_rx_page_desc *rx_page_desc =
		(struct atl1e_rx_page_desc *) &adapter->rx_ring.rx_page_desc;
	u8 rx_using = rx_page_desc->rx_using;

	return (struct atl1e_rx_page *)&(rx_page_desc->rx_page[rx_using]);
}

static void atl1e_clean_rx_irq(struct atl1e_adapter *adapter)
{
	struct net_device *netdev  = adapter->netdev;
	struct atl1e_rx_ring *rx_ring = (struct atl1e_rx_ring *)
					 &adapter->rx_ring;
	struct atl1e_rx_page_desc *rx_page_desc =
		(struct atl1e_rx_page_desc *) &rx_ring->rx_page_desc;
	struct io_buffer *iob = NULL;
	struct atl1e_rx_page *rx_page = atl1e_get_rx_page(adapter);
	u32 packet_size, write_offset;
	struct atl1e_recv_ret_status *prrs;

	write_offset = *(rx_page->write_offset_addr);
	if (rx_page->read_offset >= write_offset)
		return;

	do {
		/* get new packet's  rrs */
		prrs = (struct atl1e_recv_ret_status *) (rx_page->addr +
							 rx_page->read_offset);
		/* check sequence number */
		if (prrs->seq_num != rx_page_desc->rx_nxseq) {
			DBG("atl1e %s: RX sequence number error (%d != %d)\n",
			    netdev->name, prrs->seq_num,
			    rx_page_desc->rx_nxseq);
			rx_page_desc->rx_nxseq++;
			goto fatal_err;
		}

		rx_page_desc->rx_nxseq++;

		/* error packet */
		if (prrs->pkt_flag & RRS_IS_ERR_FRAME) {
			if (prrs->err_flag & (RRS_ERR_BAD_CRC |
					      RRS_ERR_DRIBBLE | RRS_ERR_CODE |
					      RRS_ERR_TRUNC)) {
				/* hardware error, discard this
				   packet */
				netdev_rx_err(netdev, NULL, EIO);
				goto skip_pkt;
			}
		}

		packet_size = ((prrs->word1 >> RRS_PKT_SIZE_SHIFT) &
			       RRS_PKT_SIZE_MASK) - ETH_FCS_LEN;
		iob = alloc_iob(packet_size + NET_IP_ALIGN);
		if (iob == NULL) {
			DBG("atl1e %s: dropping packet under memory pressure\n",
			    netdev->name);
			goto skip_pkt;
		}
		iob_reserve(iob, NET_IP_ALIGN);
		memcpy(iob->data, (u8 *)(prrs + 1), packet_size);
		iob_put(iob, packet_size);

		netdev_rx(netdev, iob);

skip_pkt:
		/* skip current packet whether it's ok or not. */
		rx_page->read_offset +=
			(((u32)((prrs->word1 >> RRS_PKT_SIZE_SHIFT) &
				RRS_PKT_SIZE_MASK) +
			  sizeof(struct atl1e_recv_ret_status) + 31) &
			 0xFFFFFFE0);

		if (rx_page->read_offset >= rx_ring->page_size) {
			/* mark this page clean */
			u16 reg_addr;
			u8  rx_using;

			rx_page->read_offset =
				*(rx_page->write_offset_addr) = 0;
			rx_using = rx_page_desc->rx_using;
			reg_addr =
				atl1e_rx_page_vld_regs[rx_using];
			AT_WRITE_REGB(&adapter->hw, reg_addr, 1);
			rx_page_desc->rx_using ^= 1;
			rx_page = atl1e_get_rx_page(adapter);
		}
		write_offset = *(rx_page->write_offset_addr);
	} while (rx_page->read_offset < write_offset);

	return;

fatal_err:
	if (!netdev_link_ok(adapter->netdev))
		atl1e_reset(adapter);
}

/*
 * atl1e_poll - poll for completed transmissions and received packets
 * @netdev: network device
 */
static void atl1e_poll(struct net_device *netdev)
{
	struct atl1e_adapter *adapter = netdev_priv(netdev);
	struct atl1e_hw *hw = &adapter->hw;
	int max_ints = 64;
	u32 status;

	do {
		status = AT_READ_REG(hw, REG_ISR);
		if ((status & IMR_NORMAL_MASK) == 0)
			break;

		/* link event */
		if (status & ISR_GPHY)
			atl1e_clear_phy_int(adapter);
		/* Ack ISR */
		AT_WRITE_REG(hw, REG_ISR, status | ISR_DIS_INT);

		/* check if PCIE PHY Link down */
		if (status & ISR_PHY_LINKDOWN) {
			DBG("atl1e: PCI-E PHY link down: %x\n", status);
			if (netdev_link_ok(adapter->netdev)) {
				/* reset MAC */
				atl1e_irq_reset(adapter);
				atl1e_reset(adapter);
				break;
			}
		}

		/* check if DMA read/write error */
		if (status & (ISR_DMAR_TO_RST | ISR_DMAW_TO_RST)) {
			DBG("atl1e: PCI-E DMA RW error: %x\n", status);
			atl1e_irq_reset(adapter);
			atl1e_reset(adapter);
			break;
		}

		/* link event */
		if (status & (ISR_GPHY | ISR_MANUAL)) {
			atl1e_check_link(adapter);
			break;
		}

		/* transmit event */
		if (status & ISR_TX_EVENT)
			atl1e_clean_tx_irq(adapter);

		if (status & ISR_RX_EVENT)
			atl1e_clean_rx_irq(adapter);
	} while (--max_ints > 0);

	/* re-enable Interrupt*/
	AT_WRITE_REG(&adapter->hw, REG_ISR, 0);

	return;
}

static inline u16 atl1e_tpd_avail(struct atl1e_adapter *adapter)
{
	struct atl1e_tx_ring *tx_ring = &adapter->tx_ring;
	u16 next_to_use = 0;
	u16 next_to_clean = 0;

	next_to_clean = tx_ring->next_to_clean;
	next_to_use   = tx_ring->next_to_use;

	return (u16)(next_to_clean > next_to_use) ?
		(next_to_clean - next_to_use - 1) :
		(tx_ring->count + next_to_clean - next_to_use - 1);
}

/*
 * get next usable tpd
 * Note: should call atl1e_tdp_avail to make sure
 * there is enough tpd to use
 */
static struct atl1e_tpd_desc *atl1e_get_tpd(struct atl1e_adapter *adapter)
{
	struct atl1e_tx_ring *tx_ring = &adapter->tx_ring;
	u16 next_to_use = 0;

	next_to_use = tx_ring->next_to_use;
	if (++tx_ring->next_to_use == tx_ring->count)
		tx_ring->next_to_use = 0;

	memset(&tx_ring->desc[next_to_use], 0, sizeof(struct atl1e_tpd_desc));
	return (struct atl1e_tpd_desc *)&tx_ring->desc[next_to_use];
}

static struct atl1e_tx_buffer *
atl1e_get_tx_buffer(struct atl1e_adapter *adapter, struct atl1e_tpd_desc *tpd)
{
	struct atl1e_tx_ring *tx_ring = &adapter->tx_ring;

	return &tx_ring->tx_buffer[tpd - tx_ring->desc];
}

static void atl1e_tx_map(struct atl1e_adapter *adapter,
		      struct io_buffer *iob, struct atl1e_tpd_desc *tpd)
{
	struct atl1e_tx_buffer *tx_buffer = NULL;
	u16 buf_len = iob_len(iob);

	tx_buffer = atl1e_get_tx_buffer(adapter, tpd);
	tx_buffer->iob = iob;
	tx_buffer->length = buf_len;
	tx_buffer->dma = virt_to_bus(iob->data);
	tpd->buffer_addr = cpu_to_le64(tx_buffer->dma);
	tpd->word2 = ((tpd->word2 & ~TPD_BUFLEN_MASK) |
		      ((cpu_to_le32(buf_len) & TPD_BUFLEN_MASK) <<
		       TPD_BUFLEN_SHIFT));
	tpd->word3 |= 1 << TPD_EOP_SHIFT;
}

static void atl1e_tx_queue(struct atl1e_adapter *adapter, u16 count __unused,
			   struct atl1e_tpd_desc *tpd __unused)
{
	struct atl1e_tx_ring *tx_ring = &adapter->tx_ring;
	wmb();
	AT_WRITE_REG(&adapter->hw, REG_MB_TPD_PROD_IDX, tx_ring->next_to_use);
}

static int atl1e_xmit_frame(struct net_device *netdev, struct io_buffer *iob)
{
	struct atl1e_adapter *adapter = netdev_priv(netdev);
	u16 tpd_req = 1;
	struct atl1e_tpd_desc *tpd;

	if (!netdev_link_ok(netdev)) {
		return -EINVAL;
	}

	if (atl1e_tpd_avail(adapter) < tpd_req) {
		return -EBUSY;
	}

	tpd = atl1e_get_tpd(adapter);

	atl1e_tx_map(adapter, iob, tpd);
	atl1e_tx_queue(adapter, tpd_req, tpd);

	return 0;
}

int atl1e_up(struct atl1e_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err = 0;
	u32 val;

	/* hardware has been reset, we need to reload some things */
	err = atl1e_init_hw(&adapter->hw);
	if (err) {
		return -EIO;
	}
	atl1e_init_ring_ptrs(adapter);

	memcpy(adapter->hw.mac_addr, netdev->ll_addr, ETH_ALEN);

	if (atl1e_configure(adapter) != 0) {
		return -EIO;
	}

	atl1e_irq_disable(adapter);

	val = AT_READ_REG(&adapter->hw, REG_MASTER_CTRL);
	AT_WRITE_REG(&adapter->hw, REG_MASTER_CTRL,
		      val | MASTER_CTRL_MANUAL_INT);

	return err;
}

void atl1e_irq(struct net_device *netdev, int enable)
{
	struct atl1e_adapter *adapter = netdev_priv(netdev);

	if (enable)
		atl1e_irq_enable(adapter);
	else
		atl1e_irq_disable(adapter);
}

void atl1e_down(struct atl1e_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	/* reset MAC to disable all RX/TX */
	atl1e_reset_hw(&adapter->hw);
	mdelay(1);

	netdev_link_down(netdev);
	adapter->link_speed = SPEED_0;
	adapter->link_duplex = -1;

	atl1e_clean_tx_ring(adapter);
	atl1e_clean_rx_ring(adapter);
}

/*
 * atl1e_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog timer is started,
 * and the stack is notified that the interface is ready.
 */
static int atl1e_open(struct net_device *netdev)
{
	struct atl1e_adapter *adapter = netdev_priv(netdev);
	int err;

	/* allocate rx/tx dma buffer & descriptors */
	atl1e_init_ring_resources(adapter);
	err = atl1e_setup_ring_resources(adapter);
	if (err)
		return err;

	err = atl1e_up(adapter);
	if (err)
		goto err_up;

	return 0;

err_up:
	atl1e_free_ring_resources(adapter);
	atl1e_reset_hw(&adapter->hw);

	return err;
}

/*
 * atl1e_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 */
static void atl1e_close(struct net_device *netdev)
{
	struct atl1e_adapter *adapter = netdev_priv(netdev);

	atl1e_down(adapter);
	atl1e_free_ring_resources(adapter);
}

static struct net_device_operations atl1e_netdev_ops = {
	.open		= atl1e_open,
	.close		= atl1e_close,
	.transmit	= atl1e_xmit_frame,
	.poll		= atl1e_poll,
	.irq		= atl1e_irq,
};

static void atl1e_init_netdev(struct net_device *netdev, struct pci_device *pdev)
{
	netdev_init(netdev, &atl1e_netdev_ops);

	netdev->dev = &pdev->dev;
	pci_set_drvdata(pdev, netdev);
}

/*
 * atl1e_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in atl1e_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * atl1e_probe initializes an adapter identified by a pci_device structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 */
static int atl1e_probe(struct pci_device *pdev)
{
	struct net_device *netdev;
	struct atl1e_adapter *adapter = NULL;
	static int cards_found;

	int err = 0;

	adjust_pci_device(pdev);

	netdev = alloc_etherdev(sizeof(struct atl1e_adapter));
	if (netdev == NULL) {
		err = -ENOMEM;
		DBG("atl1e: out of memory allocating net_device\n");
		goto err;
	}

	atl1e_init_netdev(netdev, pdev);

	adapter = netdev_priv(netdev);
	adapter->bd_number = cards_found;
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	adapter->hw.adapter = adapter;
	if (!pdev->membase) {
		err = -EIO;
		DBG("atl1e: cannot map device registers\n");
		goto err_free_netdev;
	}
	adapter->hw.hw_addr = bus_to_virt(pdev->membase);

	/* init mii data */
	adapter->mii.dev = netdev;
	adapter->mii.mdio_read  = atl1e_mdio_read;
	adapter->mii.mdio_write = atl1e_mdio_write;
	adapter->mii.phy_id_mask = 0x1f;
	adapter->mii.reg_num_mask = MDIO_REG_ADDR_MASK;

	/* get user settings */
	adapter->tx_ring.count = TX_DESC_COUNT;
	adapter->rx_ring.page_size = RX_MEM_SIZE;

	atl1e_setup_pcicmd(pdev);

	/* setup the private structure */
	err = atl1e_sw_init(adapter);
	if (err) {
		DBG("atl1e: private data init failed\n");
		goto err_free_netdev;
	}

	/* Init GPHY as early as possible due to power saving issue  */
	atl1e_phy_init(&adapter->hw);

	/* reset the controller to
	 * put the device in a known good starting state */
	err = atl1e_reset_hw(&adapter->hw);
	if (err) {
		err = -EIO;
		goto err_free_netdev;
	}

	/* This may have been run by a zero-wait timer around
	   now... unclear. */
	atl1e_restart_autoneg(&adapter->hw);

	if (atl1e_read_mac_addr(&adapter->hw) != 0) {
		DBG("atl1e: cannot read MAC address from EEPROM\n");
		err = -EIO;
		goto err_free_netdev;
	}

	memcpy(netdev->hw_addr, adapter->hw.perm_mac_addr, ETH_ALEN);
	memcpy(netdev->ll_addr, adapter->hw.mac_addr, ETH_ALEN);
	DBG("atl1e: Attansic L1E Ethernet controller on %s, "
	    "%02x:%02x:%02x:%02x:%02x:%02x\n", adapter->netdev->name,
	    adapter->hw.mac_addr[0], adapter->hw.mac_addr[1],
	    adapter->hw.mac_addr[2], adapter->hw.mac_addr[3],
	    adapter->hw.mac_addr[4], adapter->hw.mac_addr[5]);

	err = register_netdev(netdev);
	if (err) {
		DBG("atl1e: cannot register network device\n");
		goto err_free_netdev;
	}

	cards_found++;
	return 0;

err_free_netdev:
	netdev_nullify(netdev);
	netdev_put(netdev);
err:
	return err;
}

/*
 * atl1e_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * atl1e_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 */
static void atl1e_remove(struct pci_device *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct atl1e_adapter *adapter = netdev_priv(netdev);

	unregister_netdev(netdev);
	atl1e_free_ring_resources(adapter);
	atl1e_force_ps(&adapter->hw);
	netdev_nullify(netdev);
	netdev_put(netdev);
}

struct pci_driver atl1e_driver __pci_driver = {
	.ids      = atl1e_pci_tbl,
	.id_count = (sizeof(atl1e_pci_tbl) / sizeof(atl1e_pci_tbl[0])),
	.probe    = atl1e_probe,
	.remove   = atl1e_remove,
};

/********** Hardware-level functions: **********/

/*
 * check_eeprom_exist
 * return 0 if eeprom exist
 */
int atl1e_check_eeprom_exist(struct atl1e_hw *hw)
{
	u32 value;

	value = AT_READ_REG(hw, REG_SPI_FLASH_CTRL);
	if (value & SPI_FLASH_CTRL_EN_VPD) {
		value &= ~SPI_FLASH_CTRL_EN_VPD;
		AT_WRITE_REG(hw, REG_SPI_FLASH_CTRL, value);
	}
	value = AT_READ_REGW(hw, REG_PCIE_CAP_LIST);
	return ((value & 0xFF00) == 0x6C00) ? 0 : 1;
}

void atl1e_hw_set_mac_addr(struct atl1e_hw *hw)
{
	u32 value;
	/*
	 * 00-0B-6A-F6-00-DC
	 * 0:  6AF600DC 1: 000B
	 * low dword
	 */
	value = (((u32)hw->mac_addr[2]) << 24) |
		(((u32)hw->mac_addr[3]) << 16) |
		(((u32)hw->mac_addr[4]) << 8)  |
		(((u32)hw->mac_addr[5])) ;
	AT_WRITE_REG_ARRAY(hw, REG_MAC_STA_ADDR, 0, value);
	/* hight dword */
	value = (((u32)hw->mac_addr[0]) << 8) |
		(((u32)hw->mac_addr[1])) ;
	AT_WRITE_REG_ARRAY(hw, REG_MAC_STA_ADDR, 1, value);
}

/*
 * atl1e_get_permanent_address
 * return 0 if get valid mac address,
 */
static int atl1e_get_permanent_address(struct atl1e_hw *hw)
{
	union {
		u32 dword[2];
		u8 byte[8];
	} hw_addr;
	u32 i;
	u32 twsi_ctrl_data;
	u8  eth_addr[ETH_ALEN];

	if (!atl1e_check_eeprom_exist(hw)) {
		/* eeprom exist */
		twsi_ctrl_data = AT_READ_REG(hw, REG_TWSI_CTRL);
		twsi_ctrl_data |= TWSI_CTRL_SW_LDSTART;
		AT_WRITE_REG(hw, REG_TWSI_CTRL, twsi_ctrl_data);
		for (i = 0; i < AT_TWSI_EEPROM_TIMEOUT; i++) {
			mdelay(10);
			twsi_ctrl_data = AT_READ_REG(hw, REG_TWSI_CTRL);
			if ((twsi_ctrl_data & TWSI_CTRL_SW_LDSTART) == 0)
				break;
		}
		if (i >= AT_TWSI_EEPROM_TIMEOUT)
			return AT_ERR_TIMEOUT;
	}

	/* maybe MAC-address is from BIOS */
	hw_addr.dword[0] = AT_READ_REG(hw, REG_MAC_STA_ADDR);
	hw_addr.dword[1] = AT_READ_REG(hw, REG_MAC_STA_ADDR + 4);
	for (i = 0; i < ETH_ALEN; i++) {
		eth_addr[ETH_ALEN - i - 1] = hw_addr.byte[i];
	}

	memcpy(hw->perm_mac_addr, eth_addr, ETH_ALEN);
	return 0;
}

void atl1e_force_ps(struct atl1e_hw *hw)
{
	AT_WRITE_REGW(hw, REG_GPHY_CTRL,
			GPHY_CTRL_PW_WOL_DIS | GPHY_CTRL_EXT_RESET);
}

/*
 * Reads the adapter's MAC address from the EEPROM
 *
 * hw - Struct containing variables accessed by shared code
 */
int atl1e_read_mac_addr(struct atl1e_hw *hw)
{
	int err = 0;

	err = atl1e_get_permanent_address(hw);
	if (err)
		return AT_ERR_EEPROM;
	memcpy(hw->mac_addr, hw->perm_mac_addr, sizeof(hw->perm_mac_addr));
	return 0;
}

/*
 * Reads the value from a PHY register
 * hw - Struct containing variables accessed by shared code
 * reg_addr - address of the PHY register to read
 */
int atl1e_read_phy_reg(struct atl1e_hw *hw, u16 reg_addr, u16 *phy_data)
{
	u32 val;
	int i;

	val = ((u32)(reg_addr & MDIO_REG_ADDR_MASK)) << MDIO_REG_ADDR_SHIFT |
		MDIO_START | MDIO_SUP_PREAMBLE | MDIO_RW |
		MDIO_CLK_25_4 << MDIO_CLK_SEL_SHIFT;

	AT_WRITE_REG(hw, REG_MDIO_CTRL, val);

	wmb();

	for (i = 0; i < MDIO_WAIT_TIMES; i++) {
		udelay(2);
		val = AT_READ_REG(hw, REG_MDIO_CTRL);
		if (!(val & (MDIO_START | MDIO_BUSY)))
			break;
		wmb();
	}
	if (!(val & (MDIO_START | MDIO_BUSY))) {
		*phy_data = (u16)val;
		return 0;
	}

	return AT_ERR_PHY;
}

/*
 * Writes a value to a PHY register
 * hw - Struct containing variables accessed by shared code
 * reg_addr - address of the PHY register to write
 * data - data to write to the PHY
 */
int atl1e_write_phy_reg(struct atl1e_hw *hw, u32 reg_addr, u16 phy_data)
{
	int i;
	u32 val;

	val = ((u32)(phy_data & MDIO_DATA_MASK)) << MDIO_DATA_SHIFT |
	       (reg_addr&MDIO_REG_ADDR_MASK) << MDIO_REG_ADDR_SHIFT |
	       MDIO_SUP_PREAMBLE |
	       MDIO_START |
	       MDIO_CLK_25_4 << MDIO_CLK_SEL_SHIFT;

	AT_WRITE_REG(hw, REG_MDIO_CTRL, val);
	wmb();

	for (i = 0; i < MDIO_WAIT_TIMES; i++) {
		udelay(2);
		val = AT_READ_REG(hw, REG_MDIO_CTRL);
		if (!(val & (MDIO_START | MDIO_BUSY)))
			break;
		wmb();
	}

	if (!(val & (MDIO_START | MDIO_BUSY)))
		return 0;

	return AT_ERR_PHY;
}

/*
 * atl1e_init_pcie - init PCIE module
 */
static void atl1e_init_pcie(struct atl1e_hw *hw)
{
	u32 value;
	/* comment 2lines below to save more power when sususpend
	   value = LTSSM_TEST_MODE_DEF;
	   AT_WRITE_REG(hw, REG_LTSSM_TEST_MODE, value);
	 */

	/* pcie flow control mode change */
	value = AT_READ_REG(hw, 0x1008);
	value |= 0x8000;
	AT_WRITE_REG(hw, 0x1008, value);
}
/*
 * Configures PHY autoneg and flow control advertisement settings
 *
 * hw - Struct containing variables accessed by shared code
 */
static int atl1e_phy_setup_autoneg_adv(struct atl1e_hw *hw)
{
	s32 ret_val;
	u16 mii_autoneg_adv_reg;
	u16 mii_1000t_ctrl_reg;

	if (0 != hw->mii_autoneg_adv_reg)
		return 0;
	/* Read the MII Auto-Neg Advertisement Register (Address 4/9). */
	mii_autoneg_adv_reg = MII_AR_DEFAULT_CAP_MASK;
	mii_1000t_ctrl_reg  = MII_AT001_CR_1000T_DEFAULT_CAP_MASK;

	/*
	 * First we clear all the 10/100 mb speed bits in the Auto-Neg
	 * Advertisement Register (Address 4) and the 1000 mb speed bits in
	 * the  1000Base-T control Register (Address 9).
	 */
	mii_autoneg_adv_reg &= ~MII_AR_SPEED_MASK;
	mii_1000t_ctrl_reg  &= ~MII_AT001_CR_1000T_SPEED_MASK;

	/* Assume auto-detect media type */
	mii_autoneg_adv_reg |= (MII_AR_10T_HD_CAPS   |
				MII_AR_10T_FD_CAPS   |
				MII_AR_100TX_HD_CAPS |
				MII_AR_100TX_FD_CAPS);
	if (hw->nic_type == athr_l1e) {
		mii_1000t_ctrl_reg |= MII_AT001_CR_1000T_FD_CAPS;
	}

	/* flow control fixed to enable all */
	mii_autoneg_adv_reg |= (MII_AR_ASM_DIR | MII_AR_PAUSE);

	hw->mii_autoneg_adv_reg = mii_autoneg_adv_reg;
	hw->mii_1000t_ctrl_reg  = mii_1000t_ctrl_reg;

	ret_val = atl1e_write_phy_reg(hw, MII_ADVERTISE, mii_autoneg_adv_reg);
	if (ret_val)
		return ret_val;

	if (hw->nic_type == athr_l1e || hw->nic_type == athr_l2e_revA) {
		ret_val = atl1e_write_phy_reg(hw, MII_AT001_CR,
					   mii_1000t_ctrl_reg);
		if (ret_val)
			return ret_val;
	}

	return 0;
}


/*
 * Resets the PHY and make all config validate
 *
 * hw - Struct containing variables accessed by shared code
 *
 * Sets bit 15 and 12 of the MII control regiser (for F001 bug)
 */
int atl1e_phy_commit(struct atl1e_hw *hw)
{
	int ret_val;
	u16 phy_data;

	phy_data = MII_CR_RESET | MII_CR_AUTO_NEG_EN | MII_CR_RESTART_AUTO_NEG;

	ret_val = atl1e_write_phy_reg(hw, MII_BMCR, phy_data);
	if (ret_val) {
		u32 val;
		int i;
		/**************************************
		 * pcie serdes link may be down !
		 **************************************/
		for (i = 0; i < 25; i++) {
			mdelay(1);
			val = AT_READ_REG(hw, REG_MDIO_CTRL);
			if (!(val & (MDIO_START | MDIO_BUSY)))
				break;
		}

		if (0 != (val & (MDIO_START | MDIO_BUSY))) {
			DBG("atl1e: PCI-E link down for at least 25ms\n");
			return ret_val;
		}

		DBG("atl1e: PCI-E link up after %d ms\n", i);
	}
	return 0;
}

int atl1e_phy_init(struct atl1e_hw *hw)
{
	s32 ret_val;
	u16 phy_val;

	if (hw->phy_configured) {
		if (hw->re_autoneg) {
			hw->re_autoneg = 0;
			return atl1e_restart_autoneg(hw);
		}
		return 0;
	}

	/* RESET GPHY Core */
	AT_WRITE_REGW(hw, REG_GPHY_CTRL, GPHY_CTRL_DEFAULT);
	mdelay(2);
	AT_WRITE_REGW(hw, REG_GPHY_CTRL, GPHY_CTRL_DEFAULT |
		      GPHY_CTRL_EXT_RESET);
	mdelay(2);

	/* patches */
	/* p1. eable hibernation mode */
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_ADDR, 0xB);
	if (ret_val)
		return ret_val;
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_DATA, 0xBC00);
	if (ret_val)
		return ret_val;
	/* p2. set Class A/B for all modes */
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_ADDR, 0);
	if (ret_val)
		return ret_val;
	phy_val = 0x02ef;
	/* remove Class AB */
	/* phy_val = hw->emi_ca ? 0x02ef : 0x02df; */
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_DATA, phy_val);
	if (ret_val)
		return ret_val;
	/* p3. 10B ??? */
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_ADDR, 0x12);
	if (ret_val)
		return ret_val;
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_DATA, 0x4C04);
	if (ret_val)
		return ret_val;
	/* p4. 1000T power */
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_ADDR, 0x4);
	if (ret_val)
		return ret_val;
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_DATA, 0x8BBB);
	if (ret_val)
		return ret_val;

	ret_val = atl1e_write_phy_reg(hw, MII_DBG_ADDR, 0x5);
	if (ret_val)
		return ret_val;
	ret_val = atl1e_write_phy_reg(hw, MII_DBG_DATA, 0x2C46);
	if (ret_val)
		return ret_val;

	mdelay(1);

	/*Enable PHY LinkChange Interrupt */
	ret_val = atl1e_write_phy_reg(hw, MII_INT_CTRL, 0xC00);
	if (ret_val) {
		DBG("atl1e: Error enable PHY linkChange Interrupt\n");
		return ret_val;
	}
	/* setup AutoNeg parameters */
	ret_val = atl1e_phy_setup_autoneg_adv(hw);
	if (ret_val) {
		DBG("atl1e: Error Setting up Auto-Negotiation\n");
		return ret_val;
	}
	/* SW.Reset & En-Auto-Neg to restart Auto-Neg*/
	DBG("atl1e: Restarting Auto-Neg");
	ret_val = atl1e_phy_commit(hw);
	if (ret_val) {
		DBG("atl1e: Error Resetting the phy");
		return ret_val;
	}

	hw->phy_configured = 1;

	return 0;
}

/*
 * Reset the transmit and receive units; mask and clear all interrupts.
 * hw - Struct containing variables accessed by shared code
 * return : 0  or  idle status (if error)
 */
int atl1e_reset_hw(struct atl1e_hw *hw)
{
	struct atl1e_adapter *adapter = hw->adapter;
	struct pci_device *pdev = adapter->pdev;
	int timeout = 0;
	u32 idle_status_data = 0;
	u16 pci_cfg_cmd_word = 0;

	/* Workaround for PCI problem when BIOS sets MMRBC incorrectly. */
	pci_read_config_word(pdev, PCI_COMMAND, &pci_cfg_cmd_word);
	if ((pci_cfg_cmd_word & (PCI_COMMAND_IO | PCI_COMMAND_MEM |
				 PCI_COMMAND_MASTER))
			!= (PCI_COMMAND_IO | PCI_COMMAND_MEM |
			    PCI_COMMAND_MASTER)) {
		pci_cfg_cmd_word |= (PCI_COMMAND_IO | PCI_COMMAND_MEM |
				     PCI_COMMAND_MASTER);
		pci_write_config_word(pdev, PCI_COMMAND, pci_cfg_cmd_word);
	}

	/*
	 * Issue Soft Reset to the MAC.  This will reset the chip's
	 * transmit, receive, DMA.  It will not effect
	 * the current PCI configuration.  The global reset bit is self-
	 * clearing, and should clear within a microsecond.
	 */
	AT_WRITE_REG(hw, REG_MASTER_CTRL,
			MASTER_CTRL_LED_MODE | MASTER_CTRL_SOFT_RST);
	wmb();
	mdelay(1);

	/* Wait at least 10ms for All module to be Idle */
	for (timeout = 0; timeout < AT_HW_MAX_IDLE_DELAY; timeout++) {
		idle_status_data = AT_READ_REG(hw, REG_IDLE_STATUS);
		if (idle_status_data == 0)
			break;
		mdelay(1);
	}

	if (timeout >= AT_HW_MAX_IDLE_DELAY) {
		DBG("atl1e: MAC reset timeout\n");
		return AT_ERR_TIMEOUT;
	}

	return 0;
}


/*
 * Performs basic configuration of the adapter.
 *
 * hw - Struct containing variables accessed by shared code
 * Assumes that the controller has previously been reset and is in a
 * post-reset uninitialized state. Initializes multicast table,
 * and  Calls routines to setup link
 * Leaves the transmit and receive units disabled and uninitialized.
 */
int atl1e_init_hw(struct atl1e_hw *hw)
{
	s32 ret_val = 0;

	atl1e_init_pcie(hw);

	/* Zero out the Multicast HASH table */
	/* clear the old settings from the multicast hash table */
	AT_WRITE_REG(hw, REG_RX_HASH_TABLE, 0);
	AT_WRITE_REG_ARRAY(hw, REG_RX_HASH_TABLE, 1, 0);

	ret_val = atl1e_phy_init(hw);

	return ret_val;
}

/*
 * Detects the current speed and duplex settings of the hardware.
 *
 * hw - Struct containing variables accessed by shared code
 * speed - Speed of the connection
 * duplex - Duplex setting of the connection
 */
int atl1e_get_speed_and_duplex(struct atl1e_hw *hw, u16 *speed, u16 *duplex)
{
	int err;
	u16 phy_data;

	/* Read   PHY Specific Status Register (17) */
	err = atl1e_read_phy_reg(hw, MII_AT001_PSSR, &phy_data);
	if (err)
		return err;

	if (!(phy_data & MII_AT001_PSSR_SPD_DPLX_RESOLVED))
		return AT_ERR_PHY_RES;

	switch (phy_data & MII_AT001_PSSR_SPEED) {
	case MII_AT001_PSSR_1000MBS:
		*speed = SPEED_1000;
		break;
	case MII_AT001_PSSR_100MBS:
		*speed = SPEED_100;
		break;
	case MII_AT001_PSSR_10MBS:
		*speed = SPEED_10;
		break;
	default:
		return AT_ERR_PHY_SPEED;
		break;
	}

	if (phy_data & MII_AT001_PSSR_DPLX)
		*duplex = FULL_DUPLEX;
	else
		*duplex = HALF_DUPLEX;

	return 0;
}

int atl1e_restart_autoneg(struct atl1e_hw *hw)
{
	int err = 0;

	err = atl1e_write_phy_reg(hw, MII_ADVERTISE, hw->mii_autoneg_adv_reg);
	if (err)
		return err;

	if (hw->nic_type == athr_l1e || hw->nic_type == athr_l2e_revA) {
		err = atl1e_write_phy_reg(hw, MII_AT001_CR,
				       hw->mii_1000t_ctrl_reg);
		if (err)
			return err;
	}

	err = atl1e_write_phy_reg(hw, MII_BMCR,
			MII_CR_RESET | MII_CR_AUTO_NEG_EN |
			MII_CR_RESTART_AUTO_NEG);
	return err;
}

