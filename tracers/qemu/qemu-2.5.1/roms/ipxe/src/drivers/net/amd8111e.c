/* Advanced  Micro Devices Inc. AMD8111E Linux Network Driver 
 * Copyright (C) 2004 Advanced Micro Devices 
 * Copyright (C) 2005 Liu Tao <liutao1980@gmail.com> [etherboot port]
 * 
 * Copyright 2001,2002 Jeff Garzik <jgarzik@mandrakesoft.com> [ 8139cp.c,tg3.c ]
 * Copyright (C) 2001, 2002 David S. Miller (davem@redhat.com)[ tg3.c]
 * Copyright 1996-1999 Thomas Bogendoerfer [ pcnet32.c ]
 * Derived from the lance driver written 1993,1994,1995 by Donald Becker.
 * Copyright 1993 United States Government as represented by the
 *	Director, National Security Agency.[ pcnet32.c ]
 * Carsten Langgaard, carstenl@mips.com [ pcnet32.c ]
 * Copyright (C) 2000 MIPS Technologies, Inc.  All rights reserved.
 *
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * USA
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include "etherboot.h"
#include "nic.h"
#include "mii.h"
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>
#include "string.h"
#include "stdint.h"
#include "amd8111e.h"


/* driver definitions */
#define NUM_TX_SLOTS	2
#define NUM_RX_SLOTS	4
#define TX_SLOTS_MASK	1
#define RX_SLOTS_MASK	3

#define TX_BUF_LEN	1536
#define RX_BUF_LEN	1536

#define TX_PKT_LEN_MAX	(ETH_FRAME_LEN - ETH_HLEN)
#define RX_PKT_LEN_MIN	60
#define RX_PKT_LEN_MAX	ETH_FRAME_LEN

#define TX_TIMEOUT	3000
#define TX_PROCESS_TIME	10
#define TX_RETRY	(TX_TIMEOUT / TX_PROCESS_TIME)

#define PHY_RW_RETRY	10


struct amd8111e_tx_desc {
	u16 buf_len;
	u16 tx_flags;
	u16 tag_ctrl_info;
	u16 tag_ctrl_cmd;
	u32 buf_phy_addr;
	u32 reserved;
}; 

struct amd8111e_rx_desc {
	u32 reserved;
	u16 msg_len;
	u16 tag_ctrl_info; 
	u16 buf_len;
	u16 rx_flags;
	u32 buf_phy_addr;
};

struct eth_frame {
	u8 dst_addr[ETH_ALEN];
	u8 src_addr[ETH_ALEN];
	u16 type;
	u8 data[ETH_FRAME_LEN - ETH_HLEN];
} __attribute__((packed));

struct amd8111e_priv {
	struct amd8111e_tx_desc tx_ring[NUM_TX_SLOTS];
	struct amd8111e_rx_desc rx_ring[NUM_RX_SLOTS];
	unsigned char tx_buf[NUM_TX_SLOTS][TX_BUF_LEN];
	unsigned char rx_buf[NUM_RX_SLOTS][RX_BUF_LEN];
	unsigned long tx_idx, rx_idx;
	int tx_consistent;

	char opened;
	char link;
	char speed;
	char duplex;
	int ext_phy_addr;
	u32 ext_phy_id;

	struct pci_device *pdev;
	struct nic *nic;
	void *mmio;
};

static struct amd8111e_priv amd8111e;


/********************************************************
 * 		locale functions			*
 ********************************************************/
static void amd8111e_init_hw_default(struct amd8111e_priv *lp);
static int amd8111e_start(struct amd8111e_priv *lp);
static int amd8111e_read_phy(struct amd8111e_priv *lp, int phy_addr, int reg, u32 *val);
#if 0
static int amd8111e_write_phy(struct amd8111e_priv *lp, int phy_addr, int reg, u32 val);
#endif
static void amd8111e_probe_ext_phy(struct amd8111e_priv *lp);
static void amd8111e_disable_interrupt(struct amd8111e_priv *lp);
static void amd8111e_enable_interrupt(struct amd8111e_priv *lp);
static void amd8111e_force_interrupt(struct amd8111e_priv *lp);
static int amd8111e_get_mac_address(struct amd8111e_priv *lp);
static int amd8111e_init_rx_ring(struct amd8111e_priv *lp);
static int amd8111e_init_tx_ring(struct amd8111e_priv *lp);
static int amd8111e_wait_tx_ring(struct amd8111e_priv *lp, unsigned int index);
static void amd8111e_wait_link(struct amd8111e_priv *lp);
static void amd8111e_poll_link(struct amd8111e_priv *lp);
static void amd8111e_restart(struct amd8111e_priv *lp);


/* 
 * This function clears necessary the device registers. 
 */	
static void amd8111e_init_hw_default(struct amd8111e_priv *lp)
{
	unsigned int reg_val;
	void *mmio = lp->mmio;

        /* stop the chip */
	writel(RUN, mmio + CMD0);

	/* Clear RCV_RING_BASE_ADDR */
	writel(0, mmio + RCV_RING_BASE_ADDR0);

	/* Clear XMT_RING_BASE_ADDR */
	writel(0, mmio + XMT_RING_BASE_ADDR0);
	writel(0, mmio + XMT_RING_BASE_ADDR1);
	writel(0, mmio + XMT_RING_BASE_ADDR2);
	writel(0, mmio + XMT_RING_BASE_ADDR3);

	/* Clear CMD0  */
	writel(CMD0_CLEAR, mmio + CMD0);
	
	/* Clear CMD2 */
	writel(CMD2_CLEAR, mmio + CMD2);

	/* Clear CMD7 */
	writel(CMD7_CLEAR, mmio + CMD7);

	/* Clear DLY_INT_A and DLY_INT_B */
	writel(0x0, mmio + DLY_INT_A);
	writel(0x0, mmio + DLY_INT_B);

	/* Clear FLOW_CONTROL */
	writel(0x0, mmio + FLOW_CONTROL);

	/* Clear INT0  write 1 to clear register */
	reg_val = readl(mmio + INT0);
	writel(reg_val, mmio + INT0);

	/* Clear STVAL */
	writel(0x0, mmio + STVAL);

	/* Clear INTEN0 */
	writel(INTEN0_CLEAR, mmio + INTEN0);

	/* Clear LADRF */
	writel(0x0, mmio + LADRF);

	/* Set SRAM_SIZE & SRAM_BOUNDARY registers  */
	writel(0x80010, mmio + SRAM_SIZE);

	/* Clear RCV_RING0_LEN */
	writel(0x0, mmio +  RCV_RING_LEN0);

	/* Clear XMT_RING0/1/2/3_LEN */
	writel(0x0, mmio +  XMT_RING_LEN0);
	writel(0x0, mmio +  XMT_RING_LEN1);
	writel(0x0, mmio +  XMT_RING_LEN2);
	writel(0x0, mmio +  XMT_RING_LEN3);

	/* Clear XMT_RING_LIMIT */
	writel(0x0, mmio + XMT_RING_LIMIT);

	/* Clear MIB */
	writew(MIB_CLEAR, mmio + MIB_ADDR);

	/* Clear LARF */
	writel( 0, mmio + LADRF);
	writel( 0, mmio + LADRF + 4);

	/* SRAM_SIZE register */
	reg_val = readl(mmio + SRAM_SIZE);
	
	/* Set default value to CTRL1 Register */
	writel(CTRL1_DEFAULT, mmio + CTRL1);

	/* To avoid PCI posting bug */
	readl(mmio + CMD2);
}

/* 
 * This function initializes the device registers  and starts the device.  
 */
static int amd8111e_start(struct amd8111e_priv *lp)
{
	struct nic *nic = lp->nic;
	void *mmio = lp->mmio;
	int i, reg_val;

	/* stop the chip */
	writel(RUN, mmio + CMD0);

	/* AUTOPOLL0 Register *//*TBD default value is 8100 in FPS */
	writew(0x8100 | lp->ext_phy_addr, mmio + AUTOPOLL0);

	/* enable the port manager and set auto negotiation always */
	writel(VAL1 | EN_PMGR, mmio + CMD3 );
	writel(XPHYANE | XPHYRST, mmio + CTRL2); 

	/* set control registers */
	reg_val = readl(mmio + CTRL1);
	reg_val &= ~XMTSP_MASK;
	writel(reg_val | XMTSP_128 | CACHE_ALIGN, mmio + CTRL1);

	/* initialize tx and rx ring base addresses */
	amd8111e_init_tx_ring(lp);
	amd8111e_init_rx_ring(lp);
	writel(virt_to_bus(lp->tx_ring), mmio + XMT_RING_BASE_ADDR0);
	writel(virt_to_bus(lp->rx_ring), mmio + RCV_RING_BASE_ADDR0);
	writew(NUM_TX_SLOTS, mmio + XMT_RING_LEN0);
	writew(NUM_RX_SLOTS, mmio + RCV_RING_LEN0);
	
	/* set default IPG to 96 */
	writew(DEFAULT_IPG, mmio + IPG);
	writew(DEFAULT_IPG - IFS1_DELTA, mmio + IFS1); 

	/* AutoPAD transmit, Retransmit on Underflow */
	writel(VAL0 | APAD_XMT | REX_RTRY | REX_UFLO, mmio + CMD2);
	
	/* JUMBO disabled */
	writel(JUMBO, mmio + CMD3);

	/* Setting the MAC address to the device */
	for(i = 0; i < ETH_ALEN; i++)
		writeb(nic->node_addr[i], mmio + PADR + i); 

	/* set RUN bit to start the chip, interrupt not enabled */
	writel(VAL2 | RDMD0 | VAL0 | RUN, mmio + CMD0);
	
	/* To avoid PCI posting bug */
	readl(mmio + CMD0);
	return 0;
}

/* 
This function will read the PHY registers.
*/
static int amd8111e_read_phy(struct amd8111e_priv *lp, int phy_addr, int reg, u32 *val)
{
	void *mmio = lp->mmio;
	unsigned int reg_val;
	unsigned int retry = PHY_RW_RETRY;

	reg_val = readl(mmio + PHY_ACCESS);
	while (reg_val & PHY_CMD_ACTIVE)
		reg_val = readl(mmio + PHY_ACCESS);

	writel(PHY_RD_CMD | ((phy_addr & 0x1f) << 21) | ((reg & 0x1f) << 16),
		mmio + PHY_ACCESS);
	do {
		reg_val = readl(mmio + PHY_ACCESS);
		udelay(30);  /* It takes 30 us to read/write data */
	} while (--retry && (reg_val & PHY_CMD_ACTIVE));

	if (reg_val & PHY_RD_ERR) {
		*val = 0;
		return -1;
	}
	
	*val = reg_val & 0xffff;
	return 0;
}

/* 
This function will write into PHY registers. 
*/
#if 0
static int amd8111e_write_phy(struct amd8111e_priv *lp, int phy_addr, int reg, u32 val)
{
	void *mmio = lp->mmio;
	unsigned int reg_val;
	unsigned int retry = PHY_RW_RETRY;

	reg_val = readl(mmio + PHY_ACCESS);
	while (reg_val & PHY_CMD_ACTIVE)
		reg_val = readl(mmio + PHY_ACCESS);

	writel(PHY_WR_CMD | ((phy_addr & 0x1f) << 21) | ((reg & 0x1f) << 16) | val,
		mmio + PHY_ACCESS);
	do {
		reg_val = readl(mmio + PHY_ACCESS);
		udelay(30);  /* It takes 30 us to read/write the data */
	} while (--retry && (reg_val & PHY_CMD_ACTIVE));
	
	if(reg_val & PHY_RD_ERR)
		return -1;

	return 0;
}
#endif

static void amd8111e_probe_ext_phy(struct amd8111e_priv *lp)
{
	int i;

	lp->ext_phy_id = 0;
	lp->ext_phy_addr = 1;
	
	for (i = 0x1e; i >= 0; i--) {
		u32 id1, id2;

		if (amd8111e_read_phy(lp, i, MII_PHYSID1, &id1))
			continue;
		if (amd8111e_read_phy(lp, i, MII_PHYSID2, &id2))
			continue;
		lp->ext_phy_id = (id1 << 16) | id2;
		lp->ext_phy_addr = i;
		break;
	}

	if (lp->ext_phy_id)
		printf("Found MII PHY ID 0x%08x at address 0x%02x\n",
		       (unsigned int) lp->ext_phy_id, lp->ext_phy_addr);
	else
		printf("Couldn't detect MII PHY, assuming address 0x01\n");
}

static void amd8111e_disable_interrupt(struct amd8111e_priv *lp)
{
	void *mmio = lp->mmio;
	unsigned int int0;

	writel(INTREN, mmio + CMD0);
	writel(INTEN0_CLEAR, mmio + INTEN0);
	int0 = readl(mmio + INT0);
	writel(int0, mmio + INT0);
	readl(mmio + INT0);
}

static void amd8111e_enable_interrupt(struct amd8111e_priv *lp)
{
	void *mmio = lp->mmio;

	writel(VAL3 | LCINTEN | VAL1 | TINTEN0 | VAL0 | RINTEN0, mmio + INTEN0);
	writel(VAL0 | INTREN, mmio + CMD0);
	readl(mmio + CMD0);
}

static void amd8111e_force_interrupt(struct amd8111e_priv *lp)
{
	void *mmio = lp->mmio;

	writel(VAL0 | UINTCMD, mmio + CMD0);
	readl(mmio + CMD0);
}

static int amd8111e_get_mac_address(struct amd8111e_priv *lp)
{
	struct nic *nic = lp->nic;
	void *mmio = lp->mmio;
	int i;

	/* BIOS should have set mac address to PADR register,
	 * so we read PADR to get it.
	 */
	for (i = 0; i < ETH_ALEN; i++)
		nic->node_addr[i] = readb(mmio + PADR + i);

	DBG ( "Ethernet addr: %s\n", eth_ntoa ( nic->node_addr ) );

	return 0;
}

static int amd8111e_init_rx_ring(struct amd8111e_priv *lp)
{
	int i;

	lp->rx_idx = 0;
	
        /* Initilaizing receive descriptors */
	for (i = 0; i < NUM_RX_SLOTS; i++) {
		lp->rx_ring[i].buf_phy_addr = cpu_to_le32(virt_to_bus(lp->rx_buf[i]));
		lp->rx_ring[i].buf_len = cpu_to_le16(RX_BUF_LEN);
		wmb();
		lp->rx_ring[i].rx_flags = cpu_to_le16(OWN_BIT);
	}

	return 0;
}

static int amd8111e_init_tx_ring(struct amd8111e_priv *lp)
{
	int i;

	lp->tx_idx = 0;
	lp->tx_consistent = 1;
	
	/* Initializing transmit descriptors */
	for (i = 0; i < NUM_TX_SLOTS; i++) {
		lp->tx_ring[i].tx_flags = 0;
		lp->tx_ring[i].buf_phy_addr = 0;
		lp->tx_ring[i].buf_len = 0;
	}

	return 0;
}

static int amd8111e_wait_tx_ring(struct amd8111e_priv *lp, unsigned int index)
{
	volatile u16 status;
	int retry = TX_RETRY;

	status = le16_to_cpu(lp->tx_ring[index].tx_flags);
	while (--retry && (status & OWN_BIT)) {
		mdelay(TX_PROCESS_TIME);
		status = le16_to_cpu(lp->tx_ring[index].tx_flags);
	}
	if (status & OWN_BIT) {
		printf("Error: tx slot %d timeout, stat = 0x%x\n", index, status);
		amd8111e_restart(lp);
		return -1;
	}

	return 0;
}

static void amd8111e_wait_link(struct amd8111e_priv *lp)
{
	unsigned int status;
	u32 reg_val;

	do {
		/* read phy to update STAT0 register */
		amd8111e_read_phy(lp, lp->ext_phy_addr, MII_BMCR, &reg_val);
		amd8111e_read_phy(lp, lp->ext_phy_addr, MII_BMSR, &reg_val);
		amd8111e_read_phy(lp, lp->ext_phy_addr, MII_ADVERTISE, &reg_val);
		amd8111e_read_phy(lp, lp->ext_phy_addr, MII_LPA, &reg_val);
		status = readl(lp->mmio + STAT0);
	} while (!(status & AUTONEG_COMPLETE) || !(status & LINK_STATS));
}

static void amd8111e_poll_link(struct amd8111e_priv *lp)
{
	unsigned int status, speed;
	u32 reg_val;

	if (!lp->link) {
		/* read phy to update STAT0 register */
		amd8111e_read_phy(lp, lp->ext_phy_addr, MII_BMCR, &reg_val);
		amd8111e_read_phy(lp, lp->ext_phy_addr, MII_BMSR, &reg_val);
		amd8111e_read_phy(lp, lp->ext_phy_addr, MII_ADVERTISE, &reg_val);
		amd8111e_read_phy(lp, lp->ext_phy_addr, MII_LPA, &reg_val);
		status = readl(lp->mmio + STAT0);

		if (status & LINK_STATS) {
			lp->link = 1;
			speed = (status & SPEED_MASK) >> 7;
			if (speed == PHY_SPEED_100)
				lp->speed = 1;
			else
				lp->speed = 0;
			if (status & FULL_DPLX)
				lp->duplex = 1;
			else
				lp->duplex = 0;

			printf("Link is up: %s Mbps %s duplex\n",
				lp->speed ? "100" : "10", lp->duplex ? "full" : "half");
		}
	} else {
		status = readl(lp->mmio + STAT0);
		if (!(status & LINK_STATS)) {
			lp->link = 0;
			printf("Link is down\n");
		}
	}
}

static void amd8111e_restart(struct amd8111e_priv *lp)
{
	printf("\nStarting nic...\n");
	amd8111e_disable_interrupt(lp);
	amd8111e_init_hw_default(lp);
	amd8111e_probe_ext_phy(lp);
	amd8111e_get_mac_address(lp);
	amd8111e_start(lp);

	printf("Waiting link up...\n");
	lp->link = 0;
	amd8111e_wait_link(lp);
	amd8111e_poll_link(lp);
}


/********************************************************
 * 		Interface Functions			*
 ********************************************************/

static void amd8111e_transmit(struct nic *nic, const char *dst_addr,
		unsigned int type, unsigned int size, const char *packet)
{
	struct amd8111e_priv *lp = nic->priv_data;
	struct eth_frame *frame;
	unsigned int index;

	/* check packet size */
	if (size > TX_PKT_LEN_MAX) {
		printf("amd8111e_transmit(): too large packet, drop\n");
		return;
	}

	/* get tx slot */
	index = lp->tx_idx;
	if (amd8111e_wait_tx_ring(lp, index))
		return;

	/* fill frame */
	frame = (struct eth_frame *)lp->tx_buf[index];
	memset(frame->data, 0, TX_PKT_LEN_MAX);
	memcpy(frame->dst_addr, dst_addr, ETH_ALEN);
	memcpy(frame->src_addr, nic->node_addr, ETH_ALEN);
	frame->type = htons(type);
	memcpy(frame->data, packet, size);

	/* start xmit */
	lp->tx_ring[index].buf_len = cpu_to_le16(ETH_HLEN + size);
	lp->tx_ring[index].buf_phy_addr = cpu_to_le32(virt_to_bus(frame));
	wmb();
	lp->tx_ring[index].tx_flags = 
		cpu_to_le16(OWN_BIT | STP_BIT | ENP_BIT | ADD_FCS_BIT | LTINT_BIT);
	writel(VAL1 | TDMD0, lp->mmio + CMD0);
	readl(lp->mmio + CMD0);

	/* update slot pointer */
	lp->tx_idx = (lp->tx_idx + 1) & TX_SLOTS_MASK;
}

static int amd8111e_poll(struct nic *nic, int retrieve)
{
	/* return true if there's an ethernet packet ready to read */
	/* nic->packet should contain data on return */
	/* nic->packetlen should contain length of data */

	struct amd8111e_priv *lp = nic->priv_data;
	u16 status, pkt_len;
	unsigned int index, pkt_ok;

	amd8111e_poll_link(lp);

	index = lp->rx_idx;
	status = le16_to_cpu(lp->rx_ring[index].rx_flags);
	pkt_len = le16_to_cpu(lp->rx_ring[index].msg_len) - 4;	/* remove 4bytes FCS */
	
	if (status & OWN_BIT)
		return 0;

	if (status & ERR_BIT)
		pkt_ok = 0;
	else if (!(status & STP_BIT))
		pkt_ok = 0;
	else if (!(status & ENP_BIT))
		pkt_ok = 0;
	else if (pkt_len < RX_PKT_LEN_MIN)
		pkt_ok = 0;
	else if (pkt_len > RX_PKT_LEN_MAX)
		pkt_ok = 0;
	else
		pkt_ok = 1;

	if (pkt_ok) {
		if (!retrieve)
			return 1;
		nic->packetlen = pkt_len;
		memcpy(nic->packet, lp->rx_buf[index], nic->packetlen);
	}

	lp->rx_ring[index].buf_phy_addr = cpu_to_le32(virt_to_bus(lp->rx_buf[index]));
	lp->rx_ring[index].buf_len = cpu_to_le16(RX_BUF_LEN);
	wmb();
	lp->rx_ring[index].rx_flags = cpu_to_le16(OWN_BIT);
	writel(VAL2 | RDMD0, lp->mmio + CMD0);
	readl(lp->mmio + CMD0);

	lp->rx_idx = (lp->rx_idx + 1) & RX_SLOTS_MASK;
	return pkt_ok;
}

static void amd8111e_disable(struct nic *nic)
{
	struct amd8111e_priv *lp = nic->priv_data;

	/* disable interrupt */
	amd8111e_disable_interrupt(lp);

	/* stop chip */
	amd8111e_init_hw_default(lp);

	/* unmap mmio */
	iounmap(lp->mmio);

	/* update status */
	lp->opened = 0;
}

static void amd8111e_irq(struct nic *nic, irq_action_t action)
{
	struct amd8111e_priv *lp = nic->priv_data;
		
	switch (action) {
	case DISABLE:
		amd8111e_disable_interrupt(lp);
		break;
	case ENABLE:
		amd8111e_enable_interrupt(lp);
		break;
	case FORCE:
		amd8111e_force_interrupt(lp);
		break;
	}
}

static struct nic_operations amd8111e_operations = {
	.connect	= dummy_connect,
	.poll		= amd8111e_poll,
	.transmit	= amd8111e_transmit,
	.irq		= amd8111e_irq,
};

static int amd8111e_probe(struct nic *nic, struct pci_device *pdev)
{
	struct amd8111e_priv *lp = &amd8111e;
	unsigned long mmio_start, mmio_len;

        nic->ioaddr = pdev->ioaddr;
        nic->irqno  = pdev->irq;
	
	mmio_start = pci_bar_start(pdev, PCI_BASE_ADDRESS_0);
	mmio_len = pci_bar_size(pdev, PCI_BASE_ADDRESS_0);

	memset(lp, 0, sizeof(*lp));
	lp->pdev = pdev;
	lp->nic = nic;
	lp->mmio = ioremap(mmio_start, mmio_len);
	lp->opened = 1;
	adjust_pci_device(pdev);

	nic->priv_data = lp;

	amd8111e_restart(lp);

	nic->nic_op	= &amd8111e_operations;
	return 1;
}

static struct pci_device_id amd8111e_nics[] = {
	PCI_ROM(0x1022, 0x7462, "amd8111e",	"AMD8111E", 0),
};

PCI_DRIVER ( amd8111e_driver, amd8111e_nics, PCI_NO_CLASS );

DRIVER ( "AMD8111E", nic_driver, pci_driver, amd8111e_driver,
	 amd8111e_probe, amd8111e_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
