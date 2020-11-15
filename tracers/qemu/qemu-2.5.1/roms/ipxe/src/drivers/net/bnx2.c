/* bnx2.c: Broadcom NX2 network driver.
 *
 * Copyright (c) 2004, 2005, 2006 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Michael Chan  (mchan@broadcom.com)
 *
 * Etherboot port by Ryan Jackson (rjackson@lnxi.com), based on driver
 * version 1.4.40 from linux 2.6.17
 */

FILE_LICENCE ( GPL_ANY );

#include "etherboot.h"
#include "nic.h"
#include <errno.h>
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>
#include "string.h"
#include <mii.h>
#include "bnx2.h"
#include "bnx2_fw.h"

#if 0
/* Dummy defines for error handling */
#define EBUSY  1
#define ENODEV 2
#define EINVAL 3
#define ENOMEM 4
#define EIO    5
#endif

/* The bnx2 seems to be picky about the alignment of the receive buffers
 * and possibly the status block.
 */
static struct bss {
	struct tx_bd tx_desc_ring[TX_DESC_CNT];
	struct rx_bd rx_desc_ring[RX_DESC_CNT];
	unsigned char rx_buf[RX_BUF_CNT][RX_BUF_SIZE];
	struct status_block status_blk;
	struct statistics_block stats_blk;
} bnx2_bss;

static struct bnx2 bnx2;

static struct flash_spec flash_table[] =
{
	/* Slow EEPROM */
	{0x00000000, 0x40830380, 0x009f0081, 0xa184a053, 0xaf000400,
	 1, SEEPROM_PAGE_BITS, SEEPROM_PAGE_SIZE,
	 SEEPROM_BYTE_ADDR_MASK, SEEPROM_TOTAL_SIZE,
	 "EEPROM - slow"},
	/* Expansion entry 0001 */
	{0x08000002, 0x4b808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 0001"},
	/* Saifun SA25F010 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x04000001, 0x47808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE*2,
	 "Non-buffered flash (128kB)"},
	/* Saifun SA25F020 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x0c000003, 0x4f808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE*4,
	 "Non-buffered flash (256kB)"},
	/* Expansion entry 0100 */
	{0x11000000, 0x53808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 0100"},
	/* Entry 0101: ST M45PE10 (non-buffered flash, TetonII B0) */
	{0x19000002, 0x5b808201, 0x000500db, 0x03840253, 0xaf020406,        
	 0, ST_MICRO_FLASH_PAGE_BITS, ST_MICRO_FLASH_PAGE_SIZE,
	 ST_MICRO_FLASH_BYTE_ADDR_MASK, ST_MICRO_FLASH_BASE_TOTAL_SIZE*2,
	 "Entry 0101: ST M45PE10 (128kB non-bufferred)"},
	/* Entry 0110: ST M45PE20 (non-buffered flash)*/
	{0x15000001, 0x57808201, 0x000500db, 0x03840253, 0xaf020406,
	 0, ST_MICRO_FLASH_PAGE_BITS, ST_MICRO_FLASH_PAGE_SIZE,
	 ST_MICRO_FLASH_BYTE_ADDR_MASK, ST_MICRO_FLASH_BASE_TOTAL_SIZE*4,
	 "Entry 0110: ST M45PE20 (256kB non-bufferred)"},
	/* Saifun SA25F005 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x1d000003, 0x5f808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE,
	 "Non-buffered flash (64kB)"},
	/* Fast EEPROM */
	{0x22000000, 0x62808380, 0x009f0081, 0xa184a053, 0xaf000400,
	 1, SEEPROM_PAGE_BITS, SEEPROM_PAGE_SIZE,
	 SEEPROM_BYTE_ADDR_MASK, SEEPROM_TOTAL_SIZE,
	 "EEPROM - fast"},
	/* Expansion entry 1001 */
	{0x2a000002, 0x6b808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1001"},
	/* Expansion entry 1010 */
	{0x26000001, 0x67808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1010"},
	/* ATMEL AT45DB011B (buffered flash) */
	{0x2e000003, 0x6e808273, 0x00570081, 0x68848353, 0xaf000400,
	 1, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, BUFFERED_FLASH_TOTAL_SIZE,
	 "Buffered flash (128kB)"},
	/* Expansion entry 1100 */
	{0x33000000, 0x73808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1100"},
	/* Expansion entry 1101 */
	{0x3b000002, 0x7b808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1101"},
	/* Ateml Expansion entry 1110 */
	{0x37000001, 0x76808273, 0x00570081, 0x68848353, 0xaf000400,
	 1, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1110 (Atmel)"},
	/* ATMEL AT45DB021B (buffered flash) */
	{0x3f000003, 0x7e808273, 0x00570081, 0x68848353, 0xaf000400,
	 1, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, BUFFERED_FLASH_TOTAL_SIZE*2,
	 "Buffered flash (256kB)"},
};

static u32
bnx2_reg_rd_ind(struct bnx2 *bp, u32 offset)
{
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW_ADDRESS, offset);
	return (REG_RD(bp, BNX2_PCICFG_REG_WINDOW));
}

static void
bnx2_reg_wr_ind(struct bnx2 *bp, u32 offset, u32 val)
{
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW_ADDRESS, offset);
	REG_WR(bp, BNX2_PCICFG_REG_WINDOW, val);
}

static void
bnx2_ctx_wr(struct bnx2 *bp, u32 cid_addr, u32 offset, u32 val)
{
	offset += cid_addr;
	REG_WR(bp, BNX2_CTX_DATA_ADR, offset);
	REG_WR(bp, BNX2_CTX_DATA, val);
}

static int
bnx2_read_phy(struct bnx2 *bp, u32 reg, u32 *val)
{
	u32 val1;
	int i, ret;

	if (bp->phy_flags & PHY_INT_MODE_AUTO_POLLING_FLAG) {
		val1 = REG_RD(bp, BNX2_EMAC_MDIO_MODE);
		val1 &= ~BNX2_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(bp, BNX2_EMAC_MDIO_MODE, val1);
		REG_RD(bp, BNX2_EMAC_MDIO_MODE);

		udelay(40);
	}

	val1 = (bp->phy_addr << 21) | (reg << 16) |
		BNX2_EMAC_MDIO_COMM_COMMAND_READ | BNX2_EMAC_MDIO_COMM_DISEXT |
		BNX2_EMAC_MDIO_COMM_START_BUSY;
	REG_WR(bp, BNX2_EMAC_MDIO_COMM, val1);

	for (i = 0; i < 50; i++) {
		udelay(10);

		val1 = REG_RD(bp, BNX2_EMAC_MDIO_COMM);
		if (!(val1 & BNX2_EMAC_MDIO_COMM_START_BUSY)) {
			udelay(5);

			val1 = REG_RD(bp, BNX2_EMAC_MDIO_COMM);
			val1 &= BNX2_EMAC_MDIO_COMM_DATA;

			break;
		}
	}

	if (val1 & BNX2_EMAC_MDIO_COMM_START_BUSY) {
		*val = 0x0;
		ret = -EBUSY;
	}
	else {
		*val = val1;
		ret = 0;
	}

	if (bp->phy_flags & PHY_INT_MODE_AUTO_POLLING_FLAG) {
		val1 = REG_RD(bp, BNX2_EMAC_MDIO_MODE);
		val1 |= BNX2_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(bp, BNX2_EMAC_MDIO_MODE, val1);
		REG_RD(bp, BNX2_EMAC_MDIO_MODE);

		udelay(40);
	}

	return ret;
}

static int
bnx2_write_phy(struct bnx2 *bp, u32 reg, u32 val)
{
	u32 val1;
	int i, ret;

	if (bp->phy_flags & PHY_INT_MODE_AUTO_POLLING_FLAG) {
		val1 = REG_RD(bp, BNX2_EMAC_MDIO_MODE);
		val1 &= ~BNX2_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(bp, BNX2_EMAC_MDIO_MODE, val1);
		REG_RD(bp, BNX2_EMAC_MDIO_MODE);

		udelay(40);
	}

	val1 = (bp->phy_addr << 21) | (reg << 16) | val |
		BNX2_EMAC_MDIO_COMM_COMMAND_WRITE |
		BNX2_EMAC_MDIO_COMM_START_BUSY | BNX2_EMAC_MDIO_COMM_DISEXT;
	REG_WR(bp, BNX2_EMAC_MDIO_COMM, val1);
    
	for (i = 0; i < 50; i++) {
		udelay(10);

		val1 = REG_RD(bp, BNX2_EMAC_MDIO_COMM);
		if (!(val1 & BNX2_EMAC_MDIO_COMM_START_BUSY)) {
			udelay(5);
			break;
		}
	}

	if (val1 & BNX2_EMAC_MDIO_COMM_START_BUSY)
        	ret = -EBUSY;
	else
		ret = 0;

	if (bp->phy_flags & PHY_INT_MODE_AUTO_POLLING_FLAG) {
		val1 = REG_RD(bp, BNX2_EMAC_MDIO_MODE);
		val1 |= BNX2_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(bp, BNX2_EMAC_MDIO_MODE, val1);
		REG_RD(bp, BNX2_EMAC_MDIO_MODE);

		udelay(40);
	}

	return ret;
}

static void
bnx2_disable_int(struct bnx2 *bp)
{
	REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
	       BNX2_PCICFG_INT_ACK_CMD_MASK_INT);
	REG_RD(bp, BNX2_PCICFG_INT_ACK_CMD);

}

static int
bnx2_alloc_mem(struct bnx2 *bp)
{
	bp->tx_desc_ring = bnx2_bss.tx_desc_ring;
	bp->tx_desc_mapping = virt_to_bus(bp->tx_desc_ring);

	bp->rx_desc_ring = bnx2_bss.rx_desc_ring;
	memset(bp->rx_desc_ring, 0, sizeof(struct rx_bd) * RX_DESC_CNT);
	bp->rx_desc_mapping = virt_to_bus(bp->rx_desc_ring);

	memset(&bnx2_bss.status_blk, 0, sizeof(struct status_block));
	bp->status_blk = &bnx2_bss.status_blk;
	bp->status_blk_mapping = virt_to_bus(&bnx2_bss.status_blk);

	bp->stats_blk = &bnx2_bss.stats_blk;
	memset(&bnx2_bss.stats_blk, 0, sizeof(struct statistics_block));
	bp->stats_blk_mapping = virt_to_bus(&bnx2_bss.stats_blk);

	return 0;
}

static void
bnx2_report_fw_link(struct bnx2 *bp)
{
	u32 fw_link_status = 0;

	if (bp->link_up) {
		u32 bmsr;

		switch (bp->line_speed) {
		case SPEED_10:
			if (bp->duplex == DUPLEX_HALF)
				fw_link_status = BNX2_LINK_STATUS_10HALF;
			else
				fw_link_status = BNX2_LINK_STATUS_10FULL;
			break;
		case SPEED_100:
			if (bp->duplex == DUPLEX_HALF)
				fw_link_status = BNX2_LINK_STATUS_100HALF;
			else
				fw_link_status = BNX2_LINK_STATUS_100FULL;
			break;
		case SPEED_1000:
			if (bp->duplex == DUPLEX_HALF)
				fw_link_status = BNX2_LINK_STATUS_1000HALF;
			else
				fw_link_status = BNX2_LINK_STATUS_1000FULL;
			break;
		case SPEED_2500:
			if (bp->duplex == DUPLEX_HALF)
				fw_link_status = BNX2_LINK_STATUS_2500HALF;
			else
				fw_link_status = BNX2_LINK_STATUS_2500FULL;
			break;
		}

		fw_link_status |= BNX2_LINK_STATUS_LINK_UP;

		if (bp->autoneg) {
			fw_link_status |= BNX2_LINK_STATUS_AN_ENABLED;

			bnx2_read_phy(bp, MII_BMSR, &bmsr);
			bnx2_read_phy(bp, MII_BMSR, &bmsr);

			if (!(bmsr & BMSR_ANEGCOMPLETE) ||
			    bp->phy_flags & PHY_PARALLEL_DETECT_FLAG)
				fw_link_status |= BNX2_LINK_STATUS_PARALLEL_DET;
			else
				fw_link_status |= BNX2_LINK_STATUS_AN_COMPLETE;
		}
	}
	else
		fw_link_status = BNX2_LINK_STATUS_LINK_DOWN;

	REG_WR_IND(bp, bp->shmem_base + BNX2_LINK_STATUS, fw_link_status);
}

static void
bnx2_report_link(struct bnx2 *bp)
{
	if (bp->link_up) {
		printf("NIC Link is Up, ");

		printf("%d Mbps ", bp->line_speed);

		if (bp->duplex == DUPLEX_FULL)
			printf("full duplex");
		else
			printf("half duplex");

		if (bp->flow_ctrl) {
			if (bp->flow_ctrl & FLOW_CTRL_RX) {
				printf(", receive ");
				if (bp->flow_ctrl & FLOW_CTRL_TX)
					printf("& transmit ");
			}
			else {
				printf(", transmit ");
			}
			printf("flow control ON");
		}
		printf("\n");
	}
	else {
		printf("NIC Link is Down\n");
	}

	bnx2_report_fw_link(bp);
}

static void
bnx2_resolve_flow_ctrl(struct bnx2 *bp)
{
	u32 local_adv, remote_adv;

	bp->flow_ctrl = 0;
	if ((bp->autoneg & (AUTONEG_SPEED | AUTONEG_FLOW_CTRL)) != 
		(AUTONEG_SPEED | AUTONEG_FLOW_CTRL)) {

		if (bp->duplex == DUPLEX_FULL) {
			bp->flow_ctrl = bp->req_flow_ctrl;
		}
		return;
	}

	if (bp->duplex != DUPLEX_FULL) {
		return;
	}

	if ((bp->phy_flags & PHY_SERDES_FLAG) &&
	    (CHIP_NUM(bp) == CHIP_NUM_5708)) {
		u32 val;

		bnx2_read_phy(bp, BCM5708S_1000X_STAT1, &val);
		if (val & BCM5708S_1000X_STAT1_TX_PAUSE)
			bp->flow_ctrl |= FLOW_CTRL_TX;
		if (val & BCM5708S_1000X_STAT1_RX_PAUSE)
			bp->flow_ctrl |= FLOW_CTRL_RX;
		return;
	}

	bnx2_read_phy(bp, MII_ADVERTISE, &local_adv);
	bnx2_read_phy(bp, MII_LPA, &remote_adv);

	if (bp->phy_flags & PHY_SERDES_FLAG) {
		u32 new_local_adv = 0;
		u32 new_remote_adv = 0;

		if (local_adv & ADVERTISE_1000XPAUSE)
			new_local_adv |= ADVERTISE_PAUSE_CAP;
		if (local_adv & ADVERTISE_1000XPSE_ASYM)
			new_local_adv |= ADVERTISE_PAUSE_ASYM;
		if (remote_adv & ADVERTISE_1000XPAUSE)
			new_remote_adv |= ADVERTISE_PAUSE_CAP;
		if (remote_adv & ADVERTISE_1000XPSE_ASYM)
			new_remote_adv |= ADVERTISE_PAUSE_ASYM;

		local_adv = new_local_adv;
		remote_adv = new_remote_adv;
	}

	/* See Table 28B-3 of 802.3ab-1999 spec. */
	if (local_adv & ADVERTISE_PAUSE_CAP) {
		if(local_adv & ADVERTISE_PAUSE_ASYM) {
	                if (remote_adv & ADVERTISE_PAUSE_CAP) {
				bp->flow_ctrl = FLOW_CTRL_TX | FLOW_CTRL_RX;
			}
			else if (remote_adv & ADVERTISE_PAUSE_ASYM) {
				bp->flow_ctrl = FLOW_CTRL_RX;
			}
		}
		else {
			if (remote_adv & ADVERTISE_PAUSE_CAP) {
				bp->flow_ctrl = FLOW_CTRL_TX | FLOW_CTRL_RX;
			}
		}
	}
	else if (local_adv & ADVERTISE_PAUSE_ASYM) {
		if ((remote_adv & ADVERTISE_PAUSE_CAP) &&
			(remote_adv & ADVERTISE_PAUSE_ASYM)) {

			bp->flow_ctrl = FLOW_CTRL_TX;
		}
	}
}

static int
bnx2_5708s_linkup(struct bnx2 *bp)
{
	u32 val;

	bp->link_up = 1;
	bnx2_read_phy(bp, BCM5708S_1000X_STAT1, &val);
	switch (val & BCM5708S_1000X_STAT1_SPEED_MASK) {
		case BCM5708S_1000X_STAT1_SPEED_10:
			bp->line_speed = SPEED_10;
			break;
		case BCM5708S_1000X_STAT1_SPEED_100:
			bp->line_speed = SPEED_100;
			break;
		case BCM5708S_1000X_STAT1_SPEED_1G:
			bp->line_speed = SPEED_1000;
			break;
		case BCM5708S_1000X_STAT1_SPEED_2G5:
			bp->line_speed = SPEED_2500;
			break;
	}
	if (val & BCM5708S_1000X_STAT1_FD)
		bp->duplex = DUPLEX_FULL;
	else
		bp->duplex = DUPLEX_HALF;

	return 0;
}

static int
bnx2_5706s_linkup(struct bnx2 *bp)
{
	u32 bmcr, local_adv, remote_adv, common;

	bp->link_up = 1;
	bp->line_speed = SPEED_1000;

	bnx2_read_phy(bp, MII_BMCR, &bmcr);
	if (bmcr & BMCR_FULLDPLX) {
		bp->duplex = DUPLEX_FULL;
	}
	else {
		bp->duplex = DUPLEX_HALF;
	}

	if (!(bmcr & BMCR_ANENABLE)) {
		return 0;
	}

	bnx2_read_phy(bp, MII_ADVERTISE, &local_adv);
	bnx2_read_phy(bp, MII_LPA, &remote_adv);

	common = local_adv & remote_adv;
	if (common & (ADVERTISE_1000XHALF | ADVERTISE_1000XFULL)) {

		if (common & ADVERTISE_1000XFULL) {
			bp->duplex = DUPLEX_FULL;
		}
		else {
			bp->duplex = DUPLEX_HALF;
		}
	}

	return 0;
}

static int
bnx2_copper_linkup(struct bnx2 *bp)
{
	u32 bmcr;

	bnx2_read_phy(bp, MII_BMCR, &bmcr);
	if (bmcr & BMCR_ANENABLE) {
		u32 local_adv, remote_adv, common;

		bnx2_read_phy(bp, MII_CTRL1000, &local_adv);
		bnx2_read_phy(bp, MII_STAT1000, &remote_adv);

		common = local_adv & (remote_adv >> 2);
		if (common & ADVERTISE_1000FULL) {
			bp->line_speed = SPEED_1000;
			bp->duplex = DUPLEX_FULL;
		}
		else if (common & ADVERTISE_1000HALF) {
			bp->line_speed = SPEED_1000;
			bp->duplex = DUPLEX_HALF;
		}
		else {
			bnx2_read_phy(bp, MII_ADVERTISE, &local_adv);
			bnx2_read_phy(bp, MII_LPA, &remote_adv);

			common = local_adv & remote_adv;
			if (common & ADVERTISE_100FULL) {
				bp->line_speed = SPEED_100;
				bp->duplex = DUPLEX_FULL;
			}
			else if (common & ADVERTISE_100HALF) {
				bp->line_speed = SPEED_100;
				bp->duplex = DUPLEX_HALF;
			}
			else if (common & ADVERTISE_10FULL) {
				bp->line_speed = SPEED_10;
				bp->duplex = DUPLEX_FULL;
			}
			else if (common & ADVERTISE_10HALF) {
				bp->line_speed = SPEED_10;
				bp->duplex = DUPLEX_HALF;
			}
			else {
				bp->line_speed = 0;
				bp->link_up = 0;
			}
		}
	}
	else {
		if (bmcr & BMCR_SPEED100) {
			bp->line_speed = SPEED_100;
		}
		else {
			bp->line_speed = SPEED_10;
		}
		if (bmcr & BMCR_FULLDPLX) {
			bp->duplex = DUPLEX_FULL;
		}
		else {
			bp->duplex = DUPLEX_HALF;
		}
	}

	return 0;
}

static int
bnx2_set_mac_link(struct bnx2 *bp)
{
	u32 val;

	REG_WR(bp, BNX2_EMAC_TX_LENGTHS, 0x2620);
	if (bp->link_up && (bp->line_speed == SPEED_1000) &&
		(bp->duplex == DUPLEX_HALF)) {
		REG_WR(bp, BNX2_EMAC_TX_LENGTHS, 0x26ff);
	}

	/* Configure the EMAC mode register. */
	val = REG_RD(bp, BNX2_EMAC_MODE);

	val &= ~(BNX2_EMAC_MODE_PORT | BNX2_EMAC_MODE_HALF_DUPLEX |
		BNX2_EMAC_MODE_MAC_LOOP | BNX2_EMAC_MODE_FORCE_LINK |
		BNX2_EMAC_MODE_25G);

	if (bp->link_up) {
		switch (bp->line_speed) {
			case SPEED_10:
				if (CHIP_NUM(bp) == CHIP_NUM_5708) {
					val |= BNX2_EMAC_MODE_PORT_MII_10;
					break;
				}
				/* fall through */
			case SPEED_100:
				val |= BNX2_EMAC_MODE_PORT_MII;
				break;
			case SPEED_2500:
				val |= BNX2_EMAC_MODE_25G;
				/* fall through */
			case SPEED_1000:
				val |= BNX2_EMAC_MODE_PORT_GMII;
				break;
		}
	}
	else {
		val |= BNX2_EMAC_MODE_PORT_GMII;
	}

	/* Set the MAC to operate in the appropriate duplex mode. */
	if (bp->duplex == DUPLEX_HALF)
		val |= BNX2_EMAC_MODE_HALF_DUPLEX;
	REG_WR(bp, BNX2_EMAC_MODE, val);

	/* Enable/disable rx PAUSE. */
	bp->rx_mode &= ~BNX2_EMAC_RX_MODE_FLOW_EN;

	if (bp->flow_ctrl & FLOW_CTRL_RX)
		bp->rx_mode |= BNX2_EMAC_RX_MODE_FLOW_EN;
	REG_WR(bp, BNX2_EMAC_RX_MODE, bp->rx_mode);

	/* Enable/disable tx PAUSE. */
	val = REG_RD(bp, BNX2_EMAC_TX_MODE);
	val &= ~BNX2_EMAC_TX_MODE_FLOW_EN;

	if (bp->flow_ctrl & FLOW_CTRL_TX)
		val |= BNX2_EMAC_TX_MODE_FLOW_EN;
	REG_WR(bp, BNX2_EMAC_TX_MODE, val);

	/* Acknowledge the interrupt. */
	REG_WR(bp, BNX2_EMAC_STATUS, BNX2_EMAC_STATUS_LINK_CHANGE);

	return 0;
}

static int
bnx2_set_link(struct bnx2 *bp)
{
	u32 bmsr;
	u8 link_up;

	if (bp->loopback == MAC_LOOPBACK) {
		bp->link_up = 1;
		return 0;
	}

	link_up = bp->link_up;

	bnx2_read_phy(bp, MII_BMSR, &bmsr);
	bnx2_read_phy(bp, MII_BMSR, &bmsr);

	if ((bp->phy_flags & PHY_SERDES_FLAG) &&
	    (CHIP_NUM(bp) == CHIP_NUM_5706)) {
		u32 val;

		val = REG_RD(bp, BNX2_EMAC_STATUS);
		if (val & BNX2_EMAC_STATUS_LINK)
			bmsr |= BMSR_LSTATUS;
		else
			bmsr &= ~BMSR_LSTATUS;
	}

	if (bmsr & BMSR_LSTATUS) {
		bp->link_up = 1;

		if (bp->phy_flags & PHY_SERDES_FLAG) {
			if (CHIP_NUM(bp) == CHIP_NUM_5706)
				bnx2_5706s_linkup(bp);
			else if (CHIP_NUM(bp) == CHIP_NUM_5708)
				bnx2_5708s_linkup(bp);
		}
		else {
			bnx2_copper_linkup(bp);
		}
		bnx2_resolve_flow_ctrl(bp);
	}
	else {
		if ((bp->phy_flags & PHY_SERDES_FLAG) &&
			(bp->autoneg & AUTONEG_SPEED)) {

			u32 bmcr;

			bnx2_read_phy(bp, MII_BMCR, &bmcr);
			if (!(bmcr & BMCR_ANENABLE)) {
				bnx2_write_phy(bp, MII_BMCR, bmcr |
					BMCR_ANENABLE);
			}
		}
		bp->phy_flags &= ~PHY_PARALLEL_DETECT_FLAG;
		bp->link_up = 0;
	}

	if (bp->link_up != link_up) {
		bnx2_report_link(bp);
	}

	bnx2_set_mac_link(bp);

	return 0;
}

static int
bnx2_reset_phy(struct bnx2 *bp)
{
	int i;
	u32 reg;

        bnx2_write_phy(bp, MII_BMCR, BMCR_RESET);

#define PHY_RESET_MAX_WAIT 100
	for (i = 0; i < PHY_RESET_MAX_WAIT; i++) {
		udelay(10);

		bnx2_read_phy(bp, MII_BMCR, &reg);
		if (!(reg & BMCR_RESET)) {
			udelay(20);
			break;
		}
	}
	if (i == PHY_RESET_MAX_WAIT) {
		return -EBUSY;
	}
	return 0;
}

static u32
bnx2_phy_get_pause_adv(struct bnx2 *bp)
{
	u32 adv = 0;

	if ((bp->req_flow_ctrl & (FLOW_CTRL_RX | FLOW_CTRL_TX)) ==
		(FLOW_CTRL_RX | FLOW_CTRL_TX)) {

		if (bp->phy_flags & PHY_SERDES_FLAG) {
			adv = ADVERTISE_1000XPAUSE;
		}
		else {
			adv = ADVERTISE_PAUSE_CAP;
		}
	}
	else if (bp->req_flow_ctrl & FLOW_CTRL_TX) {
		if (bp->phy_flags & PHY_SERDES_FLAG) {
			adv = ADVERTISE_1000XPSE_ASYM;
		}
		else {
			adv = ADVERTISE_PAUSE_ASYM;
		}
	}
	else if (bp->req_flow_ctrl & FLOW_CTRL_RX) {
		if (bp->phy_flags & PHY_SERDES_FLAG) {
			adv = ADVERTISE_1000XPAUSE | ADVERTISE_1000XPSE_ASYM;
		}
		else {
			adv = ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;
		}
	}
	return adv;
}

static int
bnx2_setup_serdes_phy(struct bnx2 *bp)
{
	u32 adv, bmcr, up1;
	u32 new_adv = 0;

	if (!(bp->autoneg & AUTONEG_SPEED)) {
		u32 new_bmcr;
		int force_link_down = 0;

		if (CHIP_NUM(bp) == CHIP_NUM_5708) {
			bnx2_read_phy(bp, BCM5708S_UP1, &up1);
			if (up1 & BCM5708S_UP1_2G5) {
				up1 &= ~BCM5708S_UP1_2G5;
				bnx2_write_phy(bp, BCM5708S_UP1, up1);
				force_link_down = 1;
			}
		}

		bnx2_read_phy(bp, MII_ADVERTISE, &adv);
		adv &= ~(ADVERTISE_1000XFULL | ADVERTISE_1000XHALF);

		bnx2_read_phy(bp, MII_BMCR, &bmcr);
		new_bmcr = bmcr & ~BMCR_ANENABLE;
		new_bmcr |= BMCR_SPEED1000;
		if (bp->req_duplex == DUPLEX_FULL) {
			adv |= ADVERTISE_1000XFULL;
			new_bmcr |= BMCR_FULLDPLX;
		}
		else {
			adv |= ADVERTISE_1000XHALF;
			new_bmcr &= ~BMCR_FULLDPLX;
		}
		if ((new_bmcr != bmcr) || (force_link_down)) {
			/* Force a link down visible on the other side */
			if (bp->link_up) {
				bnx2_write_phy(bp, MII_ADVERTISE, adv &
					       ~(ADVERTISE_1000XFULL |
						 ADVERTISE_1000XHALF));
				bnx2_write_phy(bp, MII_BMCR, bmcr |
					BMCR_ANRESTART | BMCR_ANENABLE);

				bp->link_up = 0;
				bnx2_write_phy(bp, MII_BMCR, new_bmcr);
			}
			bnx2_write_phy(bp, MII_ADVERTISE, adv);
			bnx2_write_phy(bp, MII_BMCR, new_bmcr);
		}
		return 0;
	}

	if (bp->phy_flags & PHY_2_5G_CAPABLE_FLAG) {
		bnx2_read_phy(bp, BCM5708S_UP1, &up1);
		up1 |= BCM5708S_UP1_2G5;
		bnx2_write_phy(bp, BCM5708S_UP1, up1);
	}

	if (bp->advertising & ADVERTISED_1000baseT_Full)
		new_adv |= ADVERTISE_1000XFULL;

	new_adv |= bnx2_phy_get_pause_adv(bp);

	bnx2_read_phy(bp, MII_ADVERTISE, &adv);
	bnx2_read_phy(bp, MII_BMCR, &bmcr);

	bp->serdes_an_pending = 0;
	if ((adv != new_adv) || ((bmcr & BMCR_ANENABLE) == 0)) {
		/* Force a link down visible on the other side */
		if (bp->link_up) {
			int i;

			bnx2_write_phy(bp, MII_BMCR, BMCR_LOOPBACK);
			for (i = 0; i < 110; i++) {
				udelay(100);
			}
		}

		bnx2_write_phy(bp, MII_ADVERTISE, new_adv);
		bnx2_write_phy(bp, MII_BMCR, bmcr | BMCR_ANRESTART |
			BMCR_ANENABLE);
#if 0
		if (CHIP_NUM(bp) == CHIP_NUM_5706) {
			/* Speed up link-up time when the link partner
			 * does not autonegotiate which is very common
			 * in blade servers. Some blade servers use
			 * IPMI for kerboard input and it's important
			 * to minimize link disruptions. Autoneg. involves
			 * exchanging base pages plus 3 next pages and
			 * normally completes in about 120 msec.
			 */
			bp->current_interval = SERDES_AN_TIMEOUT;
			bp->serdes_an_pending = 1;
			mod_timer(&bp->timer, jiffies + bp->current_interval);
		}
#endif
	}

	return 0;
}

#define ETHTOOL_ALL_FIBRE_SPEED						\
	(ADVERTISED_1000baseT_Full)

#define ETHTOOL_ALL_COPPER_SPEED					\
	(ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full |		\
	ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full |		\
	ADVERTISED_1000baseT_Full)

#define PHY_ALL_10_100_SPEED (ADVERTISE_10HALF | ADVERTISE_10FULL | \
	ADVERTISE_100HALF | ADVERTISE_100FULL | ADVERTISE_CSMA)
	
#define PHY_ALL_1000_SPEED (ADVERTISE_1000HALF | ADVERTISE_1000FULL)

static int
bnx2_setup_copper_phy(struct bnx2 *bp)
{
	u32 bmcr;
	u32 new_bmcr;

	bnx2_read_phy(bp, MII_BMCR, &bmcr);

	if (bp->autoneg & AUTONEG_SPEED) {
		u32 adv_reg, adv1000_reg;
		u32 new_adv_reg = 0;
		u32 new_adv1000_reg = 0;

		bnx2_read_phy(bp, MII_ADVERTISE, &adv_reg);
		adv_reg &= (PHY_ALL_10_100_SPEED | ADVERTISE_PAUSE_CAP |
			ADVERTISE_PAUSE_ASYM);

		bnx2_read_phy(bp, MII_CTRL1000, &adv1000_reg);
		adv1000_reg &= PHY_ALL_1000_SPEED;

		if (bp->advertising & ADVERTISED_10baseT_Half)
			new_adv_reg |= ADVERTISE_10HALF;
		if (bp->advertising & ADVERTISED_10baseT_Full)
			new_adv_reg |= ADVERTISE_10FULL;
		if (bp->advertising & ADVERTISED_100baseT_Half)
			new_adv_reg |= ADVERTISE_100HALF;
		if (bp->advertising & ADVERTISED_100baseT_Full)
			new_adv_reg |= ADVERTISE_100FULL;
		if (bp->advertising & ADVERTISED_1000baseT_Full)
			new_adv1000_reg |= ADVERTISE_1000FULL;
		
		new_adv_reg |= ADVERTISE_CSMA;

		new_adv_reg |= bnx2_phy_get_pause_adv(bp);

		if ((adv1000_reg != new_adv1000_reg) ||
			(adv_reg != new_adv_reg) ||
			((bmcr & BMCR_ANENABLE) == 0)) {

			bnx2_write_phy(bp, MII_ADVERTISE, new_adv_reg);
			bnx2_write_phy(bp, MII_CTRL1000, new_adv1000_reg);
			bnx2_write_phy(bp, MII_BMCR, BMCR_ANRESTART |
				BMCR_ANENABLE);
		}
		else if (bp->link_up) {
			/* Flow ctrl may have changed from auto to forced */
			/* or vice-versa. */

			bnx2_resolve_flow_ctrl(bp);
			bnx2_set_mac_link(bp);
		}
		return 0;
	}

	new_bmcr = 0;
	if (bp->req_line_speed == SPEED_100) {
		new_bmcr |= BMCR_SPEED100;
	}
	if (bp->req_duplex == DUPLEX_FULL) {
		new_bmcr |= BMCR_FULLDPLX;
	}
	if (new_bmcr != bmcr) {
		u32 bmsr;
		int i = 0;

		bnx2_read_phy(bp, MII_BMSR, &bmsr);
		bnx2_read_phy(bp, MII_BMSR, &bmsr);
		
		if (bmsr & BMSR_LSTATUS) {
			/* Force link down */
			bnx2_write_phy(bp, MII_BMCR, BMCR_LOOPBACK);
			do {
				udelay(100);
				bnx2_read_phy(bp, MII_BMSR, &bmsr);
				bnx2_read_phy(bp, MII_BMSR, &bmsr);
				i++;
			} while ((bmsr & BMSR_LSTATUS) && (i < 620));
		}

		bnx2_write_phy(bp, MII_BMCR, new_bmcr);

		/* Normally, the new speed is setup after the link has
		 * gone down and up again. In some cases, link will not go
		 * down so we need to set up the new speed here.
		 */
		if (bmsr & BMSR_LSTATUS) {
			bp->line_speed = bp->req_line_speed;
			bp->duplex = bp->req_duplex;
			bnx2_resolve_flow_ctrl(bp);
			bnx2_set_mac_link(bp);
		}
	}
	return 0;
}

static int
bnx2_setup_phy(struct bnx2 *bp)
{
	if (bp->loopback == MAC_LOOPBACK)
		return 0;

	if (bp->phy_flags & PHY_SERDES_FLAG) {
		return (bnx2_setup_serdes_phy(bp));
	}
	else {
		return (bnx2_setup_copper_phy(bp));
	}
}

static int
bnx2_init_5708s_phy(struct bnx2 *bp)
{
	u32 val;

	bnx2_write_phy(bp, BCM5708S_BLK_ADDR, BCM5708S_BLK_ADDR_DIG3);
	bnx2_write_phy(bp, BCM5708S_DIG_3_0, BCM5708S_DIG_3_0_USE_IEEE);
	bnx2_write_phy(bp, BCM5708S_BLK_ADDR, BCM5708S_BLK_ADDR_DIG);

	bnx2_read_phy(bp, BCM5708S_1000X_CTL1, &val);
	val |= BCM5708S_1000X_CTL1_FIBER_MODE | BCM5708S_1000X_CTL1_AUTODET_EN;
	bnx2_write_phy(bp, BCM5708S_1000X_CTL1, val);

	bnx2_read_phy(bp, BCM5708S_1000X_CTL2, &val);
	val |= BCM5708S_1000X_CTL2_PLLEL_DET_EN;
	bnx2_write_phy(bp, BCM5708S_1000X_CTL2, val);

	if (bp->phy_flags & PHY_2_5G_CAPABLE_FLAG) {
		bnx2_read_phy(bp, BCM5708S_UP1, &val);
		val |= BCM5708S_UP1_2G5;
		bnx2_write_phy(bp, BCM5708S_UP1, val);
	}

	if ((CHIP_ID(bp) == CHIP_ID_5708_A0) ||
	    (CHIP_ID(bp) == CHIP_ID_5708_B0) ||
	    (CHIP_ID(bp) == CHIP_ID_5708_B1)) {
		/* increase tx signal amplitude */
		bnx2_write_phy(bp, BCM5708S_BLK_ADDR,
			       BCM5708S_BLK_ADDR_TX_MISC);
		bnx2_read_phy(bp, BCM5708S_TX_ACTL1, &val);
		val &= ~BCM5708S_TX_ACTL1_DRIVER_VCM;
		bnx2_write_phy(bp, BCM5708S_TX_ACTL1, val);
		bnx2_write_phy(bp, BCM5708S_BLK_ADDR, BCM5708S_BLK_ADDR_DIG);
	}

	val = REG_RD_IND(bp, bp->shmem_base + BNX2_PORT_HW_CFG_CONFIG) &
	      BNX2_PORT_HW_CFG_CFG_TXCTL3_MASK;

	if (val) {
		u32 is_backplane;

		is_backplane = REG_RD_IND(bp, bp->shmem_base +
					  BNX2_SHARED_HW_CFG_CONFIG);
		if (is_backplane & BNX2_SHARED_HW_CFG_PHY_BACKPLANE) {
			bnx2_write_phy(bp, BCM5708S_BLK_ADDR,
				       BCM5708S_BLK_ADDR_TX_MISC);
			bnx2_write_phy(bp, BCM5708S_TX_ACTL3, val);
			bnx2_write_phy(bp, BCM5708S_BLK_ADDR,
				       BCM5708S_BLK_ADDR_DIG);
		}
	}
	return 0;
}

static int
bnx2_init_5706s_phy(struct bnx2 *bp)
{
	u32 val;

	bp->phy_flags &= ~PHY_PARALLEL_DETECT_FLAG;

	if (CHIP_NUM(bp) == CHIP_NUM_5706) {
        	REG_WR(bp, BNX2_MISC_UNUSED0, 0x300);
	}


	bnx2_write_phy(bp, 0x18, 0x7);
	bnx2_read_phy(bp, 0x18, &val);
	bnx2_write_phy(bp, 0x18, val & ~0x4007);

	bnx2_write_phy(bp, 0x1c, 0x6c00);
	bnx2_read_phy(bp, 0x1c, &val);
	bnx2_write_phy(bp, 0x1c, (val & 0x3fd) | 0xec00);

	return 0;
}

static int
bnx2_init_copper_phy(struct bnx2 *bp)
{
	u32 val;

	bp->phy_flags |= PHY_CRC_FIX_FLAG;

	if (bp->phy_flags & PHY_CRC_FIX_FLAG) {
		bnx2_write_phy(bp, 0x18, 0x0c00);
		bnx2_write_phy(bp, 0x17, 0x000a);
		bnx2_write_phy(bp, 0x15, 0x310b);
		bnx2_write_phy(bp, 0x17, 0x201f);
		bnx2_write_phy(bp, 0x15, 0x9506);
		bnx2_write_phy(bp, 0x17, 0x401f);
		bnx2_write_phy(bp, 0x15, 0x14e2);
		bnx2_write_phy(bp, 0x18, 0x0400);
	}

	bnx2_write_phy(bp, 0x18, 0x7);
	bnx2_read_phy(bp, 0x18, &val);
	bnx2_write_phy(bp, 0x18, val & ~0x4007);

	bnx2_read_phy(bp, 0x10, &val);
	bnx2_write_phy(bp, 0x10, val & ~0x1);

	/* ethernet@wirespeed */
	bnx2_write_phy(bp, 0x18, 0x7007);
	bnx2_read_phy(bp, 0x18, &val);
	bnx2_write_phy(bp, 0x18, val | (1 << 15) | (1 << 4));
	return 0;
}

static int
bnx2_init_phy(struct bnx2 *bp)
{
	u32 val;
	int rc = 0;

	bp->phy_flags &= ~PHY_INT_MODE_MASK_FLAG;
	bp->phy_flags |= PHY_INT_MODE_LINK_READY_FLAG;

        REG_WR(bp, BNX2_EMAC_ATTENTION_ENA, BNX2_EMAC_ATTENTION_ENA_LINK);

	bnx2_reset_phy(bp);

	bnx2_read_phy(bp, MII_PHYSID1, &val);
	bp->phy_id = val << 16;
	bnx2_read_phy(bp, MII_PHYSID2, &val);
	bp->phy_id |= val & 0xffff;

	if (bp->phy_flags & PHY_SERDES_FLAG) {
		if (CHIP_NUM(bp) == CHIP_NUM_5706)
			rc = bnx2_init_5706s_phy(bp);
		else if (CHIP_NUM(bp) == CHIP_NUM_5708)
			rc = bnx2_init_5708s_phy(bp);
	}
	else {
		rc = bnx2_init_copper_phy(bp);
	}

	bnx2_setup_phy(bp);

	return rc;
}

static int
bnx2_fw_sync(struct bnx2 *bp, u32 msg_data, int silent)
{
	int i;
	u32 val;

	bp->fw_wr_seq++;
	msg_data |= bp->fw_wr_seq;

	REG_WR_IND(bp, bp->shmem_base + BNX2_DRV_MB, msg_data);

	/* wait for an acknowledgement. */
	for (i = 0; i < (FW_ACK_TIME_OUT_MS / 50); i++) {
		mdelay(50);

		val = REG_RD_IND(bp, bp->shmem_base + BNX2_FW_MB);

		if ((val & BNX2_FW_MSG_ACK) == (msg_data & BNX2_DRV_MSG_SEQ))
			break;
	}
	if ((msg_data & BNX2_DRV_MSG_DATA) == BNX2_DRV_MSG_DATA_WAIT0)
		return 0;

	/* If we timed out, inform the firmware that this is the case. */
	if ((val & BNX2_FW_MSG_ACK) != (msg_data & BNX2_DRV_MSG_SEQ)) {
		if (!silent)
		  printf("fw sync timeout, reset code = %x\n", (unsigned int) msg_data);

		msg_data &= ~BNX2_DRV_MSG_CODE;
		msg_data |= BNX2_DRV_MSG_CODE_FW_TIMEOUT;

		REG_WR_IND(bp, bp->shmem_base + BNX2_DRV_MB, msg_data);

		return -EBUSY;
	}

	if ((val & BNX2_FW_MSG_STATUS_MASK) != BNX2_FW_MSG_STATUS_OK)
		return -EIO;

	return 0;
}

static void
bnx2_init_context(struct bnx2 *bp)
{
	u32 vcid;

	vcid = 96;
	while (vcid) {
		u32 vcid_addr, pcid_addr, offset;

		vcid--;

		if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
			u32 new_vcid;

			vcid_addr = GET_PCID_ADDR(vcid);
			if (vcid & 0x8) {
				new_vcid = 0x60 + (vcid & 0xf0) + (vcid & 0x7);
			}
			else {
				new_vcid = vcid;
			}
			pcid_addr = GET_PCID_ADDR(new_vcid);
		}
		else {
	    		vcid_addr = GET_CID_ADDR(vcid);
			pcid_addr = vcid_addr;
		}

		REG_WR(bp, BNX2_CTX_VIRT_ADDR, 0x00);
		REG_WR(bp, BNX2_CTX_PAGE_TBL, pcid_addr);

		/* Zero out the context. */
		for (offset = 0; offset < PHY_CTX_SIZE; offset += 4) {
			CTX_WR(bp, 0x00, offset, 0);
		}

		REG_WR(bp, BNX2_CTX_VIRT_ADDR, vcid_addr);
		REG_WR(bp, BNX2_CTX_PAGE_TBL, pcid_addr);
	}
}

static int
bnx2_alloc_bad_rbuf(struct bnx2 *bp)
{
	u16 good_mbuf[512];
	u32 good_mbuf_cnt;
	u32 val;

	REG_WR(bp, BNX2_MISC_ENABLE_SET_BITS,
		BNX2_MISC_ENABLE_SET_BITS_RX_MBUF_ENABLE);

	good_mbuf_cnt = 0;

	/* Allocate a bunch of mbufs and save the good ones in an array. */
	val = REG_RD_IND(bp, BNX2_RBUF_STATUS1);
	while (val & BNX2_RBUF_STATUS1_FREE_COUNT) {
		REG_WR_IND(bp, BNX2_RBUF_COMMAND, BNX2_RBUF_COMMAND_ALLOC_REQ);

		val = REG_RD_IND(bp, BNX2_RBUF_FW_BUF_ALLOC);

		val &= BNX2_RBUF_FW_BUF_ALLOC_VALUE;

		/* The addresses with Bit 9 set are bad memory blocks. */
		if (!(val & (1 << 9))) {
			good_mbuf[good_mbuf_cnt] = (u16) val;
			good_mbuf_cnt++;
		}

		val = REG_RD_IND(bp, BNX2_RBUF_STATUS1);
	}

	/* Free the good ones back to the mbuf pool thus discarding
	 * all the bad ones. */
	while (good_mbuf_cnt) {
		good_mbuf_cnt--;

		val = good_mbuf[good_mbuf_cnt];
		val = (val << 9) | val | 1;

		REG_WR_IND(bp, BNX2_RBUF_FW_BUF_FREE, val);
	}
	return 0;
}

static void
bnx2_set_mac_addr(struct bnx2 *bp) 
{
	u32 val;
	u8 *mac_addr = bp->nic->node_addr;

	val = (mac_addr[0] << 8) | mac_addr[1];

	REG_WR(bp, BNX2_EMAC_MAC_MATCH0, val);

	val = (mac_addr[2] << 24) | (mac_addr[3] << 16) | 
		(mac_addr[4] << 8) | mac_addr[5];

	REG_WR(bp, BNX2_EMAC_MAC_MATCH1, val);
}

static void
bnx2_set_rx_mode(struct nic *nic __unused)
{
	struct bnx2 *bp = &bnx2;
	u32 rx_mode, sort_mode;
	int i;

	rx_mode = bp->rx_mode & ~(BNX2_EMAC_RX_MODE_PROMISCUOUS |
				  BNX2_EMAC_RX_MODE_KEEP_VLAN_TAG);
	sort_mode = 1 | BNX2_RPM_SORT_USER0_BC_EN;

	if (!(bp->flags & ASF_ENABLE_FLAG)) {
		rx_mode |= BNX2_EMAC_RX_MODE_KEEP_VLAN_TAG;
	}

	/* Accept all multicasts */
	for (i = 0; i < NUM_MC_HASH_REGISTERS; i++) {
		REG_WR(bp, BNX2_EMAC_MULTICAST_HASH0 + (i * 4),
		       0xffffffff);
       	}
	sort_mode |= BNX2_RPM_SORT_USER0_MC_EN;

	if (rx_mode != bp->rx_mode) {
		bp->rx_mode = rx_mode;
		REG_WR(bp, BNX2_EMAC_RX_MODE, rx_mode);
	}

	REG_WR(bp, BNX2_RPM_SORT_USER0, 0x0);
	REG_WR(bp, BNX2_RPM_SORT_USER0, sort_mode);
	REG_WR(bp, BNX2_RPM_SORT_USER0, sort_mode | BNX2_RPM_SORT_USER0_ENA);
}

static void
load_rv2p_fw(struct bnx2 *bp, u32 *rv2p_code, u32 rv2p_code_len, u32 rv2p_proc)
{
	unsigned int i;
	u32 val;


	for (i = 0; i < rv2p_code_len; i += 8) {
		REG_WR(bp, BNX2_RV2P_INSTR_HIGH, *rv2p_code);
		rv2p_code++;
		REG_WR(bp, BNX2_RV2P_INSTR_LOW, *rv2p_code);
		rv2p_code++;

		if (rv2p_proc == RV2P_PROC1) {
			val = (i / 8) | BNX2_RV2P_PROC1_ADDR_CMD_RDWR;
			REG_WR(bp, BNX2_RV2P_PROC1_ADDR_CMD, val);
		}
		else {
			val = (i / 8) | BNX2_RV2P_PROC2_ADDR_CMD_RDWR;
			REG_WR(bp, BNX2_RV2P_PROC2_ADDR_CMD, val);
		}
	}

	/* Reset the processor, un-stall is done later. */
	if (rv2p_proc == RV2P_PROC1) {
		REG_WR(bp, BNX2_RV2P_COMMAND, BNX2_RV2P_COMMAND_PROC1_RESET);
	}
	else {
		REG_WR(bp, BNX2_RV2P_COMMAND, BNX2_RV2P_COMMAND_PROC2_RESET);
	}
}

static void
load_cpu_fw(struct bnx2 *bp, struct cpu_reg *cpu_reg, struct fw_info *fw)
{
	u32 offset;
	u32 val;

	/* Halt the CPU. */
	val = REG_RD_IND(bp, cpu_reg->mode);
	val |= cpu_reg->mode_value_halt;
	REG_WR_IND(bp, cpu_reg->mode, val);
	REG_WR_IND(bp, cpu_reg->state, cpu_reg->state_value_clear);

	/* Load the Text area. */
	offset = cpu_reg->spad_base + (fw->text_addr - cpu_reg->mips_view_base);
	if (fw->text) {
		unsigned int j;

		for (j = 0; j < (fw->text_len / 4); j++, offset += 4) {
			REG_WR_IND(bp, offset, fw->text[j]);
	        }
	}

	/* Load the Data area. */
	offset = cpu_reg->spad_base + (fw->data_addr - cpu_reg->mips_view_base);
	if (fw->data) {
		unsigned int j;

		for (j = 0; j < (fw->data_len / 4); j++, offset += 4) {
			REG_WR_IND(bp, offset, fw->data[j]);
		}
	}

	/* Load the SBSS area. */
	offset = cpu_reg->spad_base + (fw->sbss_addr - cpu_reg->mips_view_base);
	if (fw->sbss) {
		unsigned int j;

		for (j = 0; j < (fw->sbss_len / 4); j++, offset += 4) {
			REG_WR_IND(bp, offset, fw->sbss[j]);
		}
	}

	/* Load the BSS area. */
	offset = cpu_reg->spad_base + (fw->bss_addr - cpu_reg->mips_view_base);
	if (fw->bss) {
		unsigned int j;

		for (j = 0; j < (fw->bss_len/4); j++, offset += 4) {
			REG_WR_IND(bp, offset, fw->bss[j]);
		}
	}

	/* Load the Read-Only area. */
	offset = cpu_reg->spad_base +
		(fw->rodata_addr - cpu_reg->mips_view_base);
	if (fw->rodata) {
		unsigned int j;

		for (j = 0; j < (fw->rodata_len / 4); j++, offset += 4) {
			REG_WR_IND(bp, offset, fw->rodata[j]);
		}
	}

	/* Clear the pre-fetch instruction. */
	REG_WR_IND(bp, cpu_reg->inst, 0);
	REG_WR_IND(bp, cpu_reg->pc, fw->start_addr);

	/* Start the CPU. */
	val = REG_RD_IND(bp, cpu_reg->mode);
	val &= ~cpu_reg->mode_value_halt;
	REG_WR_IND(bp, cpu_reg->state, cpu_reg->state_value_clear);
	REG_WR_IND(bp, cpu_reg->mode, val);
}

static void
bnx2_init_cpus(struct bnx2 *bp)
{
	struct cpu_reg cpu_reg;
	struct fw_info fw;

	/* Unfortunately, it looks like we need to load the firmware
	 * before the card will work properly.  That means this driver
	 * will be huge by Etherboot standards (approx. 50K compressed).
	 */

	/* Initialize the RV2P processor. */
	load_rv2p_fw(bp, bnx2_rv2p_proc1, sizeof(bnx2_rv2p_proc1), RV2P_PROC1);
	load_rv2p_fw(bp, bnx2_rv2p_proc2, sizeof(bnx2_rv2p_proc2), RV2P_PROC2);

	/* Initialize the RX Processor. */
	cpu_reg.mode = BNX2_RXP_CPU_MODE;
	cpu_reg.mode_value_halt = BNX2_RXP_CPU_MODE_SOFT_HALT;
	cpu_reg.mode_value_sstep = BNX2_RXP_CPU_MODE_STEP_ENA;
	cpu_reg.state = BNX2_RXP_CPU_STATE;
	cpu_reg.state_value_clear = 0xffffff;
	cpu_reg.gpr0 = BNX2_RXP_CPU_REG_FILE;
	cpu_reg.evmask = BNX2_RXP_CPU_EVENT_MASK;
	cpu_reg.pc = BNX2_RXP_CPU_PROGRAM_COUNTER;
	cpu_reg.inst = BNX2_RXP_CPU_INSTRUCTION;
	cpu_reg.bp = BNX2_RXP_CPU_HW_BREAKPOINT;
	cpu_reg.spad_base = BNX2_RXP_SCRATCH;
	cpu_reg.mips_view_base = 0x8000000;

	fw.ver_major = bnx2_RXP_b06FwReleaseMajor;
	fw.ver_minor = bnx2_RXP_b06FwReleaseMinor;
	fw.ver_fix = bnx2_RXP_b06FwReleaseFix;
	fw.start_addr = bnx2_RXP_b06FwStartAddr;

	fw.text_addr = bnx2_RXP_b06FwTextAddr;
	fw.text_len = bnx2_RXP_b06FwTextLen;
	fw.text_index = 0;
	fw.text = bnx2_RXP_b06FwText;

	fw.data_addr = bnx2_RXP_b06FwDataAddr;
	fw.data_len = bnx2_RXP_b06FwDataLen;
	fw.data_index = 0;
	fw.data = bnx2_RXP_b06FwData;

	fw.sbss_addr = bnx2_RXP_b06FwSbssAddr;
	fw.sbss_len = bnx2_RXP_b06FwSbssLen;
	fw.sbss_index = 0;
	fw.sbss = bnx2_RXP_b06FwSbss;

	fw.bss_addr = bnx2_RXP_b06FwBssAddr;
	fw.bss_len = bnx2_RXP_b06FwBssLen;
	fw.bss_index = 0;
	fw.bss = bnx2_RXP_b06FwBss;

	fw.rodata_addr = bnx2_RXP_b06FwRodataAddr;
	fw.rodata_len = bnx2_RXP_b06FwRodataLen;
	fw.rodata_index = 0;
	fw.rodata = bnx2_RXP_b06FwRodata;

	load_cpu_fw(bp, &cpu_reg, &fw);

	/* Initialize the TX Processor. */
	cpu_reg.mode = BNX2_TXP_CPU_MODE;
	cpu_reg.mode_value_halt = BNX2_TXP_CPU_MODE_SOFT_HALT;
	cpu_reg.mode_value_sstep = BNX2_TXP_CPU_MODE_STEP_ENA;
	cpu_reg.state = BNX2_TXP_CPU_STATE;
	cpu_reg.state_value_clear = 0xffffff;
	cpu_reg.gpr0 = BNX2_TXP_CPU_REG_FILE;
	cpu_reg.evmask = BNX2_TXP_CPU_EVENT_MASK;
	cpu_reg.pc = BNX2_TXP_CPU_PROGRAM_COUNTER;
	cpu_reg.inst = BNX2_TXP_CPU_INSTRUCTION;
	cpu_reg.bp = BNX2_TXP_CPU_HW_BREAKPOINT;
	cpu_reg.spad_base = BNX2_TXP_SCRATCH;
	cpu_reg.mips_view_base = 0x8000000;
    
	fw.ver_major = bnx2_TXP_b06FwReleaseMajor;
	fw.ver_minor = bnx2_TXP_b06FwReleaseMinor;
	fw.ver_fix = bnx2_TXP_b06FwReleaseFix;
	fw.start_addr = bnx2_TXP_b06FwStartAddr;

	fw.text_addr = bnx2_TXP_b06FwTextAddr;
	fw.text_len = bnx2_TXP_b06FwTextLen;
	fw.text_index = 0;
	fw.text = bnx2_TXP_b06FwText;

	fw.data_addr = bnx2_TXP_b06FwDataAddr;
	fw.data_len = bnx2_TXP_b06FwDataLen;
	fw.data_index = 0;
	fw.data = bnx2_TXP_b06FwData;

	fw.sbss_addr = bnx2_TXP_b06FwSbssAddr;
	fw.sbss_len = bnx2_TXP_b06FwSbssLen;
	fw.sbss_index = 0;
	fw.sbss = bnx2_TXP_b06FwSbss;

	fw.bss_addr = bnx2_TXP_b06FwBssAddr;
	fw.bss_len = bnx2_TXP_b06FwBssLen;
	fw.bss_index = 0;
	fw.bss = bnx2_TXP_b06FwBss;

	fw.rodata_addr = bnx2_TXP_b06FwRodataAddr;
	fw.rodata_len = bnx2_TXP_b06FwRodataLen;
	fw.rodata_index = 0;
	fw.rodata = bnx2_TXP_b06FwRodata;

	load_cpu_fw(bp, &cpu_reg, &fw);

	/* Initialize the TX Patch-up Processor. */
	cpu_reg.mode = BNX2_TPAT_CPU_MODE;
	cpu_reg.mode_value_halt = BNX2_TPAT_CPU_MODE_SOFT_HALT;
	cpu_reg.mode_value_sstep = BNX2_TPAT_CPU_MODE_STEP_ENA;
	cpu_reg.state = BNX2_TPAT_CPU_STATE;
	cpu_reg.state_value_clear = 0xffffff;
	cpu_reg.gpr0 = BNX2_TPAT_CPU_REG_FILE;
	cpu_reg.evmask = BNX2_TPAT_CPU_EVENT_MASK;
	cpu_reg.pc = BNX2_TPAT_CPU_PROGRAM_COUNTER;
	cpu_reg.inst = BNX2_TPAT_CPU_INSTRUCTION;
	cpu_reg.bp = BNX2_TPAT_CPU_HW_BREAKPOINT;
	cpu_reg.spad_base = BNX2_TPAT_SCRATCH;
	cpu_reg.mips_view_base = 0x8000000;
    
	fw.ver_major = bnx2_TPAT_b06FwReleaseMajor;
	fw.ver_minor = bnx2_TPAT_b06FwReleaseMinor;
	fw.ver_fix = bnx2_TPAT_b06FwReleaseFix;
	fw.start_addr = bnx2_TPAT_b06FwStartAddr;

	fw.text_addr = bnx2_TPAT_b06FwTextAddr;
	fw.text_len = bnx2_TPAT_b06FwTextLen;
	fw.text_index = 0;
	fw.text = bnx2_TPAT_b06FwText;

	fw.data_addr = bnx2_TPAT_b06FwDataAddr;
	fw.data_len = bnx2_TPAT_b06FwDataLen;
	fw.data_index = 0;
	fw.data = bnx2_TPAT_b06FwData;

	fw.sbss_addr = bnx2_TPAT_b06FwSbssAddr;
	fw.sbss_len = bnx2_TPAT_b06FwSbssLen;
	fw.sbss_index = 0;
	fw.sbss = bnx2_TPAT_b06FwSbss;

	fw.bss_addr = bnx2_TPAT_b06FwBssAddr;
	fw.bss_len = bnx2_TPAT_b06FwBssLen;
	fw.bss_index = 0;
	fw.bss = bnx2_TPAT_b06FwBss;

	fw.rodata_addr = bnx2_TPAT_b06FwRodataAddr;
	fw.rodata_len = bnx2_TPAT_b06FwRodataLen;
	fw.rodata_index = 0;
	fw.rodata = bnx2_TPAT_b06FwRodata;

	load_cpu_fw(bp, &cpu_reg, &fw);

	/* Initialize the Completion Processor. */
	cpu_reg.mode = BNX2_COM_CPU_MODE;
	cpu_reg.mode_value_halt = BNX2_COM_CPU_MODE_SOFT_HALT;
	cpu_reg.mode_value_sstep = BNX2_COM_CPU_MODE_STEP_ENA;
	cpu_reg.state = BNX2_COM_CPU_STATE;
	cpu_reg.state_value_clear = 0xffffff;
	cpu_reg.gpr0 = BNX2_COM_CPU_REG_FILE;
	cpu_reg.evmask = BNX2_COM_CPU_EVENT_MASK;
	cpu_reg.pc = BNX2_COM_CPU_PROGRAM_COUNTER;
	cpu_reg.inst = BNX2_COM_CPU_INSTRUCTION;
	cpu_reg.bp = BNX2_COM_CPU_HW_BREAKPOINT;
	cpu_reg.spad_base = BNX2_COM_SCRATCH;
	cpu_reg.mips_view_base = 0x8000000;
    
	fw.ver_major = bnx2_COM_b06FwReleaseMajor;
	fw.ver_minor = bnx2_COM_b06FwReleaseMinor;
	fw.ver_fix = bnx2_COM_b06FwReleaseFix;
	fw.start_addr = bnx2_COM_b06FwStartAddr;

	fw.text_addr = bnx2_COM_b06FwTextAddr;
	fw.text_len = bnx2_COM_b06FwTextLen;
	fw.text_index = 0;
	fw.text = bnx2_COM_b06FwText;

	fw.data_addr = bnx2_COM_b06FwDataAddr;
	fw.data_len = bnx2_COM_b06FwDataLen;
	fw.data_index = 0;
	fw.data = bnx2_COM_b06FwData;

	fw.sbss_addr = bnx2_COM_b06FwSbssAddr;
	fw.sbss_len = bnx2_COM_b06FwSbssLen;
	fw.sbss_index = 0;
	fw.sbss = bnx2_COM_b06FwSbss;

	fw.bss_addr = bnx2_COM_b06FwBssAddr;
	fw.bss_len = bnx2_COM_b06FwBssLen;
	fw.bss_index = 0;
	fw.bss = bnx2_COM_b06FwBss;

	fw.rodata_addr = bnx2_COM_b06FwRodataAddr;
	fw.rodata_len = bnx2_COM_b06FwRodataLen;
	fw.rodata_index = 0;
	fw.rodata = bnx2_COM_b06FwRodata;

	load_cpu_fw(bp, &cpu_reg, &fw);

}

static int
bnx2_set_power_state_0(struct bnx2 *bp)
{
	u16 pmcsr;
	u32 val;

	pci_read_config_word(bp->pdev, bp->pm_cap + PCI_PM_CTRL, &pmcsr);

	pci_write_config_word(bp->pdev, bp->pm_cap + PCI_PM_CTRL,
		(pmcsr & ~PCI_PM_CTRL_STATE_MASK) |
		PCI_PM_CTRL_PME_STATUS);

	if (pmcsr & PCI_PM_CTRL_STATE_MASK)
		/* delay required during transition out of D3hot */
		mdelay(20);

	val = REG_RD(bp, BNX2_EMAC_MODE);
	val |= BNX2_EMAC_MODE_MPKT_RCVD | BNX2_EMAC_MODE_ACPI_RCVD;
	val &= ~BNX2_EMAC_MODE_MPKT;
	REG_WR(bp, BNX2_EMAC_MODE, val);

	val = REG_RD(bp, BNX2_RPM_CONFIG);
	val &= ~BNX2_RPM_CONFIG_ACPI_ENA;
	REG_WR(bp, BNX2_RPM_CONFIG, val);
		
	return 0;
}

static void
bnx2_enable_nvram_access(struct bnx2 *bp)
{
	u32 val;

	val = REG_RD(bp, BNX2_NVM_ACCESS_ENABLE);
	/* Enable both bits, even on read. */
	REG_WR(bp, BNX2_NVM_ACCESS_ENABLE, 
	       val | BNX2_NVM_ACCESS_ENABLE_EN | BNX2_NVM_ACCESS_ENABLE_WR_EN);
}

static void
bnx2_disable_nvram_access(struct bnx2 *bp)
{
	u32 val;

	val = REG_RD(bp, BNX2_NVM_ACCESS_ENABLE);
	/* Disable both bits, even after read. */
	REG_WR(bp, BNX2_NVM_ACCESS_ENABLE, 
		val & ~(BNX2_NVM_ACCESS_ENABLE_EN |
			BNX2_NVM_ACCESS_ENABLE_WR_EN));
}

static int
bnx2_init_nvram(struct bnx2 *bp)
{
	u32 val;
	int j, entry_count, rc;
	struct flash_spec *flash;

	/* Determine the selected interface. */
	val = REG_RD(bp, BNX2_NVM_CFG1);

	entry_count = sizeof(flash_table) / sizeof(struct flash_spec);

	rc = 0;
	if (val & 0x40000000) {
		/* Flash interface has been reconfigured */
		for (j = 0, flash = &flash_table[0]; j < entry_count;
		     j++, flash++) {
			if ((val & FLASH_BACKUP_STRAP_MASK) ==
			    (flash->config1 & FLASH_BACKUP_STRAP_MASK)) {
				bp->flash_info = flash;
				break;
			}
		}
	}
	else {
		u32 mask;
		/* Not yet been reconfigured */

		if (val & (1 << 23))
			mask = FLASH_BACKUP_STRAP_MASK;
		else
			mask = FLASH_STRAP_MASK;

		for (j = 0, flash = &flash_table[0]; j < entry_count;
			j++, flash++) {

			if ((val & mask) == (flash->strapping & mask)) {
				bp->flash_info = flash;

				/* Enable access to flash interface */
				bnx2_enable_nvram_access(bp);

				/* Reconfigure the flash interface */
				REG_WR(bp, BNX2_NVM_CFG1, flash->config1);
				REG_WR(bp, BNX2_NVM_CFG2, flash->config2);
				REG_WR(bp, BNX2_NVM_CFG3, flash->config3);
				REG_WR(bp, BNX2_NVM_WRITE1, flash->write1);

				/* Disable access to flash interface */
				bnx2_disable_nvram_access(bp);

				break;
			}
		}
	} /* if (val & 0x40000000) */

	if (j == entry_count) {
		bp->flash_info = NULL;
		printf("Unknown flash/EEPROM type.\n");
		return -ENODEV;
	}

	val = REG_RD_IND(bp, bp->shmem_base + BNX2_SHARED_HW_CFG_CONFIG2);
	val &= BNX2_SHARED_HW_CFG2_NVM_SIZE_MASK;
	if (val) {
		bp->flash_size = val;
	}
	else {
		bp->flash_size = bp->flash_info->total_size;
	}

	return rc;
}

static int
bnx2_reset_chip(struct bnx2 *bp, u32 reset_code)
{
	u32 val;
	int i, rc = 0;

	/* Wait for the current PCI transaction to complete before
	 * issuing a reset. */
	REG_WR(bp, BNX2_MISC_ENABLE_CLR_BITS,
	       BNX2_MISC_ENABLE_CLR_BITS_TX_DMA_ENABLE |
	       BNX2_MISC_ENABLE_CLR_BITS_DMA_ENGINE_ENABLE |
	       BNX2_MISC_ENABLE_CLR_BITS_RX_DMA_ENABLE |
	       BNX2_MISC_ENABLE_CLR_BITS_HOST_COALESCE_ENABLE);
	val = REG_RD(bp, BNX2_MISC_ENABLE_CLR_BITS);
	udelay(5);


	/* Wait for the firmware to tell us it is ok to issue a reset. */
	bnx2_fw_sync(bp, BNX2_DRV_MSG_DATA_WAIT0 | reset_code, 1);

	/* Deposit a driver reset signature so the firmware knows that
	 * this is a soft reset. */
	REG_WR_IND(bp, bp->shmem_base + BNX2_DRV_RESET_SIGNATURE,
		   BNX2_DRV_RESET_SIGNATURE_MAGIC);

	/* Do a dummy read to force the chip to complete all current transaction
	 * before we issue a reset. */
	val = REG_RD(bp, BNX2_MISC_ID);

	val = BNX2_PCICFG_MISC_CONFIG_CORE_RST_REQ |
	      BNX2_PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
	      BNX2_PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP;

	/* Chip reset. */
	REG_WR(bp, BNX2_PCICFG_MISC_CONFIG, val);

	if ((CHIP_ID(bp) == CHIP_ID_5706_A0) ||
	    (CHIP_ID(bp) == CHIP_ID_5706_A1))
		mdelay(15);

	/* Reset takes approximate 30 usec */
	for (i = 0; i < 10; i++) {
		val = REG_RD(bp, BNX2_PCICFG_MISC_CONFIG);
		if ((val & (BNX2_PCICFG_MISC_CONFIG_CORE_RST_REQ |
			    BNX2_PCICFG_MISC_CONFIG_CORE_RST_BSY)) == 0) {
			break;
		}
		udelay(10);
	}

	if (val & (BNX2_PCICFG_MISC_CONFIG_CORE_RST_REQ |
		   BNX2_PCICFG_MISC_CONFIG_CORE_RST_BSY)) {
		printf("Chip reset did not complete\n");
		return -EBUSY;
	}

	/* Make sure byte swapping is properly configured. */
	val = REG_RD(bp, BNX2_PCI_SWAP_DIAG0);
	if (val != 0x01020304) {
		printf("Chip not in correct endian mode\n");
		return -ENODEV;
	}

	/* Wait for the firmware to finish its initialization. */
	rc = bnx2_fw_sync(bp, BNX2_DRV_MSG_DATA_WAIT1 | reset_code, 0);
	if (rc) {
		return rc;
	}

	if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
		/* Adjust the voltage regular to two steps lower.  The default
		 * of this register is 0x0000000e. */
		REG_WR(bp, BNX2_MISC_VREG_CONTROL, 0x000000fa);

		/* Remove bad rbuf memory from the free pool. */
		rc = bnx2_alloc_bad_rbuf(bp);
	}

	return rc;
}

static void
bnx2_disable(struct nic *nic __unused)
{
	struct bnx2* bp = &bnx2;

	if (bp->regview) {
		bnx2_reset_chip(bp, BNX2_DRV_MSG_CODE_UNLOAD);
		iounmap(bp->regview);
	}
}

static int
bnx2_init_chip(struct bnx2 *bp)
{
	u32 val;
	int rc;

	/* Make sure the interrupt is not active. */
	REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD, BNX2_PCICFG_INT_ACK_CMD_MASK_INT);

	val = BNX2_DMA_CONFIG_DATA_BYTE_SWAP |
	      BNX2_DMA_CONFIG_DATA_WORD_SWAP |
#if __BYTE_ORDER ==  __BIG_ENDIAN
	      BNX2_DMA_CONFIG_CNTL_BYTE_SWAP | 
#endif
	      BNX2_DMA_CONFIG_CNTL_WORD_SWAP | 
	      DMA_READ_CHANS << 12 |
	      DMA_WRITE_CHANS << 16;

	val |= (0x2 << 20) | (1 << 11);

	if ((bp->flags & PCIX_FLAG) && (bp->bus_speed_mhz == 133))
		val |= (1 << 23);

	if ((CHIP_NUM(bp) == CHIP_NUM_5706) &&
	    (CHIP_ID(bp) != CHIP_ID_5706_A0) && !(bp->flags & PCIX_FLAG))
		val |= BNX2_DMA_CONFIG_CNTL_PING_PONG_DMA;

	REG_WR(bp, BNX2_DMA_CONFIG, val);

	if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
		val = REG_RD(bp, BNX2_TDMA_CONFIG);
		val |= BNX2_TDMA_CONFIG_ONE_DMA;
		REG_WR(bp, BNX2_TDMA_CONFIG, val);
	}

	if (bp->flags & PCIX_FLAG) {
		u16 val16;

		pci_read_config_word(bp->pdev, bp->pcix_cap + PCI_X_CMD,
				     &val16);
		pci_write_config_word(bp->pdev, bp->pcix_cap + PCI_X_CMD,
				      val16 & ~PCI_X_CMD_ERO);
	}

	REG_WR(bp, BNX2_MISC_ENABLE_SET_BITS,
	       BNX2_MISC_ENABLE_SET_BITS_HOST_COALESCE_ENABLE |
	       BNX2_MISC_ENABLE_STATUS_BITS_RX_V2P_ENABLE |
	       BNX2_MISC_ENABLE_STATUS_BITS_CONTEXT_ENABLE);

	/* Initialize context mapping and zero out the quick contexts.  The
	 * context block must have already been enabled. */
	bnx2_init_context(bp);

	bnx2_init_nvram(bp);
	bnx2_init_cpus(bp);

	bnx2_set_mac_addr(bp);

	val = REG_RD(bp, BNX2_MQ_CONFIG);
	val &= ~BNX2_MQ_CONFIG_KNL_BYP_BLK_SIZE;
	val |= BNX2_MQ_CONFIG_KNL_BYP_BLK_SIZE_256;
	REG_WR(bp, BNX2_MQ_CONFIG, val);

	val = 0x10000 + (MAX_CID_CNT * MB_KERNEL_CTX_SIZE);
	REG_WR(bp, BNX2_MQ_KNL_BYP_WIND_START, val);
	REG_WR(bp, BNX2_MQ_KNL_WIND_END, val);

	val = (BCM_PAGE_BITS - 8) << 24;
	REG_WR(bp, BNX2_RV2P_CONFIG, val);

	/* Configure page size. */
	val = REG_RD(bp, BNX2_TBDR_CONFIG);
	val &= ~BNX2_TBDR_CONFIG_PAGE_SIZE;
	val |= (BCM_PAGE_BITS - 8) << 24 | 0x40;
	REG_WR(bp, BNX2_TBDR_CONFIG, val);

	val = bp->mac_addr[0] +
	      (bp->mac_addr[1] << 8) +
	      (bp->mac_addr[2] << 16) +
	      bp->mac_addr[3] +
	      (bp->mac_addr[4] << 8) +
	      (bp->mac_addr[5] << 16);
	REG_WR(bp, BNX2_EMAC_BACKOFF_SEED, val);

	/* Program the MTU.  Also include 4 bytes for CRC32. */
	val = ETH_MAX_MTU + ETH_HLEN + 4;
	if (val > (MAX_ETHERNET_PACKET_SIZE + 4))
		val |= BNX2_EMAC_RX_MTU_SIZE_JUMBO_ENA;
	REG_WR(bp, BNX2_EMAC_RX_MTU_SIZE, val);

	bp->last_status_idx = 0;
	bp->rx_mode = BNX2_EMAC_RX_MODE_SORT_MODE;

	/* Set up how to generate a link change interrupt. */
	REG_WR(bp, BNX2_EMAC_ATTENTION_ENA, BNX2_EMAC_ATTENTION_ENA_LINK);

	REG_WR(bp, BNX2_HC_STATUS_ADDR_L,
	       (u64) bp->status_blk_mapping & 0xffffffff);
	REG_WR(bp, BNX2_HC_STATUS_ADDR_H, (u64) bp->status_blk_mapping >> 32);

	REG_WR(bp, BNX2_HC_STATISTICS_ADDR_L,
	       (u64) bp->stats_blk_mapping & 0xffffffff);
	REG_WR(bp, BNX2_HC_STATISTICS_ADDR_H,
	       (u64) bp->stats_blk_mapping >> 32);

	REG_WR(bp, BNX2_HC_TX_QUICK_CONS_TRIP, 
	       (bp->tx_quick_cons_trip_int << 16) | bp->tx_quick_cons_trip);

	REG_WR(bp, BNX2_HC_RX_QUICK_CONS_TRIP,
	       (bp->rx_quick_cons_trip_int << 16) | bp->rx_quick_cons_trip);

	REG_WR(bp, BNX2_HC_COMP_PROD_TRIP,
	       (bp->comp_prod_trip_int << 16) | bp->comp_prod_trip);

	REG_WR(bp, BNX2_HC_TX_TICKS, (bp->tx_ticks_int << 16) | bp->tx_ticks);

	REG_WR(bp, BNX2_HC_RX_TICKS, (bp->rx_ticks_int << 16) | bp->rx_ticks);

	REG_WR(bp, BNX2_HC_COM_TICKS,
	       (bp->com_ticks_int << 16) | bp->com_ticks);

	REG_WR(bp, BNX2_HC_CMD_TICKS,
	       (bp->cmd_ticks_int << 16) | bp->cmd_ticks);

	REG_WR(bp, BNX2_HC_STATS_TICKS, bp->stats_ticks & 0xffff00);
	REG_WR(bp, BNX2_HC_STAT_COLLECT_TICKS, 0xbb8);  /* 3ms */

	if (CHIP_ID(bp) == CHIP_ID_5706_A1)
		REG_WR(bp, BNX2_HC_CONFIG, BNX2_HC_CONFIG_COLLECT_STATS);
	else {
		REG_WR(bp, BNX2_HC_CONFIG, BNX2_HC_CONFIG_RX_TMR_MODE |
		       BNX2_HC_CONFIG_TX_TMR_MODE |
		       BNX2_HC_CONFIG_COLLECT_STATS);
	}

	/* Clear internal stats counters. */
	REG_WR(bp, BNX2_HC_COMMAND, BNX2_HC_COMMAND_CLR_STAT_NOW);

	REG_WR(bp, BNX2_HC_ATTN_BITS_ENABLE, STATUS_ATTN_BITS_LINK_STATE);

	if (REG_RD_IND(bp, bp->shmem_base + BNX2_PORT_FEATURE) &
	    BNX2_PORT_FEATURE_ASF_ENABLED)
		bp->flags |= ASF_ENABLE_FLAG;

	/* Initialize the receive filter. */
	bnx2_set_rx_mode(bp->nic);

	rc = bnx2_fw_sync(bp, BNX2_DRV_MSG_DATA_WAIT2 | BNX2_DRV_MSG_CODE_RESET,
			  0);

	REG_WR(bp, BNX2_MISC_ENABLE_SET_BITS, 0x5ffffff);
	REG_RD(bp, BNX2_MISC_ENABLE_SET_BITS);

	udelay(20);

	bp->hc_cmd = REG_RD(bp, BNX2_HC_COMMAND);

	return rc;
}

static void
bnx2_init_tx_ring(struct bnx2 *bp)
{
	struct tx_bd *txbd;
	u32 val;

	txbd = &bp->tx_desc_ring[MAX_TX_DESC_CNT];
		
	/* Etherboot lives below 4GB, so hi is always 0 */
	txbd->tx_bd_haddr_hi = 0;
	txbd->tx_bd_haddr_lo = bp->tx_desc_mapping;

	bp->tx_prod = 0;
	bp->tx_cons = 0;
	bp->hw_tx_cons = 0;
	bp->tx_prod_bseq = 0;
	
	val = BNX2_L2CTX_TYPE_TYPE_L2;
	val |= BNX2_L2CTX_TYPE_SIZE_L2;
	CTX_WR(bp, GET_CID_ADDR(TX_CID), BNX2_L2CTX_TYPE, val);

	val = BNX2_L2CTX_CMD_TYPE_TYPE_L2;
	val |= 8 << 16;
	CTX_WR(bp, GET_CID_ADDR(TX_CID), BNX2_L2CTX_CMD_TYPE, val);

	/* Etherboot lives below 4GB, so hi is always 0 */
	CTX_WR(bp, GET_CID_ADDR(TX_CID), BNX2_L2CTX_TBDR_BHADDR_HI, 0);

	val = (u64) bp->tx_desc_mapping & 0xffffffff;
	CTX_WR(bp, GET_CID_ADDR(TX_CID), BNX2_L2CTX_TBDR_BHADDR_LO, val);
}

static void
bnx2_init_rx_ring(struct bnx2 *bp)
{
	struct rx_bd *rxbd;
	unsigned int i;
	u16 prod, ring_prod;
	u32 val;

	bp->rx_buf_use_size = RX_BUF_USE_SIZE;
	bp->rx_buf_size = RX_BUF_SIZE;

	ring_prod = prod = bp->rx_prod = 0;
	bp->rx_cons = 0;
	bp->hw_rx_cons = 0;
	bp->rx_prod_bseq = 0;

	memset(bnx2_bss.rx_buf, 0, sizeof(bnx2_bss.rx_buf));
		
	rxbd = &bp->rx_desc_ring[0];
	for (i = 0; i < MAX_RX_DESC_CNT; i++, rxbd++) {
		rxbd->rx_bd_len = bp->rx_buf_use_size;
		rxbd->rx_bd_flags = RX_BD_FLAGS_START | RX_BD_FLAGS_END;
	}
	rxbd->rx_bd_haddr_hi = 0;
	rxbd->rx_bd_haddr_lo = (u64) bp->rx_desc_mapping & 0xffffffff;

	val = BNX2_L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_VALUE;
	val |= BNX2_L2CTX_CTX_TYPE_SIZE_L2;
	val |= 0x02 << 8;
	CTX_WR(bp, GET_CID_ADDR(RX_CID), BNX2_L2CTX_CTX_TYPE, val);

	/* Etherboot doesn't use memory above 4GB, so this is always 0 */
	CTX_WR(bp, GET_CID_ADDR(RX_CID), BNX2_L2CTX_NX_BDHADDR_HI, 0);

	val = bp->rx_desc_mapping & 0xffffffff;
	CTX_WR(bp, GET_CID_ADDR(RX_CID), BNX2_L2CTX_NX_BDHADDR_LO, val);

	for (i = 0; (int) i < bp->rx_ring_size; i++) {
		rxbd = &bp->rx_desc_ring[RX_RING_IDX(ring_prod)];
		rxbd->rx_bd_haddr_hi = 0;
		rxbd->rx_bd_haddr_lo = virt_to_bus(&bnx2_bss.rx_buf[ring_prod][0]);
		bp->rx_prod_bseq += bp->rx_buf_use_size;
		prod = NEXT_RX_BD(prod);
		ring_prod = RX_RING_IDX(prod);
	}
	bp->rx_prod = prod;

	REG_WR16(bp, MB_RX_CID_ADDR + BNX2_L2CTX_HOST_BDIDX, bp->rx_prod);

	REG_WR(bp, MB_RX_CID_ADDR + BNX2_L2CTX_HOST_BSEQ, bp->rx_prod_bseq);
}

static int
bnx2_reset_nic(struct bnx2 *bp, u32 reset_code)
{
	int rc;

	rc = bnx2_reset_chip(bp, reset_code);
	if (rc) {
		return rc;
	}

	bnx2_init_chip(bp);
	bnx2_init_tx_ring(bp);
	bnx2_init_rx_ring(bp);
	return 0;
}

static int
bnx2_init_nic(struct bnx2 *bp)
{
	int rc;

	if ((rc = bnx2_reset_nic(bp, BNX2_DRV_MSG_CODE_RESET)) != 0)
		return rc;

	bnx2_init_phy(bp);
	bnx2_set_link(bp);
	return 0;
}

static int
bnx2_init_board(struct pci_device *pdev, struct nic *nic)
{
	unsigned long bnx2reg_base, bnx2reg_len;
	struct bnx2 *bp = &bnx2;
	int rc;
	u32 reg;

	bp->flags = 0;
	bp->phy_flags = 0;

	/* enable device (incl. PCI PM wakeup), and bus-mastering */
	adjust_pci_device(pdev);

	nic->ioaddr = pdev->ioaddr & ~3;
	nic->irqno = 0;

	rc = 0;
	bp->pm_cap = pci_find_capability(pdev, PCI_CAP_ID_PM);
	if (bp->pm_cap == 0) {
		printf("Cannot find power management capability, aborting.\n");
		rc = -EIO;
		goto err_out_disable;
	}

	bp->pcix_cap = pci_find_capability(pdev, PCI_CAP_ID_PCIX);
	if (bp->pcix_cap == 0) {
		printf("Cannot find PCIX capability, aborting.\n");
		rc = -EIO;
		goto err_out_disable;
	}

	bp->pdev = pdev;
	bp->nic = nic;

	bnx2reg_base = pci_bar_start(pdev, PCI_BASE_ADDRESS_0);
	bnx2reg_len = MB_GET_CID_ADDR(17);

	bp->regview = ioremap(bnx2reg_base, bnx2reg_len);

	if (!bp->regview) {
		printf("Cannot map register space, aborting.\n");
		rc = -EIO;
		goto err_out_disable;
	}

	/* Configure byte swap and enable write to the reg_window registers.
	 * Rely on CPU to do target byte swapping on big endian systems
	 * The chip's target access swapping will not swap all accesses
	 */
	pci_write_config_dword(bp->pdev, BNX2_PCICFG_MISC_CONFIG,
			       BNX2_PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
			       BNX2_PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP);

	bnx2_set_power_state_0(bp);

	bp->chip_id = REG_RD(bp, BNX2_MISC_ID);

	/* Get bus information. */
	reg = REG_RD(bp, BNX2_PCICFG_MISC_STATUS);
	if (reg & BNX2_PCICFG_MISC_STATUS_PCIX_DET) {
		u32 clkreg;

		bp->flags |= PCIX_FLAG;

		clkreg = REG_RD(bp, BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS);
		
		clkreg &= BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET;
		switch (clkreg) {
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_133MHZ:
			bp->bus_speed_mhz = 133;
			break;

		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_95MHZ:
			bp->bus_speed_mhz = 100;
			break;

		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_66MHZ:
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_80MHZ:
			bp->bus_speed_mhz = 66;
			break;

		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_48MHZ:
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_55MHZ:
			bp->bus_speed_mhz = 50;
			break;

		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_LOW:
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_32MHZ:
		case BNX2_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_38MHZ:
			bp->bus_speed_mhz = 33;
			break;
		}
	}
	else {
		if (reg & BNX2_PCICFG_MISC_STATUS_M66EN)
			bp->bus_speed_mhz = 66;
		else
			bp->bus_speed_mhz = 33;
	}

	if (reg & BNX2_PCICFG_MISC_STATUS_32BIT_DET)
		bp->flags |= PCI_32BIT_FLAG;

	/* 5706A0 may falsely detect SERR and PERR. */
	if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
		reg = REG_RD(bp, PCI_COMMAND);
		reg &= ~(PCI_COMMAND_SERR | PCI_COMMAND_PARITY);
		REG_WR(bp, PCI_COMMAND, reg);
	}
	else if ((CHIP_ID(bp) == CHIP_ID_5706_A1) &&
		!(bp->flags & PCIX_FLAG)) {

		printf("5706 A1 can only be used in a PCIX bus, aborting.\n");
		goto err_out_disable;
	}

	bnx2_init_nvram(bp);

	reg = REG_RD_IND(bp, BNX2_SHM_HDR_SIGNATURE);

	if ((reg & BNX2_SHM_HDR_SIGNATURE_SIG_MASK) ==
	    BNX2_SHM_HDR_SIGNATURE_SIG)
		bp->shmem_base = REG_RD_IND(bp, BNX2_SHM_HDR_ADDR_0);
	else
		bp->shmem_base = HOST_VIEW_SHMEM_BASE;

	/* Get the permanent MAC address.  First we need to make sure the
	 * firmware is actually running.
	 */
	reg = REG_RD_IND(bp, bp->shmem_base + BNX2_DEV_INFO_SIGNATURE);

	if ((reg & BNX2_DEV_INFO_SIGNATURE_MAGIC_MASK) !=
	    BNX2_DEV_INFO_SIGNATURE_MAGIC) {
		printf("Firmware not running, aborting.\n");
		rc = -ENODEV;
		goto err_out_disable;
	}

	bp->fw_ver = REG_RD_IND(bp, bp->shmem_base + BNX2_DEV_INFO_BC_REV);

	reg = REG_RD_IND(bp, bp->shmem_base + BNX2_PORT_HW_CFG_MAC_UPPER);
	bp->mac_addr[0] = (u8) (reg >> 8);
	bp->mac_addr[1] = (u8) reg;

	reg = REG_RD_IND(bp, bp->shmem_base + BNX2_PORT_HW_CFG_MAC_LOWER);
	bp->mac_addr[2] = (u8) (reg >> 24);
	bp->mac_addr[3] = (u8) (reg >> 16);
	bp->mac_addr[4] = (u8) (reg >> 8);
	bp->mac_addr[5] = (u8) reg;

	bp->tx_ring_size = MAX_TX_DESC_CNT;
	bp->rx_ring_size = RX_BUF_CNT;
	bp->rx_max_ring_idx = MAX_RX_DESC_CNT;

	bp->rx_offset = RX_OFFSET;

	bp->tx_quick_cons_trip_int = 20;
	bp->tx_quick_cons_trip = 20;
	bp->tx_ticks_int = 80;
	bp->tx_ticks = 80;
		
	bp->rx_quick_cons_trip_int = 6;
	bp->rx_quick_cons_trip = 6;
	bp->rx_ticks_int = 18;
	bp->rx_ticks = 18;

	bp->stats_ticks = 1000000 & 0xffff00;

	bp->phy_addr = 1;

	/* No need for WOL support in Etherboot */
	bp->flags |= NO_WOL_FLAG;

	/* Disable WOL support if we are running on a SERDES chip. */
	if (CHIP_BOND_ID(bp) & CHIP_BOND_ID_SERDES_BIT) {
		bp->phy_flags |= PHY_SERDES_FLAG;
		if (CHIP_NUM(bp) == CHIP_NUM_5708) {
			bp->phy_addr = 2;
			reg = REG_RD_IND(bp, bp->shmem_base +
					 BNX2_SHARED_HW_CFG_CONFIG);
			if (reg & BNX2_SHARED_HW_CFG_PHY_2_5G)
				bp->phy_flags |= PHY_2_5G_CAPABLE_FLAG;
		}
	}

	if (CHIP_ID(bp) == CHIP_ID_5706_A0) {
		bp->tx_quick_cons_trip_int =
			bp->tx_quick_cons_trip;
		bp->tx_ticks_int = bp->tx_ticks;
		bp->rx_quick_cons_trip_int =
			bp->rx_quick_cons_trip;
		bp->rx_ticks_int = bp->rx_ticks;
		bp->comp_prod_trip_int = bp->comp_prod_trip;
		bp->com_ticks_int = bp->com_ticks;
		bp->cmd_ticks_int = bp->cmd_ticks;
	}

	bp->autoneg = AUTONEG_SPEED | AUTONEG_FLOW_CTRL;
	bp->req_line_speed = 0;
	if (bp->phy_flags & PHY_SERDES_FLAG) {
		bp->advertising = ETHTOOL_ALL_FIBRE_SPEED | ADVERTISED_Autoneg;

		reg = REG_RD_IND(bp, bp->shmem_base + BNX2_PORT_HW_CFG_CONFIG);
		reg &= BNX2_PORT_HW_CFG_CFG_DFLT_LINK_MASK;
		if (reg == BNX2_PORT_HW_CFG_CFG_DFLT_LINK_1G) {
			bp->autoneg = 0;
			bp->req_line_speed = bp->line_speed = SPEED_1000;
			bp->req_duplex = DUPLEX_FULL;
		}
	}
	else {
		bp->advertising = ETHTOOL_ALL_COPPER_SPEED | ADVERTISED_Autoneg;
	}

	bp->req_flow_ctrl = FLOW_CTRL_RX | FLOW_CTRL_TX;

	/* Disable driver heartbeat checking */
	REG_WR_IND(bp, bp->shmem_base + BNX2_DRV_PULSE_MB,
			BNX2_DRV_MSG_DATA_PULSE_CODE_ALWAYS_ALIVE);
	REG_RD_IND(bp, bp->shmem_base + BNX2_DRV_PULSE_MB);

	return 0;

err_out_disable:
	bnx2_disable(nic);

	return rc;
}

static void
bnx2_transmit(struct nic *nic, const char *dst_addr,
		unsigned int type, unsigned int size, const char *packet)
{
	/* Sometimes the nic will be behind by a frame.  Using two transmit
	 * buffers prevents us from timing out in that case.
	 */
	static struct eth_frame {
		uint8_t  dst_addr[ETH_ALEN];
		uint8_t  src_addr[ETH_ALEN];
		uint16_t type;
		uint8_t  data [ETH_FRAME_LEN - ETH_HLEN];
	} frame[2];
	static int frame_idx = 0;
	
	/* send the packet to destination */
	struct tx_bd *txbd;
	struct bnx2 *bp = &bnx2;
	u16 prod, ring_prod;
	u16 hw_cons;
	int i = 0;

	prod = bp->tx_prod;
	ring_prod = TX_RING_IDX(prod);
	hw_cons = bp->status_blk->status_tx_quick_consumer_index0;
	if ((hw_cons & MAX_TX_DESC_CNT) == MAX_TX_DESC_CNT) {
		hw_cons++;
	}

	while((hw_cons != prod) && (hw_cons != (PREV_TX_BD(prod)))) {
		mdelay(10);	/* give the nic a chance */
		//poll_interruptions();
		if (++i > 500) { /* timeout 5s for transmit */
			printf("transmit timed out\n");
			bnx2_disable(bp->nic);
			bnx2_init_board(bp->pdev, bp->nic);
			return;
		}
	}
	if (i != 0) {
		printf("#");
	}

	/* Copy the packet to the our local buffer */
	memcpy(&frame[frame_idx].dst_addr, dst_addr, ETH_ALEN);
	memcpy(&frame[frame_idx].src_addr, nic->node_addr, ETH_ALEN);
	frame[frame_idx].type = htons(type);
	memset(&frame[frame_idx].data, 0, sizeof(frame[frame_idx].data));
	memcpy(&frame[frame_idx].data, packet, size);

	/* Setup the ring buffer entry to transmit */
	txbd = &bp->tx_desc_ring[ring_prod];
	txbd->tx_bd_haddr_hi = 0; /* Etherboot runs under 4GB */
	txbd->tx_bd_haddr_lo = virt_to_bus(&frame[frame_idx]);
	txbd->tx_bd_mss_nbytes = (size + ETH_HLEN);
	txbd->tx_bd_vlan_tag_flags = TX_BD_FLAGS_START | TX_BD_FLAGS_END;

	/* Advance to the next entry */
	prod = NEXT_TX_BD(prod);
	frame_idx ^= 1;

	bp->tx_prod_bseq += (size + ETH_HLEN);

	REG_WR16(bp, MB_TX_CID_ADDR + BNX2_L2CTX_TX_HOST_BIDX, prod);
	REG_WR(bp, MB_TX_CID_ADDR + BNX2_L2CTX_TX_HOST_BSEQ, bp->tx_prod_bseq);

	wmb();

	bp->tx_prod = prod;
}

static int
bnx2_poll_link(struct bnx2 *bp)
{
	u32 new_link_state, old_link_state, emac_status;

	new_link_state = bp->status_blk->status_attn_bits &
		STATUS_ATTN_BITS_LINK_STATE;

	old_link_state = bp->status_blk->status_attn_bits_ack &
		STATUS_ATTN_BITS_LINK_STATE;

	if (!new_link_state && !old_link_state) {
		/* For some reason the card doesn't always update the link
		 * status bits properly.  Kick the stupid thing and try again.
		 */
		u32 bmsr;

		bnx2_read_phy(bp, MII_BMSR, &bmsr);
		bnx2_read_phy(bp, MII_BMSR, &bmsr);

		if ((bp->phy_flags & PHY_SERDES_FLAG) &&
		    (CHIP_NUM(bp) == CHIP_NUM_5706)) {
			REG_RD(bp, BNX2_EMAC_STATUS);
		}

		new_link_state = bp->status_blk->status_attn_bits &
			STATUS_ATTN_BITS_LINK_STATE;

		old_link_state = bp->status_blk->status_attn_bits_ack &
			STATUS_ATTN_BITS_LINK_STATE;

		/* Okay, for some reason the above doesn't work with some
		 * switches (like HP ProCurve). If the above doesn't work,
		 * check the MAC directly to see if we have a link.  Perhaps we
		 * should always check the MAC instead probing the MII.
		 */
		if (!new_link_state && !old_link_state) {
			emac_status = REG_RD(bp, BNX2_EMAC_STATUS);
			if (emac_status & BNX2_EMAC_STATUS_LINK_CHANGE) {
				/* Acknowledge the link change */
				REG_WR(bp, BNX2_EMAC_STATUS, BNX2_EMAC_STATUS_LINK_CHANGE);
			} else if (emac_status & BNX2_EMAC_STATUS_LINK) {
				new_link_state = !old_link_state;
			}
		}

	}

	if (new_link_state != old_link_state) {
		if (new_link_state) {
			REG_WR(bp, BNX2_PCICFG_STATUS_BIT_SET_CMD,
				STATUS_ATTN_BITS_LINK_STATE);
		}
		else {
			REG_WR(bp, BNX2_PCICFG_STATUS_BIT_CLEAR_CMD,
				STATUS_ATTN_BITS_LINK_STATE);
		}

		bnx2_set_link(bp);

		/* This is needed to take care of transient status
		 * during link changes.
		 */

		REG_WR(bp, BNX2_HC_COMMAND,
		       bp->hc_cmd | BNX2_HC_COMMAND_COAL_NOW_WO_INT);
		REG_RD(bp, BNX2_HC_COMMAND);

	}

	return bp->link_up;
}

static int
bnx2_poll(struct nic* nic, int retrieve)
{
	struct bnx2 *bp = &bnx2;
	struct rx_bd *cons_bd, *prod_bd;
	u16 hw_cons, sw_cons, sw_ring_cons, sw_prod, sw_ring_prod;
	struct l2_fhdr *rx_hdr;
	int result = 0;
	unsigned int len;
	unsigned char *data;
	u32 status;
	
#if 0
	if ((bp->status_blk->status_idx == bp->last_status_idx) &&
	    (REG_RD(bp, BNX2_PCICFG_MISC_STATUS) &
	     BNX2_PCICFG_MISC_STATUS_INTA_VALUE)) {

		bp->last_status_idx = bp->status_blk->status_idx;
		REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
	       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
	       BNX2_PCICFG_INT_ACK_CMD_MASK_INT |
	       bp->last_status_idx);
		return 0;
	}
#endif

	if ((bp->status_blk->status_rx_quick_consumer_index0 != bp->rx_cons) && !retrieve)
		return 1;

	if (bp->status_blk->status_rx_quick_consumer_index0 != bp->rx_cons) {

		hw_cons = bp->hw_rx_cons = bp->status_blk->status_rx_quick_consumer_index0;
		if ((hw_cons & MAX_RX_DESC_CNT) == MAX_RX_DESC_CNT) {
			hw_cons++;
		}
		sw_cons = bp->rx_cons;
		sw_prod = bp->rx_prod;

		rmb();
		if (sw_cons != hw_cons) {

			sw_ring_cons = RX_RING_IDX(sw_cons);
			sw_ring_prod = RX_RING_IDX(sw_prod);

			data = bus_to_virt(bp->rx_desc_ring[sw_ring_cons].rx_bd_haddr_lo);

			rx_hdr = (struct l2_fhdr *)data;
			len = rx_hdr->l2_fhdr_pkt_len - 4;
			if ((len > (ETH_MAX_MTU + ETH_HLEN)) ||
				((status = rx_hdr->l2_fhdr_status) &
				(L2_FHDR_ERRORS_BAD_CRC |
				L2_FHDR_ERRORS_PHY_DECODE |
				L2_FHDR_ERRORS_ALIGNMENT |
				L2_FHDR_ERRORS_TOO_SHORT |
				L2_FHDR_ERRORS_GIANT_FRAME))) {
				result = 0;
			}
			else
			{
				nic->packetlen = len;
				memcpy(nic->packet, data + bp->rx_offset, len);
				result = 1;
			}

			/* Reuse the buffer */
			bp->rx_prod_bseq += bp->rx_buf_use_size;
			if (sw_cons != sw_prod) {
				cons_bd = &bp->rx_desc_ring[sw_ring_cons];
				prod_bd = &bp->rx_desc_ring[sw_ring_prod];
				prod_bd->rx_bd_haddr_hi = 0; /* Etherboot runs under 4GB */
				prod_bd->rx_bd_haddr_lo = cons_bd->rx_bd_haddr_lo;
			}

			sw_cons = NEXT_RX_BD(sw_cons);
			sw_prod = NEXT_RX_BD(sw_prod);

		}

		bp->rx_cons = sw_cons;
		bp->rx_prod = sw_prod;

		REG_WR16(bp, MB_RX_CID_ADDR + BNX2_L2CTX_HOST_BDIDX, bp->rx_prod);

		REG_WR(bp, MB_RX_CID_ADDR + BNX2_L2CTX_HOST_BSEQ, bp->rx_prod_bseq);

		wmb();

	}

	bnx2_poll_link(bp);

#if 0
	bp->last_status_idx = bp->status_blk->status_idx;
	rmb();

	REG_WR(bp, BNX2_PCICFG_INT_ACK_CMD,
	       BNX2_PCICFG_INT_ACK_CMD_INDEX_VALID |
	       BNX2_PCICFG_INT_ACK_CMD_MASK_INT |
	       bp->last_status_idx);

	REG_WR(bp, BNX2_HC_COMMAND, bp->hc_cmd | BNX2_HC_COMMAND_COAL_NOW_WO_INT);
#endif

	return result;
}

static void
bnx2_irq(struct nic *nic __unused, irq_action_t action __unused)
{
	switch ( action ) {
		case DISABLE: break;
		case ENABLE: break;
		case FORCE: break;
	}
}

static struct nic_operations bnx2_operations = {
	.connect	= dummy_connect,
	.poll		= bnx2_poll,
	.transmit	= bnx2_transmit,
	.irq		= bnx2_irq,
};

static int
bnx2_probe(struct nic *nic, struct pci_device *pdev)
{
	struct bnx2 *bp = &bnx2;
	int i, rc;

	memset(bp, 0, sizeof(*bp));

	rc = bnx2_init_board(pdev, nic);
	if (rc < 0) {
		return 0;
	}

	/*
	nic->disable = bnx2_disable;
	nic->transmit = bnx2_transmit;
	nic->poll = bnx2_poll;
	nic->irq = bnx2_irq;
	*/
	
	nic->nic_op	= &bnx2_operations;

	memcpy(nic->node_addr, bp->mac_addr, ETH_ALEN);
	printf("Ethernet addr: %s\n", eth_ntoa( nic->node_addr ) );
	printf("Broadcom NetXtreme II (%c%d) PCI%s %s %dMHz\n",
	        (int) ((CHIP_ID(bp) & 0xf000) >> 12) + 'A',
	        (int) ((CHIP_ID(bp) & 0x0ff0) >> 4),
		((bp->flags & PCIX_FLAG) ? "-X" : ""),
		((bp->flags & PCI_32BIT_FLAG) ? "32-bit" : "64-bit"),
		bp->bus_speed_mhz);

	bnx2_set_power_state_0(bp);
	bnx2_disable_int(bp);

	bnx2_alloc_mem(bp);

	rc = bnx2_init_nic(bp);
	if (rc) {
		return 0;
	}

	bnx2_poll_link(bp);
	for(i = 0; !bp->link_up && (i < VALID_LINK_TIMEOUT*100); i++) {
		mdelay(1);
		bnx2_poll_link(bp);
	}
#if 1
	if (!bp->link_up){
		printf("Valid link not established\n");
		goto err_out_disable;
	}
#endif
	
	return 1;

err_out_disable:
	bnx2_disable(nic);
	return 0;
}

static struct pci_device_id bnx2_nics[] = {
	PCI_ROM(0x14e4, 0x164a, "bnx2-5706",        "Broadcom NetXtreme II BCM5706", 0),
	PCI_ROM(0x14e4, 0x164c, "bnx2-5708",        "Broadcom NetXtreme II BCM5708", 0),
	PCI_ROM(0x14e4, 0x16aa, "bnx2-5706S",       "Broadcom NetXtreme II BCM5706S", 0),
	PCI_ROM(0x14e4, 0x16ac, "bnx2-5708S",       "Broadcom NetXtreme II BCM5708S", 0),
};

PCI_DRIVER ( bnx2_driver, bnx2_nics, PCI_NO_CLASS );

DRIVER ( "BNX2", nic_driver, pci_driver, bnx2_driver, bnx2_probe, bnx2_disable );

/*
static struct pci_driver bnx2_driver __pci_driver = {
	.type     = NIC_DRIVER,
	.name     = "BNX2",              
	.probe    = bnx2_probe,
	.ids      = bnx2_nics,                  
	.id_count = sizeof(bnx2_nics)/sizeof(bnx2_nics[0]), 
	.class    = 0,    
};
*/
