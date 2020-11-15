/*
 * iPXE driver for Marvell Yukon 2 chipset. Derived from Linux sky2 driver
 * (v1.22), which was based on earlier sk98lin and skge drivers.
 *
 * This driver intentionally does not support all the features
 * of the original driver such as link fail-over and link management because
 * those should be done at higher levels.
 *
 * Copyright (C) 2005 Stephen Hemminger <shemminger@osdl.org>
 *
 * Modified for iPXE, April 2009 by Joshua Oreman
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_ONLY );

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <byteswap.h>
#include <mii.h>

#include "sky2.h"

#define DRV_NAME		"sky2"
#define DRV_VERSION		"1.22"
#define PFX			DRV_NAME " "

/*
 * The Yukon II chipset takes 64 bit command blocks (called list elements)
 * that are organized into three (receive, transmit, status) different rings
 * similar to Tigon3.
 *
 * Each ring start must be aligned to a 4k boundary. You will get mysterious
 * "invalid LE" errors if they're not.
 *
 * The card silently forces each ring size to be at least 128. If you
 * act as though one of them is smaller (by setting the below
 * #defines) you'll get bad bugs.
 */

#define RX_LE_SIZE	    	128
#define RX_LE_BYTES		(RX_LE_SIZE*sizeof(struct sky2_rx_le))
#define RX_RING_ALIGN		4096
#define RX_PENDING		(RX_LE_SIZE/6 - 2)

#define TX_RING_SIZE		128
#define TX_PENDING		(TX_RING_SIZE - 1)
#define TX_RING_ALIGN		4096
#define MAX_SKB_TX_LE		4

#define STATUS_RING_SIZE	512	/* 2 ports * (TX + RX) */
#define STATUS_LE_BYTES		(STATUS_RING_SIZE*sizeof(struct sky2_status_le))
#define STATUS_RING_ALIGN       4096
#define PHY_RETRIES		1000

#define SKY2_EEPROM_MAGIC	0x9955aabb


#define RING_NEXT(x,s)	(((x)+1) & ((s)-1))

static struct pci_device_id sky2_id_table[] = {
	PCI_ROM(0x1148, 0x9000, "sk9sxx", "Syskonnect SK-9Sxx", 0),
	PCI_ROM(0x1148, 0x9e00, "sk9exx", "Syskonnect SK-9Exx", 0),
	PCI_ROM(0x1186, 0x4b00, "dge560t", "D-Link DGE-560T", 0),
	PCI_ROM(0x1186, 0x4001, "dge550sx", "D-Link DGE-550SX", 0),
	PCI_ROM(0x1186, 0x4b02, "dge560sx", "D-Link DGE-560SX", 0),
	PCI_ROM(0x1186, 0x4b03, "dge550t", "D-Link DGE-550T", 0),
	PCI_ROM(0x11ab, 0x4340, "m88e8021", "Marvell 88E8021", 0),
	PCI_ROM(0x11ab, 0x4341, "m88e8022", "Marvell 88E8022", 0),
	PCI_ROM(0x11ab, 0x4342, "m88e8061", "Marvell 88E8061", 0),
	PCI_ROM(0x11ab, 0x4343, "m88e8062", "Marvell 88E8062", 0),
	PCI_ROM(0x11ab, 0x4344, "m88e8021b", "Marvell 88E8021", 0),
	PCI_ROM(0x11ab, 0x4345, "m88e8022b", "Marvell 88E8022", 0),
	PCI_ROM(0x11ab, 0x4346, "m88e8061b", "Marvell 88E8061", 0),
	PCI_ROM(0x11ab, 0x4347, "m88e8062b", "Marvell 88E8062", 0),
	PCI_ROM(0x11ab, 0x4350, "m88e8035", "Marvell 88E8035", 0),
	PCI_ROM(0x11ab, 0x4351, "m88e8036", "Marvell 88E8036", 0),
	PCI_ROM(0x11ab, 0x4352, "m88e8038", "Marvell 88E8038", 0),
	PCI_ROM(0x11ab, 0x4353, "m88e8039", "Marvell 88E8039", 0),
	PCI_ROM(0x11ab, 0x4354, "m88e8040", "Marvell 88E8040", 0),
	PCI_ROM(0x11ab, 0x4355, "m88e8040t", "Marvell 88E8040T", 0),
	PCI_ROM(0x11ab, 0x4356, "m88ec033", "Marvel 88EC033", 0),
	PCI_ROM(0x11ab, 0x4357, "m88e8042", "Marvell 88E8042", 0),
	PCI_ROM(0x11ab, 0x435a, "m88e8048", "Marvell 88E8048", 0),
	PCI_ROM(0x11ab, 0x4360, "m88e8052", "Marvell 88E8052", 0),
	PCI_ROM(0x11ab, 0x4361, "m88e8050", "Marvell 88E8050", 0),
	PCI_ROM(0x11ab, 0x4362, "m88e8053", "Marvell 88E8053", 0),
	PCI_ROM(0x11ab, 0x4363, "m88e8055", "Marvell 88E8055", 0),
	PCI_ROM(0x11ab, 0x4364, "m88e8056", "Marvell 88E8056", 0),
	PCI_ROM(0x11ab, 0x4365, "m88e8070", "Marvell 88E8070", 0),
	PCI_ROM(0x11ab, 0x4366, "m88ec036", "Marvell 88EC036", 0),
	PCI_ROM(0x11ab, 0x4367, "m88ec032", "Marvell 88EC032", 0),
	PCI_ROM(0x11ab, 0x4368, "m88ec034", "Marvell 88EC034", 0),
	PCI_ROM(0x11ab, 0x4369, "m88ec042", "Marvell 88EC042", 0),
	PCI_ROM(0x11ab, 0x436a, "m88e8058", "Marvell 88E8058", 0),
	PCI_ROM(0x11ab, 0x436b, "m88e8071", "Marvell 88E8071", 0),
	PCI_ROM(0x11ab, 0x436c, "m88e8072", "Marvell 88E8072", 0),
	PCI_ROM(0x11ab, 0x436d, "m88e8055b", "Marvell 88E8055", 0),
	PCI_ROM(0x11ab, 0x4370, "m88e8075", "Marvell 88E8075", 0),
	PCI_ROM(0x11ab, 0x4380, "m88e8057", "Marvell 88E8057", 0)
};

/* Avoid conditionals by using array */
static const unsigned txqaddr[] = { Q_XA1, Q_XA2 };
static const unsigned rxqaddr[] = { Q_R1, Q_R2 };
static const u32 portirq_msk[] = { Y2_IS_PORT_1, Y2_IS_PORT_2 };

static void sky2_set_multicast(struct net_device *dev);

/* Access to PHY via serial interconnect */
static int gm_phy_write(struct sky2_hw *hw, unsigned port, u16 reg, u16 val)
{
	int i;

	gma_write16(hw, port, GM_SMI_DATA, val);
	gma_write16(hw, port, GM_SMI_CTRL,
		    GM_SMI_CT_PHY_AD(PHY_ADDR_MARV) | GM_SMI_CT_REG_AD(reg));

	for (i = 0; i < PHY_RETRIES; i++) {
		u16 ctrl = gma_read16(hw, port, GM_SMI_CTRL);
		if (ctrl == 0xffff)
			goto io_error;

		if (!(ctrl & GM_SMI_CT_BUSY))
			return 0;

		udelay(10);
	}

	DBG(PFX "%s: phy write timeout\n", hw->dev[port]->name);
	return -ETIMEDOUT;

io_error:
	DBG(PFX "%s: phy I/O error\n", hw->dev[port]->name);
	return -EIO;
}

static int __gm_phy_read(struct sky2_hw *hw, unsigned port, u16 reg, u16 *val)
{
	int i;

	gma_write16(hw, port, GM_SMI_CTRL, GM_SMI_CT_PHY_AD(PHY_ADDR_MARV)
		    | GM_SMI_CT_REG_AD(reg) | GM_SMI_CT_OP_RD);

	for (i = 0; i < PHY_RETRIES; i++) {
		u16 ctrl = gma_read16(hw, port, GM_SMI_CTRL);
		if (ctrl == 0xffff)
			goto io_error;

		if (ctrl & GM_SMI_CT_RD_VAL) {
			*val = gma_read16(hw, port, GM_SMI_DATA);
			return 0;
		}

		udelay(10);
	}

	DBG(PFX "%s: phy read timeout\n", hw->dev[port]->name);
	return -ETIMEDOUT;
io_error:
	DBG(PFX "%s: phy I/O error\n", hw->dev[port]->name);
	return -EIO;
}

static inline u16 gm_phy_read(struct sky2_hw *hw, unsigned port, u16 reg)
{
	u16 v = 0;
	__gm_phy_read(hw, port, reg, &v);
	return v;
}


static void sky2_power_on(struct sky2_hw *hw)
{
	/* switch power to VCC (WA for VAUX problem) */
	sky2_write8(hw, B0_POWER_CTRL,
		    PC_VAUX_ENA | PC_VCC_ENA | PC_VAUX_OFF | PC_VCC_ON);

	/* disable Core Clock Division, */
	sky2_write32(hw, B2_Y2_CLK_CTRL, Y2_CLK_DIV_DIS);

	if (hw->chip_id == CHIP_ID_YUKON_XL && hw->chip_rev > 1)
		/* enable bits are inverted */
		sky2_write8(hw, B2_Y2_CLK_GATE,
			    Y2_PCI_CLK_LNK1_DIS | Y2_COR_CLK_LNK1_DIS |
			    Y2_CLK_GAT_LNK1_DIS | Y2_PCI_CLK_LNK2_DIS |
			    Y2_COR_CLK_LNK2_DIS | Y2_CLK_GAT_LNK2_DIS);
	else
		sky2_write8(hw, B2_Y2_CLK_GATE, 0);

	if (hw->flags & SKY2_HW_ADV_POWER_CTL) {
		u32 reg;

		sky2_pci_write32(hw, PCI_DEV_REG3, 0);

		reg = sky2_pci_read32(hw, PCI_DEV_REG4);
		/* set all bits to 0 except bits 15..12 and 8 */
		reg &= P_ASPM_CONTROL_MSK;
		sky2_pci_write32(hw, PCI_DEV_REG4, reg);

		reg = sky2_pci_read32(hw, PCI_DEV_REG5);
		/* set all bits to 0 except bits 28 & 27 */
		reg &= P_CTL_TIM_VMAIN_AV_MSK;
		sky2_pci_write32(hw, PCI_DEV_REG5, reg);

		sky2_pci_write32(hw, PCI_CFG_REG_1, 0);

		/* Enable workaround for dev 4.107 on Yukon-Ultra & Extreme */
		reg = sky2_read32(hw, B2_GP_IO);
		reg |= GLB_GPIO_STAT_RACE_DIS;
		sky2_write32(hw, B2_GP_IO, reg);

		sky2_read32(hw, B2_GP_IO);
	}
}

static void sky2_power_aux(struct sky2_hw *hw)
{
	if (hw->chip_id == CHIP_ID_YUKON_XL && hw->chip_rev > 1)
		sky2_write8(hw, B2_Y2_CLK_GATE, 0);
	else
		/* enable bits are inverted */
		sky2_write8(hw, B2_Y2_CLK_GATE,
			    Y2_PCI_CLK_LNK1_DIS | Y2_COR_CLK_LNK1_DIS |
			    Y2_CLK_GAT_LNK1_DIS | Y2_PCI_CLK_LNK2_DIS |
			    Y2_COR_CLK_LNK2_DIS | Y2_CLK_GAT_LNK2_DIS);

	/* switch power to VAUX */
	if (sky2_read16(hw, B0_CTST) & Y2_VAUX_AVAIL)
		sky2_write8(hw, B0_POWER_CTRL,
			    (PC_VAUX_ENA | PC_VCC_ENA |
			     PC_VAUX_ON | PC_VCC_OFF));
}

static void sky2_gmac_reset(struct sky2_hw *hw, unsigned port)
{
	u16 reg;

	/* disable all GMAC IRQ's */
	sky2_write8(hw, SK_REG(port, GMAC_IRQ_MSK), 0);

	gma_write16(hw, port, GM_MC_ADDR_H1, 0);	/* clear MC hash */
	gma_write16(hw, port, GM_MC_ADDR_H2, 0);
	gma_write16(hw, port, GM_MC_ADDR_H3, 0);
	gma_write16(hw, port, GM_MC_ADDR_H4, 0);

	reg = gma_read16(hw, port, GM_RX_CTRL);
	reg |= GM_RXCR_UCF_ENA | GM_RXCR_MCF_ENA;
	gma_write16(hw, port, GM_RX_CTRL, reg);
}

/* flow control to advertise bits */
static const u16 copper_fc_adv[] = {
	[FC_NONE]	= 0,
	[FC_TX]		= PHY_M_AN_ASP,
	[FC_RX]		= PHY_M_AN_PC,
	[FC_BOTH]	= PHY_M_AN_PC | PHY_M_AN_ASP,
};

/* flow control to advertise bits when using 1000BaseX */
static const u16 fiber_fc_adv[] = {
	[FC_NONE] = PHY_M_P_NO_PAUSE_X,
	[FC_TX]   = PHY_M_P_ASYM_MD_X,
	[FC_RX]	  = PHY_M_P_SYM_MD_X,
	[FC_BOTH] = PHY_M_P_BOTH_MD_X,
};

/* flow control to GMA disable bits */
static const u16 gm_fc_disable[] = {
	[FC_NONE] = GM_GPCR_FC_RX_DIS | GM_GPCR_FC_TX_DIS,
	[FC_TX]	  = GM_GPCR_FC_RX_DIS,
	[FC_RX]	  = GM_GPCR_FC_TX_DIS,
	[FC_BOTH] = 0,
};


static void sky2_phy_init(struct sky2_hw *hw, unsigned port)
{
	struct sky2_port *sky2 = netdev_priv(hw->dev[port]);
	u16 ctrl, ct1000, adv, pg, ledctrl, ledover, reg;

	if (sky2->autoneg == AUTONEG_ENABLE &&
	    !(hw->flags & SKY2_HW_NEWER_PHY)) {
		u16 ectrl = gm_phy_read(hw, port, PHY_MARV_EXT_CTRL);

		ectrl &= ~(PHY_M_EC_M_DSC_MSK | PHY_M_EC_S_DSC_MSK |
			   PHY_M_EC_MAC_S_MSK);
		ectrl |= PHY_M_EC_MAC_S(MAC_TX_CLK_25_MHZ);

		/* on PHY 88E1040 Rev.D0 (and newer) downshift control changed */
		if (hw->chip_id == CHIP_ID_YUKON_EC)
			/* set downshift counter to 3x and enable downshift */
			ectrl |= PHY_M_EC_DSC_2(2) | PHY_M_EC_DOWN_S_ENA;
		else
			/* set master & slave downshift counter to 1x */
			ectrl |= PHY_M_EC_M_DSC(0) | PHY_M_EC_S_DSC(1);

		gm_phy_write(hw, port, PHY_MARV_EXT_CTRL, ectrl);
	}

	ctrl = gm_phy_read(hw, port, PHY_MARV_PHY_CTRL);
	if (sky2_is_copper(hw)) {
		if (!(hw->flags & SKY2_HW_GIGABIT)) {
			/* enable automatic crossover */
			ctrl |= PHY_M_PC_MDI_XMODE(PHY_M_PC_ENA_AUTO) >> 1;

			if (hw->chip_id == CHIP_ID_YUKON_FE_P &&
			    hw->chip_rev == CHIP_REV_YU_FE2_A0) {
				u16 spec;

				/* Enable Class A driver for FE+ A0 */
				spec = gm_phy_read(hw, port, PHY_MARV_FE_SPEC_2);
				spec |= PHY_M_FESC_SEL_CL_A;
				gm_phy_write(hw, port, PHY_MARV_FE_SPEC_2, spec);
			}
		} else {
			/* disable energy detect */
			ctrl &= ~PHY_M_PC_EN_DET_MSK;

			/* enable automatic crossover */
			ctrl |= PHY_M_PC_MDI_XMODE(PHY_M_PC_ENA_AUTO);

			/* downshift on PHY 88E1112 and 88E1149 is changed */
			if (sky2->autoneg == AUTONEG_ENABLE
			    && (hw->flags & SKY2_HW_NEWER_PHY)) {
				/* set downshift counter to 3x and enable downshift */
				ctrl &= ~PHY_M_PC_DSC_MSK;
				ctrl |= PHY_M_PC_DSC(2) | PHY_M_PC_DOWN_S_ENA;
			}
		}
	} else {
		/* workaround for deviation #4.88 (CRC errors) */
		/* disable Automatic Crossover */

		ctrl &= ~PHY_M_PC_MDIX_MSK;
	}

	gm_phy_write(hw, port, PHY_MARV_PHY_CTRL, ctrl);

	/* special setup for PHY 88E1112 Fiber */
	if (hw->chip_id == CHIP_ID_YUKON_XL && (hw->flags & SKY2_HW_FIBRE_PHY)) {
		pg = gm_phy_read(hw, port, PHY_MARV_EXT_ADR);

		/* Fiber: select 1000BASE-X only mode MAC Specific Ctrl Reg. */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 2);
		ctrl = gm_phy_read(hw, port, PHY_MARV_PHY_CTRL);
		ctrl &= ~PHY_M_MAC_MD_MSK;
		ctrl |= PHY_M_MAC_MODE_SEL(PHY_M_MAC_MD_1000BX);
		gm_phy_write(hw, port, PHY_MARV_PHY_CTRL, ctrl);

		if (hw->pmd_type  == 'P') {
			/* select page 1 to access Fiber registers */
			gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 1);

			/* for SFP-module set SIGDET polarity to low */
			ctrl = gm_phy_read(hw, port, PHY_MARV_PHY_CTRL);
			ctrl |= PHY_M_FIB_SIGD_POL;
			gm_phy_write(hw, port, PHY_MARV_PHY_CTRL, ctrl);
		}

		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, pg);
	}

	ctrl = PHY_CT_RESET;
	ct1000 = 0;
	adv = PHY_AN_CSMA;
	reg = 0;

	if (sky2->autoneg == AUTONEG_ENABLE) {
		if (sky2_is_copper(hw)) {
			if (sky2->advertising & ADVERTISED_1000baseT_Full)
				ct1000 |= PHY_M_1000C_AFD;
			if (sky2->advertising & ADVERTISED_1000baseT_Half)
				ct1000 |= PHY_M_1000C_AHD;
			if (sky2->advertising & ADVERTISED_100baseT_Full)
				adv |= PHY_M_AN_100_FD;
			if (sky2->advertising & ADVERTISED_100baseT_Half)
				adv |= PHY_M_AN_100_HD;
			if (sky2->advertising & ADVERTISED_10baseT_Full)
				adv |= PHY_M_AN_10_FD;
			if (sky2->advertising & ADVERTISED_10baseT_Half)
				adv |= PHY_M_AN_10_HD;

			adv |= copper_fc_adv[sky2->flow_mode];
		} else {	/* special defines for FIBER (88E1040S only) */
			if (sky2->advertising & ADVERTISED_1000baseT_Full)
				adv |= PHY_M_AN_1000X_AFD;
			if (sky2->advertising & ADVERTISED_1000baseT_Half)
				adv |= PHY_M_AN_1000X_AHD;

			adv |= fiber_fc_adv[sky2->flow_mode];
		}

		/* Restart Auto-negotiation */
		ctrl |= PHY_CT_ANE | PHY_CT_RE_CFG;
	} else {
		/* forced speed/duplex settings */
		ct1000 = PHY_M_1000C_MSE;

		/* Disable auto update for duplex flow control and speed */
		reg |= GM_GPCR_AU_ALL_DIS;

		switch (sky2->speed) {
		case SPEED_1000:
			ctrl |= PHY_CT_SP1000;
			reg |= GM_GPCR_SPEED_1000;
			break;
		case SPEED_100:
			ctrl |= PHY_CT_SP100;
			reg |= GM_GPCR_SPEED_100;
			break;
		}

		if (sky2->duplex == DUPLEX_FULL) {
			reg |= GM_GPCR_DUP_FULL;
			ctrl |= PHY_CT_DUP_MD;
		} else if (sky2->speed < SPEED_1000)
			sky2->flow_mode = FC_NONE;


		reg |= gm_fc_disable[sky2->flow_mode];

		/* Forward pause packets to GMAC? */
		if (sky2->flow_mode & FC_RX)
			sky2_write8(hw, SK_REG(port, GMAC_CTRL), GMC_PAUSE_ON);
		else
			sky2_write8(hw, SK_REG(port, GMAC_CTRL), GMC_PAUSE_OFF);
	}

	gma_write16(hw, port, GM_GP_CTRL, reg);

	if (hw->flags & SKY2_HW_GIGABIT)
		gm_phy_write(hw, port, PHY_MARV_1000T_CTRL, ct1000);

	gm_phy_write(hw, port, PHY_MARV_AUNE_ADV, adv);
	gm_phy_write(hw, port, PHY_MARV_CTRL, ctrl);

	/* Setup Phy LED's */
	ledctrl = PHY_M_LED_PULS_DUR(PULS_170MS);
	ledover = 0;

	switch (hw->chip_id) {
	case CHIP_ID_YUKON_FE:
		/* on 88E3082 these bits are at 11..9 (shifted left) */
		ledctrl |= PHY_M_LED_BLINK_RT(BLINK_84MS) << 1;

		ctrl = gm_phy_read(hw, port, PHY_MARV_FE_LED_PAR);

		/* delete ACT LED control bits */
		ctrl &= ~PHY_M_FELP_LED1_MSK;
		/* change ACT LED control to blink mode */
		ctrl |= PHY_M_FELP_LED1_CTRL(LED_PAR_CTRL_ACT_BL);
		gm_phy_write(hw, port, PHY_MARV_FE_LED_PAR, ctrl);
		break;

	case CHIP_ID_YUKON_FE_P:
		/* Enable Link Partner Next Page */
		ctrl = gm_phy_read(hw, port, PHY_MARV_PHY_CTRL);
		ctrl |= PHY_M_PC_ENA_LIP_NP;

		/* disable Energy Detect and enable scrambler */
		ctrl &= ~(PHY_M_PC_ENA_ENE_DT | PHY_M_PC_DIS_SCRAMB);
		gm_phy_write(hw, port, PHY_MARV_PHY_CTRL, ctrl);

		/* set LED2 -> ACT, LED1 -> LINK, LED0 -> SPEED */
		ctrl = PHY_M_FELP_LED2_CTRL(LED_PAR_CTRL_ACT_BL) |
			PHY_M_FELP_LED1_CTRL(LED_PAR_CTRL_LINK) |
			PHY_M_FELP_LED0_CTRL(LED_PAR_CTRL_SPEED);

		gm_phy_write(hw, port, PHY_MARV_FE_LED_PAR, ctrl);
		break;

	case CHIP_ID_YUKON_XL:
		pg = gm_phy_read(hw, port, PHY_MARV_EXT_ADR);

		/* select page 3 to access LED control register */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 3);

		/* set LED Function Control register */
		gm_phy_write(hw, port, PHY_MARV_PHY_CTRL,
			     (PHY_M_LEDC_LOS_CTRL(1) |	/* LINK/ACT */
			      PHY_M_LEDC_INIT_CTRL(7) |	/* 10 Mbps */
			      PHY_M_LEDC_STA1_CTRL(7) |	/* 100 Mbps */
			      PHY_M_LEDC_STA0_CTRL(7)));	/* 1000 Mbps */

		/* set Polarity Control register */
		gm_phy_write(hw, port, PHY_MARV_PHY_STAT,
			     (PHY_M_POLC_LS1_P_MIX(4) |
			      PHY_M_POLC_IS0_P_MIX(4) |
			      PHY_M_POLC_LOS_CTRL(2) |
			      PHY_M_POLC_INIT_CTRL(2) |
			      PHY_M_POLC_STA1_CTRL(2) |
			      PHY_M_POLC_STA0_CTRL(2)));

		/* restore page register */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, pg);
		break;

	case CHIP_ID_YUKON_EC_U:
	case CHIP_ID_YUKON_EX:
	case CHIP_ID_YUKON_SUPR:
		pg = gm_phy_read(hw, port, PHY_MARV_EXT_ADR);

		/* select page 3 to access LED control register */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 3);

		/* set LED Function Control register */
		gm_phy_write(hw, port, PHY_MARV_PHY_CTRL,
			     (PHY_M_LEDC_LOS_CTRL(1) |	/* LINK/ACT */
			      PHY_M_LEDC_INIT_CTRL(8) |	/* 10 Mbps */
			      PHY_M_LEDC_STA1_CTRL(7) |	/* 100 Mbps */
			      PHY_M_LEDC_STA0_CTRL(7)));/* 1000 Mbps */

		/* set Blink Rate in LED Timer Control Register */
		gm_phy_write(hw, port, PHY_MARV_INT_MASK,
			     ledctrl | PHY_M_LED_BLINK_RT(BLINK_84MS));
		/* restore page register */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, pg);
		break;

	default:
		/* set Tx LED (LED_TX) to blink mode on Rx OR Tx activity */
		ledctrl |= PHY_M_LED_BLINK_RT(BLINK_84MS) | PHY_M_LEDC_TX_CTRL;

		/* turn off the Rx LED (LED_RX) */
		ledover |= PHY_M_LED_MO_RX(MO_LED_OFF);
	}

	if (hw->chip_id == CHIP_ID_YUKON_EC_U || hw->chip_id == CHIP_ID_YUKON_UL_2) {
		/* apply fixes in PHY AFE */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 255);

		/* increase differential signal amplitude in 10BASE-T */
		gm_phy_write(hw, port, 0x18, 0xaa99);
		gm_phy_write(hw, port, 0x17, 0x2011);

		if (hw->chip_id == CHIP_ID_YUKON_EC_U) {
			/* fix for IEEE A/B Symmetry failure in 1000BASE-T */
			gm_phy_write(hw, port, 0x18, 0xa204);
			gm_phy_write(hw, port, 0x17, 0x2002);
		}

		/* set page register to 0 */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 0);
	} else if (hw->chip_id == CHIP_ID_YUKON_FE_P &&
		   hw->chip_rev == CHIP_REV_YU_FE2_A0) {
		/* apply workaround for integrated resistors calibration */
		gm_phy_write(hw, port, PHY_MARV_PAGE_ADDR, 17);
		gm_phy_write(hw, port, PHY_MARV_PAGE_DATA, 0x3f60);
	} else if (hw->chip_id != CHIP_ID_YUKON_EX &&
		   hw->chip_id < CHIP_ID_YUKON_SUPR) {
		/* no effect on Yukon-XL */
		gm_phy_write(hw, port, PHY_MARV_LED_CTRL, ledctrl);

		if (sky2->autoneg == AUTONEG_DISABLE || sky2->speed == SPEED_100) {
			/* turn on 100 Mbps LED (LED_LINK100) */
			ledover |= PHY_M_LED_MO_100(MO_LED_ON);
		}

		if (ledover)
			gm_phy_write(hw, port, PHY_MARV_LED_OVER, ledover);

	}

	/* Enable phy interrupt on auto-negotiation complete (or link up) */
	if (sky2->autoneg == AUTONEG_ENABLE)
		gm_phy_write(hw, port, PHY_MARV_INT_MASK, PHY_M_IS_AN_COMPL);
	else
		gm_phy_write(hw, port, PHY_MARV_INT_MASK, PHY_M_DEF_MSK);
}

static const u32 phy_power[] = { PCI_Y2_PHY1_POWD, PCI_Y2_PHY2_POWD };
static const u32 coma_mode[] = { PCI_Y2_PHY1_COMA, PCI_Y2_PHY2_COMA };

static void sky2_phy_power_up(struct sky2_hw *hw, unsigned port)
{
	u32 reg1;

	sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_ON);
	reg1 = sky2_pci_read32(hw, PCI_DEV_REG1);
	reg1 &= ~phy_power[port];

	if (hw->chip_id == CHIP_ID_YUKON_XL && hw->chip_rev > 1)
		reg1 |= coma_mode[port];

	sky2_pci_write32(hw, PCI_DEV_REG1, reg1);
	sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
	sky2_pci_read32(hw, PCI_DEV_REG1);

	if (hw->chip_id == CHIP_ID_YUKON_FE)
		gm_phy_write(hw, port, PHY_MARV_CTRL, PHY_CT_ANE);
	else if (hw->flags & SKY2_HW_ADV_POWER_CTL)
		sky2_write8(hw, SK_REG(port, GPHY_CTRL), GPC_RST_CLR);
}

static void sky2_phy_power_down(struct sky2_hw *hw, unsigned port)
{
	u32 reg1;
	u16 ctrl;

	/* release GPHY Control reset */
	sky2_write8(hw, SK_REG(port, GPHY_CTRL), GPC_RST_CLR);

	/* release GMAC reset */
	sky2_write8(hw, SK_REG(port, GMAC_CTRL), GMC_RST_CLR);

	if (hw->flags & SKY2_HW_NEWER_PHY) {
		/* select page 2 to access MAC control register */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 2);

		ctrl = gm_phy_read(hw, port, PHY_MARV_PHY_CTRL);
		/* allow GMII Power Down */
		ctrl &= ~PHY_M_MAC_GMIF_PUP;
		gm_phy_write(hw, port, PHY_MARV_PHY_CTRL, ctrl);

		/* set page register back to 0 */
		gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 0);
	}

	/* setup General Purpose Control Register */
	gma_write16(hw, port, GM_GP_CTRL,
		    GM_GPCR_FL_PASS | GM_GPCR_SPEED_100 | GM_GPCR_AU_ALL_DIS);

	if (hw->chip_id != CHIP_ID_YUKON_EC) {
		if (hw->chip_id == CHIP_ID_YUKON_EC_U) {
			/* select page 2 to access MAC control register */
			gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 2);

			ctrl = gm_phy_read(hw, port, PHY_MARV_PHY_CTRL);
			/* enable Power Down */
			ctrl |= PHY_M_PC_POW_D_ENA;
			gm_phy_write(hw, port, PHY_MARV_PHY_CTRL, ctrl);

			/* set page register back to 0 */
			gm_phy_write(hw, port, PHY_MARV_EXT_ADR, 0);
		}

		/* set IEEE compatible Power Down Mode (dev. #4.99) */
		gm_phy_write(hw, port, PHY_MARV_CTRL, PHY_CT_PDOWN);
	}

	sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_ON);
	reg1 = sky2_pci_read32(hw, PCI_DEV_REG1);
	reg1 |= phy_power[port];		/* set PHY to PowerDown/COMA Mode */
	sky2_pci_write32(hw, PCI_DEV_REG1, reg1);
	sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
}

static void sky2_set_tx_stfwd(struct sky2_hw *hw, unsigned port)
{
	if ( (hw->chip_id == CHIP_ID_YUKON_EX &&
	      hw->chip_rev != CHIP_REV_YU_EX_A0) ||
	     hw->chip_id == CHIP_ID_YUKON_FE_P ||
	     hw->chip_id == CHIP_ID_YUKON_SUPR) {
		/* disable jumbo frames on devices that support them */
		sky2_write32(hw, SK_REG(port, TX_GMF_CTRL_T),
			     TX_JUMBO_DIS | TX_STFW_ENA);
	} else {
		sky2_write32(hw, SK_REG(port, TX_GMF_CTRL_T), TX_STFW_ENA);
	}
}

static void sky2_mac_init(struct sky2_hw *hw, unsigned port)
{
	u16 reg;
	u32 rx_reg;
	int i;
	const u8 *addr = hw->dev[port]->ll_addr;

	sky2_write8(hw, SK_REG(port, GPHY_CTRL), GPC_RST_SET);
	sky2_write8(hw, SK_REG(port, GPHY_CTRL), GPC_RST_CLR);

	sky2_write8(hw, SK_REG(port, GMAC_CTRL), GMC_RST_CLR);

	if (hw->chip_id == CHIP_ID_YUKON_XL && hw->chip_rev == 0 && port == 1) {
		/* WA DEV_472 -- looks like crossed wires on port 2 */
		/* clear GMAC 1 Control reset */
		sky2_write8(hw, SK_REG(0, GMAC_CTRL), GMC_RST_CLR);
		do {
			sky2_write8(hw, SK_REG(1, GMAC_CTRL), GMC_RST_SET);
			sky2_write8(hw, SK_REG(1, GMAC_CTRL), GMC_RST_CLR);
		} while (gm_phy_read(hw, 1, PHY_MARV_ID0) != PHY_MARV_ID0_VAL ||
			 gm_phy_read(hw, 1, PHY_MARV_ID1) != PHY_MARV_ID1_Y2 ||
			 gm_phy_read(hw, 1, PHY_MARV_INT_MASK) != 0);
	}

	sky2_read16(hw, SK_REG(port, GMAC_IRQ_SRC));

	/* Enable Transmit FIFO Underrun */
	sky2_write8(hw, SK_REG(port, GMAC_IRQ_MSK), GMAC_DEF_MSK);

	sky2_phy_power_up(hw, port);
	sky2_phy_init(hw, port);

	/* MIB clear */
	reg = gma_read16(hw, port, GM_PHY_ADDR);
	gma_write16(hw, port, GM_PHY_ADDR, reg | GM_PAR_MIB_CLR);

	for (i = GM_MIB_CNT_BASE; i <= GM_MIB_CNT_END; i += 4)
		gma_read16(hw, port, i);
	gma_write16(hw, port, GM_PHY_ADDR, reg);

	/* transmit control */
	gma_write16(hw, port, GM_TX_CTRL, TX_COL_THR(TX_COL_DEF));

	/* receive control reg: unicast + multicast + no FCS  */
	gma_write16(hw, port, GM_RX_CTRL,
		    GM_RXCR_UCF_ENA | GM_RXCR_CRC_DIS | GM_RXCR_MCF_ENA);

	/* transmit flow control */
	gma_write16(hw, port, GM_TX_FLOW_CTRL, 0xffff);

	/* transmit parameter */
	gma_write16(hw, port, GM_TX_PARAM,
		    TX_JAM_LEN_VAL(TX_JAM_LEN_DEF) |
		    TX_JAM_IPG_VAL(TX_JAM_IPG_DEF) |
		    TX_IPG_JAM_DATA(TX_IPG_JAM_DEF) |
		    TX_BACK_OFF_LIM(TX_BOF_LIM_DEF));

	/* serial mode register */
	reg = DATA_BLIND_VAL(DATA_BLIND_DEF) |
		GM_SMOD_VLAN_ENA | IPG_DATA_VAL(IPG_DATA_DEF);

	gma_write16(hw, port, GM_SERIAL_MODE, reg);

	/* virtual address for data */
	gma_set_addr(hw, port, GM_SRC_ADDR_2L, addr);

	/* physical address: used for pause frames */
	gma_set_addr(hw, port, GM_SRC_ADDR_1L, addr);

	/* ignore counter overflows */
	gma_write16(hw, port, GM_TX_IRQ_MSK, 0);
	gma_write16(hw, port, GM_RX_IRQ_MSK, 0);
	gma_write16(hw, port, GM_TR_IRQ_MSK, 0);

	/* Configure Rx MAC FIFO */
	sky2_write8(hw, SK_REG(port, RX_GMF_CTRL_T), GMF_RST_CLR);
	rx_reg = GMF_OPER_ON | GMF_RX_F_FL_ON;
	if (hw->chip_id == CHIP_ID_YUKON_EX ||
	    hw->chip_id == CHIP_ID_YUKON_FE_P)
		rx_reg |= GMF_RX_OVER_ON;

	sky2_write32(hw, SK_REG(port, RX_GMF_CTRL_T), rx_reg);

	if (hw->chip_id == CHIP_ID_YUKON_XL) {
		/* Hardware errata - clear flush mask */
		sky2_write16(hw, SK_REG(port, RX_GMF_FL_MSK), 0);
	} else {
		/* Flush Rx MAC FIFO on any flow control or error */
		sky2_write16(hw, SK_REG(port, RX_GMF_FL_MSK), GMR_FS_ANY_ERR);
	}

	/* Set threshold to 0xa (64 bytes) + 1 to workaround pause bug  */
	reg = RX_GMF_FL_THR_DEF + 1;
	/* Another magic mystery workaround from sk98lin */
	if (hw->chip_id == CHIP_ID_YUKON_FE_P &&
	    hw->chip_rev == CHIP_REV_YU_FE2_A0)
		reg = 0x178;
	sky2_write16(hw, SK_REG(port, RX_GMF_FL_THR), reg);

	/* Configure Tx MAC FIFO */
	sky2_write8(hw, SK_REG(port, TX_GMF_CTRL_T), GMF_RST_CLR);
	sky2_write16(hw, SK_REG(port, TX_GMF_CTRL_T), GMF_OPER_ON);

	/* On chips without ram buffer, pause is controlled by MAC level */
	if (!(hw->flags & SKY2_HW_RAM_BUFFER)) {
		sky2_write8(hw, SK_REG(port, RX_GMF_LP_THR), 768/8);
		sky2_write8(hw, SK_REG(port, RX_GMF_UP_THR), 1024/8);

		sky2_set_tx_stfwd(hw, port);
	}

	if (hw->chip_id == CHIP_ID_YUKON_FE_P &&
	    hw->chip_rev == CHIP_REV_YU_FE2_A0) {
		/* disable dynamic watermark */
		reg = sky2_read16(hw, SK_REG(port, TX_GMF_EA));
		reg &= ~TX_DYN_WM_ENA;
		sky2_write16(hw, SK_REG(port, TX_GMF_EA), reg);
	}
}

/* Assign Ram Buffer allocation to queue */
static void sky2_ramset(struct sky2_hw *hw, u16 q, u32 start, u32 space)
{
	u32 end;

	/* convert from K bytes to qwords used for hw register */
	start *= 1024/8;
	space *= 1024/8;
	end = start + space - 1;

	sky2_write8(hw, RB_ADDR(q, RB_CTRL), RB_RST_CLR);
	sky2_write32(hw, RB_ADDR(q, RB_START), start);
	sky2_write32(hw, RB_ADDR(q, RB_END), end);
	sky2_write32(hw, RB_ADDR(q, RB_WP), start);
	sky2_write32(hw, RB_ADDR(q, RB_RP), start);

	if (q == Q_R1 || q == Q_R2) {
		u32 tp = space - space/4;

		/* On receive queue's set the thresholds
		 * give receiver priority when > 3/4 full
		 * send pause when down to 2K
		 */
		sky2_write32(hw, RB_ADDR(q, RB_RX_UTHP), tp);
		sky2_write32(hw, RB_ADDR(q, RB_RX_LTHP), space/2);

		tp = space - 2048/8;
		sky2_write32(hw, RB_ADDR(q, RB_RX_UTPP), tp);
		sky2_write32(hw, RB_ADDR(q, RB_RX_LTPP), space/4);
	} else {
		/* Enable store & forward on Tx queue's because
		 * Tx FIFO is only 1K on Yukon
		 */
		sky2_write8(hw, RB_ADDR(q, RB_CTRL), RB_ENA_STFWD);
	}

	sky2_write8(hw, RB_ADDR(q, RB_CTRL), RB_ENA_OP_MD);
	sky2_read8(hw, RB_ADDR(q, RB_CTRL));
}

/* Setup Bus Memory Interface */
static void sky2_qset(struct sky2_hw *hw, u16 q)
{
	sky2_write32(hw, Q_ADDR(q, Q_CSR), BMU_CLR_RESET);
	sky2_write32(hw, Q_ADDR(q, Q_CSR), BMU_OPER_INIT);
	sky2_write32(hw, Q_ADDR(q, Q_CSR), BMU_FIFO_OP_ON);
	sky2_write32(hw, Q_ADDR(q, Q_WM),  BMU_WM_DEFAULT);
}

/* Setup prefetch unit registers. This is the interface between
 * hardware and driver list elements
 */
static void sky2_prefetch_init(struct sky2_hw *hw, u32 qaddr,
				      u64 addr, u32 last)
{
	sky2_write32(hw, Y2_QADDR(qaddr, PREF_UNIT_CTRL), PREF_UNIT_RST_SET);
	sky2_write32(hw, Y2_QADDR(qaddr, PREF_UNIT_CTRL), PREF_UNIT_RST_CLR);
	sky2_write32(hw, Y2_QADDR(qaddr, PREF_UNIT_ADDR_HI), addr >> 32);
	sky2_write32(hw, Y2_QADDR(qaddr, PREF_UNIT_ADDR_LO), (u32) addr);
	sky2_write16(hw, Y2_QADDR(qaddr, PREF_UNIT_LAST_IDX), last);
	sky2_write32(hw, Y2_QADDR(qaddr, PREF_UNIT_CTRL), PREF_UNIT_OP_ON);

	sky2_read32(hw, Y2_QADDR(qaddr, PREF_UNIT_CTRL));
}

static inline struct sky2_tx_le *get_tx_le(struct sky2_port *sky2)
{
	struct sky2_tx_le *le = sky2->tx_le + sky2->tx_prod;

	sky2->tx_prod = RING_NEXT(sky2->tx_prod, TX_RING_SIZE);
	le->ctrl = 0;
	return le;
}

static void tx_init(struct sky2_port *sky2)
{
	struct sky2_tx_le *le;

	sky2->tx_prod = sky2->tx_cons = 0;

	le = get_tx_le(sky2);
	le->addr = 0;
	le->opcode = OP_ADDR64 | HW_OWNER;
}

static inline struct tx_ring_info *tx_le_re(struct sky2_port *sky2,
					    struct sky2_tx_le *le)
{
	return sky2->tx_ring + (le - sky2->tx_le);
}

/* Update chip's next pointer */
static inline void sky2_put_idx(struct sky2_hw *hw, unsigned q, u16 idx)
{
	/* Make sure write' to descriptors are complete before we tell hardware */
	wmb();
	sky2_write16(hw, Y2_QADDR(q, PREF_UNIT_PUT_IDX), idx);
	DBGIO(PFX "queue %#x idx <- %d\n", q, idx);
}


static inline struct sky2_rx_le *sky2_next_rx(struct sky2_port *sky2)
{
	struct sky2_rx_le *le = sky2->rx_le + sky2->rx_put;

	sky2->rx_put = RING_NEXT(sky2->rx_put, RX_LE_SIZE);
	le->ctrl = 0;
	return le;
}

/* Build description to hardware for one receive segment */
static void sky2_rx_add(struct sky2_port *sky2,  u8 op,
			u32 map, unsigned len)
{
	struct sky2_rx_le *le;

	le = sky2_next_rx(sky2);
	le->addr = cpu_to_le32(map);
	le->length = cpu_to_le16(len);
	le->opcode = op | HW_OWNER;
}

/* Build description to hardware for one possibly fragmented skb */
static void sky2_rx_submit(struct sky2_port *sky2,
			   const struct rx_ring_info *re)
{
	sky2_rx_add(sky2, OP_PACKET, re->data_addr, sky2->rx_data_size);
}


static void sky2_rx_map_iob(struct pci_device *pdev __unused,
			    struct rx_ring_info *re,
			    unsigned size __unused)
{
	struct io_buffer *iob = re->iob;
	re->data_addr = virt_to_bus(iob->data);
}

/* Diable the checksum offloading.
 */
static void rx_set_checksum(struct sky2_port *sky2)
{
	struct sky2_rx_le *le = sky2_next_rx(sky2);

	le->addr = cpu_to_le32((ETH_HLEN << 16) | ETH_HLEN);
	le->ctrl = 0;
	le->opcode = OP_TCPSTART | HW_OWNER;

	sky2_write32(sky2->hw,
		     Q_ADDR(rxqaddr[sky2->port], Q_CSR),
		     BMU_DIS_RX_CHKSUM);
}

/*
 * The RX Stop command will not work for Yukon-2 if the BMU does not
 * reach the end of packet and since we can't make sure that we have
 * incoming data, we must reset the BMU while it is not doing a DMA
 * transfer. Since it is possible that the RX path is still active,
 * the RX RAM buffer will be stopped first, so any possible incoming
 * data will not trigger a DMA. After the RAM buffer is stopped, the
 * BMU is polled until any DMA in progress is ended and only then it
 * will be reset.
 */
static void sky2_rx_stop(struct sky2_port *sky2)
{
	struct sky2_hw *hw = sky2->hw;
	unsigned rxq = rxqaddr[sky2->port];
	int i;

	/* disable the RAM Buffer receive queue */
	sky2_write8(hw, RB_ADDR(rxq, RB_CTRL), RB_DIS_OP_MD);

	for (i = 0; i < 0xffff; i++)
		if (sky2_read8(hw, RB_ADDR(rxq, Q_RSL))
		    == sky2_read8(hw, RB_ADDR(rxq, Q_RL)))
			goto stopped;

	DBG(PFX "%s: receiver stop failed\n", sky2->netdev->name);
stopped:
	sky2_write32(hw, Q_ADDR(rxq, Q_CSR), BMU_RST_SET | BMU_FIFO_RST);

	/* reset the Rx prefetch unit */
	sky2_write32(hw, Y2_QADDR(rxq, PREF_UNIT_CTRL), PREF_UNIT_RST_SET);
	wmb();
}

/* Clean out receive buffer area, assumes receiver hardware stopped */
static void sky2_rx_clean(struct sky2_port *sky2)
{
	unsigned i;

	memset(sky2->rx_le, 0, RX_LE_BYTES);
	for (i = 0; i < RX_PENDING; i++) {
		struct rx_ring_info *re = sky2->rx_ring + i;

		if (re->iob) {
			free_iob(re->iob);
			re->iob = NULL;
		}
	}
}

/*
 * Allocate an iob for receiving.
 */
static struct io_buffer *sky2_rx_alloc(struct sky2_port *sky2)
{
	struct io_buffer *iob;

	iob = alloc_iob(sky2->rx_data_size + ETH_DATA_ALIGN);
	if (!iob)
		return NULL;

	/*
	 * Cards with a RAM buffer hang in the rx FIFO if the
	 * receive buffer isn't aligned to (Linux module comments say
	 * 64 bytes, Linux module code says 8 bytes). Since io_buffers
	 * are always 2kb-aligned under iPXE, just leave it be
	 * without ETH_DATA_ALIGN in those cases.
	 *
	 * XXX This causes unaligned access to the IP header,
	 * which is undesirable, but it's less undesirable than the
	 * card hanging.
	 */
	if (!(sky2->hw->flags & SKY2_HW_RAM_BUFFER)) {
		iob_reserve(iob, ETH_DATA_ALIGN);
	}

	return iob;
}

static inline void sky2_rx_update(struct sky2_port *sky2, unsigned rxq)
{
	sky2_put_idx(sky2->hw, rxq, sky2->rx_put);
}

/*
 * Allocate and setup receiver buffer pool.
 * Normal case this ends up creating one list element for skb
 * in the receive ring. One element is used for checksum
 * enable/disable, and one extra to avoid wrap.
 */
static int sky2_rx_start(struct sky2_port *sky2)
{
	struct sky2_hw *hw = sky2->hw;
	struct rx_ring_info *re;
	unsigned rxq = rxqaddr[sky2->port];
	unsigned i, size, thresh;

	sky2->rx_put = sky2->rx_next = 0;
	sky2_qset(hw, rxq);

	/* On PCI express lowering the watermark gives better performance */
	if (pci_find_capability(hw->pdev, PCI_CAP_ID_EXP))
		sky2_write32(hw, Q_ADDR(rxq, Q_WM), BMU_WM_PEX);

	/* These chips have no ram buffer?
	 * MAC Rx RAM Read is controlled by hardware */
	if (hw->chip_id == CHIP_ID_YUKON_EC_U &&
	    (hw->chip_rev == CHIP_REV_YU_EC_U_A1
	     || hw->chip_rev == CHIP_REV_YU_EC_U_B0))
		sky2_write32(hw, Q_ADDR(rxq, Q_TEST), F_M_RX_RAM_DIS);

	sky2_prefetch_init(hw, rxq, sky2->rx_le_map, RX_LE_SIZE - 1);

	if (!(hw->flags & SKY2_HW_NEW_LE))
		rx_set_checksum(sky2);

	/* Space needed for frame data + headers rounded up */
	size = (ETH_FRAME_LEN + 8) & ~7;

	/* Stopping point for hardware truncation */
	thresh = (size - 8) / sizeof(u32);

	sky2->rx_data_size = size;

	/* Fill Rx ring */
	for (i = 0; i < RX_PENDING; i++) {
		re = sky2->rx_ring + i;

		re->iob = sky2_rx_alloc(sky2);
		if (!re->iob)
			goto nomem;

		sky2_rx_map_iob(hw->pdev, re, sky2->rx_data_size);
		sky2_rx_submit(sky2, re);
	}

	/*
	 * The receiver hangs if it receives frames larger than the
	 * packet buffer. As a workaround, truncate oversize frames, but
	 * the register is limited to 9 bits, so if you do frames > 2052
	 * you better get the MTU right!
	 */
	if (thresh > 0x1ff)
		sky2_write32(hw, SK_REG(sky2->port, RX_GMF_CTRL_T), RX_TRUNC_OFF);
	else {
		sky2_write16(hw, SK_REG(sky2->port, RX_GMF_TR_THR), thresh);
		sky2_write32(hw, SK_REG(sky2->port, RX_GMF_CTRL_T), RX_TRUNC_ON);
	}

	/* Tell chip about available buffers */
	sky2_rx_update(sky2, rxq);
	return 0;
nomem:
	sky2_rx_clean(sky2);
	return -ENOMEM;
}

/* Free the le and ring buffers */
static void sky2_free_rings(struct sky2_port *sky2)
{
	free_dma(sky2->rx_le, RX_LE_BYTES);
	free(sky2->rx_ring);

	free_dma(sky2->tx_le, TX_RING_SIZE * sizeof(struct sky2_tx_le));
	free(sky2->tx_ring);

	sky2->tx_le = NULL;
	sky2->rx_le = NULL;

	sky2->rx_ring = NULL;
	sky2->tx_ring = NULL;
}

/* Bring up network interface. */
static int sky2_up(struct net_device *dev)
{
	struct sky2_port *sky2 = netdev_priv(dev);
	struct sky2_hw *hw = sky2->hw;
	unsigned port = sky2->port;
	u32 imask, ramsize;
	int err = -ENOMEM;

	netdev_link_down(dev);

	/* must be power of 2 */
	sky2->tx_le = malloc_dma(TX_RING_SIZE * sizeof(struct sky2_tx_le), TX_RING_ALIGN);
	sky2->tx_le_map = virt_to_bus(sky2->tx_le);
	if (!sky2->tx_le)
		goto err_out;
	memset(sky2->tx_le, 0, TX_RING_SIZE * sizeof(struct sky2_tx_le));

	sky2->tx_ring = zalloc(TX_RING_SIZE * sizeof(struct tx_ring_info));
	if (!sky2->tx_ring)
		goto err_out;

	tx_init(sky2);

	sky2->rx_le = malloc_dma(RX_LE_BYTES, RX_RING_ALIGN);
	sky2->rx_le_map = virt_to_bus(sky2->rx_le);
	if (!sky2->rx_le)
		goto err_out;
	memset(sky2->rx_le, 0, RX_LE_BYTES);

	sky2->rx_ring = zalloc(RX_PENDING * sizeof(struct rx_ring_info));
	if (!sky2->rx_ring)
		goto err_out;

	sky2_mac_init(hw, port);

	/* Register is number of 4K blocks on internal RAM buffer. */
	ramsize = sky2_read8(hw, B2_E_0) * 4;
	if (ramsize > 0) {
		u32 rxspace;

		hw->flags |= SKY2_HW_RAM_BUFFER;
		DBG2(PFX "%s: ram buffer %dK\n", dev->name, ramsize);
		if (ramsize < 16)
			rxspace = ramsize / 2;
		else
			rxspace = 8 + (2*(ramsize - 16))/3;

		sky2_ramset(hw, rxqaddr[port], 0, rxspace);
		sky2_ramset(hw, txqaddr[port], rxspace, ramsize - rxspace);

		/* Make sure SyncQ is disabled */
		sky2_write8(hw, RB_ADDR(port == 0 ? Q_XS1 : Q_XS2, RB_CTRL),
			    RB_RST_SET);
	}

	sky2_qset(hw, txqaddr[port]);

	/* This is copied from sk98lin 10.0.5.3; no one tells me about erratta's */
	if (hw->chip_id == CHIP_ID_YUKON_EX && hw->chip_rev == CHIP_REV_YU_EX_B0)
		sky2_write32(hw, Q_ADDR(txqaddr[port], Q_TEST), F_TX_CHK_AUTO_OFF);

	/* Set almost empty threshold */
	if (hw->chip_id == CHIP_ID_YUKON_EC_U
	    && hw->chip_rev == CHIP_REV_YU_EC_U_A0)
		sky2_write16(hw, Q_ADDR(txqaddr[port], Q_AL), ECU_TXFF_LEV);

	sky2_prefetch_init(hw, txqaddr[port], sky2->tx_le_map,
			   TX_RING_SIZE - 1);

	err = sky2_rx_start(sky2);
	if (err)
		goto err_out;

	/* Enable interrupts from phy/mac for port */
	imask = sky2_read32(hw, B0_IMSK);
	imask |= portirq_msk[port];
	sky2_write32(hw, B0_IMSK, imask);

	DBGIO(PFX "%s: le bases: st %p [%x], rx %p [%x], tx %p [%x]\n",
	      dev->name, hw->st_le, hw->st_dma, sky2->rx_le, sky2->rx_le_map,
	      sky2->tx_le, sky2->tx_le_map);

	sky2_set_multicast(dev);
	return 0;

err_out:
	sky2_free_rings(sky2);
	return err;
}

/* Modular subtraction in ring */
static inline int tx_dist(unsigned tail, unsigned head)
{
	return (head - tail) & (TX_RING_SIZE - 1);
}

/* Number of list elements available for next tx */
static inline int tx_avail(const struct sky2_port *sky2)
{
	return TX_PENDING - tx_dist(sky2->tx_cons, sky2->tx_prod);
}


/*
 * Put one packet in ring for transmit.
 * A single packet can generate multiple list elements, and
 * the number of ring elements will probably be less than the number
 * of list elements used.
 */
static int sky2_xmit_frame(struct net_device *dev, struct io_buffer *iob)
{
	struct sky2_port *sky2 = netdev_priv(dev);
	struct sky2_hw *hw = sky2->hw;
	struct sky2_tx_le *le = NULL;
	struct tx_ring_info *re;
	unsigned len;
	u32 mapping;
	u8 ctrl;

	if (tx_avail(sky2) < 1)
		return -EBUSY;

	len = iob_len(iob);
	mapping = virt_to_bus(iob->data);

	DBGIO(PFX "%s: tx queued, slot %d, len %d\n", dev->name,
	      sky2->tx_prod, len);

	ctrl = 0;

	le = get_tx_le(sky2);
	le->addr = cpu_to_le32((u32) mapping);
	le->length = cpu_to_le16(len);
	le->ctrl = ctrl;
	le->opcode = (OP_PACKET | HW_OWNER);

	re = tx_le_re(sky2, le);
	re->iob = iob;

	le->ctrl |= EOP;

	sky2_put_idx(hw, txqaddr[sky2->port], sky2->tx_prod);

	return 0;
}

/*
 * Free ring elements from starting at tx_cons until "done"
 *
 * NB: the hardware will tell us about partial completion of multi-part
 *     buffers so make sure not to free iob too early.
 */
static void sky2_tx_complete(struct sky2_port *sky2, u16 done)
{
	struct net_device *dev = sky2->netdev;
	unsigned idx;

	assert(done < TX_RING_SIZE);

	for (idx = sky2->tx_cons; idx != done;
	     idx = RING_NEXT(idx, TX_RING_SIZE)) {
		struct sky2_tx_le *le = sky2->tx_le + idx;
		struct tx_ring_info *re = sky2->tx_ring + idx;

		if (le->ctrl & EOP) {
			DBGIO(PFX "%s: tx done %d\n", dev->name, idx);
			netdev_tx_complete(dev, re->iob);
		}
	}

	sky2->tx_cons = idx;
	mb();
}

/* Cleanup all untransmitted buffers, assume transmitter not running */
static void sky2_tx_clean(struct net_device *dev)
{
	struct sky2_port *sky2 = netdev_priv(dev);

	sky2_tx_complete(sky2, sky2->tx_prod);
}

/* Network shutdown */
static void sky2_down(struct net_device *dev)
{
	struct sky2_port *sky2 = netdev_priv(dev);
	struct sky2_hw *hw = sky2->hw;
	unsigned port = sky2->port;
	u16 ctrl;
	u32 imask;

	/* Never really got started! */
	if (!sky2->tx_le)
		return;

	DBG2(PFX "%s: disabling interface\n", dev->name);

	/* Disable port IRQ */
	imask = sky2_read32(hw, B0_IMSK);
	imask &= ~portirq_msk[port];
	sky2_write32(hw, B0_IMSK, imask);

	sky2_gmac_reset(hw, port);

	/* Stop transmitter */
	sky2_write32(hw, Q_ADDR(txqaddr[port], Q_CSR), BMU_STOP);
	sky2_read32(hw, Q_ADDR(txqaddr[port], Q_CSR));

	sky2_write32(hw, RB_ADDR(txqaddr[port], RB_CTRL),
		     RB_RST_SET | RB_DIS_OP_MD);

	ctrl = gma_read16(hw, port, GM_GP_CTRL);
	ctrl &= ~(GM_GPCR_TX_ENA | GM_GPCR_RX_ENA);
	gma_write16(hw, port, GM_GP_CTRL, ctrl);

	sky2_write8(hw, SK_REG(port, GPHY_CTRL), GPC_RST_SET);

	/* Workaround shared GMAC reset */
	if (!(hw->chip_id == CHIP_ID_YUKON_XL && hw->chip_rev == 0
	      && port == 0 && hw->dev[1]))
		sky2_write8(hw, SK_REG(port, GMAC_CTRL), GMC_RST_SET);

	/* Disable Force Sync bit and Enable Alloc bit */
	sky2_write8(hw, SK_REG(port, TXA_CTRL),
		    TXA_DIS_FSYNC | TXA_DIS_ALLOC | TXA_STOP_RC);

	/* Stop Interval Timer and Limit Counter of Tx Arbiter */
	sky2_write32(hw, SK_REG(port, TXA_ITI_INI), 0L);
	sky2_write32(hw, SK_REG(port, TXA_LIM_INI), 0L);

	/* Reset the PCI FIFO of the async Tx queue */
	sky2_write32(hw, Q_ADDR(txqaddr[port], Q_CSR),
		     BMU_RST_SET | BMU_FIFO_RST);

	/* Reset the Tx prefetch units */
	sky2_write32(hw, Y2_QADDR(txqaddr[port], PREF_UNIT_CTRL),
		     PREF_UNIT_RST_SET);

	sky2_write32(hw, RB_ADDR(txqaddr[port], RB_CTRL), RB_RST_SET);

	sky2_rx_stop(sky2);

	sky2_write8(hw, SK_REG(port, RX_GMF_CTRL_T), GMF_RST_SET);
	sky2_write8(hw, SK_REG(port, TX_GMF_CTRL_T), GMF_RST_SET);

	sky2_phy_power_down(hw, port);

	/* turn off LED's */
	sky2_write16(hw, B0_Y2LED, LED_STAT_OFF);

	sky2_tx_clean(dev);
	sky2_rx_clean(sky2);

	sky2_free_rings(sky2);

	return;
}

static u16 sky2_phy_speed(const struct sky2_hw *hw, u16 aux)
{
	if (hw->flags & SKY2_HW_FIBRE_PHY)
		return SPEED_1000;

	if (!(hw->flags & SKY2_HW_GIGABIT)) {
		if (aux & PHY_M_PS_SPEED_100)
			return SPEED_100;
		else
			return SPEED_10;
	}

	switch (aux & PHY_M_PS_SPEED_MSK) {
	case PHY_M_PS_SPEED_1000:
		return SPEED_1000;
	case PHY_M_PS_SPEED_100:
		return SPEED_100;
	default:
		return SPEED_10;
	}
}

static void sky2_link_up(struct sky2_port *sky2)
{
	struct sky2_hw *hw = sky2->hw;
	unsigned port = sky2->port;
	u16 reg;
	static const char *fc_name[] = {
		[FC_NONE]	= "none",
		[FC_TX]		= "tx",
		[FC_RX]		= "rx",
		[FC_BOTH]	= "both",
	};

	/* enable Rx/Tx */
	reg = gma_read16(hw, port, GM_GP_CTRL);
	reg |= GM_GPCR_RX_ENA | GM_GPCR_TX_ENA;
	gma_write16(hw, port, GM_GP_CTRL, reg);

	gm_phy_write(hw, port, PHY_MARV_INT_MASK, PHY_M_DEF_MSK);

	netdev_link_up(sky2->netdev);

	/* Turn on link LED */
	sky2_write8(hw, SK_REG(port, LNK_LED_REG),
		    LINKLED_ON | LINKLED_BLINK_OFF | LINKLED_LINKSYNC_OFF);

	DBG(PFX "%s: Link is up at %d Mbps, %s duplex, flow control %s\n",
	    sky2->netdev->name, sky2->speed,
	    sky2->duplex == DUPLEX_FULL ? "full" : "half",
	    fc_name[sky2->flow_status]);
}

static void sky2_link_down(struct sky2_port *sky2)
{
	struct sky2_hw *hw = sky2->hw;
	unsigned port = sky2->port;
	u16 reg;

	gm_phy_write(hw, port, PHY_MARV_INT_MASK, 0);

	reg = gma_read16(hw, port, GM_GP_CTRL);
	reg &= ~(GM_GPCR_RX_ENA | GM_GPCR_TX_ENA);
	gma_write16(hw, port, GM_GP_CTRL, reg);

	netdev_link_down(sky2->netdev);

	/* Turn on link LED */
	sky2_write8(hw, SK_REG(port, LNK_LED_REG), LINKLED_OFF);

	DBG(PFX "%s: Link is down.\n", sky2->netdev->name);

	sky2_phy_init(hw, port);
}

static int sky2_autoneg_done(struct sky2_port *sky2, u16 aux)
{
	struct sky2_hw *hw = sky2->hw;
	unsigned port = sky2->port;
	u16 advert, lpa;

	advert = gm_phy_read(hw, port, PHY_MARV_AUNE_ADV);
	lpa = gm_phy_read(hw, port, PHY_MARV_AUNE_LP);
	if (lpa & PHY_M_AN_RF) {
		DBG(PFX "%s: remote fault\n", sky2->netdev->name);
		return -1;
	}

	if (!(aux & PHY_M_PS_SPDUP_RES)) {
		DBG(PFX "%s: speed/duplex mismatch\n", sky2->netdev->name);
		return -1;
	}

	sky2->speed = sky2_phy_speed(hw, aux);
	sky2->duplex = (aux & PHY_M_PS_FULL_DUP) ? DUPLEX_FULL : DUPLEX_HALF;

	/* Since the pause result bits seem to in different positions on
	 * different chips. look at registers.
	 */

	sky2->flow_status = FC_NONE;
	if (advert & ADVERTISE_PAUSE_CAP) {
		if (lpa & LPA_PAUSE_CAP)
			sky2->flow_status = FC_BOTH;
		else if (advert & ADVERTISE_PAUSE_ASYM)
			sky2->flow_status = FC_RX;
	} else if (advert & ADVERTISE_PAUSE_ASYM) {
		if ((lpa & LPA_PAUSE_CAP) && (lpa & LPA_PAUSE_ASYM))
			sky2->flow_status = FC_TX;
	}

	if (sky2->duplex == DUPLEX_HALF && sky2->speed < SPEED_1000
	    && !(hw->chip_id == CHIP_ID_YUKON_EC_U || hw->chip_id == CHIP_ID_YUKON_EX))
		sky2->flow_status = FC_NONE;

	if (sky2->flow_status & FC_TX)
		sky2_write8(hw, SK_REG(port, GMAC_CTRL), GMC_PAUSE_ON);
	else
		sky2_write8(hw, SK_REG(port, GMAC_CTRL), GMC_PAUSE_OFF);

	return 0;
}

/* Interrupt from PHY */
static void sky2_phy_intr(struct sky2_hw *hw, unsigned port)
{
	struct net_device *dev = hw->dev[port];
	struct sky2_port *sky2 = netdev_priv(dev);
	u16 istatus, phystat;

	istatus = gm_phy_read(hw, port, PHY_MARV_INT_STAT);
	phystat = gm_phy_read(hw, port, PHY_MARV_PHY_STAT);

	DBGIO(PFX "%s: phy interrupt status 0x%x 0x%x\n",
	      sky2->netdev->name, istatus, phystat);

	if (sky2->autoneg == AUTONEG_ENABLE && (istatus & PHY_M_IS_AN_COMPL)) {
		if (sky2_autoneg_done(sky2, phystat) == 0)
			sky2_link_up(sky2);
		return;
	}

	if (istatus & PHY_M_IS_LSP_CHANGE)
		sky2->speed = sky2_phy_speed(hw, phystat);

	if (istatus & PHY_M_IS_DUP_CHANGE)
		sky2->duplex =
		    (phystat & PHY_M_PS_FULL_DUP) ? DUPLEX_FULL : DUPLEX_HALF;

	if (istatus & PHY_M_IS_LST_CHANGE) {
		if (phystat & PHY_M_PS_LINK_UP)
			sky2_link_up(sky2);
		else
			sky2_link_down(sky2);
	}
}

/* Normal packet - take iob from ring element and put in a new one  */
static struct io_buffer *receive_new(struct sky2_port *sky2,
				     struct rx_ring_info *re,
				     unsigned int length)
{
	struct io_buffer *iob, *niob;
	unsigned hdr_space = sky2->rx_data_size;

	/* Don't be tricky about reusing pages (yet) */
	niob = sky2_rx_alloc(sky2);
	if (!niob)
		return NULL;

	iob = re->iob;

	re->iob = niob;
	sky2_rx_map_iob(sky2->hw->pdev, re, hdr_space);

	iob_put(iob, length);
	return iob;
}

/*
 * Receive one packet.
 * For larger packets, get new buffer.
 */
static struct io_buffer *sky2_receive(struct net_device *dev,
				      u16 length, u32 status)
{
	struct sky2_port *sky2 = netdev_priv(dev);
	struct rx_ring_info *re = sky2->rx_ring + sky2->rx_next;
	struct io_buffer *iob = NULL;
	u16 count = (status & GMR_FS_LEN) >> 16;

	DBGIO(PFX "%s: rx slot %d status 0x%x len %d\n",
	      dev->name, sky2->rx_next, status, length);

	sky2->rx_next = (sky2->rx_next + 1) % RX_PENDING;

	/* This chip has hardware problems that generates bogus status.
	 * So do only marginal checking and expect higher level protocols
	 * to handle crap frames.
	 */
	if (sky2->hw->chip_id == CHIP_ID_YUKON_FE_P &&
	    sky2->hw->chip_rev == CHIP_REV_YU_FE2_A0 &&
	    length == count)
		goto okay;

	if (status & GMR_FS_ANY_ERR)
		goto error;

	if (!(status & GMR_FS_RX_OK))
		goto resubmit;

	/* if length reported by DMA does not match PHY, packet was truncated */
	if (length != count)
		goto len_error;

okay:
	iob = receive_new(sky2, re, length);
resubmit:
	sky2_rx_submit(sky2, re);

	return iob;

len_error:
	/* Truncation of overlength packets
	   causes PHY length to not match MAC length */
	DBG2(PFX "%s: rx length error: status %#x length %d\n",
	     dev->name, status, length);

	/* Pass NULL as iob because we want to keep our iob in the
	   ring for the next packet. */
	netdev_rx_err(dev, NULL, -EINVAL);
	goto resubmit;

error:
	if (status & GMR_FS_RX_FF_OV) {
		DBG2(PFX "%s: FIFO overflow error\n", dev->name);
		netdev_rx_err(dev, NULL, -EBUSY);
		goto resubmit;
	}

	DBG2(PFX "%s: rx error, status 0x%x length %d\n",
	     dev->name, status, length);
	netdev_rx_err(dev, NULL, -EIO);

	goto resubmit;
}

/* Transmit complete */
static inline void sky2_tx_done(struct net_device *dev, u16 last)
{
	struct sky2_port *sky2 = netdev_priv(dev);

	sky2_tx_complete(sky2, last);
}

/* Process status response ring */
static void sky2_status_intr(struct sky2_hw *hw, u16 idx)
{
	unsigned rx[2] = { 0, 0 };

	rmb();
	do {
		struct sky2_status_le *le  = hw->st_le + hw->st_idx;
		unsigned port;
		struct net_device *dev;
		struct io_buffer *iob;
		u32 status;
		u16 length;
		u8 opcode = le->opcode;

		if (!(opcode & HW_OWNER))
			break;

		port = le->css & CSS_LINK_BIT;
		dev = hw->dev[port];
		length = le16_to_cpu(le->length);
		status = le32_to_cpu(le->status);

		hw->st_idx = RING_NEXT(hw->st_idx, STATUS_RING_SIZE);

		le->opcode = 0;
		switch (opcode & ~HW_OWNER) {
		case OP_RXSTAT:
			++rx[port];
			iob = sky2_receive(dev, length, status);
			if (!iob) {
				netdev_rx_err(dev, NULL, -ENOMEM);
				break;
			}

			netdev_rx(dev, iob);
			break;

		case OP_RXCHKS:
			DBG2(PFX "status OP_RXCHKS but checksum offloading disabled\n");
			break;

		case OP_TXINDEXLE:
			/* TX index reports status for both ports */
			assert(TX_RING_SIZE <= 0x1000);
			sky2_tx_done(hw->dev[0], status & 0xfff);
			if (hw->dev[1])
				sky2_tx_done(hw->dev[1],
				     ((status >> 24) & 0xff)
					     | (u16)(length & 0xf) << 8);
			break;

		default:
			DBG(PFX "unknown status opcode 0x%x\n", opcode);
		}
	} while (hw->st_idx != idx);

	/* Fully processed status ring so clear irq */
	sky2_write32(hw, STAT_CTRL, SC_STAT_CLR_IRQ);

	if (rx[0])
		sky2_rx_update(netdev_priv(hw->dev[0]), Q_R1);

	if (rx[1])
		sky2_rx_update(netdev_priv(hw->dev[1]), Q_R2);
}

static void sky2_hw_error(struct sky2_hw *hw, unsigned port, u32 status)
{
	struct net_device *dev = hw->dev[port];

	DBGIO(PFX "%s: hw error interrupt status 0x%x\n", dev->name, status);

	if (status & Y2_IS_PAR_RD1) {
		DBG(PFX "%s: ram data read parity error\n", dev->name);
		/* Clear IRQ */
		sky2_write16(hw, RAM_BUFFER(port, B3_RI_CTRL), RI_CLR_RD_PERR);
	}

	if (status & Y2_IS_PAR_WR1) {
		DBG(PFX "%s: ram data write parity error\n", dev->name);
		sky2_write16(hw, RAM_BUFFER(port, B3_RI_CTRL), RI_CLR_WR_PERR);
	}

	if (status & Y2_IS_PAR_MAC1) {
		DBG(PFX "%s: MAC parity error\n", dev->name);
		sky2_write8(hw, SK_REG(port, TX_GMF_CTRL_T), GMF_CLI_TX_PE);
	}

	if (status & Y2_IS_PAR_RX1) {
		DBG(PFX "%s: RX parity error\n", dev->name);
		sky2_write32(hw, Q_ADDR(rxqaddr[port], Q_CSR), BMU_CLR_IRQ_PAR);
	}

	if (status & Y2_IS_TCP_TXA1) {
		DBG(PFX "%s: TCP segmentation error\n", dev->name);
		sky2_write32(hw, Q_ADDR(txqaddr[port], Q_CSR), BMU_CLR_IRQ_TCP);
	}
}

static void sky2_hw_intr(struct sky2_hw *hw)
{
	u32 status = sky2_read32(hw, B0_HWE_ISRC);
	u32 hwmsk = sky2_read32(hw, B0_HWE_IMSK);

	status &= hwmsk;

	if (status & Y2_IS_TIST_OV)
		sky2_write8(hw, GMAC_TI_ST_CTRL, GMT_ST_CLR_IRQ);

	if (status & (Y2_IS_MST_ERR | Y2_IS_IRQ_STAT)) {
		u16 pci_err;

		sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_ON);
		pci_err = sky2_pci_read16(hw, PCI_STATUS);
		DBG(PFX "PCI hardware error (0x%x)\n", pci_err);

		sky2_pci_write16(hw, PCI_STATUS,
				 pci_err | PCI_STATUS_ERROR_BITS);
		sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
	}

	if (status & Y2_IS_PCI_EXP) {
		/* PCI-Express uncorrectable Error occurred */
		u32 err;

		sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_ON);
		err = sky2_read32(hw, Y2_CFG_AER + PCI_ERR_UNCOR_STATUS);
		sky2_write32(hw, Y2_CFG_AER + PCI_ERR_UNCOR_STATUS,
			     0xfffffffful);
		DBG(PFX "PCI-Express error (0x%x)\n", err);

		sky2_read32(hw, Y2_CFG_AER + PCI_ERR_UNCOR_STATUS);
		sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
	}

	if (status & Y2_HWE_L1_MASK)
		sky2_hw_error(hw, 0, status);
	status >>= 8;
	if (status & Y2_HWE_L1_MASK)
		sky2_hw_error(hw, 1, status);
}

static void sky2_mac_intr(struct sky2_hw *hw, unsigned port)
{
	struct net_device *dev = hw->dev[port];
	u8 status = sky2_read8(hw, SK_REG(port, GMAC_IRQ_SRC));

	DBGIO(PFX "%s: mac interrupt status 0x%x\n", dev->name, status);

	if (status & GM_IS_RX_CO_OV)
		gma_read16(hw, port, GM_RX_IRQ_SRC);

	if (status & GM_IS_TX_CO_OV)
		gma_read16(hw, port, GM_TX_IRQ_SRC);

	if (status & GM_IS_RX_FF_OR) {
		sky2_write8(hw, SK_REG(port, RX_GMF_CTRL_T), GMF_CLI_RX_FO);
	}

	if (status & GM_IS_TX_FF_UR) {
		sky2_write8(hw, SK_REG(port, TX_GMF_CTRL_T), GMF_CLI_TX_FU);
	}
}

/* This should never happen it is a bug. */
static void sky2_le_error(struct sky2_hw *hw, unsigned port,
			  u16 q, unsigned ring_size __unused)
{
	struct net_device *dev = hw->dev[port];
	struct sky2_port *sky2 = netdev_priv(dev);
	int idx;
	const u64 *le = (q == Q_R1 || q == Q_R2)
		? (u64 *) sky2->rx_le : (u64 *) sky2->tx_le;

	idx = sky2_read16(hw, Y2_QADDR(q, PREF_UNIT_GET_IDX));
	DBG(PFX "%s: descriptor error q=%#x get=%d [%llx] last=%d put=%d should be %d\n",
	    dev->name, (unsigned) q, idx, (unsigned long long) le[idx],
	    (int) sky2_read16(hw, Y2_QADDR(q, PREF_UNIT_LAST_IDX)),
	    (int) sky2_read16(hw, Y2_QADDR(q, PREF_UNIT_PUT_IDX)),
	    le == (u64 *)sky2->rx_le? sky2->rx_put : sky2->tx_prod);

	sky2_write32(hw, Q_ADDR(q, Q_CSR), BMU_CLR_IRQ_CHK);
}

/* Hardware/software error handling */
static void sky2_err_intr(struct sky2_hw *hw, u32 status)
{
	DBG(PFX "error interrupt status=%#x\n", status);

	if (status & Y2_IS_HW_ERR)
		sky2_hw_intr(hw);

	if (status & Y2_IS_IRQ_MAC1)
		sky2_mac_intr(hw, 0);

	if (status & Y2_IS_IRQ_MAC2)
		sky2_mac_intr(hw, 1);

	if (status & Y2_IS_CHK_RX1)
		sky2_le_error(hw, 0, Q_R1, RX_LE_SIZE);

	if (status & Y2_IS_CHK_RX2)
		sky2_le_error(hw, 1, Q_R2, RX_LE_SIZE);

	if (status & Y2_IS_CHK_TXA1)
		sky2_le_error(hw, 0, Q_XA1, TX_RING_SIZE);

	if (status & Y2_IS_CHK_TXA2)
		sky2_le_error(hw, 1, Q_XA2, TX_RING_SIZE);
}

static void sky2_poll(struct net_device *dev)
{
	struct sky2_port *sky2 = netdev_priv(dev);
	struct sky2_hw *hw = sky2->hw;
	u32 status = sky2_read32(hw, B0_Y2_SP_EISR);
	u16 idx;

	if (status & Y2_IS_ERROR)
		sky2_err_intr(hw, status);

	if (status & Y2_IS_IRQ_PHY1)
		sky2_phy_intr(hw, 0);

	if (status & Y2_IS_IRQ_PHY2)
		sky2_phy_intr(hw, 1);

	while ((idx = sky2_read16(hw, STAT_PUT_IDX)) != hw->st_idx) {
		sky2_status_intr(hw, idx);
	}

	/* Bug/Errata workaround?
	 * Need to kick the TX irq moderation timer.
	 */
	if (sky2_read8(hw, STAT_TX_TIMER_CTRL) == TIM_START) {
		sky2_write8(hw, STAT_TX_TIMER_CTRL, TIM_STOP);
		sky2_write8(hw, STAT_TX_TIMER_CTRL, TIM_START);
	}
	sky2_read32(hw, B0_Y2_SP_LISR);
}

/* Chip internal frequency for clock calculations */
static u32 sky2_mhz(const struct sky2_hw *hw)
{
	switch (hw->chip_id) {
	case CHIP_ID_YUKON_EC:
	case CHIP_ID_YUKON_EC_U:
	case CHIP_ID_YUKON_EX:
	case CHIP_ID_YUKON_SUPR:
	case CHIP_ID_YUKON_UL_2:
		return 125;

	case CHIP_ID_YUKON_FE:
		return 100;

	case CHIP_ID_YUKON_FE_P:
		return 50;

	case CHIP_ID_YUKON_XL:
		return 156;

	default:
		DBG(PFX "unknown chip ID!\n");
		return 100;	/* bogus */
	}
}

static inline u32 sky2_us2clk(const struct sky2_hw *hw, u32 us)
{
	return sky2_mhz(hw) * us;
}

static inline u32 sky2_clk2us(const struct sky2_hw *hw, u32 clk)
{
	return clk / sky2_mhz(hw);
}

static int sky2_init(struct sky2_hw *hw)
{
	u8 t8;

	/* Enable all clocks and check for bad PCI access */
	sky2_pci_write32(hw, PCI_DEV_REG3, 0);

	sky2_write8(hw, B0_CTST, CS_RST_CLR);

	hw->chip_id = sky2_read8(hw, B2_CHIP_ID);
	hw->chip_rev = (sky2_read8(hw, B2_MAC_CFG) & CFG_CHIP_R_MSK) >> 4;

	switch(hw->chip_id) {
	case CHIP_ID_YUKON_XL:
		hw->flags = SKY2_HW_GIGABIT | SKY2_HW_NEWER_PHY;
		break;

	case CHIP_ID_YUKON_EC_U:
		hw->flags = SKY2_HW_GIGABIT
			| SKY2_HW_NEWER_PHY
			| SKY2_HW_ADV_POWER_CTL;
		break;

	case CHIP_ID_YUKON_EX:
		hw->flags = SKY2_HW_GIGABIT
			| SKY2_HW_NEWER_PHY
			| SKY2_HW_NEW_LE
			| SKY2_HW_ADV_POWER_CTL;
		break;

	case CHIP_ID_YUKON_EC:
		/* This rev is really old, and requires untested workarounds */
		if (hw->chip_rev == CHIP_REV_YU_EC_A1) {
			DBG(PFX "unsupported revision Yukon-EC rev A1\n");
			return -EOPNOTSUPP;
		}
		hw->flags = SKY2_HW_GIGABIT;
		break;

	case CHIP_ID_YUKON_FE:
		break;

	case CHIP_ID_YUKON_FE_P:
		hw->flags = SKY2_HW_NEWER_PHY
			| SKY2_HW_NEW_LE
			| SKY2_HW_AUTO_TX_SUM
			| SKY2_HW_ADV_POWER_CTL;
		break;

	case CHIP_ID_YUKON_SUPR:
		hw->flags = SKY2_HW_GIGABIT
			| SKY2_HW_NEWER_PHY
			| SKY2_HW_NEW_LE
			| SKY2_HW_AUTO_TX_SUM
			| SKY2_HW_ADV_POWER_CTL;
		break;

	case CHIP_ID_YUKON_UL_2:
		hw->flags = SKY2_HW_GIGABIT
			| SKY2_HW_ADV_POWER_CTL;
		break;

	default:
		DBG(PFX "unsupported chip type 0x%x\n", hw->chip_id);
		return -EOPNOTSUPP;
	}

	hw->pmd_type = sky2_read8(hw, B2_PMD_TYP);
	if (hw->pmd_type == 'L' || hw->pmd_type == 'S' || hw->pmd_type == 'P')
		hw->flags |= SKY2_HW_FIBRE_PHY;

	hw->ports = 1;
	t8 = sky2_read8(hw, B2_Y2_HW_RES);
	if ((t8 & CFG_DUAL_MAC_MSK) == CFG_DUAL_MAC_MSK) {
		if (!(sky2_read8(hw, B2_Y2_CLK_GATE) & Y2_STATUS_LNK2_INAC))
			++hw->ports;
	}

	return 0;
}

static void sky2_reset(struct sky2_hw *hw)
{
	u16 status;
	int i, cap;
	u32 hwe_mask = Y2_HWE_ALL_MASK;

	/* disable ASF */
	if (hw->chip_id == CHIP_ID_YUKON_EX) {
		status = sky2_read16(hw, HCU_CCSR);
		status &= ~(HCU_CCSR_AHB_RST | HCU_CCSR_CPU_RST_MODE |
			    HCU_CCSR_UC_STATE_MSK);
		sky2_write16(hw, HCU_CCSR, status);
	} else
		sky2_write8(hw, B28_Y2_ASF_STAT_CMD, Y2_ASF_RESET);
	sky2_write16(hw, B0_CTST, Y2_ASF_DISABLE);

	/* do a SW reset */
	sky2_write8(hw, B0_CTST, CS_RST_SET);
	sky2_write8(hw, B0_CTST, CS_RST_CLR);

	/* allow writes to PCI config */
	sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_ON);

	/* clear PCI errors, if any */
	status = sky2_pci_read16(hw, PCI_STATUS);
	status |= PCI_STATUS_ERROR_BITS;
	sky2_pci_write16(hw, PCI_STATUS, status);

	sky2_write8(hw, B0_CTST, CS_MRST_CLR);

	cap = pci_find_capability(hw->pdev, PCI_CAP_ID_EXP);
	if (cap) {
		sky2_write32(hw, Y2_CFG_AER + PCI_ERR_UNCOR_STATUS,
			     0xfffffffful);

		/* If an error bit is stuck on ignore it */
		if (sky2_read32(hw, B0_HWE_ISRC) & Y2_IS_PCI_EXP)
			DBG(PFX "ignoring stuck error report bit\n");
		else
			hwe_mask |= Y2_IS_PCI_EXP;
	}

	sky2_power_on(hw);
	sky2_write8(hw, B2_TST_CTRL1, TST_CFG_WRITE_OFF);

	for (i = 0; i < hw->ports; i++) {
		sky2_write8(hw, SK_REG(i, GMAC_LINK_CTRL), GMLC_RST_SET);
		sky2_write8(hw, SK_REG(i, GMAC_LINK_CTRL), GMLC_RST_CLR);

		if (hw->chip_id == CHIP_ID_YUKON_EX ||
		    hw->chip_id == CHIP_ID_YUKON_SUPR)
			sky2_write16(hw, SK_REG(i, GMAC_CTRL),
				     GMC_BYP_MACSECRX_ON | GMC_BYP_MACSECTX_ON
				     | GMC_BYP_RETR_ON);
	}

	/* Clear I2C IRQ noise */
	sky2_write32(hw, B2_I2C_IRQ, 1);

	/* turn off hardware timer (unused) */
	sky2_write8(hw, B2_TI_CTRL, TIM_STOP);
	sky2_write8(hw, B2_TI_CTRL, TIM_CLR_IRQ);

	sky2_write8(hw, B0_Y2LED, LED_STAT_ON);

	/* Turn off descriptor polling */
	sky2_write32(hw, B28_DPT_CTRL, DPT_STOP);

	/* Turn off receive timestamp */
	sky2_write8(hw, GMAC_TI_ST_CTRL, GMT_ST_STOP);
	sky2_write8(hw, GMAC_TI_ST_CTRL, GMT_ST_CLR_IRQ);

	/* enable the Tx Arbiters */
	for (i = 0; i < hw->ports; i++)
		sky2_write8(hw, SK_REG(i, TXA_CTRL), TXA_ENA_ARB);

	/* Initialize ram interface */
	for (i = 0; i < hw->ports; i++) {
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_CTRL), RI_RST_CLR);

		sky2_write8(hw, RAM_BUFFER(i, B3_RI_WTO_R1), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_WTO_XA1), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_WTO_XS1), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_RTO_R1), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_RTO_XA1), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_RTO_XS1), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_WTO_R2), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_WTO_XA2), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_WTO_XS2), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_RTO_R2), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_RTO_XA2), SK_RI_TO_53);
		sky2_write8(hw, RAM_BUFFER(i, B3_RI_RTO_XS2), SK_RI_TO_53);
	}

	sky2_write32(hw, B0_HWE_IMSK, hwe_mask);

	for (i = 0; i < hw->ports; i++)
		sky2_gmac_reset(hw, i);

	memset(hw->st_le, 0, STATUS_LE_BYTES);
	hw->st_idx = 0;

	sky2_write32(hw, STAT_CTRL, SC_STAT_RST_SET);
	sky2_write32(hw, STAT_CTRL, SC_STAT_RST_CLR);

	sky2_write32(hw, STAT_LIST_ADDR_LO, hw->st_dma);
	sky2_write32(hw, STAT_LIST_ADDR_HI, (u64) hw->st_dma >> 32);

	/* Set the list last index */
	sky2_write16(hw, STAT_LAST_IDX, STATUS_RING_SIZE - 1);

	sky2_write16(hw, STAT_TX_IDX_TH, 10);
	sky2_write8(hw, STAT_FIFO_WM, 16);

	/* set Status-FIFO ISR watermark */
	if (hw->chip_id == CHIP_ID_YUKON_XL && hw->chip_rev == 0)
		sky2_write8(hw, STAT_FIFO_ISR_WM, 4);
	else
		sky2_write8(hw, STAT_FIFO_ISR_WM, 16);

	sky2_write32(hw, STAT_TX_TIMER_INI, sky2_us2clk(hw, 1000));
	sky2_write32(hw, STAT_ISR_TIMER_INI, sky2_us2clk(hw, 20));
	sky2_write32(hw, STAT_LEV_TIMER_INI, sky2_us2clk(hw, 100));

	/* enable status unit */
	sky2_write32(hw, STAT_CTRL, SC_STAT_OP_ON);

	sky2_write8(hw, STAT_TX_TIMER_CTRL, TIM_START);
	sky2_write8(hw, STAT_LEV_TIMER_CTRL, TIM_START);
	sky2_write8(hw, STAT_ISR_TIMER_CTRL, TIM_START);
}

static u32 sky2_supported_modes(const struct sky2_hw *hw)
{
	if (sky2_is_copper(hw)) {
		u32 modes = SUPPORTED_10baseT_Half
			| SUPPORTED_10baseT_Full
			| SUPPORTED_100baseT_Half
			| SUPPORTED_100baseT_Full
			| SUPPORTED_Autoneg | SUPPORTED_TP;

		if (hw->flags & SKY2_HW_GIGABIT)
			modes |= SUPPORTED_1000baseT_Half
				| SUPPORTED_1000baseT_Full;
		return modes;
	} else
		return  SUPPORTED_1000baseT_Half
			| SUPPORTED_1000baseT_Full
			| SUPPORTED_Autoneg
			| SUPPORTED_FIBRE;
}

static void sky2_set_multicast(struct net_device *dev)
{
	struct sky2_port *sky2 = netdev_priv(dev);
	struct sky2_hw *hw = sky2->hw;
	unsigned port = sky2->port;
	u16 reg;
	u8 filter[8];

	reg = gma_read16(hw, port, GM_RX_CTRL);
	reg |= GM_RXCR_UCF_ENA;

	memset(filter, 0xff, sizeof(filter));

	gma_write16(hw, port, GM_MC_ADDR_H1,
		    (u16) filter[0] | ((u16) filter[1] << 8));
	gma_write16(hw, port, GM_MC_ADDR_H2,
		    (u16) filter[2] | ((u16) filter[3] << 8));
	gma_write16(hw, port, GM_MC_ADDR_H3,
		    (u16) filter[4] | ((u16) filter[5] << 8));
	gma_write16(hw, port, GM_MC_ADDR_H4,
		    (u16) filter[6] | ((u16) filter[7] << 8));

	gma_write16(hw, port, GM_RX_CTRL, reg);
}

/* Initialize network device */
static struct net_device *sky2_init_netdev(struct sky2_hw *hw,
						     unsigned port)
{
	struct sky2_port *sky2;
	struct net_device *dev = alloc_etherdev(sizeof(*sky2));

	if (!dev) {
		DBG(PFX "etherdev alloc failed\n");
		return NULL;
	}

	dev->dev = &hw->pdev->dev;

	sky2 = netdev_priv(dev);
	sky2->netdev = dev;
	sky2->hw = hw;

	/* Auto speed and flow control */
	sky2->autoneg = AUTONEG_ENABLE;
	sky2->flow_mode = FC_BOTH;

	sky2->duplex = -1;
	sky2->speed = -1;
	sky2->advertising = sky2_supported_modes(hw);

	hw->dev[port] = dev;

	sky2->port = port;

	/* read the mac address */
	memcpy(dev->hw_addr, (void *)(hw->regs + B2_MAC_1 + port * 8), ETH_ALEN);

	return dev;
}

static void sky2_show_addr(struct net_device *dev)
{
	DBG2(PFX "%s: addr %s\n", dev->name, netdev_addr(dev));
}

#if DBGLVL_MAX
/* This driver supports yukon2 chipset only */
static const char *sky2_name(u8 chipid, char *buf, int sz)
{
	const char *name[] = {
		"XL",		/* 0xb3 */
		"EC Ultra", 	/* 0xb4 */
		"Extreme",	/* 0xb5 */
		"EC",		/* 0xb6 */
		"FE",		/* 0xb7 */
		"FE+",		/* 0xb8 */
		"Supreme",	/* 0xb9 */
		"UL 2",		/* 0xba */
	};

	if (chipid >= CHIP_ID_YUKON_XL && chipid <= CHIP_ID_YUKON_UL_2)
		strncpy(buf, name[chipid - CHIP_ID_YUKON_XL], sz);
	else
		snprintf(buf, sz, "(chip %#x)", chipid);
	return buf;
}
#endif

static void sky2_net_irq(struct net_device *dev, int enable)
{
	struct sky2_port *sky2 = netdev_priv(dev);
	struct sky2_hw *hw = sky2->hw;

	u32 imask = sky2_read32(hw, B0_IMSK);
	if (enable)
		imask |= portirq_msk[sky2->port];
	else
		imask &= ~portirq_msk[sky2->port];
	sky2_write32(hw, B0_IMSK, imask);
}

static struct net_device_operations sky2_operations = {
	.open     = sky2_up,
	.close    = sky2_down,
	.transmit = sky2_xmit_frame,
	.poll     = sky2_poll,
	.irq      = sky2_net_irq
};

static int sky2_probe(struct pci_device *pdev)
{
	struct net_device *dev;
	struct sky2_hw *hw;
	int err;
	char buf1[16] __unused;	/* only for debugging */

	adjust_pci_device(pdev);

	err = -ENOMEM;
	hw = zalloc(sizeof(*hw));
	if (!hw) {
		DBG(PFX "cannot allocate hardware struct\n");
		goto err_out;
	}

	hw->pdev = pdev;

	hw->regs = (unsigned long)ioremap(pci_bar_start(pdev, PCI_BASE_ADDRESS_0), 0x4000);
	if (!hw->regs) {
		DBG(PFX "cannot map device registers\n");
		goto err_out_free_hw;
	}

	/* ring for status responses */
	hw->st_le = malloc_dma(STATUS_LE_BYTES, STATUS_RING_ALIGN);
	if (!hw->st_le)
		goto err_out_iounmap;
	hw->st_dma = virt_to_bus(hw->st_le);
	memset(hw->st_le, 0, STATUS_LE_BYTES);

	err = sky2_init(hw);
	if (err)
		goto err_out_iounmap;

#if DBGLVL_MAX
	DBG2(PFX "Yukon-2 %s chip revision %d\n",
	     sky2_name(hw->chip_id, buf1, sizeof(buf1)), hw->chip_rev);
#endif

	sky2_reset(hw);

	dev = sky2_init_netdev(hw, 0);
	if (!dev) {
		err = -ENOMEM;
		goto err_out_free_pci;
	}

	netdev_init(dev, &sky2_operations);

	err = register_netdev(dev);
	if (err) {
		DBG(PFX "cannot register net device\n");
		goto err_out_free_netdev;
	}

	sky2_write32(hw, B0_IMSK, Y2_IS_BASE);

	sky2_show_addr(dev);

	if (hw->ports > 1) {
		struct net_device *dev1;

		dev1 = sky2_init_netdev(hw, 1);
		if (!dev1)
			DBG(PFX "allocation for second device failed\n");
		else if ((err = register_netdev(dev1))) {
			DBG(PFX "register of second port failed (%d)\n", err);
			hw->dev[1] = NULL;
			netdev_nullify(dev1);
			netdev_put(dev1);
		} else
			sky2_show_addr(dev1);
	}

	pci_set_drvdata(pdev, hw);

	return 0;

err_out_free_netdev:
	netdev_nullify(dev);
	netdev_put(dev);
err_out_free_pci:
	sky2_write8(hw, B0_CTST, CS_RST_SET);
	free_dma(hw->st_le, STATUS_LE_BYTES);
err_out_iounmap:
	iounmap((void *)hw->regs);
err_out_free_hw:
	free(hw);
err_out:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void sky2_remove(struct pci_device *pdev)
{
	struct sky2_hw *hw = pci_get_drvdata(pdev);
	int i;

	if (!hw)
		return;

	for (i = hw->ports-1; i >= 0; --i)
		unregister_netdev(hw->dev[i]);

	sky2_write32(hw, B0_IMSK, 0);

	sky2_power_aux(hw);

	sky2_write16(hw, B0_Y2LED, LED_STAT_OFF);
	sky2_write8(hw, B0_CTST, CS_RST_SET);
	sky2_read8(hw, B0_CTST);

	free_dma(hw->st_le, STATUS_LE_BYTES);

	for (i = hw->ports-1; i >= 0; --i) {
		netdev_nullify(hw->dev[i]);
		netdev_put(hw->dev[i]);
	}

	iounmap((void *)hw->regs);
	free(hw);

	pci_set_drvdata(pdev, NULL);
}

struct pci_driver sky2_driver __pci_driver = {
	.ids      = sky2_id_table,
	.id_count = (sizeof (sky2_id_table) / sizeof (sky2_id_table[0])),
	.probe    = sky2_probe,
	.remove   = sky2_remove
};
