/*
 * tg3.c: Broadcom Tigon3 ethernet driver.
 *
 * Copyright (C) 2001, 2002, 2003, 2004 David S. Miller (davem@redhat.com)
 * Copyright (C) 2001, 2002, 2003 Jeff Garzik (jgarzik@pobox.com)
 * Copyright (C) 2004 Sun Microsystems Inc.
 * Copyright (C) 2005-2011 Broadcom Corporation.
 *
 * Firmware is:
 *	Derived from proprietary unpublished source code,
 *	Copyright (C) 2000-2003 Broadcom Corporation.
 *
 *	Permission is hereby granted for the distribution of this firmware
 *	data in hexadecimal or equivalent format, provided this copyright
 *	notice is accompanying it.
 */

FILE_LICENCE ( GPL2_ONLY );

#include <mii.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/iobuf.h>
#include <ipxe/timer.h>
#include <ipxe/malloc.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/netdevice.h>

#include "tg3.h"

#define RESET_KIND_SHUTDOWN	0
#define RESET_KIND_INIT		1
#define RESET_KIND_SUSPEND	2

#define TG3_DEF_MAC_MODE	0

void tg3_write_indirect_reg32(struct tg3 *tp, u32 off, u32 val)
{	DBGP("%s\n", __func__);

	pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off);
	pci_write_config_dword(tp->pdev, TG3PCI_REG_DATA, val);
}

u32 tg3_read_indirect_reg32(struct tg3 *tp, u32 off)
{	DBGP("%s\n", __func__);

	u32 val;

	pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off);
	pci_read_config_dword(tp->pdev, TG3PCI_REG_DATA, &val);
	return val;
}

static u32 tg3_read32_mbox_5906(struct tg3 *tp, u32 off)
{	DBGP("%s\n", __func__);

	return readl(tp->regs + off + GRCMBOX_BASE);
}

static void tg3_write32_mbox_5906(struct tg3 *tp, u32 off, u32 val)
{	DBGP("%s\n", __func__);

	writel(val, tp->regs + off + GRCMBOX_BASE);
}

void tg3_write_indirect_mbox(struct tg3 *tp, u32 off, u32 val)
{	DBGP("%s\n", __func__);

	if (off == (MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW)) {
		pci_write_config_dword(tp->pdev, TG3PCI_RCV_RET_RING_CON_IDX +
				       TG3_64BIT_REG_LOW, val);
		return;
	}
	if (off == TG3_RX_STD_PROD_IDX_REG) {
		pci_write_config_dword(tp->pdev, TG3PCI_STD_RING_PROD_IDX +
				       TG3_64BIT_REG_LOW, val);
		return;
	}

	pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off + 0x5600);
	pci_write_config_dword(tp->pdev, TG3PCI_REG_DATA, val);

	/* In indirect mode when disabling interrupts, we also need
	 * to clear the interrupt bit in the GRC local ctrl register.
	 */
	if ((off == (MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW)) &&
	    (val == 0x1)) {
		pci_write_config_dword(tp->pdev, TG3PCI_MISC_LOCAL_CTRL,
				       tp->grc_local_ctrl|GRC_LCLCTRL_CLEARINT);
	}
}

u32 tg3_read_indirect_mbox(struct tg3 *tp, u32 off)
{	DBGP("%s\n", __func__);

	u32 val;

	pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off + 0x5600);
	pci_read_config_dword(tp->pdev, TG3PCI_REG_DATA, &val);

	return val;
}

/* usec_wait specifies the wait time in usec when writing to certain registers
 * where it is unsafe to read back the register without some delay.
 * GRC_LOCAL_CTRL is one example if the GPIOs are toggled to switch power.
 * TG3PCI_CLOCK_CTRL is another example if the clock frequencies are changed.
 */
void _tw32_flush(struct tg3 *tp, u32 off, u32 val, u32 usec_wait)
{	DBGP("%s\n", __func__);

	tw32(off, val);
	if (usec_wait)
		udelay(usec_wait);
	tr32(off);

	/* Wait again after the read for the posted method to guarantee that
	 * the wait time is met.
	 */
	if (usec_wait)
		udelay(usec_wait);
}

/* stolen from legacy etherboot tg3 driver */
void tg3_set_power_state_0(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	uint16_t power_control;
	int pm = tp->pm_cap;

	/* Make sure register accesses (indirect or otherwise)
	 * will function correctly.
	 */
	pci_write_config_dword(tp->pdev,  TG3PCI_MISC_HOST_CTRL, tp->misc_host_ctrl);

	pci_read_config_word(tp->pdev, pm + PCI_PM_CTRL, &power_control);

	power_control |= PCI_PM_CTRL_PME_STATUS;
	power_control &= ~(PCI_PM_CTRL_STATE_MASK);
	power_control |= 0;
	pci_write_config_word(tp->pdev, pm + PCI_PM_CTRL, power_control);

	tw32_wait_f(GRC_LOCAL_CTRL, tp->grc_local_ctrl, 100);

	return;
}

void tg3_read_mem(struct tg3 *tp, u32 off, u32 *val)
{	DBGP("%s\n", __func__);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906 &&
	    (off >= NIC_SRAM_STATS_BLK) && (off < NIC_SRAM_TX_BUFFER_DESC)) {
		*val = 0;
		return;
	}

	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, off);
	pci_read_config_dword(tp->pdev, TG3PCI_MEM_WIN_DATA, val);

	/* Always leave this as zero. */
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);
}

#define PCI_VENDOR_ID_ARIMA                0x161f

static void tg3_get_eeprom_hw_cfg(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 val;
	u16 pmcsr;

	/* On some early chips the SRAM cannot be accessed in D3hot state,
	 * so need make sure we're in D0.
	 */
	pci_read_config_word(tp->pdev, tp->pm_cap + PCI_PM_CTRL, &pmcsr);
	pmcsr &= ~PCI_PM_CTRL_STATE_MASK;
	pci_write_config_word(tp->pdev, tp->pm_cap + PCI_PM_CTRL, pmcsr);
	mdelay(1);

	/* Make sure register accesses (indirect or otherwise)
	 * will function correctly.
	 */
	pci_write_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			       tp->misc_host_ctrl);

	/* The memory arbiter has to be enabled in order for SRAM accesses
	 * to succeed.  Normally on powerup the tg3 chip firmware will make
	 * sure it is enabled, but other entities such as system netboot
	 * code might disable it.
	 */
	val = tr32(MEMARB_MODE);
	tw32(MEMARB_MODE, val | MEMARB_MODE_ENABLE);

	tp->phy_id = TG3_PHY_ID_INVALID;
	tp->led_ctrl = LED_CTRL_MODE_PHY_1;

	/* Assume an onboard device by default.  */
	tg3_flag_set(tp, EEPROM_WRITE_PROT);

	tg3_read_mem(tp, NIC_SRAM_DATA_SIG, &val);
	if (val == NIC_SRAM_DATA_SIG_MAGIC) {
		u32 nic_cfg, led_cfg;
		u32 nic_phy_id, ver, cfg2 = 0, cfg4 = 0, eeprom_phy_id;
		int eeprom_phy_serdes = 0;

		tg3_read_mem(tp, NIC_SRAM_DATA_CFG, &nic_cfg);
		tp->nic_sram_data_cfg = nic_cfg;

		tg3_read_mem(tp, NIC_SRAM_DATA_VER, &ver);
		ver >>= NIC_SRAM_DATA_VER_SHIFT;
		if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700 &&
		    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5701 &&
		    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5703 &&
		    (ver > 0) && (ver < 0x100))
			tg3_read_mem(tp, NIC_SRAM_DATA_CFG_2, &cfg2);

		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5785)
			tg3_read_mem(tp, NIC_SRAM_DATA_CFG_4, &cfg4);

		if ((nic_cfg & NIC_SRAM_DATA_CFG_PHY_TYPE_MASK) ==
		    NIC_SRAM_DATA_CFG_PHY_TYPE_FIBER)
			eeprom_phy_serdes = 1;

		tg3_read_mem(tp, NIC_SRAM_DATA_PHY_ID, &nic_phy_id);
		if (nic_phy_id != 0) {
			u32 id1 = nic_phy_id & NIC_SRAM_DATA_PHY_ID1_MASK;
			u32 id2 = nic_phy_id & NIC_SRAM_DATA_PHY_ID2_MASK;

			eeprom_phy_id  = (id1 >> 16) << 10;
			eeprom_phy_id |= (id2 & 0xfc00) << 16;
			eeprom_phy_id |= (id2 & 0x03ff) <<  0;
		} else
			eeprom_phy_id = 0;

		tp->phy_id = eeprom_phy_id;
		if (eeprom_phy_serdes) {
			if (!tg3_flag(tp, 5705_PLUS))
				tp->phy_flags |= TG3_PHYFLG_PHY_SERDES;
			else
				tp->phy_flags |= TG3_PHYFLG_MII_SERDES;
		}

		if (tg3_flag(tp, 5750_PLUS))
			led_cfg = cfg2 & (NIC_SRAM_DATA_CFG_LED_MODE_MASK |
				    SHASTA_EXT_LED_MODE_MASK);
		else
			led_cfg = nic_cfg & NIC_SRAM_DATA_CFG_LED_MODE_MASK;

		switch (led_cfg) {
		default:
		case NIC_SRAM_DATA_CFG_LED_MODE_PHY_1:
			tp->led_ctrl = LED_CTRL_MODE_PHY_1;
			break;

		case NIC_SRAM_DATA_CFG_LED_MODE_PHY_2:
			tp->led_ctrl = LED_CTRL_MODE_PHY_2;
			break;

		case NIC_SRAM_DATA_CFG_LED_MODE_MAC:
			tp->led_ctrl = LED_CTRL_MODE_MAC;

			/* Default to PHY_1_MODE if 0 (MAC_MODE) is
			 * read on some older 5700/5701 bootcode.
			 */
			if (GET_ASIC_REV(tp->pci_chip_rev_id) ==
			    ASIC_REV_5700 ||
			    GET_ASIC_REV(tp->pci_chip_rev_id) ==
			    ASIC_REV_5701)
				tp->led_ctrl = LED_CTRL_MODE_PHY_1;

			break;

		case SHASTA_EXT_LED_SHARED:
			tp->led_ctrl = LED_CTRL_MODE_SHARED;
			if (tp->pci_chip_rev_id != CHIPREV_ID_5750_A0 &&
			    tp->pci_chip_rev_id != CHIPREV_ID_5750_A1)
				tp->led_ctrl |= (LED_CTRL_MODE_PHY_1 |
						 LED_CTRL_MODE_PHY_2);
			break;

		case SHASTA_EXT_LED_MAC:
			tp->led_ctrl = LED_CTRL_MODE_SHASTA_MAC;
			break;

		case SHASTA_EXT_LED_COMBO:
			tp->led_ctrl = LED_CTRL_MODE_COMBO;
			if (tp->pci_chip_rev_id != CHIPREV_ID_5750_A0)
				tp->led_ctrl |= (LED_CTRL_MODE_PHY_1 |
						 LED_CTRL_MODE_PHY_2);
			break;

		}

		if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
		     GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701) &&
		    tp->subsystem_vendor == PCI_VENDOR_ID_DELL)
			tp->led_ctrl = LED_CTRL_MODE_PHY_2;

		if (GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5784_AX)
			tp->led_ctrl = LED_CTRL_MODE_PHY_1;

		if (nic_cfg & NIC_SRAM_DATA_CFG_EEPROM_WP) {
			tg3_flag_set(tp, EEPROM_WRITE_PROT);
			if ((tp->subsystem_vendor ==
			     PCI_VENDOR_ID_ARIMA) &&
			    (tp->subsystem_device == 0x205a ||
			     tp->subsystem_device == 0x2063))
				tg3_flag_clear(tp, EEPROM_WRITE_PROT);
		} else {
			tg3_flag_clear(tp, EEPROM_WRITE_PROT);
			tg3_flag_set(tp, IS_NIC);
		}

		if (nic_cfg & NIC_SRAM_DATA_CFG_ASF_ENABLE) {
			tg3_flag_set(tp, ENABLE_ASF);
			if (tg3_flag(tp, 5750_PLUS))
				tg3_flag_set(tp, ASF_NEW_HANDSHAKE);
		}

		if ((nic_cfg & NIC_SRAM_DATA_CFG_APE_ENABLE) &&
		    tg3_flag(tp, ENABLE_ASF))
			tg3_flag_set(tp, ENABLE_APE);

		if (cfg2 & (1 << 17))
			tp->phy_flags |= TG3_PHYFLG_CAPACITIVE_COUPLING;

		/* serdes signal pre-emphasis in register 0x590 set by */
		/* bootcode if bit 18 is set */
		if (cfg2 & (1 << 18))
			tp->phy_flags |= TG3_PHYFLG_SERDES_PREEMPHASIS;

		if ((tg3_flag(tp, 57765_PLUS) ||
		     (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 &&
		      GET_CHIP_REV(tp->pci_chip_rev_id) != CHIPREV_5784_AX)) &&
		    (cfg2 & NIC_SRAM_DATA_CFG_2_APD_EN))
			tp->phy_flags |= TG3_PHYFLG_ENABLE_APD;

		if (tg3_flag(tp, PCI_EXPRESS) &&
		    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5785 &&
		    !tg3_flag(tp, 57765_PLUS)) {
			u32 cfg3;

			tg3_read_mem(tp, NIC_SRAM_DATA_CFG_3, &cfg3);
		}

		if (cfg4 & NIC_SRAM_RGMII_INBAND_DISABLE)
			tg3_flag_set(tp, RGMII_INBAND_DISABLE);
		if (cfg4 & NIC_SRAM_RGMII_EXT_IBND_RX_EN)
			tg3_flag_set(tp, RGMII_EXT_IBND_RX_EN);
		if (cfg4 & NIC_SRAM_RGMII_EXT_IBND_TX_EN)
			tg3_flag_set(tp, RGMII_EXT_IBND_TX_EN);
	}
}

static void tg3_switch_clocks(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 clock_ctrl;
	u32 orig_clock_ctrl;

	if (tg3_flag(tp, CPMU_PRESENT) || tg3_flag(tp, 5780_CLASS))
		return;

	clock_ctrl = tr32(TG3PCI_CLOCK_CTRL);

	orig_clock_ctrl = clock_ctrl;
	clock_ctrl &= (CLOCK_CTRL_FORCE_CLKRUN |
		       CLOCK_CTRL_CLKRUN_OENABLE |
		       0x1f);
	tp->pci_clock_ctrl = clock_ctrl;

	if (tg3_flag(tp, 5705_PLUS)) {
		if (orig_clock_ctrl & CLOCK_CTRL_625_CORE) {
			tw32_wait_f(TG3PCI_CLOCK_CTRL,
				    clock_ctrl | CLOCK_CTRL_625_CORE, 40);
		}
	} else if ((orig_clock_ctrl & CLOCK_CTRL_44MHZ_CORE) != 0) {
		tw32_wait_f(TG3PCI_CLOCK_CTRL,
			    clock_ctrl |
			    (CLOCK_CTRL_44MHZ_CORE | CLOCK_CTRL_ALTCLK),
			    40);
		tw32_wait_f(TG3PCI_CLOCK_CTRL,
			    clock_ctrl | (CLOCK_CTRL_ALTCLK),
			    40);
	}
	tw32_wait_f(TG3PCI_CLOCK_CTRL, clock_ctrl, 40);
}

int tg3_get_invariants(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 misc_ctrl_reg;
	u32 pci_state_reg, grc_misc_cfg;
	u32 val;
	u16 pci_cmd;
	int err;

	/* Force memory write invalidate off.  If we leave it on,
	 * then on 5700_BX chips we have to enable a workaround.
	 * The workaround is to set the TG3PCI_DMA_RW_CTRL boundary
	 * to match the cacheline size.  The Broadcom driver have this
	 * workaround but turns MWI off all the times so never uses
	 * it.  This seems to suggest that the workaround is insufficient.
	 */
	pci_read_config_word(tp->pdev, PCI_COMMAND, &pci_cmd);
	pci_cmd &= ~PCI_COMMAND_INVALIDATE;
	pci_write_config_word(tp->pdev, PCI_COMMAND, pci_cmd);

	/* It is absolutely critical that TG3PCI_MISC_HOST_CTRL
	 * has the register indirect write enable bit set before
	 * we try to access any of the MMIO registers.  It is also
	 * critical that the PCI-X hw workaround situation is decided
	 * before that as well.
	 */
	pci_read_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			      &misc_ctrl_reg);

	tp->pci_chip_rev_id = (misc_ctrl_reg >>
			       MISC_HOST_CTRL_CHIPREV_SHIFT);
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_USE_PROD_ID_REG) {
		u32 prod_id_asic_rev;

		if (tp->pdev->device == TG3PCI_DEVICE_TIGON3_5717 ||
		    tp->pdev->device == TG3PCI_DEVICE_TIGON3_5718 ||
		    tp->pdev->device == TG3PCI_DEVICE_TIGON3_5719 ||
		    tp->pdev->device == TG3PCI_DEVICE_TIGON3_5720)
			pci_read_config_dword(tp->pdev,
					      TG3PCI_GEN2_PRODID_ASICREV,
					      &prod_id_asic_rev);
		else if (tp->pdev->device == TG3PCI_DEVICE_TIGON3_57781 ||
			 tp->pdev->device == TG3PCI_DEVICE_TIGON3_57785 ||
			 tp->pdev->device == TG3PCI_DEVICE_TIGON3_57761 ||
			 tp->pdev->device == TG3PCI_DEVICE_TIGON3_57762 ||
			 tp->pdev->device == TG3PCI_DEVICE_TIGON3_57765 ||
			 tp->pdev->device == TG3PCI_DEVICE_TIGON3_57766 ||
			 tp->pdev->device == TG3PCI_DEVICE_TIGON3_57791 ||
			 tp->pdev->device == TG3PCI_DEVICE_TIGON3_57795)
			pci_read_config_dword(tp->pdev,
					      TG3PCI_GEN15_PRODID_ASICREV,
					      &prod_id_asic_rev);
		else
			pci_read_config_dword(tp->pdev, TG3PCI_PRODID_ASICREV,
					      &prod_id_asic_rev);

		tp->pci_chip_rev_id = prod_id_asic_rev;
	}

	/* Wrong chip ID in 5752 A0. This code can be removed later
	 * as A0 is not in production.
	 */
	if (tp->pci_chip_rev_id == CHIPREV_ID_5752_A0_HW)
		tp->pci_chip_rev_id = CHIPREV_ID_5752_A0;

	/* Initialize misc host control in PCI block. */
	tp->misc_host_ctrl |= (misc_ctrl_reg &
			       MISC_HOST_CTRL_CHIPREV);
	pci_write_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			       tp->misc_host_ctrl);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5717 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5719 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720)
		tg3_flag_set(tp, 5717_PLUS);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57765 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57766 ||
	    tg3_flag(tp, 5717_PLUS))
		tg3_flag_set(tp, 57765_PLUS);

	/* Intentionally exclude ASIC_REV_5906 */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5755 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5761 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5785 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57780 ||
	    tg3_flag(tp, 57765_PLUS))
		tg3_flag_set(tp, 5755_PLUS);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5752 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906 ||
	    tg3_flag(tp, 5755_PLUS) ||
	    tg3_flag(tp, 5780_CLASS))
		tg3_flag_set(tp, 5750_PLUS);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 ||
	    tg3_flag(tp, 5750_PLUS))
		tg3_flag_set(tp, 5705_PLUS);

	if (tg3_flag(tp, 5717_PLUS))
		tg3_flag_set(tp, LRG_PROD_RING_CAP);

	pci_read_config_dword(tp->pdev, TG3PCI_PCISTATE,
			      &pci_state_reg);

	tp->pcie_cap = pci_find_capability(tp->pdev, PCI_CAP_ID_EXP);
	if (tp->pcie_cap != 0) {
		u16 lnkctl;

		tg3_flag_set(tp, PCI_EXPRESS);

		pci_read_config_word(tp->pdev,
				     tp->pcie_cap + PCI_EXP_LNKCTL,
				     &lnkctl);
		if (lnkctl & PCI_EXP_LNKCTL_CLKREQ_EN) {
			if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 ||
			    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5761 ||
			    tp->pci_chip_rev_id == CHIPREV_ID_57780_A0 ||
			    tp->pci_chip_rev_id == CHIPREV_ID_57780_A1)
				tg3_flag_set(tp, CLKREQ_BUG);
		} else if (tp->pci_chip_rev_id == CHIPREV_ID_5717_A0) {
			tg3_flag_set(tp, L1PLLPD_EN);
		}
	} else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5785) {
		tg3_flag_set(tp, PCI_EXPRESS);
	} else if (!tg3_flag(tp, 5705_PLUS) ||
		   tg3_flag(tp, 5780_CLASS)) {
		tp->pcix_cap = pci_find_capability(tp->pdev, PCI_CAP_ID_PCIX);
		if (!tp->pcix_cap) {
			DBGC(&tp->pdev->dev,
				"Cannot find PCI-X capability, aborting\n");
			return -EIO;
		}

		if (!(pci_state_reg & PCISTATE_CONV_PCI_MODE))
			tg3_flag_set(tp, PCIX_MODE);
	}

	/* If we have an AMD 762 or VIA K8T800 chipset, write
	 * reordering to the mailbox registers done by the host
	 * controller can cause major troubles.  We read back from
	 * every mailbox register write to force the writes to be
	 * posted to the chip in order.
	 */

	pci_read_config_byte(tp->pdev, PCI_CACHE_LINE_SIZE,
			     &tp->pci_cacheline_sz);
	pci_read_config_byte(tp->pdev, PCI_LATENCY_TIMER,
			     &tp->pci_lat_timer);
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 &&
	    tp->pci_lat_timer < 64) {
		tp->pci_lat_timer = 64;
		pci_write_config_byte(tp->pdev, PCI_LATENCY_TIMER,
				      tp->pci_lat_timer);
	}

	if (GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5700_BX) {
		/* 5700 BX chips need to have their TX producer index
		 * mailboxes written twice to workaround a bug.
		 */
		tg3_flag_set(tp, TXD_MBOX_HWBUG);

		/* If we are in PCI-X mode, enable register write workaround.
		 *
		 * The workaround is to use indirect register accesses
		 * for all chip writes not to mailbox registers.
		 */
		if (tg3_flag(tp, PCIX_MODE)) {
			u32 pm_reg;

			tg3_flag_set(tp, PCIX_TARGET_HWBUG);

			/* The chip can have it's power management PCI config
			 * space registers clobbered due to this bug.
			 * So explicitly force the chip into D0 here.
			 */
			pci_read_config_dword(tp->pdev,
					      tp->pm_cap + PCI_PM_CTRL,
					      &pm_reg);
			pm_reg &= ~PCI_PM_CTRL_STATE_MASK;
			pm_reg |= PCI_PM_CTRL_PME_ENABLE | 0 /* D0 */;
			pci_write_config_dword(tp->pdev,
					       tp->pm_cap + PCI_PM_CTRL,
					       pm_reg);

			/* Also, force SERR#/PERR# in PCI command. */
			pci_read_config_word(tp->pdev, PCI_COMMAND, &pci_cmd);
			pci_cmd |= PCI_COMMAND_PARITY | PCI_COMMAND_SERR;
			pci_write_config_word(tp->pdev, PCI_COMMAND, pci_cmd);
		}
	}

	if ((pci_state_reg & PCISTATE_BUS_SPEED_HIGH) != 0)
		tg3_flag_set(tp, PCI_HIGH_SPEED);
	if ((pci_state_reg & PCISTATE_BUS_32BIT) != 0)
		tg3_flag_set(tp, PCI_32BIT);

	/* Chip-specific fixup from Broadcom driver */
	if ((tp->pci_chip_rev_id == CHIPREV_ID_5704_A0) &&
	    (!(pci_state_reg & PCISTATE_RETRY_SAME_DMA))) {
		pci_state_reg |= PCISTATE_RETRY_SAME_DMA;
		pci_write_config_dword(tp->pdev, TG3PCI_PCISTATE, pci_state_reg);
	}

	tp->write32_mbox = tg3_write_indirect_reg32;
	tp->write32_rx_mbox = tg3_write_indirect_mbox;
	tp->write32_tx_mbox = tg3_write_indirect_mbox;
	tp->read32_mbox = tg3_read_indirect_mbox;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906) {
		tp->read32_mbox = tg3_read32_mbox_5906;
		tp->write32_mbox = tg3_write32_mbox_5906;
		tp->write32_tx_mbox = tg3_write32_mbox_5906;
		tp->write32_rx_mbox = tg3_write32_mbox_5906;
	}

	/* Get eeprom hw config before calling tg3_set_power_state().
	 * In particular, the TG3_FLAG_IS_NIC flag must be
	 * determined before calling tg3_set_power_state() so that
	 * we know whether or not to switch out of Vaux power.
	 * When the flag is set, it means that GPIO1 is used for eeprom
	 * write protect and also implies that it is a LOM where GPIOs
	 * are not used to switch power.
	 */
	tg3_get_eeprom_hw_cfg(tp);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5761 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5785 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57780 ||
	    tg3_flag(tp, 57765_PLUS))
		tg3_flag_set(tp, CPMU_PRESENT);

	/* Set up tp->grc_local_ctrl before calling tg3_power_up().
	 * GPIO1 driven high will bring 5700's external PHY out of reset.
	 * It is also used as eeprom write protect on LOMs.
	 */
	tp->grc_local_ctrl = GRC_LCLCTRL_INT_ON_ATTN | GRC_LCLCTRL_AUTO_SEEPROM;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
	    tg3_flag(tp, EEPROM_WRITE_PROT))
		tp->grc_local_ctrl |= (GRC_LCLCTRL_GPIO_OE1 |
				       GRC_LCLCTRL_GPIO_OUTPUT1);
	/* Unused GPIO3 must be driven as output on 5752 because there
	 * are no pull-up resistors on unused GPIO pins.
	 */
	else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5752)
		tp->grc_local_ctrl |= GRC_LCLCTRL_GPIO_OE3;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5755 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57780 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57765)
		tp->grc_local_ctrl |= GRC_LCLCTRL_GPIO_UART_SEL;

	if (tp->pdev->device == PCI_DEVICE_ID_TIGON3_5761 ||
	    tp->pdev->device == TG3PCI_DEVICE_TIGON3_5761S) {
		/* Turn off the debug UART. */
		tp->grc_local_ctrl |= GRC_LCLCTRL_GPIO_UART_SEL;
		if (tg3_flag(tp, IS_NIC))
			/* Keep VMain power. */
			tp->grc_local_ctrl |= GRC_LCLCTRL_GPIO_OE0 |
					      GRC_LCLCTRL_GPIO_OUTPUT0;
	}

	/* Force the chip into D0. */
	tg3_set_power_state_0(tp);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906)
		tp->phy_flags |= TG3_PHYFLG_IS_FET;

	/* A few boards don't want Ethernet@WireSpeed phy feature */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
	    (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 &&
	     (tp->pci_chip_rev_id != CHIPREV_ID_5705_A0) &&
	     (tp->pci_chip_rev_id != CHIPREV_ID_5705_A1)) ||
	    (tp->phy_flags & TG3_PHYFLG_IS_FET) ||
	    (tp->phy_flags & TG3_PHYFLG_ANY_SERDES))
		tp->phy_flags |= TG3_PHYFLG_NO_ETH_WIRE_SPEED;

	if (GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5703_AX ||
	    GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5704_AX)
		tp->phy_flags |= TG3_PHYFLG_ADC_BUG;
	if (tp->pci_chip_rev_id == CHIPREV_ID_5704_A0)
		tp->phy_flags |= TG3_PHYFLG_5704_A0_BUG;

	if (tg3_flag(tp, 5705_PLUS) &&
	    !(tp->phy_flags & TG3_PHYFLG_IS_FET) &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5785 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_57780 &&
	    !tg3_flag(tp, 57765_PLUS)) {
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5755 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5761) {
			if (tp->pdev->device != PCI_DEVICE_ID_TIGON3_5756 &&
			    tp->pdev->device != PCI_DEVICE_ID_TIGON3_5722)
				tp->phy_flags |= TG3_PHYFLG_JITTER_BUG;
			if (tp->pdev->device == PCI_DEVICE_ID_TIGON3_5755M)
				tp->phy_flags |= TG3_PHYFLG_ADJUST_TRIM;
		} else
			tp->phy_flags |= TG3_PHYFLG_BER_BUG;
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 &&
	    GET_CHIP_REV(tp->pci_chip_rev_id) != CHIPREV_5784_AX) {
		tp->phy_otp = tg3_read_otp_phycfg(tp);
		if (tp->phy_otp == 0)
			tp->phy_otp = TG3_OTP_DEFAULT;
	}

	if (tg3_flag(tp, CPMU_PRESENT))
		tp->mi_mode = MAC_MI_MODE_500KHZ_CONST;
	else
		tp->mi_mode = MAC_MI_MODE_BASE;

	tp->coalesce_mode = 0;
	if (GET_CHIP_REV(tp->pci_chip_rev_id) != CHIPREV_5700_AX &&
	    GET_CHIP_REV(tp->pci_chip_rev_id) != CHIPREV_5700_BX)
		tp->coalesce_mode |= HOSTCC_MODE_32BYTE;

	/* Set these bits to enable statistics workaround. */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5717 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5719_A0 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5720_A0) {
		tp->coalesce_mode |= HOSTCC_MODE_ATTN;
		tp->grc_mode |= GRC_MODE_IRQ_ON_FLOW_ATTN;
	}

	tg3_mdio_init(tp);

	/* Initialize data/descriptor byte/word swapping. */
	val = tr32(GRC_MODE);
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720)
		val &= (GRC_MODE_BYTE_SWAP_B2HRX_DATA |
			GRC_MODE_WORD_SWAP_B2HRX_DATA |
			GRC_MODE_B2HRX_ENABLE |
			GRC_MODE_HTX2B_ENABLE |
			GRC_MODE_HOST_STACKUP);
	else
		val &= GRC_MODE_HOST_STACKUP;

	tw32(GRC_MODE, val | tp->grc_mode);

	tg3_switch_clocks(tp);

	/* Clear this out for sanity. */
	tw32(TG3PCI_MEM_WIN_BASE_ADDR, 0);

	pci_read_config_dword(tp->pdev, TG3PCI_PCISTATE,
			      &pci_state_reg);
	if ((pci_state_reg & PCISTATE_CONV_PCI_MODE) == 0 &&
	    !tg3_flag(tp, PCIX_TARGET_HWBUG)) {
		u32 chiprevid = GET_CHIP_REV_ID(tp->misc_host_ctrl);

		if (chiprevid == CHIPREV_ID_5701_A0 ||
		    chiprevid == CHIPREV_ID_5701_B0 ||
		    chiprevid == CHIPREV_ID_5701_B2 ||
		    chiprevid == CHIPREV_ID_5701_B5) {
			void *sram_base;

			/* Write some dummy words into the SRAM status block
			 * area, see if it reads back correctly.  If the return
			 * value is bad, force enable the PCIX workaround.
			 */
			sram_base = tp->regs + NIC_SRAM_WIN_BASE + NIC_SRAM_STATS_BLK;

			writel(0x00000000, sram_base);
			writel(0x00000000, sram_base + 4);
			writel(0xffffffff, sram_base + 4);
			if (readl(sram_base) != 0x00000000)
				tg3_flag_set(tp, PCIX_TARGET_HWBUG);
		}
	}

	udelay(50);
	/* FIXME: do we need nvram access? */
///	tg3_nvram_init(tp);

	grc_misc_cfg = tr32(GRC_MISC_CFG);
	grc_misc_cfg &= GRC_MISC_CFG_BOARD_ID_MASK;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 &&
	    (grc_misc_cfg == GRC_MISC_CFG_BOARD_ID_5788 ||
	     grc_misc_cfg == GRC_MISC_CFG_BOARD_ID_5788M))
		tg3_flag_set(tp, IS_5788);

	if (!tg3_flag(tp, IS_5788) &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700)
		tg3_flag_set(tp, TAGGED_STATUS);
	if (tg3_flag(tp, TAGGED_STATUS)) {
		tp->coalesce_mode |= (HOSTCC_MODE_CLRTICK_RXBD |
				      HOSTCC_MODE_CLRTICK_TXBD);

		tp->misc_host_ctrl |= MISC_HOST_CTRL_TAGGED_STATUS;
		pci_write_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
				       tp->misc_host_ctrl);
	}

	/* Preserve the APE MAC_MODE bits */
	if (tg3_flag(tp, ENABLE_APE))
		tp->mac_mode = MAC_MODE_APE_TX_EN | MAC_MODE_APE_RX_EN;
	else
		tp->mac_mode = TG3_DEF_MAC_MODE;

	/* these are limited to 10/100 only */
	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 &&
	     (grc_misc_cfg == 0x8000 || grc_misc_cfg == 0x4000)) ||
	    (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 &&
	     tp->pdev->vendor == PCI_VENDOR_ID_BROADCOM &&
	     (tp->pdev->device == PCI_DEVICE_ID_TIGON3_5901 ||
	      tp->pdev->device == PCI_DEVICE_ID_TIGON3_5901_2 ||
	      tp->pdev->device == PCI_DEVICE_ID_TIGON3_5705F)) ||
	    (tp->pdev->vendor == PCI_VENDOR_ID_BROADCOM &&
	     (tp->pdev->device == PCI_DEVICE_ID_TIGON3_5751F ||
	      tp->pdev->device == PCI_DEVICE_ID_TIGON3_5753F ||
	      tp->pdev->device == PCI_DEVICE_ID_TIGON3_5787F)) ||
	    tp->pdev->device == TG3PCI_DEVICE_TIGON3_57790 ||
	    tp->pdev->device == TG3PCI_DEVICE_TIGON3_57791 ||
	    tp->pdev->device == TG3PCI_DEVICE_TIGON3_57795 ||
	    (tp->phy_flags & TG3_PHYFLG_IS_FET))
		tp->phy_flags |= TG3_PHYFLG_10_100_ONLY;

	err = tg3_phy_probe(tp);
	if (err) {
		DBGC(&tp->pdev->dev, "phy probe failed, err: %s\n", strerror(err));
		/* ... but do not return immediately ... */
	}

	if (tp->phy_flags & TG3_PHYFLG_PHY_SERDES) {
		tp->phy_flags &= ~TG3_PHYFLG_USE_MI_INTERRUPT;
	} else {
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700)
			tp->phy_flags |= TG3_PHYFLG_USE_MI_INTERRUPT;
		else
			tp->phy_flags &= ~TG3_PHYFLG_USE_MI_INTERRUPT;
	}

	/* For all SERDES we poll the MAC status register. */
	if (tp->phy_flags & TG3_PHYFLG_PHY_SERDES)
		tg3_flag_set(tp, POLL_SERDES);
	else
		tg3_flag_clear(tp, POLL_SERDES);

	/* Increment the rx prod index on the rx std ring by at most
	 * 8 for these chips to workaround hw errata.
	 */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5752 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5755)
		tp->rx_std_max_post = 8;

	return err;
}

void tg3_init_bufmgr_config(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tg3_flag(tp, 57765_PLUS)) {
		tp->bufmgr_config.mbuf_read_dma_low_water =
			DEFAULT_MB_RDMA_LOW_WATER_5705;
		tp->bufmgr_config.mbuf_mac_rx_low_water =
			DEFAULT_MB_MACRX_LOW_WATER_57765;
		tp->bufmgr_config.mbuf_high_water =
			DEFAULT_MB_HIGH_WATER_57765;

		tp->bufmgr_config.mbuf_read_dma_low_water_jumbo =
			DEFAULT_MB_RDMA_LOW_WATER_5705;
		tp->bufmgr_config.mbuf_mac_rx_low_water_jumbo =
			DEFAULT_MB_MACRX_LOW_WATER_JUMBO_57765;
		tp->bufmgr_config.mbuf_high_water_jumbo =
			DEFAULT_MB_HIGH_WATER_JUMBO_57765;
	} else if (tg3_flag(tp, 5705_PLUS)) {
		tp->bufmgr_config.mbuf_read_dma_low_water =
			DEFAULT_MB_RDMA_LOW_WATER_5705;
		tp->bufmgr_config.mbuf_mac_rx_low_water =
			DEFAULT_MB_MACRX_LOW_WATER_5705;
		tp->bufmgr_config.mbuf_high_water =
			DEFAULT_MB_HIGH_WATER_5705;
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906) {
			tp->bufmgr_config.mbuf_mac_rx_low_water =
				DEFAULT_MB_MACRX_LOW_WATER_5906;
			tp->bufmgr_config.mbuf_high_water =
				DEFAULT_MB_HIGH_WATER_5906;
		}

		tp->bufmgr_config.mbuf_read_dma_low_water_jumbo =
			DEFAULT_MB_RDMA_LOW_WATER_JUMBO_5780;
		tp->bufmgr_config.mbuf_mac_rx_low_water_jumbo =
			DEFAULT_MB_MACRX_LOW_WATER_JUMBO_5780;
		tp->bufmgr_config.mbuf_high_water_jumbo =
			DEFAULT_MB_HIGH_WATER_JUMBO_5780;
	} else {
		tp->bufmgr_config.mbuf_read_dma_low_water =
			DEFAULT_MB_RDMA_LOW_WATER;
		tp->bufmgr_config.mbuf_mac_rx_low_water =
			DEFAULT_MB_MACRX_LOW_WATER;
		tp->bufmgr_config.mbuf_high_water =
			DEFAULT_MB_HIGH_WATER;

		tp->bufmgr_config.mbuf_read_dma_low_water_jumbo =
			DEFAULT_MB_RDMA_LOW_WATER_JUMBO;
		tp->bufmgr_config.mbuf_mac_rx_low_water_jumbo =
			DEFAULT_MB_MACRX_LOW_WATER_JUMBO;
		tp->bufmgr_config.mbuf_high_water_jumbo =
			DEFAULT_MB_HIGH_WATER_JUMBO;
	}

	tp->bufmgr_config.dma_low_water = DEFAULT_DMA_LOW_WATER;
	tp->bufmgr_config.dma_high_water = DEFAULT_DMA_HIGH_WATER;
}

#define TG3_FW_EVENT_TIMEOUT_USEC 2500

void tg3_wait_for_event_ack(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int i;

	for (i = 0; i < TG3_FW_EVENT_TIMEOUT_USEC / 10; i++) {
		if (!(tr32(GRC_RX_CPU_EVENT) & GRC_RX_CPU_DRIVER_EVENT))
			break;

		udelay(10);
	}
}

void tg3_write_mem(struct tg3 *tp, u32 off, u32 val)
{	DBGP("%s\n", __func__);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906 &&
	    (off >= NIC_SRAM_STATS_BLK) && (off < NIC_SRAM_TX_BUFFER_DESC))
		return;

	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, off);
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_DATA, val);

	/* Always leave this as zero. */
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);
}

static void tg3_stop_fw(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tg3_flag(tp, ENABLE_ASF) && !tg3_flag(tp, ENABLE_APE)) {
		/* Wait for RX cpu to ACK the previous event. */
		tg3_wait_for_event_ack(tp);

		tg3_write_mem(tp, NIC_SRAM_FW_CMD_MBOX, FWCMD_NICDRV_PAUSE_FW);

		tg3_generate_fw_event(tp);

		/* Wait for RX cpu to ACK this event. */
		tg3_wait_for_event_ack(tp);
	}
}

static void tg3_write_sig_pre_reset(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	tg3_write_mem(tp, NIC_SRAM_FIRMWARE_MBOX,
		      NIC_SRAM_FIRMWARE_MBOX_MAGIC1);
}

void tg3_disable_ints(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	tw32(TG3PCI_MISC_HOST_CTRL,
	     (tp->misc_host_ctrl | MISC_HOST_CTRL_MASK_PCI_INT));

	tw32_mailbox_f(tp->int_mbox, 0x00000001);
}

void tg3_enable_ints(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	tw32(TG3PCI_MISC_HOST_CTRL,
	     (tp->misc_host_ctrl & ~MISC_HOST_CTRL_MASK_PCI_INT));

	tp->coal_now = tp->coalesce_mode | HOSTCC_MODE_ENABLE;

	tw32_mailbox_f(tp->int_mbox, tp->last_tag << 24);

	/* Force an initial interrupt */
	if (!tg3_flag(tp, TAGGED_STATUS) &&
	    (tp->hw_status->status & SD_STATUS_UPDATED))
		tw32(GRC_LOCAL_CTRL, tp->grc_local_ctrl | GRC_LCLCTRL_SETINT);
	else
		tw32(HOSTCC_MODE, tp->coal_now);
}

#define MAX_WAIT_CNT 1000

/* To stop a block, clear the enable bit and poll till it clears. */
static int tg3_stop_block(struct tg3 *tp, unsigned long ofs, u32 enable_bit)
{	DBGP("%s\n", __func__);

	unsigned int i;
	u32 val;

	if (tg3_flag(tp, 5705_PLUS)) {
		switch (ofs) {
		case RCVLSC_MODE:
		case DMAC_MODE:
		case MBFREE_MODE:
		case BUFMGR_MODE:
		case MEMARB_MODE:
			/* We can't enable/disable these bits of the
			 * 5705/5750, just say success.
			 */
			return 0;

		default:
			break;
		}
	}

	val = tr32(ofs);
	val &= ~enable_bit;
	tw32_f(ofs, val);

	for (i = 0; i < MAX_WAIT_CNT; i++) {
		udelay(100);
		val = tr32(ofs);
		if ((val & enable_bit) == 0)
			break;
	}

	if (i == MAX_WAIT_CNT) {
		DBGC(&tp->pdev->dev,
			"tg3_stop_block timed out, ofs=%lx enable_bit=%x\n",
			ofs, enable_bit);
		return -ENODEV;
	}

	return 0;
}

static int tg3_abort_hw(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int i, err;

	tg3_disable_ints(tp);

	tp->rx_mode &= ~RX_MODE_ENABLE;
	tw32_f(MAC_RX_MODE, tp->rx_mode);
	udelay(10);

	err  = tg3_stop_block(tp, RCVBDI_MODE, RCVBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVLPC_MODE, RCVLPC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVLSC_MODE, RCVLSC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVDBDI_MODE, RCVDBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVDCC_MODE, RCVDCC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVCC_MODE, RCVCC_MODE_ENABLE);

	err |= tg3_stop_block(tp, SNDBDS_MODE, SNDBDS_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDBDI_MODE, SNDBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDDATAI_MODE, SNDDATAI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RDMAC_MODE, RDMAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDDATAC_MODE, SNDDATAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, DMAC_MODE, DMAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDBDC_MODE, SNDBDC_MODE_ENABLE);

	tp->mac_mode &= ~MAC_MODE_TDE_ENABLE;
	tw32_f(MAC_MODE, tp->mac_mode);
	udelay(40);

	tp->tx_mode &= ~TX_MODE_ENABLE;
	tw32_f(MAC_TX_MODE, tp->tx_mode);

	for (i = 0; i < MAX_WAIT_CNT; i++) {
		udelay(100);
		if (!(tr32(MAC_TX_MODE) & TX_MODE_ENABLE))
			break;
	}
	if (i >= MAX_WAIT_CNT) {
		DBGC(&tp->pdev->dev,
			"%s timed out, TX_MODE_ENABLE will not clear "
			"MAC_TX_MODE=%08x\n", __func__, tr32(MAC_TX_MODE));
		err |= -ENODEV;
	}

	err |= tg3_stop_block(tp, HOSTCC_MODE, HOSTCC_MODE_ENABLE);
	err |= tg3_stop_block(tp, WDMAC_MODE, WDMAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, MBFREE_MODE, MBFREE_MODE_ENABLE);

	tw32(FTQ_RESET, 0xffffffff);
	tw32(FTQ_RESET, 0x00000000);

	err |= tg3_stop_block(tp, BUFMGR_MODE, BUFMGR_MODE_ENABLE);
	err |= tg3_stop_block(tp, MEMARB_MODE, MEMARB_MODE_ENABLE);

	if (tp->hw_status)
		memset(tp->hw_status, 0, TG3_HW_STATUS_SIZE);

	return err;
}

void __tg3_set_mac_addr(struct tg3 *tp, int skip_mac_1)
{	DBGP("%s\n", __func__);

	u32 addr_high, addr_low;
	int i;

	addr_high = ((tp->dev->ll_addr[0] << 8) |
		     tp->dev->ll_addr[1]);
	addr_low = ((tp->dev->ll_addr[2] << 24) |
		    (tp->dev->ll_addr[3] << 16) |
		    (tp->dev->ll_addr[4] <<  8) |
		    (tp->dev->ll_addr[5] <<  0));
	for (i = 0; i < 4; i++) {
		if (i == 1 && skip_mac_1)
			continue;
		tw32(MAC_ADDR_0_HIGH + (i * 8), addr_high);
		tw32(MAC_ADDR_0_LOW + (i * 8), addr_low);
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) {
		for (i = 0; i < 12; i++) {
			tw32(MAC_EXTADDR_0_HIGH + (i * 8), addr_high);
			tw32(MAC_EXTADDR_0_LOW + (i * 8), addr_low);
		}
	}

	addr_high = (tp->dev->ll_addr[0] +
		     tp->dev->ll_addr[1] +
		     tp->dev->ll_addr[2] +
		     tp->dev->ll_addr[3] +
		     tp->dev->ll_addr[4] +
		     tp->dev->ll_addr[5]) &
		TX_BACKOFF_SEED_MASK;
	tw32(MAC_TX_BACKOFF_SEED, addr_high);
}

/* Save PCI command register before chip reset */
static void tg3_save_pci_state(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	pci_read_config_word(tp->pdev, PCI_COMMAND, &tp->pci_cmd);
}

/* Restore PCI state after chip reset */
static void tg3_restore_pci_state(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 val;

	/* Re-enable indirect register accesses. */
	pci_write_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			       tp->misc_host_ctrl);

	/* Set MAX PCI retry to zero. */
	val = (PCISTATE_ROM_ENABLE | PCISTATE_ROM_RETRY_ENABLE);
	if (tp->pci_chip_rev_id == CHIPREV_ID_5704_A0 &&
	    tg3_flag(tp, PCIX_MODE))
		val |= PCISTATE_RETRY_SAME_DMA;

	pci_write_config_dword(tp->pdev, TG3PCI_PCISTATE, val);

	pci_write_config_word(tp->pdev, PCI_COMMAND, tp->pci_cmd);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5785) {
			pci_write_config_byte(tp->pdev, PCI_CACHE_LINE_SIZE,
					      tp->pci_cacheline_sz);
			pci_write_config_byte(tp->pdev, PCI_LATENCY_TIMER,
					      tp->pci_lat_timer);
	}


	/* Make sure PCI-X relaxed ordering bit is clear. */
	if (tg3_flag(tp, PCIX_MODE)) {
		u16 pcix_cmd;

		pci_read_config_word(tp->pdev, tp->pcix_cap + PCI_X_CMD,
				     &pcix_cmd);
		pcix_cmd &= ~PCI_X_CMD_ERO;
		pci_write_config_word(tp->pdev, tp->pcix_cap + PCI_X_CMD,
				      pcix_cmd);
	}
}

static int tg3_poll_fw(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int i;
	u32 val;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906) {
		/* Wait up to 20ms for init done. */
		for (i = 0; i < 200; i++) {
			if (tr32(VCPU_STATUS) & VCPU_STATUS_INIT_DONE)
				return 0;
			udelay(100);
		}
		return -ENODEV;
	}

	/* Wait for firmware initialization to complete. */
	for (i = 0; i < 100000; i++) {
		tg3_read_mem(tp, NIC_SRAM_FIRMWARE_MBOX, &val);
		if (val == (u32)~NIC_SRAM_FIRMWARE_MBOX_MAGIC1)
			break;
		udelay(10);
	}

	/* Chip might not be fitted with firmware.  Some Sun onboard
	 * parts are configured like that.  So don't signal the timeout
	 * of the above loop as an error, but do report the lack of
	 * running firmware once.
	 */
	if (i >= 100000 && !tg3_flag(tp, NO_FWARE_REPORTED)) {
		tg3_flag_set(tp, NO_FWARE_REPORTED);

		DBGC(tp->dev, "No firmware running\n");
	}

	if (tp->pci_chip_rev_id == CHIPREV_ID_57765_A0) {
		/* The 57765 A0 needs a little more
		 * time to do some important work.
		 */
		mdelay(10);
	}

	return 0;
}

static int tg3_nvram_lock(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tg3_flag(tp, NVRAM)) {
		int i;

		if (tp->nvram_lock_cnt == 0) {
			tw32(NVRAM_SWARB, SWARB_REQ_SET1);
			for (i = 0; i < 8000; i++) {
				if (tr32(NVRAM_SWARB) & SWARB_GNT1)
					break;
				udelay(20);
			}
			if (i == 8000) {
				tw32(NVRAM_SWARB, SWARB_REQ_CLR1);
				return -ENODEV;
			}
		}
		tp->nvram_lock_cnt++;
	}
	return 0;
}

static void tg3_nvram_unlock(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tg3_flag(tp, NVRAM)) {
		if (tp->nvram_lock_cnt > 0)
			tp->nvram_lock_cnt--;
		if (tp->nvram_lock_cnt == 0)
			tw32_f(NVRAM_SWARB, SWARB_REQ_CLR1);
	}
}

static int tg3_chip_reset(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 val;
	int err;

	tg3_nvram_lock(tp);


	/* No matching tg3_nvram_unlock() after this because
	 * chip reset below will undo the nvram lock.
	 */
	tp->nvram_lock_cnt = 0;

	/* GRC_MISC_CFG core clock reset will clear the memory
	 * enable bit in PCI register 4 and the MSI enable bit
	 * on some chips, so we save relevant registers here.
	 */
	tg3_save_pci_state(tp);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5752 ||
	    tg3_flag(tp, 5755_PLUS))
		tw32(GRC_FASTBOOT_PC, 0);

#if 0
	/*
	 * We must avoid the readl() that normally takes place.
	 * It locks machines, causes machine checks, and other
	 * fun things.  So, temporarily disable the 5701
	 * hardware workaround, while we do the reset.
	 */
	write_op = tp->write32;
	if (write_op == tg3_write_flush_reg32)
		tp->write32 = tg3_write32;
#endif

	/* Prevent the irq handler from reading or writing PCI registers
	 * during chip reset when the memory enable bit in the PCI command
	 * register may be cleared.  The chip does not generate interrupt
	 * at this time, but the irq handler may still be called due to irq
	 * sharing or irqpoll.
	 */
	tg3_flag_set(tp, CHIP_RESETTING);

	if (tp->hw_status) {
		tp->hw_status->status = 0;
		tp->hw_status->status_tag = 0;
	}
	tp->last_tag = 0;
	tp->last_irq_tag = 0;

	mb();

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57780) {
		val = tr32(TG3_PCIE_LNKCTL) & ~TG3_PCIE_LNKCTL_L1_PLL_PD_EN;
		tw32(TG3_PCIE_LNKCTL, val | TG3_PCIE_LNKCTL_L1_PLL_PD_DIS);
	}

	/* do the reset */
	val = GRC_MISC_CFG_CORECLK_RESET;

	if (tg3_flag(tp, PCI_EXPRESS)) {
		/* Force PCIe 1.0a mode */
		if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5785 &&
		    !tg3_flag(tp, 57765_PLUS) &&
		    tr32(TG3_PCIE_PHY_TSTCTL) ==
		    (TG3_PCIE_PHY_TSTCTL_PCIE10 | TG3_PCIE_PHY_TSTCTL_PSCRAM))
			tw32(TG3_PCIE_PHY_TSTCTL, TG3_PCIE_PHY_TSTCTL_PSCRAM);

		if (tp->pci_chip_rev_id != CHIPREV_ID_5750_A0) {
			tw32(GRC_MISC_CFG, (1 << 29));
			val |= (1 << 29);
		}
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906) {
		tw32(VCPU_STATUS, tr32(VCPU_STATUS) | VCPU_STATUS_DRV_RESET);
		tw32(GRC_VCPU_EXT_CTRL,
		     tr32(GRC_VCPU_EXT_CTRL) & ~GRC_VCPU_EXT_CTRL_HALT_CPU);
	}

	/* Manage gphy power for all CPMU absent PCIe devices. */
	if (tg3_flag(tp, 5705_PLUS) && !tg3_flag(tp, CPMU_PRESENT))
		val |= GRC_MISC_CFG_KEEP_GPHY_POWER;

	tw32(GRC_MISC_CFG, val);

	/* Unfortunately, we have to delay before the PCI read back.
	 * Some 575X chips even will not respond to a PCI cfg access
	 * when the reset command is given to the chip.
	 *
	 * How do these hardware designers expect things to work
	 * properly if the PCI write is posted for a long period
	 * of time?  It is always necessary to have some method by
	 * which a register read back can occur to push the write
	 * out which does the reset.
	 *
	 * For most tg3 variants the trick below was working.
	 * Ho hum...
	 */
	udelay(120);

	/* Flush PCI posted writes.  The normal MMIO registers
	 * are inaccessible at this time so this is the only
	 * way to make this reliably (actually, this is no longer
	 * the case, see above).  I tried to use indirect
	 * register read/write but this upset some 5701 variants.
	 */
	pci_read_config_dword(tp->pdev, PCI_COMMAND, &val);

	udelay(120);

	if (tg3_flag(tp, PCI_EXPRESS) && tp->pcie_cap) {
		u16 val16;

		if (tp->pci_chip_rev_id == CHIPREV_ID_5750_A0) {
			int i;
			u32 cfg_val;

			/* Wait for link training to complete.  */
			for (i = 0; i < 5000; i++)
				udelay(100);

			pci_read_config_dword(tp->pdev, 0xc4, &cfg_val);
			pci_write_config_dword(tp->pdev, 0xc4,
					       cfg_val | (1 << 15));
		}

		/* Clear the "no snoop" and "relaxed ordering" bits. */
		pci_read_config_word(tp->pdev,
				     tp->pcie_cap + PCI_EXP_DEVCTL,
				     &val16);
		val16 &= ~(PCI_EXP_DEVCTL_RELAX_EN |
			   PCI_EXP_DEVCTL_NOSNOOP_EN);
		/*
		 * Older PCIe devices only support the 128 byte
		 * MPS setting.  Enforce the restriction.
		 */
		if (!tg3_flag(tp, CPMU_PRESENT))
			val16 &= ~PCI_EXP_DEVCTL_PAYLOAD;
		pci_write_config_word(tp->pdev,
				      tp->pcie_cap + PCI_EXP_DEVCTL,
				      val16);

		/* Clear error status */
		pci_write_config_word(tp->pdev,
				      tp->pcie_cap + PCI_EXP_DEVSTA,
				      PCI_EXP_DEVSTA_CED |
				      PCI_EXP_DEVSTA_NFED |
				      PCI_EXP_DEVSTA_FED |
				      PCI_EXP_DEVSTA_URD);
	}

	tg3_restore_pci_state(tp);

	tg3_flag_clear(tp, CHIP_RESETTING);
	tg3_flag_clear(tp, ERROR_PROCESSED);

	val = 0;
	if (tg3_flag(tp, 5780_CLASS))
		val = tr32(MEMARB_MODE);
	tw32(MEMARB_MODE, val | MEMARB_MODE_ENABLE);

	if (tp->pci_chip_rev_id == CHIPREV_ID_5750_A3) {
		tg3_stop_fw(tp);
		tw32(0x5000, 0x400);
	}

	tw32(GRC_MODE, tp->grc_mode);

	if (tp->pci_chip_rev_id == CHIPREV_ID_5705_A0) {
		val = tr32(0xc4);

		tw32(0xc4, val | (1 << 15));
	}

	if ((tp->nic_sram_data_cfg & NIC_SRAM_DATA_CFG_MINI_PCI) != 0 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705) {
		tp->pci_clock_ctrl |= CLOCK_CTRL_CLKRUN_OENABLE;
		if (tp->pci_chip_rev_id == CHIPREV_ID_5705_A0)
			tp->pci_clock_ctrl |= CLOCK_CTRL_FORCE_CLKRUN;
		tw32(TG3PCI_CLOCK_CTRL, tp->pci_clock_ctrl);
	}

	if (tp->phy_flags & TG3_PHYFLG_PHY_SERDES) {
		tp->mac_mode |= MAC_MODE_PORT_MODE_TBI;
		val = tp->mac_mode;
	} else if (tp->phy_flags & TG3_PHYFLG_MII_SERDES) {
		tp->mac_mode |= MAC_MODE_PORT_MODE_GMII;
		val = tp->mac_mode;
	} else
		val = 0;

	tw32_f(MAC_MODE, val);
	udelay(40);

	err = tg3_poll_fw(tp);
	if (err)
		return err;

	if (tg3_flag(tp, PCI_EXPRESS) &&
	    tp->pci_chip_rev_id != CHIPREV_ID_5750_A0 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5785 &&
	    !tg3_flag(tp, 57765_PLUS)) {
		val = tr32(0x7c00);

		tw32(0x7c00, val | (1 << 25));
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720) {
		val = tr32(TG3_CPMU_CLCK_ORIDE);
		tw32(TG3_CPMU_CLCK_ORIDE, val & ~CPMU_CLCK_ORIDE_MAC_ORIDE_EN);
	}

	if (tg3_flag(tp, CPMU_PRESENT)) {
		tw32(TG3_CPMU_D0_CLCK_POLICY, 0);
		val = tr32(TG3_CPMU_CLCK_ORIDE_EN);
		tw32(TG3_CPMU_CLCK_ORIDE_EN,
		     val | CPMU_CLCK_ORIDE_MAC_CLCK_ORIDE_EN);
	}

	return 0;
}

int tg3_halt(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int err;

	tg3_stop_fw(tp);

	tg3_write_sig_pre_reset(tp);

	tg3_abort_hw(tp);
	err = tg3_chip_reset(tp);

	__tg3_set_mac_addr(tp, 0);

	if (err)
		return err;

	return 0;
}

static int tg3_nvram_read_using_eeprom(struct tg3 *tp,
					u32 offset, u32 *val)
{	DBGP("%s\n", __func__);

	u32 tmp;
	int i;

	if (offset > EEPROM_ADDR_ADDR_MASK || (offset % 4) != 0)
		return -EINVAL;

	tmp = tr32(GRC_EEPROM_ADDR) & ~(EEPROM_ADDR_ADDR_MASK |
					EEPROM_ADDR_DEVID_MASK |
					EEPROM_ADDR_READ);
	tw32(GRC_EEPROM_ADDR,
	     tmp |
	     (0 << EEPROM_ADDR_DEVID_SHIFT) |
	     ((offset << EEPROM_ADDR_ADDR_SHIFT) &
	      EEPROM_ADDR_ADDR_MASK) |
	     EEPROM_ADDR_READ | EEPROM_ADDR_START);

	for (i = 0; i < 1000; i++) {
		tmp = tr32(GRC_EEPROM_ADDR);

		if (tmp & EEPROM_ADDR_COMPLETE)
			break;
		mdelay(1);
	}
	if (!(tmp & EEPROM_ADDR_COMPLETE))
		return -EBUSY;

	tmp = tr32(GRC_EEPROM_DATA);

	/*
	 * The data will always be opposite the native endian
	 * format.  Perform a blind byteswap to compensate.
	 */
	*val = bswap_32(tmp);

	return 0;
}

static u32 tg3_nvram_phys_addr(struct tg3 *tp, u32 addr)
{	DBGP("%s\n", __func__);

	if (tg3_flag(tp, NVRAM) &&
	    tg3_flag(tp, NVRAM_BUFFERED) &&
	    tg3_flag(tp, FLASH) &&
	    !tg3_flag(tp, NO_NVRAM_ADDR_TRANS) &&
	    (tp->nvram_jedecnum == JEDEC_ATMEL))

		addr = ((addr / tp->nvram_pagesize) <<
			ATMEL_AT45DB0X1B_PAGE_POS) +
		       (addr % tp->nvram_pagesize);

	return addr;
}

static void tg3_enable_nvram_access(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tg3_flag(tp, 5750_PLUS) && !tg3_flag(tp, PROTECTED_NVRAM)) {
		u32 nvaccess = tr32(NVRAM_ACCESS);

		tw32(NVRAM_ACCESS, nvaccess | ACCESS_ENABLE);
	}
}

static void tg3_disable_nvram_access(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tg3_flag(tp, 5750_PLUS) && !tg3_flag(tp, PROTECTED_NVRAM)) {
		u32 nvaccess = tr32(NVRAM_ACCESS);

		tw32(NVRAM_ACCESS, nvaccess & ~ACCESS_ENABLE);
	}
}

#define NVRAM_CMD_TIMEOUT 10000

static int tg3_nvram_exec_cmd(struct tg3 *tp, u32 nvram_cmd)
{	DBGP("%s\n", __func__);

	int i;

	tw32(NVRAM_CMD, nvram_cmd);
	for (i = 0; i < NVRAM_CMD_TIMEOUT; i++) {
		udelay(10);
		if (tr32(NVRAM_CMD) & NVRAM_CMD_DONE) {
			udelay(10);
			break;
		}
	}

	if (i == NVRAM_CMD_TIMEOUT)
		return -EBUSY;

	return 0;
}

/* NOTE: Data read in from NVRAM is byteswapped according to
 * the byteswapping settings for all other register accesses.
 * tg3 devices are BE devices, so on a BE machine, the data
 * returned will be exactly as it is seen in NVRAM.  On a LE
 * machine, the 32-bit value will be byteswapped.
 */
static int tg3_nvram_read(struct tg3 *tp, u32 offset, u32 *val)
{	DBGP("%s\n", __func__);

	int ret;

	if (!tg3_flag(tp, NVRAM))
		return tg3_nvram_read_using_eeprom(tp, offset, val);

	offset = tg3_nvram_phys_addr(tp, offset);

	if (offset > NVRAM_ADDR_MSK)
		return -EINVAL;

	ret = tg3_nvram_lock(tp);
	if (ret)
		return ret;

	tg3_enable_nvram_access(tp);

	tw32(NVRAM_ADDR, offset);
	ret = tg3_nvram_exec_cmd(tp, NVRAM_CMD_RD | NVRAM_CMD_GO |
		NVRAM_CMD_FIRST | NVRAM_CMD_LAST | NVRAM_CMD_DONE);

	if (ret == 0)
		*val = tr32(NVRAM_RDDATA);

	tg3_disable_nvram_access(tp);

	tg3_nvram_unlock(tp);

	return ret;
}

/* Ensures NVRAM data is in bytestream format. */
static int tg3_nvram_read_be32(struct tg3 *tp, u32 offset, u32 *val)
{	DBGP("%s\n", __func__);

	u32 v = 0;
	int res = tg3_nvram_read(tp, offset, &v);
	if (!res)
		*val = cpu_to_be32(v);
	return res;
}

int tg3_get_device_address(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	struct net_device *dev = tp->dev;
	u32 hi, lo, mac_offset;
	int addr_ok = 0;

	mac_offset = 0x7c;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704 ||
	    tg3_flag(tp, 5780_CLASS)) {
		if (tr32(TG3PCI_DUAL_MAC_CTRL) & DUAL_MAC_CTRL_ID)
			mac_offset = 0xcc;
		if (tg3_nvram_lock(tp))
			tw32_f(NVRAM_CMD, NVRAM_CMD_RESET);
		else
			tg3_nvram_unlock(tp);
	} else if (tg3_flag(tp, 5717_PLUS)) {
		if (PCI_FUNC(tp->pdev->busdevfn) & 1)
			mac_offset = 0xcc;
		if (PCI_FUNC(tp->pdev->busdevfn) > 1)
			mac_offset += 0x18c;
	} else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906)
		mac_offset = 0x10;

	/* First try to get it from MAC address mailbox. */
	tg3_read_mem(tp, NIC_SRAM_MAC_ADDR_HIGH_MBOX, &hi);
	if ((hi >> 16) == 0x484b) {
		dev->hw_addr[0] = (hi >>  8) & 0xff;
		dev->hw_addr[1] = (hi >>  0) & 0xff;

		tg3_read_mem(tp, NIC_SRAM_MAC_ADDR_LOW_MBOX, &lo);
		dev->hw_addr[2] = (lo >> 24) & 0xff;
		dev->hw_addr[3] = (lo >> 16) & 0xff;
		dev->hw_addr[4] = (lo >>  8) & 0xff;
		dev->hw_addr[5] = (lo >>  0) & 0xff;

		/* Some old bootcode may report a 0 MAC address in SRAM */
		addr_ok = is_valid_ether_addr(&dev->hw_addr[0]);
	}
	if (!addr_ok) {
		/* Next, try NVRAM. */
		if (!tg3_flag(tp, NO_NVRAM) &&
		    !tg3_nvram_read_be32(tp, mac_offset + 0, &hi) &&
		    !tg3_nvram_read_be32(tp, mac_offset + 4, &lo)) {
			memcpy(&dev->hw_addr[0], ((char *)&hi) + 2, 2);
			memcpy(&dev->hw_addr[2], (char *)&lo, sizeof(lo));
		}
		/* Finally just fetch it out of the MAC control regs. */
		else {
			hi = tr32(MAC_ADDR_0_HIGH);
			lo = tr32(MAC_ADDR_0_LOW);

			dev->hw_addr[5] = lo & 0xff;
			dev->hw_addr[4] = (lo >> 8) & 0xff;
			dev->hw_addr[3] = (lo >> 16) & 0xff;
			dev->hw_addr[2] = (lo >> 24) & 0xff;
			dev->hw_addr[1] = hi & 0xff;
			dev->hw_addr[0] = (hi >> 8) & 0xff;
		}
	}

	if (!is_valid_ether_addr(&dev->hw_addr[0])) {
		return -EINVAL;
	}

	return 0;
}

static void __tg3_set_rx_mode(struct net_device *dev)
{	DBGP("%s\n", __func__);

	struct tg3 *tp = netdev_priv(dev);
	u32 rx_mode;

	rx_mode = tp->rx_mode & ~(RX_MODE_PROMISC |
				  RX_MODE_KEEP_VLAN_TAG);

	rx_mode |= RX_MODE_KEEP_VLAN_TAG;

	/* Accept all multicast. */
	tw32(MAC_HASH_REG_0, 0xffffffff);
	tw32(MAC_HASH_REG_1, 0xffffffff);
	tw32(MAC_HASH_REG_2, 0xffffffff);
	tw32(MAC_HASH_REG_3, 0xffffffff);

	if (rx_mode != tp->rx_mode) {
		tp->rx_mode = rx_mode;
		tw32_f(MAC_RX_MODE, rx_mode);
		udelay(10);
	}
}

static void __tg3_set_coalesce(struct tg3 *tp)
{	DBGP("%s\n", __func__);


	tw32(HOSTCC_RXCOL_TICKS, 0);
	tw32(HOSTCC_TXCOL_TICKS, LOW_TXCOL_TICKS);
	tw32(HOSTCC_RXMAX_FRAMES, 1);
	/* FIXME: mix between TXMAX and RXMAX taken from legacy driver */
	tw32(HOSTCC_TXMAX_FRAMES, LOW_RXMAX_FRAMES);
	tw32(HOSTCC_RXCOAL_MAXF_INT, 1);
	tw32(HOSTCC_TXCOAL_MAXF_INT, 0);

	if (!tg3_flag(tp, 5705_PLUS)) {
		u32 val = DEFAULT_STAT_COAL_TICKS;

		tw32(HOSTCC_RXCOAL_TICK_INT, DEFAULT_RXCOAL_TICK_INT);
		tw32(HOSTCC_TXCOAL_TICK_INT, DEFAULT_TXCOAL_TICK_INT);

		if (!netdev_link_ok(tp->dev))
			val = 0;

		tw32(HOSTCC_STAT_COAL_TICKS, val);
	}
}

static void tg3_set_bdinfo(struct tg3 *tp, u32 bdinfo_addr,
			   dma_addr_t mapping, u32 maxlen_flags,
			   u32 nic_addr)
{	DBGP("%s\n", __func__);

	tg3_write_mem(tp,
		      (bdinfo_addr + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_HIGH),
		      ((u64) mapping >> 32));
	tg3_write_mem(tp,
		      (bdinfo_addr + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_LOW),
		      ((u64) mapping & 0xffffffff));
	tg3_write_mem(tp,
		      (bdinfo_addr + TG3_BDINFO_MAXLEN_FLAGS),
		       maxlen_flags);

	if (!tg3_flag(tp, 5705_PLUS))
		tg3_write_mem(tp,
			      (bdinfo_addr + TG3_BDINFO_NIC_ADDR),
			      nic_addr);
}

static void tg3_rings_reset(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int i;
	u32 txrcb, rxrcb, limit;

	/* Disable all transmit rings but the first. */
	if (!tg3_flag(tp, 5705_PLUS))
		limit = NIC_SRAM_SEND_RCB + TG3_BDINFO_SIZE * 16;
	else if (tg3_flag(tp, 5717_PLUS))
		limit = NIC_SRAM_SEND_RCB + TG3_BDINFO_SIZE * 4;
	else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57765)
		limit = NIC_SRAM_SEND_RCB + TG3_BDINFO_SIZE * 2;
	else
		limit = NIC_SRAM_SEND_RCB + TG3_BDINFO_SIZE;

	for (txrcb = NIC_SRAM_SEND_RCB + TG3_BDINFO_SIZE;
	     txrcb < limit; txrcb += TG3_BDINFO_SIZE)
		tg3_write_mem(tp, txrcb + TG3_BDINFO_MAXLEN_FLAGS,
			      BDINFO_FLAGS_DISABLED);


	/* Disable all receive return rings but the first. */
	if (tg3_flag(tp, 5717_PLUS))
		limit = NIC_SRAM_RCV_RET_RCB + TG3_BDINFO_SIZE * 17;
	else if (!tg3_flag(tp, 5705_PLUS))
		limit = NIC_SRAM_RCV_RET_RCB + TG3_BDINFO_SIZE * 16;
	else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5755 ||
		 GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57765)
		limit = NIC_SRAM_RCV_RET_RCB + TG3_BDINFO_SIZE * 4;
	else
		limit = NIC_SRAM_RCV_RET_RCB + TG3_BDINFO_SIZE;

	for (rxrcb = NIC_SRAM_RCV_RET_RCB + TG3_BDINFO_SIZE;
	     rxrcb < limit; rxrcb += TG3_BDINFO_SIZE)
		tg3_write_mem(tp, rxrcb + TG3_BDINFO_MAXLEN_FLAGS,
			      BDINFO_FLAGS_DISABLED);

	/* Disable interrupts */
	tw32_mailbox_f(tp->int_mbox, 1);

	tp->tx_prod = 0;
	tp->tx_cons = 0;
	tw32_mailbox(tp->prodmbox, 0);
	tw32_rx_mbox(tp->consmbox, 0);

	/* Make sure the NIC-based send BD rings are disabled. */
	if (!tg3_flag(tp, 5705_PLUS)) {
		u32 mbox = MAILBOX_SNDNIC_PROD_IDX_0 + TG3_64BIT_REG_LOW;
		for (i = 0; i < 16; i++)
			tw32_tx_mbox(mbox + i * 8, 0);
	}

	txrcb = NIC_SRAM_SEND_RCB;
	rxrcb = NIC_SRAM_RCV_RET_RCB;

	/* Clear status block in ram. */
	memset(tp->hw_status, 0, TG3_HW_STATUS_SIZE);

	/* Set status block DMA address */
	tw32(HOSTCC_STATUS_BLK_HOST_ADDR + TG3_64BIT_REG_HIGH,
	     ((u64) tp->status_mapping >> 32));
	tw32(HOSTCC_STATUS_BLK_HOST_ADDR + TG3_64BIT_REG_LOW,
	     ((u64) tp->status_mapping & 0xffffffff));

	if (tp->tx_ring) {
		tg3_set_bdinfo(tp, txrcb, tp->tx_desc_mapping,
			       (TG3_TX_RING_SIZE <<
				BDINFO_FLAGS_MAXLEN_SHIFT),
			       NIC_SRAM_TX_BUFFER_DESC);
		txrcb += TG3_BDINFO_SIZE;
	}

	/* FIXME: will TG3_RX_RET_MAX_SIZE_5705 work on all cards? */
	if (tp->rx_rcb) {
		tg3_set_bdinfo(tp, rxrcb, tp->rx_rcb_mapping,
			        TG3_RX_RET_MAX_SIZE_5705 <<
				BDINFO_FLAGS_MAXLEN_SHIFT, 0);
		rxrcb += TG3_BDINFO_SIZE;
	}
}

static void tg3_setup_rxbd_thresholds(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 val, bdcache_maxcnt;

	if (!tg3_flag(tp, 5750_PLUS) ||
	    tg3_flag(tp, 5780_CLASS) ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5752)
		bdcache_maxcnt = TG3_SRAM_RX_STD_BDCACHE_SIZE_5700;
	else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5755 ||
		 GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787)
		bdcache_maxcnt = TG3_SRAM_RX_STD_BDCACHE_SIZE_5755;
	else
		bdcache_maxcnt = TG3_SRAM_RX_STD_BDCACHE_SIZE_5906;


	/* NOTE: legacy driver uses RX_PENDING / 8, we only use 4 descriptors
	 * for now, use / 4 so the result is > 0
	 */
	val = TG3_DEF_RX_RING_PENDING / 4;
	tw32(RCVBDI_STD_THRESH, val);

	if (tg3_flag(tp, 57765_PLUS))
		tw32(STD_REPLENISH_LWM, bdcache_maxcnt);
}

static int tg3_reset_hw(struct tg3 *tp, int reset_phy)
{	DBGP("%s\n", __func__);

	u32 val, rdmac_mode;
	int i, err, limit;
	struct tg3_rx_prodring_set *tpr = &tp->prodring;

	tg3_stop_fw(tp);

	tg3_write_sig_pre_reset(tp);

	if (tg3_flag(tp, INIT_COMPLETE))
		tg3_abort_hw(tp);

	if (reset_phy)
		tg3_phy_reset(tp);

	err = tg3_chip_reset(tp);
	if (err)
		return err;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57780) {
		val = tr32(PCIE_PWR_MGMT_THRESH) & ~PCIE_PWR_MGMT_L1_THRESH_MSK;
		val |= PCIE_PWR_MGMT_EXT_ASPM_TMR_EN |
		       PCIE_PWR_MGMT_L1_THRESH_4MS;
		tw32(PCIE_PWR_MGMT_THRESH, val);

		val = tr32(TG3_PCIE_EIDLE_DELAY) & ~TG3_PCIE_EIDLE_DELAY_MASK;
		tw32(TG3_PCIE_EIDLE_DELAY, val | TG3_PCIE_EIDLE_DELAY_13_CLKS);

		tw32(TG3_CORR_ERR_STAT, TG3_CORR_ERR_STAT_CLEAR);

		val = tr32(TG3_PCIE_LNKCTL) & ~TG3_PCIE_LNKCTL_L1_PLL_PD_EN;
		tw32(TG3_PCIE_LNKCTL, val | TG3_PCIE_LNKCTL_L1_PLL_PD_DIS);
	}

	if (tg3_flag(tp, L1PLLPD_EN)) {
		u32 grc_mode = tr32(GRC_MODE);

		/* Access the lower 1K of PL PCIE block registers. */
		val = grc_mode & ~GRC_MODE_PCIE_PORT_MASK;
		tw32(GRC_MODE, val | GRC_MODE_PCIE_PL_SEL);

		val = tr32(TG3_PCIE_TLDLPL_PORT + TG3_PCIE_PL_LO_PHYCTL1);
		tw32(TG3_PCIE_TLDLPL_PORT + TG3_PCIE_PL_LO_PHYCTL1,
		     val | TG3_PCIE_PL_LO_PHYCTL1_L1PLLPD_EN);

		tw32(GRC_MODE, grc_mode);
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57765) {
		if (tp->pci_chip_rev_id == CHIPREV_ID_57765_A0) {
			u32 grc_mode = tr32(GRC_MODE);

			/* Access the lower 1K of PL PCIE block registers. */
			val = grc_mode & ~GRC_MODE_PCIE_PORT_MASK;
			tw32(GRC_MODE, val | GRC_MODE_PCIE_PL_SEL);

			val = tr32(TG3_PCIE_TLDLPL_PORT +
				   TG3_PCIE_PL_LO_PHYCTL5);
			tw32(TG3_PCIE_TLDLPL_PORT + TG3_PCIE_PL_LO_PHYCTL5,
			     val | TG3_PCIE_PL_LO_PHYCTL5_DIS_L2CLKREQ);

			tw32(GRC_MODE, grc_mode);
		}

		if (GET_CHIP_REV(tp->pci_chip_rev_id) != CHIPREV_57765_AX) {
			u32 grc_mode = tr32(GRC_MODE);

			/* Access the lower 1K of DL PCIE block registers. */
			val = grc_mode & ~GRC_MODE_PCIE_PORT_MASK;
			tw32(GRC_MODE, val | GRC_MODE_PCIE_DL_SEL);

			val = tr32(TG3_PCIE_TLDLPL_PORT +
				   TG3_PCIE_DL_LO_FTSMAX);
			val &= ~TG3_PCIE_DL_LO_FTSMAX_MSK;
			tw32(TG3_PCIE_TLDLPL_PORT + TG3_PCIE_DL_LO_FTSMAX,
			     val | TG3_PCIE_DL_LO_FTSMAX_VAL);

			tw32(GRC_MODE, grc_mode);
		}

		val = tr32(TG3_CPMU_LSPD_10MB_CLK);
		val &= ~CPMU_LSPD_10MB_MACCLK_MASK;
		val |= CPMU_LSPD_10MB_MACCLK_6_25;
		tw32(TG3_CPMU_LSPD_10MB_CLK, val);
	}

	/* This works around an issue with Athlon chipsets on
	 * B3 tigon3 silicon.  This bit has no effect on any
	 * other revision.  But do not set this on PCI Express
	 * chips and don't even touch the clocks if the CPMU is present.
	 */
	if (!tg3_flag(tp, CPMU_PRESENT)) {
		if (!tg3_flag(tp, PCI_EXPRESS))
			tp->pci_clock_ctrl |= CLOCK_CTRL_DELAY_PCI_GRANT;
		tw32_f(TG3PCI_CLOCK_CTRL, tp->pci_clock_ctrl);
	}

	if (tp->pci_chip_rev_id == CHIPREV_ID_5704_A0 &&
	    tg3_flag(tp, PCIX_MODE)) {
		val = tr32(TG3PCI_PCISTATE);
		val |= PCISTATE_RETRY_SAME_DMA;
		tw32(TG3PCI_PCISTATE, val);
	}

	if (GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5704_BX) {
		/* Enable some hw fixes.  */
		val = tr32(TG3PCI_MSI_DATA);
		val |= (1 << 26) | (1 << 28) | (1 << 29);
		tw32(TG3PCI_MSI_DATA, val);
	}

	/* Descriptor ring init may make accesses to the
	 * NIC SRAM area to setup the TX descriptors, so we
	 * can only do this after the hardware has been
	 * successfully reset.
	 */
	err = tg3_init_rings(tp);
	if (err)
		return err;

	if (tg3_flag(tp, 57765_PLUS)) {
		val = tr32(TG3PCI_DMA_RW_CTRL) &
		      ~DMA_RWCTRL_DIS_CACHE_ALIGNMENT;
		if (tp->pci_chip_rev_id == CHIPREV_ID_57765_A0)
			val &= ~DMA_RWCTRL_CRDRDR_RDMA_MRRS_MSK;
		if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_57765 &&
		    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5717)
			val |= DMA_RWCTRL_TAGGED_STAT_WA;
		tw32(TG3PCI_DMA_RW_CTRL, val | tp->dma_rwctrl);
	} else if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5784 &&
		   GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5761) {
		/* This value is determined during the probe time DMA
		 * engine test, tg3_test_dma.
		 */
		tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);
	}

	tp->grc_mode &= ~(GRC_MODE_HOST_SENDBDS |
			  GRC_MODE_4X_NIC_SEND_RINGS |
			  GRC_MODE_NO_TX_PHDR_CSUM |
			  GRC_MODE_NO_RX_PHDR_CSUM);
	tp->grc_mode |= GRC_MODE_HOST_SENDBDS;
	tp->grc_mode |= GRC_MODE_NO_RX_PHDR_CSUM;

	/* Pseudo-header checksum is done by hardware logic and not
	 * the offload processers, so make the chip do the pseudo-
	 * header checksums on receive.  For transmit it is more
	 * convenient to do the pseudo-header checksum in software
	 * as Linux does that on transmit for us in all cases.
	 */
	tp->grc_mode |= GRC_MODE_NO_TX_PHDR_CSUM;

	tw32(GRC_MODE,
	     tp->grc_mode |
	     (GRC_MODE_IRQ_ON_MAC_ATTN | GRC_MODE_HOST_STACKUP));

	/* Setup the timer prescalar register.  Clock is always 66Mhz. */
	val = tr32(GRC_MISC_CFG);
	val &= ~0xff;
	val |= (65 << GRC_MISC_CFG_PRESCALAR_SHIFT);
	tw32(GRC_MISC_CFG, val);

	/* Initialize MBUF/DESC pool. */
	if (tg3_flag(tp, 5750_PLUS)) {
		/* Do nothing.  */
	} else if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705) {
		tw32(BUFMGR_MB_POOL_ADDR, NIC_SRAM_MBUF_POOL_BASE);
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)
			tw32(BUFMGR_MB_POOL_SIZE, NIC_SRAM_MBUF_POOL_SIZE64);
		else
			tw32(BUFMGR_MB_POOL_SIZE, NIC_SRAM_MBUF_POOL_SIZE96);
		tw32(BUFMGR_DMA_DESC_POOL_ADDR, NIC_SRAM_DMA_DESC_POOL_BASE);
		tw32(BUFMGR_DMA_DESC_POOL_SIZE, NIC_SRAM_DMA_DESC_POOL_SIZE);
	}

	tw32(BUFMGR_MB_RDMA_LOW_WATER,
	     tp->bufmgr_config.mbuf_read_dma_low_water);
	tw32(BUFMGR_MB_MACRX_LOW_WATER,
	     tp->bufmgr_config.mbuf_mac_rx_low_water);
	tw32(BUFMGR_MB_HIGH_WATER,
	     tp->bufmgr_config.mbuf_high_water);

	tw32(BUFMGR_DMA_LOW_WATER,
	     tp->bufmgr_config.dma_low_water);
	tw32(BUFMGR_DMA_HIGH_WATER,
	     tp->bufmgr_config.dma_high_water);

	val = BUFMGR_MODE_ENABLE | BUFMGR_MODE_ATTN_ENABLE;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5719)
		val |= BUFMGR_MODE_NO_TX_UNDERRUN;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5717 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5719_A0 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5720_A0)
		val |= BUFMGR_MODE_MBLOW_ATTN_ENAB;
	tw32(BUFMGR_MODE, val);
	for (i = 0; i < 2000; i++) {
		if (tr32(BUFMGR_MODE) & BUFMGR_MODE_ENABLE)
			break;
		udelay(10);
	}
	if (i >= 2000) {
		DBGC(tp->dev, "%s cannot enable BUFMGR\n", __func__);
		return -ENODEV;
	}

	if (tp->pci_chip_rev_id == CHIPREV_ID_5906_A1)
		tw32(ISO_PKT_TX, (tr32(ISO_PKT_TX) & ~0x3) | 0x2);

	tg3_setup_rxbd_thresholds(tp);

	/* Initialize TG3_BDINFO's at:
	 *  RCVDBDI_STD_BD:	standard eth size rx ring
	 *  RCVDBDI_JUMBO_BD:	jumbo frame rx ring
	 *  RCVDBDI_MINI_BD:	small frame rx ring (??? does not work)
	 *
	 * like so:
	 *  TG3_BDINFO_HOST_ADDR:	high/low parts of DMA address of ring
	 *  TG3_BDINFO_MAXLEN_FLAGS:	(rx max buffer size << 16) |
	 *                              ring attribute flags
	 *  TG3_BDINFO_NIC_ADDR:	location of descriptors in nic SRAM
	 *
	 * Standard receive ring @ NIC_SRAM_RX_BUFFER_DESC, 512 entries.
	 * Jumbo receive ring @ NIC_SRAM_RX_JUMBO_BUFFER_DESC, 256 entries.
	 *
	 * The size of each ring is fixed in the firmware, but the location is
	 * configurable.
	 */
	tw32(RCVDBDI_STD_BD + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_HIGH,
	     ((u64) tpr->rx_std_mapping >> 32));
	tw32(RCVDBDI_STD_BD + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_LOW,
	     ((u64) tpr->rx_std_mapping & 0xffffffff));
	if (!tg3_flag(tp, 5717_PLUS))
		tw32(RCVDBDI_STD_BD + TG3_BDINFO_NIC_ADDR,
		     NIC_SRAM_RX_BUFFER_DESC);

	/* Disable the mini ring */
	if (!tg3_flag(tp, 5705_PLUS))
		tw32(RCVDBDI_MINI_BD + TG3_BDINFO_MAXLEN_FLAGS,
		     BDINFO_FLAGS_DISABLED);

	val = TG3_RX_STD_MAX_SIZE_5700 << BDINFO_FLAGS_MAXLEN_SHIFT;

	if (tg3_flag(tp, 57765_PLUS))
		val |= (RX_STD_MAX_SIZE << 2);

	tw32(RCVDBDI_STD_BD + TG3_BDINFO_MAXLEN_FLAGS, val);

	tpr->rx_std_prod_idx = 0;

	/* std prod index is updated by tg3_refill_prod_ring() */
	tw32_rx_mbox(TG3_RX_STD_PROD_IDX_REG, 0);
	tw32_rx_mbox(TG3_RX_JMB_PROD_IDX_REG, 0);

	tg3_rings_reset(tp);

	__tg3_set_mac_addr(tp,0);

#define	TG3_MAX_MTU	1522
	/* MTU + ethernet header + FCS + optional VLAN tag */
	tw32(MAC_RX_MTU_SIZE, TG3_MAX_MTU);

	/* The slot time is changed by tg3_setup_phy if we
	 * run at gigabit with half duplex.
	 */
	val = (2 << TX_LENGTHS_IPG_CRS_SHIFT) |
	      (6 << TX_LENGTHS_IPG_SHIFT) |
	      (32 << TX_LENGTHS_SLOT_TIME_SHIFT);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720)
		val |= tr32(MAC_TX_LENGTHS) &
		       (TX_LENGTHS_JMB_FRM_LEN_MSK |
			TX_LENGTHS_CNT_DWN_VAL_MSK);

	tw32(MAC_TX_LENGTHS, val);

	/* Receive rules. */
	tw32(MAC_RCV_RULE_CFG, RCV_RULE_CFG_DEFAULT_CLASS);
	tw32(RCVLPC_CONFIG, 0x0181);

	/* Calculate RDMAC_MODE setting early, we need it to determine
	 * the RCVLPC_STATE_ENABLE mask.
	 */
	rdmac_mode = (RDMAC_MODE_ENABLE | RDMAC_MODE_TGTABORT_ENAB |
		      RDMAC_MODE_MSTABORT_ENAB | RDMAC_MODE_PARITYERR_ENAB |
		      RDMAC_MODE_ADDROFLOW_ENAB | RDMAC_MODE_FIFOOFLOW_ENAB |
		      RDMAC_MODE_FIFOURUN_ENAB | RDMAC_MODE_FIFOOREAD_ENAB |
		      RDMAC_MODE_LNGREAD_ENAB);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5717)
		rdmac_mode |= RDMAC_MODE_MULT_DMA_RD_DIS;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5785 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57780)
		rdmac_mode |= RDMAC_MODE_BD_SBD_CRPT_ENAB |
			      RDMAC_MODE_MBUF_RBD_CRPT_ENAB |
			      RDMAC_MODE_MBUF_SBD_CRPT_ENAB;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 &&
	    tp->pci_chip_rev_id != CHIPREV_ID_5705_A0) {
		if (tg3_flag(tp, TSO_CAPABLE) &&
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705) {
			rdmac_mode |= RDMAC_MODE_FIFO_SIZE_128;
		} else if (!(tr32(TG3PCI_PCISTATE) & PCISTATE_BUS_SPEED_HIGH) &&
			   !tg3_flag(tp, IS_5788)) {
			rdmac_mode |= RDMAC_MODE_FIFO_LONG_BURST;
		}
	}

	if (tg3_flag(tp, PCI_EXPRESS))
		rdmac_mode |= RDMAC_MODE_FIFO_LONG_BURST;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720)
		rdmac_mode |= tr32(RDMAC_MODE) & RDMAC_MODE_H2BNC_VLAN_DET;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5761 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5785 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57780 ||
	    tg3_flag(tp, 57765_PLUS)) {
		val = tr32(TG3_RDMA_RSRVCTRL_REG);
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5719 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720) {
			val &= ~(TG3_RDMA_RSRVCTRL_TXMRGN_MASK |
				 TG3_RDMA_RSRVCTRL_FIFO_LWM_MASK |
				 TG3_RDMA_RSRVCTRL_FIFO_HWM_MASK);
			val |= TG3_RDMA_RSRVCTRL_TXMRGN_320B |
			       TG3_RDMA_RSRVCTRL_FIFO_LWM_1_5K |
			       TG3_RDMA_RSRVCTRL_FIFO_HWM_1_5K;
		}
		tw32(TG3_RDMA_RSRVCTRL_REG,
		     val | TG3_RDMA_RSRVCTRL_FIFO_OFLW_FIX);
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5719 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720) {
		val = tr32(TG3_LSO_RD_DMA_CRPTEN_CTRL);
		tw32(TG3_LSO_RD_DMA_CRPTEN_CTRL, val |
		     TG3_LSO_RD_DMA_CRPTEN_CTRL_BLEN_BD_4K |
		     TG3_LSO_RD_DMA_CRPTEN_CTRL_BLEN_LSO_4K);
	}

	/* Receive/send statistics. */
	if (tg3_flag(tp, 5750_PLUS)) {
		val = tr32(RCVLPC_STATS_ENABLE);
		val &= ~RCVLPC_STATSENAB_DACK_FIX;
		tw32(RCVLPC_STATS_ENABLE, val);
	} else if ((rdmac_mode & RDMAC_MODE_FIFO_SIZE_128) &&
		   tg3_flag(tp, TSO_CAPABLE)) {
		val = tr32(RCVLPC_STATS_ENABLE);
		val &= ~RCVLPC_STATSENAB_LNGBRST_RFIX;
		tw32(RCVLPC_STATS_ENABLE, val);
	} else {
		tw32(RCVLPC_STATS_ENABLE, 0xffffff);
	}
	tw32(RCVLPC_STATSCTRL, RCVLPC_STATSCTRL_ENABLE);
	tw32(SNDDATAI_STATSENAB, 0xffffff);
	tw32(SNDDATAI_STATSCTRL,
	     (SNDDATAI_SCTRL_ENABLE |
	      SNDDATAI_SCTRL_FASTUPD));

	/* Setup host coalescing engine. */
	tw32(HOSTCC_MODE, 0);
	for (i = 0; i < 2000; i++) {
		if (!(tr32(HOSTCC_MODE) & HOSTCC_MODE_ENABLE))
			break;
		udelay(10);
	}

	__tg3_set_coalesce(tp);

	if (!tg3_flag(tp, 5705_PLUS)) {
		/* Status/statistics block address.  See tg3_timer,
		 * the tg3_periodic_fetch_stats call there, and
		 * tg3_get_stats to see how this works for 5705/5750 chips.
		 * NOTE: stats block removed for iPXE
		 */
		tw32(HOSTCC_STATUS_BLK_NIC_ADDR, NIC_SRAM_STATUS_BLK);

		/* Clear statistics and status block memory areas */
		for (i = NIC_SRAM_STATS_BLK;
		     i < NIC_SRAM_STATUS_BLK + TG3_HW_STATUS_SIZE;
		     i += sizeof(u32)) {
			tg3_write_mem(tp, i, 0);
			udelay(40);
		}
	}

	tw32(HOSTCC_MODE, HOSTCC_MODE_ENABLE | tp->coalesce_mode);

	tw32(RCVCC_MODE, RCVCC_MODE_ENABLE | RCVCC_MODE_ATTN_ENABLE);
	tw32(RCVLPC_MODE, RCVLPC_MODE_ENABLE);
	if (!tg3_flag(tp, 5705_PLUS))
		tw32(RCVLSC_MODE, RCVLSC_MODE_ENABLE | RCVLSC_MODE_ATTN_ENABLE);

	if (tp->phy_flags & TG3_PHYFLG_MII_SERDES) {
		tp->phy_flags &= ~TG3_PHYFLG_PARALLEL_DETECT;
		/* reset to prevent losing 1st rx packet intermittently */
		tw32_f(MAC_RX_MODE, RX_MODE_RESET);
		udelay(10);
	}

	if (tg3_flag(tp, ENABLE_APE))
		tp->mac_mode = MAC_MODE_APE_TX_EN | MAC_MODE_APE_RX_EN;
	else
		tp->mac_mode = 0;
	tp->mac_mode |= MAC_MODE_TXSTAT_ENABLE | MAC_MODE_RXSTAT_ENABLE |
		MAC_MODE_TDE_ENABLE | MAC_MODE_RDE_ENABLE | MAC_MODE_FHDE_ENABLE;
	if (!tg3_flag(tp, 5705_PLUS) &&
	    !(tp->phy_flags & TG3_PHYFLG_PHY_SERDES) &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700)
		tp->mac_mode |= MAC_MODE_LINK_POLARITY;
	tw32_f(MAC_MODE, tp->mac_mode | MAC_MODE_RXSTAT_CLEAR | MAC_MODE_TXSTAT_CLEAR);
	udelay(40);

	/* tp->grc_local_ctrl is partially set up during tg3_get_invariants().
	 * If TG3_FLAG_IS_NIC is zero, we should read the
	 * register to preserve the GPIO settings for LOMs. The GPIOs,
	 * whether used as inputs or outputs, are set by boot code after
	 * reset.
	 */
	if (!tg3_flag(tp, IS_NIC)) {
		u32 gpio_mask;

		gpio_mask = GRC_LCLCTRL_GPIO_OE0 | GRC_LCLCTRL_GPIO_OE1 |
			    GRC_LCLCTRL_GPIO_OE2 | GRC_LCLCTRL_GPIO_OUTPUT0 |
			    GRC_LCLCTRL_GPIO_OUTPUT1 | GRC_LCLCTRL_GPIO_OUTPUT2;

		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5752)
			gpio_mask |= GRC_LCLCTRL_GPIO_OE3 |
				     GRC_LCLCTRL_GPIO_OUTPUT3;

		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5755)
			gpio_mask |= GRC_LCLCTRL_GPIO_UART_SEL;

		tp->grc_local_ctrl &= ~gpio_mask;
		tp->grc_local_ctrl |= tr32(GRC_LOCAL_CTRL) & gpio_mask;

		/* GPIO1 must be driven high for eeprom write protect */
		if (tg3_flag(tp, EEPROM_WRITE_PROT))
			tp->grc_local_ctrl |= (GRC_LCLCTRL_GPIO_OE1 |
					       GRC_LCLCTRL_GPIO_OUTPUT1);
	}
	tw32_f(GRC_LOCAL_CTRL, tp->grc_local_ctrl);
	udelay(100);

	if (!tg3_flag(tp, 5705_PLUS)) {
		tw32_f(DMAC_MODE, DMAC_MODE_ENABLE);
		udelay(40);
	}

	val = (WDMAC_MODE_ENABLE | WDMAC_MODE_TGTABORT_ENAB |
	       WDMAC_MODE_MSTABORT_ENAB | WDMAC_MODE_PARITYERR_ENAB |
	       WDMAC_MODE_ADDROFLOW_ENAB | WDMAC_MODE_FIFOOFLOW_ENAB |
	       WDMAC_MODE_FIFOURUN_ENAB | WDMAC_MODE_FIFOOREAD_ENAB |
	       WDMAC_MODE_LNGREAD_ENAB);

	/* Enable host coalescing bug fix */
	if (tg3_flag(tp, 5755_PLUS))
		val |= WDMAC_MODE_STATUS_TAG_FIX;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5785)
		val |= WDMAC_MODE_BURST_ALL_DATA;

	tw32_f(WDMAC_MODE, val);
	udelay(40);

	if (tg3_flag(tp, PCIX_MODE)) {
		u16 pcix_cmd;

		pci_read_config_word(tp->pdev, tp->pcix_cap + PCI_X_CMD,
				     &pcix_cmd);
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) {
			pcix_cmd &= ~PCI_X_CMD_MAX_READ;
			pcix_cmd |= PCI_X_CMD_READ_2K;
		} else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) {
			pcix_cmd &= ~(PCI_X_CMD_MAX_SPLIT | PCI_X_CMD_MAX_READ);
			pcix_cmd |= PCI_X_CMD_READ_2K;
		}
		pci_write_config_word(tp->pdev, tp->pcix_cap + PCI_X_CMD,
				      pcix_cmd);
	}

	tw32_f(RDMAC_MODE, rdmac_mode);
	udelay(40);

	tw32(RCVDCC_MODE, RCVDCC_MODE_ENABLE | RCVDCC_MODE_ATTN_ENABLE);
	if (!tg3_flag(tp, 5705_PLUS))
		tw32(MBFREE_MODE, MBFREE_MODE_ENABLE);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5761)
		tw32(SNDDATAC_MODE,
		     SNDDATAC_MODE_ENABLE | SNDDATAC_MODE_CDELAY);
	else
		tw32(SNDDATAC_MODE, SNDDATAC_MODE_ENABLE);

	tw32(SNDBDC_MODE, SNDBDC_MODE_ENABLE | SNDBDC_MODE_ATTN_ENABLE);
	tw32(RCVBDI_MODE, RCVBDI_MODE_ENABLE | RCVBDI_MODE_RCB_ATTN_ENAB);
	val = RCVDBDI_MODE_ENABLE | RCVDBDI_MODE_INV_RING_SZ;
	if (tg3_flag(tp, LRG_PROD_RING_CAP))
		val |= RCVDBDI_MODE_LRG_RING_SZ;
	tw32(RCVDBDI_MODE, val);
	tw32(SNDDATAI_MODE, SNDDATAI_MODE_ENABLE);

	val = SNDBDI_MODE_ENABLE | SNDBDI_MODE_ATTN_ENABLE;
	if (tg3_flag(tp, ENABLE_TSS))
		val |= SNDBDI_MODE_MULTI_TXQ_EN;
	tw32(SNDBDI_MODE, val);
	tw32(SNDBDS_MODE, SNDBDS_MODE_ENABLE | SNDBDS_MODE_ATTN_ENABLE);


	/* FIXME: 5701 firmware fix? */
#if 0
	if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0) {
		err = tg3_load_5701_a0_firmware_fix(tp);
		if (err)
			return err;
	}
#endif

	tp->tx_mode = TX_MODE_ENABLE;

	if (tg3_flag(tp, 5755_PLUS) ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906)
		tp->tx_mode |= TX_MODE_MBUF_LOCKUP_FIX;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720) {
		val = TX_MODE_JMB_FRM_LEN | TX_MODE_CNT_DN_MODE;
		tp->tx_mode &= ~val;
		tp->tx_mode |= tr32(MAC_TX_MODE) & val;
	}

	tw32_f(MAC_TX_MODE, tp->tx_mode);
	udelay(100);

	tp->rx_mode = RX_MODE_ENABLE;

	tw32_f(MAC_RX_MODE, tp->rx_mode);
	udelay(10);

	tw32(MAC_LED_CTRL, tp->led_ctrl);

	tw32(MAC_MI_STAT, MAC_MI_STAT_LNKSTAT_ATTN_ENAB);
	if (tp->phy_flags & TG3_PHYFLG_PHY_SERDES) {
		tw32_f(MAC_RX_MODE, RX_MODE_RESET);
		udelay(10);
	}
	tw32_f(MAC_RX_MODE, tp->rx_mode);
	udelay(10);

	if (tp->phy_flags & TG3_PHYFLG_PHY_SERDES) {
		if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) &&
			!(tp->phy_flags & TG3_PHYFLG_SERDES_PREEMPHASIS)) {
			/* Set drive transmission level to 1.2V  */
			/* only if the signal pre-emphasis bit is not set  */
			val = tr32(MAC_SERDES_CFG);
			val &= 0xfffff000;
			val |= 0x880;
			tw32(MAC_SERDES_CFG, val);
		}
		if (tp->pci_chip_rev_id == CHIPREV_ID_5703_A1)
			tw32(MAC_SERDES_CFG, 0x616000);
	}

	/* Prevent chip from dropping frames when flow control
	 * is enabled.
	 */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57765)
		val = 1;
	else
		val = 2;
	tw32_f(MAC_LOW_WMARK_MAX_RX_FRAME, val);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704 &&
	    (tp->phy_flags & TG3_PHYFLG_PHY_SERDES)) {
		/* Use hardware link auto-negotiation */
		tg3_flag_set(tp, HW_AUTONEG);
	}

	if ((tp->phy_flags & TG3_PHYFLG_MII_SERDES) &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5714) {
		u32 tmp;

		tmp = tr32(SERDES_RX_CTRL);
		tw32(SERDES_RX_CTRL, tmp | SERDES_RX_SIG_DETECT);
		tp->grc_local_ctrl &= ~GRC_LCLCTRL_USE_EXT_SIG_DETECT;
		tp->grc_local_ctrl |= GRC_LCLCTRL_USE_SIG_DETECT;
		tw32(GRC_LOCAL_CTRL, tp->grc_local_ctrl);
	}

	err = tg3_setup_phy(tp, 0);
	if (err)
		return err;

	if (!(tp->phy_flags & TG3_PHYFLG_PHY_SERDES) &&
	    !(tp->phy_flags & TG3_PHYFLG_IS_FET)) {
		u32 tmp;

		/* Clear CRC stats. */
		if (!tg3_readphy(tp, MII_TG3_TEST1, &tmp)) {
			tg3_writephy(tp, MII_TG3_TEST1,
				     tmp | MII_TG3_TEST1_CRC_EN);
			tg3_readphy(tp, MII_TG3_RXR_COUNTERS, &tmp);
		}
	}

	__tg3_set_rx_mode(tp->dev);

	/* Initialize receive rules. */
	tw32(MAC_RCV_RULE_0,  0xc2000000 & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_VALUE_0, 0xffffffff & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_RULE_1,  0x86000004 & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_VALUE_1, 0xffffffff & RCV_RULE_DISABLE_MASK);

	if (tg3_flag(tp, 5705_PLUS) && !tg3_flag(tp, 5780_CLASS))
		limit = 8;
	else
		limit = 16;
	if (tg3_flag(tp, ENABLE_ASF))
		limit -= 4;
	switch (limit) {
	case 16:
		tw32(MAC_RCV_RULE_15,  0); tw32(MAC_RCV_VALUE_15,  0);
	case 15:
		tw32(MAC_RCV_RULE_14,  0); tw32(MAC_RCV_VALUE_14,  0);
	case 14:
		tw32(MAC_RCV_RULE_13,  0); tw32(MAC_RCV_VALUE_13,  0);
	case 13:
		tw32(MAC_RCV_RULE_12,  0); tw32(MAC_RCV_VALUE_12,  0);
	case 12:
		tw32(MAC_RCV_RULE_11,  0); tw32(MAC_RCV_VALUE_11,  0);
	case 11:
		tw32(MAC_RCV_RULE_10,  0); tw32(MAC_RCV_VALUE_10,  0);
	case 10:
		tw32(MAC_RCV_RULE_9,  0); tw32(MAC_RCV_VALUE_9,  0);
	case 9:
		tw32(MAC_RCV_RULE_8,  0); tw32(MAC_RCV_VALUE_8,  0);
	case 8:
		tw32(MAC_RCV_RULE_7,  0); tw32(MAC_RCV_VALUE_7,  0);
	case 7:
		tw32(MAC_RCV_RULE_6,  0); tw32(MAC_RCV_VALUE_6,  0);
	case 6:
		tw32(MAC_RCV_RULE_5,  0); tw32(MAC_RCV_VALUE_5,  0);
	case 5:
		tw32(MAC_RCV_RULE_4,  0); tw32(MAC_RCV_VALUE_4,  0);
	case 4:
		/* tw32(MAC_RCV_RULE_3,  0); tw32(MAC_RCV_VALUE_3,  0); */
	case 3:
		/* tw32(MAC_RCV_RULE_2,  0); tw32(MAC_RCV_VALUE_2,  0); */
	case 2:
	case 1:

	default:
		break;
	}

	return 0;
}

/* Called at device open time to get the chip ready for
 * packet processing.  Invoked with tp->lock held.
 */
int tg3_init_hw(struct tg3 *tp, int reset_phy)
{	DBGP("%s\n", __func__);

	tg3_switch_clocks(tp);

	tw32(TG3PCI_MEM_WIN_BASE_ADDR, 0);

	return tg3_reset_hw(tp, reset_phy);
}

void tg3_set_txd(struct tg3 *tp, int entry,
			dma_addr_t mapping, int len, u32 flags)
{	DBGP("%s\n", __func__);

	struct tg3_tx_buffer_desc *txd = &tp->tx_ring[entry];

	txd->addr_hi = ((u64) mapping >> 32);
	txd->addr_lo = ((u64) mapping & 0xffffffff);
	txd->len_flags = (len << TXD_LEN_SHIFT) | flags;
	txd->vlan_tag = 0;
}

int tg3_do_test_dma(struct tg3 *tp, u32 __unused *buf, dma_addr_t buf_dma, int size, int to_device)
{	DBGP("%s\n", __func__);

	struct tg3_internal_buffer_desc test_desc;
	u32 sram_dma_descs;
	int ret;
	unsigned int i;

	sram_dma_descs = NIC_SRAM_DMA_DESC_POOL_BASE;

	tw32(FTQ_RCVBD_COMP_FIFO_ENQDEQ, 0);
	tw32(FTQ_RCVDATA_COMP_FIFO_ENQDEQ, 0);
	tw32(RDMAC_STATUS, 0);
	tw32(WDMAC_STATUS, 0);

	tw32(BUFMGR_MODE, 0);
	tw32(FTQ_RESET, 0);

	test_desc.addr_hi = ((u64) buf_dma) >> 32;
	test_desc.addr_lo = buf_dma & 0xffffffff;
	test_desc.nic_mbuf = 0x00002100;
	test_desc.len = size;

	/*
	 * HP ZX1 was seeing test failures for 5701 cards running at 33Mhz
	 * the *second* time the tg3 driver was getting loaded after an
	 * initial scan.
	 *
	 * Broadcom tells me:
	 *   ...the DMA engine is connected to the GRC block and a DMA
	 *   reset may affect the GRC block in some unpredictable way...
	 *   The behavior of resets to individual blocks has not been tested.
	 *
	 * Broadcom noted the GRC reset will also reset all sub-components.
	 */
	if (to_device) {
		test_desc.cqid_sqid = (13 << 8) | 2;

		tw32_f(RDMAC_MODE, RDMAC_MODE_ENABLE);
		udelay(40);
	} else {
		test_desc.cqid_sqid = (16 << 8) | 7;

		tw32_f(WDMAC_MODE, WDMAC_MODE_ENABLE);
		udelay(40);
	}
	test_desc.flags = 0x00000005;

	for (i = 0; i < (sizeof(test_desc) / sizeof(u32)); i++) {
		u32 val;

		val = *(((u32 *)&test_desc) + i);
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR,
				       sram_dma_descs + (i * sizeof(u32)));
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_DATA, val);
	}
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);

	if (to_device)
		tw32(FTQ_DMA_HIGH_READ_FIFO_ENQDEQ, sram_dma_descs);
	else
		tw32(FTQ_DMA_HIGH_WRITE_FIFO_ENQDEQ, sram_dma_descs);

	ret = -ENODEV;
	for (i = 0; i < 40; i++) {
		u32 val;

		if (to_device)
			val = tr32(FTQ_RCVBD_COMP_FIFO_ENQDEQ);
		else
			val = tr32(FTQ_RCVDATA_COMP_FIFO_ENQDEQ);
		if ((val & 0xffff) == sram_dma_descs) {
			ret = 0;
			break;
		}

		udelay(100);
	}

	return ret;
}
