
#include <mii.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/pci.h>

#include "tg3.h"

static void tg3_link_report(struct tg3 *tp);

void tg3_mdio_init(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tg3_flag(tp, 5717_PLUS)) {
		u32 is_serdes;

		tp->phy_addr = PCI_FUNC(tp->pdev->busdevfn) + 1;

		if (tp->pci_chip_rev_id != CHIPREV_ID_5717_A0)
			is_serdes = tr32(SG_DIG_STATUS) & SG_DIG_IS_SERDES;
		else
			is_serdes = tr32(TG3_CPMU_PHY_STRAP) &
				    TG3_CPMU_PHY_STRAP_IS_SERDES;
		if (is_serdes)
			tp->phy_addr += 7;
	} else
		tp->phy_addr = TG3_PHY_MII_ADDR;
}

static int tg3_issue_otp_command(struct tg3 *tp, u32 cmd)
{	DBGP("%s\n", __func__);

	int i;
	u32 val;

	tw32(OTP_CTRL, cmd | OTP_CTRL_OTP_CMD_START);
	tw32(OTP_CTRL, cmd);

	/* Wait for up to 1 ms for command to execute. */
	for (i = 0; i < 100; i++) {
		val = tr32(OTP_STATUS);
		if (val & OTP_STATUS_CMD_DONE)
			break;
		udelay(10);
	}

	return (val & OTP_STATUS_CMD_DONE) ? 0 : -EBUSY;
}

/* Read the gphy configuration from the OTP region of the chip.  The gphy
 * configuration is a 32-bit value that straddles the alignment boundary.
 * We do two 32-bit reads and then shift and merge the results.
 */
u32 tg3_read_otp_phycfg(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 bhalf_otp, thalf_otp;

	tw32(OTP_MODE, OTP_MODE_OTP_THRU_GRC);

	if (tg3_issue_otp_command(tp, OTP_CTRL_OTP_CMD_INIT))
		return 0;

	tw32(OTP_ADDRESS, OTP_ADDRESS_MAGIC1);

	if (tg3_issue_otp_command(tp, OTP_CTRL_OTP_CMD_READ))
		return 0;

	thalf_otp = tr32(OTP_READ_DATA);

	tw32(OTP_ADDRESS, OTP_ADDRESS_MAGIC2);

	if (tg3_issue_otp_command(tp, OTP_CTRL_OTP_CMD_READ))
		return 0;

	bhalf_otp = tr32(OTP_READ_DATA);

	return ((thalf_otp & 0x0000ffff) << 16) | (bhalf_otp >> 16);
}

#define PHY_BUSY_LOOPS	5000

int tg3_readphy(struct tg3 *tp, int reg, u32 *val)
{	DBGP("%s\n", __func__);

	u32 frame_val;
	unsigned int loops;
	int ret;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE,
		     (tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL));
		udelay(80);
	}

	*val = 0x0;

	frame_val  = ((tp->phy_addr << MI_COM_PHY_ADDR_SHIFT) &
		      MI_COM_PHY_ADDR_MASK);
	frame_val |= ((reg << MI_COM_REG_ADDR_SHIFT) &
		      MI_COM_REG_ADDR_MASK);
	frame_val |= (MI_COM_CMD_READ | MI_COM_START);

	tw32_f(MAC_MI_COM, frame_val);

	loops = PHY_BUSY_LOOPS;
	while (loops != 0) {
		udelay(10);
		frame_val = tr32(MAC_MI_COM);

		if ((frame_val & MI_COM_BUSY) == 0) {
			udelay(5);
			frame_val = tr32(MAC_MI_COM);
			break;
		}
		loops -= 1;
	}

	ret = -EBUSY;
	if (loops != 0) {
		*val = frame_val & MI_COM_DATA_MASK;
		ret = 0;
	}

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE, tp->mi_mode);
		udelay(80);
	}

	return ret;
}

struct subsys_tbl_ent {
	u16 subsys_vendor, subsys_devid;
	u32 phy_id;
};

static struct subsys_tbl_ent subsys_id_to_phy_id[] = {
	/* Broadcom boards. */
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95700A6, TG3_PHY_ID_BCM5401 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95701A5, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95700T6, TG3_PHY_ID_BCM8002 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95700A9, 0 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95701T1, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95701T8, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95701A7, 0 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95701A10, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95701A12, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95703AX1, TG3_PHY_ID_BCM5703 },
	{ TG3PCI_SUBVENDOR_ID_BROADCOM,
	  TG3PCI_SUBDEVICE_ID_BROADCOM_95703AX2, TG3_PHY_ID_BCM5703 },

	/* 3com boards. */
	{ TG3PCI_SUBVENDOR_ID_3COM,
	  TG3PCI_SUBDEVICE_ID_3COM_3C996T, TG3_PHY_ID_BCM5401 },
	{ TG3PCI_SUBVENDOR_ID_3COM,
	  TG3PCI_SUBDEVICE_ID_3COM_3C996BT, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_3COM,
	  TG3PCI_SUBDEVICE_ID_3COM_3C996SX, 0 },
	{ TG3PCI_SUBVENDOR_ID_3COM,
	  TG3PCI_SUBDEVICE_ID_3COM_3C1000T, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_3COM,
	  TG3PCI_SUBDEVICE_ID_3COM_3C940BR01, TG3_PHY_ID_BCM5701 },

	/* DELL boards. */
	{ TG3PCI_SUBVENDOR_ID_DELL,
	  TG3PCI_SUBDEVICE_ID_DELL_VIPER, TG3_PHY_ID_BCM5401 },
	{ TG3PCI_SUBVENDOR_ID_DELL,
	  TG3PCI_SUBDEVICE_ID_DELL_JAGUAR, TG3_PHY_ID_BCM5401 },
	{ TG3PCI_SUBVENDOR_ID_DELL,
	  TG3PCI_SUBDEVICE_ID_DELL_MERLOT, TG3_PHY_ID_BCM5411 },
	{ TG3PCI_SUBVENDOR_ID_DELL,
	  TG3PCI_SUBDEVICE_ID_DELL_SLIM_MERLOT, TG3_PHY_ID_BCM5411 },

	/* Compaq boards. */
	{ TG3PCI_SUBVENDOR_ID_COMPAQ,
	  TG3PCI_SUBDEVICE_ID_COMPAQ_BANSHEE, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_COMPAQ,
	  TG3PCI_SUBDEVICE_ID_COMPAQ_BANSHEE_2, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_COMPAQ,
	  TG3PCI_SUBDEVICE_ID_COMPAQ_CHANGELING, 0 },
	{ TG3PCI_SUBVENDOR_ID_COMPAQ,
	  TG3PCI_SUBDEVICE_ID_COMPAQ_NC7780, TG3_PHY_ID_BCM5701 },
	{ TG3PCI_SUBVENDOR_ID_COMPAQ,
	  TG3PCI_SUBDEVICE_ID_COMPAQ_NC7780_2, TG3_PHY_ID_BCM5701 },

	/* IBM boards. */
	{ TG3PCI_SUBVENDOR_ID_IBM,
	  TG3PCI_SUBDEVICE_ID_IBM_5703SAX2, 0 }
};

static struct subsys_tbl_ent *tg3_lookup_by_subsys(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int i;

	DBGC(tp->dev, "Matching with: %x:%x\n", tp->subsystem_vendor, tp->subsystem_device);

	for (i = 0; i < (int) ARRAY_SIZE(subsys_id_to_phy_id); i++) {
		if ((subsys_id_to_phy_id[i].subsys_vendor ==
		     tp->subsystem_vendor) &&
		    (subsys_id_to_phy_id[i].subsys_devid ==
		     tp->subsystem_device))
			return &subsys_id_to_phy_id[i];
	}
	return NULL;
}

int tg3_writephy(struct tg3 *tp, int reg, u32 val)
{	DBGP("%s\n", __func__);

	u32 frame_val;
	unsigned int loops;
	int ret;

	if ((tp->phy_flags & TG3_PHYFLG_IS_FET) &&
	    (reg == MII_TG3_CTRL || reg == MII_TG3_AUX_CTRL))
		return 0;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE,
		     (tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL));
		udelay(80);
	}

	frame_val  = ((tp->phy_addr << MI_COM_PHY_ADDR_SHIFT) &
		      MI_COM_PHY_ADDR_MASK);
	frame_val |= ((reg << MI_COM_REG_ADDR_SHIFT) &
		      MI_COM_REG_ADDR_MASK);
	frame_val |= (val & MI_COM_DATA_MASK);
	frame_val |= (MI_COM_CMD_WRITE | MI_COM_START);

	tw32_f(MAC_MI_COM, frame_val);

	loops = PHY_BUSY_LOOPS;
	while (loops != 0) {
		udelay(10);
		frame_val = tr32(MAC_MI_COM);
		if ((frame_val & MI_COM_BUSY) == 0) {
			udelay(5);
			frame_val = tr32(MAC_MI_COM);
			break;
		}
		loops -= 1;
	}

	ret = -EBUSY;
	if (loops != 0)
		ret = 0;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE, tp->mi_mode);
		udelay(80);
	}

	return ret;
}

static int tg3_bmcr_reset(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 phy_control;
	int limit, err;

	/* OK, reset it, and poll the BMCR_RESET bit until it
	 * clears or we time out.
	 */
	phy_control = BMCR_RESET;
	err = tg3_writephy(tp, MII_BMCR, phy_control);
	if (err != 0)
		return -EBUSY;

	limit = 5000;
	while (limit--) {
		err = tg3_readphy(tp, MII_BMCR, &phy_control);
		if (err != 0)
			return -EBUSY;

		if ((phy_control & BMCR_RESET) == 0) {
			udelay(40);
			break;
		}
		udelay(10);
	}
	if (limit < 0)
		return -EBUSY;

	return 0;
}

static int tg3_wait_macro_done(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int limit = 100;

	while (limit--) {
		u32 tmp32;

		if (!tg3_readphy(tp, MII_TG3_DSP_CONTROL, &tmp32)) {
			if ((tmp32 & 0x1000) == 0)
				break;
		}
	}
	if (limit < 0)
		return -EBUSY;

	return 0;
}

static int tg3_phy_write_and_check_testpat(struct tg3 *tp, int *resetp)
{	DBGP("%s\n", __func__);

	static const u32 test_pat[4][6] = {
	{ 0x00005555, 0x00000005, 0x00002aaa, 0x0000000a, 0x00003456, 0x00000003 },
	{ 0x00002aaa, 0x0000000a, 0x00003333, 0x00000003, 0x0000789a, 0x00000005 },
	{ 0x00005a5a, 0x00000005, 0x00002a6a, 0x0000000a, 0x00001bcd, 0x00000003 },
	{ 0x00002a5a, 0x0000000a, 0x000033c3, 0x00000003, 0x00002ef1, 0x00000005 }
	};
	int chan;

	for (chan = 0; chan < 4; chan++) {
		int i;

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			     (chan * 0x2000) | 0x0200);
		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0002);

		for (i = 0; i < 6; i++)
			tg3_writephy(tp, MII_TG3_DSP_RW_PORT,
				     test_pat[chan][i]);

		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0202);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			     (chan * 0x2000) | 0x0200);
		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0082);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0802);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		for (i = 0; i < 6; i += 2) {
			u32 low, high;

			if (tg3_readphy(tp, MII_TG3_DSP_RW_PORT, &low) ||
			    tg3_readphy(tp, MII_TG3_DSP_RW_PORT, &high) ||
			    tg3_wait_macro_done(tp)) {
				*resetp = 1;
				return -EBUSY;
			}
			low &= 0x7fff;
			high &= 0x000f;
			if (low != test_pat[chan][i] ||
			    high != test_pat[chan][i+1]) {
				tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x000b);
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x4001);
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x4005);

				return -EBUSY;
			}
		}
	}

	return 0;
}

static int tg3_phy_reset_chanpat(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int chan;

	for (chan = 0; chan < 4; chan++) {
		int i;

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			     (chan * 0x2000) | 0x0200);
		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0002);
		for (i = 0; i < 6; i++)
			tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x000);
		tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0202);
		if (tg3_wait_macro_done(tp))
			return -EBUSY;
	}

	return 0;
}

static int tg3_phydsp_write(struct tg3 *tp, u32 reg, u32 val)
{	DBGP("%s\n", __func__);

	int err;

	err = tg3_writephy(tp, MII_TG3_DSP_ADDRESS, reg);
	if (!err)
		err = tg3_writephy(tp, MII_TG3_DSP_RW_PORT, val);

	return err;
}

static int tg3_phy_auxctl_write(struct tg3 *tp, int reg, u32 set)
{	DBGP("%s\n", __func__);

	if (reg == MII_TG3_AUXCTL_SHDWSEL_MISC)
		set |= MII_TG3_AUXCTL_MISC_WREN;

	return tg3_writephy(tp, MII_TG3_AUX_CTRL, set | reg);
}

#define TG3_PHY_AUXCTL_SMDSP_ENABLE(tp) \
	tg3_phy_auxctl_write((tp), MII_TG3_AUXCTL_SHDWSEL_AUXCTL, \
			     MII_TG3_AUXCTL_ACTL_SMDSP_ENA | \
			     MII_TG3_AUXCTL_ACTL_TX_6DB)

#define TG3_PHY_AUXCTL_SMDSP_DISABLE(tp) \
	tg3_phy_auxctl_write((tp), MII_TG3_AUXCTL_SHDWSEL_AUXCTL, \
			     MII_TG3_AUXCTL_ACTL_TX_6DB);

static int tg3_phy_reset_5703_4_5(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 reg32, phy9_orig;
	int retries, do_phy_reset, err;

	retries = 10;
	do_phy_reset = 1;
	do {
		if (do_phy_reset) {
			err = tg3_bmcr_reset(tp);
			if (err)
				return err;
			do_phy_reset = 0;
		}

		/* Disable transmitter and interrupt.  */
		if (tg3_readphy(tp, MII_TG3_EXT_CTRL, &reg32))
			continue;

		reg32 |= 0x3000;
		tg3_writephy(tp, MII_TG3_EXT_CTRL, reg32);

		/* Set full-duplex, 1000 mbps.  */
		tg3_writephy(tp, MII_BMCR,
			     BMCR_FULLDPLX | TG3_BMCR_SPEED1000);

		/* Set to master mode.  */
		if (tg3_readphy(tp, MII_TG3_CTRL, &phy9_orig))
			continue;

		tg3_writephy(tp, MII_TG3_CTRL,
			     (MII_TG3_CTRL_AS_MASTER |
			      MII_TG3_CTRL_ENABLE_AS_MASTER));

		err = TG3_PHY_AUXCTL_SMDSP_ENABLE(tp);
		if (err)
			return err;

		/* Block the PHY control access.  */
		tg3_phydsp_write(tp, 0x8005, 0x0800);

		err = tg3_phy_write_and_check_testpat(tp, &do_phy_reset);
		if (!err)
			break;
	} while (--retries);

	err = tg3_phy_reset_chanpat(tp);
	if (err)
		return err;

	tg3_phydsp_write(tp, 0x8005, 0x0000);

	tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x8200);
	tg3_writephy(tp, MII_TG3_DSP_CONTROL, 0x0000);

	TG3_PHY_AUXCTL_SMDSP_DISABLE(tp);

	tg3_writephy(tp, MII_TG3_CTRL, phy9_orig);

	if (!tg3_readphy(tp, MII_TG3_EXT_CTRL, &reg32)) {
		reg32 &= ~0x3000;
		tg3_writephy(tp, MII_TG3_EXT_CTRL, reg32);
	} else if (!err)
		err = -EBUSY;

	return err;
}

static void tg3_phy_apply_otp(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 otp, phy;

	if (!tp->phy_otp)
		return;

	otp = tp->phy_otp;

	if (TG3_PHY_AUXCTL_SMDSP_ENABLE(tp))
		return;

	phy = ((otp & TG3_OTP_AGCTGT_MASK) >> TG3_OTP_AGCTGT_SHIFT);
	phy |= MII_TG3_DSP_TAP1_AGCTGT_DFLT;
	tg3_phydsp_write(tp, MII_TG3_DSP_TAP1, phy);

	phy = ((otp & TG3_OTP_HPFFLTR_MASK) >> TG3_OTP_HPFFLTR_SHIFT) |
	      ((otp & TG3_OTP_HPFOVER_MASK) >> TG3_OTP_HPFOVER_SHIFT);
	tg3_phydsp_write(tp, MII_TG3_DSP_AADJ1CH0, phy);

	phy = ((otp & TG3_OTP_LPFDIS_MASK) >> TG3_OTP_LPFDIS_SHIFT);
	phy |= MII_TG3_DSP_AADJ1CH3_ADCCKADJ;
	tg3_phydsp_write(tp, MII_TG3_DSP_AADJ1CH3, phy);

	phy = ((otp & TG3_OTP_VDAC_MASK) >> TG3_OTP_VDAC_SHIFT);
	tg3_phydsp_write(tp, MII_TG3_DSP_EXP75, phy);

	phy = ((otp & TG3_OTP_10BTAMP_MASK) >> TG3_OTP_10BTAMP_SHIFT);
	tg3_phydsp_write(tp, MII_TG3_DSP_EXP96, phy);

	phy = ((otp & TG3_OTP_ROFF_MASK) >> TG3_OTP_ROFF_SHIFT) |
	      ((otp & TG3_OTP_RCOFF_MASK) >> TG3_OTP_RCOFF_SHIFT);
	tg3_phydsp_write(tp, MII_TG3_DSP_EXP97, phy);

	TG3_PHY_AUXCTL_SMDSP_DISABLE(tp);
}

static int tg3_phy_auxctl_read(struct tg3 *tp, int reg, u32 *val)
{	DBGP("%s\n", __func__);

	int err;

	err = tg3_writephy(tp, MII_TG3_AUX_CTRL,
			   (reg << MII_TG3_AUXCTL_MISC_RDSEL_SHIFT) |
			   MII_TG3_AUXCTL_SHDWSEL_MISC);
	if (!err)
		err = tg3_readphy(tp, MII_TG3_AUX_CTRL, val);

	return err;
}

static void tg3_phy_toggle_automdix(struct tg3 *tp, int enable)
{	DBGP("%s\n", __func__);

	u32 phy;

	if (!tg3_flag(tp, 5705_PLUS) ||
	    (tp->phy_flags & TG3_PHYFLG_ANY_SERDES))
		return;

	if (tp->phy_flags & TG3_PHYFLG_IS_FET) {
		u32 ephy;

		if (!tg3_readphy(tp, MII_TG3_FET_TEST, &ephy)) {
			u32 reg = MII_TG3_FET_SHDW_MISCCTRL;

			tg3_writephy(tp, MII_TG3_FET_TEST,
				     ephy | MII_TG3_FET_SHADOW_EN);
			if (!tg3_readphy(tp, reg, &phy)) {
				if (enable)
					phy |= MII_TG3_FET_SHDW_MISCCTRL_MDIX;
				else
					phy &= ~MII_TG3_FET_SHDW_MISCCTRL_MDIX;
				tg3_writephy(tp, reg, phy);
			}
			tg3_writephy(tp, MII_TG3_FET_TEST, ephy);
		}
	} else {
		int ret;

		ret = tg3_phy_auxctl_read(tp,
					  MII_TG3_AUXCTL_SHDWSEL_MISC, &phy);
		if (!ret) {
			if (enable)
				phy |= MII_TG3_AUXCTL_MISC_FORCE_AMDIX;
			else
				phy &= ~MII_TG3_AUXCTL_MISC_FORCE_AMDIX;
			tg3_phy_auxctl_write(tp,
					     MII_TG3_AUXCTL_SHDWSEL_MISC, phy);
		}
	}
}

static void tg3_phy_set_wirespeed(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int ret;
	u32 val;

	if (tp->phy_flags & TG3_PHYFLG_NO_ETH_WIRE_SPEED)
		return;

	ret = tg3_phy_auxctl_read(tp, MII_TG3_AUXCTL_SHDWSEL_MISC, &val);
	if (!ret)
		tg3_phy_auxctl_write(tp, MII_TG3_AUXCTL_SHDWSEL_MISC,
				     val | MII_TG3_AUXCTL_MISC_WIRESPD_EN);
}

/* This will reset the tigon3 PHY if there is no valid
 * link unless the FORCE argument is non-zero.
 */
int tg3_phy_reset(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 val, cpmuctrl;
	int err;

	DBGCP(&tp->pdev->dev, "%s\n", __func__);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906) {
		val = tr32(GRC_MISC_CFG);
		tw32_f(GRC_MISC_CFG, val & ~GRC_MISC_CFG_EPHY_IDDQ);
		udelay(40);
	}
	err  = tg3_readphy(tp, MII_BMSR, &val);
	err |= tg3_readphy(tp, MII_BMSR, &val);
	if (err != 0)
		return -EBUSY;

	netdev_link_down(tp->dev);
	tg3_link_report(tp);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705) {
		err = tg3_phy_reset_5703_4_5(tp);
		if (err)
			return err;
		goto out;
	}

	cpmuctrl = 0;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5784 &&
	    GET_CHIP_REV(tp->pci_chip_rev_id) != CHIPREV_5784_AX) {
		cpmuctrl = tr32(TG3_CPMU_CTRL);
		if (cpmuctrl & CPMU_CTRL_GPHY_10MB_RXONLY)
			tw32(TG3_CPMU_CTRL,
			     cpmuctrl & ~CPMU_CTRL_GPHY_10MB_RXONLY);
	}

	err = tg3_bmcr_reset(tp);
	if (err)
		return err;

	if (cpmuctrl & CPMU_CTRL_GPHY_10MB_RXONLY) {
		val = MII_TG3_DSP_EXP8_AEDW | MII_TG3_DSP_EXP8_REJ2MHz;
		tg3_phydsp_write(tp, MII_TG3_DSP_EXP8, val);

		tw32(TG3_CPMU_CTRL, cpmuctrl);
	}

	if (GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5784_AX ||
	    GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5761_AX) {
		val = tr32(TG3_CPMU_LSPD_1000MB_CLK);
		if ((val & CPMU_LSPD_1000MB_MACCLK_MASK) ==
		    CPMU_LSPD_1000MB_MACCLK_12_5) {
			val &= ~CPMU_LSPD_1000MB_MACCLK_MASK;
			udelay(40);
			tw32_f(TG3_CPMU_LSPD_1000MB_CLK, val);
		}
	}

	if (tg3_flag(tp, 5717_PLUS) &&
	    (tp->phy_flags & TG3_PHYFLG_MII_SERDES))
		return 0;

	tg3_phy_apply_otp(tp);

out:
	if ((tp->phy_flags & TG3_PHYFLG_ADC_BUG) &&
	    !TG3_PHY_AUXCTL_SMDSP_ENABLE(tp)) {
		tg3_phydsp_write(tp, 0x201f, 0x2aaa);
		tg3_phydsp_write(tp, 0x000a, 0x0323);
		TG3_PHY_AUXCTL_SMDSP_DISABLE(tp);
	}

	if (tp->phy_flags & TG3_PHYFLG_5704_A0_BUG) {
		tg3_writephy(tp, MII_TG3_MISC_SHDW, 0x8d68);
		tg3_writephy(tp, MII_TG3_MISC_SHDW, 0x8d68);
	}

	if (tp->phy_flags & TG3_PHYFLG_BER_BUG) {
		if (!TG3_PHY_AUXCTL_SMDSP_ENABLE(tp)) {
			tg3_phydsp_write(tp, 0x000a, 0x310b);
			tg3_phydsp_write(tp, 0x201f, 0x9506);
			tg3_phydsp_write(tp, 0x401f, 0x14e2);
			TG3_PHY_AUXCTL_SMDSP_DISABLE(tp);
		}
	} else if (tp->phy_flags & TG3_PHYFLG_JITTER_BUG) {
		if (!TG3_PHY_AUXCTL_SMDSP_ENABLE(tp)) {
			tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x000a);
			if (tp->phy_flags & TG3_PHYFLG_ADJUST_TRIM) {
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x110b);
				tg3_writephy(tp, MII_TG3_TEST1,
					     MII_TG3_TEST1_TRIM_EN | 0x4);
			} else
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x010b);

			TG3_PHY_AUXCTL_SMDSP_DISABLE(tp);
		}
	}

	if ((tp->phy_id & TG3_PHY_ID_MASK) == TG3_PHY_ID_BCM5401) {
		/* Cannot do read-modify-write on 5401 */
		tg3_phy_auxctl_write(tp, MII_TG3_AUXCTL_SHDWSEL_AUXCTL, 0x4c20);
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5906) {
		/* adjust output voltage */
		tg3_writephy(tp, MII_TG3_FET_PTEST, 0x12);
	}

	tg3_phy_toggle_automdix(tp, 1);
	tg3_phy_set_wirespeed(tp);
	return 0;
}

static int tg3_copper_is_advertising_all(struct tg3 *tp, u32 mask)
{	DBGP("%s\n", __func__);

	u32 adv_reg, all_mask = 0;

	if (mask & ADVERTISED_10baseT_Half)
		all_mask |= ADVERTISE_10HALF;
	if (mask & ADVERTISED_10baseT_Full)
		all_mask |= ADVERTISE_10FULL;
	if (mask & ADVERTISED_100baseT_Half)
		all_mask |= ADVERTISE_100HALF;
	if (mask & ADVERTISED_100baseT_Full)
		all_mask |= ADVERTISE_100FULL;

	if (tg3_readphy(tp, MII_ADVERTISE, &adv_reg))
		return 0;

	if ((adv_reg & all_mask) != all_mask)
		return 0;
	if (!(tp->phy_flags & TG3_PHYFLG_10_100_ONLY)) {
		u32 tg3_ctrl;

		all_mask = 0;
		if (mask & ADVERTISED_1000baseT_Half)
			all_mask |= ADVERTISE_1000HALF;
		if (mask & ADVERTISED_1000baseT_Full)
			all_mask |= ADVERTISE_1000FULL;

		if (tg3_readphy(tp, MII_TG3_CTRL, &tg3_ctrl))
			return 0;

		if ((tg3_ctrl & all_mask) != all_mask)
			return 0;
	}
	return 1;
}

static u16 tg3_advert_flowctrl_1000T(u8 flow_ctrl)
{	DBGP("%s\n", __func__);

	u16 miireg;

	if ((flow_ctrl & FLOW_CTRL_TX) && (flow_ctrl & FLOW_CTRL_RX))
		miireg = ADVERTISE_PAUSE_CAP;
	else if (flow_ctrl & FLOW_CTRL_TX)
		miireg = ADVERTISE_PAUSE_ASYM;
	else if (flow_ctrl & FLOW_CTRL_RX)
		miireg = ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;
	else
		miireg = 0;

	return miireg;
}

static int tg3_phy_autoneg_cfg(struct tg3 *tp, u32 advertise, u32 flowctrl)
{	DBGP("%s\n", __func__);

	int err = 0;
	u32 val __unused, new_adv;

	new_adv = ADVERTISE_CSMA;
	if (advertise & ADVERTISED_10baseT_Half)
		new_adv |= ADVERTISE_10HALF;
	if (advertise & ADVERTISED_10baseT_Full)
		new_adv |= ADVERTISE_10FULL;
	if (advertise & ADVERTISED_100baseT_Half)
		new_adv |= ADVERTISE_100HALF;
	if (advertise & ADVERTISED_100baseT_Full)
		new_adv |= ADVERTISE_100FULL;

	new_adv |= tg3_advert_flowctrl_1000T(flowctrl);

	err = tg3_writephy(tp, MII_ADVERTISE, new_adv);
	if (err)
		goto done;

	if (tp->phy_flags & TG3_PHYFLG_10_100_ONLY)
		goto done;

	new_adv = 0;
	if (advertise & ADVERTISED_1000baseT_Half)
		new_adv |= MII_TG3_CTRL_ADV_1000_HALF;
	if (advertise & ADVERTISED_1000baseT_Full)
		new_adv |= MII_TG3_CTRL_ADV_1000_FULL;

	if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5701_B0)
		new_adv |= (MII_TG3_CTRL_AS_MASTER |
			    MII_TG3_CTRL_ENABLE_AS_MASTER);

	err = tg3_writephy(tp, MII_TG3_CTRL, new_adv);
	if (err)
		goto done;

	if (!(tp->phy_flags & TG3_PHYFLG_EEE_CAP))
		goto done;

done:
	return err;
}

static int tg3_init_5401phy_dsp(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	int err;

	/* Turn off tap power management. */
	/* Set Extended packet length bit */
	err = tg3_phy_auxctl_write(tp, MII_TG3_AUXCTL_SHDWSEL_AUXCTL, 0x4c20);

	err |= tg3_phydsp_write(tp, 0x0012, 0x1804);
	err |= tg3_phydsp_write(tp, 0x0013, 0x1204);
	err |= tg3_phydsp_write(tp, 0x8006, 0x0132);
	err |= tg3_phydsp_write(tp, 0x8006, 0x0232);
	err |= tg3_phydsp_write(tp, 0x201f, 0x0a20);

	udelay(40);

	return err;
}

#define ADVERTISED_Autoneg              (1 << 6)
#define ADVERTISED_Pause                (1 << 13)
#define ADVERTISED_TP                   (1 << 7)
#define ADVERTISED_FIBRE                (1 << 10)

#define AUTONEG_ENABLE          0x01

static void tg3_phy_init_link_config(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 adv = ADVERTISED_Autoneg |
		  ADVERTISED_Pause;


	if (!(tp->phy_flags & TG3_PHYFLG_10_100_ONLY))
		adv |= ADVERTISED_1000baseT_Half |
		       ADVERTISED_1000baseT_Full;
	if (!(tp->phy_flags & TG3_PHYFLG_ANY_SERDES))
		adv |= ADVERTISED_100baseT_Half |
		       ADVERTISED_100baseT_Full |
		       ADVERTISED_10baseT_Half |
		       ADVERTISED_10baseT_Full |
		       ADVERTISED_TP;
	else
		adv |= ADVERTISED_FIBRE;

	tp->link_config.advertising = adv;
	tp->link_config.speed = SPEED_INVALID;
	tp->link_config.duplex = DUPLEX_INVALID;
	tp->link_config.autoneg = AUTONEG_ENABLE;
	tp->link_config.active_speed = SPEED_INVALID;
	tp->link_config.active_duplex = DUPLEX_INVALID;
	tp->link_config.orig_speed = SPEED_INVALID;
	tp->link_config.orig_duplex = DUPLEX_INVALID;
	tp->link_config.orig_autoneg = AUTONEG_INVALID;
}

int tg3_phy_probe(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 hw_phy_id_1, hw_phy_id_2;
	u32 hw_phy_id, hw_phy_id_masked;
	int err;

	/* flow control autonegotiation is default behavior */
	tg3_flag_set(tp, PAUSE_AUTONEG);
	tp->link_config.flowctrl = FLOW_CTRL_TX | FLOW_CTRL_RX;

	/* Reading the PHY ID register can conflict with ASF
	 * firmware access to the PHY hardware.
	 */
	err = 0;
	if (tg3_flag(tp, ENABLE_ASF) || tg3_flag(tp, ENABLE_APE)) {
		hw_phy_id = hw_phy_id_masked = TG3_PHY_ID_INVALID;
	} else {
		/* Now read the physical PHY_ID from the chip and verify
		 * that it is sane.  If it doesn't look good, we fall back
		 * to either the hard-coded table based PHY_ID and failing
		 * that the value found in the eeprom area.
		 */
		err |= tg3_readphy(tp, MII_PHYSID1, &hw_phy_id_1);
		err |= tg3_readphy(tp, MII_PHYSID2, &hw_phy_id_2);

		hw_phy_id  = (hw_phy_id_1 & 0xffff) << 10;
		hw_phy_id |= (hw_phy_id_2 & 0xfc00) << 16;
		hw_phy_id |= (hw_phy_id_2 & 0x03ff) <<  0;

		hw_phy_id_masked = hw_phy_id & TG3_PHY_ID_MASK;
	}

	if (!err && TG3_KNOWN_PHY_ID(hw_phy_id_masked)) {
		tp->phy_id = hw_phy_id;
		if (hw_phy_id_masked == TG3_PHY_ID_BCM8002)
			tp->phy_flags |= TG3_PHYFLG_PHY_SERDES;
		else
			tp->phy_flags &= ~TG3_PHYFLG_PHY_SERDES;
	} else {
		if (tp->phy_id != TG3_PHY_ID_INVALID) {
			/* Do nothing, phy ID already set up in
			 * tg3_get_eeprom_hw_cfg().
			 */
		} else {
			struct subsys_tbl_ent *p;

			/* No eeprom signature?  Try the hardcoded
			 * subsys device table.
			 */
			p = tg3_lookup_by_subsys(tp);
			if (!p) {
				DBGC(&tp->pdev->dev, "lookup by subsys failed\n");
				return -ENODEV;
			}

			tp->phy_id = p->phy_id;
			if (!tp->phy_id ||
			    tp->phy_id == TG3_PHY_ID_BCM8002)
				tp->phy_flags |= TG3_PHYFLG_PHY_SERDES;
		}
	}

	if (!(tp->phy_flags & TG3_PHYFLG_ANY_SERDES) &&
	    ((tp->pdev->device == TG3PCI_DEVICE_TIGON3_5718 &&
	      tp->pci_chip_rev_id != CHIPREV_ID_5717_A0) ||
	     (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_57765 &&
	      tp->pci_chip_rev_id != CHIPREV_ID_57765_A0)))
		tp->phy_flags |= TG3_PHYFLG_EEE_CAP;

	tg3_phy_init_link_config(tp);

	if (!(tp->phy_flags & TG3_PHYFLG_ANY_SERDES) &&
	    !tg3_flag(tp, ENABLE_APE) &&
	    !tg3_flag(tp, ENABLE_ASF)) {
		u32 bmsr;
		u32 mask;

		tg3_readphy(tp, MII_BMSR, &bmsr);
		if (!tg3_readphy(tp, MII_BMSR, &bmsr) &&
		    (bmsr & BMSR_LSTATUS))
			goto skip_phy_reset;

		err = tg3_phy_reset(tp);
		if (err)
			return err;

		tg3_phy_set_wirespeed(tp);

		mask = (ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full |
			ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full |
			ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full);
		if (!tg3_copper_is_advertising_all(tp, mask)) {
			tg3_phy_autoneg_cfg(tp, tp->link_config.advertising,
			                    tp->link_config.flowctrl);

			tg3_writephy(tp, MII_BMCR,
				     BMCR_ANENABLE | BMCR_ANRESTART);
		}
	}

skip_phy_reset:
	if ((tp->phy_id & TG3_PHY_ID_MASK) == TG3_PHY_ID_BCM5401) {
		err = tg3_init_5401phy_dsp(tp);
		if (err)
			return err;

		err = tg3_init_5401phy_dsp(tp);
	}

	return err;
}

void tg3_poll_link(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tp->hw_status->status & SD_STATUS_LINK_CHG) {
		DBGC(tp->dev,"link_changed\n");
		tp->hw_status->status &= ~SD_STATUS_LINK_CHG;
		tg3_setup_phy(tp, 0);
	}
}

static void tg3_aux_stat_to_speed_duplex(struct tg3 *tp, u32 val, u16 *speed, u8 *duplex)
{	DBGP("%s\n", __func__);

	switch (val & MII_TG3_AUX_STAT_SPDMASK) {
	case MII_TG3_AUX_STAT_10HALF:
		*speed = SPEED_10;
		*duplex = DUPLEX_HALF;
		break;

	case MII_TG3_AUX_STAT_10FULL:
		*speed = SPEED_10;
		*duplex = DUPLEX_FULL;
		break;

	case MII_TG3_AUX_STAT_100HALF:
		*speed = SPEED_100;
		*duplex = DUPLEX_HALF;
		break;

	case MII_TG3_AUX_STAT_100FULL:
		*speed = SPEED_100;
		*duplex = DUPLEX_FULL;
		break;

	case MII_TG3_AUX_STAT_1000HALF:
		*speed = SPEED_1000;
		*duplex = DUPLEX_HALF;
		break;

	case MII_TG3_AUX_STAT_1000FULL:
		*speed = SPEED_1000;
		*duplex = DUPLEX_FULL;
		break;

	default:
		if (tp->phy_flags & TG3_PHYFLG_IS_FET) {
			*speed = (val & MII_TG3_AUX_STAT_100) ? SPEED_100 :
				 SPEED_10;
			*duplex = (val & MII_TG3_AUX_STAT_FULL) ? DUPLEX_FULL :
				  DUPLEX_HALF;
			break;
		}
		*speed = SPEED_INVALID;
		*duplex = DUPLEX_INVALID;
		break;
	}
}

static int tg3_adv_1000T_flowctrl_ok(struct tg3 *tp, u32 *lcladv, u32 *rmtadv)
{	DBGP("%s\n", __func__);

	u32 curadv, reqadv;

	if (tg3_readphy(tp, MII_ADVERTISE, lcladv))
		return 1;

	curadv = *lcladv & (ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);
	reqadv = tg3_advert_flowctrl_1000T(tp->link_config.flowctrl);

	if (tp->link_config.active_duplex == DUPLEX_FULL) {
		if (curadv != reqadv)
			return 0;

		if (tg3_flag(tp, PAUSE_AUTONEG))
			tg3_readphy(tp, MII_LPA, rmtadv);
	} else {
		/* Reprogram the advertisement register, even if it
		 * does not affect the current link.  If the link
		 * gets renegotiated in the future, we can save an
		 * additional renegotiation cycle by advertising
		 * it correctly in the first place.
		 */
		if (curadv != reqadv) {
			*lcladv &= ~(ADVERTISE_PAUSE_CAP |
				     ADVERTISE_PAUSE_ASYM);
			tg3_writephy(tp, MII_ADVERTISE, *lcladv | reqadv);
		}
	}

	return 1;
}

static u8 tg3_resolve_flowctrl_1000X(u16 lcladv, u16 rmtadv)
{	DBGP("%s\n", __func__);

	u8 cap = 0;

	if (lcladv & ADVERTISE_1000XPAUSE) {
		if (lcladv & ADVERTISE_1000XPSE_ASYM) {
			if (rmtadv & LPA_1000XPAUSE)
				cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
			else if (rmtadv & LPA_1000XPAUSE_ASYM)
				cap = FLOW_CTRL_RX;
		} else {
			if (rmtadv & LPA_1000XPAUSE)
				cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
		}
	} else if (lcladv & ADVERTISE_1000XPSE_ASYM) {
		if ((rmtadv & LPA_1000XPAUSE) && (rmtadv & LPA_1000XPAUSE_ASYM))
			cap = FLOW_CTRL_TX;
	}

	return cap;
}

static void tg3_setup_flow_control(struct tg3 *tp, u32 lcladv, u32 rmtadv)
{	DBGP("%s\n", __func__);

	u8 flowctrl = 0;
	u32 old_rx_mode = tp->rx_mode;
	u32 old_tx_mode = tp->tx_mode;

	if (tg3_flag(tp, PAUSE_AUTONEG)) {
		if (tp->phy_flags & TG3_PHYFLG_ANY_SERDES)
			flowctrl = tg3_resolve_flowctrl_1000X(lcladv, rmtadv);
		else
			flowctrl = mii_resolve_flowctrl_fdx(lcladv, rmtadv);
	} else
		flowctrl = tp->link_config.flowctrl;

	tp->link_config.active_flowctrl = flowctrl;

	if (flowctrl & FLOW_CTRL_RX)
		tp->rx_mode |= RX_MODE_FLOW_CTRL_ENABLE;
	else
		tp->rx_mode &= ~RX_MODE_FLOW_CTRL_ENABLE;

	if (old_rx_mode != tp->rx_mode)
		tw32_f(MAC_RX_MODE, tp->rx_mode);

	if (flowctrl & FLOW_CTRL_TX)
		tp->tx_mode |= TX_MODE_FLOW_CTRL_ENABLE;
	else
		tp->tx_mode &= ~TX_MODE_FLOW_CTRL_ENABLE;

	if (old_tx_mode != tp->tx_mode)
		tw32_f(MAC_TX_MODE, tp->tx_mode);
}

static void tg3_phy_copper_begin(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 new_adv;

	if (tp->link_config.speed == SPEED_INVALID) {
		if (tp->phy_flags & TG3_PHYFLG_10_100_ONLY)
			tp->link_config.advertising &=
				~(ADVERTISED_1000baseT_Half |
				  ADVERTISED_1000baseT_Full);

		tg3_phy_autoneg_cfg(tp, tp->link_config.advertising,
				    tp->link_config.flowctrl);
	} else {
		/* Asking for a specific link mode. */
		if (tp->link_config.speed == SPEED_1000) {
			if (tp->link_config.duplex == DUPLEX_FULL)
				new_adv = ADVERTISED_1000baseT_Full;
			else
				new_adv = ADVERTISED_1000baseT_Half;
		} else if (tp->link_config.speed == SPEED_100) {
			if (tp->link_config.duplex == DUPLEX_FULL)
				new_adv = ADVERTISED_100baseT_Full;
			else
				new_adv = ADVERTISED_100baseT_Half;
		} else {
			if (tp->link_config.duplex == DUPLEX_FULL)
				new_adv = ADVERTISED_10baseT_Full;
			else
				new_adv = ADVERTISED_10baseT_Half;
		}

		tg3_phy_autoneg_cfg(tp, new_adv,
				    tp->link_config.flowctrl);
	}

	tg3_writephy(tp, MII_BMCR, BMCR_ANENABLE | BMCR_ANRESTART);
}

static int tg3_5700_link_polarity(struct tg3 *tp, u32 speed)
{	DBGP("%s\n", __func__);

	if (tp->led_ctrl == LED_CTRL_MODE_PHY_2)
		return 1;
	else if ((tp->phy_id & TG3_PHY_ID_MASK) == TG3_PHY_ID_BCM5411) {
		if (speed != SPEED_10)
			return 1;
	} else if (speed == SPEED_10)
		return 1;

	return 0;
}

#if 1

static void tg3_ump_link_report(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	u32 reg;
	u32 val;

	if (!tg3_flag(tp, 5780_CLASS) || !tg3_flag(tp, ENABLE_ASF))
		return;

	tg3_wait_for_event_ack(tp);

	tg3_write_mem(tp, NIC_SRAM_FW_CMD_MBOX, FWCMD_NICDRV_LINK_UPDATE);

	tg3_write_mem(tp, NIC_SRAM_FW_CMD_LEN_MBOX, 14);

	val = 0;
	if (!tg3_readphy(tp, MII_BMCR, &reg))
		val = reg << 16;
	if (!tg3_readphy(tp, MII_BMSR, &reg))
		val |= (reg & 0xffff);
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX, val);

	val = 0;
	if (!tg3_readphy(tp, MII_ADVERTISE, &reg))
		val = reg << 16;
	if (!tg3_readphy(tp, MII_LPA, &reg))
		val |= (reg & 0xffff);
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX + 4, val);

	val = 0;
	if (!(tp->phy_flags & TG3_PHYFLG_MII_SERDES)) {
		if (!tg3_readphy(tp, MII_CTRL1000, &reg))
			val = reg << 16;
		if (!tg3_readphy(tp, MII_STAT1000, &reg))
			val |= (reg & 0xffff);
	}
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX + 8, val);

	if (!tg3_readphy(tp, MII_PHYADDR, &reg))
		val = reg << 16;
	else
		val = 0;
	tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX + 12, val);

	tg3_generate_fw_event(tp);
}

/* NOTE: Debugging only code */
static void tg3_link_report(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (!netdev_link_ok(tp->dev)) {
		DBGC(tp->dev, "Link is down\n");
		tg3_ump_link_report(tp);
	} else {
		DBGC(tp->dev, "Link is up at %d Mbps, %s duplex\n",
			    (tp->link_config.active_speed == SPEED_1000 ?
			     1000 :
			     (tp->link_config.active_speed == SPEED_100 ?
			      100 : 10)),
			    (tp->link_config.active_duplex == DUPLEX_FULL ?
			     "full" : "half"));

		DBGC(tp->dev, "Flow control is %s for TX and %s for RX\n",
			    (tp->link_config.active_flowctrl & FLOW_CTRL_TX) ?
			    "on" : "off",
			    (tp->link_config.active_flowctrl & FLOW_CTRL_RX) ?
			    "on" : "off");

		if (tp->phy_flags & TG3_PHYFLG_EEE_CAP)
			DBGC(tp->dev, "EEE is %s\n",
				    tp->setlpicnt ? "enabled" : "disabled");

		tg3_ump_link_report(tp);
	}
}
#endif

static int tg3_setup_copper_phy(struct tg3 *tp, int force_reset)
{	DBGP("%s\n", __func__);

	int current_link_up;
	u32 bmsr, val;
	u32 lcl_adv, rmt_adv;
	u16 current_speed;
	u8 current_duplex;
	int i, err;

	tw32(MAC_EVENT, 0);

	tw32_f(MAC_STATUS,
	     (MAC_STATUS_SYNC_CHANGED |
	      MAC_STATUS_CFG_CHANGED |
	      MAC_STATUS_MI_COMPLETION |
	      MAC_STATUS_LNKSTATE_CHANGED));
	udelay(40);

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32_f(MAC_MI_MODE,
		     (tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL));
		udelay(80);
	}

	tg3_phy_auxctl_write(tp, MII_TG3_AUXCTL_SHDWSEL_PWRCTL, 0);

	/* Some third-party PHYs need to be reset on link going
	 * down.
	 */
	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 ||
	     GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704 ||
	     GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705) &&
	    netdev_link_ok(tp->dev)) {
		tg3_readphy(tp, MII_BMSR, &bmsr);
		if (!tg3_readphy(tp, MII_BMSR, &bmsr) &&
		    !(bmsr & BMSR_LSTATUS))
			force_reset = 1;
	}
	if (force_reset)
		tg3_phy_reset(tp);

	if ((tp->phy_id & TG3_PHY_ID_MASK) == TG3_PHY_ID_BCM5401) {
		tg3_readphy(tp, MII_BMSR, &bmsr);
		if (tg3_readphy(tp, MII_BMSR, &bmsr) ||
		    !tg3_flag(tp, INIT_COMPLETE))
			bmsr = 0;

		if (!(bmsr & BMSR_LSTATUS)) {
			err = tg3_init_5401phy_dsp(tp);
			if (err)
				return err;

			tg3_readphy(tp, MII_BMSR, &bmsr);
			for (i = 0; i < 1000; i++) {
				udelay(10);
				if (!tg3_readphy(tp, MII_BMSR, &bmsr) &&
				    (bmsr & BMSR_LSTATUS)) {
					udelay(40);
					break;
				}
			}

			if ((tp->phy_id & TG3_PHY_ID_REV_MASK) ==
			    TG3_PHY_REV_BCM5401_B0 &&
			    !(bmsr & BMSR_LSTATUS) &&
			    tp->link_config.active_speed == SPEED_1000) {
				err = tg3_phy_reset(tp);
				if (!err)
					err = tg3_init_5401phy_dsp(tp);
				if (err)
					return err;
			}
		}
	} else if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
		   tp->pci_chip_rev_id == CHIPREV_ID_5701_B0) {
		/* 5701 {A0,B0} CRC bug workaround */
		tg3_writephy(tp, 0x15, 0x0a75);
		tg3_writephy(tp, MII_TG3_MISC_SHDW, 0x8c68);
		tg3_writephy(tp, MII_TG3_MISC_SHDW, 0x8d68);
		tg3_writephy(tp, MII_TG3_MISC_SHDW, 0x8c68);
	}

	/* Clear pending interrupts... */
	tg3_readphy(tp, MII_TG3_ISTAT, &val);
	tg3_readphy(tp, MII_TG3_ISTAT, &val);

	if (tp->phy_flags & TG3_PHYFLG_USE_MI_INTERRUPT)
		tg3_writephy(tp, MII_TG3_IMASK, ~MII_TG3_INT_LINKCHG);
	else if (!(tp->phy_flags & TG3_PHYFLG_IS_FET))
		tg3_writephy(tp, MII_TG3_IMASK, ~0);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701) {
		if (tp->led_ctrl == LED_CTRL_MODE_PHY_1)
			tg3_writephy(tp, MII_TG3_EXT_CTRL,
				     MII_TG3_EXT_CTRL_LNK3_LED_MODE);
		else
			tg3_writephy(tp, MII_TG3_EXT_CTRL, 0);
	}

	current_link_up = 0;
	current_speed = SPEED_INVALID;
	current_duplex = DUPLEX_INVALID;

	if (tp->phy_flags & TG3_PHYFLG_CAPACITIVE_COUPLING) {
		err = tg3_phy_auxctl_read(tp,
					  MII_TG3_AUXCTL_SHDWSEL_MISCTEST,
					  &val);
		if (!err && !(val & (1 << 10))) {
			tg3_phy_auxctl_write(tp,
					     MII_TG3_AUXCTL_SHDWSEL_MISCTEST,
					     val | (1 << 10));
			goto relink;
		}
	}

	bmsr = 0;
	for (i = 0; i < 100; i++) {
		tg3_readphy(tp, MII_BMSR, &bmsr);
		if (!tg3_readphy(tp, MII_BMSR, &bmsr) &&
		    (bmsr & BMSR_LSTATUS))
			break;
		udelay(40);
	}

	if (bmsr & BMSR_LSTATUS) {
		u32 aux_stat, bmcr;

		tg3_readphy(tp, MII_TG3_AUX_STAT, &aux_stat);
		for (i = 0; i < 2000; i++) {
			udelay(10);
			if (!tg3_readphy(tp, MII_TG3_AUX_STAT, &aux_stat) &&
			    aux_stat)
				break;
		}

		tg3_aux_stat_to_speed_duplex(tp, aux_stat,
					     &current_speed,
					     &current_duplex);

		bmcr = 0;
		for (i = 0; i < 200; i++) {
			tg3_readphy(tp, MII_BMCR, &bmcr);
			if (tg3_readphy(tp, MII_BMCR, &bmcr))
				continue;
			if (bmcr && bmcr != 0x7fff)
				break;
			udelay(10);
		}

		lcl_adv = 0;
		rmt_adv = 0;

		tp->link_config.active_speed = current_speed;
		tp->link_config.active_duplex = current_duplex;

		if ((bmcr & BMCR_ANENABLE) &&
		    tg3_copper_is_advertising_all(tp,
					tp->link_config.advertising)) {
			if (tg3_adv_1000T_flowctrl_ok(tp, &lcl_adv,
							  &rmt_adv)) {
				current_link_up = 1;
			}
		}

		if (current_link_up == 1 &&
		    tp->link_config.active_duplex == DUPLEX_FULL)
			tg3_setup_flow_control(tp, lcl_adv, rmt_adv);
	}

relink:
	if (current_link_up == 0) {
		tg3_phy_copper_begin(tp);

		tg3_readphy(tp, MII_BMSR, &bmsr);
		if ((!tg3_readphy(tp, MII_BMSR, &bmsr) && (bmsr & BMSR_LSTATUS)) ||
		    (tp->mac_mode & MAC_MODE_PORT_INT_LPBACK))
			current_link_up = 1;
	}

	tp->mac_mode &= ~MAC_MODE_PORT_MODE_MASK;
	if (current_link_up == 1) {
		if (tp->link_config.active_speed == SPEED_100 ||
		    tp->link_config.active_speed == SPEED_10)
			tp->mac_mode |= MAC_MODE_PORT_MODE_MII;
		else
			tp->mac_mode |= MAC_MODE_PORT_MODE_GMII;
	} else if (tp->phy_flags & TG3_PHYFLG_IS_FET)
		tp->mac_mode |= MAC_MODE_PORT_MODE_MII;
	else
		tp->mac_mode |= MAC_MODE_PORT_MODE_GMII;

	tp->mac_mode &= ~MAC_MODE_HALF_DUPLEX;
	if (tp->link_config.active_duplex == DUPLEX_HALF)
		tp->mac_mode |= MAC_MODE_HALF_DUPLEX;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700) {
		if (current_link_up == 1 &&
		    tg3_5700_link_polarity(tp, tp->link_config.active_speed))
			tp->mac_mode |= MAC_MODE_LINK_POLARITY;
		else
			tp->mac_mode &= ~MAC_MODE_LINK_POLARITY;
	}

	/* ??? Without this setting Netgear GA302T PHY does not
	 * ??? send/receive packets...
	 */
	if ((tp->phy_id & TG3_PHY_ID_MASK) == TG3_PHY_ID_BCM5411 &&
	    tp->pci_chip_rev_id == CHIPREV_ID_5700_ALTIMA) {
		tp->mi_mode |= MAC_MI_MODE_AUTO_POLL;
		tw32_f(MAC_MI_MODE, tp->mi_mode);
		udelay(80);
	}

	tw32_f(MAC_MODE, tp->mac_mode);
	udelay(40);

	/* Enabled attention when the link has changed state. */
	tw32_f(MAC_EVENT, MAC_EVENT_LNKSTATE_CHANGED);
	udelay(40);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 &&
	    current_link_up == 1 &&
	    tp->link_config.active_speed == SPEED_1000 &&
	    (tg3_flag(tp, PCIX_MODE) || tg3_flag(tp, PCI_HIGH_SPEED))) {
		udelay(120);
		/* NOTE: this freezes for mdc? */
		tw32_f(MAC_STATUS,
		     (MAC_STATUS_SYNC_CHANGED |
		      MAC_STATUS_CFG_CHANGED));
		udelay(40);
		tg3_write_mem(tp,
			      NIC_SRAM_FIRMWARE_MBOX,
			      NIC_SRAM_FIRMWARE_MBOX_MAGIC2);
	}

	/* Prevent send BD corruption. */
	if (tg3_flag(tp, CLKREQ_BUG)) {
		u16 oldlnkctl, newlnkctl;

		pci_read_config_word(tp->pdev,
				     tp->pcie_cap + PCI_EXP_LNKCTL,
				     &oldlnkctl);
		if (tp->link_config.active_speed == SPEED_100 ||
		    tp->link_config.active_speed == SPEED_10)
			newlnkctl = oldlnkctl & ~PCI_EXP_LNKCTL_CLKREQ_EN;
		else
			newlnkctl = oldlnkctl | PCI_EXP_LNKCTL_CLKREQ_EN;
		if (newlnkctl != oldlnkctl)
			pci_write_config_word(tp->pdev,
					      tp->pcie_cap + PCI_EXP_LNKCTL,
					      newlnkctl);
	}

	if (current_link_up != netdev_link_ok(tp->dev)) {
		if (current_link_up)
			netdev_link_up(tp->dev);
		else
			netdev_link_down(tp->dev);
		tg3_link_report(tp);
	}

	return 0;
}

int tg3_setup_phy(struct tg3 *tp, int force_reset)
{	DBGP("%s\n", __func__);

	u32 val;
	int err;

#if 0
	if (tp->phy_flags & TG3_PHYFLG_PHY_SERDES)
		err = tg3_setup_fiber_phy(tp, force_reset);
	else if (tp->phy_flags & TG3_PHYFLG_MII_SERDES)
		err = tg3_setup_fiber_mii_phy(tp, force_reset);
	else
#endif
	/* FIXME: add only copper phy variants for now */
	err = tg3_setup_copper_phy(tp, force_reset);

	val = (2 << TX_LENGTHS_IPG_CRS_SHIFT) |
	      (6 << TX_LENGTHS_IPG_SHIFT);
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5720)
		val |= tr32(MAC_TX_LENGTHS) &
		       (TX_LENGTHS_JMB_FRM_LEN_MSK |
			TX_LENGTHS_CNT_DWN_VAL_MSK);

	if (tp->link_config.active_speed == SPEED_1000 &&
	    tp->link_config.active_duplex == DUPLEX_HALF)
		tw32(MAC_TX_LENGTHS, val |
		     (0xff << TX_LENGTHS_SLOT_TIME_SHIFT));
	else
		tw32(MAC_TX_LENGTHS, val |
		     (32 << TX_LENGTHS_SLOT_TIME_SHIFT));

	if (!tg3_flag(tp, 5705_PLUS)) {
		if (netdev_link_ok(tp->dev)) {
			tw32(HOSTCC_STAT_COAL_TICKS, DEFAULT_STAT_COAL_TICKS);
		} else {
			tw32(HOSTCC_STAT_COAL_TICKS, 0);
		}
	}

	val = tr32(PCIE_PWR_MGMT_THRESH);
	if (!netdev_link_ok(tp->dev))
		val = (val & ~PCIE_PWR_MGMT_L1_THRESH_MSK);
	else
		val |= PCIE_PWR_MGMT_L1_THRESH_MSK;
	tw32(PCIE_PWR_MGMT_THRESH, val);

	return err;
}
