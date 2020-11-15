/*******************************************************************************

  Intel(R) 82576 Virtual Function Linux driver
  Copyright(c) 1999 - 2008 Intel Corporation.

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
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

FILE_LICENCE ( GPL2_ONLY );

#include "igbvf_vf.h"


static s32       igbvf_init_mac_params_vf(struct e1000_hw *hw);
static s32       igbvf_check_for_link_vf(struct e1000_hw *hw);
static s32       igbvf_get_link_up_info_vf(struct e1000_hw *hw, u16 *speed,
                                              u16 *duplex);
static s32       igbvf_init_hw_vf(struct e1000_hw *hw);
static s32       igbvf_reset_hw_vf(struct e1000_hw *hw);
static void      igbvf_update_mc_addr_list_vf(struct e1000_hw *hw, u8 *, u32);
static void      igbvf_rar_set_vf(struct e1000_hw *, u8 *, u32);
static s32       igbvf_read_mac_addr_vf(struct e1000_hw *);

/**
 *  igbvf_init_mac_params_vf - Inits MAC params
 *  @hw: pointer to the HW structure
 **/
static s32 igbvf_init_mac_params_vf(struct e1000_hw *hw)
{
	struct e1000_mac_info *mac = &hw->mac;

	DEBUGFUNC("igbvf_init_mac_params_vf");

	/* VF's have no MTA Registers - PF feature only */
	mac->mta_reg_count = 128;
	/* VF's have no access to RAR entries  */
	mac->rar_entry_count = 1;

	/* Function pointers */
	/* reset */
	mac->ops.reset_hw = igbvf_reset_hw_vf;
	/* hw initialization */
	mac->ops.init_hw = igbvf_init_hw_vf;
	/* check for link */
	mac->ops.check_for_link = igbvf_check_for_link_vf;
	/* link info */
	mac->ops.get_link_up_info = igbvf_get_link_up_info_vf;
	/* multicast address update */
	mac->ops.update_mc_addr_list = igbvf_update_mc_addr_list_vf;
	/* set mac address */
	mac->ops.rar_set = igbvf_rar_set_vf;
	/* read mac address */
	mac->ops.read_mac_addr = igbvf_read_mac_addr_vf;


	return E1000_SUCCESS;
}

/**
 *  igbvf_init_function_pointers_vf - Inits function pointers
 *  @hw: pointer to the HW structure
 **/
void igbvf_init_function_pointers_vf(struct e1000_hw *hw)
{
	DEBUGFUNC("igbvf_init_function_pointers_vf");

	hw->mac.ops.init_params = igbvf_init_mac_params_vf;
	hw->mbx.ops.init_params = igbvf_init_mbx_params_vf;
}

/**
 *  igbvf_get_link_up_info_vf - Gets link info.
 *  @hw: pointer to the HW structure
 *  @speed: pointer to 16 bit value to store link speed.
 *  @duplex: pointer to 16 bit value to store duplex.
 *
 *  Since we cannot read the PHY and get accurate link info, we must rely upon
 *  the status register's data which is often stale and inaccurate.
 **/
static s32 igbvf_get_link_up_info_vf(struct e1000_hw *hw, u16 *speed,
                                     u16 *duplex)
{
	s32 status;

	DEBUGFUNC("igbvf_get_link_up_info_vf");

	status = E1000_READ_REG(hw, E1000_STATUS);
	if (status & E1000_STATUS_SPEED_1000) {
		*speed = SPEED_1000;
		DEBUGOUT("1000 Mbs, ");
	} else if (status & E1000_STATUS_SPEED_100) {
		*speed = SPEED_100;
		DEBUGOUT("100 Mbs, ");
	} else {
		*speed = SPEED_10;
		DEBUGOUT("10 Mbs, ");
	}

	if (status & E1000_STATUS_FD) {
		*duplex = FULL_DUPLEX;
		DEBUGOUT("Full Duplex\n");
	} else {
		*duplex = HALF_DUPLEX;
		DEBUGOUT("Half Duplex\n");
	}

	return E1000_SUCCESS;
}

/**
 *  igbvf_reset_hw_vf - Resets the HW
 *  @hw: pointer to the HW structure
 *
 *  VF's provide a function level reset. This is done using bit 26 of ctrl_reg.
 *  This is all the reset we can perform on a VF.
 **/
static s32 igbvf_reset_hw_vf(struct e1000_hw *hw)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	u32 timeout = E1000_VF_INIT_TIMEOUT;
	s32 ret_val = -E1000_ERR_MAC_INIT;
	u32 ctrl, msgbuf[3];
	u8 *addr = (u8 *)(&msgbuf[1]);

	DEBUGFUNC("igbvf_reset_hw_vf");

	DEBUGOUT("Issuing a function level reset to MAC\n");
	ctrl = E1000_READ_REG(hw, E1000_CTRL);
	E1000_WRITE_REG(hw, E1000_CTRL, ctrl | E1000_CTRL_RST);

	/* we cannot reset while the RSTI / RSTD bits are asserted */
	while (!mbx->ops.check_for_rst(hw, 0) && timeout) {
		timeout--;
		usec_delay(5);
	}

	if (timeout) {
		/* mailbox timeout can now become active */
		mbx->timeout = E1000_VF_MBX_INIT_TIMEOUT;

		msgbuf[0] = E1000_VF_RESET;
		mbx->ops.write_posted(hw, msgbuf, 1, 0);

		msec_delay(10);

		/* set our "perm_addr" based on info provided by PF */
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, 0);
		if (!ret_val) {
			if (msgbuf[0] == (E1000_VF_RESET |
						E1000_VT_MSGTYPE_ACK))
				memcpy(hw->mac.perm_addr, addr, 6);
			else
				ret_val = -E1000_ERR_MAC_INIT;
		}
	}

	return ret_val;
}

/**
 *  igbvf_init_hw_vf - Inits the HW
 *  @hw: pointer to the HW structure
 *
 *  Not much to do here except clear the PF Reset indication if there is one.
 **/
static s32 igbvf_init_hw_vf(struct e1000_hw *hw)
{
	DEBUGFUNC("igbvf_init_hw_vf");

	/* attempt to set and restore our mac address */
	igbvf_rar_set_vf(hw, hw->mac.addr, 0);

	return E1000_SUCCESS;
}

/**
 *  igbvf_rar_set_vf - set device MAC address
 *  @hw: pointer to the HW structure
 *  @addr: pointer to the receive address
 *  @index receive address array register
 **/
static void igbvf_rar_set_vf(struct e1000_hw *hw, u8 * addr, u32 index __unused)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[3];
	u8 *msg_addr = (u8 *)(&msgbuf[1]);
	s32 ret_val;

	memset(msgbuf, 0, 12);
	msgbuf[0] = E1000_VF_SET_MAC_ADDR;
	memcpy(msg_addr, addr, 6);
	ret_val = mbx->ops.write_posted(hw, msgbuf, 3, 0);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, 0);

	msgbuf[0] &= ~E1000_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
	    (msgbuf[0] == (E1000_VF_SET_MAC_ADDR | E1000_VT_MSGTYPE_NACK)))
		igbvf_read_mac_addr_vf(hw);
}

/**
 *  igbvf_hash_mc_addr_vf - Generate a multicast hash value
 *  @hw: pointer to the HW structure
 *  @mc_addr: pointer to a multicast address
 *
 *  Generates a multicast address hash value which is used to determine
 *  the multicast filter table array address and new table value.  See
 *  igbvf_mta_set_generic()
 **/
static u32 igbvf_hash_mc_addr_vf(struct e1000_hw *hw, u8 *mc_addr)
{
	u32 hash_value, hash_mask;
	u8 bit_shift = 0;

	DEBUGFUNC("igbvf_hash_mc_addr_generic");

	/* Register count multiplied by bits per register */
	hash_mask = (hw->mac.mta_reg_count * 32) - 1;

	/*
	 * The bit_shift is the number of left-shifts
	 * where 0xFF would still fall within the hash mask.
	 */
	while (hash_mask >> bit_shift != 0xFF)
		bit_shift++;

	hash_value = hash_mask & (((mc_addr[4] >> (8 - bit_shift)) |
	                          (((u16) mc_addr[5]) << bit_shift)));

	return hash_value;
}

/**
 *  igbvf_update_mc_addr_list_vf - Update Multicast addresses
 *  @hw: pointer to the HW structure
 *  @mc_addr_list: array of multicast addresses to program
 *  @mc_addr_count: number of multicast addresses to program
 *
 *  Updates the Multicast Table Array.
 *  The caller must have a packed mc_addr_list of multicast addresses.
 **/
void igbvf_update_mc_addr_list_vf(struct e1000_hw *hw,
                                  u8 *mc_addr_list, u32 mc_addr_count)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[E1000_VFMAILBOX_SIZE];
	u16 *hash_list = (u16 *)&msgbuf[1];
	u32 hash_value;
	u32 i;

	DEBUGFUNC("igbvf_update_mc_addr_list_vf");

	/* Each entry in the list uses 1 16 bit word.  We have 30
	 * 16 bit words available in our HW msg buffer (minus 1 for the
	 * msg type).  That's 30 hash values if we pack 'em right.  If
	 * there are more than 30 MC addresses to add then punt the
	 * extras for now and then add code to handle more than 30 later.
	 * It would be unusual for a server to request that many multi-cast
	 * addresses except for in large enterprise network environments.
	 */

	DEBUGOUT1("MC Addr Count = %d\n", mc_addr_count);

	msgbuf[0] = E1000_VF_SET_MULTICAST;

	if (mc_addr_count > 30) {
		msgbuf[0] |= E1000_VF_SET_MULTICAST_OVERFLOW;
		mc_addr_count = 30;
	}

	msgbuf[0] |= mc_addr_count << E1000_VT_MSGINFO_SHIFT;

	for (i = 0; i < mc_addr_count; i++) {
		hash_value = igbvf_hash_mc_addr_vf(hw, mc_addr_list);
		DEBUGOUT1("Hash value = 0x%03X\n", hash_value);
		hash_list[i] = hash_value & 0x0FFF;
		mc_addr_list += ETH_ADDR_LEN;
	}

	mbx->ops.write_posted(hw, msgbuf, E1000_VFMAILBOX_SIZE, 0);
}

/**
 *  igbvf_vfta_set_vf - Set/Unset vlan filter table address
 *  @hw: pointer to the HW structure
 *  @vid: determines the vfta register and bit to set/unset
 *  @set: if true then set bit, else clear bit
 **/
void igbvf_vfta_set_vf(struct e1000_hw *hw, u16 vid, bool set)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];

	msgbuf[0] = E1000_VF_SET_VLAN;
	msgbuf[1] = vid;
	/* Setting the 8 bit field MSG INFO to TRUE indicates "add" */
	if (set)
		msgbuf[0] |= E1000_VF_SET_VLAN_ADD;

	mbx->ops.write_posted(hw, msgbuf, 2, 0);
}

/** igbvf_rlpml_set_vf - Set the maximum receive packet length
 *  @hw: pointer to the HW structure
 *  @max_size: value to assign to max frame size
 **/
void igbvf_rlpml_set_vf(struct e1000_hw *hw, u16 max_size)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];

	msgbuf[0] = E1000_VF_SET_LPE;
	msgbuf[1] = max_size;

	mbx->ops.write_posted(hw, msgbuf, 2, 0);
}

/**
 *  igbvf_promisc_set_vf - Set flags for Unicast or Multicast promisc
 *  @hw: pointer to the HW structure
 *  @uni: boolean indicating unicast promisc status
 *  @multi: boolean indicating multicast promisc status
 **/
s32 igbvf_promisc_set_vf(struct e1000_hw *hw, enum e1000_promisc_type type)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	u32 msgbuf = E1000_VF_SET_PROMISC;
	s32 ret_val;

	switch (type) {
	case e1000_promisc_multicast:
		msgbuf |= E1000_VF_SET_PROMISC_MULTICAST;
		break;
	case e1000_promisc_enabled:
		msgbuf |= E1000_VF_SET_PROMISC_MULTICAST;
	case e1000_promisc_unicast:
		msgbuf |= E1000_VF_SET_PROMISC_UNICAST;
	case e1000_promisc_disabled:
		break;
	default:
		return -E1000_ERR_MAC_INIT;
	}

	 ret_val = mbx->ops.write_posted(hw, &msgbuf, 1, 0);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, &msgbuf, 1, 0);

	if (!ret_val && !(msgbuf & E1000_VT_MSGTYPE_ACK))
		ret_val = -E1000_ERR_MAC_INIT;

	return ret_val;
}

/**
 *  igbvf_read_mac_addr_vf - Read device MAC address
 *  @hw: pointer to the HW structure
 **/
static s32 igbvf_read_mac_addr_vf(struct e1000_hw *hw)
{
	int i;

	for (i = 0; i < ETH_ADDR_LEN; i++)
		hw->mac.addr[i] = hw->mac.perm_addr[i];

	return E1000_SUCCESS;
}

/**
 *  igbvf_check_for_link_vf - Check for link for a virtual interface
 *  @hw: pointer to the HW structure
 *
 *  Checks to see if the underlying PF is still talking to the VF and
 *  if it is then it reports the link state to the hardware, otherwise
 *  it reports link down and returns an error.
 **/
static s32 igbvf_check_for_link_vf(struct e1000_hw *hw)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	struct e1000_mac_info *mac = &hw->mac;
	s32 ret_val = E1000_SUCCESS;
	u32 in_msg = 0;

	DEBUGFUNC("igbvf_check_for_link_vf");

	/*
	 * We only want to run this if there has been a rst asserted.
	 * in this case that could mean a link change, device reset,
	 * or a virtual function reset
	 */

	/* If we were hit with a reset drop the link */
	if (!mbx->ops.check_for_rst(hw, 0))
		mac->get_link_status = true;

	if (!mac->get_link_status)
		goto out;

	/* if link status is down no point in checking to see if pf is up */
	if (!(E1000_READ_REG(hw, E1000_STATUS) & E1000_STATUS_LU))
		goto out;

	/* if the read failed it could just be a mailbox collision, best wait
	 * until we are called again and don't report an error */
	if (mbx->ops.read(hw, &in_msg, 1, 0))
		goto out;

	/* if incoming message isn't clear to send we are waiting on response */
	if (!(in_msg & E1000_VT_MSGTYPE_CTS)) {
		/* message is not CTS and is NACK we have lost CTS status */
		if (in_msg & E1000_VT_MSGTYPE_NACK)
			ret_val = -E1000_ERR_MAC_INIT;
		goto out;
	}

	/* at this point we know the PF is talking to us, check and see if
	 * we are still accepting timeout or if we had a timeout failure.
	 * if we failed then we will need to reinit */
	if (!mbx->timeout) {
		ret_val = -E1000_ERR_MAC_INIT;
		goto out;
	}

	/* if we passed all the tests above then the link is up and we no
	 * longer need to check for link */
	mac->get_link_status = false;

out:
	return ret_val;
}

