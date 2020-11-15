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

#include "igbvf_mbx.h"

/**
 *  igbvf_poll_for_msg - Wait for message notification
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message notification
 **/
static s32 igbvf_poll_for_msg(struct e1000_hw *hw, u16 mbx_id)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	DEBUGFUNC("igbvf_poll_for_msg");

	if (!countdown || !mbx->ops.check_for_msg)
		goto out;

	while (countdown && mbx->ops.check_for_msg(hw, mbx_id)) {
		countdown--;
		if (!countdown)
			break;
		usec_delay(mbx->usec_delay);
	}

	/* if we failed, all future posted messages fail until reset */
	if (!countdown)
		mbx->timeout = 0;
out:
	return countdown ? E1000_SUCCESS : -E1000_ERR_MBX;
}

/**
 *  igbvf_poll_for_ack - Wait for message acknowledgement
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message acknowledgement
 **/
static s32 igbvf_poll_for_ack(struct e1000_hw *hw, u16 mbx_id)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	DEBUGFUNC("igbvf_poll_for_ack");

	if (!countdown || !mbx->ops.check_for_ack)
		goto out;

	while (countdown && mbx->ops.check_for_ack(hw, mbx_id)) {
		countdown--;
		if (!countdown)
			break;
		usec_delay(mbx->usec_delay);
	}

	/* if we failed, all future posted messages fail until reset */
	if (!countdown)
		mbx->timeout = 0;
out:
	return countdown ? E1000_SUCCESS : -E1000_ERR_MBX;
}

/**
 *  igbvf_read_posted_mbx - Wait for message notification and receive message
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message notification and
 *  copied it into the receive buffer.
 **/
static s32 igbvf_read_posted_mbx(struct e1000_hw *hw, u32 *msg, u16 size,
                                 u16 mbx_id)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	s32 ret_val = -E1000_ERR_MBX;

	DEBUGFUNC("igbvf_read_posted_mbx");

	if (!mbx->ops.read)
		goto out;

	ret_val = igbvf_poll_for_msg(hw, mbx_id);

	/* if ack received read message, otherwise we timed out */
	if (!ret_val)
		ret_val = mbx->ops.read(hw, msg, size, mbx_id);
out:
	return ret_val;
}

/**
 *  igbvf_write_posted_mbx - Write a message to the mailbox, wait for ack
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully copied message into the buffer and
 *  received an ack to that message within delay * timeout period
 **/
static s32 igbvf_write_posted_mbx(struct e1000_hw *hw, u32 *msg, u16 size,
                                  u16 mbx_id)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	s32 ret_val = -E1000_ERR_MBX;

	DEBUGFUNC("igbvf_write_posted_mbx");

	/* exit if either we can't write or there isn't a defined timeout */
	if (!mbx->ops.write || !mbx->timeout)
		goto out;

	/* send msg */
	ret_val = mbx->ops.write(hw, msg, size, mbx_id);

	/* if msg sent wait until we receive an ack */
	if (!ret_val)
		ret_val = igbvf_poll_for_ack(hw, mbx_id);
out:
	return ret_val;
}

/**
 *  igbvf_init_mbx_ops_generic - Initialize NVM function pointers
 *  @hw: pointer to the HW structure
 *
 *  Setups up the function pointers to no-op functions
 **/
void igbvf_init_mbx_ops_generic(struct e1000_hw *hw)
{
	struct e1000_mbx_info *mbx = &hw->mbx;
	mbx->ops.read_posted = igbvf_read_posted_mbx;
	mbx->ops.write_posted = igbvf_write_posted_mbx;
}

/**
 *  igbvf_read_v2p_mailbox - read v2p mailbox
 *  @hw: pointer to the HW structure
 *
 *  This function is used to read the v2p mailbox without losing the read to
 *  clear status bits.
 **/
static u32 igbvf_read_v2p_mailbox(struct e1000_hw *hw)
{
	u32 v2p_mailbox = E1000_READ_REG(hw, E1000_V2PMAILBOX(0));

	v2p_mailbox |= hw->dev_spec.vf.v2p_mailbox;
	hw->dev_spec.vf.v2p_mailbox |= v2p_mailbox & E1000_V2PMAILBOX_R2C_BITS;

	return v2p_mailbox;
}

/**
 *  igbvf_check_for_bit_vf - Determine if a status bit was set
 *  @hw: pointer to the HW structure
 *  @mask: bitmask for bits to be tested and cleared
 *
 *  This function is used to check for the read to clear bits within
 *  the V2P mailbox.
 **/
static s32 igbvf_check_for_bit_vf(struct e1000_hw *hw, u32 mask)
{
	u32 v2p_mailbox = igbvf_read_v2p_mailbox(hw);
	s32 ret_val = -E1000_ERR_MBX;

	if (v2p_mailbox & mask)
		ret_val = E1000_SUCCESS;

	hw->dev_spec.vf.v2p_mailbox &= ~mask;

	return ret_val;
}

/**
 *  igbvf_check_for_msg_vf - checks to see if the PF has sent mail
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to check
 *
 *  returns SUCCESS if the PF has set the Status bit or else ERR_MBX
 **/
static s32 igbvf_check_for_msg_vf(struct e1000_hw *hw, u16 mbx_id __unused)
{
	s32 ret_val = -E1000_ERR_MBX;

	DEBUGFUNC("igbvf_check_for_msg_vf");

	if (!igbvf_check_for_bit_vf(hw, E1000_V2PMAILBOX_PFSTS)) {
		ret_val = E1000_SUCCESS;
		hw->mbx.stats.reqs++;
	}

	return ret_val;
}

/**
 *  igbvf_check_for_ack_vf - checks to see if the PF has ACK'd
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to check
 *
 *  returns SUCCESS if the PF has set the ACK bit or else ERR_MBX
 **/
static s32 igbvf_check_for_ack_vf(struct e1000_hw *hw, u16 mbx_id __unused)
{
	s32 ret_val = -E1000_ERR_MBX;

	DEBUGFUNC("igbvf_check_for_ack_vf");

	if (!igbvf_check_for_bit_vf(hw, E1000_V2PMAILBOX_PFACK)) {
		ret_val = E1000_SUCCESS;
		hw->mbx.stats.acks++;
	}

	return ret_val;
}

/**
 *  igbvf_check_for_rst_vf - checks to see if the PF has reset
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to check
 *
 *  returns true if the PF has set the reset done bit or else false
 **/
static s32 igbvf_check_for_rst_vf(struct e1000_hw *hw, u16 mbx_id __unused)
{
	s32 ret_val = -E1000_ERR_MBX;

	DEBUGFUNC("igbvf_check_for_rst_vf");

	if (!igbvf_check_for_bit_vf(hw, (E1000_V2PMAILBOX_RSTD |
	                                 E1000_V2PMAILBOX_RSTI))) {
		ret_val = E1000_SUCCESS;
		hw->mbx.stats.rsts++;
	}

	return ret_val;
}

/**
 *  igbvf_obtain_mbx_lock_vf - obtain mailbox lock
 *  @hw: pointer to the HW structure
 *
 *  return SUCCESS if we obtained the mailbox lock
 **/
static s32 igbvf_obtain_mbx_lock_vf(struct e1000_hw *hw)
{
	s32 ret_val = -E1000_ERR_MBX;

	DEBUGFUNC("igbvf_obtain_mbx_lock_vf");

	/* Take ownership of the buffer */
	E1000_WRITE_REG(hw, E1000_V2PMAILBOX(0), E1000_V2PMAILBOX_VFU);

	/* reserve mailbox for vf use */
	if (igbvf_read_v2p_mailbox(hw) & E1000_V2PMAILBOX_VFU)
		ret_val = E1000_SUCCESS;

	return ret_val;
}

/**
 *  igbvf_write_mbx_vf - Write a message to the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully copied message into the buffer
 **/
static s32 igbvf_write_mbx_vf(struct e1000_hw *hw, u32 *msg, u16 size,
                              u16 mbx_id __unused)
{
	s32 ret_val;
	u16 i;


	DEBUGFUNC("igbvf_write_mbx_vf");

	/* lock the mailbox to prevent pf/vf race condition */
	ret_val = igbvf_obtain_mbx_lock_vf(hw);
	if (ret_val)
		goto out_no_write;

	/* flush msg and acks as we are overwriting the message buffer */
	igbvf_check_for_msg_vf(hw, 0);
	igbvf_check_for_ack_vf(hw, 0);

	/* copy the caller specified message to the mailbox memory buffer */
	for (i = 0; i < size; i++)
		E1000_WRITE_REG_ARRAY(hw, E1000_VMBMEM(0), i, msg[i]);

	/* update stats */
	hw->mbx.stats.msgs_tx++;

	/* Drop VFU and interrupt the PF to tell it a message has been sent */
	E1000_WRITE_REG(hw, E1000_V2PMAILBOX(0), E1000_V2PMAILBOX_REQ);

out_no_write:
	return ret_val;
}

/**
 *  igbvf_read_mbx_vf - Reads a message from the inbox intended for vf
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to read
 *
 *  returns SUCCESS if it successfuly read message from buffer
 **/
static s32 igbvf_read_mbx_vf(struct e1000_hw *hw, u32 *msg, u16 size,
                             u16 mbx_id __unused)
{
	s32 ret_val = E1000_SUCCESS;
	u16 i;

	DEBUGFUNC("igbvf_read_mbx_vf");

	/* lock the mailbox to prevent pf/vf race condition */
	ret_val = igbvf_obtain_mbx_lock_vf(hw);
	if (ret_val)
		goto out_no_read;

	/* copy the message from the mailbox memory buffer */
	for (i = 0; i < size; i++)
		msg[i] = E1000_READ_REG_ARRAY(hw, E1000_VMBMEM(0), i);

	/* Acknowledge receipt and release mailbox, then we're done */
	E1000_WRITE_REG(hw, E1000_V2PMAILBOX(0), E1000_V2PMAILBOX_ACK);

	/* update stats */
	hw->mbx.stats.msgs_rx++;

out_no_read:
	return ret_val;
}

/**
 *  igbvf_init_mbx_params_vf - set initial values for vf mailbox
 *  @hw: pointer to the HW structure
 *
 *  Initializes the hw->mbx struct to correct values for vf mailbox
 */
s32 igbvf_init_mbx_params_vf(struct e1000_hw *hw)
{
	struct e1000_mbx_info *mbx = &hw->mbx;

	/* start mailbox as timed out and let the reset_hw call set the timeout
	 * value to begin communications */
	mbx->timeout = 0;
	mbx->usec_delay = E1000_VF_MBX_INIT_DELAY;

	mbx->size = E1000_VFMAILBOX_SIZE;

	mbx->ops.read = igbvf_read_mbx_vf;
	mbx->ops.write = igbvf_write_mbx_vf;
	mbx->ops.read_posted = igbvf_read_posted_mbx;
	mbx->ops.write_posted = igbvf_write_posted_mbx;
	mbx->ops.check_for_msg = igbvf_check_for_msg_vf;
	mbx->ops.check_for_ack = igbvf_check_for_ack_vf;
	mbx->ops.check_for_rst = igbvf_check_for_rst_vf;

	mbx->stats.msgs_tx = 0;
	mbx->stats.msgs_rx = 0;
	mbx->stats.reqs = 0;
	mbx->stats.acks = 0;
	mbx->stats.rsts = 0;

	return E1000_SUCCESS;
}

