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

#ifndef _IGBVF_MBX_H_
#define _IGBVF_MBX_H_

#include "igbvf_vf.h"

/* Define mailbox specific registers */
#define E1000_V2PMAILBOX(_n)   (0x00C40 + (4 * (_n)))
#define E1000_VMBMEM(_n)       (0x00800 + (64 * (_n)))

/* Define mailbox register bits */
#define E1000_V2PMAILBOX_REQ   0x00000001 /* Request for PF Ready bit */
#define E1000_V2PMAILBOX_ACK   0x00000002 /* Ack PF message received */
#define E1000_V2PMAILBOX_VFU   0x00000004 /* VF owns the mailbox buffer */
#define E1000_V2PMAILBOX_PFU   0x00000008 /* PF owns the mailbox buffer */
#define E1000_V2PMAILBOX_PFSTS 0x00000010 /* PF wrote a message in the MB */
#define E1000_V2PMAILBOX_PFACK 0x00000020 /* PF ack the previous VF msg */
#define E1000_V2PMAILBOX_RSTI  0x00000040 /* PF has reset indication */
#define E1000_V2PMAILBOX_RSTD  0x00000080 /* PF has indicated reset done */
#define E1000_V2PMAILBOX_R2C_BITS 0x000000B0 /* All read to clear bits */

#define E1000_VFMAILBOX_SIZE   16 /* 16 32 bit words - 64 bytes */

/* If it's a E1000_VF_* msg then it originates in the VF and is sent to the
 * PF.  The reverse is true if it is E1000_PF_*.
 * Message ACK's are the value or'd with 0xF0000000
 */
#define E1000_VT_MSGTYPE_ACK      0x80000000  /* Messages below or'd with
                                               * this are the ACK */
#define E1000_VT_MSGTYPE_NACK     0x40000000  /* Messages below or'd with
                                               * this are the NACK */
#define E1000_VT_MSGTYPE_CTS      0x20000000  /* Indicates that VF is still
                                                 clear to send requests */
#define E1000_VT_MSGINFO_SHIFT    16
/* bits 23:16 are used for exra info for certain messages */
#define E1000_VT_MSGINFO_MASK     (0xFF << E1000_VT_MSGINFO_SHIFT)

#define E1000_VF_RESET            0x01 /* VF requests reset */
#define E1000_VF_SET_MAC_ADDR     0x02 /* VF requests to set MAC addr */
#define E1000_VF_SET_MULTICAST    0x03 /* VF requests to set MC addr */
#define E1000_VF_SET_MULTICAST_COUNT_MASK (0x1F << E1000_VT_MSGINFO_SHIFT)
#define E1000_VF_SET_MULTICAST_OVERFLOW   (0x80 << E1000_VT_MSGINFO_SHIFT)
#define E1000_VF_SET_VLAN         0x04 /* VF requests to set VLAN */
#define E1000_VF_SET_VLAN_ADD             (0x01 << E1000_VT_MSGINFO_SHIFT)
#define E1000_VF_SET_LPE          0x05 /* VF requests to set VMOLR.LPE */
#define E1000_VF_SET_PROMISC      0x06 /*VF requests to clear VMOLR.ROPE/MPME*/
#define E1000_VF_SET_PROMISC_UNICAST      (0x01 << E1000_VT_MSGINFO_SHIFT)
#define E1000_VF_SET_PROMISC_MULTICAST    (0x02 << E1000_VT_MSGINFO_SHIFT)

#define E1000_PF_CONTROL_MSG      0x0100 /* PF control message */

#define E1000_VF_MBX_INIT_TIMEOUT 2000 /* number of retries on mailbox */
#define E1000_VF_MBX_INIT_DELAY   500  /* microseconds between retries */

void igbvf_init_mbx_ops_generic(struct e1000_hw *hw);
s32 igbvf_init_mbx_params_vf(struct e1000_hw *);

#endif /* _IGBVF_MBX_H_ */
