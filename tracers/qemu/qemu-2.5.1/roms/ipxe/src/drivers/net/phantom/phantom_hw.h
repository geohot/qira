#ifndef _PHANTOM_HW_H
#define _PHANTOM_HW_H

/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
 * Copyright (C) 2008 NetXen, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * @file
 *
 * Phantom hardware definitions
 *
 */

/** A Phantom RX descriptor */
struct phantom_rds_pb {
	pseudo_bit_t handle[16];		/**< Reference handle */
	pseudo_bit_t flags[16];			/**< Flags */
	pseudo_bit_t length[32];		/**< Buffer length */

	/* --------------------------------------------------------------- */

	pseudo_bit_t dma_addr[64];		/**< Buffer DMA address */

};

/** A Phantom RX status descriptor */
struct phantom_sds_pb {
	pseudo_bit_t port[4];			/**< Port number */
	pseudo_bit_t status[4];			/**< Checksum status */
	pseudo_bit_t type[4];			/**< Type */
	pseudo_bit_t total_length[16];		/**< Total packet length */
	pseudo_bit_t handle[16];		/**< Reference handle */
	pseudo_bit_t protocol[4];		/**< Protocol */
	pseudo_bit_t pkt_offset[5];		/**< Offset to packet start */
	pseudo_bit_t desc_cnt[3];		/**< Descriptor count */
	pseudo_bit_t owner[2];			/**< Owner */
	pseudo_bit_t opcode[6];			/**< Opcode */

	/* --------------------------------------------------------------- */

	pseudo_bit_t hash_value[32];		/**< RSS hash value */
	pseudo_bit_t hash_type[8];		/**< RSS hash type */
	pseudo_bit_t lro[8];			/**< LRO data */
};

/** Phantom RX status opcodes */
enum phantom_sds_opcode {
	UNM_SYN_OFFLOAD = 0x03,
	UNM_RXPKT_DESC = 0x04,
};

/** A Phantom TX descriptor */
struct phantom_tx_cds_pb {
	pseudo_bit_t tcp_hdr_offset[8];		/**< TCP header offset (LSO) */
        pseudo_bit_t ip_hdr_offset[8];		/**< IP header offset (LSO) */
	pseudo_bit_t flags[7];			/**< Flags */
	pseudo_bit_t opcode[6];			/**< Opcode */
	pseudo_bit_t hw_rsvd_0[3];		/**< (Reserved) */
	pseudo_bit_t num_buffers[8];		/**< Total number of buffers */
	pseudo_bit_t length[24];		/**< Total length */

	/* --------------------------------------------------------------- */

	pseudo_bit_t buffer2_dma_addr[64];	/**< Buffer 2 DMA address */

	/* --------------------------------------------------------------- */

	pseudo_bit_t handle[16];		/**< Reference handle (n/a) */
	pseudo_bit_t port_mss[16];		/**< TCP MSS (LSO) */
	pseudo_bit_t port[4];			/**< Port */
	pseudo_bit_t context_id[4];		/**< Context ID */
	pseudo_bit_t total_hdr_length[8];	/**< MAC+IP+TCP header (LSO) */
	pseudo_bit_t conn_id[16];		/**< IPSec connection ID */

	/* --------------------------------------------------------------- */

	pseudo_bit_t buffer3_dma_addr[64];	/**< Buffer 3 DMA address */

	/* --------------------------------------------------------------- */

	pseudo_bit_t buffer1_dma_addr[64];	/**< Buffer 1 DMA address */

	/* --------------------------------------------------------------- */

	pseudo_bit_t buffer1_length[16];	/**< Buffer 1 length */
	pseudo_bit_t buffer2_length[16];	/**< Buffer 2 length */
	pseudo_bit_t buffer3_length[16];	/**< Buffer 3 length */
	pseudo_bit_t buffer4_length[16];	/**< Buffer 4 length */

	/* --------------------------------------------------------------- */

	pseudo_bit_t buffer4_dma_addr[64];	/**< Buffer 4 DMA address */

	/* --------------------------------------------------------------- */

	pseudo_bit_t hw_rsvd_1[64];		/**< (Reserved) */
};

/** A Phantom MAC address request body */
struct phantom_nic_request_body_mac_request_pb {
	pseudo_bit_t opcode[8];			/**< Opcode */
	pseudo_bit_t tag[8];			/**< Tag */
	pseudo_bit_t mac_addr_0[8];		/**< MAC address byte 0 */
	pseudo_bit_t mac_addr_1[8];		/**< MAC address byte 1 */
	pseudo_bit_t mac_addr_2[8];		/**< MAC address byte 2 */
	pseudo_bit_t mac_addr_3[8];		/**< MAC address byte 3 */
	pseudo_bit_t mac_addr_4[8];		/**< MAC address byte 4 */
	pseudo_bit_t mac_addr_5[8];		/**< MAC address byte 5 */
};

/** Phantom MAC request opcodes */
enum phantom_mac_request_opcode {
	UNM_MAC_ADD = 0x01,			/**< Add MAC address */
	UNM_MAC_DEL = 0x02,			/**< Delete MAC address */
};

/** A Phantom NIC request command descriptor */
struct phantom_nic_request_cds_pb {
	struct {
		pseudo_bit_t dst_minor[18];
		pseudo_bit_t dst_subq[1];
		pseudo_bit_t dst_major[4];
		pseudo_bit_t opcode[6];
		pseudo_bit_t hw_rsvd_0[3];
		pseudo_bit_t msginfo[24];
		pseudo_bit_t hw_rsvd_1[2];
		pseudo_bit_t qmsg_type[6];
	} common;

	/* --------------------------------------------------------------- */

	struct {
		pseudo_bit_t opcode[8];
		pseudo_bit_t comp_id [8];
		pseudo_bit_t context_id[16];
		pseudo_bit_t need_completion[1];
		pseudo_bit_t hw_rsvd_0[23];
		pseudo_bit_t sub_opcode[8];
	} header;

	/* --------------------------------------------------------------- */

	union {
		struct phantom_nic_request_body_mac_request_pb mac_request;
		pseudo_bit_t padding[384];
	} body;
};

/** Phantom NIC request opcodes */
enum phantom_nic_request_opcode {
	UNM_MAC_EVENT = 0x01,			/**< Add/delete MAC address */
};

/** A Phantom command descriptor */
union phantom_cds_pb {
	struct phantom_tx_cds_pb tx;
	struct phantom_nic_request_cds_pb nic_request;
};

/** Phantom command descriptor opcodes */
enum phantom_cds_opcode {
	UNM_TX_ETHER_PKT = 0x01,		/**< Transmit raw Ethernet */
	UNM_NIC_REQUEST = 0x14,			/**< NIC request */
};

#endif /* _PHANTOM_HW_H */
