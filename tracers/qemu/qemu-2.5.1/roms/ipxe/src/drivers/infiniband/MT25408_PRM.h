/*
  This software is available to you under a choice of one of two
  licenses.  You may choose to be licensed under the terms of the GNU
  General Public License (GPL) Version 2, available at
  <http://www.fsf.org/copyleft/gpl.html>, or the OpenIB.org BSD
  license, available in the LICENSE.TXT file accompanying this
  software.  These details are also available at
  <http://openib.org/license.html>.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.

  Copyright (c) 2004 Mellanox Technologies Ltd.  All rights reserved.
*/

FILE_LICENCE ( GPL2_ONLY );

/***
 *** This file was generated at "Mon Apr 16 23:22:02 2007"
 *** by:
 ***    % csp_bf -copyright=/mswg/misc/license-header.txt -prefix hermonprm_ -bits -fixnames MT25408_PRM.csp
 ***/

#ifndef H_prefix_hermonprm_bits_fixnames_MT25408_PRM_csp_H
#define H_prefix_hermonprm_bits_fixnames_MT25408_PRM_csp_H

/* UD Address Vector */

struct hermonprm_ud_address_vector_st {	/* Little Endian */
    pseudo_bit_t	pd[0x00018];           /* Protection Domain */
    pseudo_bit_t	port_number[0x00002];  /* Port number
                                                 1 - Port 1
                                                 2 - Port 2
                                                 other - reserved */
    pseudo_bit_t	reserved0[0x00005];
    pseudo_bit_t	fl[0x00001];           /* force loopback */
/* -------------- */
    pseudo_bit_t	rlid[0x00010];         /* Remote (Destination) LID */
    pseudo_bit_t	my_lid_path_bits[0x00007];/* Source LID - the lower 7 bits (upper bits are taken from PortInfo) */
    pseudo_bit_t	g[0x00001];            /* Global address enable - if set, GRH will be formed for packet header */
    pseudo_bit_t	reserved1[0x00008];
/* -------------- */
    pseudo_bit_t	hop_limit[0x00008];    /* IPv6 hop limit */
    pseudo_bit_t	max_stat_rate[0x00004];/* Maximum static rate control. 
                                                 0 - 4X injection rate
                                                 1 - 1X injection rate
                                                 other - reserved
                                                  */
    pseudo_bit_t	reserved2[0x00004];
    pseudo_bit_t	mgid_index[0x00007];   /* Index to port GID table
                                                 mgid_index = (port_number-1) * 2^log_max_gid + gid_index
                                                 Where:
                                                 1. log_max_gid is taken from QUERY_DEV_CAP command
                                                 2. gid_index is the index to the GID table */
    pseudo_bit_t	reserved3[0x00009];
/* -------------- */
    pseudo_bit_t	flow_label[0x00014];   /* IPv6 flow label */
    pseudo_bit_t	tclass[0x00008];       /* IPv6 TClass */
    pseudo_bit_t	sl[0x00004];           /* InfiniBand Service Level (SL) */
/* -------------- */
    pseudo_bit_t	rgid_127_96[0x00020];  /* Remote GID[127:96] */
/* -------------- */
    pseudo_bit_t	rgid_95_64[0x00020];   /* Remote GID[95:64] */
/* -------------- */
    pseudo_bit_t	rgid_63_32[0x00020];   /* Remote GID[63:32] */
/* -------------- */
    pseudo_bit_t	rgid_31_0[0x00020];    /* Remote GID[31:0] if G bit is set. Must be set to 0x2 if G bit is cleared. */
/* -------------- */
}; 

/* Send doorbell */

struct hermonprm_send_doorbell_st {	/* Little Endian */
    pseudo_bit_t	nopcode[0x00005];      /* Opcode of descriptor to be executed */
    pseudo_bit_t	f[0x00001];            /* Fence bit. If set, descriptor is fenced */
    pseudo_bit_t	reserved0[0x00002];
    pseudo_bit_t	wqe_counter[0x00010];  /* Modulo-64K counter of WQEs posted to the QP since its creation excluding the newly posted WQEs in this doorbell. Should be zero for the first doorbell on the QP */
    pseudo_bit_t	wqe_cnt[0x00008];      /* Number of WQEs posted with this doorbell. Must be grater then zero. */
/* -------------- */
    pseudo_bit_t	nds[0x00006];          /* Next descriptor size (in 16-byte chunks) */
    pseudo_bit_t	reserved1[0x00002];
    pseudo_bit_t	qpn[0x00018];          /* QP number this doorbell is rung on */
/* -------------- */
}; 

/* Send wqe segment data inline */

struct hermonprm_wqe_segment_data_inline_st {	/* Little Endian */
    pseudo_bit_t	byte_count[0x0000a];   /* Not including padding for 16Byte chunks */
    pseudo_bit_t	reserved0[0x00015];
    pseudo_bit_t	always1[0x00001];
/* -------------- */
    pseudo_bit_t	data[0x00018];         /* Data may be more this segment size - in 16Byte chunks */
    pseudo_bit_t	reserved1[0x00008];
/* -------------- */
    pseudo_bit_t	reserved2[0x00040];
/* -------------- */
}; 

/* Send wqe segment data ptr */

struct hermonprm_wqe_segment_data_ptr_st {	/* Little Endian */
    pseudo_bit_t	byte_count[0x0001f];
    pseudo_bit_t	always0[0x00001];
/* -------------- */
    pseudo_bit_t	l_key[0x00020];
/* -------------- */
    pseudo_bit_t	local_address_h[0x00020];
/* -------------- */
    pseudo_bit_t	local_address_l[0x00020];
/* -------------- */
}; 

/* Send wqe segment rd */

struct hermonprm_local_invalidate_segment_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00040];
/* -------------- */
    pseudo_bit_t	mem_key[0x00018];
    pseudo_bit_t	reserved1[0x00008];
/* -------------- */
    pseudo_bit_t	reserved2[0x000a0];
/* -------------- */
}; 

/* Fast_Registration_Segment   ####michal - doesn't match PRM (fields were added, see below) new table size in bytes -  0x30 */

struct hermonprm_fast_registration_segment_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x0001b];
    pseudo_bit_t	lr[0x00001];           /* If set - Local Read access will be enabled */
    pseudo_bit_t	lw[0x00001];           /* If set - Local Write access will be enabled */
    pseudo_bit_t	rr[0x00001];           /* If set - Remote Read access will be enabled */
    pseudo_bit_t	rw[0x00001];           /* If set - Remote Write access will be enabled */
    pseudo_bit_t	a[0x00001];            /* If set - Remote Atomic access will be enabled */
/* -------------- */
    pseudo_bit_t	pbl_ptr_63_32[0x00020];/* Physical address pointer [63:32] to the physical buffer list  ### michal - this field is replaced with mem_key .32 */
/* -------------- */
    pseudo_bit_t	mem_key[0x00020];      /* Memory Key on which the fast registration is executed on. ###michal-this field is replaced with pbl_ptr_63_32 */
/* -------------- */
    pseudo_bit_t	page_size[0x00005];    /* Page size used for the region. Actual size is [4K]*2^Page_size bytes.
                                                 page_size should be less than 20. ###michal - field doesn't exsist (see replacement above) */
    pseudo_bit_t	reserved1[0x00002];
    pseudo_bit_t	zb[0x00001];           /* Zero Based Region               ###michal - field doesn't exsist (see replacement above) */
    pseudo_bit_t	pbl_ptr_31_8[0x00018]; /* Physical address pointer [31:8] to the physical buffer list    ###michal - field doesn't exsist (see replacement above) */
/* -------------- */
    pseudo_bit_t	start_address_h[0x00020];/* Start Address[63:32] - Virtual Address where this region starts */
/* -------------- */
    pseudo_bit_t	start_address_l[0x00020];/* Start Address[31:0] - Virtual Address where this region starts */
/* -------------- */
    pseudo_bit_t	reg_len_h[0x00020];    /* Region Length[63:32] */
/* -------------- */
    pseudo_bit_t	reg_len_l[0x00020];    /* Region Length[31:0] */
/* -------------- */
}; 

/* Send wqe segment atomic */

struct hermonprm_wqe_segment_atomic_st {	/* Little Endian */
    pseudo_bit_t	swap_add_h[0x00020];
/* -------------- */
    pseudo_bit_t	swap_add_l[0x00020];
/* -------------- */
    pseudo_bit_t	compare_h[0x00020];
/* -------------- */
    pseudo_bit_t	compare_l[0x00020];
/* -------------- */
}; 

/* Send wqe segment remote address */

struct hermonprm_wqe_segment_remote_address_st {	/* Little Endian */
    pseudo_bit_t	remote_virt_addr_h[0x00020];
/* -------------- */
    pseudo_bit_t	remote_virt_addr_l[0x00020];
/* -------------- */
    pseudo_bit_t	rkey[0x00020];
/* -------------- */
    pseudo_bit_t	reserved0[0x00020];
/* -------------- */
}; 

/* end wqe segment bind */

struct hermonprm_wqe_segment_bind_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x0001d];
    pseudo_bit_t	rr[0x00001];           /* If set, Remote Read Enable for bound window. */
    pseudo_bit_t	rw[0x00001];           /* If set, Remote Write Enable for bound window.
                                                  */
    pseudo_bit_t	a[0x00001];            /* If set, Atomic Enable for bound window. */
/* -------------- */
    pseudo_bit_t	reserved1[0x0001e];
    pseudo_bit_t	zb[0x00001];           /* If set, Window is Zero Based. */
    pseudo_bit_t	type[0x00001];         /* Window type.
                                                 0 - Type one window
                                                 1 - Type two window
                                                  */
/* -------------- */
    pseudo_bit_t	new_rkey[0x00020];     /* The new RKey of window to bind */
/* -------------- */
    pseudo_bit_t	region_lkey[0x00020];  /* Local key of region, which window will be bound to */
/* -------------- */
    pseudo_bit_t	start_address_h[0x00020];
/* -------------- */
    pseudo_bit_t	start_address_l[0x00020];
/* -------------- */
    pseudo_bit_t	length_h[0x00020];
/* -------------- */
    pseudo_bit_t	length_l[0x00020];
/* -------------- */
}; 

/* Send wqe segment ud */

struct hermonprm_wqe_segment_ud_st {	/* Little Endian */
    struct hermonprm_ud_address_vector_st	ud_address_vector;/* UD Address Vector */
/* -------------- */
    pseudo_bit_t	destination_qp[0x00018];
    pseudo_bit_t	reserved0[0x00008];
/* -------------- */
    pseudo_bit_t	q_key[0x00020];
/* -------------- */
    pseudo_bit_t	reserved1[0x00040];
/* -------------- */
}; 

/* Send wqe segment rd */

struct hermonprm_wqe_segment_rd_st {	/* Little Endian */
    pseudo_bit_t	destination_qp[0x00018];
    pseudo_bit_t	reserved0[0x00008];
/* -------------- */
    pseudo_bit_t	q_key[0x00020];
/* -------------- */
    pseudo_bit_t	reserved1[0x00040];
/* -------------- */
}; 

/* Send wqe segment ctrl */

struct hermonprm_wqe_segment_ctrl_send_st {	/* Little Endian */
    pseudo_bit_t	opcode[0x00005];
    pseudo_bit_t	reserved0[0x0001a];
    pseudo_bit_t	owner[0x00001];
/* -------------- */
    pseudo_bit_t	ds[0x00006];           /* descriptor (wqe) size in 16bytes chunk */
    pseudo_bit_t	f[0x00001];            /* fence */
    pseudo_bit_t	reserved1[0x00019];
/* -------------- */
    pseudo_bit_t	fl[0x00001];           /* Force LoopBack */
    pseudo_bit_t	s[0x00001];            /* Remote Solicited Event */
    pseudo_bit_t	c[0x00002];            /* completion required: 0b00 - no   0b11 - yes */
    pseudo_bit_t	ip[0x00001];           /* When set, InfiniHost III Ex will calculate the IP checksum of the IP header that is present immediately after the IPoverIB encapsulation header. In the case of multiple headers (encapsulation), InfiniHost III Ex will calculate the checksum only for the first IP header following the IPoverIB encapsulation header. Not Valid for IPv6 packets */
    pseudo_bit_t	tcp_udp[0x00001];      /* When set, InfiniHost III Ex will calculate the TCP/UDP checksum of the packet that is present immediately after the IP header. In the case of multiple headers (encapsulation), InfiniHost III Ex will calculate the checksum only for the first TCP header following the IP header. This bit may be set only if the entire TCP/UDP segment is present in one IB packet */
    pseudo_bit_t	reserved2[0x00001];
    pseudo_bit_t	so[0x00001];           /* Strong Ordering - when set, the WQE will be executed only after all previous WQEs have been executed. Can be set for RC WQEs only. This bit must be set in type two BIND, Fast Registration and Local invalidate operations. */
    pseudo_bit_t	src_remote_buf[0x00018];
/* -------------- */
    pseudo_bit_t	immediate[0x00020];    /* If the OpCode encodes an operation with Immediate (RDMA-write/SEND), This field will hold the Immediate data to be sent. If the OpCode encodes send and invalidate operations, this field holds the Invalidation key to be inserted into the packet; otherwise, this field is reserved. */
/* -------------- */
}; 

/* Address Path	# ###michal - match to PRM */

struct hermonprm_address_path_st {	/* Little Endian */
    pseudo_bit_t	pkey_index[0x00007];   /* PKey table index */
    pseudo_bit_t	reserved0[0x00016];
    pseudo_bit_t	sv[0x00001];           /* Service  VLAN on QP */
    pseudo_bit_t	cv[0x00001];           /* Customer VLAN in QP */
    pseudo_bit_t	fl[0x00001];           /* Force LoopBack */
/* -------------- */
    pseudo_bit_t	rlid[0x00010];         /* Remote (Destination) LID */
    pseudo_bit_t	my_lid_smac_idx[0x00007];/* Source LID - the lower 7 bits (upper bits are taken from PortInfo) */
    pseudo_bit_t	grh_ip[0x00001];       /* Global address enable - if set, GRH will be formed for packet header */
    pseudo_bit_t	reserved1[0x00008];
/* -------------- */
    pseudo_bit_t	hop_limit[0x00008];    /* IPv6 hop limit */
    pseudo_bit_t	max_stat_rate[0x00004];/* Maximum static rate control. 
                                                 0 - 100% injection rate 
                                                 1 - 25% injection rate
                                                 2 - 12.5% injection rate
                                                 3 - 50% injection rate
                                                 7: 2.5 Gb/s. 
                                                 8: 10 Gb/s. 
                                                 9: 30 Gb/s. 
                                                 10: 5 Gb/s. 
                                                 11: 20 Gb/s.
                                                 12: 40 Gb/s. 
                                                 13: 60 Gb/s. 
                                                 14: 80 Gb/s. 
                                                 15: 120 Gb/s. */
    pseudo_bit_t	reserved2[0x00004];
    pseudo_bit_t	mgid_index[0x00007];   /* Index to port GID table */
    pseudo_bit_t	reserved3[0x00004];
    pseudo_bit_t	ack_timeout[0x00005];  /* Local ACK timeout - Transport timer for activation of retransmission mechanism. Refer to IB spec Vol1 9.7.6.1.3 for further details.
                                                 The transport timer is set to 4.096us*2^ack_timeout, if ack_timeout is 0 then transport timer is disabled. */
/* -------------- */
    pseudo_bit_t	flow_label[0x00014];   /* IPv6 flow label */
    pseudo_bit_t	tclass[0x00008];       /* IPv6 TClass */
    pseudo_bit_t	reserved4[0x00004];
/* -------------- */
    pseudo_bit_t	rgid_127_96[0x00020];  /* Remote GID[127:96] */
/* -------------- */
    pseudo_bit_t	rgid_95_64[0x00020];   /* Remote GID[95:64] */
/* -------------- */
    pseudo_bit_t	rgid_63_32[0x00020];   /* Remote GID[63:32] */
/* -------------- */
    pseudo_bit_t	rgid_31_0[0x00020];    /* Remote GID[31:0] */
/* -------------- */
    pseudo_bit_t	reserved5[0x00008];
    pseudo_bit_t	sp[0x00001];           /* if set, spoofing protection is enforced on this QP and Ethertype headers are restricted */
    pseudo_bit_t	reserved6[0x00002];
    pseudo_bit_t	fvl[0x00001];          /* force VLAN */
    pseudo_bit_t	fsip[0x00001];         /* force source IP */
    pseudo_bit_t	fsm[0x00001];          /* force source MAC */
    pseudo_bit_t	reserved7[0x0000a];
    pseudo_bit_t	sched_queue[0x00008];
/* -------------- */
    pseudo_bit_t	dmac_47_32[0x00010];
    pseudo_bit_t	vlan_index[0x00007];
    pseudo_bit_t	reserved8[0x00001];
    pseudo_bit_t	counter_index[0x00008];/* Index to a table of counters that counts egress packets and bytes, 0xFF not valid */
/* -------------- */
    pseudo_bit_t	dmac_31_0[0x00020];
/* -------------- */
}; 

/* HCA Command Register (HCR)    #### michal - match PRM */

struct hermonprm_hca_command_register_st {	/* Little Endian */
    pseudo_bit_t	in_param_h[0x00020];   /* Input Parameter: parameter[63:32] or pointer[63:32] to input mailbox (see command description) */
/* -------------- */
    pseudo_bit_t	in_param_l[0x00020];   /* Input Parameter: parameter[31:0] or pointer[31:0] to input mailbox (see command description) */
/* -------------- */
    pseudo_bit_t	input_modifier[0x00020];/* Input Parameter Modifier */
/* -------------- */
    pseudo_bit_t	out_param_h[0x00020];  /* Output Parameter: parameter[63:32] or pointer[63:32] to output mailbox (see command description) */
/* -------------- */
    pseudo_bit_t	out_param_l[0x00020];  /* Output Parameter: parameter[31:0] or pointer[31:0] to output mailbox (see command description) */
/* -------------- */
    pseudo_bit_t	reserved0[0x00010];
    pseudo_bit_t	token[0x00010];        /* Software assigned token to the command, to uniquely identify it. The token is returned to the software in the EQE reported. */
/* -------------- */
    pseudo_bit_t	opcode[0x0000c];       /* Command opcode */
    pseudo_bit_t	opcode_modifier[0x00004];/* Opcode Modifier, see specific description for each command. */
    pseudo_bit_t	reserved1[0x00005];
    pseudo_bit_t	t[0x00001];	       /* Toggle */
    pseudo_bit_t	e[0x00001];            /* Event Request
                                                 0 - Don't report event (software will poll the GO bit)
                                                 1 - Report event to EQ when the command completes */
    pseudo_bit_t	go[0x00001];           /* Go (0=Software ownership for the HCR, 1=Hardware ownership for the HCR)
                                                 Software can write to the HCR only if Go bit is cleared.
                                                 Software must set the Go bit to trigger the HW to execute the command. Software must not write to this register value other than 1 for the Go bit. */
    pseudo_bit_t	status[0x00008];       /* Command execution status report. Valid only if command interface in under SW ownership (Go bit is cleared)
                                                 0 - command completed without error. If different than zero, command execution completed with error. Syndrom encoding is depended on command executed and is defined for each command */
/* -------------- */
}; 

/* CQ Doorbell */

struct hermonprm_cq_cmd_doorbell_st {	/* Little Endian */
    pseudo_bit_t	cqn[0x00018];          /* CQ number accessed */
    pseudo_bit_t	cmd[0x00003];          /* Command to be executed on CQ
                                                 0x0 - Reserved
                                                 0x1 - Request notification for next Solicited completion event. CQ_param specifies the current CQ Consumer Counter.
                                                 0x2 - Request notification for next Solicited or Unsolicited completion event. CQ_param specifies the current CQ Consumer Counter.
                                                 0x3 - Request notification for multiple completions (Arm-N). CQ_param specifies the value of the CQ Counter that when reached by HW (i.e. HW generates a CQE into this Counter) Event will be generated
                                                 Other - Reserved */
    pseudo_bit_t	reserved0[0x00001];
    pseudo_bit_t	cmd_sn[0x00002];       /* Command Sequence Number - This field should be incremented upon receiving completion notification of the respective CQ.
                                                 This transition is done by ringing Request notification for next Solicited, Request notification for next Solicited or Unsolicited 
                                                 completion or Request notification for multiple completions doorbells after receiving completion notification.
                                                 This field is initialized to Zero */
    pseudo_bit_t	reserved1[0x00002];
/* -------------- */
    pseudo_bit_t	cq_param[0x00020];     /* parameter to be used by CQ command */
/* -------------- */
}; 

/* RD-send doorbell */

struct hermonprm_rd_send_doorbell_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00008];
    pseudo_bit_t	een[0x00018];          /* End-to-end context number (reliable datagram)
                                                 Must be zero for Nop and Bind operations */
/* -------------- */
    pseudo_bit_t	reserved1[0x00008];
    pseudo_bit_t	qpn[0x00018];          /* QP number this doorbell is rung on */
/* -------------- */
    struct hermonprm_send_doorbell_st	send_doorbell;/* Send Parameters */
/* -------------- */
}; 

/* Multicast Group Member QP   #### michal - match PRM */

struct hermonprm_mgmqp_st {	/* Little Endian */
    pseudo_bit_t	qpn_i[0x00018];        /* QPN_i: QP number which is a member in this multicast group. Valid only if Qi bit is set. Length of the QPN_i list is set in INIT_HCA */
    pseudo_bit_t	reserved0[0x00006];
    pseudo_bit_t	blck_lb[0x00001];      /* Block self-loopback messages arriving to this qp */
    pseudo_bit_t	qi[0x00001];           /* Qi: QPN_i is valid */
/* -------------- */
}; 

/* vsd */

struct hermonprm_vsd_st {	/* Little Endian */
    pseudo_bit_t	vsd_dw0[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw1[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw2[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw3[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw4[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw5[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw6[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw7[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw8[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw9[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw10[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw11[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw12[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw13[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw14[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw15[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw16[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw17[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw18[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw19[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw20[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw21[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw22[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw23[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw24[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw25[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw26[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw27[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw28[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw29[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw30[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw31[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw32[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw33[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw34[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw35[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw36[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw37[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw38[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw39[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw40[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw41[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw42[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw43[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw44[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw45[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw46[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw47[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw48[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw49[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw50[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw51[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw52[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw53[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw54[0x00020];
/* -------------- */
    pseudo_bit_t	vsd_dw55[0x00020];
/* -------------- */
}; 

/* UAR Parameters */

struct hermonprm_uar_params_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00040];
/* -------------- */
    pseudo_bit_t	uar_page_sz[0x00008];  /* This field defines the size of each UAR page.
                                                 Size of UAR Page is 4KB*2^UAR_Page_Size */
    pseudo_bit_t	log_max_uars[0x00004]; /* Number of UARs supported is 2^log_max_UARs */
    pseudo_bit_t	reserved1[0x00014];
/* -------------- */
    pseudo_bit_t	reserved2[0x000a0];
/* -------------- */
}; 

/* Translation and Protection Tables Parameters */

struct hermonprm_tptparams_st {	/* Little Endian */
    pseudo_bit_t	dmpt_base_adr_h[0x00020];/* dMPT - Memory Protection Table base physical address [63:32].
                                                 Entry size is 64 bytes.
                                                 Table must be aligned to its size.
                                                 Address may be set to 0xFFFFFFFF if address translation and protection is not supported. */
/* -------------- */
    pseudo_bit_t	dmpt_base_adr_l[0x00020];/* dMPT - Memory Protection Table base physical address [31:0].
                                                 Entry size is 64 bytes.
                                                 Table must be aligned to its size.
                                                 Address may be set to 0xFFFFFFFF if address translation and protection is not supported. */
/* -------------- */
    pseudo_bit_t	log_dmpt_sz[0x00006];  /* Log (base 2) of the number of region/windows entries in the dMPT table. */
    pseudo_bit_t	reserved0[0x00002];
    pseudo_bit_t	pfto[0x00005];         /* Page Fault RNR Timeout - 
                                                 The field returned in RNR Naks generated when a page fault is detected.
                                                 It has no effect when on-demand-paging is not used. */
    pseudo_bit_t	reserved1[0x00013];
/* -------------- */
    pseudo_bit_t	reserved2[0x00020];
/* -------------- */
    pseudo_bit_t	mtt_base_addr_h[0x00020];/* MTT - Memory Translation table base physical address [63:32].
                                                 Table must be aligned to its size.
                                                 Address may be set to 0xFFFFFFFF if address translation and protection is not supported. */
/* -------------- */
    pseudo_bit_t	mtt_base_addr_l[0x00020];/* MTT - Memory Translation table base physical address [31:0].
                                                 Table must be aligned to its size.
                                                 Address may be set to 0xFFFFFFFF if address translation and protection is not supported. */
/* -------------- */
    pseudo_bit_t	cmpt_base_adr_h[0x00020];/* cMPT - Memory Protection Table base physical address [63:32].
                                                 Entry size is 64 bytes.
                                                 Table must be aligned to its size. */
/* -------------- */
    pseudo_bit_t	cmpt_base_adr_l[0x00020];/* cMPT - Memory Protection Table base physical address [31:0].
                                                 Entry size is 64 bytes.
                                                 Table must be aligned to its size. */
/* -------------- */
}; 

/* Multicast Support Parameters   #### michal - match PRM */

struct hermonprm_multicastparam_st {	/* Little Endian */
    pseudo_bit_t	mc_base_addr_h[0x00020];/* Base Address of the Multicast Table [63:32].
                                                 The base address must be aligned to the entry size.
                                                 Address may be set to 0xFFFFFFFF if multicast is not supported. */
/* -------------- */
    pseudo_bit_t	mc_base_addr_l[0x00020];/* Base Address of the Multicast Table [31:0]. 
                                                 The base address must be aligned to the entry size.
                                                 Address may be set to 0xFFFFFFFF if multicast is not supported. */
/* -------------- */
    pseudo_bit_t	reserved0[0x00040];
/* -------------- */
    pseudo_bit_t	log_mc_table_entry_sz[0x00005];/* Log2 of the Size of multicast group member (MGM) entry.
                                                 Must be greater than 5 (to allow CTRL and GID sections). 
                                                 That implies the number of QPs per MC table entry. */
    pseudo_bit_t	reserved1[0x0000b];
    pseudo_bit_t	reserved2[0x00010];
/* -------------- */
    pseudo_bit_t	log_mc_table_hash_sz[0x00005];/* Number of entries in multicast DGID hash table (must be power of 2)
                                                 INIT_HCA - the required number of entries
                                                 QUERY_HCA - the actual number of entries assigned by firmware (will be less than or equal to the amount required in INIT_HCA) */
    pseudo_bit_t	reserved3[0x0001b];
/* -------------- */
    pseudo_bit_t	log_mc_table_sz[0x00005];/* Log2 of the overall number of MC entries in the MCG table (includes both hash and auxiliary tables) */
    pseudo_bit_t	reserved4[0x00013];
    pseudo_bit_t	mc_hash_fn[0x00003];   /* Multicast hash function
                                                 0 - Default hash function
                                                 other - reserved */
    pseudo_bit_t	uc_group_steering[0x00001];
    pseudo_bit_t	reserved5[0x00004];
/* -------------- */
    pseudo_bit_t	reserved6[0x00020];
/* -------------- */
}; 

/* QPC/EEC/CQC/EQC/RDB Parameters   #### michal - doesn't match PRM (field name are differs. see below) */

struct hermonprm_qpcbaseaddr_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00080];
/* -------------- */
    pseudo_bit_t	qpc_base_addr_h[0x00020];/* QPC Base Address [63:32]
                                                 Table must be aligned on its size */
/* -------------- */
    pseudo_bit_t	log_num_of_qp[0x00005];/* Log base 2 of number of supported QPs */
    pseudo_bit_t	qpc_base_addr_l[0x0001b];/* QPC Base Address [31:7]
                                                 Table must be aligned on its size */
/* -------------- */
    pseudo_bit_t	reserved1[0x00040];
/* -------------- */
    pseudo_bit_t	reserved2[0x00040];
/* -------------- */
    pseudo_bit_t	srqc_base_addr_h[0x00020];/* SRQ Context Base Address [63:32]
                                                 Table must be aligned on its size
                                                 Address may be set to 0xFFFFFFFF if SRQ is not supported. */
/* -------------- */
    pseudo_bit_t	log_num_of_srq[0x00005];/* Log base 2 of number of supported SRQs. */
    pseudo_bit_t	srqc_base_addr_l[0x0001b];/* SRQ Context Base Address [31:5]
                                                 Table must be aligned on its size
                                                 Address may be set to 0xFFFFFFFF if SRQ is not supported. */
/* -------------- */
    pseudo_bit_t	cqc_base_addr_h[0x00020];/* CQC Base Address [63:32]
                                                 Table must be aligned on its size */
/* -------------- */
    pseudo_bit_t	log_num_of_cq[0x00005];/* Log base 2 of number of supported CQs. */
    pseudo_bit_t	cqc_base_addr_l[0x0001b];/* CQC Base Address [31:6]
                                                 Table must be aligned on its size */
/* -------------- */
    pseudo_bit_t	reserved3[0x00040];
/* -------------- */
    pseudo_bit_t	altc_base_addr_h[0x00020];/* AltC Base Address (altc_base_addr_h) [63:32]
                                                 Table has same number of entries as QPC table.
                                                 Table must be aligned to entry size. */
/* -------------- */
    pseudo_bit_t	altc_base_addr_l[0x00020];/* AltC Base Address (altc_base_addr_l) [31:0]
                                                 Table has same number of entries as QPC table.
                                                 Table must be aligned to entry size. */
/* -------------- */
    pseudo_bit_t	reserved4[0x00040];
/* -------------- */
    pseudo_bit_t	auxc_base_addr_h[0x00020];
/* -------------- */
    pseudo_bit_t	auxc_base_addr_l[0x00020];
/* -------------- */
    pseudo_bit_t	reserved5[0x00040];
/* -------------- */
    pseudo_bit_t	eqc_base_addr_h[0x00020];/* EQC Base Address [63:32]
                                                 Address may be set to 0xFFFFFFFF if EQs are not supported.
                                                 Table must be aligned to entry size. */
/* -------------- */
    pseudo_bit_t	log_num_of_eq[0x00005];/* Log base 2 of number of supported EQs.
                                                 Must be 6 or less in InfiniHost-III-EX. */
    pseudo_bit_t	eqc_base_addr_l[0x0001b];/* EQC Base Address [31:6]
                                                 Address may be set to 0xFFFFFFFF if EQs are not supported.
                                                 Table must be aligned to entry size. */
/* -------------- */
    pseudo_bit_t	reserved6[0x00040];
/* -------------- */
    pseudo_bit_t	rdmardc_base_addr_h[0x00020];/* rdmardc_base_addr_h: Base address of table that holds remote read and remote atomic requests [63:32]. */
/* -------------- */
    pseudo_bit_t	log_num_rd[0x00003];   /* Log (base 2) of the maximum number of RdmaRdC entries per QP. This denotes the maximum number of outstanding reads/atomics as a responder. */
    pseudo_bit_t	reserved7[0x00002];
    pseudo_bit_t	rdmardc_base_addr_l[0x0001b];/* rdmardc_base_addr_l: Base address of table that holds remote read and remote atomic requests [31:0]. 
                                                 Table must be aligned to RDB entry size (32 bytes). */
/* -------------- */
    pseudo_bit_t	reserved8[0x00040];
/* -------------- */
}; 

/* Header_Log_Register */

struct hermonprm_header_log_register_st {	/* Little Endian */
    pseudo_bit_t	place_holder[0x00020];
/* -------------- */
    pseudo_bit_t	reserved0[0x00060];
/* -------------- */
}; 

/* Performance Monitors */

struct hermonprm_performance_monitors_st {	/* Little Endian */
    pseudo_bit_t	e0[0x00001];           /* Enables counting of respective performance counter */
    pseudo_bit_t	e1[0x00001];           /* Enables counting of respective performance counter */
    pseudo_bit_t	e2[0x00001];           /* Enables counting of respective performance counter */
    pseudo_bit_t	reserved0[0x00001];
    pseudo_bit_t	r0[0x00001];           /* If written to as '1 - resets respective performance counter, if written to az '0 - no change to matter */
    pseudo_bit_t	r1[0x00001];           /* If written to as '1 - resets respective performance counter, if written to az '0 - no change to matter */
    pseudo_bit_t	r2[0x00001];           /* If written to as '1 - resets respective performance counter, if written to az '0 - no change to matter */
    pseudo_bit_t	reserved1[0x00001];
    pseudo_bit_t	i0[0x00001];           /* Interrupt enable on respective counter overflow. '1 - interrupt enabled, '0 - interrupt disabled. */
    pseudo_bit_t	i1[0x00001];           /* Interrupt enable on respective counter overflow. '1 - interrupt enabled, '0 - interrupt disabled. */
    pseudo_bit_t	i2[0x00001];           /* Interrupt enable on respective counter overflow. '1 - interrupt enabled, '0 - interrupt disabled. */
    pseudo_bit_t	reserved2[0x00001];
    pseudo_bit_t	f0[0x00001];           /* Overflow flag. If set, overflow occurred on respective counter. Cleared if written to as '1 */
    pseudo_bit_t	f1[0x00001];           /* Overflow flag. If set, overflow occurred on respective counter. Cleared if written to as '1 */
    pseudo_bit_t	f2[0x00001];           /* Overflow flag. If set, overflow occurred on respective counter. Cleared if written to as '1 */
    pseudo_bit_t	reserved3[0x00001];
    pseudo_bit_t	ev_cnt1[0x00005];      /* Specifies event to be counted by Event_counter1 See XXX for events' definition. */
    pseudo_bit_t	reserved4[0x00003];
    pseudo_bit_t	ev_cnt2[0x00005];      /* Specifies event to be counted by Event_counter2 See XXX for events' definition. */
    pseudo_bit_t	reserved5[0x00003];
/* -------------- */
    pseudo_bit_t	clock_counter[0x00020];
/* -------------- */
    pseudo_bit_t	event_counter1[0x00020];
/* -------------- */
    pseudo_bit_t	event_counter2[0x00020];/* Read/write event counter, counting events specified by EvCntl and EvCnt2 fields repsectively. When the event counter reaches is maximum value of 0xFFFFFF, the next event will cause it to roll over to zero, set F1 or F2 bit respectively and generate interrupt by I1 I2 bit respectively. */
/* -------------- */
}; 

/* MLX WQE segment format */

struct hermonprm_wqe_segment_ctrl_mlx_st {	/* Little Endian */
    pseudo_bit_t	opcode[0x00005];       /* must be 0xA = SEND */
    pseudo_bit_t	reserved0[0x0001a];
    pseudo_bit_t	owner[0x00001];
/* -------------- */
    pseudo_bit_t	ds[0x00006];           /* Descriptor Size */
    pseudo_bit_t	reserved1[0x0001a];
/* -------------- */
    pseudo_bit_t	fl[0x00001];           /* Force LoopBack */
    pseudo_bit_t	reserved2[0x00001];
    pseudo_bit_t	c[0x00002];            /* Create CQE (for "requested signalling" QP) */
    pseudo_bit_t	icrc[0x00001];         /* last dword of the packet: 0 - Calculate ICRC and put it instead of last dword. 1 - Leave last dword as is. */
    pseudo_bit_t	reserved3[0x00003];
    pseudo_bit_t	sl[0x00004];
    pseudo_bit_t	max_statrate[0x00004];
    pseudo_bit_t	slr[0x00001];          /* 0= take slid from port. 1= take slid from given headers */
    pseudo_bit_t	v15[0x00001];          /* Send packet over VL15 */
    pseudo_bit_t	reserved4[0x0000e];
/* -------------- */
    pseudo_bit_t	reserved5[0x00010];
    pseudo_bit_t	rlid[0x00010];         /* Destination LID (must match given headers) */
/* -------------- */
}; 

/* Send WQE segment format */

struct hermonprm_send_wqe_segment_st {	/* Little Endian */
    struct hermonprm_wqe_segment_ctrl_send_st	wqe_segment_ctrl_send;/* Send wqe segment ctrl */
/* -------------- */
    struct hermonprm_wqe_segment_rd_st	wqe_segment_rd;/* Send wqe segment rd */
/* -------------- */
    struct hermonprm_wqe_segment_ud_st	wqe_segment_ud;/* Send wqe segment ud */
/* -------------- */
    struct hermonprm_wqe_segment_bind_st	wqe_segment_bind;/* Send wqe segment bind */
/* -------------- */
    pseudo_bit_t	reserved0[0x00180];
/* -------------- */
    struct hermonprm_wqe_segment_remote_address_st	wqe_segment_remote_address;/* Send wqe segment remote address */
/* -------------- */
    struct hermonprm_wqe_segment_atomic_st	wqe_segment_atomic;/* Send wqe segment atomic */
/* -------------- */
    struct hermonprm_fast_registration_segment_st	fast_registration_segment;/* Fast Registration Segment */
/* -------------- */
    struct hermonprm_local_invalidate_segment_st	local_invalidate_segment;/* local invalidate segment */
/* -------------- */
    struct hermonprm_wqe_segment_data_ptr_st	wqe_segment_data_ptr;/* Send wqe segment data ptr */
/* -------------- */
    struct hermonprm_wqe_segment_data_inline_st	wqe_segment_data_inline;/* Send wqe segment data inline */
/* -------------- */
    pseudo_bit_t	reserved1[0x00200];
/* -------------- */
}; 

/* QP and EE Context Entry */

struct hermonprm_queue_pair_ee_context_entry_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00008];
    pseudo_bit_t	reserved1[0x00001];
    pseudo_bit_t	reserved2[0x00002];
    pseudo_bit_t	pm_state[0x00002];     /* Path migration state (Migrated, Armed or Rearm)
                                                 11-Migrated
                                                 00-Armed
                                                 01-Rearm
                                                 10-Reserved
                                                 Should be set to 11 for UD QPs and for QPs which do not support APM */
    pseudo_bit_t	reserved3[0x00003];
    pseudo_bit_t	st[0x00004];           /* Transport Service Type: RC: 0, UC: 1, RD: 2, UD: 3, FCMND:4, FEXCH:5, SRC:6, MLX 7, Raw Eth 11 */
    pseudo_bit_t	reserved4[0x00008];
    pseudo_bit_t	state[0x00004];        /* QP/EE state:
                                                 0 - RST
                                                 1 - INIT
                                                 2 - RTR
                                                 3 - RTS
                                                 4 - SQEr
                                                 5 - SQD (Send Queue Drained)
                                                 6 - ERR
                                                 7 - Send Queue Draining
                                                 8 - Reserved
                                                 9 - Suspended
                                                 A- F - Reserved
                                                 (Valid for QUERY_QPEE and ERR2RST_QPEE commands only) */
/* -------------- */
    pseudo_bit_t	pd[0x00018];
    pseudo_bit_t	reserved5[0x00008];
/* -------------- */
    pseudo_bit_t	reserved6[0x00004];
    pseudo_bit_t	rlky[0x00001];         /* When set this QP can use the Reserved L_Key */
    pseudo_bit_t	reserved7[0x00003];
    pseudo_bit_t	log_sq_stride[0x00003];/* Stride on the send queue. WQ entry is 16*(2^log_SQ_stride) bytes.
                                                 Stride must be equal or bigger then 64 bytes (minimum log_RQ_stride value allowed is 2). */
    pseudo_bit_t	log_sq_size[0x00004];  /* Log2 of the Number of WQEs in the Send Queue. */
    pseudo_bit_t	reserved8[0x00001];
    pseudo_bit_t	log_rq_stride[0x00003];/* Stride on the receive queue. WQ entry is 16*(2^log_RQ_stride) bytes.
                                                 Stride must be equal or bigger then 64 bytes (minimum log_RQ_stride value allowed is 2). */
    pseudo_bit_t	log_rq_size[0x00004];  /* Log2 of the Number of WQEs in the Receive Queue. */
    pseudo_bit_t	reserved9[0x00001];
    pseudo_bit_t	msg_max[0x00005];      /* Max message size allowed on the QP. Maximum message size is 2^msg_Max.
                                                 Must be equal to MTU for UD and MLX QPs. */
    pseudo_bit_t	mtu[0x00003];          /* MTU of the QP (Must be the same for both paths: primary and alternative):
                                                 0x1 - 256 bytes
                                                 0x2 - 512
                                                 0x3 - 1024
                                                 0x4 - 2048
                                                 other - reserved
                                                 
                                                 Should be configured to 0x4 for UD and MLX QPs. */
/* -------------- */
    pseudo_bit_t	usr_page[0x00018];     /* UAR number to ring doorbells for this QP (aliased to doorbell and Blue Flame pages) */
    pseudo_bit_t	reserved10[0x00008];
/* -------------- */
    pseudo_bit_t	local_qpn_een[0x00018];/* Local QP/EE number Lower bits determine position of this record in QPC table, and - thus - constrained
                                                 This field is valid for QUERY and ERR2RST commands only. */
    pseudo_bit_t	reserved11[0x00008];
/* -------------- */
    pseudo_bit_t	remote_qpn_een[0x00018];/* Remote QP/EE number */
    pseudo_bit_t	reserved12[0x00008];
/* -------------- */
    struct hermonprm_address_path_st	primary_address_path;/* Primary address path for the QP/EE */
/* -------------- */
    struct hermonprm_address_path_st	alternative_address_path;/* Alternate address path for the QP/EE */
/* -------------- */
    pseudo_bit_t	reserved13[0x00003];
    pseudo_bit_t	reserved14[0x00001];
    pseudo_bit_t	reserved15[0x00001];
    pseudo_bit_t	cur_retry_cnt[0x00003];/* Current transport retry counter (QUERY_QPEE only).
                                                 The current transport retry counter can vary from retry_count down to 1, where 1 means that the last retry attempt is currently executing. */
    pseudo_bit_t	cur_rnr_retry[0x00003];/* Current RNR retry counter (QUERY_QPEE only).
                                                 The current RNR retry counter can vary from rnr_retry to 1, where 1 means that the last retry attempt is currently executing. */
    pseudo_bit_t	fre[0x00001];          /* Fast Registration Work Request Enabled. (Reserved for EE) */
    pseudo_bit_t	reserved16[0x00001];
    pseudo_bit_t	rnr_retry[0x00003];
    pseudo_bit_t	retry_count[0x00003];  /* Transport timeout Retry count */
    pseudo_bit_t	reserved17[0x00002];
    pseudo_bit_t	sra_max[0x00003];      /* Maximum number of outstanding RDMA-read/Atomic operations allowed in the send queue. Maximum number is 2^SRA_Max. Must be zero in EE context. */
    pseudo_bit_t	reserved18[0x00004];
    pseudo_bit_t	ack_req_freq[0x00004]; /* ACK required frequency. ACK required bit will be set in every 2^AckReqFreq packets at least. Not valid for RD QP. */
/* -------------- */
    pseudo_bit_t	reserved19[0x00020];
/* -------------- */
    pseudo_bit_t	next_send_psn[0x00018];/* Next PSN to be sent */
    pseudo_bit_t	reserved20[0x00008];
/* -------------- */
    pseudo_bit_t	cqn_snd[0x00018];      /* CQ number completions from the send queue to be reported to. Not valid (reserved) in EE context. */
    pseudo_bit_t	reserved21[0x00008];
/* -------------- */
    pseudo_bit_t	reserved22[0x00040];
/* -------------- */
    pseudo_bit_t	last_acked_psn[0x00018];/* The last acknowledged PSN for the requester (QUERY_QPEE only) */
    pseudo_bit_t	reserved23[0x00008];
/* -------------- */
    pseudo_bit_t	ssn[0x00018];          /* Requester Send Sequence Number (QUERY_QPEE only) */
    pseudo_bit_t	reserved24[0x00008];
/* -------------- */
    pseudo_bit_t	reserved25[0x00004];
    pseudo_bit_t	ric[0x00001];          /* Invalid Credits. 
                                                 1 - place "Invalid Credits" to ACKs sent from this queue.
                                                 0 - ACKs report the actual number of end to end credits on the connection.
                                                 Not valid (reserved) in EE context.
                                                 Must be set to 1 on QPs which are attached to SRQ. */
    pseudo_bit_t	reserved26[0x00001];
    pseudo_bit_t	page_offset[0x00006];  /* start address of wqes in first page (11:6), bits [5:0] reserved */
    pseudo_bit_t	reserved27[0x00001];
    pseudo_bit_t	rae[0x00001];          /* If set - Atomic operations enabled. on receive queue. Not valid (reserved) in EE context. */
    pseudo_bit_t	rwe[0x00001];          /* If set - RDMA - write enabled on receive queue. Not valid (reserved) in EE context. */
    pseudo_bit_t	rre[0x00001];          /* If set - RDMA - read enabled on receive queue. Not valid (reserved) in EE context. */
    pseudo_bit_t	reserved28[0x00005];
    pseudo_bit_t	rra_max[0x00003];      /* Maximum number of outstanding RDMA-read/Atomic operations allowed on receive queue is 2^RRA_Max. 
                                                 Must be 0 for EE context. */
    pseudo_bit_t	physical_function[0x00008];
/* -------------- */
    pseudo_bit_t	next_rcv_psn[0x00018]; /* Next (expected) PSN on receive */
    pseudo_bit_t	min_rnr_nak[0x00005];  /* Minimum RNR NAK timer value (TTTTT field encoding according to the IB spec Vol1 9.7.5.2.8). 
                                                 Not valid (reserved) in EE context. */
    pseudo_bit_t	reserved30[0x00003];
/* -------------- */
    pseudo_bit_t	srcd[0x00010];         /* Scalable Reliable Connection Domain. Valid for SRC transport service */
    pseudo_bit_t	reserved31[0x00010];
/* -------------- */
    pseudo_bit_t	cqn_rcv[0x00018];      /* CQ number completions from receive queue to be reported to. Not valid (reserved) in EE context. */
    pseudo_bit_t	reserved32[0x00008];
/* -------------- */
    pseudo_bit_t	db_record_addr_h[0x00020];/* QP DB Record physical address */
/* -------------- */
    pseudo_bit_t	reserved33[0x00002];
    pseudo_bit_t	db_record_addr_l[0x0001e];/* QP DB Record physical address */
/* -------------- */
    pseudo_bit_t	q_key[0x00020];        /* Q_Key to be validated against received datagrams.
                                                 On send datagrams, if Q_Key[31] specified in the WQE is set, then this Q_Key will be transmitted in the outgoing message.
                                                 Not valid (reserved) in EE context. */
/* -------------- */
    pseudo_bit_t	srqn[0x00018];         /* SRQN - Shared Receive Queue Number - specifies the SRQ number from which the QP dequeues receive descriptors. 
                                                 SRQN is valid only if SRQ bit is set. Not valid (reserved) in EE context. */
    pseudo_bit_t	srq[0x00001];          /* SRQ - Shared Receive Queue. If this bit is set, then the QP is associated with a SRQ. Not valid (reserved) in EE context. */
    pseudo_bit_t	reserved34[0x00007];
/* -------------- */
    pseudo_bit_t	rmsn[0x00018];         /* Responder current message sequence number (QUERY_QPEE only) */
    pseudo_bit_t	reserved35[0x00008];
/* -------------- */
    pseudo_bit_t	sq_wqe_counter[0x00010];/* A 16bits counter that is incremented for each WQE posted to the SQ.
                                                 Must be 0x0 in SQ initialization.
                                                 (QUERY_QPEE only). */
    pseudo_bit_t	rq_wqe_counter[0x00010];/* A 16bits counter that is incremented for each WQE posted to the RQ.
                                                 Must be 0x0 in RQ initialization.
                                                 (QUERY_QPEE only). */
/* -------------- */
    pseudo_bit_t	reserved36[0x00040];
/* -------------- */
    pseudo_bit_t	rmc_parent_qpn[0x00018];/* reliable multicast parent queue number */
    pseudo_bit_t	hs[0x00001];           /* Header Separation. If set, the byte count of the first scatter entry will be ignored. The buffer specified by the first scatter entry will contain packet headers (up to TCP). CQE will report number of bytes scattered to the first scatter entry. Intended for use on IPoverIB on UD QP or Raw Ethernet QP. */
    pseudo_bit_t	is[0x00001];           /* when set - inline scatter is enabled for this RQ */
    pseudo_bit_t	reserved37[0x00001];
    pseudo_bit_t	rme[0x00002];          /* Reliable Multicast
                                                 00 - disabled
                                                 01 - parent QP (requester)
                                                 10 - child QP (requester)
                                                 11 - responder QP
                                                 Note that Reliable Multicast is a preliminary definition which can be subject to change. */
    pseudo_bit_t	reserved38[0x00002];
    pseudo_bit_t	mkey_rmp[0x00001];     /* If set, MKey used to access TPT for incoming RDMA-write request is calculated by adding MKey from the packet to base_MKey field in the QPC. Can be set only for QPs that are not target for RDMA-read request. */
/* -------------- */
    pseudo_bit_t	base_mkey[0x00018];    /* Base Mkey bits [31:8]. Lower 8 bits must be zero. */
    pseudo_bit_t	num_rmc_peers[0x00008];/* Number of remote peers in Reliable Multicast group */
/* -------------- */
    pseudo_bit_t	mtt_base_addr_h[0x00008];/* MTT Base Address [39:32] in ICM relative to INIT_HCA.mtt_base_addr */
    pseudo_bit_t	reserved39[0x00010];
    pseudo_bit_t	log2_page_size[0x00006];/* Log (base 2) of MTT page size in units of 4KByte */
    pseudo_bit_t	reserved40[0x00002];
/* -------------- */
    pseudo_bit_t	reserved41[0x00003];
    pseudo_bit_t	mtt_base_addr_l[0x0001d];/* MTT Base Address [31:3] in ICM relative to INIT_HCA.mtt_base_addr */
/* -------------- */
    pseudo_bit_t	vft_lan[0x0000c];
    pseudo_bit_t	vft_prio[0x00003];     /* The Priority filed in the VFT header for FCP */
    pseudo_bit_t	reserved42[0x00001];
    pseudo_bit_t	cs_ctl[0x00009];       /* The Priority filed in the VFT header for FCP */
    pseudo_bit_t	reserved43[0x00006];
    pseudo_bit_t	ve[0x00001];           /* Should we add/check the VFT header */
/* -------------- */
    pseudo_bit_t	exch_base[0x00010];    /* For init QP only - The base exchanges */
    pseudo_bit_t	reserved44[0x00008];
    pseudo_bit_t	exch_size[0x00004];    /* For CMMD QP only - The size (from base) exchanges is 2exchanges_size */
    pseudo_bit_t	reserved45[0x00003];
    pseudo_bit_t	fc[0x00001];           /* When set it mean that this QP is used for FIBRE CHANNEL. */
/* -------------- */
    pseudo_bit_t	remote_id[0x00018];    /* Peer NX port ID */
    pseudo_bit_t	reserved46[0x00008];
/* -------------- */
    pseudo_bit_t	fcp_mtu[0x0000a];      /* In 4*Bytes units. The MTU Size */
    pseudo_bit_t	reserved47[0x00006];
    pseudo_bit_t	my_id_indx[0x00008];   /* Index to My NX port ID table */
    pseudo_bit_t	vft_hop_count[0x00008];/* HopCnt value for the VFT header */
/* -------------- */
    pseudo_bit_t	reserved48[0x000c0];
/* -------------- */
}; 

/*  */

struct hermonprm_mcg_qp_dw_st {	/* Little Endian */
    pseudo_bit_t	qpn[0x00018];
    pseudo_bit_t	reserved0[0x00006];
    pseudo_bit_t	blck_lb[0x00001];
    pseudo_bit_t	reserved1[0x00001];
/* -------------- */
}; 

/* Clear Interrupt [63:0]              #### michal - match to PRM */

struct hermonprm_clr_int_st {	/* Little Endian */
    pseudo_bit_t	clr_int_h[0x00020];    /* Clear Interrupt [63:32]
                                                 Write transactions to this register will clear (de-assert) the virtual interrupt output pins of InfiniHost-III-EX. The value to be written in this register is obtained by executing QUERY_ADAPTER command on command interface after system boot. 
                                                 This register is write-only. Reading from this register will cause undefined result
                                                  */
/* -------------- */
    pseudo_bit_t	clr_int_l[0x00020];    /* Clear Interrupt [31:0]
                                                 Write transactions to this register will clear (de-assert) the virtual interrupt output pins of InfiniHost-III-EX. The value to be written in this register is obtained by executing QUERY_ADAPTER command on command interface after system boot. 
                                                 This register is write-only. Reading from this register will cause undefined result */
/* -------------- */
}; 

/* EQ Set CI DBs Table */

struct hermonprm_eq_set_ci_table_st {	/* Little Endian */
    pseudo_bit_t	eq0_set_ci[0x00020];   /* EQ0_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved0[0x00020];
/* -------------- */
    pseudo_bit_t	eq1_set_ci[0x00020];   /* EQ1_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved1[0x00020];
/* -------------- */
    pseudo_bit_t	eq2_set_ci[0x00020];   /* EQ2_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved2[0x00020];
/* -------------- */
    pseudo_bit_t	eq3_set_ci[0x00020];   /* EQ3_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved3[0x00020];
/* -------------- */
    pseudo_bit_t	eq4_set_ci[0x00020];   /* EQ4_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved4[0x00020];
/* -------------- */
    pseudo_bit_t	eq5_set_ci[0x00020];   /* EQ5_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved5[0x00020];
/* -------------- */
    pseudo_bit_t	eq6_set_ci[0x00020];   /* EQ6_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved6[0x00020];
/* -------------- */
    pseudo_bit_t	eq7_set_ci[0x00020];   /* EQ7_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved7[0x00020];
/* -------------- */
    pseudo_bit_t	eq8_set_ci[0x00020];   /* EQ8_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved8[0x00020];
/* -------------- */
    pseudo_bit_t	eq9_set_ci[0x00020];   /* EQ9_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved9[0x00020];
/* -------------- */
    pseudo_bit_t	eq10_set_ci[0x00020];  /* EQ10_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved10[0x00020];
/* -------------- */
    pseudo_bit_t	eq11_set_ci[0x00020];  /* EQ11_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved11[0x00020];
/* -------------- */
    pseudo_bit_t	eq12_set_ci[0x00020];  /* EQ12_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved12[0x00020];
/* -------------- */
    pseudo_bit_t	eq13_set_ci[0x00020];  /* EQ13_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved13[0x00020];
/* -------------- */
    pseudo_bit_t	eq14_set_ci[0x00020];  /* EQ14_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved14[0x00020];
/* -------------- */
    pseudo_bit_t	eq15_set_ci[0x00020];  /* EQ15_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved15[0x00020];
/* -------------- */
    pseudo_bit_t	eq16_set_ci[0x00020];  /* EQ16_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved16[0x00020];
/* -------------- */
    pseudo_bit_t	eq17_set_ci[0x00020];  /* EQ17_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved17[0x00020];
/* -------------- */
    pseudo_bit_t	eq18_set_ci[0x00020];  /* EQ18_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved18[0x00020];
/* -------------- */
    pseudo_bit_t	eq19_set_ci[0x00020];  /* EQ19_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved19[0x00020];
/* -------------- */
    pseudo_bit_t	eq20_set_ci[0x00020];  /* EQ20_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved20[0x00020];
/* -------------- */
    pseudo_bit_t	eq21_set_ci[0x00020];  /* EQ21_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved21[0x00020];
/* -------------- */
    pseudo_bit_t	eq22_set_ci[0x00020];  /* EQ22_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved22[0x00020];
/* -------------- */
    pseudo_bit_t	eq23_set_ci[0x00020];  /* EQ23_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved23[0x00020];
/* -------------- */
    pseudo_bit_t	eq24_set_ci[0x00020];  /* EQ24_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved24[0x00020];
/* -------------- */
    pseudo_bit_t	eq25_set_ci[0x00020];  /* EQ25_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved25[0x00020];
/* -------------- */
    pseudo_bit_t	eq26_set_ci[0x00020];  /* EQ26_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved26[0x00020];
/* -------------- */
    pseudo_bit_t	eq27_set_ci[0x00020];  /* EQ27_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved27[0x00020];
/* -------------- */
    pseudo_bit_t	eq28_set_ci[0x00020];  /* EQ28_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved28[0x00020];
/* -------------- */
    pseudo_bit_t	eq29_set_ci[0x00020];  /* EQ29_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved29[0x00020];
/* -------------- */
    pseudo_bit_t	eq30_set_ci[0x00020];  /* EQ30_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved30[0x00020];
/* -------------- */
    pseudo_bit_t	eq31_set_ci[0x00020];  /* EQ31_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved31[0x00020];
/* -------------- */
    pseudo_bit_t	eq32_set_ci[0x00020];  /* EQ32_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved32[0x00020];
/* -------------- */
    pseudo_bit_t	eq33_set_ci[0x00020];  /* EQ33_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved33[0x00020];
/* -------------- */
    pseudo_bit_t	eq34_set_ci[0x00020];  /* EQ34_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved34[0x00020];
/* -------------- */
    pseudo_bit_t	eq35_set_ci[0x00020];  /* EQ35_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved35[0x00020];
/* -------------- */
    pseudo_bit_t	eq36_set_ci[0x00020];  /* EQ36_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved36[0x00020];
/* -------------- */
    pseudo_bit_t	eq37_set_ci[0x00020];  /* EQ37_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved37[0x00020];
/* -------------- */
    pseudo_bit_t	eq38_set_ci[0x00020];  /* EQ38_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved38[0x00020];
/* -------------- */
    pseudo_bit_t	eq39_set_ci[0x00020];  /* EQ39_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved39[0x00020];
/* -------------- */
    pseudo_bit_t	eq40_set_ci[0x00020];  /* EQ40_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved40[0x00020];
/* -------------- */
    pseudo_bit_t	eq41_set_ci[0x00020];  /* EQ41_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved41[0x00020];
/* -------------- */
    pseudo_bit_t	eq42_set_ci[0x00020];  /* EQ42_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved42[0x00020];
/* -------------- */
    pseudo_bit_t	eq43_set_ci[0x00020];  /* EQ43_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved43[0x00020];
/* -------------- */
    pseudo_bit_t	eq44_set_ci[0x00020];  /* EQ44_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved44[0x00020];
/* -------------- */
    pseudo_bit_t	eq45_set_ci[0x00020];  /* EQ45_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved45[0x00020];
/* -------------- */
    pseudo_bit_t	eq46_set_ci[0x00020];  /* EQ46_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved46[0x00020];
/* -------------- */
    pseudo_bit_t	eq47_set_ci[0x00020];  /* EQ47_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved47[0x00020];
/* -------------- */
    pseudo_bit_t	eq48_set_ci[0x00020];  /* EQ48_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved48[0x00020];
/* -------------- */
    pseudo_bit_t	eq49_set_ci[0x00020];  /* EQ49_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved49[0x00020];
/* -------------- */
    pseudo_bit_t	eq50_set_ci[0x00020];  /* EQ50_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved50[0x00020];
/* -------------- */
    pseudo_bit_t	eq51_set_ci[0x00020];  /* EQ51_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved51[0x00020];
/* -------------- */
    pseudo_bit_t	eq52_set_ci[0x00020];  /* EQ52_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved52[0x00020];
/* -------------- */
    pseudo_bit_t	eq53_set_ci[0x00020];  /* EQ53_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved53[0x00020];
/* -------------- */
    pseudo_bit_t	eq54_set_ci[0x00020];  /* EQ54_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved54[0x00020];
/* -------------- */
    pseudo_bit_t	eq55_set_ci[0x00020];  /* EQ55_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved55[0x00020];
/* -------------- */
    pseudo_bit_t	eq56_set_ci[0x00020];  /* EQ56_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved56[0x00020];
/* -------------- */
    pseudo_bit_t	eq57_set_ci[0x00020];  /* EQ57_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved57[0x00020];
/* -------------- */
    pseudo_bit_t	eq58_set_ci[0x00020];  /* EQ58_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved58[0x00020];
/* -------------- */
    pseudo_bit_t	eq59_set_ci[0x00020];  /* EQ59_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved59[0x00020];
/* -------------- */
    pseudo_bit_t	eq60_set_ci[0x00020];  /* EQ60_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved60[0x00020];
/* -------------- */
    pseudo_bit_t	eq61_set_ci[0x00020];  /* EQ61_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved61[0x00020];
/* -------------- */
    pseudo_bit_t	eq62_set_ci[0x00020];  /* EQ62_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved62[0x00020];
/* -------------- */
    pseudo_bit_t	eq63_set_ci[0x00020];  /* EQ63_Set_CI */
/* -------------- */
    pseudo_bit_t	reserved63[0x00020];
/* -------------- */
}; 

/* InfiniHost-III-EX Configuration Registers     #### michal - match to PRM */

struct hermonprm_configuration_registers_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x403400];
/* -------------- */
    struct hermonprm_hca_command_register_st	hca_command_interface_register;/* HCA Command Register */
/* -------------- */
    pseudo_bit_t	reserved1[0x3fcb20];
/* -------------- */
}; 

/* QP_DB_Record         ### michal = gdror fixed */

struct hermonprm_qp_db_record_st {	/* Little Endian */
    pseudo_bit_t	receive_wqe_counter[0x00010];/* Modulo-64K counter of WQEs posted to the QP since its creation. Should be initialized to zero. */
    pseudo_bit_t	reserved0[0x00010];
/* -------------- */
}; 

/* CQ_ARM_DB_Record */

struct hermonprm_cq_arm_db_record_st {	/* Little Endian */
    pseudo_bit_t	counter[0x00020];      /* CQ counter for the arming request */
/* -------------- */
    pseudo_bit_t	cmd[0x00003];          /* 0x0 - No command
                                                 0x1 - Request notification for next Solicited completion event. Counter filed specifies the current CQ Consumer Counter.
                                                 0x2 - Request notification for next Solicited or Unsolicited completion event. Counter filed specifies the current CQ Consumer counter.
                                                 0x3 - Request notification for multiple completions (Arm-N). Counter filed specifies the value of the CQ Index that when reached by HW (i.e. HW generates a CQE into this Index) Event will be generated
                                                 Other - Reserved */
    pseudo_bit_t	cmd_sn[0x00002];       /* Command Sequence Number - See Table 35, "CQ Doorbell Layout" for definition of this filed */
    pseudo_bit_t	res[0x00003];          /* Must be 0x2 */
    pseudo_bit_t	cq_number[0x00018];    /* CQ number */
/* -------------- */
}; 

/* CQ_CI_DB_Record */

struct hermonprm_cq_ci_db_record_st {	/* Little Endian */
    pseudo_bit_t	counter[0x00020];      /* CQ counter */
/* -------------- */
    pseudo_bit_t	reserved0[0x00005];
    pseudo_bit_t	res[0x00003];          /* Must be 0x1 */
    pseudo_bit_t	cq_number[0x00018];    /* CQ number */
/* -------------- */
}; 

/* Virtual_Physical_Mapping */

struct hermonprm_virtual_physical_mapping_st {	/* Little Endian */
    pseudo_bit_t	va_h[0x00020];         /* Virtual Address[63:32]. Valid only for MAP_ICM command. */
/* -------------- */
    pseudo_bit_t	reserved0[0x0000c];
    pseudo_bit_t	va_l[0x00014];         /* Virtual Address[31:12]. Valid only for MAP_ICM command. */
/* -------------- */
    pseudo_bit_t	pa_h[0x00020];         /* Physical Address[63:32] */
/* -------------- */
    pseudo_bit_t	log2size[0x00006];     /* Log2 of the size in 4KB pages of the physical and virtual contiguous memory that starts at PA_L/H and VA_L/H */
    pseudo_bit_t	reserved1[0x00006];
    pseudo_bit_t	pa_l[0x00014];         /* Physical Address[31:12] */
/* -------------- */
}; 

/* MOD_STAT_CFG            #### michal - gdror fix */

struct hermonprm_mod_stat_cfg_st {	/* Little Endian */
    pseudo_bit_t	log_pg_sz[0x00008];
    pseudo_bit_t	log_pg_sz_m[0x00001];
    pseudo_bit_t	reserved0[0x00005];
    pseudo_bit_t	dife[0x00001];
    pseudo_bit_t	dife_m[0x00001];
    pseudo_bit_t	rx_options[0x00004];   /* number of RX options to sweep when doing SerDes parameters AutoNegotiation. */
    pseudo_bit_t	reserved1[0x00003];
    pseudo_bit_t	rx_options_m[0x00001]; /* Modify rx_options */
    pseudo_bit_t	tx_options[0x00004];   /* number of TX options to sweep when doing SerDes parameters AutoNegotiation. */
    pseudo_bit_t	reserved2[0x00003];
    pseudo_bit_t	tx_options_m[0x00001]; /* Modify tx_options */
/* -------------- */
    pseudo_bit_t	reserved3[0x00010];
    pseudo_bit_t	qdr_rx_options[0x00004];
    pseudo_bit_t	reserved4[0x00003];
    pseudo_bit_t	qdr_rx_options_m[0x00001];
    pseudo_bit_t	qdr_tx_options[0x00004];
    pseudo_bit_t	reserved5[0x00003];
    pseudo_bit_t	qdr_tx_options_m[0x00001];
/* -------------- */
    pseudo_bit_t	reserved6[0x00020];
/* -------------- */
    pseudo_bit_t	lid[0x00010];          /* default LID */
    pseudo_bit_t	lid_m[0x00001];        /* Modify default LID */
    pseudo_bit_t	reserved7[0x00003];
    pseudo_bit_t	port_en[0x00001];      /* enable port (E_Key) */
    pseudo_bit_t	port_en_m[0x00001];    /* Modify  port_en */
    pseudo_bit_t	reserved8[0x00002];
    pseudo_bit_t	port_pause_mode[0x00002];
    pseudo_bit_t	reserved9[0x00001];
    pseudo_bit_t	port_pause_mode_m[0x00001];
    pseudo_bit_t	reserved10[0x00004];
/* -------------- */
    pseudo_bit_t	reserved11[0x0001f];
    pseudo_bit_t	guid_hi_m[0x00001];    /* Modify guid_hi */
/* -------------- */
    pseudo_bit_t	guid_hi[0x00020];
/* -------------- */
    pseudo_bit_t	reserved12[0x0001f];
    pseudo_bit_t	guid_lo_m[0x00001];    /* Modify guid_lo */
/* -------------- */
    pseudo_bit_t	guid_lo[0x00020];
/* -------------- */
    pseudo_bit_t	reserved13[0x0001f];
    pseudo_bit_t	nodeguid_hi_m[0x00001];
/* -------------- */
    pseudo_bit_t	nodeguid_hi[0x00020];
/* -------------- */
    pseudo_bit_t	reserved14[0x0001f];
    pseudo_bit_t	nodeguid_lo_m[0x00001];
/* -------------- */
    pseudo_bit_t	nodeguid_lo[0x00020];
/* -------------- */
    pseudo_bit_t	ob_preemp_pre[0x00005];
    pseudo_bit_t	reserved15[0x00003];
    pseudo_bit_t	ob_preemp_post[0x00005];
    pseudo_bit_t	reserved16[0x00003];
    pseudo_bit_t	ob_preemp_main[0x00005];
    pseudo_bit_t	reserved17[0x00003];
    pseudo_bit_t	ob_preemp[0x00005];
    pseudo_bit_t	reserved18[0x00002];
    pseudo_bit_t	serdes_m[0x00001];
/* -------------- */
    pseudo_bit_t	inbuf_ind_en[0x00003];
    pseudo_bit_t	reserved19[0x00001];
    pseudo_bit_t	sd_main[0x00004];
    pseudo_bit_t	reserved20[0x00004];
    pseudo_bit_t	sd_equal[0x00004];
    pseudo_bit_t	reserved21[0x00004];
    pseudo_bit_t	sd_mux_main[0x00002];
    pseudo_bit_t	reserved22[0x00002];
    pseudo_bit_t	mux_eq[0x00002];
    pseudo_bit_t	reserved23[0x00002];
    pseudo_bit_t	sigdet_th[0x00003];
    pseudo_bit_t	reserved24[0x00001];
/* -------------- */
    pseudo_bit_t	reserved25[0x00040];
/* -------------- */
    pseudo_bit_t	port_protocol[0x00008];
    pseudo_bit_t	port_dual[0x00001];
    pseudo_bit_t	reserved26[0x00006];
    pseudo_bit_t	port_protocol_m[0x00001];
    pseudo_bit_t	num_port[0x00008];
    pseudo_bit_t	reserved27[0x00008];
/* -------------- */
    pseudo_bit_t	port_protocol_vpi[0x00008];
    pseudo_bit_t	reserved28[0x00018];
/* -------------- */
    pseudo_bit_t	reserved29[0x00180];
/* -------------- */
    pseudo_bit_t	fw_rev_major[0x00010];
    pseudo_bit_t	reserved30[0x0000f];
    pseudo_bit_t	fw_rev_support[0x00001];
/* -------------- */
    pseudo_bit_t	fw_rev_minor[0x00010];
    pseudo_bit_t	fw_rev_subminor[0x00010];
/* -------------- */
    pseudo_bit_t	cmd_interface_rev[0x00010];
    pseudo_bit_t	reserved31[0x00010];
/* -------------- */
    pseudo_bit_t	reserved32[0x00060];
/* -------------- */
    pseudo_bit_t	mac_high[0x00010];
    pseudo_bit_t	reserved33[0x0000f];
    pseudo_bit_t	mac_m[0x00001];
/* -------------- */
    pseudo_bit_t	mac_low[0x00020];
/* -------------- */
    pseudo_bit_t	reserved34[0x00010];
    pseudo_bit_t	num_veps[0x00008];
    pseudo_bit_t	num_vep_groups[0x00008];
/* -------------- */
    pseudo_bit_t	reserved35[0x00020];
/* -------------- */
    pseudo_bit_t	reserved36[0x00018];
    pseudo_bit_t	outer_vlan_en[0x00001];
    pseudo_bit_t	reserved37[0x00002];
    pseudo_bit_t	outer_vlan_en_m[0x00001];
    pseudo_bit_t	port_net_boot[0x00001];
    pseudo_bit_t	reserved38[0x00002];
    pseudo_bit_t	port_net_boot_m[0x00001];
/* -------------- */
    pseudo_bit_t	reserved39[0x00060];
/* -------------- */
    pseudo_bit_t	port_eth_mode_capability[0x0001f];
    pseudo_bit_t	reserved40[0x00001];
/* -------------- */
    pseudo_bit_t	port_eth_mode_enabled[0x0001f];
    pseudo_bit_t	port_eth_mod_m[0x00001];
/* -------------- */
    pseudo_bit_t	port_eth_mode_current[0x0001f];
    pseudo_bit_t	reserved41[0x00001];
/* -------------- */
    pseudo_bit_t	reserved42[0x00220];
};

/* SRQ Context */

struct hermonprm_srq_context_st {	/* Little Endian */
    pseudo_bit_t	srqn[0x00018];         /* SRQ number */
    pseudo_bit_t	log_srq_size[0x00004]; /* Log2 of the Number of WQEs in the Receive Queue.
                                                 Maximum value is 0x10, i.e. 16M WQEs. */
    pseudo_bit_t	state[0x00004];        /* SRQ State:
                                                 1111 - SW Ownership
                                                 0000 - HW Ownership
                                                 0001 - Error
                                                 Valid only on QUERY_SRQ and HW2SW_SRQ commands. */
/* -------------- */
    pseudo_bit_t	src_domain[0x00010];   /* The Scalable RC Domain. Messages coming to receive ports specifying this SRQ as receive queue will be served only if SRC_Domain of the SRQ matches SRC_Domain of the transport QP of this message. */
    pseudo_bit_t	reserved0[0x00008];
    pseudo_bit_t	log_srq_stride[0x00003];/* Stride (max WQE size) on the receive queue. WQ entry is 16*(2^log_RQ_stride) bytes. */
    pseudo_bit_t	reserved1[0x00005];
/* -------------- */
    pseudo_bit_t	cqn[0x00018];          /* Completion Queue to report SRC messages directed to this SRQ. */
    pseudo_bit_t	page_offset[0x00006];  /* The offset of the first WQE from the beginning of 4Kbyte page (Figure 52,�Work Queue Buffer Structure�) */
    pseudo_bit_t	reserved2[0x00002];
/* -------------- */
    pseudo_bit_t	reserved3[0x00020];
/* -------------- */
    pseudo_bit_t	mtt_base_addr_h[0x00008];/* MTT Base Address [39:32] in ICM relative to INIT_HCA.mtt_base_addr */
    pseudo_bit_t	reserved4[0x00010];
    pseudo_bit_t	log2_page_size[0x00006];/* Log (base 2) of MTT page size in units of 4KByte */
    pseudo_bit_t	reserved5[0x00002];
/* -------------- */
    pseudo_bit_t	reserved6[0x00003];
    pseudo_bit_t	mtt_base_addr_l[0x0001d];/* MTT Base Address [31:3] in ICM relative to INIT_HCA.mtt_base_addr */
/* -------------- */
    pseudo_bit_t	pd[0x00018];           /* SRQ protection domain */
    pseudo_bit_t	reserved7[0x00008];
/* -------------- */
    pseudo_bit_t	wqe_cnt[0x00010];      /* WQE count on the SRQ. Valid only upon QUERY_SRQ and HW2SW_SRQ commands. */
    pseudo_bit_t	lwm[0x00010];          /* Limit Water Mark - if the LWM is not zero, and the wqe_cnt drops below LWM when a WQE is dequeued from the SRQ, then an SRQ limit event is fired and the LWM is set to zero. Valid only upon QUERY_SRQ and HW2SW_SRQ commands. */
/* -------------- */
    pseudo_bit_t	srq_wqe_counter[0x00010];/* A 16-bit counter incremented for each WQE posted to the SRQ. Must be 0x0 in SRQ initialization. Valid only upon the QUERY_SRQ command. */
    pseudo_bit_t	reserved8[0x00010];
/* -------------- */
    pseudo_bit_t	reserved9[0x00020];
/* -------------- */
    pseudo_bit_t	db_record_addr_h[0x00020];/* SRQ DB Record physical address [63:32] */
/* -------------- */
    pseudo_bit_t	reserved10[0x00002];
    pseudo_bit_t	db_record_addr_l[0x0001e];/* SRQ DB Record physical address [31:2] */
/* -------------- */
}; 

/* PBL */

struct hermonprm_pbl_st {	/* Little Endian */
    pseudo_bit_t	mtt_0_h[0x00020];      /* First MTT[63:32] */
/* -------------- */
    pseudo_bit_t	mtt_0_l[0x00020];      /* First MTT[31:0] */
/* -------------- */
    pseudo_bit_t	mtt_1_h[0x00020];      /* Second MTT[63:32] */
/* -------------- */
    pseudo_bit_t	mtt_1_l[0x00020];      /* Second MTT[31:0] */
/* -------------- */
    pseudo_bit_t	mtt_2_h[0x00020];      /* Third MTT[63:32] */
/* -------------- */
    pseudo_bit_t	mtt_2_l[0x00020];      /* Third MTT[31:0] */
/* -------------- */
    pseudo_bit_t	mtt_3_h[0x00020];      /* Fourth MTT[63:32] */
/* -------------- */
    pseudo_bit_t	mtt_3_l[0x00020];      /* Fourth MTT[31:0] */
/* -------------- */
}; 

/* Performance Counters   #### michal - gdror fixed */

struct hermonprm_performance_counters_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00080];
/* -------------- */
    pseudo_bit_t	reserved1[0x00080];
/* -------------- */
    pseudo_bit_t	reserved2[0x00080];
/* -------------- */
    pseudo_bit_t	reserved3[0x00060];
/* -------------- */
    pseudo_bit_t	reserved4[0x00620];
/* -------------- */
}; 

/* Transport and CI Error Counters */

struct hermonprm_transport_and_ci_error_counters_st {	/* Little Endian */
    pseudo_bit_t	rq_num_lle[0x00020];   /* Responder - number of local length errors */
/* -------------- */
    pseudo_bit_t	sq_num_lle[0x00020];   /* Requester - number of local length errors */
/* -------------- */
    pseudo_bit_t	rq_num_lqpoe[0x00020]; /* Responder - number local QP operation error */
/* -------------- */
    pseudo_bit_t	sq_num_lqpoe[0x00020]; /* Requester - number local QP operation error */
/* -------------- */
    pseudo_bit_t	rq_num_leeoe[0x00020]; /* Responder - number local EE operation error */
/* -------------- */
    pseudo_bit_t	sq_num_leeoe[0x00020]; /* Requester - number local EE operation error */
/* -------------- */
    pseudo_bit_t	rq_num_lpe[0x00020];   /* Responder - number of local protection errors */
/* -------------- */
    pseudo_bit_t	sq_num_lpe[0x00020];   /* Requester - number of local protection errors */
/* -------------- */
    pseudo_bit_t	rq_num_wrfe[0x00020];  /* Responder - number of CQEs with error. 
                                                 Incremented each time a CQE with error is generated */
/* -------------- */
    pseudo_bit_t	sq_num_wrfe[0x00020];  /* Requester - number of CQEs with error. 
                                                 Incremented each time a CQE with error is generated */
/* -------------- */
    pseudo_bit_t	reserved0[0x00020];
/* -------------- */
    pseudo_bit_t	sq_num_mwbe[0x00020];  /* Requester - number of memory window bind errors */
/* -------------- */
    pseudo_bit_t	reserved1[0x00020];
/* -------------- */
    pseudo_bit_t	sq_num_bre[0x00020];   /* Requester - number of bad response errors */
/* -------------- */
    pseudo_bit_t	rq_num_lae[0x00020];   /* Responder - number of local access errors */
/* -------------- */
    pseudo_bit_t	reserved2[0x00040];
/* -------------- */
    pseudo_bit_t	sq_num_rire[0x00020];  /* Requester - number of remote invalid request errors
                                                 NAK-Invalid Request on:
                                                 1. Unsupported OpCode: Responder detected an unsupported OpCode.
                                                 2. Unexpected OpCode: Responder detected an error in the sequence of OpCodes, such
                                                 as a missing "Last" packet.
                                                 Note: there is no PSN error, thus this does not indicate a dropped packet. */
/* -------------- */
    pseudo_bit_t	rq_num_rire[0x00020];  /* Responder - number of remote invalid request errors.
                                                 NAK may or may not be sent.
                                                 1. QP Async Affiliated Error: Unsupported or Reserved OpCode (RC,RD only):
                                                 Inbound request OpCode was either reserved, or was for a function not supported by this
                                                 QP. (E.g. RDMA or ATOMIC on QP not set up for this).
                                                 2. Misaligned ATOMIC: VA does not point to an aligned address on an atomic opera-tion.
                                                 3. Too many RDMA READ or ATOMIC Requests: There were more requests received
                                                 and not ACKed than allowed for the connection.
                                                 4. Out of Sequence OpCode, current packet is "First" or "Only": The Responder
                                                 detected an error in the sequence of OpCodes; a missing "Last" packet
                                                 5. Out of Sequence OpCode, current packet is not "First" or "Only": The Responder
                                                 detected an error in the sequence of OpCodes; a missing "First" packet
                                                 6. Local Length Error: Inbound "Send" request message exceeded the responder.s avail-able
                                                 buffer space.
                                                 7. Length error: RDMA WRITE request message contained too much or too little pay-load
                                                 data compared to the DMA length advertised in the first or only packet.
                                                 8. Length error: Payload length was not consistent with the opcode:
                                                 a: 0 byte <= "only" <= PMTU bytes
                                                 b: ("first" or "middle") == PMTU bytes
                                                 c: 1byte <= "last" <= PMTU bytes
                                                 9. Length error: Inbound message exceeded the size supported by the CA port. */
/* -------------- */
    pseudo_bit_t	sq_num_rae[0x00020];   /* Requester - number of remote access errors.
                                                 NAK-Remote Access Error on:
                                                 R_Key Violation: Responder detected an invalid R_Key while executing an RDMA
                                                 Request. */
/* -------------- */
    pseudo_bit_t	rq_num_rae[0x00020];   /* Responder - number of remote access errors.
                                                 R_Key Violation Responder detected an R_Key violation while executing an RDMA
                                                 request.
                                                 NAK may or may not be sent. */
/* -------------- */
    pseudo_bit_t	sq_num_roe[0x00020];   /* Requester - number of remote operation errors.
                                                 NAK-Remote Operation Error on:
                                                 Remote Operation Error: Responder encountered an error, (local to the responder),
                                                 which prevented it from completing the request. */
/* -------------- */
    pseudo_bit_t	rq_num_roe[0x00020];   /* Responder - number of remote operation errors.
                                                 NAK-Remote Operation Error on:
                                                 1. Malformed WQE: Responder detected a malformed Receive Queue WQE while pro-cessing
                                                 the packet.
                                                 2. Remote Operation Error: Responder encountered an error, (local to the responder),
                                                 which prevented it from completing the request. */
/* -------------- */
    pseudo_bit_t	sq_num_tree[0x00020];  /* Requester - number of transport retries exceeded errors */
/* -------------- */
    pseudo_bit_t	reserved3[0x00020];
/* -------------- */
    pseudo_bit_t	sq_num_rree[0x00020];  /* Requester - number of RNR nak retries exceeded errors */
/* -------------- */
    pseudo_bit_t	rq_num_rnr[0x00020];   /* Responder - the number of RNR Naks sent */
/* -------------- */
    pseudo_bit_t	sq_num_rnr[0x00020];   /* Requester - the number of RNR Naks received */
/* -------------- */
    pseudo_bit_t	reserved4[0x00040];
/* -------------- */
    pseudo_bit_t	reserved5[0x00020];
/* -------------- */
    pseudo_bit_t	sq_num_rabrte[0x00020];/* Requester - number of remote aborted errors */
/* -------------- */
    pseudo_bit_t	reserved6[0x00020];
/* -------------- */
    pseudo_bit_t	sq_num_ieecne[0x00020];/* Requester - number of invalid EE context number errors */
/* -------------- */
    pseudo_bit_t	reserved7[0x00020];
/* -------------- */
    pseudo_bit_t	sq_num_ieecse[0x00020];/* Requester - invalid EE context state errors */
/* -------------- */
    pseudo_bit_t	reserved8[0x00380];
/* -------------- */
    pseudo_bit_t	rq_num_oos[0x00020];   /* Responder - number of out of sequence requests received */
/* -------------- */
    pseudo_bit_t	sq_num_oos[0x00020];   /* Requester - number of out of sequence Naks received */
/* -------------- */
    pseudo_bit_t	rq_num_mce[0x00020];   /* Responder - number of bad multicast packets received */
/* -------------- */
    pseudo_bit_t	reserved9[0x00020];
/* -------------- */
    pseudo_bit_t	rq_num_rsync[0x00020]; /* Responder - number of RESYNC operations */
/* -------------- */
    pseudo_bit_t	sq_num_rsync[0x00020]; /* Requester - number of RESYNC operations */
/* -------------- */
    pseudo_bit_t	rq_num_udsdprd[0x00020];/* The number of UD packets silently discarded on the receive queue due to lack of receive descriptor. */
/* -------------- */
    pseudo_bit_t	reserved10[0x00020];
/* -------------- */
    pseudo_bit_t	rq_num_ucsdprd[0x00020];/* The number of UC packets silently discarded on the receive queue due to lack of receive descriptor. */
/* -------------- */
    pseudo_bit_t	reserved11[0x003e0];
/* -------------- */
    pseudo_bit_t	num_cqovf[0x00020];    /* Number of CQ overflows */
/* -------------- */
    pseudo_bit_t	num_eqovf[0x00020];    /* Number of EQ overflows */
/* -------------- */
    pseudo_bit_t	num_baddb[0x00020];    /* Number of bad doorbells */
/* -------------- */
    pseudo_bit_t	reserved12[0x002a0];
/* -------------- */
}; 

/* Event_data Field - HCR Completion Event   #### michal - match PRM */

struct hermonprm_hcr_completion_event_st {	/* Little Endian */
    pseudo_bit_t	token[0x00010];        /* HCR Token */
    pseudo_bit_t	reserved0[0x00010];
/* -------------- */
    pseudo_bit_t	reserved1[0x00020];
/* -------------- */
    pseudo_bit_t	status[0x00008];       /* HCR Status */
    pseudo_bit_t	reserved2[0x00018];
/* -------------- */
    pseudo_bit_t	out_param_h[0x00020];  /* HCR Output Parameter [63:32] */
/* -------------- */
    pseudo_bit_t	out_param_l[0x00020];  /* HCR Output Parameter [31:0] */
/* -------------- */
    pseudo_bit_t	reserved3[0x00020];
/* -------------- */
}; 

/* Completion with Error CQE             #### michal - gdror fixed */

struct hermonprm_completion_with_error_st {	/* Little Endian */
    pseudo_bit_t	qpn[0x00018];          /* Indicates the QP for which completion is being reported */
    pseudo_bit_t	reserved0[0x00008];
/* -------------- */
    pseudo_bit_t	reserved1[0x000a0];
/* -------------- */
    pseudo_bit_t	syndrome[0x00008];     /* Completion with error syndrome:
                                                         0x01 - Local Length Error
                                                         0x02 - Local QP Operation Error
                                                         0x03 - Local EE Context Operation Error
                                                         0x04 - Local Protection Error
                                                         0x05 - Work Request Flushed Error 
                                                         0x06 - Memory Window Bind Error
                                                         0x10 - Bad Response Error
                                                         0x11 - Local Access Error
                                                         0x12 - Remote Invalid Request Error
                                                         0x13 - Remote Access Error
                                                         0x14 - Remote Operation Error
                                                         0x15 - Transport Retry Counter Exceeded
                                                         0x16 - RNR Retry Counter Exceeded
                                                         0x20 - Local RDD Violation Error
                                                         0x21 - Remote Invalid RD Request
                                                         0x22 - Remote Aborted Error
                                                         0x23 - Invalid EE Context Number
                                                         0x24 - Invalid EE Context State
                                                         other - Reserved
                                                 Syndrome is defined according to the IB specification volume 1. For detailed explanation of the syndromes, refer to chapters 10-11 of the IB specification rev 1.1. */
    pseudo_bit_t	vendor_error_syndrome[0x00008];
    pseudo_bit_t	wqe_counter[0x00010];
/* -------------- */
    pseudo_bit_t	opcode[0x00005];       /* The opcode of WQE completion is reported for.
                                                 
                                                 The following values are reported in case of completion with error:
                                                 0xFE - For completion with error on Receive Queues
                                                 0xFF - For completion with error on Send Queues */
    pseudo_bit_t	reserved2[0x00001];
    pseudo_bit_t	s_r[0x00001];          /* send 1 / receive 0 */
    pseudo_bit_t	owner[0x00001];        /* HW Flips this bit for every CQ warp around. Initialized to Zero. */
    pseudo_bit_t	reserved3[0x00018];
/* -------------- */
}; 

/* Resize CQ Input Mailbox */

struct hermonprm_resize_cq_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00040];
/* -------------- */
    pseudo_bit_t	reserved1[0x00006];
    pseudo_bit_t	page_offset[0x00006];
    pseudo_bit_t	reserved2[0x00014];
/* -------------- */
    pseudo_bit_t	reserved3[0x00018];
    pseudo_bit_t	log_cq_size[0x00005];  /* Log (base 2) of the CQ size (in entries) */
    pseudo_bit_t	reserved4[0x00003];
/* -------------- */
    pseudo_bit_t	reserved5[0x00020];
/* -------------- */
    pseudo_bit_t	mtt_base_addr_h[0x00008];
    pseudo_bit_t	reserved6[0x00010];
    pseudo_bit_t	log2_page_size[0x00006];
    pseudo_bit_t	reserved7[0x00002];
/* -------------- */
    pseudo_bit_t	reserved8[0x00003];
    pseudo_bit_t	mtt_base_addr_l[0x0001d];
/* -------------- */
    pseudo_bit_t	reserved9[0x00020];
/* -------------- */
    pseudo_bit_t	reserved10[0x00100];
/* -------------- */
}; 

/* MAD_IFC Input Modifier */

struct hermonprm_mad_ifc_input_modifier_st {	/* Little Endian */
    pseudo_bit_t	port_number[0x00008];  /* The packet reception port number (1 or 2). */
    pseudo_bit_t	mad_extended_info[0x00001];/* Mad_Extended_Info valid bit (MAD_IFC Input Mailbox data from offset 00100h and down). MAD_Extended_Info is read only if this bit is set.
                                                 Required for trap generation when BKey check is enabled and for global routed packets. */
    pseudo_bit_t	reserved0[0x00007];
    pseudo_bit_t	rlid[0x00010];         /* Remote (source) LID  from the received MAD.
                                                 This field is required for trap generation upon MKey/BKey validation. */
/* -------------- */
}; 

/* MAD_IFC Input Mailbox     ###michal -gdror fixed */

struct hermonprm_mad_ifc_st {	/* Little Endian */
    pseudo_bit_t	request_mad_packet[64][0x00020];/* Request MAD Packet (256bytes) */
/* -------------- */
    pseudo_bit_t	my_qpn[0x00018];       /* Destination QP number from the received MAD. 
                                                 This field is reserved if Mad_extended_info indication in the input modifier is clear. */
    pseudo_bit_t	reserved0[0x00008];
/* -------------- */
    pseudo_bit_t	reserved1[0x00020];
/* -------------- */
    pseudo_bit_t	rqpn[0x00018];         /* Remote (source) QP number  from the received MAD.
                                                 This field is reserved if Mad_extended_info indication in the input modifier is clear. */
    pseudo_bit_t	reserved2[0x00008];
/* -------------- */
    pseudo_bit_t	reserved3[0x00010];
    pseudo_bit_t	ml_path[0x00007];      /* My (destination) LID path bits  from the received MAD.
                                                 This field is reserved if Mad_extended_info indication in the input modifier is clear. */
    pseudo_bit_t	g[0x00001];            /* If set, the GRH field in valid. 
                                                 This field is reserved if Mad_extended_info indication in the input modifier is clear. */
    pseudo_bit_t	reserved4[0x00004];
    pseudo_bit_t	sl[0x00004];           /* Service Level of the received MAD.
                                                 This field is reserved if Mad_extended_info indication in the input modifier is clear. */
/* -------------- */
    pseudo_bit_t	pkey_indx[0x00010];    /* Index in PKey table that matches PKey of the received MAD. 
                                                 This field is reserved if Mad_extended_info indication in the input modifier is clear. */
    pseudo_bit_t	reserved5[0x00010];
/* -------------- */
    pseudo_bit_t	reserved6[0x00160];
/* -------------- */
    pseudo_bit_t	grh[10][0x00020];      /* The GRH field of the MAD packet that was scattered to the first 40 bytes pointed to by the scatter list. 
                                                 Valid if Mad_extended_info bit (in the input modifier) and g bit are set. 
                                                 Otherwise this field is reserved. */
/* -------------- */
    pseudo_bit_t	reserved7[0x004c0];
/* -------------- */
}; 

/* Query Debug Message     #### michal - gdror fixed */

struct hermonprm_query_debug_msg_st {	/* Little Endian */
    pseudo_bit_t	phy_addr_h[0x00020];   /* Translation of the address in firmware area. High 32 bits. */
/* -------------- */
    pseudo_bit_t	v[0x00001];            /* Physical translation is valid */
    pseudo_bit_t	reserved0[0x0000b];
    pseudo_bit_t	phy_addr_l[0x00014];   /* Translation of the address in firmware area. Low 32 bits. */
/* -------------- */
    pseudo_bit_t	fw_area_base[0x00020]; /* Firmware area base address. The format strings and the trace buffers may be located starting from this address. */
/* -------------- */
    pseudo_bit_t	fw_area_size[0x00020]; /* Firmware area size */
/* -------------- */
    pseudo_bit_t	trc_hdr_sz[0x00020];   /* Trace message header size in dwords. */
/* -------------- */
    pseudo_bit_t	trc_arg_num[0x00020];  /* The number of arguments per trace message. */
/* -------------- */
    pseudo_bit_t	reserved1[0x000c0];
/* -------------- */
    pseudo_bit_t	dbg_msk_h[0x00020];    /* Debug messages mask [63:32] */
/* -------------- */
    pseudo_bit_t	dbg_msk_l[0x00020];    /* Debug messages mask [31:0] */
/* -------------- */
    pseudo_bit_t	reserved2[0x00040];
/* -------------- */
    pseudo_bit_t	buff0_addr[0x00020];   /* Address in firmware area of Trace Buffer 0 */
/* -------------- */
    pseudo_bit_t	buff0_size[0x00020];   /* Size of Trace Buffer 0 */
/* -------------- */
    pseudo_bit_t	buff1_addr[0x00020];   /* Address in firmware area of Trace Buffer 1 */
/* -------------- */
    pseudo_bit_t	buff1_size[0x00020];   /* Size of Trace Buffer 1 */
/* -------------- */
    pseudo_bit_t	buff2_addr[0x00020];   /* Address in firmware area of Trace Buffer 2 */
/* -------------- */
    pseudo_bit_t	buff2_size[0x00020];   /* Size of Trace Buffer 2 */
/* -------------- */
    pseudo_bit_t	buff3_addr[0x00020];   /* Address in firmware area of Trace Buffer 3 */
/* -------------- */
    pseudo_bit_t	buff3_size[0x00020];   /* Size of Trace Buffer 3 */
/* -------------- */
    pseudo_bit_t	buff4_addr[0x00020];   /* Address in firmware area of Trace Buffer 4 */
/* -------------- */
    pseudo_bit_t	buff4_size[0x00020];   /* Size of Trace Buffer 4 */
/* -------------- */
    pseudo_bit_t	buff5_addr[0x00020];   /* Address in firmware area of Trace Buffer 5 */
/* -------------- */
    pseudo_bit_t	buff5_size[0x00020];   /* Size of Trace Buffer 5 */
/* -------------- */
    pseudo_bit_t	reserved3[0x00080];
/* -------------- */
    pseudo_bit_t	hw_buff_addr[0x00020]; /* Dror Mux Bohrer tracer */
/* -------------- */
    pseudo_bit_t	hw_buff_size[0x00020];
/* -------------- */
    pseudo_bit_t	reserved4[0x003c0];
/* -------------- */
}; 

/* User Access Region */

struct hermonprm_uar_st {	/* Little Endian */
    struct hermonprm_rd_send_doorbell_st	rd_send_doorbell;/* Reliable Datagram send doorbell */
/* -------------- */
    struct hermonprm_send_doorbell_st	send_doorbell;/* Send doorbell */
/* -------------- */
    pseudo_bit_t	reserved0[0x00040];
/* -------------- */
    struct hermonprm_cq_cmd_doorbell_st	cq_command_doorbell;/* CQ Doorbell */
/* -------------- */
    pseudo_bit_t	reserved1[0x03ec0];
/* -------------- */
}; 

/* Receive doorbell */

struct hermonprm_receive_doorbell_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00008];
    pseudo_bit_t	wqe_counter[0x00010];  /* Modulo-64K counter of WQEs posted on this queue since its creation. Should be zero for the first doorbell on the QP */
    pseudo_bit_t	reserved1[0x00008];
/* -------------- */
    pseudo_bit_t	reserved2[0x00005];
    pseudo_bit_t	srq[0x00001];          /* If set, this is a Shared Receive Queue */
    pseudo_bit_t	reserved3[0x00002];
    pseudo_bit_t	qpn[0x00018];          /* QP number or SRQ number this doorbell is rung on */
/* -------------- */
}; 

/* SET_IB Parameters */

struct hermonprm_set_ib_st {	/* Little Endian */
    pseudo_bit_t	rqk[0x00001];          /* Reset QKey Violation Counter */
    pseudo_bit_t	reserved0[0x00011];
    pseudo_bit_t	sig[0x00001];          /* Set System Image GUID to system_image_guid specified.
                                                 system_image_guid and sig must be the same for all ports. */
    pseudo_bit_t	reserved1[0x0000d];
/* -------------- */
    pseudo_bit_t	capability_mask[0x00020];/* PortInfo Capability Mask */
/* -------------- */
    pseudo_bit_t	system_image_guid_h[0x00020];/* System Image GUID[63:32], takes effect only if the SIG bit is set
                                                 Must be the same for both ports. */
/* -------------- */
    pseudo_bit_t	system_image_guid_l[0x00020];/* System Image GUID[31:0], takes effect only if the SIG bit is set
                                                 Must be the same for both ports. */
/* -------------- */
    pseudo_bit_t	reserved2[0x00180];
/* -------------- */
}; 

/* Multicast Group Member    #### michal - gdror fixed */

struct hermonprm_mgm_entry_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00006];
    pseudo_bit_t	next_gid_index[0x0001a];/* Index of next Multicast Group Member whose GID maps to same MGID_HASH number.
                                                 The index is into the Multicast Group Table, which is the comprised the MGHT and AMGM tables.
                                                 next_gid_index=0 means end of the chain. */
/* -------------- */
    pseudo_bit_t	reserved1[0x00060];
/* -------------- */
    pseudo_bit_t	mgid_128_96[0x00020];  /* Multicast group GID[128:96] in big endian format.
                                                 Use the Reserved GID 0:0:0:0:0:0:0:0 for an invalid entry. */
/* -------------- */
    pseudo_bit_t	mgid_95_64[0x00020];   /* Multicast group GID[95:64] in big endian format.
                                                 Use the Reserved GID 0:0:0:0:0:0:0:0 for an invalid entry. */
/* -------------- */
    pseudo_bit_t	mgid_63_32[0x00020];   /* Multicast group GID[63:32] in big endian format.
                                                 Use the Reserved GID 0:0:0:0:0:0:0:0 for an invalid entry. */
/* -------------- */
    pseudo_bit_t	mgid_31_0[0x00020];    /* Multicast group GID[31:0] in big endian format.
                                                 Use the Reserved GID 0:0:0:0:0:0:0:0 for an invalid entry. */
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp_0;   /* Multicast Group Member QP */
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp_1;   /* Multicast Group Member QP */
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp_2;   /* Multicast Group Member QP */
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp_3;   /* Multicast Group Member QP */
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp_4;   /* Multicast Group Member QP */
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp_5;   /* Multicast Group Member QP */
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp_6;   /* Multicast Group Member QP */
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp_7;   /* Multicast Group Member QP */
/* -------------- */
}; 

/* INIT_PORT Parameters    #### michal - match PRM */

struct hermonprm_init_port_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00004];
    pseudo_bit_t	vl_cap[0x00004];       /* Maximum VLs supported on the port, excluding VL15.
                                                 Legal values are 1,2,4 and 8. */
    pseudo_bit_t	port_width_cap[0x00004];/* IB Port Width
                                                 1   - 1x
                                                 3   - 1x, 4x
                                                 11 - 1x, 4x or 12x (must not be used in InfiniHost-III-EX MT25208)
                                                 else - Reserved */
    pseudo_bit_t	reserved1[0x00004];
    pseudo_bit_t	g0[0x00001];           /* Set port GUID0 to GUID0 specified */
    pseudo_bit_t	ng[0x00001];           /* Set node GUID to node_guid specified.
                                                 node_guid and ng must be the same for all ports. */
    pseudo_bit_t	sig[0x00001];          /* Set System Image GUID to system_image_guid specified.
                                                 system_image_guid and sig must be the same for all ports. */
    pseudo_bit_t	reserved2[0x0000d];
/* -------------- */
    pseudo_bit_t	max_gid[0x00010];      /* Maximum number of GIDs for the port */
    pseudo_bit_t	mtu[0x00010];          /* Maximum MTU Supported in bytes
                                                 must be: 256, 512, 1024, 2048 or 4096
                                                 For Eth port, can be any
                                                 Field must not cross device capabilities as reported
                                                  */
/* -------------- */
    pseudo_bit_t	max_pkey[0x00010];     /* Maximum pkeys for the port.
                                                 Must be the same for both ports. */
    pseudo_bit_t	reserved3[0x00010];
/* -------------- */
    pseudo_bit_t	reserved4[0x00020];
/* -------------- */
    pseudo_bit_t	guid0_h[0x00020];      /* EUI-64 GUID assigned by the manufacturer, takes effect only if the G0 bit is set (bits 63:32) */
/* -------------- */
    pseudo_bit_t	guid0_l[0x00020];      /* EUI-64 GUID assigned by the manufacturer, takes effect only if the G0 bit is set (bits 31:0) */
/* -------------- */
    pseudo_bit_t	node_guid_h[0x00020];  /* Node GUID[63:32], takes effect only if the NG bit is set
                                                 Must be the same for both ports. */
/* -------------- */
    pseudo_bit_t	node_guid_l[0x00020];  /* Node GUID[31:0], takes effect only if the NG bit is set
                                                 Must be the same for both ports. */
/* -------------- */
    pseudo_bit_t	system_image_guid_h[0x00020];/* System Image GUID[63:32], takes effect only if the SIG bit is set
                                                 Must be the same for both ports. */
/* -------------- */
    pseudo_bit_t	system_image_guid_l[0x00020];/* System Image GUID[31:0], takes effect only if the SIG bit is set
                                                 Must be the same for both ports. */
/* -------------- */
    pseudo_bit_t	reserved5[0x006c0];
/* -------------- */
}; 

/* Query Device Capablities     #### michal - gdror fixed */

struct hermonprm_query_dev_cap_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00080];
/* -------------- */
    pseudo_bit_t	log_max_qp[0x00005];   /* Log2 of the Maximum number of QPs supported */
    pseudo_bit_t	reserved1[0x00003];
    pseudo_bit_t	log2_rsvd_qps[0x00004];/* Log (base 2) of the number of QPs reserved for firmware use
                                                 The reserved resources are numbered from 0 to 2^log2_rsvd_qps-1 */
    pseudo_bit_t	reserved2[0x00004];
    pseudo_bit_t	log_max_qp_sz[0x00008];/* The maximum number of WQEs allowed on the RQ or the SQ is 2^log_max_qp_sz-1 */
    pseudo_bit_t	log_max_srq_sz[0x00008];/* The maximum number of WQEs allowed on the SRQ is 2^log_max_srq_sz-1 */
/* -------------- */
    pseudo_bit_t	log_max_scqs[0x00004]; /* log base 2 of number of supported schedule queues */
    pseudo_bit_t	reserved3[0x00004];
    pseudo_bit_t	num_rsvd_scqs[0x00006];
    pseudo_bit_t	reserved4[0x00002];
    pseudo_bit_t	log_max_srqs[0x00005];
    pseudo_bit_t	reserved5[0x00007];
    pseudo_bit_t	log2_rsvd_srqs[0x00004];
/* -------------- */
    pseudo_bit_t	log_max_cq[0x00005];   /* Log2 of the Maximum number of CQs supported */
    pseudo_bit_t	reserved6[0x00003];
    pseudo_bit_t	log2_rsvd_cqs[0x00004];/* Log (base 2) of the number of CQs reserved for firmware use
                                                 The reserved resources are numbered from 0 to 2^log2_rsrvd_cqs-1 */
    pseudo_bit_t	reserved7[0x00004];
    pseudo_bit_t	log_max_cq_sz[0x00008];/* Log2 of the Maximum CQEs allowed in a CQ */
    pseudo_bit_t	num_rsvd_eqs[0x00008]; /* The number of EQs reserved for firmware use
                                                 The reserved resources are numbered from 0 to num_rsvd_eqs-1
                                                 If 0 - no resources are reserved. */
/* -------------- */
    pseudo_bit_t	log_max_eq[0x00004];   /* Log2 of the Maximum number of EQs */
    pseudo_bit_t	reserved9[0x00004];
    pseudo_bit_t	log2_rsvd_eqs[0x00004]; /* The number of EQs reserved for firmware use
                                                 The reserved resources are numbered from 0 to num_rsvd_eqs-1
                                                 If 0 - no resources are reserved. */
    pseudo_bit_t	reserved10[0x00004];
    pseudo_bit_t	log_max_d_mpts[0x00006];/* Log (base 2) of the maximum number of data MPT entries (the number of Regions/Windows) */
    pseudo_bit_t	reserved11[0x00002];
    pseudo_bit_t	log_max_eq_sz[0x00008];/* Log2 of the Maximum EQEs allowed in a EQ */
/* -------------- */
    pseudo_bit_t	log_max_mtts[0x00006]; /* Log2 of the Maximum number of MTT entries */
    pseudo_bit_t	reserved12[0x00002];
    pseudo_bit_t	log2_rsvd_mrws[0x00004];/* Log (base 2) of the number of MPTs reserved for firmware use
                                                 The reserved resources are numbered from 0 to 2^log2_rsvd_mrws-1 */
    pseudo_bit_t	reserved13[0x00004];
    pseudo_bit_t	log_max_mrw_sz[0x00007];/* Log2 of the Maximum Size of Memory Region/Window. is it in PRM layout? */
    pseudo_bit_t	reserved14[0x00005];
    pseudo_bit_t	log2_rsvd_mtts[0x00004];/* Log (base 2) of the number of MTT entries reserved for firmware use
                                                 The reserved resources are numbered from 0 to 2^log2_rsvd_mtts-1
                                                  */
/* -------------- */
    pseudo_bit_t	reserved15[0x00020];
/* -------------- */
    pseudo_bit_t	log_max_ra_res_qp[0x00006];/* Log2 of the Maximum number of outstanding RDMA read/Atomic per QP as a responder */
    pseudo_bit_t	reserved16[0x0000a];
    pseudo_bit_t	log_max_ra_req_qp[0x00006];/* Log2 of the maximum number of outstanding RDMA read/Atomic per QP as a requester */
    pseudo_bit_t	reserved17[0x0000a];
/* -------------- */
    pseudo_bit_t	log_max_ra_res_global[0x00006];/* Log2 of the maximum number of RDMA read/atomic operations the HCA responder can support globally. That implies the RDB table size. */
    pseudo_bit_t	reserved18[0x0001a];
/* -------------- */
    pseudo_bit_t	rsz_srq[0x00001];      /* Ability to modify the maximum number of WRs per SRQ. */
    pseudo_bit_t	reserved19[0x0001f];
/* -------------- */
    pseudo_bit_t	num_ports[0x00004];    /* Number of IB ports. */
    pseudo_bit_t	reserved47[0x00004];
    pseudo_bit_t	pci_pf_num[0x00008];    /* Number of supported physical functions */
    pseudo_bit_t	local_ca_ack_delay[0x00005];/* The Local CA ACK Delay. This is the value recommended to be returned in Query HCA verb.
                                                 The delay value in microseconds is computed using 4.096us * 2^(local_ca_ack_delay). */
    pseudo_bit_t	port_type[0x00004];    /* Hermon New. bit per port. bit0 is first port. value '1' is ehternet. '0' is IB */
    pseudo_bit_t	reserved20[0x00004];
    pseudo_bit_t	w[0x00001];            /* Hermon New. 10GB eth support */
    pseudo_bit_t	j[0x00001];            /* Hermon New. Jumbo frame support */
    pseudo_bit_t	reserved21[0x00001];
/* -------------- */
    pseudo_bit_t	log_max_gid[0x00004];  /* Log2 of the maximum number of GIDs per port */
    pseudo_bit_t	reserved22[0x00004];
    pseudo_bit_t	log_ethtype[0x00004];  /* Hermon New. log2 eth type table size */
    pseudo_bit_t	reserved23[0x00004];
    pseudo_bit_t	log_drain_size[0x00008];/* Log (base 2) of minimum size of the NoDropVLDrain buffer, specified in 4Kpages units */
    pseudo_bit_t	log_max_msg[0x00005];  /* Log (base 2) of the maximum message size supported by the device */
    pseudo_bit_t	reserved24[0x00003];
/* -------------- */
    pseudo_bit_t	log_max_pkey[0x00004]; /* Log2 of the max PKey Table Size (per IB port) */
    pseudo_bit_t	reserved25[0x0000c];
    pseudo_bit_t	stat_rate_support[0x00010];/* bit mask of stat rate supported
                                                 bit 0 - full bw
                                                 bit 1 - 1/4 bw
                                                 bit 2 - 1/8 bw
                                                 bit 3 - 1/2 bw; */
/* -------------- */
    pseudo_bit_t	reserved26[0x00008];
    pseudo_bit_t	rss_udp[0x00001];
    pseudo_bit_t	vep_uc_steering[0x00001];
    pseudo_bit_t	vep_mc_steering[0x00001];
    pseudo_bit_t	reserved27[0x00015];

/* -------------- */
    pseudo_bit_t	rc[0x00001];           /* RC Transport supported */
    pseudo_bit_t	uc[0x00001];           /* UC Transport Supported */
    pseudo_bit_t	ud[0x00001];           /* UD Transport Supported */
    pseudo_bit_t	src[0x00001];          /* SRC Transport Supported. Hermon New instead of RD. */
    pseudo_bit_t	rcm[0x00001];          /* Reliable Multicast support. Hermon New instead of IPv6 Transport Supported */
    pseudo_bit_t	fcoib[0x00001];        /* Hermon New */
    pseudo_bit_t	srq[0x00001];          /* SRQ is supported
                                                  */
    pseudo_bit_t	checksum[0x00001];     /* IP over IB checksum is supported */
    pseudo_bit_t	pkv[0x00001];          /* PKey Violation Counter Supported */
    pseudo_bit_t	qkv[0x00001];          /* QKey Violation Coutner Supported */
    pseudo_bit_t	vmm[0x00001];          /* Hermon New */
    pseudo_bit_t	fcoe[0x00001];
    pseudo_bit_t	dpdp[0x00001];	       /* Dual Port Different Protocols */
    pseudo_bit_t	raw_ethertype[0x00001];
    pseudo_bit_t	raw_ipv6[0x00001];
    pseudo_bit_t	blh[0x00001];
    pseudo_bit_t	mw[0x00001];           /* Memory windows supported */
    pseudo_bit_t	apm[0x00001];          /* Automatic Path Migration Supported */
    pseudo_bit_t	atm[0x00001];          /* Atomic operations supported (atomicity is guaranteed between QPs on this HCA) */
    pseudo_bit_t	rm[0x00001];           /* Raw Multicast Supported */
    pseudo_bit_t	avp[0x00001];          /* Address Vector Port checking supported */
    pseudo_bit_t	udm[0x00001];          /* UD Multicast Supported */
    pseudo_bit_t	reserved28[0x00002];
    pseudo_bit_t	pg[0x00001];           /* Paging on demand supported */
    pseudo_bit_t	r[0x00001];            /* Router mode supported */
    pseudo_bit_t	reserved29[0x00006];
/* -------------- */
    pseudo_bit_t	log_pg_sz[0x00008];    /* Minimum system page size supported (log2).
                                                 For proper operation it must be less than or equal the hosting platform (CPU) minimum page size. */
    pseudo_bit_t	reserved30[0x00008];
    pseudo_bit_t	uar_sz[0x00006];       /* UAR Area Size = 1MB * 2^uar_sz */
    pseudo_bit_t	reserved31[0x00006];
    pseudo_bit_t	num_rsvd_uars[0x00004];/* The number of UARs reserved for firmware use
                                                 The reserved resources are numbered from 0 to num_reserved_uars-1
                                                 Note that UAR number num_reserved_uars is always for the kernel. */
/* -------------- */
    pseudo_bit_t	log_max_bf_pages[0x00006];/* Maximum number of BlueFlame pages is 2^log_max_bf_pages */
    pseudo_bit_t	reserved32[0x00002];
    pseudo_bit_t	log_max_bf_regs_per_page[0x00006];/* Maximum number of BlueFlame registers per page is 2^log_max_bf_regs_per_page. It may be that only the beginning of a page contains BlueFlame registers. */
    pseudo_bit_t	reserved33[0x00002];
    pseudo_bit_t	log_bf_reg_size[0x00005];/* BlueFlame register size in bytes is 2^log_bf_reg_size */
    pseudo_bit_t	reserved34[0x0000a];
    pseudo_bit_t	bf[0x00001];           /* If set to "1" then BlueFlame may be used. */
/* -------------- */
    pseudo_bit_t	max_desc_sz_sq[0x00010];/* Max descriptor size in bytes for the send queue */
    pseudo_bit_t	max_sg_sq[0x00008];    /* The maximum S/G list elements in a SQ WQE (max_desc_sz/16 - 3) */
    pseudo_bit_t	reserved35[0x00008];
/* -------------- */
    pseudo_bit_t	max_desc_sz_rq[0x00010];/* Max descriptor size in bytes for the receive queue */
    pseudo_bit_t	max_sg_rq[0x00008];    /* The maximum S/G list elements in a RQ WQE (max_desc_sz/16 - 3) */
    pseudo_bit_t	reserved36[0x00008];
/* -------------- */
    pseudo_bit_t	reserved37[0x00001];
    pseudo_bit_t	fexch_base_mpt_31_25[0x00007];/* Hermon New. FC mpt base mpt number */
    pseudo_bit_t	fcp_ud_base_23_8[0x00010];/* Hermon New. FC ud QP  base QPN */
    pseudo_bit_t	fexch_base_qp_23_16[0x00008];/* Hermon New. FC Exchange QP base QPN */
/* -------------- */
    pseudo_bit_t	reserved38[0x00020];
/* -------------- */
    pseudo_bit_t	log_max_mcg[0x00008];  /* Log2 of the maximum number of multicast groups */
    pseudo_bit_t	num_rsvd_mcgs[0x00004];/* The number of MGMs reserved for firmware use in the MGHT.
                                                 The reserved resources are numbered from 0 to num_reserved_mcgs-1
                                                 If 0 - no resources are reserved. */
    pseudo_bit_t	reserved39[0x00004];
    pseudo_bit_t	log_max_qp_mcg[0x00008];/* Log2 of the maximum number of QPs per multicast group */
    pseudo_bit_t	reserved40[0x00008];
/* -------------- */
    pseudo_bit_t	log_max_srcds[0x00004];/* Log2 of the maximum number of SRC Domains */
    pseudo_bit_t	reserved41[0x00008];
    pseudo_bit_t	num_rsvd_scrds[0x00004];/* The number of SRCDs reserved for firmware use
                                                 The reserved resources are numbered from 0 to num_reserved_rdds-1.
                                                 If 0 - no resources are reserved. */
    pseudo_bit_t	log_max_pd[0x00005];   /* Log2 of the maximum number of PDs */
    pseudo_bit_t	reserved42[0x00007];
    pseudo_bit_t	num_rsvd_pds[0x00004]; /* The number of PDs reserved for firmware use
                                                 The reserved resources are numbered from 0 to num_reserved_pds-1
                                                 If 0 - no resources are reserved. */
/* -------------- */
    pseudo_bit_t	reserved43[0x000c0];
/* -------------- */
    pseudo_bit_t	qpc_entry_sz[0x00010]; /* QPC Entry Size for the device
                                                 For the InfiniHost-III-EX MT25208 entry size is 256 bytes */
    pseudo_bit_t	rdmardc_entry_sz[0x00010];/* RdmaRdC Entry Size for the device
                                                 For the InfiniHost-III-EX MT25208 entry size is 256 bytes */
/* -------------- */
    pseudo_bit_t	altc_entry_sz[0x00010];/* Extended QPC entry size for the device
                                                 For the InfiniHost-III-EX MT25208 entry size is 32 bytes */
    pseudo_bit_t	aux_entry_sz[0x00010]; /* Auxilary context entry size */
/* -------------- */
    pseudo_bit_t	cqc_entry_sz[0x00010]; /* CQC entry size for the device
                                                 For the InfiniHost-III-EX MT25208 entry size is 64 bytes */
    pseudo_bit_t	eqc_entry_sz[0x00010]; /* EQ context entry size for the device
                                                 For the InfiniHost-III-EX MT25208 entry size is 64 bytes */
/* -------------- */
    pseudo_bit_t	c_mpt_entry_sz[0x00010];/* cMPT entry size in Bytes for the device.
                                                 For the InfiniHost-III-EX MT25208 entry size is 64 bytes */
    pseudo_bit_t	srq_entry_sz[0x00010]; /* SRQ context entry size for the device
                                                 For the InfiniHost-III-EX MT25208 entry size is 32 bytes */
/* -------------- */
    pseudo_bit_t	d_mpt_entry_sz[0x00010];/* dMPT entry size in Bytes for the device.
                                                 For the InfiniHost-III-EX MT25208 entry size is 64 bytes */
    pseudo_bit_t	mtt_entry_sz[0x00010]; /* MTT entry size in Bytes for the device.
                                                 For the InfiniHost-III-EX MT25208 entry size is 8 bytes */
/* -------------- */
    pseudo_bit_t	bmme[0x00001];         /* Base Memory Management Extension Support */
    pseudo_bit_t	win_type[0x00001];     /* Bound Type 2 Memory Window Association mechanism:
                                                 0 - Type 2A - QP Number Association; or
                                                 1 - Type 2B - QP Number and PD Association. */
    pseudo_bit_t	mps[0x00001];          /* Ability of this HCA to support multiple page sizes per Memory Region. */
    pseudo_bit_t	bl[0x00001];           /* Ability of this HCA to support Block List Physical Buffer Lists. */
    pseudo_bit_t	zb[0x00001];           /* Zero Based region/windows supported */
    pseudo_bit_t	lif[0x00001];          /* Ability of this HCA to support Local Invalidate Fencing. */
    pseudo_bit_t	reserved44[0x0001a];
/* -------------- */
    pseudo_bit_t	resd_lkey[0x00020];    /* The value of the reserved Lkey for Base Memory Management Extension */
/* -------------- */
    pseudo_bit_t	reserved45[0x00020];
/* -------------- */
    pseudo_bit_t	max_icm_size_h[0x00020];/* Bits [63:32] of maximum ICM size InfiniHost III Ex support in bytes. */
/* -------------- */
    pseudo_bit_t	max_icm_size_l[0x00020];/* Bits [31:0] of maximum ICM size InfiniHost III Ex support in bytes. */
/* -------------- */
    pseudo_bit_t	reserved46[0x002c0];
/* -------------- */
}; 

/* QUERY_ADAPTER Parameters Block    #### michal - gdror fixed */

struct hermonprm_query_adapter_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00080];
/* -------------- */
    pseudo_bit_t	reserved1[0x00018];
    pseudo_bit_t	intapin[0x00008];      /* Driver should set this field to INTR value in the event queue in order to get Express interrupt messages. */
/* -------------- */
    pseudo_bit_t	reserved2[0x00060];
/* -------------- */
    struct hermonprm_vsd_st	vsd;         /* ###michal- this field was replaced by 2 fields : vsd .1664; vsd(continued/psid .128; */
/* -------------- */
}; 

/* QUERY_FW Parameters Block      #### michal - doesn't match PRM */

struct hermonprm_query_fw_st {	/* Little Endian */
    pseudo_bit_t	fw_rev_major[0x00010]; /* Firmware Revision - Major */
    pseudo_bit_t	fw_pages[0x00010];     /* Amount of physical memory to be allocated for FW usage is in 4KByte pages. */
/* -------------- */
    pseudo_bit_t	fw_rev_minor[0x00010]; /* Firmware Revision - Minor */
    pseudo_bit_t	fw_rev_subminor[0x00010];/* Firmware Sub-minor version (Patch level). */
/* -------------- */
    pseudo_bit_t	cmd_interface_rev[0x00010];/* Command Interface Interpreter Revision ID */
    pseudo_bit_t	reserved0[0x00010];
/* -------------- */
    pseudo_bit_t	log_max_outstanding_cmd[0x00008];/* Log2 of the maximum number of commands the HCR can support simultaneously */
    pseudo_bit_t	reserved1[0x00017];
    pseudo_bit_t	dt[0x00001];           /* Debug Trace Support
                                                 0 - Debug trace is not supported 
                                                 1 - Debug trace is supported */
/* -------------- */
    pseudo_bit_t	reserved2[0x00001];
    pseudo_bit_t	ccq[0x00001];          /* CCQ support */
    pseudo_bit_t	reserved3[0x00006];
    pseudo_bit_t	fw_seconds[0x00008];   /* FW timestamp - seconds. Dispalyed as Hexadecimal number */
    pseudo_bit_t	fw_minutes[0x00008];   /* FW timestamp - minutes. Dispalyed as Hexadecimal number */
    pseudo_bit_t	fw_hour[0x00008];      /* FW timestamp - hour.    Dispalyed as Hexadecimal number */
/* -------------- */
    pseudo_bit_t	fw_day[0x00008];       /* FW timestamp - day.     Dispalyed as Hexadecimal number */
    pseudo_bit_t	fw_month[0x00008];     /* FW timestamp - month.   Dispalyed as Hexadecimal number */
    pseudo_bit_t	fw_year[0x00010];      /* FW timestamp - year.    Dispalyed as Hexadecimal number (e.g. 0x2005) */
/* -------------- */
    pseudo_bit_t	reserved4[0x00040];
/* -------------- */
    pseudo_bit_t	clr_int_base_offset_h[0x00020];/* Bits [63:32] of the Clear Interrupt registers offset from clr_int_bar register in PCIaddress space. Points to a 64-bit register. */
/* -------------- */
    pseudo_bit_t	clr_int_base_offset_l[0x00020];/* Bits [31:0] of the Clear Interrupt registers offset from clr_int_bar register in PCIaddress space. Points to a 64-bit register. */
/* -------------- */
    pseudo_bit_t	reserved5[0x0001e];
    pseudo_bit_t	clr_int_bar[0x00002];  /* PCI base address register (BAR) where clr_int register is located.
                                                 00 - BAR 0-1
                                                 01 - BAR 2-3
                                                 10 - BAR 4-5
                                                 11 - Reserved
                                                 The PCI BARs of ConnectX are 64 bit BARs.
                                                 In ConnectX, clr_int register is located on BAR 0-1. */
/* -------------- */
    pseudo_bit_t	reserved6[0x00020];
/* -------------- */
    pseudo_bit_t	error_buf_offset_h[0x00020];/* Read Only buffer for catastrophic error reports (bits [63:32] of offset from error_buf_bar register in PCI address space.) */
/* -------------- */
    pseudo_bit_t	error_buf_offset_l[0x00020];/* Read Only buffer for catastrophic error reports (bits [31:0]  of offset from error_buf_bar register in PCI address space.) */
/* -------------- */
    pseudo_bit_t	error_buf_size[0x00020];/* Size in words */
/* -------------- */
    pseudo_bit_t	reserved7[0x0001e];
    pseudo_bit_t	error_buf_bar[0x00002];/* PCI base address register (BAR) where error_buf register is located.
                                                 00 - BAR 0-1
                                                 01 - BAR 2-3
                                                 10 - BAR 4-5
                                                 11 - Reserved
                                                 The PCI BARs of ConnectX are 64 bit BARs.
                                                 In ConnectX, error_buf register is located on BAR 0-1. */
/* -------------- */
    pseudo_bit_t	reserved8[0x00600];
/* -------------- */
}; 

/* Memory Access Parameters for UD Address Vector Table */

struct hermonprm_udavtable_memory_parameters_st {	/* Little Endian */
    pseudo_bit_t	l_key[0x00020];        /* L_Key used to access TPT */
/* -------------- */
    pseudo_bit_t	pd[0x00018];           /* PD used by TPT for matching against PD of region entry being accessed. */
    pseudo_bit_t	reserved0[0x00005];
    pseudo_bit_t	xlation_en[0x00001];   /* When cleared, address is physical address and no translation will be done. When set, address is virtual. */
    pseudo_bit_t	reserved1[0x00002];
/* -------------- */
}; 

/* INIT_HCA & QUERY_HCA Parameters Block ####michal-doesn't match PRM (see differs below) new size in bytes:0x300 */

struct hermonprm_init_hca_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00018];
    pseudo_bit_t	version[0x00008];
/* -------------- */
    pseudo_bit_t	reserved1[0x00040];
/* -------------- */
    pseudo_bit_t	reserved2[0x00010];
    pseudo_bit_t	hca_core_clock[0x00010];/* Internal Clock freq in MHz */
/* -------------- */
    pseudo_bit_t	router_qp[0x00018];    /* QP number for router mode (8 LSBits should be 0). Low order 8 bits are taken from the TClass field of the incoming packet.
                                                 Valid only if RE bit is set */
    pseudo_bit_t	reserved3[0x00005];
    pseudo_bit_t	ipr2[0x00001];         /* Hermon New. IP router on port 2 */
    pseudo_bit_t	ipr1[0x00001];         /* Hermon New. IP router on port 1 */
    pseudo_bit_t	ibr[0x00001];          /* InfiniBand Router Mode */
/* -------------- */
    pseudo_bit_t	udp[0x00001];          /* UD Port Check Enable
                                                 0 - Port field in Address Vector is ignored
                                                 1 - HCA will check the port field in AV entry (fetched for UD descriptor) against the Port of the UD QP executing the descriptor. */
    pseudo_bit_t	he[0x00001];           /* Host Endianess - Used for Atomic Operations
                                                 0 - Host is Little Endian
                                                 1 - Host is Big endian
                                                  */
    pseudo_bit_t	reserved4[0x00001];
    pseudo_bit_t	ce[0x00001];           /* Checksum Enabled - when Set IPoverIB checksum generation & checking is enabled */
    pseudo_bit_t	reserved5[0x0001c];
/* -------------- */
    pseudo_bit_t	reserved6[0x00040];
/* -------------- */
    struct hermonprm_qpcbaseaddr_st	qpc_eec_cqc_eqc_rdb_parameters;/* ## michal - this field has chenged to - "qpc_cqc_eqc_parameters" - gdror, this is ok for now */
/* -------------- */
    pseudo_bit_t	reserved7[0x00100];
/* -------------- */
    struct hermonprm_multicastparam_st	multicast_parameters;/* ##michal- this field has chenged to - "IBUD/IPv6_multicast_parameters" - gdror - this is OK for now */
/* -------------- */
    pseudo_bit_t	reserved8[0x00080];
/* -------------- */
    struct hermonprm_tptparams_st	tpt_parameters;
/* -------------- */
    pseudo_bit_t	reserved9[0x00080];
/* -------------- */
    struct hermonprm_uar_params_st	uar_parameters;/* UAR Parameters */
/* -------------- */
    pseudo_bit_t	reserved10[0x00600];
/* -------------- */
}; 

/* Event Queue Context Table Entry     #### michal - gdror fixed */

struct hermonprm_eqc_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00008];
    pseudo_bit_t	st[0x00004];           /* Event delivery state machine
                                                 0x9 - Armed
                                                 0xA - Fired
                                                 0xB - Always_Armed (auto-rearm)
                                                 other - reserved */
    pseudo_bit_t	reserved1[0x00005];
    pseudo_bit_t	oi[0x00001];           /* Oerrun ignore.
                                                 If set, HW will not check EQ full condition when writing new EQEs. */
    pseudo_bit_t	ec[0x00001];           /* is set, all EQEs are written (coalesced) to first EQ entry */
    pseudo_bit_t	reserved2[0x00009];
    pseudo_bit_t	status[0x00004];       /* EQ status:
                                                 0000 - OK
                                                 1010 - EQ write failure
                                                 Valid for the QUERY_EQ and HW2SW_EQ commands only */
/* -------------- */
    pseudo_bit_t	reserved3[0x00020];
/* -------------- */
    pseudo_bit_t	reserved4[0x00005];
    pseudo_bit_t	page_offset[0x00007];  /* offset bits[11:5] of first EQE in the EQ relative to the first page in memory region mapping this EQ */
    pseudo_bit_t	reserved5[0x00014];
/* -------------- */
    pseudo_bit_t	reserved6[0x00018];
    pseudo_bit_t	log_eq_size[0x00005];  /* Log (base 2) of the EQ size (in entries).  Maximum EQ size is 2^22 EQEs (max log_eq_size is 22) */
    pseudo_bit_t	reserved7[0x00003];
/* -------------- */
    pseudo_bit_t	eq_max_count[0x00010]; /* Event Generation Moderation counter */
    pseudo_bit_t	eq_period[0x00010];    /* Event Generation moderation timed, microseconds */
/* -------------- */
    pseudo_bit_t	intr[0x0000a];         /* MSI-X table entry index to be used to signal interrupts on this EQ.  Reserved if MSI-X are not enabled in the PCI configuration header. */
    pseudo_bit_t	reserved8[0x00016];
/* -------------- */
    pseudo_bit_t	mtt_base_addr_h[0x00008];/* MTT Base Address [39:32] relative to INIT_HCA.mtt_base_addr */
    pseudo_bit_t	reserved9[0x00010];
    pseudo_bit_t	log2_page_size[0x00006];/* Log (base 2) of MTT page size in units of 4KByte */
    pseudo_bit_t	reserved10[0x00002];
/* -------------- */
    pseudo_bit_t	reserved11[0x00003];
    pseudo_bit_t	mtt_base_addr_l[0x0001d];/* MTT Base Address [31:3] relative to INIT_HCA.mtt_base_addr */
/* -------------- */
    pseudo_bit_t	reserved12[0x00040];
/* -------------- */
    pseudo_bit_t	consumer_counter[0x00018];/* Consumer counter. The counter is incremented for each EQE polled from the EQ. 
                                                  Must be 0x0 in EQ initialization. 
                                                  Maintained by HW (valid for the QUERY_EQ command only). */
    pseudo_bit_t	reserved13[0x00008];
/* -------------- */
    pseudo_bit_t	producer_counter[0x00018];/* Producer Coutner. The counter is incremented for each EQE that is written by the HW to the EQ. 
                                                  EQ overrun is reported if Producer_counter + 1 equals to Consumer_counter and a EQE needs to be added.
                                                  Maintained by HW (valid for the QUERY_EQ command only) */
    pseudo_bit_t	reserved14[0x00008];
/* -------------- */
    pseudo_bit_t	reserved15[0x00080];
/* -------------- */
}; 

/* Memory Translation Table (MTT) Entry     #### michal - match to PRM */

struct hermonprm_mtt_st {	/* Little Endian */
    pseudo_bit_t	ptag_h[0x00020];       /* High-order bits of physical tag. The size of the field depends on the page size of the region. Maximum PTAG size is 52 bits. */
/* -------------- */
    pseudo_bit_t	p[0x00001];            /* Present bit. If set, page entry is valid. If cleared, access to this page will generate non-present page access fault. */
    pseudo_bit_t	reserved0[0x00002];
    pseudo_bit_t	ptag_l[0x0001d];       /* Low-order bits of Physical tag. The size of the field depends on the page size of the region. Maximum PTAG size is 52 bits. */
/* -------------- */
}; 

/* Memory Protection Table (MPT) Entry   ### doesn't match PRM (new fields were added). new size in bytes : 0x54 */

struct hermonprm_mpt_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00008];
    pseudo_bit_t	r_w[0x00001];          /* Defines whether this entry is Region (1) or Window (0) */
    pseudo_bit_t	pa[0x00001];           /* Physical address. If set, no virtual-to-physical address translation is performed for this region */
    pseudo_bit_t	lr[0x00001];           /* If set - local read access is enabled. Must be set for all MPT Entries. */
    pseudo_bit_t	lw[0x00001];           /* If set - local write access is enabled */
    pseudo_bit_t	rr[0x00001];           /* If set - remote read access is enabled. */
    pseudo_bit_t	rw[0x00001];           /* If set - remote write access is enabled */
    pseudo_bit_t	atomic[0x00001];       /* If set - remote Atomic access is allowed. */
    pseudo_bit_t	eb[0x00001];           /* If set - bind is enabled. Valid only for regions. */
    pseudo_bit_t	atc_req[0x00001];      /* If set, second hop of address translation (PA to MA) to be performed in the device prior to issuing the uplink request. */
    pseudo_bit_t	atc_xlated[0x00001];   /* If set, uplink cycle to be issues with ATC_translated indicator to force bypass of the chipset IOMMU. */
    pseudo_bit_t	reserved1[0x00001];
    pseudo_bit_t	no_snoop[0x00001];     /* If set, issue PCIe cycle with ûno Snoopÿ attribute - cycle not to be snooped in CPU caches */
    pseudo_bit_t	reserved2[0x00008];
    pseudo_bit_t	status[0x00004];       /* 0xF - Not Valid 0x3 - Free. else - HW ownership.Unbound Type1 windows are denoted by reg_wnd_len=0. Unbound Type II windows are denoted by Status = Free. */
/* -------------- */
    pseudo_bit_t	reserved3[0x00007];
    pseudo_bit_t	bqp[0x00001];          /* 0 - not bound to qp (type 1 window, MR)1 - bound to qp (type 2 window) */
    pseudo_bit_t	qpn[0x00018];          /* QP number this MW is attached to. Valid for type2 memory windows and on QUERY_MPT only */
/* -------------- */
    pseudo_bit_t	mem_key[0x00020];      /* The memory Key. The field holds the mem_key field in the following semantics: {key[7:0],key[31:8]}. */
/* -------------- */
    pseudo_bit_t	pd[0x00018];           /* Protection Domain. If VMM support is enabled PD[17:23] specify Guest VM Identifier */
    pseudo_bit_t	en_rinv[0x00001];      /* Enable remote invalidation */
    pseudo_bit_t	ei[0x00001];           /* Enable Invalidation - When set, Local/Remote invalidation can be executed on this window/region. Must be set for type2 windows and non-shared physical memory regions. Must be clear for regions that are used to access Work Queues, Completion Queues and Event Queues */
    pseudo_bit_t	nce[0x00001];          /* Data can be cached in Network Cache (see ûNetwork Cacheÿ on page 81) */
    pseudo_bit_t	fre[0x00001];          /* When set, Fast Registration Operations can be executed on this region */
    pseudo_bit_t	rae[0x00001];          /* When set, remote access can be enabled on this region. Used when executing Fast Registration Work Request to validate that remote access rights can be granted to this MPT. If the bit is cleared, Fast Registration Work Request requesting remote access rights will fail */
    pseudo_bit_t	w_dif[0x00001];        /* Wire space contains dif */
    pseudo_bit_t	m_dif[0x00001];        /* Memory space contains dif */
    pseudo_bit_t	reserved4[0x00001];
/* -------------- */
    pseudo_bit_t	start_addr_h[0x00020]; /* Start Address - Virtual Address where this region/window starts */
/* -------------- */
    pseudo_bit_t	start_addr_l[0x00020]; /* Start Address - Virtual Address where this region/window starts */
/* -------------- */
    pseudo_bit_t	len_h[0x00020];        /* Region/Window Length */
/* -------------- */
    pseudo_bit_t	len_l[0x00020];        /* Region/Window Length */
/* -------------- */
    pseudo_bit_t	lkey[0x00020];         /* Must be 0 for SW2HW_MPT. On QUERY_MPT and HW2SW_MPT commands for Memory Window it reflects the LKey of the Region that the Window is bound to.The field holds the lkey field in the following semantics: {key[7:0],key[31:8]}. */
/* -------------- */
    pseudo_bit_t	win_cnt[0x00018];      /* Number of windows bound to this region. Valid for regions only.The field is valid only for the QUERY_MPT and HW2SW_MPT commands. */
    pseudo_bit_t	reserved5[0x00008];
/* -------------- */
    pseudo_bit_t	mtt_rep[0x00004];      /* Log (base 2) of the number of time an MTT is replicated.E.g. for 64KB virtual blocks from 512B blocks, a replication factor of 2^7 is needed (MTT_REPLICATION_FACTOR=7).Up to 1MB of replicated block works */
    pseudo_bit_t	reserved6[0x00011];
    pseudo_bit_t	block_mode[0x00001];   /* If set, the page size is not power of two, and entity_size is in bytes. */
    pseudo_bit_t	len64[0x00001];        /* Region/Window Length[64]. This bit added to enable registering 2^64 bytes per region */
    pseudo_bit_t	fbo_en[0x00001];       /* If set, mtt_fbo field is valid, otherwise it is calculated from least significant bytes of the address. Must be set when mtt_rep is used or MPT is block-mode region */
    pseudo_bit_t	reserved7[0x00008];
/* -------------- */
    pseudo_bit_t	mtt_adr_h[0x00008];    /* Offset to MTT list for this region. Must be aligned on 8 bytes. */
    pseudo_bit_t	reserved8[0x00018];
/* -------------- */
    pseudo_bit_t	mtt_adr_l[0x00020];    /* Offset to MTT list for this region. Must be aligned on 8 bytes.###michal-relpaced with: RESERVED .3;mtt_adr_l .29; gdror - this is OK to leave it this way. */
/* -------------- */
    pseudo_bit_t	mtt_size[0x00020];     /* Number of MTT entries allocated for this MR.When Fast Registration Operations cannot be executed on this region (FRE bit is zero) this field is reserved.When Fast Registration Operation is enabled (FRE bit is set) this field indicates the number of MTTs allocated for this MR. If mtt_sz value cannot be zero. */
/* -------------- */
    pseudo_bit_t	entity_size[0x00015];  /* Page/block size. If MPT maps pages, the page size is 2entiry_size. If MPT maps blocks, the entity_size field specifies block size in bytes. The minimum amount of memory that can be mapped with single MTT is 512 bytes. */
    pseudo_bit_t	reserved9[0x0000b];
/* -------------- */
    pseudo_bit_t	mtt_fbo[0x00015];      /* First byte offset in the zero-based region - the first byte within the first block/page start address refers to. When mtt_rep is being used, fbo points within the replicated block (i.e. block-size x 2^mtt_rep) */
    pseudo_bit_t	reserved10[0x0000b];
/* -------------- */
}; 

/* Completion Queue Context Table Entry	#### michal - match PRM */

struct hermonprm_completion_queue_context_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00008];
    pseudo_bit_t	st[0x00004];           /* Event delivery state machine
                                                 0x0 - reserved
                                                 0x9 - ARMED (Request for Notification)
                                                 0x6 - ARMED SOLICITED (Request Solicited Notification)
                                                 0xA - FIRED
                                                 other - reserved
                                                 
                                                 Must be 0x0 in CQ initialization.
                                                 Valid for the QUERY_CQ and HW2SW_CQ commands only. */
    pseudo_bit_t	reserved1[0x00005];
    pseudo_bit_t	oi[0x00001];           /* When set, overrun ignore is enabled.
                                                 When set, Updates of CQ consumer counter (poll for completion) or Request completion notifications (Arm CQ) doorbells should not be rang on that CQ. */
    pseudo_bit_t	cc[0x00001];           /* is set, all CQEs are written (coalesced) to first CQ entry */
    pseudo_bit_t	reserved2[0x00009];
    pseudo_bit_t	status[0x00004];       /* CQ status
                                                 0000 - OK
                                                 1001 - CQ overflow
                                                 1010 - CQ write failure
                                                 Valid for the QUERY_CQ and HW2SW_CQ commands only */
/* -------------- */
    pseudo_bit_t	reserved3[0x00020];
/* -------------- */
    pseudo_bit_t	reserved4[0x00005];
    pseudo_bit_t	page_offset[0x00007];  /* offset of first CQE in the CQ relative to the first page in memory region mapping this CQ */
    pseudo_bit_t	reserved5[0x00014];
/* -------------- */
    pseudo_bit_t	usr_page[0x00018];     /* UAR page this CQ can be accessed through (ringinig CQ doorbells) */
    pseudo_bit_t	log_cq_size[0x00005];  /* Log (base 2) of the CQ size (in entries).
                                                 Maximum CQ size is 2^17 CQEs (max log_cq_size is 17) */
    pseudo_bit_t	reserved6[0x00003];
/* -------------- */
    pseudo_bit_t	cq_max_count[0x00010]; /* Event Generation Moderation counter */
    pseudo_bit_t	cq_period[0x00010];    /* Event Generation moderation timed, microseconds */
/* -------------- */
    pseudo_bit_t	c_eqn[0x00009];        /* Event Queue this CQ reports completion events to.
                                                 Valid values are 0 to 63
                                                 If configured to value other than 0-63, completion events will not be reported on the CQ. */
    pseudo_bit_t	reserved7[0x00017];
/* -------------- */
    pseudo_bit_t	mtt_base_addr_h[0x00008];/* MTT Base Address [39:32] in ICM relative to INIT_HCA.mtt_base_addr */
    pseudo_bit_t	reserved8[0x00010];
    pseudo_bit_t	log2_page_size[0x00006];
    pseudo_bit_t	reserved9[0x00002];
/* -------------- */
    pseudo_bit_t	reserved10[0x00003];
    pseudo_bit_t	mtt_base_addr_l[0x0001d];/* MTT Base Address [31:3] in ICM relative to INIT_HCA.mtt_base_addr */
/* -------------- */
    pseudo_bit_t	last_notified_indx[0x00018];/* Maintained by HW.
                                                 Valid for QUERY_CQ and HW2SW_CQ commands only. */
    pseudo_bit_t	reserved11[0x00008];
/* -------------- */
    pseudo_bit_t	solicit_producer_indx[0x00018];/* Maintained by HW.
                                                 Valid for QUERY_CQ and HW2SW_CQ commands only. 
                                                  */
    pseudo_bit_t	reserved12[0x00008];
/* -------------- */
    pseudo_bit_t	consumer_counter[0x00018];/* Consumer counter is a 32bits counter that is incremented for each CQE pooled from the CQ.
                                                  */
    pseudo_bit_t	reserved13[0x00008];
/* -------------- */
    pseudo_bit_t	producer_counter[0x00018];/* Producer counter is a 32bits counter that is incremented for each CQE that is written by the HW to the CQ.
                                                 CQ overrun is reported if Producer_counter + 1 equals to Consumer_counter and a CQE needs to be added..
                                                 Maintained by HW (valid for the QUERY_CQ and HW2SW_CQ commands only) */
    pseudo_bit_t	reserved14[0x00008];
/* -------------- */
    pseudo_bit_t	reserved15[0x00020];
/* -------------- */
    pseudo_bit_t	reserved16[0x00020];
/* -------------- */
    pseudo_bit_t	db_record_addr_h[0x00020];/* CQ DB Record physical address [63:32] */
/* -------------- */
    pseudo_bit_t	reserved17[0x00003];
    pseudo_bit_t	db_record_addr_l[0x0001d];/* CQ DB Record physical address [31:3] */
/* -------------- */
}; 

/* GPIO_event_data   #### michal - gdror fixed */

struct hermonprm_gpio_event_data_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00060];
/* -------------- */
    pseudo_bit_t	gpio_event_hi[0x00020];/* If any bit is set to 1, then a rising/falling event has occurred on the corrsponding GPIO pin. */
/* -------------- */
    pseudo_bit_t	gpio_event_lo[0x00020];/* If any bit is set to 1, then a rising/falling event has occurred on the corrsponding GPIO pin. */
/* -------------- */
    pseudo_bit_t	reserved1[0x00020];
/* -------------- */
}; 

/* Event_data Field - QP/EE Events     #### michal - doesn't match PRM */

struct hermonprm_qp_ee_event_st {	/* Little Endian */
    pseudo_bit_t	qpn_een[0x00018];      /* QP/EE/SRQ number event is reported for  ###michal - field changed to QP number */
    pseudo_bit_t	reserved0[0x00008];
/* -------------- */
    pseudo_bit_t	reserved1[0x00020];
/* -------------- */
    pseudo_bit_t	reserved2[0x0001c];
    pseudo_bit_t	e_q[0x00001];          /* If set - EEN if cleared - QP in the QPN/EEN field
                                                 Not valid on SRQ events  ###michal - field replaced with RESERVED */
    pseudo_bit_t	reserved3[0x00003];
/* -------------- */
    pseudo_bit_t	reserved4[0x00060];
/* -------------- */
}; 

/* InfiniHost-III-EX Type0 Configuration Header   ####michal - doesn't match PRM (new fields added, see below) */

struct hermonprm_mt25208_type0_st {	/* Little Endian */
    pseudo_bit_t	vendor_id[0x00010];    /* Hardwired to 0x15B3 */
    pseudo_bit_t	device_id[0x00010];    /* 25208 (decimal) - InfiniHost-III compatible mode
                                                 25408 (decimal) - InfiniHost-III EX mode (the mode described in this manual)
                                                 25209 (decimal) - Flash burner mode - see Flash burning application note for further details on this mode
                                                  */
/* -------------- */
    pseudo_bit_t	command[0x00010];      /* PCI Command Register */
    pseudo_bit_t	status[0x00010];       /* PCI Status Register */
/* -------------- */
    pseudo_bit_t	revision_id[0x00008];
    pseudo_bit_t	class_code_hca_class_code[0x00018];
/* -------------- */
    pseudo_bit_t	cache_line_size[0x00008];/* Cache Line Size */
    pseudo_bit_t	latency_timer[0x00008];
    pseudo_bit_t	header_type[0x00008];  /* hardwired to zero */
    pseudo_bit_t	bist[0x00008];
/* -------------- */
    pseudo_bit_t	bar0_ctrl[0x00004];    /* hard-wired to 0100 */
    pseudo_bit_t	reserved0[0x00010];
    pseudo_bit_t	bar0_l[0x0000c];       /* Lower bits of BAR0 (Device Configuration Space) */
/* -------------- */
    pseudo_bit_t	bar0_h[0x00020];       /* Upper 32 bits of BAR0 (Device Configuration Space) */
/* -------------- */
    pseudo_bit_t	bar1_ctrl[0x00004];    /* Hardwired to 1100 */
    pseudo_bit_t	reserved1[0x00010];
    pseudo_bit_t	bar1_l[0x0000c];       /* Lower bits of BAR1 (User Access Region - UAR - space) */
/* -------------- */
    pseudo_bit_t	bar1_h[0x00020];       /* upper 32 bits of BAR1 (User Access Region - UAR - space) */
/* -------------- */
    pseudo_bit_t	bar2_ctrl[0x00004];    /* Hardwired to 1100 */
    pseudo_bit_t	reserved2[0x00010];
    pseudo_bit_t	bar2_l[0x0000c];       /* Lower bits of BAR2 - Local Attached Memory if present and enabled. Else zeroed. */
/* -------------- */
    pseudo_bit_t	bar2_h[0x00020];       /* Upper 32 bits of BAR2 - Local Attached Memory if present and enabled. Else zeroed. */
/* -------------- */
    pseudo_bit_t	cardbus_cis_pointer[0x00020];
/* -------------- */
    pseudo_bit_t	subsystem_vendor_id[0x00010];/* Specified by the device NVMEM configuration */
    pseudo_bit_t	subsystem_id[0x00010]; /* Specified by the device NVMEM configuration */
/* -------------- */
    pseudo_bit_t	expansion_rom_enable[0x00001];/* Expansion ROM Enable. Hardwired to 0 if expansion ROM is disabled in the device NVMEM configuration. */
    pseudo_bit_t	reserved3[0x0000a];
    pseudo_bit_t	expansion_rom_base_address[0x00015];/* Expansion ROM Base Address (upper 21 bit). Hardwired to 0 if expansion ROM is disabled in the device NVMEM configuration. */
/* -------------- */
    pseudo_bit_t	capabilities_pointer[0x00008];/* Specified by the device NVMEM configuration */
    pseudo_bit_t	reserved4[0x00018];
/* -------------- */
    pseudo_bit_t	reserved5[0x00020];
/* -------------- */
    pseudo_bit_t	interrupt_line[0x00008];
    pseudo_bit_t	interrupt_pin[0x00008];
    pseudo_bit_t	min_gnt[0x00008];
    pseudo_bit_t	max_latency[0x00008];
/* -------------- */
    pseudo_bit_t	reserved6[0x00100];
/* -------------- */
    pseudo_bit_t	msi_cap_id[0x00008];
    pseudo_bit_t	msi_next_cap_ptr[0x00008];
    pseudo_bit_t	msi_en[0x00001];
    pseudo_bit_t	multiple_msg_cap[0x00003];
    pseudo_bit_t	multiple_msg_en[0x00003];
    pseudo_bit_t	cap_64_bit_addr[0x00001];
    pseudo_bit_t	reserved7[0x00008];
/* -------------- */
    pseudo_bit_t	msg_addr_l[0x00020];
/* -------------- */
    pseudo_bit_t	msg_addr_h[0x00020];
/* -------------- */
    pseudo_bit_t	msg_data[0x00010];
    pseudo_bit_t	reserved8[0x00010];
/* -------------- */
    pseudo_bit_t	reserved9[0x00080];
/* -------------- */
    pseudo_bit_t	pm_cap_id[0x00008];    /* Power management capability ID - 01h */
    pseudo_bit_t	pm_next_cap_ptr[0x00008];
    pseudo_bit_t	pm_cap[0x00010];       /* [2:0] Version - 02h
                                                 [3] PME clock - 0h
                                                 [4] RsvP
                                                 [5] Device specific initialization - 0h
                                                 [8:6] AUX current - 0h
                                                 [9] D1 support - 0h
                                                 [10] D2 support - 0h
                                                 [15:11] PME support - 0h */
/* -------------- */
    pseudo_bit_t	pm_status_control[0x00010];/* [14:13] - Data scale - 0h */
    pseudo_bit_t	pm_control_status_brdg_ext[0x00008];
    pseudo_bit_t	data[0x00008];
/* -------------- */
    pseudo_bit_t	reserved10[0x00040];
/* -------------- */
    pseudo_bit_t	vpd_cap_id[0x00008];   /* 03h */
    pseudo_bit_t	vpd_next_cap_id[0x00008];
    pseudo_bit_t	vpd_address[0x0000f];
    pseudo_bit_t	f[0x00001];
/* -------------- */
    pseudo_bit_t	vpd_data[0x00020];
/* -------------- */
    pseudo_bit_t	reserved11[0x00040];
/* -------------- */
    pseudo_bit_t	pciex_cap_id[0x00008]; /* PCI-Express capability ID - 10h */
    pseudo_bit_t	pciex_next_cap_ptr[0x00008];
    pseudo_bit_t	pciex_cap[0x00010];    /* [3:0] Capability version - 1h
                                                 [7:4] Device/Port Type - 0h
                                                 [8] Slot implemented - 0h
                                                 [13:9] Interrupt message number
                                                  */
/* -------------- */
    pseudo_bit_t	device_cap[0x00020];   /* [2:0] Max_Payload_Size supported - 2h
                                                 [4:3] Phantom Function supported - 0h
                                                 [5] Extended Tag Filed supported - 0h
                                                 [8:6] Endpoint L0s Acceptable Latency - TBD
                                                 [11:9] Endpoint L1 Acceptable Latency - TBD
                                                 [12] Attention Button Present - configured through InfiniBurn
                                                 [13] Attention Indicator Present - configured through InfiniBurn
                                                 [14] Power Indicator Present - configured through InfiniBurn
                                                 [25:18] Captured Slot Power Limit Value
                                                 [27:26] Captured Slot Power Limit Scale */
/* -------------- */
    pseudo_bit_t	device_control[0x00010];
    pseudo_bit_t	device_status[0x00010];
/* -------------- */
    pseudo_bit_t	link_cap[0x00020];     /* [3:0] Maximum Link Speed - 1h
                                                 [9:4] Maximum Link Width - 8h
                                                 [11:10] Active State Power Management Support - 3h
                                                 [14:12] L0s Exit Latency - TBD
                                                 [17:15] L1 Exit Latency - TBD
                                                 [31:24] Port Number - 0h */
/* -------------- */
    pseudo_bit_t	link_control[0x00010];
    pseudo_bit_t	link_status[0x00010];  /* [3:0] Link Speed - 1h
                                                 [9:4] Negotiated Link Width
                                                 [12] Slot clock configuration - 1h */
/* -------------- */
    pseudo_bit_t	reserved12[0x00260];
/* -------------- */
    pseudo_bit_t	advanced_error_reporting_cap_id[0x00010];/* 0001h. */
    pseudo_bit_t	capability_version[0x00004];/* 1h */
    pseudo_bit_t	next_capability_offset[0x0000c];/* 0h */
/* -------------- */
    pseudo_bit_t	uncorrectable_error_status_register[0x00020];/* 0 Training Error Status
                                                 4 Data Link Protocol Error Status
                                                 12 Poisoned TLP Status 
                                                 13 Flow Control Protocol Error Status 
                                                 14 Completion Timeout Status 
                                                 15 Completer Abort Status 
                                                 16 Unexpected Completion Status 
                                                 17 Receiver Overflow Status 
                                                 18 Malformed TLP Status 
                                                 19 ECRC Error Status 
                                                 20 Unsupported Request Error Status */
/* -------------- */
    pseudo_bit_t	uncorrectable_error_mask_register[0x00020];/* 0 Training Error Mask
                                                 4 Data Link Protocol Error Mask
                                                 12 Poisoned TLP Mask 
                                                 13 Flow Control Protocol Error Mask
                                                 14 Completion Timeout Mask
                                                 15 Completer Abort Mask
                                                 16 Unexpected Completion Mask
                                                 17 Receiver Overflow Mask
                                                 18 Malformed TLP Mask
                                                 19 ECRC Error Mask
                                                 20 Unsupported Request Error Mask */
/* -------------- */
    pseudo_bit_t	uncorrectable_severity_mask_register[0x00020];/* 0 Training Error Severity
                                                 4 Data Link Protocol Error Severity
                                                 12 Poisoned TLP Severity
                                                 13 Flow Control Protocol Error Severity
                                                 14 Completion Timeout Severity
                                                 15 Completer Abort Severity
                                                 16 Unexpected Completion Severity
                                                 17 Receiver Overflow Severity
                                                 18 Malformed TLP Severity
                                                 19 ECRC Error Severity
                                                 20 Unsupported Request Error Severity */
/* -------------- */
    pseudo_bit_t	correctable_error_status_register[0x00020];/* 0 Receiver Error Status
                                                 6 Bad TLP Status
                                                 7 Bad DLLP Status
                                                 8 REPLAY_NUM Rollover Status
                                                 12 Replay Timer Timeout Status */
/* -------------- */
    pseudo_bit_t	correctable_error_mask_register[0x00020];/* 0 Receiver Error Mask
                                                 6 Bad TLP Mask
                                                 7 Bad DLLP Mask
                                                 8 REPLAY_NUM Rollover Mask
                                                 12 Replay Timer Timeout Mask */
/* -------------- */
    pseudo_bit_t	advance_error_capabilities_and_control_register[0x00020];
/* -------------- */
    struct hermonprm_header_log_register_st	header_log_register;
/* -------------- */
    pseudo_bit_t	reserved13[0x006a0];
/* -------------- */
}; 

/* Event Data Field - Performance Monitor */

struct hermonprm_performance_monitor_event_st {	/* Little Endian */
    struct hermonprm_performance_monitors_st	performance_monitor_snapshot;/* Performance monitor snapshot */
/* -------------- */
    pseudo_bit_t	monitor_number[0x00008];/* 0x01 - SQPC
                                                 0x02 - RQPC
                                                 0x03 - CQC
                                                 0x04 - Rkey
                                                 0x05 - TLB
                                                 0x06 - port0
                                                 0x07 - port1 */
    pseudo_bit_t	reserved0[0x00018];
/* -------------- */
    pseudo_bit_t	reserved1[0x00040];
/* -------------- */
}; 

/* Event_data Field - Page Faults */

struct hermonprm_page_fault_event_data_st {	/* Little Endian */
    pseudo_bit_t	va_h[0x00020];         /* Virtual Address[63:32] this page fault is reported on */
/* -------------- */
    pseudo_bit_t	va_l[0x00020];         /* Virtual Address[63:32] this page fault is reported on */
/* -------------- */
    pseudo_bit_t	mem_key[0x00020];      /* Memory Key this page fault is reported on */
/* -------------- */
    pseudo_bit_t	qp[0x00018];           /* QP this page fault is reported on */
    pseudo_bit_t	reserved0[0x00003];
    pseudo_bit_t	a[0x00001];            /* If set the memory access that caused the page fault was atomic */
    pseudo_bit_t	lw[0x00001];           /* If set the memory access that caused the page fault was local write */
    pseudo_bit_t	lr[0x00001];           /* If set the memory access that caused the page fault was local read */
    pseudo_bit_t	rw[0x00001];           /* If set the memory access that caused the page fault was remote write */
    pseudo_bit_t	rr[0x00001];           /* If set the memory access that caused the page fault was remote read */
/* -------------- */
    pseudo_bit_t	pd[0x00018];           /* PD this page fault is reported on */
    pseudo_bit_t	reserved1[0x00008];
/* -------------- */
    pseudo_bit_t	prefetch_len[0x00020]; /* Indicates how many subsequent pages in the same memory region/window will be accessed by the following transaction after this page fault is resolved. measured in bytes. SW can use this information in order to page-in the subsequent pages if they are not present. */
/* -------------- */
}; 

/* WQE segments format */

struct hermonprm_wqe_segment_st {	/* Little Endian */
    struct hermonprm_send_wqe_segment_st	send_wqe_segment;/* Send WQE segment format */
/* -------------- */
    pseudo_bit_t	reserved0[0x00280];
/* -------------- */
    struct hermonprm_wqe_segment_ctrl_mlx_st	mlx_wqe_segment_ctrl;/* MLX WQE segment format */
/* -------------- */
    pseudo_bit_t	reserved1[0x00100];
/* -------------- */
    pseudo_bit_t	recv_wqe_segment_ctrl[4][0x00020];/* Receive segment format */
/* -------------- */
    pseudo_bit_t	reserved2[0x00080];
/* -------------- */
}; 

/* Event_data Field - Port State Change   #### michal - match PRM */

struct hermonprm_port_state_change_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00040];
/* -------------- */
    pseudo_bit_t	reserved1[0x0001c];
    pseudo_bit_t	p[0x00002];            /* Port number (1 or 2) */
    pseudo_bit_t	reserved2[0x00002];
/* -------------- */
    pseudo_bit_t	reserved3[0x00060];
/* -------------- */
}; 

/* Event_data Field - Completion Queue Error     #### michal - match PRM */

struct hermonprm_completion_queue_error_st {	/* Little Endian */
    pseudo_bit_t	cqn[0x00018];          /* CQ number event is reported for */
    pseudo_bit_t	reserved0[0x00008];
/* -------------- */
    pseudo_bit_t	reserved1[0x00020];
/* -------------- */
    pseudo_bit_t	syndrome[0x00008];     /* Error syndrome
                                                 0x01 - CQ overrun
                                                 0x02 - CQ access violation error */
    pseudo_bit_t	reserved2[0x00018];
/* -------------- */
    pseudo_bit_t	reserved3[0x00060];
/* -------------- */
}; 

/* Event_data Field - Completion Event	#### michal - match PRM */

struct hermonprm_completion_event_st {	/* Little Endian */
    pseudo_bit_t	cqn[0x00018];          /* CQ number event is reported for */
    pseudo_bit_t	reserved0[0x00008];
/* -------------- */
    pseudo_bit_t	reserved1[0x000a0];
/* -------------- */
}; 

/* Event Queue Entry         #### michal - match to PRM */

struct hermonprm_event_queue_entry_st {	/* Little Endian */
    pseudo_bit_t	event_sub_type[0x00008];/* Event Sub Type. 
                                                 Defined for events which have sub types, zero elsewhere. */
    pseudo_bit_t	reserved0[0x00008];
    pseudo_bit_t	event_type[0x00008];   /* Event Type */
    pseudo_bit_t	reserved1[0x00008];
/* -------------- */
    pseudo_bit_t	event_data[6][0x00020];/* Delivers auxilary data to handle event. */
/* -------------- */
    pseudo_bit_t	reserved2[0x00007];
    pseudo_bit_t	owner[0x00001];        /* Owner of the entry 
                                                 0 SW 
                                                 1 HW */
    pseudo_bit_t	reserved3[0x00018];
/* -------------- */
}; 

/* QP/EE State Transitions Command Parameters  ###michal - doesn't match PRM (field name changed) */

struct hermonprm_qp_ee_state_transitions_st {	/* Little Endian */
    pseudo_bit_t	opt_param_mask[0x00020];/* This field defines which optional parameters are passed. Each bit specifies whether optional parameter is passed (set) or not (cleared). The optparammask is defined for each QP/EE command. */
/* -------------- */
    pseudo_bit_t	reserved0[0x00020];
/* -------------- */
    struct hermonprm_queue_pair_ee_context_entry_st	qpc_eec_data;/* QPC/EEC data  ###michal - field has replaced with "qpc_data" (size .1948) */
/* -------------- */
    pseudo_bit_t	reserved1[0x00800];
/* -------------- */
}; 

/* Completion Queue Entry Format        #### michal - fixed by gdror */

struct hermonprm_completion_queue_entry_st {	/* Little Endian */
    pseudo_bit_t	qpn[0x00018];          /* Indicates the QP for which completion is being reported */
    pseudo_bit_t	reserved0[0x00002];
    pseudo_bit_t	d2s[0x00001];          /* Duplicate to Sniffer. This bit is set if both Send and Receive queues are subject for sniffer queue. The HW delivers
                                                 packet only to send-associated sniffer receive queue. */
    pseudo_bit_t	fcrc_sd[0x00001];      /* FCRC: If set, FC CRC is correct in FC frame encapsulated in payload. Valid for Raw Frame FC receive queue only.
                                                 SD: CQ associated with Sniffer receive queue. If set, packets were skipped due to lack of receive buffers on the Sniffer receive queue */
    pseudo_bit_t	fl[0x00001];           /* Force Loopback Valid for responder RawEth and UD only. */
    pseudo_bit_t	vlan[0x00002];         /* Valid for RawEth and UD over Ethernet only. Applicable for RawEth and UD over Ethernet Receive queue
                                                  00 - No VLAN header was present in the packet
                                                 01 - C-VLAN (802.1q) Header was present in the frame.
                                                 10 - S-VLAN (802.1ad) Header was present in the frame. */
    pseudo_bit_t	dife[0x00001];         /* DIF Error */
/* -------------- */
    pseudo_bit_t	immediate_rssvalue_invalidatekey[0x00020];/* For a responder CQE, if completed WQE Opcode is Send With Immediate or Write With Immediate, this field contains immediate field of the received message.
                                                 For a responder CQE, if completed WQE Opcode is Send With Invalidate, this field contains the R_key that was invalidated.
                                                 For a responder CQE of a GSI packet this filed contains the Pkey Index of the packet.
                                                 For IPoIB (UD) and RawEth CQEs this field contains the RSS hash function value.
                                                 Otherwise, this field is reserved. */
/* -------------- */
    pseudo_bit_t	srq_rqpn[0x00018];     /* For Responder UD QPs, Remote (source) QP number. 
                                                 For Responder SRC QPs, SRQ number.
                                                 Otherwise, this field is reserved. */
    pseudo_bit_t	ml_path_mac_index[0x00007];/* For responder UD over IB CQE: These are the lower LMC bits of the DLID in an incoming UD packet, higher bits of this field, that are not part of the LMC bits are zeroed by HW. Invalid if incoming message DLID is the permissive LID or incoming message is multicast.
                                                  For responder UD over Ethernet and RawEth CQEs: Index of the MAC Table entry that the packet DMAC was matched against.
                                                  Otherwise, this field is reserved. */
    pseudo_bit_t	g[0x00001];            /* For responder UD over IB CQE this bit indicates the presence of a GRH
                                                 For responder UD over Ethernet CQE this bit is set if IPv6 L3 header was present in the packet, this bit is cleared if IPv4 L3 Header was present in the packet.
                                                 Otherwise, this field is reserved. */
/* -------------- */
    pseudo_bit_t	slid_smac47_32[0x00010];/* For responder UD over IB CQE it is the source LID of the packet.
                                                 For responder UD over Ethernet and RawEth CQEs it is the source-MAC[47:32] of the packet.
                                                 Otherwise, this field is reserved. */
    pseudo_bit_t	vid[0x0000c];          /* Frame VID, valid for Responder Raw Ethernet and UD over Ethernet QP. Otherwise, this field is reserved. */
    pseudo_bit_t	sl[0x00004];           /* For responder UD over IB - the Service Level of the packet.
                                                  For responder UD over Ethernet and RawEth - it is VLAN-header[15:12]
                                                  Otherwise, this field is reserved. */
/* -------------- */
    pseudo_bit_t	smac31_0_rawether_ipoib_status[0x00020];/* For responder UD over Ethernet - source MAC[31:0] of the packet. 
                                                  For responder RawEth and UD over IB - RawEth-IPoIB status {3 reserved, ipok,udp,tcp,ipv4opt,ipv6,ipv4vf,ipv4,rht(6),ipv6extmask(6),reserved(2),l2am,reserved(2),bfcs,reserved(2),enc} 
                                                  Otherwise, this field is reserved. */
/* -------------- */
    pseudo_bit_t	byte_cnt[0x00020];     /* Byte count of data transferred. Applicable for RDMA-read, Atomic and all receive operations. completions. 
                                                 For Receive Queue that is subject for headers. separation, byte_cnt[31:24] specify number of bytes scattered to the first scatter entry (headers. length). Byte_cnt[23:0] specify total byte count received (including headers). */
/* -------------- */
    pseudo_bit_t	checksum[0x00010];     /* Valid for RawEth and IPoIB only. */
    pseudo_bit_t	wqe_counter[0x00010];
/* -------------- */
    pseudo_bit_t	opcode[0x00005];       /* Send completions - same encoding as WQE. 
                                                  Error coding is 0x1F
                                                  Receive:
                                                  0x0 - RDMA-Write with Immediate
                                                  0x1 - Send
                                                  0x2 - Send with Immediate
                                                  0x3 - Send & Invalidate
                                                  */
    pseudo_bit_t	is[0x00001];           /* inline scatter */
    pseudo_bit_t	s_r[0x00001];          /* send 1 / receive 0 */
    pseudo_bit_t	owner[0x00001];        /* HW Flips this bit for every CQ warp around. Initialized to Zero. */
    pseudo_bit_t	reserved1[0x00010];
    pseudo_bit_t	reserved2[0x00008];
/* -------------- */
}; 

/*  */

struct hermonprm_mcg_qps_st {	/* Little Endian */
    struct hermonprm_mcg_qp_dw_st	dw[128];
/* -------------- */
}; 

/*  */

struct hermonprm_mcg_hdr_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00006];
    pseudo_bit_t	next_mcg[0x0001a];
/* -------------- */
    pseudo_bit_t	members_count[0x00018];
    pseudo_bit_t	member_remove[0x00001];
    pseudo_bit_t	reserved1[0x00005];
    pseudo_bit_t	protocol[0x00002];
/* -------------- */
    pseudo_bit_t	reserved2[0x00020];
/* -------------- */
    pseudo_bit_t	reserved3[0x00020];
/* -------------- */
    pseudo_bit_t	gid3[0x00020];
/* -------------- */
    pseudo_bit_t	gid2[0x00020];
/* -------------- */
    pseudo_bit_t	gid1[0x00020];
/* -------------- */
    pseudo_bit_t	gid0[0x00020];
/* -------------- */
}; 

/*  */

struct hermonprm_sched_queue_context_st {	/* Little Endian */
    pseudo_bit_t	policy[0x00003];       /* Schedule Queue Policy - 0 - LLSQ, 1 - GBSQ, 2 - BESQ */
    pseudo_bit_t	vl15[0x00001];
    pseudo_bit_t	sl[0x00004];           /* SL this Schedule Queue is associated with (if vl15 bit is 0) */
    pseudo_bit_t	port[0x00002];         /* Port this Schedule Queue is associated with */
    pseudo_bit_t	reserved0[0x00006];
    pseudo_bit_t	weight[0x00010];       /* Weight of this SchQ */
/* -------------- */
}; 

/*  */

struct hermonprm_ecc_detect_event_data_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00080];
/* -------------- */
    pseudo_bit_t	cause_lsb[0x00001];
    pseudo_bit_t	reserved1[0x00002];
    pseudo_bit_t	cause_msb[0x00001];
    pseudo_bit_t	reserved2[0x00002];
    pseudo_bit_t	err_rmw[0x00001];
    pseudo_bit_t	err_src_id[0x00003];
    pseudo_bit_t	err_da[0x00002];
    pseudo_bit_t	err_ba[0x00002];
    pseudo_bit_t	reserved3[0x00011];
    pseudo_bit_t	overflow[0x00001];
/* -------------- */
    pseudo_bit_t	err_ra[0x00010];
    pseudo_bit_t	err_ca[0x00010];
/* -------------- */
}; 

/* Event_data Field - ECC Detection Event */

struct hermonprm_scrubbing_event_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00080];
/* -------------- */
    pseudo_bit_t	cause_lsb[0x00001];    /* data integrity error cause:
                                                 single ECC error in the 64bit lsb data, on the rise edge of the clock */
    pseudo_bit_t	reserved1[0x00002];
    pseudo_bit_t	cause_msb[0x00001];    /* data integrity error cause:
                                                 single ECC error in the 64bit msb data, on the fall edge of the clock */
    pseudo_bit_t	reserved2[0x00002];
    pseudo_bit_t	err_rmw[0x00001];      /* transaction type:
                                                 0 - read
                                                 1 - read/modify/write */
    pseudo_bit_t	err_src_id[0x00003];   /* source of the transaction: 0x4 - PCI, other - internal or IB */
    pseudo_bit_t	err_da[0x00002];       /* Error DIMM address */
    pseudo_bit_t	err_ba[0x00002];       /* Error bank address */
    pseudo_bit_t	reserved3[0x00011];
    pseudo_bit_t	overflow[0x00001];     /* Fatal: ECC error FIFO overflow - ECC errors were detected, which may or may not have been corrected by InfiniHost-III-EX */
/* -------------- */
    pseudo_bit_t	err_ra[0x00010];       /* Error row address */
    pseudo_bit_t	err_ca[0x00010];       /* Error column address */
/* -------------- */
}; 

/*  */

struct hermonprm_eq_cmd_doorbell_st {	/* Little Endian */
    pseudo_bit_t	reserved0[0x00020];
/* -------------- */
}; 

/* 0 */

struct hermonprm_hermon_prm_st {	/* Little Endian */
    struct hermonprm_completion_queue_entry_st	completion_queue_entry;/* Completion Queue Entry Format */
/* -------------- */
    pseudo_bit_t	reserved0[0x7ff00];
/* -------------- */
    struct hermonprm_qp_ee_state_transitions_st	qp_ee_state_transitions;/* QP/EE State Transitions Command Parameters */
/* -------------- */
    pseudo_bit_t	reserved1[0x7f000];
/* -------------- */
    struct hermonprm_event_queue_entry_st	event_queue_entry;/* Event Queue Entry */
/* -------------- */
    pseudo_bit_t	reserved2[0x7ff00];
/* -------------- */
    struct hermonprm_completion_event_st	completion_event;/* Event_data Field - Completion Event */
/* -------------- */
    pseudo_bit_t	reserved3[0x7ff40];
/* -------------- */
    struct hermonprm_completion_queue_error_st	completion_queue_error;/* Event_data Field - Completion Queue Error */
/* -------------- */
    pseudo_bit_t	reserved4[0x7ff40];
/* -------------- */
    struct hermonprm_port_state_change_st	port_state_change;/* Event_data Field - Port State Change */
/* -------------- */
    pseudo_bit_t	reserved5[0x7ff40];
/* -------------- */
    struct hermonprm_wqe_segment_st	wqe_segment;/* WQE segments format */
/* -------------- */
    pseudo_bit_t	reserved6[0x7f000];
/* -------------- */
    struct hermonprm_page_fault_event_data_st	page_fault_event_data;/* Event_data Field - Page Faults */
/* -------------- */
    pseudo_bit_t	reserved7[0x7ff40];
/* -------------- */
    struct hermonprm_performance_monitor_event_st	performance_monitor_event;/* Event Data Field - Performance Monitor */
/* -------------- */
    pseudo_bit_t	reserved8[0xfff20];
/* -------------- */
    struct hermonprm_mt25208_type0_st	mt25208_type0;/* InfiniHost-III-EX Type0 Configuration Header */
/* -------------- */
    pseudo_bit_t	reserved9[0x7f000];
/* -------------- */
    struct hermonprm_qp_ee_event_st	qp_ee_event;/* Event_data Field - QP/EE Events */
/* -------------- */
    pseudo_bit_t	reserved10[0x00040];
/* -------------- */
    struct hermonprm_gpio_event_data_st	gpio_event_data;
/* -------------- */
    pseudo_bit_t	reserved11[0x7fe40];
/* -------------- */
    struct hermonprm_ud_address_vector_st	ud_address_vector;/* UD Address Vector */
/* -------------- */
    pseudo_bit_t	reserved12[0x7ff00];
/* -------------- */
    struct hermonprm_queue_pair_ee_context_entry_st	queue_pair_ee_context_entry;/* QP and EE Context Entry */
/* -------------- */
    pseudo_bit_t	reserved13[0x7f840];
/* -------------- */
    struct hermonprm_address_path_st	address_path;/* Address Path */
/* -------------- */
    pseudo_bit_t	reserved14[0x7fea0];
/* -------------- */
    struct hermonprm_completion_queue_context_st	completion_queue_context;/* Completion Queue Context Table Entry */
/* -------------- */
    pseudo_bit_t	reserved15[0x7fe00];
/* -------------- */
    struct hermonprm_mpt_st	mpt;         /* Memory Protection Table (MPT) Entry */
/* -------------- */
    pseudo_bit_t	reserved16[0x7fe00];
/* -------------- */
    struct hermonprm_mtt_st	mtt;         /* Memory Translation Table (MTT) Entry */
/* -------------- */
    pseudo_bit_t	reserved17[0x7ffc0];
/* -------------- */
    struct hermonprm_eqc_st	eqc;         /* Event Queue Context Table Entry */
/* -------------- */
    pseudo_bit_t	reserved18[0x7fe00];
/* -------------- */
    struct hermonprm_performance_monitors_st	performance_monitors;/* Performance Monitors */
/* -------------- */
    pseudo_bit_t	reserved19[0x7ff80];
/* -------------- */
    struct hermonprm_hca_command_register_st	hca_command_register;/* HCA Command Register (HCR) */
/* -------------- */
    pseudo_bit_t	reserved20[0xfff20];
/* -------------- */
    struct hermonprm_init_hca_st	init_hca;/* INIT_HCA & QUERY_HCA Parameters Block */
/* -------------- */
    pseudo_bit_t	reserved21[0x7f000];
/* -------------- */
    struct hermonprm_qpcbaseaddr_st	qpcbaseaddr;/* QPC/EEC/CQC/EQC/RDB Parameters */
/* -------------- */
    pseudo_bit_t	reserved22[0x7fc00];
/* -------------- */
    struct hermonprm_udavtable_memory_parameters_st	udavtable_memory_parameters;/* Memory Access Parameters for UD Address Vector Table */
/* -------------- */
    pseudo_bit_t	reserved23[0x7ffc0];
/* -------------- */
    struct hermonprm_multicastparam_st	multicastparam;/* Multicast Support Parameters */
/* -------------- */
    pseudo_bit_t	reserved24[0x7ff00];
/* -------------- */
    struct hermonprm_tptparams_st	tptparams;/* Translation and Protection Tables Parameters */
/* -------------- */
    pseudo_bit_t	reserved25[0x7ff00];
/* -------------- */
    pseudo_bit_t	reserved26[0x00800];
/* -------------- */
    pseudo_bit_t	reserved27[0x00100];
/* -------------- */
    pseudo_bit_t	reserved28[0x7f700];
/* -------------- */
    pseudo_bit_t	reserved29[0x00100];
/* -------------- */
    pseudo_bit_t	reserved30[0x7ff00];
/* -------------- */
    struct hermonprm_query_fw_st	query_fw;/* QUERY_FW Parameters Block */
/* -------------- */
    pseudo_bit_t	reserved31[0x7f800];
/* -------------- */
    struct hermonprm_query_adapter_st	query_adapter;/* QUERY_ADAPTER Parameters Block */
/* -------------- */
    pseudo_bit_t	reserved32[0x7f800];
/* -------------- */
    struct hermonprm_query_dev_cap_st	query_dev_cap;/* Query Device Limitations */
/* -------------- */
    pseudo_bit_t	reserved33[0x7f800];
/* -------------- */
    struct hermonprm_uar_params_st	uar_params;/* UAR Parameters */
/* -------------- */
    pseudo_bit_t	reserved34[0x7ff00];
/* -------------- */
    struct hermonprm_init_port_st	init_port;/* INIT_PORT Parameters */
/* -------------- */
    pseudo_bit_t	reserved35[0x7f800];
/* -------------- */
    struct hermonprm_mgm_entry_st	mgm_entry;/* Multicast Group Member */
/* -------------- */
    pseudo_bit_t	reserved36[0x7fe00];
/* -------------- */
    struct hermonprm_set_ib_st	set_ib;   /* SET_IB Parameters */
/* -------------- */
    pseudo_bit_t	reserved37[0x7fe00];
/* -------------- */
    struct hermonprm_rd_send_doorbell_st	rd_send_doorbell;/* RD-send doorbell */
/* -------------- */
    pseudo_bit_t	reserved38[0x7ff80];
/* -------------- */
    struct hermonprm_send_doorbell_st	send_doorbell;/* Send doorbell */
/* -------------- */
    pseudo_bit_t	reserved39[0x7ffc0];
/* -------------- */
    struct hermonprm_receive_doorbell_st	receive_doorbell;/* Receive doorbell */
/* -------------- */
    pseudo_bit_t	reserved40[0x7ffc0];
/* -------------- */
    struct hermonprm_cq_cmd_doorbell_st	cq_cmd_doorbell;/* CQ Doorbell */
/* -------------- */
    pseudo_bit_t	reserved41[0xfffc0];
/* -------------- */
    struct hermonprm_uar_st	uar;         /* User Access Region */
/* -------------- */
    pseudo_bit_t	reserved42[0x7c000];
/* -------------- */
    struct hermonprm_mgmqp_st	mgmqp;     /* Multicast Group Member QP */
/* -------------- */
    pseudo_bit_t	reserved43[0x7ffe0];
/* -------------- */
    struct hermonprm_query_debug_msg_st	query_debug_msg;/* Query Debug Message */
/* -------------- */
    pseudo_bit_t	reserved44[0x7f800];
/* -------------- */
    struct hermonprm_mad_ifc_st	mad_ifc; /* MAD_IFC Input Mailbox */
/* -------------- */
    pseudo_bit_t	reserved45[0x00900];
/* -------------- */
    struct hermonprm_mad_ifc_input_modifier_st	mad_ifc_input_modifier;/* MAD_IFC Input Modifier */
/* -------------- */
    pseudo_bit_t	reserved46[0x7e6e0];
/* -------------- */
    struct hermonprm_resize_cq_st	resize_cq;/* Resize CQ Input Mailbox */
/* -------------- */
    pseudo_bit_t	reserved47[0x7fe00];
/* -------------- */
    struct hermonprm_completion_with_error_st	completion_with_error;/* Completion with Error CQE */
/* -------------- */
    pseudo_bit_t	reserved48[0x7ff00];
/* -------------- */
    struct hermonprm_hcr_completion_event_st	hcr_completion_event;/* Event_data Field - HCR Completion Event */
/* -------------- */
    pseudo_bit_t	reserved49[0x7ff40];
/* -------------- */
    struct hermonprm_transport_and_ci_error_counters_st	transport_and_ci_error_counters;/* Transport and CI Error Counters */
/* -------------- */
    pseudo_bit_t	reserved50[0x7f000];
/* -------------- */
    struct hermonprm_performance_counters_st	performance_counters;/* Performance Counters */
/* -------------- */
    pseudo_bit_t	reserved51[0x9ff800];
/* -------------- */
    struct hermonprm_fast_registration_segment_st	fast_registration_segment;/* Fast Registration Segment */
/* -------------- */
    pseudo_bit_t	reserved52[0x7ff00];
/* -------------- */
    struct hermonprm_pbl_st	pbl;         /* Physical Buffer List */
/* -------------- */
    pseudo_bit_t	reserved53[0x7ff00];
/* -------------- */
    struct hermonprm_srq_context_st	srq_context;/* SRQ Context */
/* -------------- */
    pseudo_bit_t	reserved54[0x7fe80];
/* -------------- */
    struct hermonprm_mod_stat_cfg_st	mod_stat_cfg;/* MOD_STAT_CFG */
/* -------------- */
    pseudo_bit_t	reserved55[0x7f800];
/* -------------- */
    struct hermonprm_virtual_physical_mapping_st	virtual_physical_mapping;/* Virtual and Physical Mapping */
/* -------------- */
    pseudo_bit_t	reserved56[0x7ff80];
/* -------------- */
    struct hermonprm_cq_ci_db_record_st	cq_ci_db_record;/* CQ_CI_DB_Record */
/* -------------- */
    pseudo_bit_t	reserved57[0x7ffc0];
/* -------------- */
    struct hermonprm_cq_arm_db_record_st	cq_arm_db_record;/* CQ_ARM_DB_Record */
/* -------------- */
    pseudo_bit_t	reserved58[0x7ffc0];
/* -------------- */
    struct hermonprm_qp_db_record_st	qp_db_record;/* QP_DB_Record */
/* -------------- */
    pseudo_bit_t	reserved59[0x00020];
/* -------------- */
    pseudo_bit_t	reserved60[0x1fffc0];
/* -------------- */
    struct hermonprm_configuration_registers_st	configuration_registers;/* InfiniHost III EX Configuration Registers */
/* -------------- */
    struct hermonprm_eq_set_ci_table_st	eq_set_ci_table;/* EQ Set CI DBs Table */
/* -------------- */
    pseudo_bit_t	reserved61[0x01000];
/* -------------- */
    pseudo_bit_t	reserved62[0x00040];
/* -------------- */
    pseudo_bit_t	reserved63[0x00fc0];
/* -------------- */
    struct hermonprm_clr_int_st	clr_int; /* Clear Interrupt Register */
/* -------------- */
    pseudo_bit_t	reserved64[0xffcfc0];
/* -------------- */
}; 
#endif /* H_prefix_hermonprm_bits_fixnames_MT25408_PRM_csp_H */
