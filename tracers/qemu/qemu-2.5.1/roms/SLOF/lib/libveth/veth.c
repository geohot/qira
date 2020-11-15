/******************************************************************************
 * Copyright (c) 2011, 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <helpers.h>
#include "veth.h"
#include "libhvcall.h"

#undef VETH_DEBUG
//#define VETH_DEBUG
#ifdef VETH_DEBUG
#define dprintf(_x ...) do { printf(_x); } while(0)
#else
#define dprintf(_x ...)
#endif

/* *** WARNING: We pass our addresses as-is as DMA addresses,
 *     we -do- rely on the forth code to have enabled TCE bypass
 *     on our device !
 */
#define vaddr_to_dma(vaddr)	((uint64_t)vaddr)

struct ibmveth_buf_desc_fields {
	uint32_t flags_len;
#define IBMVETH_BUF_VALID	0x80000000
#define IBMVETH_BUF_TOGGLE	0x40000000
#define IBMVETH_BUF_NO_CSUM	0x02000000
#define IBMVETH_BUF_CSUM_GOOD	0x01000000
#define IBMVETH_BUF_LEN_MASK	0x00FFFFFF
	uint32_t address;
};

union ibmveth_buf_desc {
	uint64_t desc;
	struct ibmveth_buf_desc_fields fields;
};

struct ibmveth_rx_q_entry {
	uint32_t flags_off;
#define IBMVETH_RXQ_TOGGLE		0x80000000
#define IBMVETH_RXQ_TOGGLE_SHIFT	31
#define IBMVETH_RXQ_VALID		0x40000000
#define IBMVETH_RXQ_NO_CSUM		0x02000000
#define IBMVETH_RXQ_CSUM_GOOD		0x01000000
#define IBMVETH_RXQ_OFF_MASK		0x0000FFFF

	uint32_t length;
	uint64_t correlator;
};

static void *buffer_list; 
static void *filter_list; 
static uint64_t *rx_bufs;
static uint64_t *rx_bufs_aligned;
static uint32_t cur_rx_toggle;
static uint32_t cur_rx_index;

#define RX_QUEUE_SIZE	256
#define RX_BUF_SIZE	2048
#define RX_BUF_MULT	(RX_BUF_SIZE >> 3)

static struct ibmveth_rx_q_entry *rx_queue;

static inline uint64_t *veth_get_rx_buf(unsigned int i)
{
	return &rx_bufs_aligned[i * RX_BUF_MULT];
}

static int veth_init(net_driver_t *driver)
{
	char *mac_addr;
	union ibmveth_buf_desc rxq_desc;
	unsigned long rx_queue_len = sizeof(struct ibmveth_rx_q_entry) *
		RX_QUEUE_SIZE;
	unsigned int i;
	long rc;

	if (!driver)
		return -1;

	dprintf("veth_init(%02x:%02x:%02x:%02x:%02x:%02x)\n",
		mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);

	if (driver->running != 0)
		return 0;

	mac_addr = (char *)driver->mac_addr;
	cur_rx_toggle = IBMVETH_RXQ_TOGGLE;
	cur_rx_index = 0;
	buffer_list = SLOF_alloc_mem_aligned(8192, 4096);
	filter_list = buffer_list + 4096;
	rx_queue = SLOF_alloc_mem_aligned(rx_queue_len, 16);
	rx_bufs = SLOF_alloc_mem(2048 * RX_QUEUE_SIZE + 4);
	if (!buffer_list || !filter_list || !rx_queue || !rx_bufs) {
		printf("veth: Failed to allocate memory !\n");
		goto fail;
	}
	rx_bufs_aligned = (uint64_t *)(((uint64_t)rx_bufs | 3) + 1);
	rxq_desc.fields.address = vaddr_to_dma(rx_queue);
	rxq_desc.fields.flags_len = IBMVETH_BUF_VALID | rx_queue_len;

	rc = h_register_logical_lan(driver->reg,
				    vaddr_to_dma(buffer_list),
				    rxq_desc.desc,
				    vaddr_to_dma(filter_list),
				    (*(uint64_t *)mac_addr) >> 16);
	if (rc != H_SUCCESS) {
		printf("veth: Error %ld registering interface !\n", rc);
		goto fail;
	}
	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		uint64_t *buf = veth_get_rx_buf(i);
		union ibmveth_buf_desc desc;
		*buf = (uint64_t)buf;
		desc.fields.address = vaddr_to_dma(buf);
		desc.fields.flags_len = IBMVETH_BUF_VALID | RX_BUF_SIZE;
		h_add_logical_lan_buffer(driver->reg, desc.desc);
	}

	driver->running = 1;

	return 0;
 fail:
	if (buffer_list)
		SLOF_free_mem(buffer_list, 8192);
	if (rx_queue)
		SLOF_free_mem(rx_queue, rx_queue_len);
	if (rx_bufs)
		SLOF_free_mem(rx_bufs, 2048 * RX_QUEUE_SIZE + 4);
	return -1;
}

static int veth_term(net_driver_t *driver)
{
	dprintf("veth_term()\n");

	if (driver->running == 0)
		return 0;

	h_free_logical_lan(driver->reg);

	if (buffer_list)
		SLOF_free_mem(buffer_list, 8192);
	if (rx_queue)
		SLOF_free_mem(rx_queue, sizeof(struct ibmveth_rx_q_entry) * RX_QUEUE_SIZE);
	if (rx_bufs)
		SLOF_free_mem(rx_bufs, 2048 * RX_QUEUE_SIZE + 4);

	driver->running = 0;

	return 0;
}

static int veth_receive(char *f_buffer_pc, int f_len_i, net_driver_t *driver)
{
	int packet = 0;

	dprintf("veth_receive()\n");

	while(!packet) {
		struct ibmveth_rx_q_entry *desc = &rx_queue[cur_rx_index];
		union ibmveth_buf_desc bdesc;
		void *buf;

		buf = (void *)desc->correlator;

		if ((desc->flags_off & IBMVETH_RXQ_TOGGLE) != cur_rx_toggle)
			break;

		if (!(desc->flags_off & IBMVETH_RXQ_VALID))
			goto recycle;
		if (desc->length > f_len_i) {
			printf("veth: Dropping too big packet [%d bytes]\n",
			       desc->length);
			goto recycle;
		}

		packet = desc->length;
		memcpy(f_buffer_pc,
		       buf + (desc->flags_off & IBMVETH_RXQ_OFF_MASK), packet);
	recycle:
		bdesc.fields.address = vaddr_to_dma(buf);
		bdesc.fields.flags_len = IBMVETH_BUF_VALID | RX_BUF_SIZE;
		h_add_logical_lan_buffer(driver->reg, bdesc.desc);

		cur_rx_index = (cur_rx_index + 1) % RX_QUEUE_SIZE;
		if (cur_rx_index == 0)
			cur_rx_toggle ^= IBMVETH_RXQ_TOGGLE;
	}

	return packet;
}

static int veth_xmit(char *f_buffer_pc, int f_len_i, net_driver_t *driver)
{
	union ibmveth_buf_desc tx_desc;
	long rc;

	dprintf("veth_xmit(packet at %p, %d bytes)\n", f_buffer_pc, f_len_i);

	tx_desc.fields.address = vaddr_to_dma(f_buffer_pc);
	tx_desc.fields.flags_len = IBMVETH_BUF_VALID | f_len_i;

	rc = hv_send_logical_lan(driver->reg, tx_desc.desc, 0, 0, 0, 0, 0);
	if (rc != H_SUCCESS) {
		printf("veth: Error %ld sending packet !\n", rc);
		return -1;
	}

	return f_len_i;
}

net_driver_t *libveth_open(char *mac_addr, int mac_len, char *reg, int reg_len)
{
	net_driver_t *driver;

	driver = SLOF_alloc_mem(sizeof(*driver));
	if (!driver) {
		printf("Unable to allocate veth driver\n");
		return NULL;
	}

	/* veth uses a 8-byte wide property instead of 6-byte wide MACs */
	if ((mac_len == 8) && (mac_addr[0] == 0) && mac_addr[1] == 0)
		mac_addr += 2;
	memcpy(driver->mac_addr, mac_addr, 6);
	driver->reg = *(uint32_t *)reg;
	driver->running = 0;

	if (veth_init(driver)) {
		SLOF_free_mem(driver, sizeof(*driver));
		return NULL;
	}

	return driver;
}

void libveth_close(net_driver_t *driver)
{
	if (driver) {
		veth_term(driver);
		SLOF_free_mem(driver, sizeof(*driver));
	}
}

int libveth_read(char *buf, int len, net_driver_t *driver)
{
	if (buf)
		return veth_receive(buf, len, driver);

	return -1;
}

int libveth_write(char *buf, int len, net_driver_t *driver)
{
	if (buf)
		return veth_xmit(buf, len, driver);

	return -1;
}
