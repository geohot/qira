/******************************************************************************
 * Copyright (c) 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

/*
 * This is the implementation for the Virtio network device driver. Details
 * about the virtio-net interface can be found in Rusty Russel's "Virtio PCI
 * Card Specification v0.8.10", appendix C, which can be found here:
 *
 *        http://ozlabs.org/~rusty/virtio-spec/virtio-spec.pdf
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <helpers.h>
#include <cache.h>
#include <byteorder.h>
#include "virtio.h"
#include "virtio-net.h"

#undef DEBUG
//#define DEBUG
#ifdef DEBUG
# define dprintf(fmt...) do { printf(fmt); } while(0)
#else
# define dprintf(fmt...)
#endif

#define sync()  asm volatile (" sync \n" ::: "memory")

/* PCI virtio header offsets */
#define VIRTIOHDR_DEVICE_FEATURES       0
#define VIRTIOHDR_GUEST_FEATURES        4
#define VIRTIOHDR_QUEUE_ADDRESS         8
#define VIRTIOHDR_QUEUE_SIZE            12
#define VIRTIOHDR_QUEUE_SELECT          14
#define VIRTIOHDR_QUEUE_NOTIFY          16
#define VIRTIOHDR_DEVICE_STATUS         18
#define VIRTIOHDR_ISR_STATUS            19
#define VIRTIOHDR_DEVICE_CONFIG         20
#define VIRTIOHDR_MAC_ADDRESS           20

struct virtio_device virtiodev;
struct vqs vq[2];     /* Information about virtqueues */

/* See Virtio Spec, appendix C, "Device Operation" */ 
struct virtio_net_hdr {
	uint8_t  flags;
	uint8_t  gso_type;
	uint16_t  hdr_len;
	uint16_t  gso_size;
	uint16_t  csum_start;
	uint16_t  csum_offset;
	// uint16_t  num_buffers;	/* Only if VIRTIO_NET_F_MRG_RXBUF */
};

static uint16_t last_rx_idx;	/* Last index in RX "used" ring */

/**
 * Module init for virtio via PCI.
 * Checks whether we're reponsible for the given device and set up
 * the virtqueue configuration.
 */
static int virtionet_init_pci(struct virtio_device *dev)
{
	int i;

	dprintf("virtionet: doing virtionet_init_pci!\n");

	if (!dev)
		return -1;

	virtiodev.base = dev->base;
	virtiodev.type = dev->type;

	/* Reset device */
	virtio_reset_device(&virtiodev);

	/* The queue information can be retrieved via the virtio header that
	 * can be found in the I/O BAR. First queue is the receive queue,
	 * second the transmit queue, and the forth is the control queue for
	 * networking options.
	 * We are only interested in the receive and transmit queue here. */

	for (i=VQ_RX; i<=VQ_TX; i++) {
		/* Select ring (0=RX, 1=TX): */
		vq[i].id = i-VQ_RX;
		ci_write_16(virtiodev.base+VIRTIOHDR_QUEUE_SELECT,
			    cpu_to_le16(vq[i].id));

		vq[i].size = le16_to_cpu(ci_read_16(virtiodev.base+VIRTIOHDR_QUEUE_SIZE));
		vq[i].desc = SLOF_alloc_mem_aligned(virtio_vring_size(vq[i].size), 4096);
		if (!vq[i].desc) {
			printf("memory allocation failed!\n");
			return -1;
		}
		memset(vq[i].desc, 0, virtio_vring_size(vq[i].size));
		ci_write_32(virtiodev.base+VIRTIOHDR_QUEUE_ADDRESS,
			    cpu_to_le32((long)vq[i].desc / 4096));
		vq[i].avail = (void*)vq[i].desc
				    + vq[i].size * sizeof(struct vring_desc);
		vq[i].used = (void*)VQ_ALIGN((long)vq[i].avail
				    + vq[i].size * sizeof(struct vring_avail));

		dprintf("%i: vq.id = %llx\nvq.size =%x\n vq.avail =%p\nvq.used=%p\n",
			i, vq[i].id, vq[i].size, vq[i].avail, vq[i].used);
	}

	/* Acknowledge device. */
	virtio_set_status(&virtiodev, VIRTIO_STAT_ACKNOWLEDGE);

	return 0;
}

/**
 * Initialize the virtio-net device.
 * See the Virtio Spec, chapter 2.2.1 and Appendix C "Device Initialization"
 * for details.
 */
static int virtionet_init(net_driver_t *driver)
{
	int i;

	dprintf("virtionet_init(%02x:%02x:%02x:%02x:%02x:%02x)\n",
		driver->mac_addr[0], driver->mac_addr[1],
		driver->mac_addr[2], driver->mac_addr[3],
		driver->mac_addr[4], driver->mac_addr[5]);

	if (driver->running != 0)
		return 0;

	/* Tell HV that we know how to drive the device. */
	virtio_set_status(&virtiodev, VIRTIO_STAT_ACKNOWLEDGE|VIRTIO_STAT_DRIVER);

	/* Device specific setup - we do not support special features right now */
	virtio_set_guest_features(&virtiodev,  0);

	/* Allocate memory for one transmit an multiple receive buffers */
	vq[VQ_RX].buf_mem = SLOF_alloc_mem((BUFFER_ENTRY_SIZE+sizeof(struct virtio_net_hdr))
				   * RX_QUEUE_SIZE);
	if (!vq[VQ_RX].buf_mem) {
		printf("virtionet: Failed to allocate buffers!\n");
		virtio_set_status(&virtiodev, VIRTIO_STAT_FAILED);
		return -1;
	}

	/* Prepare receive buffer queue */
	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		struct vring_desc *desc;
		/* Descriptor for net_hdr: */
		desc = &vq[VQ_RX].desc[i*2];
		desc->addr = (uint64_t)vq[VQ_RX].buf_mem
			     + i * (BUFFER_ENTRY_SIZE+sizeof(struct virtio_net_hdr));
		desc->len = sizeof(struct virtio_net_hdr);
		desc->flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
		desc->next = i*2+1;

		/* Descriptor for data: */
		desc = &vq[VQ_RX].desc[i*2+1];
		desc->addr = vq[VQ_RX].desc[i*2].addr + sizeof(struct virtio_net_hdr);
		desc->len = BUFFER_ENTRY_SIZE;
		desc->flags = VRING_DESC_F_WRITE;
		desc->next = 0;

		vq[VQ_RX].avail->ring[i] = i*2;
	}
	sync();
	vq[VQ_RX].avail->flags = VRING_AVAIL_F_NO_INTERRUPT;
	vq[VQ_RX].avail->idx = RX_QUEUE_SIZE;

	last_rx_idx = vq[VQ_RX].used->idx;

	vq[VQ_TX].avail->flags = VRING_AVAIL_F_NO_INTERRUPT;
	vq[VQ_TX].avail->idx = 0;

	/* Tell HV that setup succeeded */
	virtio_set_status(&virtiodev, VIRTIO_STAT_ACKNOWLEDGE
				      |VIRTIO_STAT_DRIVER
				      |VIRTIO_STAT_DRIVER_OK);

	/* Tell HV that RX queues are ready */
	virtio_queue_notify(&virtiodev, VQ_RX);

	driver->running = 1;

	return 0;
}


/**
 * Shutdown driver.
 * We've got to make sure that the hosts stops all transfers since the buffers
 * in our main memory will become invalid after this module has been terminated.
 */
static int virtionet_term(net_driver_t *driver)
{
	dprintf("virtionet_term()\n");

	if (driver->running == 0)
		return 0;

	/* Quiesce device */
	virtio_set_status(&virtiodev, VIRTIO_STAT_FAILED);

	/* Reset device */
	virtio_reset_device(&virtiodev);

	driver->running = 0;

	return 0;
}


/**
 * Transmit a packet
 */
static int virtionet_xmit(char *buf, int len)
{
	struct vring_desc *desc;
	int id;
	static struct virtio_net_hdr nethdr;

	if (len > BUFFER_ENTRY_SIZE) {
		printf("virtionet: Packet too big!\n");
		return 0;
	}

	dprintf("\nvirtionet_xmit(packet at %p, %d bytes)\n", buf, len);

	memset(&nethdr, 0, sizeof(nethdr));

	/* Determine descriptor index */
	id = (vq[VQ_TX].avail->idx * 2) % vq[VQ_TX].size;

	/* Set up virtqueue descriptor for header */
	desc = &vq[VQ_TX].desc[id];
	desc->addr = (uint64_t)&nethdr;
	desc->len = sizeof(struct virtio_net_hdr);
	desc->flags = VRING_DESC_F_NEXT;
	desc->next = id + 1;

	/* Set up virtqueue descriptor for data */
	desc = &vq[VQ_TX].desc[id+1];
	desc->addr = (uint64_t)buf;
	desc->len = len;
	desc->flags = 0;
	desc->next = 0;

	vq[VQ_TX].avail->ring[vq[VQ_TX].avail->idx % vq[VQ_TX].size] = id;
	sync();
	vq[VQ_TX].avail->idx += 1;
	sync();

	/* Tell HV that TX queue is ready */
	virtio_queue_notify(&virtiodev, VQ_TX);

	return len;
}


/**
 * Receive a packet
 */
static int virtionet_receive(char *buf, int maxlen)
{
	int len = 0;
	int id;

	if (last_rx_idx == vq[VQ_RX].used->idx) {
		/* Nothing received yet */
		return 0;
	}

	id = (vq[VQ_RX].used->ring[last_rx_idx % vq[VQ_RX].size].id + 1)
	     % vq[VQ_RX].size;
	len = vq[VQ_RX].used->ring[last_rx_idx % vq[VQ_RX].size].len
	      - sizeof(struct virtio_net_hdr);

	dprintf("virtionet_receive() last_rx_idx=%i, vq[VQ_RX].used->idx=%i,"
		" id=%i len=%i\n", last_rx_idx, vq[VQ_RX].used->idx, id, len);

	if (len > maxlen) {
		printf("virtio-net: Receive buffer not big enough!\n");
		len = maxlen;
	}

#if 0
	/* Dump packet */
	printf("\n");
	int i;
	for (i=0; i<64; i++) {
		printf(" %02x", *(uint8_t*)(vq[VQ_RX].desc[id].addr+i));
		if ((i%16)==15)
			printf("\n");
	}
	prinfk("\n");
#endif

	/* Copy data to destination buffer */
	memcpy(buf, (void*)vq[VQ_RX].desc[id].addr, len);

	/* Move indices to next entries */
	last_rx_idx = last_rx_idx + 1;

	vq[VQ_RX].avail->ring[vq[VQ_RX].avail->idx % vq[VQ_RX].size] = id - 1;
	sync();
	vq[VQ_RX].avail->idx += 1;

	/* Tell HV that RX queue entry is ready */
	virtio_queue_notify(&virtiodev, VQ_RX);

	return len;
}

net_driver_t *virtionet_open(char *mac_addr, int len, struct virtio_device *dev)
{
	net_driver_t *driver;

	driver = SLOF_alloc_mem(sizeof(*driver));
	if (!driver) {
		printf("Unable to allocate virtio-net driver\n");
		return NULL;
	}

	memcpy(driver->mac_addr, mac_addr, 6);
	driver->running = 0;

	if (virtionet_init_pci(dev))
		goto FAIL;

	if (virtionet_init(driver))
		goto FAIL;

	return driver;

FAIL:	SLOF_free_mem(driver, sizeof(*driver));
	return NULL;
}

void virtionet_close(net_driver_t *driver)
{
	if (driver) {
		virtionet_term(driver);
		SLOF_free_mem(driver, sizeof(*driver));
	}
}

int virtionet_read(char *buf, int len)
{
	if (buf)
		return virtionet_receive(buf, len);
	return -1;
}

int virtionet_write(char *buf, int len)
{
	if (buf)
		return virtionet_xmit(buf, len);
	return -1;
}
