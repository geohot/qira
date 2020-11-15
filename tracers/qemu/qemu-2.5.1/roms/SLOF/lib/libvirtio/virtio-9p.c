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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <byteorder.h>
#include <cpu.h>

#include "virtio-9p.h"
#include "p9.h"


/**
 * Notes for 9P Server config:
 *
 * make distclean; cm make qemu
 * sudo cp boot_rom.bin /opt/qemu/share/qemu/slof.bin
 * /opt/qemu/bin/qemu-system-ppc64 -M pseries -m 512 -boot d -nographic -fsdev
 *    local,id=trule,path=/home/trule/virtfs,security_model=none -device
 *    virtio-9p-spapr,fsdev=trule,mount_tag=trule
 * load virtfs:\some\file
 */

/* We support only one instance due to the (ab)use of globals. We
 * use the buffer size as an open marker as well.
 */
static int __buf_size;


#define ROOT_FID	1
#define FILE_FID	2
#define TAG_SIZE	128
#define MIN(a,b)	((a)>(b)?(b):(a))


#undef DEBUG
//#define DEBUG
#ifdef DEBUG
#define dprintf(_x ...) do { printf(_x); } while(0)
#else
#define dprintf(_x ...)
#endif

#ifdef DEBUG
static void dprint_buffer(const char *name, uint8_t *buffer, int length)
{
	int i;

	printf("*** %s ***", name);

	for (i = 0; i < length; i++) {
		if (i % 16 == 0) {
			printf("\n %04x:", i);
		}

		printf(" %02x", buffer[i]);
	}

	printf("\n");
}
#else
#define dprint_buffer(n, b, l)
#endif

/**
 * virtio_9p_transact
 *
 * Perform a 9P transaction over the VIRTIO queue interface. This function is
 * registered with the p9.c library via p9_reg_transport() to provide
 * connectivity to the 9P server.
 *
 * @param tx[in]	Data to send, mapped to first queue item.
 * @param tx_size[in]	Size of data to send.
 * @param rx[out]	Data to receive, mappend to second queue item.
 * @param rx_size[out]	Size of data received.
 * @return	0 = success, -ve = error.
 */
static int virtio_9p_transact(void *opaque, uint8_t *tx, int tx_size, uint8_t *rx,
			      int *rx_size)
{
	struct virtio_device *dev = opaque;
	struct vring_desc *desc;
	int id, i;
	uint32_t vq_size;
	struct vring_desc *vq_desc;
	struct vring_avail *vq_avail;
	struct vring_used *vq_used;
	volatile uint16_t *current_used_idx;
	uint16_t last_used_idx;


	/* Virt IO queues. */
	vq_size = virtio_get_qsize(dev, 0);
	vq_desc = virtio_get_vring_desc(dev, 0);
	vq_avail = virtio_get_vring_avail(dev, 0);
	vq_used = virtio_get_vring_used(dev, 0);

	last_used_idx = vq_used->idx;
	current_used_idx = &vq_used->idx;

	/* Determine descriptor index */
	id = (vq_avail->idx * 3) % vq_size;

	/* TX in first queue item. */
	dprint_buffer("TX", tx, tx_size);

	desc = &vq_desc[id];
	desc->addr = (uint64_t)tx;
	desc->len = tx_size;
	desc->flags = VRING_DESC_F_NEXT;
	desc->next = (id + 1) % vq_size;

	/* RX in the second queue item. */
	desc = &vq_desc[(id + 1) % vq_size];
	desc->addr = (uint64_t)rx;
	desc->len = *rx_size;
	desc->flags = VRING_DESC_F_WRITE;
	desc->next = 0;

	/* Tell HV that the queue is ready */
	vq_avail->ring[vq_avail->idx % vq_size] = id;
	mb();
	vq_avail->idx += 1;
	virtio_queue_notify(dev, 0);

	/* Receive the response. */
	i = 10000000;
	while (*current_used_idx == last_used_idx && i-- > 0) {
		// do something better
		mb();
	}
	if (i == 0) {
		return -1;
	}

	*rx_size = MIN(*rx_size, le32_to_cpu(*(uint32_t*)(&rx[0])));
	dprint_buffer("RX", rx, *rx_size);

	return 0;
}

/**
 * virtio_9p_init
 *
 * Establish the VIRTIO connection for use with the 9P server. Setup queues
 * and negotiate capabilities. Setup the 9P (Client) library.
 *
 * @param reg[in]	Pointer to device tree node for VIRTIO/9P interface.
 * @param tx_buf[in]	TX buffer for use by 9P Client lib - 8K in size.
 * @param rx_buf[in]	TX buffer for use by 9P Client lib - 8K in size.
 * @param buf_size	Somewhat redundant, buffer size expected to be 8k.
 * @return	0 = success, -ve = error.
 */
int virtio_9p_init(struct virtio_device *dev, void *tx_buf, void *rx_buf,
		   int buf_size)
{
	struct vring_avail *vq_avail;

	/* Check for double open */
	if (__buf_size)
		return -1;
	__buf_size = buf_size;

        dprintf("%s : device at %p\n", __func__, dev->base);
        dprintf("%s : type is %04x\n", __func__, dev->type);

	/* Reset device */
	// XXX That will clear the virtq base. We need to move
	//     initializing it to here anyway
	//
	//	 virtio_reset_device(dev);

	/* Acknowledge device. */
	virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE);

	/* Tell HV that we know how to drive the device. */
	virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE | VIRTIO_STAT_DRIVER);

	/* Device specific setup - we do not support special features */
	virtio_set_guest_features(dev,  0);

	vq_avail = virtio_get_vring_avail(dev, 0);
	vq_avail->flags = VRING_AVAIL_F_NO_INTERRUPT;
	vq_avail->idx = 0;

	/* Tell HV that setup succeeded */
	virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE | VIRTIO_STAT_DRIVER
			  |VIRTIO_STAT_DRIVER_OK);

	/* Setup 9P library. */
	p9_reg_transport(virtio_9p_transact, dev,(uint8_t *)tx_buf,
			(uint8_t *)rx_buf);

	dprintf("%s : complete\n", __func__);
	return 0;
}

/**
 * virtio_9p_shutdown
 */
void virtio_9p_shutdown(struct virtio_device *dev)
{
        /* Quiesce device */
        virtio_set_status(dev, VIRTIO_STAT_FAILED);

        /* Reset device */
        virtio_reset_device(dev);

	__buf_size = 0;
}

/**
 * virtio_9p_load
 *
 * Read a file from the 9P Server on the VIRTIO interface.
 *
 * @param file_name[in]	File to read, use Linux style paths.
 * @param buffer[out]	Where to read the file to.
 * @return	+ve = amount of data read, -ve = error.
 */
int virtio_9p_load(struct virtio_device *dev, const char *file_name, uint8_t *buffer)
{
	int rc;
	uint16_t tag_len;
	char tag_name[TAG_SIZE];
	uint64_t offset = 0;
	uint8_t *pos = (uint8_t *)file_name;
	int start_fid = ROOT_FID;
	p9_connection_t connection = {
		.message_size = __buf_size,
		.fid = ROOT_FID,
		.uname = "slof"
	};
	p9_file_t file = {
		.connection = &connection,
		.fid = FILE_FID,
	};


	/* Get the share name from 9P config space. */
	tag_len = virtio_get_config(dev, 0, sizeof(tag_len));
	if (tag_len >= TAG_SIZE)
		tag_len = TAG_SIZE - 1;
	__virtio_read_config(dev, tag_name, 2, tag_len);
	connection.aname = tag_name;

	/* Connect to the 9P server. */
	dprintf("%s : connecting, tag = %s, user = %s, msgsize = %d\n",
			__func__, connection.aname, connection.uname,
			connection.message_size);
	rc = p9_version(&connection);
	if (rc != 0) {
		printf("Version check failed, rc = %d\n", rc);
		goto cleanup_connection;
	}
	rc = p9_attach(&connection);
	if (rc != 0) {
		printf("Attach failed, rc = %d\n", rc);
		goto cleanup_connection;
	}
	dprintf("%s : connected, msgsize = %d\n", __func__,
			connection.message_size);

	/* Walk to the file. */
	do {
		dprintf("%s : walk path %s\n", __func__, pos);
		rc = p9_walk(&connection, start_fid, FILE_FID, &pos);

		if (rc < 0) {	/* Some error. */
			printf("Walk failed, rc = %d\n", rc);
			goto cleanup_connection;
		}

		/*
		 * If partial walk (*pos != 0) then continue the walk from
		 * mid point with start_fid updated to current position
		 * FILE_FID. FILE_FID will then be reused for the result of
		 * the next call to walk.
		 */
		start_fid = FILE_FID;
	} while (*pos != 0);

	/* Open the file. */
	dprintf("%s : stat and open\n", __func__);
	rc = p9_stat(&file);
	if (rc != 0) {
		printf("Stat failed, rc = %d\n", rc);
		goto cleanup_file;
	}
	rc = p9_open(&file, 0x00); /* TODO find include for "read mode" */
	if (rc != 0) {
		printf("Open failed, rc = %d\n", rc);
		goto cleanup_file;
	}
	dprintf("%s : file opened, size %lld\n", __func__, file.length);

	/* Read the file contents to buffer. */
	while (offset < file.length) {
		dprintf("%s : read from offset %llu\n", __func__, offset);
		rc = p9_read(&file, buffer + offset,
				file.length - offset, offset);
		dprintf("%s : read done, length was %d\n", __func__, rc);
		if (rc < 0) {
			printf("Read failed, rc = %d\n", rc);
			goto cleanup_file;
		}
		if (rc == 0) {
			break;
		}
		offset += rc;
		rc = 0;
	}

	/* Cleanup and disconnect. */
cleanup_file:
	dprintf("%s : clunking file\n", __func__);
	p9_clunk(&connection, file.fid);

cleanup_connection:
	dprintf("%s : clunking connection\n", __func__);
	p9_clunk(&connection, connection.fid);


	dprintf("%s : complete, read %llu bytes\n", __func__, offset);
	return rc == 0 ? offset : rc;
}
