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

#ifndef VIRTIO_9P_H_
#define VIRTIO_9P_H_

#include <stdint.h>

#include "virtio.h"

#if 0
typedef struct {
    uint16_t tag_lenth;
    char tag[0];
} virtio_9p_config_t;
#endif
int virtio_9p_init(struct virtio_device *dev, void *tx_buf, void *rx_buf,
		   int buf_size);
void virtio_9p_shutdown(struct virtio_device *dev);
int virtio_9p_load(struct virtio_device *dev, const char *file_name, uint8_t *buffer);


#endif /* VIRTIO_9P_H_ */
