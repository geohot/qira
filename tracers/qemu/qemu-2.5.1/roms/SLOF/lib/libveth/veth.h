/******************************************************************************
 * Copyright (c) 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 * IBM Corporation - initial implementation
 ******************************************************************************/

#ifndef _VETH_H
#define _VETH_H

#include <stdint.h>
#include <netdriver.h>

extern net_driver_t *libveth_open(char *mac_addr, int mac_len, char *reg, int reg_len);
extern void libveth_close(net_driver_t *driver);
extern int libveth_read(char *buf, int len, net_driver_t *driver);
extern int libveth_write(char *buf, int len, net_driver_t *driver);

#endif
