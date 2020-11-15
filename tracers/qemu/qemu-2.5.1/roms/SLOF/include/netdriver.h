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

#ifndef _NETDRIVER_H
#define _NETDRIVER_H

#include <stdint.h>

typedef struct net_driver {
	uint8_t mac_addr[6];
	uint32_t reg;
	int running;
} net_driver_t;

#endif
