/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef __RTAS_I2C_BMC_H
#define __RTAS_I2C_BMC_H

#include <stddef.h>

void i2c_system_reboot (void);
void i2c_power_off (void);
short i2c_set_flashside (short mode);
short i2c_get_flashside (void);
int i2c_stop_bootwatchdog (void);
uint32_t i2c_read_vpd (uint8_t *dst, uint32_t len, uint32_t offset);
uint32_t i2c_write_vpd (uint8_t *src, uint32_t len, uint32_t offset);
int i2c_set_bootwatchdog(unsigned short seconds);

#endif		/* __RTAS_I2C_BMC_H */
