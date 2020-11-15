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

#ifndef __BMC_H
#define __BMC_H

void (*bmc_system_reboot) (void);
void (*bmc_power_off) (void);

short (*bmc_set_flashside) (short mode);
short (*bmc_get_flashside) (void);
int (*bmc_stop_bootwatchdog) (void);
int (*bmc_set_bootwatchdog) (unsigned short);

uint32_t(*bmc_read_vpd) (uint8_t * dst, uint32_t len, uint32_t offset);
uint32_t(*bmc_write_vpd) (uint8_t * src, uint32_t len, uint32_t offset);

uint32_t(*bmc_get_blade_descr) (uint8_t * dst, uint32_t maxlen, uint32_t * len);

#endif				/* __BMC_H */
