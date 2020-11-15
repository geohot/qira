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

#ifndef __LIBIPMI_H
#define __LIBIPMI_H

#include <stdint.h>

extern int ipmi_kcs_cmd(uint8_t *, uint8_t *, uint32_t, uint32_t *);

extern void ipmi_system_reboot(void);
extern void ipmi_power_off(void);
extern int ipmi_set_sensor(const int sensor, int number_of_args, ...);

extern int ipmi_oem_stop_bootwatchdog(void);
extern int ipmi_oem_set_bootwatchdog(uint16_t seconds);
extern int ipmi_oem_reset_bootwatchdog(void);
extern int ipmi_oem_led_set(int type, int instance, int state);
extern uint32_t ipmi_oem_read_vpd(uint8_t *dst, uint32_t len, uint32_t offset);
extern uint32_t ipmi_oem_write_vpd(uint8_t *src, uint32_t len, uint32_t offset);
extern uint32_t ipmi_oem_get_blade_descr(uint8_t *dst, uint32_t maxlen, uint32_t *len);
extern int ipmi_oem_bios2sp(int swid, int type, char *data, int len);

#endif
