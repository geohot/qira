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

#ifndef __RTAS_BOARD_H
#define __RTAS_BOARD_H

#include <stddef.h>

extern volatile unsigned char u4Flag;

void rtas_ibm_read_pci_config(rtas_args_t * pArgs);
void rtas_ibm_write_pci_config(rtas_args_t * pArgs);
void rtas_read_pci_config(rtas_args_t * pArgs);
void rtas_write_pci_config(rtas_args_t * pArgs);
void rtas_system_reboot(rtas_args_t * pArgs);
void rtas_power_off(rtas_args_t * pArgs);
void rtas_display_character(rtas_args_t * pArgs);
void rtas_flash_test(rtas_args_t * pArgs);
void rtas_ibm_update_flash_64_and_reboot(rtas_args_t * pArgs);
void rtas_set_indicator(rtas_args_t * pArgs);
void rtas_event_scan(rtas_args_t * pArgs);
void rtas_ibm_manage_flash_image(rtas_args_t * pArgs);
void rtas_ibm_validate_flash_image(rtas_args_t * pArgs);
void rtas_update_flash(rtas_args_t * pArgs);
void rtas_set_flashside(rtas_args_t * pArgs);
void rtas_get_flashside(rtas_args_t * pArgs);
void rtas_dump_flash(rtas_args_t * pArgs);
void rtas_start_cpu(rtas_args_t * pArgs);
void rtas_read_vpd(rtas_args_t * pArgs);
void rtas_write_vpd(rtas_args_t * pArgs);
void rtas_fetch_slaves(rtas_args_t * pArgs);
void rtas_stop_bootwatchdog(rtas_args_t * pArgs);
void rtas_get_blade_descr(rtas_args_t * pArgs);
void rtas_set_bootwatchdog(rtas_args_t * pArgs);

#endif				/* __RTAS_BOARD_H */
