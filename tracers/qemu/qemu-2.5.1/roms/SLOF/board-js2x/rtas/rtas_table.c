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

#include <stdint.h>
#include <rtas.h>
#include "rtas_table.h"
#include "rtas_board.h"

const rtas_funcdescr_t rtas_func_tab[] = {
	{"ibm,read-pci-config", rtas_ibm_read_pci_config, 0},
	{"ibm,write-pci-config", rtas_ibm_write_pci_config, 0},
	{"system-reboot", rtas_system_reboot, 0},
	{"power-off", rtas_power_off, 0},
	{"set-indicator", rtas_set_indicator, 0},
	{"rtas-flash-test", rtas_flash_test, RTAS_TBLFLG_INTERNAL},
	{"ibm,update-flash-64-and-reboot", rtas_ibm_update_flash_64_and_reboot, 0},
	{"display-character", rtas_display_character, 0},
	{"event-scan", rtas_event_scan, 0},
	{"ibm,manage-flash-image", rtas_ibm_manage_flash_image, 0},
	{"ibm,validate-flash-image", rtas_ibm_validate_flash_image, 0},
	{"ibm,update-flash-64", rtas_update_flash, 0},
	{"rtas-set-flashside", rtas_set_flashside, 0},
	{"rtas-get-flashside", rtas_get_flashside, 0},
	{"rtas-dump-flash", rtas_dump_flash, RTAS_TBLFLG_INTERNAL},
	{"start-cpu", rtas_start_cpu, 0},
	{"msg-read-vpd", rtas_read_vpd, RTAS_TBLFLG_INTERNAL},
	{"msg-write-vpd", rtas_write_vpd, RTAS_TBLFLG_INTERNAL},
	{"read-pci-config", rtas_read_pci_config, 0},
	{"write-pci-config", rtas_write_pci_config, 0},
	{"rtas-fetch-slaves", rtas_fetch_slaves, RTAS_TBLFLG_INTERNAL},
	{"rtas-stop-bootwatchdog", rtas_stop_bootwatchdog, RTAS_TBLFLG_INTERNAL},
	{"rtas-set-bootwatchdog", rtas_set_bootwatchdog, RTAS_TBLFLG_INTERNAL},
	{"rtas-get-blade-descr", rtas_get_blade_descr, RTAS_TBLFLG_INTERNAL},
};

const int rtas_func_tab_size = sizeof(rtas_func_tab) / sizeof(rtas_func_tab[0]);
