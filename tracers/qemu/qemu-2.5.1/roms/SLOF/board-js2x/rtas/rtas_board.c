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
#include "rtas_board.h"
#include <bmc.h>
#include <rtas_i2c_bmc.h>
#include <rtas_ipmi_bmc.h>
#include "libipmi.h"
#include <hw.h>

void io_init(void);
short reg_get_flashside(void);
void rtas_init(void);

typedef struct {
	uint64_t r3;
	uint64_t addr;
	volatile uint64_t id;
} slave_t;

volatile slave_t rtas_slave_interface;

static void
rtas_slave_loop(volatile slave_t * pIface)
{
	uint64_t mask = pIface->id;
	pIface->id = 0;
	while (pIface->id != mask); {
		int dly = 0x1000;
		while (dly--);
	}
	pIface->id = 0;
	asm volatile ("  mr 3,%0 ; mtctr %1 ; bctr "
			::"r"(pIface->r3), "r"(pIface->addr));
}

void
rtas_fetch_slaves(rtas_args_t * pArgs)
{
	int retVal = 0;
	int idx = 0;
	uint32_t mask = pArgs->args[0] & 0xFFFFFFFE;
	uint64_t *rtas_slave_loop_ptr = (uint64_t *)rtas_slave_loop;
	while (mask) {
		if (mask & 0x1) {
			rtas_slave_interface.id = idx | 0x100;
			*(int *) 0x3fc0 = (int)(unsigned long) &rtas_slave_interface;	// r3
			*(int *) 0x3f80 = *rtas_slave_loop_ptr;		// addr
			*(int *) 0x3fa0 = idx | 0x100;	// pid
			while (rtas_slave_interface.id);
		}
		mask >>= 1;
		idx++;
	}
	pArgs->args[pArgs->nargs] = retVal;
}

void
rtas_start_cpu(rtas_args_t * pArgs)
{
	int retVal = 0;
	int idx = pArgs->args[0];	// pid
	rtas_slave_interface.r3 = pArgs->args[2];	// r3
	rtas_slave_interface.addr = pArgs->args[1];	// addr
	asm(" sync ");
	rtas_slave_interface.id = idx | 0x100;	// pid
	while (rtas_slave_interface.id);
	pArgs->args[pArgs->nargs] = retVal;
}

void
rtas_read_vpd(rtas_args_t * pArgs)
{
	pArgs->args[pArgs->nargs] =
	    bmc_read_vpd((uint8_t *) (uint64_t) pArgs->args[2], pArgs->args[1],
			 pArgs->args[0]);
}

void
rtas_write_vpd(rtas_args_t * pArgs)
{
	pArgs->args[pArgs->nargs] =
	    bmc_write_vpd((uint8_t *) (uint64_t) pArgs->args[2], pArgs->args[1],
			  pArgs->args[0]);
}

void
rtas_set_indicator(rtas_args_t * pArgs)
{
	pArgs->args[pArgs->nargs] = -1;
}

void
rtas_event_scan(rtas_args_t * pArgs)
{
	pArgs->args[pArgs->nargs] = -1;
}

void
rtas_stop_bootwatchdog(rtas_args_t * pArgs)
{
	pArgs->args[pArgs->nargs] = bmc_stop_bootwatchdog();
}

void
rtas_set_bootwatchdog(rtas_args_t * pArgs)
{
	pArgs->args[pArgs->nargs] = bmc_set_bootwatchdog(pArgs->args[0]);
}

void
rtas_set_flashside(rtas_args_t * pArgs)
{
	pArgs->args[pArgs->nargs] = bmc_set_flashside(pArgs->args[0]);
}

void
rtas_get_flashside(rtas_args_t * pArgs)
{
	int retVal = bmc_get_flashside();
	pArgs->args[pArgs->nargs] = retVal;
}

void
rtas_flash_test(rtas_args_t * pArgs)
{
	pArgs->args[pArgs->nargs] = -1;
}

void
rtas_system_reboot(rtas_args_t * pArgs)
{
	bmc_system_reboot();
	pArgs->args[pArgs->nargs] = -1;
}

void
rtas_power_off(rtas_args_t * pArgs)
{
	bmc_power_off();
	pArgs->args[pArgs->nargs] = -1;
}

void
rtas_get_blade_descr(rtas_args_t * pArgs)
{
	uint8_t *buffer = (uint8_t *) (uint64_t) pArgs->args[0];
	uint32_t maxlen = pArgs->args[1];
	uint32_t retlen = 0;
	uint32_t retval = bmc_get_blade_descr(buffer, maxlen, &retlen);
	pArgs->args[pArgs->nargs] = retlen;
	pArgs->args[pArgs->nargs + 1] = retval;
}

// for JS20 cannot read blade descr
static uint32_t
dummy_get_blade_descr(uint8_t *dst, uint32_t maxlen, uint32_t *len)
{
	// to not have a warning we need to do _something_ with *dst and maxlen...
	*dst = *dst;
	maxlen = maxlen;
	*len = 0;
	return -1;
}

/* read flashside from register */
short
reg_get_flashside(void)
{
	short retVal;
	uint8_t val = load8_ci(0xf4003fe3);
	if (val & 0x80) {
		// temp
		retVal = 1;
	} else {
		// perm
		retVal = 0;
	}
	return retVal;
}

void
rtas_init(void)
{
	io_init();
	if (u4Flag) {
		bmc_system_reboot = ipmi_system_reboot;
		bmc_power_off = ipmi_power_off;
		bmc_set_flashside = ipmi_set_flashside;
		bmc_get_flashside = reg_get_flashside;
		bmc_stop_bootwatchdog = ipmi_oem_stop_bootwatchdog;
		bmc_set_bootwatchdog = ipmi_oem_set_bootwatchdog;
		bmc_read_vpd = ipmi_oem_read_vpd;
		bmc_write_vpd = ipmi_oem_write_vpd;
		bmc_get_blade_descr = ipmi_oem_get_blade_descr;
	} else {
		bmc_system_reboot = i2c_system_reboot;
		bmc_power_off = i2c_power_off;
		bmc_set_flashside = i2c_set_flashside;
		bmc_get_flashside = i2c_get_flashside;
		bmc_stop_bootwatchdog = i2c_stop_bootwatchdog;
		bmc_set_bootwatchdog = i2c_set_bootwatchdog;
		bmc_read_vpd = i2c_read_vpd;
		bmc_write_vpd = i2c_write_vpd;
		bmc_get_blade_descr = dummy_get_blade_descr;
	}
}
