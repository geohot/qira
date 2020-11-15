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
#include <hw.h>
#include "rtas_board.h"

void
rtas_ibm_read_pci_config (rtas_args_t *rtas_args)
{
	int retVal = 0;
	uint64_t addr = ((uint64_t) rtas_args->args[1]) << 32;  // high 32 bits of PHB UID
	addr |= (rtas_args->args[2] & 0xFFFFFFFF); // low 32 bits of PHB UID
	addr |= (rtas_args->args[0] & 0x00FFFFFF); // bus, devfn, offset
	unsigned int size = rtas_args->args[3];

	/* Check for bus != 0  on PCI/PCI-X (PHB UID = 0xf2000000) */
	if (((addr & 0xf2000000) == 0xf2000000) && (addr & 0xff0000))
		addr += 0x1000000;

	if (size == 1)
		rtas_args->args[5] = load8_ci(addr);
	else if (size == 2)
		rtas_args->args[5] = bswap16_load(addr);
	else if (size == 4)
		rtas_args->args[5] = bswap32_load(addr);
	else
		retVal = -3;  /* Bad arguments */

	rtas_args->args[4] = retVal;
}

void
rtas_ibm_write_pci_config (rtas_args_t *rtas_args)
{
	int retVal = 0;
	uint64_t addr = ((uint64_t) rtas_args->args[1]) << 32;  // high 32 bits of PHB UID
	addr |= (rtas_args->args[2] & 0xFFFFFFFF); // low 32 bits of PHB UID
	addr |= (rtas_args->args[0] & 0x00FFFFFF); // bus, devfn, offset
	unsigned int size = rtas_args->args[3];

	addr |= 0xf2000000;

	/* Check for bus != 0  on PCI/PCI-X (PHB UID = 0xf2000000) */
	if (((addr & 0xf2000000) == 0xf2000000) && (addr & 0xff0000))
		addr += 0x1000000;

	if (size == 1)
		store8_ci(addr, rtas_args->args[4]);
	else if (size == 2)
		bswap16_store(addr, rtas_args->args[4]);
	else if (size == 4)
		bswap32_store(addr, rtas_args->args[4]);
	else
		retVal = -3;  /* Bad arguments */

	rtas_args->args[5] = retVal;
}

void
rtas_read_pci_config (rtas_args_t *rtas_args)
{
	int retVal = 0;
	unsigned long addr = rtas_args->args[0];
	unsigned int size = rtas_args->args[1];
	addr |= 0xf2000000;

	/* Check for bus != 0 */
	if (addr & 0xff0000)
		addr += 0x1000000;

	if (size == 1)
		rtas_args->args[3] = load8_ci(addr);
	else if (size == 2)
		rtas_args->args[3] = bswap16_load(addr);
	else if (size == 4)
		rtas_args->args[3] = bswap32_load(addr);
	else
		retVal = -3;  /* Bad arguments */

	rtas_args->args[2] = retVal;
}

void
rtas_write_pci_config (rtas_args_t *rtas_args)
{
	int retVal = 0;
	unsigned long addr = rtas_args->args[0];
	unsigned int size = rtas_args->args[1];

	addr |= 0xf2000000;

	/* Check for bus != 0 */
	if (addr & 0xff0000)
		addr += 0x1000000;

	if (size == 1)
		store8_ci(addr, rtas_args->args[2]);
	else if (size == 2)
		bswap16_store(addr, rtas_args->args[2]);
	else if (size == 4)
		bswap32_store(addr, rtas_args->args[2]);
	else
		retVal = -3;  /* Bad arguments */

	rtas_args->args[3] = retVal;
}
