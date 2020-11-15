/*
 *   Creation Date: <2010/06/25 20:00:00 mcayland>
 *   Time-stamp: <2010/06/25 20:00:00 mcayland>
 *
 *	<load.c>
 *
 *	C implementation of load
 *
 *   Copyright (C) 2010 Mark Cave-Ayland (mark.cave-ayland@siriusit.co.uk)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/bindings.h"
#include "libopenbios/sys_info.h"
#include "libopenbios/load.h"

#ifdef CONFIG_LOADER_ELF
#include "libopenbios/elf_load.h"
#endif

#ifdef CONFIG_LOADER_AOUT
#include "libopenbios/aout_load.h"
#endif

#ifdef CONFIG_LOADER_FCODE
#include "libopenbios/fcode_load.h"
#endif

#ifdef CONFIG_LOADER_FORTH
#include "libopenbios/forth_load.h"
#endif

#ifdef CONFIG_LOADER_BOOTCODE
#include "libopenbios/bootcode_load.h"
#endif


struct sys_info sys_info;
void *elf_boot_notes = NULL;

/* ( addr -- size ) */

void load(ihandle_t dev)
{
	/* Invoke the loaders on the specified device */
	char *param;
	ucell valid;

	/* TODO: Currently the internal loader APIs use load-base directly, so
	   drop the address */
	POP();

#ifdef CONFIG_LOADER_ELF

	/* Grab the boot arguments */
	push_str("bootargs");
	push_str("/chosen");
	fword("(find-dev)");
	POP();
	fword("get-package-property");
	POP();
	param = pop_fstr_copy();

	elf_load(&sys_info, dev, param, &elf_boot_notes);
        feval("state-valid @");
        valid = POP();
        if (valid) {
                feval("saved-program-state >sps.file-size @");
                return;
        }
#endif

#ifdef CONFIG_LOADER_AOUT
	aout_load(&sys_info, dev);
        feval("state-valid @");
        valid = POP();
        if (valid) {
                feval("saved-program-state >sps.file-size @");
                return;
        }
#endif

#ifdef CONFIG_LOADER_FCODE
	fcode_load(dev);
        feval("state-valid @");
        valid = POP();
        if (valid) {
                feval("saved-program-state >sps.file-size @");
                return;
        }
#endif

#ifdef CONFIG_LOADER_FORTH
	forth_load(dev);
        feval("state-valid @");
        valid = POP();
        if (valid) {
                feval("saved-program-state >sps.file-size @");
                return;
        }
#endif

#ifdef CONFIG_LOADER_BOOTCODE
	/* Check for a "raw" %BOOT bootcode payload */
	bootcode_load(dev);
        feval("state-valid @");
        valid = POP();
        if (valid) {
                feval("saved-program-state >sps.file-size @");
                return;
        }
#endif

        /* Didn't load anything, so return zero size */
        PUSH(0);
}
