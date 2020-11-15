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
#include "kernel.h"

//*******************************************************************
// variable "tb_freq" contains the frequency in Hz
// and is read from the device tree (setup by LLFW) in "init.c"
uint64_t tb_freq;

//-------------------------------------------------------------------
// Read the current timebase
uint64_t get_time(void)
{
    uint64_t act;

    __asm__ __volatile__( 
        "0:     mftbu   %0 ;\
                mftbl   %%r0 ; \
                mftbu   %%r4 ; \
                cmpw    %0,%%r4 ; \
                bne     0b; \
                sldi    %0,%0,32; \
                or      %0,%0,%%r0"
        : "=r"(act)
        : /* no inputs */
        : "r0", "r4");
    return act;
}
