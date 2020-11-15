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

#include <kernel.h>
#include "time.h"

int get_msec_ticks()
{
        return tb_freq/1000;
}

int get_sec_ticks()
{
        return tb_freq;
}

void set_timer(int val)
{
        asm volatile ("mtdec %0"::"r" (val));
}

int get_timer()
{
        int val;
        asm volatile ("mfdec %0":"=r" (val));
        return val;
}
