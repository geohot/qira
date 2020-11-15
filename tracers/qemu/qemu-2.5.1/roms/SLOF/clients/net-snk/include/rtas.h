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


#ifndef RTAS_H
#define RTAS_H

#include "of.h"

typedef struct dtime {
        unsigned int year;
        unsigned int month;
        unsigned int day;
        unsigned int hour;
        unsigned int minute;
        unsigned int second;
        unsigned int nano;
} dtime;

typedef void (*thread_t) (int);

int rtas_token(const char *);
int rtas_call(int, int, int, int *, ...);
void rtas_init(void);
int rtas_pci_config_read (long long, int, int, int, int);
int rtas_pci_config_write (long long, int, int, int, int, int);
int rtas_set_time_of_day(dtime *);
int rtas_get_time_of_day(dtime *);
int rtas_ibm_update_flash_64(long long, long long);
int rtas_ibm_update_flash_64_and_reboot(long long, long long);
int rtas_system_reboot(void);
int rtas_start_cpu (int, thread_t, int);
int rtas_stop_self (void);
int rtas_ibm_manage_flash(int);

#endif
