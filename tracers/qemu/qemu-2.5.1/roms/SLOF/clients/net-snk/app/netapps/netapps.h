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

#ifndef _NETAPPS_H_
#define _NETAPPS_H_

#include <netlib/tftp.h>

#define F_IPV4	4
#define F_IPV6	6

int netboot(int argc, char *argv[]);
int netsave(int argc, char *argv[]);
int netflash(int argc, char *argv[]);
int bcmflash(int argc, char *argv[]);
int mac_sync(int argc, char *argv[]);
int net_eeprom_version( void );
int ping(int argc, char *argv[]);
int dhcp(char *ret_buffer, filename_ip_t * fn_ip, unsigned int retries, int flags);

#endif
