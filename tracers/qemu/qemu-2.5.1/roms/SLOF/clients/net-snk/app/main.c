/******************************************************************************
 * Copyright (c) 2004, 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <string.h>
#include <stdio.h>
#include <of.h>
#include <netapps/netapps.h>
#include <libbootmsg.h>

#ifdef SNK_BIOSEMU_APPS
#include "biosemu/biosemu.h"
#include "biosemu/vbe.h"
#endif

extern void _callback_entry(void);
int callback(int argc, char *argv[]);


int
main(int argc, char *argv[])
{
	int i;
	of_set_callback((void *) &_callback_entry);

	if (strcmp(argv[0], "netboot") == 0 && argc >= 5)
		return netboot(argc, argv);
	if (strcmp(argv[0], "ping") == 0)
		return ping(argc, argv);
#ifdef SNK_BIOSEMU_APPS
	// BIOS Emulator applications
	if (strcmp(argv[0], "biosemu") == 0)
		return biosemu(argc, argv);
	if (strcmp(argv[0], "get_vbe_info") == 0)
		return vbe_get_info(argc, argv);
#endif

	printf("Unknown client application called\n");
	for (i = 0; i < argc; i++)
		printf("argv[%d] %s\n", i, argv[i]);

	return -1;
}

int
callback(int argc, char *argv[])
{
	int i;

	printf("\n");

	/*
	 * Register your application's callback handler here, similar to
	 * the way you would register an application.
	 * Please note that callback functions can be called safely only after
	 * your application has called of_yield(). If you return or exit() from
	 * your client application, the callback can no longer be used.
	 */
#if 0
	if (strcmp(argv[0], "example") == 0)
		return example(argc, argv);
#endif

	printf("No such callback function\n");
	for (i = 0; i < argc; i++)
		printf("argv[%d] %s\n", i, argv[i]);

	return (-1);
}
