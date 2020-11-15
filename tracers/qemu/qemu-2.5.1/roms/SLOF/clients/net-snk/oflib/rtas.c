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
#include <stdarg.h>
#include <stdio.h>
#include <rtas.h>
#include <of.h>
#include <kernel.h>

typedef int rtas_arg_t;

typedef struct {
	int token;
	int nargs;
	int nret;
	rtas_arg_t args[16];
	rtas_arg_t *rets;	/* Pointer to return values in args[]. */
} rtas_args_t;

rtas_args_t rtas_args;

typedef struct {
	void *rtas_start;
	void *rtas_entry;
	int rtas_size;
	phandle_t dev;
} rtas_t;

extern rtas_t _rtas;
static int instantiate_rtas(void);
void rtas_call_entry(rtas_args_t *, void *, void *);

int
rtas_token(const char *service)
{
	int token;
	int retVal;
	if (_rtas.dev == 0)
		instantiate_rtas();

	retVal = of_getprop(_rtas.dev, service, &token, sizeof(token));
	if (retVal == -1) {
		token = 0;
	}
	return token;
}

int
rtas_call(int token, int nargs, int nret, int *outputs, ...)
{
	va_list list;
	int i;

	rtas_args.token = token;
	rtas_args.nargs = nargs;
	rtas_args.nret = nret;
	rtas_args.rets = (rtas_arg_t *) & (rtas_args.args[nargs]);
	va_start(list, outputs);
	for (i = 0; i < nargs; ++i) {
		rtas_args.args[i] = (rtas_arg_t) (va_arg(list, unsigned int));
	}
	va_end(list);

	for (i = 0; i < nret; ++i)
		rtas_args.rets[i] = 0;

	rtas_call_entry(&rtas_args, _rtas.rtas_start, _rtas.rtas_entry);
	if (nret > 0 && outputs != 0)
		for (i = 0; i < nret; i++)
			outputs[i] = rtas_args.rets[i];
#if 0
	printf("rtas call %x %x %x args: %x %x %x %x %x %x %x %x\n",
	       token, nargs, nret,
	       rtas_args.args[0],
	       rtas_args.args[1],
	       rtas_args.args[2],
	       rtas_args.args[3],
	       rtas_args.args[4], rtas_args.args[5], outputs[0], outputs[1]);
#endif
	return ((nret > 0) ? rtas_args.rets[0] : 0);
}

rtas_t _rtas;

static int
instantiate_rtas(void)
{
	long long *rtas_mem_space;
	ihandle_t ihandle;

	_rtas.dev = of_finddevice("/rtas");
	if ((long) _rtas.dev < 0) {
		printf("\nCould not open /rtas\n");
		return -1;
	}

	of_getprop(_rtas.dev, "rtas-size", &_rtas.rtas_size,
		   sizeof(_rtas.rtas_size));

	if (_rtas.rtas_size <= 0) {
		printf("\nSize of rtas (%x) too small to make sense\n",
		       _rtas.rtas_size);
		return -1;
	}

	rtas_mem_space = (long long *) malloc_aligned(_rtas.rtas_size, 0x100);

	if (!rtas_mem_space) {
		printf("\nFailed to allocated memory for RTAS\n");
		return -1;
	}

	ihandle = of_open("/rtas");

	if ((long) ihandle < 0) {
		printf("Could not open /rtas\n");
		return -1;
	}

	if ((long) (_rtas.rtas_entry = of_call_method_3("instantiate-rtas",
							ihandle,
							p32cast rtas_mem_space))
	    > 0) {
		_rtas.rtas_start = rtas_mem_space;
	} else {
		printf("instantiate-rtas failed\n");
		return -1;
	}
#if 0
	printf("\ninstantiate-rtas at %x size %x entry %x\n",
	       _rtas.rtas_start, _rtas.rtas_size, _rtas.rtas_entry);
#endif
	return 0;
}

static int read_pci_config_token = 0;
static int write_pci_config_token = 0;
static int ibm_read_pci_config_token = 0;
static int ibm_write_pci_config_token = 0;
static int get_time_of_day_token = 0;

void
rtas_init()
{
	int ret;
	ret = instantiate_rtas();
	if (ret)
		return;
	read_pci_config_token = rtas_token("read-pci-config");
	ibm_read_pci_config_token = rtas_token("ibm,read-pci-config");
	write_pci_config_token = rtas_token("write-pci-config");
	ibm_write_pci_config_token = rtas_token("ibm,write-pci-config");
	get_time_of_day_token = rtas_token("get-time-of-day");
}


int
rtas_pci_config_read(long long puid, int size, int bus, int devfn, int offset)
{
	int value[2];

	if (ibm_read_pci_config_token && puid) {
		rtas_call(ibm_read_pci_config_token, 4, 2, value,
			  bus << 16 | devfn << 8 | offset,
			  puid >> 32, puid & 0xffffffffULL, size);
	} else if (read_pci_config_token) {
		rtas_call(read_pci_config_token, 2, 2, value,
			  bus << 16 | devfn << 8 | offset, size);
	}

	return value[1];
}

int
rtas_pci_config_write(long long puid, int size, int bus, int devfn,
		      int offset, int value)
{
	int rc;

	if (ibm_write_pci_config_token && puid) {
		rtas_call(ibm_write_pci_config_token, 5, 1, &rc,
			  bus << 16 | devfn << 8 | offset,
			  puid >> 32, puid & 0xffffffffULL, size, value);
	} else
		rtas_call(write_pci_config_token, 3, 1, &rc,
			  bus << 16 | devfn << 8 | offset, size, value);

	return rc;
}

int
rtas_get_time_of_day(dtime * get)
{
	int rc = -1;
	unsigned int year;
	unsigned int month;
	unsigned int day;
	unsigned int hour;
	unsigned int minute;
	unsigned int second;
	unsigned int nano;

	if (get_time_of_day_token)
		rtas_call(get_time_of_day_token, 0, 8, &rc, &year, &month, &day,
			  &hour, &minute, &second, &nano);

	get->year = year;
	get->month = month;
	get->day = day;
	get->hour = hour;
	get->minute = minute;
	get->second = second;
	get->nano = nano;

	return rc;
}
