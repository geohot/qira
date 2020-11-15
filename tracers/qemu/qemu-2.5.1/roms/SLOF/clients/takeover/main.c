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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <of.h>
#include <pci.h>
#include <cpu.h>
#include <unistd.h>
#include <takeover.h>

extern void call_client_interface(of_arg_t *);
extern void m_sync(void);

int callback(int argc, char *argv[]);

#define boot_rom_bin_start _binary_______boot_rom_bin_start
#define boot_rom_bin_end   _binary_______boot_rom_bin_end

extern char boot_rom_bin_start;
extern char boot_rom_bin_end;

#if defined(__GNUC__)
# define UNUSED __attribute__((unused))
#else
# define UNUSED
#endif

void *
sbrk(int incr)
{
	return (void *) -1;
}

static void
doWait(void)
{
	static const char *wheel = "|/-\\";
	static int i = 0;
	volatile int dly = 0xf0000;
	while (dly--)
		asm volatile (" nop ");
	printf("\b%c", wheel[i++]);
	i &= 0x3;
}

static void
quiesce(void)
{
	of_arg_t arg = {
		p32cast "quiesce",
		0, 0,
	};
	call_client_interface(&arg);
}

static int
startCpu(int num, int addr, int reg)
{
	of_arg_t arg = {
		p32cast "start-cpu",
		3, 0,
		{num, addr, reg}
	};
	call_client_interface(&arg);
	return arg.args[3];
}

volatile unsigned long slaveQuitt;
int takeoverFlag;

void
main(int argc, char *argv[])
{
	phandle_t cpus;
	phandle_t cpu;
	unsigned long slaveMask;
	extern int slaveLoop[];
	extern int slaveLoopNoTakeover[];
	int index = 0;
	int delay = 100;
	unsigned long reg;
	unsigned long msr;

	asm volatile ("mfmsr %0":"=r" (msr));
	if (msr & 0x1000000000000000)
		takeoverFlag = 0;
	else
		takeoverFlag = 1;

	cpus = of_finddevice("/cpus");
	cpu = of_child(cpus);
	slaveMask = 0;
	while (cpu) {
		char devType[100];
		*devType = '\0';
		of_getprop(cpu, "device_type", devType, sizeof(devType));
		if (strcmp(devType, "cpu") == 0) {
			of_getprop(cpu, "reg", &reg, sizeof(reg));
			if (index) {
				printf("\r\n takeover on cpu%d (%x, %lx) ", index,
				       cpu, reg);
				slaveQuitt = -1;
				if (takeoverFlag)
					startCpu(cpu, (int)(unsigned long)slaveLoop, index);
				else
					startCpu(cpu, (int)(unsigned long)slaveLoopNoTakeover,
						 index);
				slaveMask |= 0x1 << index;
				delay = 100;
				while (delay-- && slaveQuitt)
					doWait();
			}
			index++;
		}
		cpu = of_peer(cpu);
	}


	printf("\r\n takeover on master cpu  ");
	quiesce();

	delay = 5;
	while (delay--)
		doWait();
	if (takeoverFlag)
		takeover();

	memcpy((void*)TAKEOVERBASEADDRESS, &boot_rom_bin_start, &boot_rom_bin_end - &boot_rom_bin_start);
	flush_cache((void *)TAKEOVERBASEADDRESS, &boot_rom_bin_end - &boot_rom_bin_start);
	index = 0;

	while (slaveMask) {
		m_sync();
		unsigned long shifter = 0x1 << index;
		if (shifter & slaveMask) {
			slaveQuitt = index;
			while (slaveQuitt)
				m_sync();
			slaveMask &= ~shifter;
		}
		index++;
	}

	asm volatile(" mtctr %0 ; bctr " : : "r" (TAKEOVERBASEADDRESS+0x180) );
}

int
callback(int argc, char *argv[])
{
	/* Dummy, only for takeover */
	return (0);
}
