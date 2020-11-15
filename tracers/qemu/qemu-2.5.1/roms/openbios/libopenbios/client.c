/*
 *   Creation Date: <2003/11/25 14:29:08 samuel>
 *   Time-stamp: <2004/03/27 01:13:53 samuel>
 *
 *	<client.c>
 *
 *	OpenFirmware client interface
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/of.h"

/* Uncomment to enable debug printout of client interface calls */
//#define DEBUG_CIF
//#define DUMP_IO

/* OF client interface. r3 points to the argument array. On return,
 * r3 should contain 0==true or -1==false. r4-r12,cr0,cr1 may
 * be modified freely.
 *
 * -1 should only be returned if the control transfer to OF fails
 * (it doesn't) or if the function is unimplemented.
 */

#define PROM_MAX_ARGS	10
typedef struct prom_args {
    prom_uarg_t service;
    prom_arg_t  nargs;
    prom_arg_t  nret;
    prom_uarg_t args[PROM_MAX_ARGS];
} __attribute__((packed)) prom_args_t;

static inline const char *
arg2pointer(prom_uarg_t value)
{
    return (char*)(uintptr_t)value;
}

static inline const char *
get_service(prom_args_t *pb)
{
    return arg2pointer(pb->service);
}

#ifdef DEBUG_CIF
static void memdump(const char *mem, unsigned long size)
{
	int i;
	
	if (size == (unsigned long) -1)
		return;

	for (i = 0; i < size; i += 16) {
		int j;

		printk("0x%08lx ", (unsigned long)mem + i);

		for (j = 0; j < 16 && i + j < size; j++)
			printk(" %02x", *(unsigned char*)(mem + i + j));

		for ( ; j < 16; j++)
			printk(" __");

		printk("  ");

		for (j = 0; j < 16 && i + j < size; j++) {
			unsigned char c = *(mem + i + j);
			if (isprint(c))
				printk("%c", c);
			else
				printk(".");
		}
		printk("\n");
	}
}

static void dump_service(prom_args_t *pb)
{
	int i;
	const char *service = get_service(pb);
	if (strcmp(service, "test") == 0) {
		printk("test(\"%s\") = ", arg2pointer(pb->args[0]));
	} else if (strcmp(service, "peer") == 0) {
		printk("peer(0x" FMT_prom_uargx ") = ", pb->args[0]);
	} else if (strcmp(service, "child") == 0) {
		printk("child(0x" FMT_prom_uargx ") = ", pb->args[0]);
	} else if (strcmp(service, "parent") == 0) {
		printk("parent(0x" FMT_prom_uargx ") = ", pb->args[0]);
	} else if (strcmp(service, "instance-to-package") == 0) {
		printk("instance-to-package(0x" FMT_prom_uargx ") = ", pb->args[0]);
	} else if (strcmp(service, "getproplen") == 0) {
		printk("getproplen(0x" FMT_prom_uargx ", \"%s\") = ",
			pb->args[0], arg2pointer(pb->args[1]));
	} else if (strcmp(service, "getprop") == 0) {
		printk("getprop(0x" FMT_prom_uargx ", \"%s\", 0x" FMT_prom_uargx ", " FMT_prom_arg ") = ",
			pb->args[0], arg2pointer(pb->args[1]),
			pb->args[2], pb->args[3]);
	} else if (strcmp(service, "nextprop") == 0) {
		printk("nextprop(0x" FMT_prom_uargx ", \"%s\", 0x" FMT_prom_uargx ") = ",
			pb->args[0], arg2pointer(pb->args[1]), pb->args[2]);
	} else if (strcmp(service, "setprop") == 0) {
		printk("setprop(0x" FMT_prom_uargx ", \"%s\", 0x" FMT_prom_uargx ", " FMT_prom_arg ")\n",
			pb->args[0], arg2pointer(pb->args[1]),
			pb->args[2], pb->args[3]);
		memdump(arg2pointer(pb->args[2]), pb->args[3]);
		printk(" = ");
	} else if (strcmp(service, "canon") == 0) {
		printk("canon(\"%s\", 0x" FMT_prom_uargx ", " FMT_prom_arg ")\n",
			arg2pointer(pb->args[0]), pb->args[1], pb->args[2]);
	} else if (strcmp(service, "finddevice") == 0) {
		printk("finddevice(\"%s\") = ", arg2pointer(pb->args[0]));
	} else if (strcmp(service, "instance-to-path") == 0) {
		printk("instance-to-path(0x" FMT_prom_uargx ", 0x" FMT_prom_uargx ", " FMT_prom_arg ") = ",
			pb->args[0], pb->args[1], pb->args[2]);
	} else if (strcmp(service, "package-to-path") == 0) {
		printk("package-to-path(0x" FMT_prom_uargx ", 0x" FMT_prom_uargx ", " FMT_prom_arg ") = ",
			pb->args[0], pb->args[1], pb->args[2]);
	} else if (strcmp(service, "open") == 0) {
		printk("open(\"%s\") = ", arg2pointer(pb->args[0]));
	} else if (strcmp(service, "close") == 0) {
		printk("close(0x" FMT_prom_uargx ")\n", pb->args[0]);
	} else if (strcmp(service, "read") == 0) {
#ifdef DUMP_IO
		printk("read(0x" FMT_prom_uargx ", 0x" FMT_prom_uargx ", " FMT_prom_arg ") = ",
			pb->args[0], pb->args[1], pb->args[2]);
#endif
	} else if (strcmp(service, "write") == 0) {
#ifdef DUMP_IO
		printk("write(0x" FMT_prom_uargx ", 0x" FMT_prom_uargx ", " FMT_prom_arg ")\n",
			pb->args[0], pb->args[1], pb->args[2]);
		memdump(arg2pointer(pb->args[1]), pb->args[2]);
		printk(" = ");
#endif
	} else if (strcmp(service, "seek") == 0) {
#ifdef DUMP_IO
		printk("seek(0x" FMT_prom_uargx ", 0x" FMT_prom_uargx ", 0x" FMT_prom_uargx ") = ",
			pb->args[0], pb->args[1], pb->args[2]);
#endif
	} else if (strcmp(service, "claim") == 0) {
		printk("claim(0x" FMT_prom_uargx ", " FMT_prom_arg ", " FMT_prom_arg ") = ",
			pb->args[0], pb->args[1], pb->args[2]);
	} else if (strcmp(service, "release") == 0) {
		printk("release(0x" FMT_prom_uargx ", " FMT_prom_arg ")\n",
			pb->args[0], pb->args[1]);
	} else if (strcmp(service, "boot") == 0) {
		printk("boot \"%s\"\n", arg2pointer(pb->args[0]));
	} else if (strcmp(service, "enter") == 0) {
		printk("enter()\n");
	} else if (strcmp(service, "exit") == 0) {
		printk("exit()\n");
	} else if (strcmp(service, "test-method") == 0) {
		printk("test-method(0x" FMT_prom_uargx ", \"%s\") = ",
			pb->args[0], arg2pointer(pb->args[1]));
	} else {
		printk("of_client_interface: %s", service);
		for( i = 0; i < pb->nargs; i++ )
			printk(" " FMT_prom_uargx, pb->args[i]);
		printk("\n");
	}
}

static void dump_return(prom_args_t *pb)
{
	int i;
	const char *service = get_service(pb);
	if (strcmp(service, "test") == 0) {
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "peer") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "child") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "parent") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "instance-to-package") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "getproplen") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "getprop") == 0) {
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
		if ((prom_arg_t)pb->args[pb->nargs] != -1)
			memdump(arg2pointer(pb->args[2]), MIN(pb->args[3], pb->args[pb->nargs]));
	} else if (strcmp(service, "nextprop") == 0) {
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
		memdump(arg2pointer(pb->args[2]), 32);
	} else if (strcmp(service, "setprop") == 0) {
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "canon") == 0) {
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
		memdump(arg2pointer(pb->args[1]), pb->args[pb->nargs]);
	} else if (strcmp(service, "finddevice") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "instance-to-path") == 0) {
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
		memdump(arg2pointer(pb->args[1]), pb->args[pb->nargs]);
	} else if (strcmp(service, "package-to-path") == 0) {
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
		memdump(arg2pointer(pb->args[1]), pb->args[pb->nargs]);
	} else if (strcmp(service, "open") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "close") == 0) {
		/* do nothing */
	} else if (strcmp(service, "read") == 0) {
#ifdef DUMP_IO
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
		memdump(arg2pointer(pb->args[1]), pb->args[pb->nargs]);
#endif
	} else if (strcmp(service, "write") == 0) {
#ifdef DUMP_IO
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
#endif
	} else if (strcmp(service, "seek") == 0) {
#ifdef DUMP_IO
		printk(FMT_prom_arg "\n", pb->args[pb->nargs]);
#endif
	} else if (strcmp(service, "claim") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else if (strcmp(service, "release") == 0) {
		/* do nothing */
	} else if (strcmp(service, "boot") == 0) {
		/* do nothing */
	} else if (strcmp(service, "enter") == 0) {
		/* do nothing */
	} else if (strcmp(service, "exit") == 0) {
		/* do nothing */
	} else if (strcmp(service, "test-method") == 0) {
		printk("0x" FMT_prom_uargx "\n", pb->args[pb->nargs]);
	} else {
		printk("of_client_interface return:");
		for (i = 0; i < pb->nret; i++) {
			printk(" " FMT_prom_uargx, pb->args[pb->nargs + i]);
		}
		printk("\n");
	}
}
#endif

/* call-method, interpret */
static int
handle_calls(prom_args_t *pb)
{
	int i, j, dstacksave;
	ucell val;

#ifdef DEBUG_CIF
	printk("%s %s ([" FMT_prom_arg "] -- [" FMT_prom_arg "])\n",
		get_service(pb), arg2pointer(pb->args[0]), pb->nargs, pb->nret);
#endif

	dstacksave = dstackcnt;
	for (i = pb->nargs - 1; i >= 0; i--)
		PUSH(pb->args[i]);

	push_str(get_service(pb));
	fword("client-call-iface");

	/* Ignore client-call-iface return */
	POP();

	/* If the catch result is non-zero, restore stack and exit */
	val = POP();
	if (val) {
		printk("%s %s failed with error " FMT_ucellx "\n", get_service(pb), arg2pointer(pb->args[0]), val);
		dstackcnt = dstacksave;
		return 0;
	}

	/* Store catch result */
	pb->args[pb->nargs] = val;
	
	j = dstackcnt;
	for (i = 1; i < pb->nret; i++, j--) {
                if (dstackcnt > dstacksave) {
			pb->args[pb->nargs + i] = POP();
		}
	}

#ifdef DEBUG_CIF
	/* useful for debug but not necessarily an error */
	if (j != dstacksave) {
		printk("%s '%s': possible argument error (" FMT_prom_arg "--" FMT_prom_arg ") got %d\n",
			get_service(pb), arg2pointer(pb->args[0]),
			pb->nargs - 2, pb->nret, j - dstacksave);
	}

	printk("handle_calls return:");
	for (i = 0; i < pb->nret; i++) {
		printk(" " FMT_prom_uargx, pb->args[pb->nargs + i]);
	}
	printk("\n");
#endif

	dstackcnt = dstacksave;
	return 0;
}

int
of_client_interface(int *params)
{
	prom_args_t *pb = (prom_args_t*)params;
	ucell val;
	int i, j, dstacksave;

	if (pb->nargs < 0 || pb->nret < 0 ||
            pb->nargs + pb->nret > PROM_MAX_ARGS)
		return -1;

#ifdef DEBUG_CIF
	dump_service(pb);
#endif

	/* call-method exceptions are special */
	if (!strcmp("call-method", get_service(pb)) || !strcmp("interpret", get_service(pb)))
		return handle_calls(pb);

	dstacksave = dstackcnt;
	for (i = pb->nargs - 1; i >= 0; i--)
		PUSH(pb->args[i]);

	push_str(get_service(pb));
	fword("client-iface");

	val = POP();
	if (val) {
		if (val == -1) {
			printk("Unimplemented service %s ([" FMT_prom_arg "] -- [" FMT_prom_arg "])\n",
				get_service(pb), pb->nargs, pb->nret);
		} else {
#ifdef DEBUG_CIF
			printk("Error calling client interface: " FMT_ucellx "\n", val);
#endif
		}

		dstackcnt = dstacksave;
		return -1;
	}

	j = dstackcnt;
	for (i = 0; i < pb->nret; i++, j--) {
		if (dstackcnt > dstacksave) {
			pb->args[pb->nargs + i] = POP();
		}
	}

#ifdef DEBUG_CIF
	if (j != dstacksave) {
		printk("service %s: possible argument error (%d %d)\n",
		       get_service(pb), i, j - dstacksave);

		/* Some clients request less parameters than the CIF method
		returns, e.g. getprop with OpenSolaris. Hence we drop any
		stack parameters on exit after issuing a warning above */
	}

	dump_return(pb);
#endif

	dstackcnt = dstacksave;
	return 0;
}
