/* tag: hosted forth environment, executable code
 *
 * Copyright (C) 2003-2005 Patrick Mauritz, Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#define __USE_LARGEFILE64
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>

#ifdef __GLIBC__
#define _GNU_SOURCE
#include <getopt.h>
#endif

#include "sysinclude.h"
#include "mconfig.h"
#include "config.h"
#include "kernel/kernel.h"
#include "dict.h"
#include "kernel/stack.h"
#include "arch/unix/plugins.h"
#include "libopenbios/bindings.h"
#include "libopenbios/console.h"
#include "libopenbios/openbios.h"
#include "openbios-version.h"

#include "blk.h"
#include "libopenbios/ofmem.h"

#define MEMORY_SIZE	(4*1024*1024)	/* 4M ram for hosted system */
#define DICTIONARY_SIZE	(256*1024)	/* 256k for the dictionary   */

#if defined(_FILE_OFFSET_BITS) && (_FILE_OFFSET_BITS==64)
#define lseek lseek64
#define __LFS O_LARGEFILE
#else
#define __LFS 0
#endif

/* prototypes */
static void exit_terminal(void);
void boot(void);

unsigned long virt_offset = 0;

/* local variables */

static ucell *memory;

static int diskemu;

static int segfault = 0;
static int verbose = 0;

#if defined(CONFIG_PPC) || defined(CONFIG_SPARC64)
unsigned long isa_io_base;
#endif

int errno_int;	/* implement for fs drivers, needed to build on Mac OS X */

ucell ofmem_claim(ucell addr, ucell size, ucell align)
{
    return 0;
}

#ifdef CONFIG_PPC
extern void flush_icache_range(char *start, char *stop);

void flush_icache_range(char *start, char *stop)
{
}
#endif

#ifdef CONFIG_PPC
/* Expose system level is_machine helpers to make generic code easier */

#include "drivers/drivers.h"
int is_apple(void)
{
    return 0;
}

int is_oldworld(void)
{
    return 0;
}

int is_newworld(void)
{
    return 0;
}
#endif

#if 0
static void write_dictionary(char *filename)
{
	FILE *f;
	xt_t initxt;

	initxt = findword("initialize-of");
	if (!initxt)
		printk("warning: dictionary needs word called initialize-of\n");

	f = fopen(filename, "w");
	if (!f) {
		printk("panic: can't open dictionary.\n");
		exit_terminal();
		exit(1);
	}

	fwrite(DICTID, 16, 1, f);
	fwrite(dict, dicthead, 1, f);

	/* Write start address and last to relocate on load */
	fwrite(&dict, sizeof(ucell), 1, f);
	fwrite(&last, sizeof(ucell), 1, f);

	fclose(f);

#ifdef CONFIG_DEBUG_DICTIONARY
	printk("wrote dictionary to file %s.\n", filename);
#endif
}
#endif

static ucell read_dictionary(char *fil)
{
	int ilen;
	ucell ret;
	char *mem;
	FILE *f;
	struct stat finfo;

	if (stat(fil, &finfo))
		return 0;

	ilen = finfo.st_size;

	if ((mem = malloc(ilen)) == NULL) {
		printk("panic: not enough memory.\n");
		exit_terminal();
		exit(1);
	}

	f = fopen(fil, "r");
	if (!f) {
		printk("panic: can't open dictionary.\n");
		exit_terminal();
		exit(1);
	}

	if (fread(mem, ilen, 1, f) != 1) {
		printk("panic: can't read dictionary.\n");
		fclose(f);
		exit_terminal();
		exit(1);
	}
	fclose(f);

	ret = load_dictionary(mem, ilen);

	free(mem);
	return ret;
}


/*
 * functions used by primitives
 */

static int unix_availchar(void)
{
	int tmp = getc(stdin);
	if (tmp != EOF) {
		ungetc(tmp, stdin);
		return -1;
	}
	return 0;
}

static int unix_putchar(int c)
{
	putc(c, stdout);
	return c;
}

static int unix_getchar(void)
{
	return getc(stdin);
}

static struct _console_ops unix_console_ops = {
	.putchar = unix_putchar,
	.availchar = unix_availchar,
	.getchar = unix_getchar
};

u8 inb(u32 reg)
{
#ifdef CONFIG_PLUGINS
	io_ops_t *ior = find_iorange(reg);
	if (ior)
		return ior->inb(reg);
#endif

	printk("TRAP: io byte read @0x%x", reg);
	return 0xff;
}

u16 inw(u32 reg)
{
#ifdef CONFIG_PLUGINS
	io_ops_t *ior = find_iorange(reg);
	if (ior)
		return ior->inw(reg);
#endif

	printk("TRAP: io word read @0x%x", reg);
	return 0xffff;
}

u32 inl(u32 reg)
{
#ifdef CONFIG_PLUGINS
	io_ops_t *ior = find_iorange(reg);
	if (ior)
		return ior->inl(reg);
#endif

	printk("TRAP: io long read @0x%x", reg);
	return 0xffffffff;
}

void outb(u32 reg, u8 val)
{
#ifdef CONFIG_PLUGINS
	io_ops_t *ior = find_iorange(reg);
	if (ior) {
		ior->outb(reg, val);
		return;
	}
#endif

	printk("TRAP: io byte write 0x%x -> 0x%x", val, reg);
}

void outw(u32 reg, u16 val)
{
#ifdef CONFIG_PLUGINS
	io_ops_t *ior = find_iorange(reg);
	if (ior) {
		ior->outw(reg, val);
		return;
	}
#endif
	printk("TRAP: io word write 0x%x -> 0x%x", val, reg);
}

void outl(u32 reg, u32 val)
{
#ifdef CONFIG_PLUGINS
	io_ops_t *ior = find_iorange(reg);
	if (ior) {
		ior->outl(reg, val);
		return;
	}
#endif
	printk("TRAP: io long write 0x%x -> 0x%x", val, reg);
}

/*
 * terminal initialization and cleanup.
 */

static struct termios saved_termios;

static void init_terminal(void)
{
	struct termios termios;

	tcgetattr(0, &saved_termios);
	tcgetattr(0, &termios);
	termios.c_lflag &= ~(ICANON | ECHO);
        termios.c_cc[VMIN] = 1;
        termios.c_cc[VTIME] = 3; // 300 ms
	tcsetattr(0, 0, &termios);
}

static void exit_terminal(void)
{
	tcsetattr(0, 0, &saved_termios);
}

/*
 *  segmentation fault handler. linux specific?
 */

static void
segv_handler(int signo __attribute__ ((unused)),
	     siginfo_t * si, void *context __attribute__ ((unused)))
{
	static int count = 0;
	ucell addr = 0xdeadbeef;

	if (count) {
		printk("Died while dumping forth dictionary core.\n");
		goto out;
	}

	count++;

	if (PC >= (ucell) dict && PC <= (ucell) dict + dicthead)
		addr = *(ucell *) PC;

	printk("panic: segmentation violation at %x\n", (ucell)si->si_addr);
	printk("dict=0x%x here=0x%x(dict+0x%x) pc=0x%x(dict+0x%x)\n",
	       (ucell)dict, (ucell)dict + dicthead, dicthead, PC, PC - (ucell) dict);
	printk("dstackcnt=%d rstackcnt=%d instruction=%x\n",
	       dstackcnt, rstackcnt, addr);

#ifdef CONFIG_DEBUG_DSTACK
	printdstack();
#endif
#ifdef CONFIG_DEBUG_RSTACK
	printrstack();
#endif
#if 0
	printk("Writing dictionary core file\n");
	write_dictionary("forth.dict.core");
#endif

      out:
	exit_terminal();
	exit(1);
}

/*
 *  Interrupt handler. linux specific?
 *  Restore terminal state on ctrl-C.
 */

static void
int_handler(int signo __attribute__ ((unused)),
            siginfo_t * si __attribute__ ((unused)),
            void *context __attribute__ ((unused)))
{
    printk("\n");
    exit_terminal();
    exit(1);
}

/*
 * allocate memory and prepare engine for memory management.
 */

static void init_memory(void)
{
	memory = malloc(MEMORY_SIZE);
	if (!memory) {
		printk("panic: not enough memory on host system.\n");
		exit_terminal();
		exit(1);
	}

	memset (memory, 0, MEMORY_SIZE);
	/* we push start and end of memory to the stack
	 * so that it can be used by the forth word QUIT
	 * to initialize the memory allocator
	 */

	PUSH((ucell) memory);
	PUSH((ucell) memory + MEMORY_SIZE);
}

void exception(__attribute__((unused)) cell no)
{
	/*
	 * this is a noop since the dictionary has to take care
	 * itself of errors it generates outside of the bootstrap
	 */
}

static void
arch_init( void )
{
	openbios_init();
	modules_init();
	if(diskemu!=-1)
		blk_init();

	device_end();
        bind_func("platform-boot", boot);
}

int
read_from_disk( int channel, int unit, int blk, unsigned long mphys, int size )
{
	// channels and units not supported yet.
	unsigned char *buf=(unsigned char *)mphys;

	if(diskemu==-1)
		return -1;

	//printk("read: ch=%d, unit=%d, blk=%ld, phys=%lx, size=%d\n",
	//		channel, unit, blk, mphys, size);

	lseek(diskemu, (ducell)blk*512, SEEK_SET);
	read(diskemu, buf, size);

	return 0;
}

/*
 * main loop
 */

#define BANNER	"OpenBIOS core. (C) 2003-2006 Patrick Mauritz, Stefan Reinauer\n"\
		"This software comes with absolutely no warranty. "\
		"All rights reserved.\n\n"


#define USAGE   "usage: %s [options] [dictionary file|source file]\n\n"

int main(int argc, char *argv[])
{
	struct sigaction sa;
#if 0
	unsigned char *dictname = NULL;
#endif
	int c;

	const char *optstring = "VvhsD:P:p:f:?";

	while (1) {
#ifdef __GLIBC__
		int option_index = 0;
		static struct option long_options[] = {
			{"version", 0, NULL, 'V'},
			{"verbose", 0, NULL, 'v'},
			{"help", 0, NULL, 'h'},
//			{"dictionary", 1, NULL, 'D'},
			{"segfault", 0, NULL, 's'},
#ifdef CONFIG_PLUGINS
			{"plugin-path", 1, NULL, 'P'},
			{"plugin", 1, NULL, 'p'},
#endif
			{"file", 1, NULL, 'f'}
		};

		c = getopt_long(argc, argv, optstring, long_options,
				&option_index);
#else
		c = getopt(argc, argv, optstring);
#endif
		if (c == -1)
			break;

		switch (c) {
		case 'V':
                        printk(BANNER "Version " OPENBIOS_VERSION_STR "\n");
			return 0;
		case 'h':
		case '?':
                        printk(BANNER "Version " OPENBIOS_VERSION_STR "\n"
                               USAGE, argv[0]);
			return 0;
		case 'v':
			verbose = 1;
			break;
		case 's':
			segfault = 1;
			break;
#if 0
		case 'D':
			printk("Dumping final dictionary to '%s'\n", optarg);
			dictname = optarg;
			break;
#endif
#ifdef CONFIG_PLUGINS
		case 'P':
			printk("Plugin search path is now '%s'\n", optarg);
			plugindir = optarg;
			break;
		case 'p':
			printk("Loading plugin %s\n", optarg);
			load_plugin(optarg);
			break;
#endif
		case 'f':
			diskemu=open(optarg, O_RDONLY|__LFS);
			if(diskemu!=-1)
				printk("Using %s as harddisk.\n", optarg);
			else
				printk("%s not found. no harddisk node.\n",
						optarg);
			break;
		default:
			return 1;
		}
	}

	if (argc < optind + 1) {
		printk(USAGE, argv[0]);
		return 1;
	}

	/* Initialise console */
	init_console(unix_console_ops);

	if ((dict = (unsigned char *) malloc(DICTIONARY_SIZE)) == NULL) {
		printk("panic: not enough memory.\n");
		return 1;
	}

	dictlimit = DICTIONARY_SIZE;
	memset(dict, 0, DICTIONARY_SIZE);

	if (!segfault) {
		if (verbose)
			printk("Installing SIGSEGV handler...");

		sa.sa_sigaction = segv_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO | SA_NODEFER;
		sigaction(SIGSEGV, &sa, NULL);

		if (verbose)
			printk("done.\n");
	}

	/* set terminal to do non blocking reads */
	init_terminal();

        if (verbose)
            printk("Installing SIGINT handler...");

        sa.sa_sigaction = int_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(SIGINT, &sa, NULL);

        if (verbose)
            printk("done.\n");

	read_dictionary(argv[optind]);
	forth_init();

	PUSH_xt( bind_noname_func(arch_init) );
	fword("PREPOST-initializer");

	PC = (cell)findword("initialize-of");
	if (PC) {
		if (verbose) {
			if (optind + 1 != argc)
				printk("Warning: only first dictionary used.\n");

			printk("dictionary loaded (%d bytes).\n", dicthead);
			printk("Initializing memory...");
		}
		init_memory();

		if (verbose) {
			printk("done\n");

			printk("Jumping to dictionary...");
		}

		enterforth((xt_t)PC);
#if 0
		if (dictname != NULL)
			write_dictionary(dictname);
#endif

		free(memory);

	} else {		/* input file is not a dictionary */
		printk("not supported.\n");
	}

	exit_terminal();
	if (diskemu!=-1)
		close(diskemu);

	free(dict);
	return 0;
}

#undef printk
int
printk( const char *fmt, ... )
{
	int i;

	va_list args;
	va_start( args, fmt );
	i = vprintf(fmt, args );
	va_end( args );
	return i;
}
