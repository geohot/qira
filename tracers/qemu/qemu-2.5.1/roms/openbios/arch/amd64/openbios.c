/* tag: openbios forth environment, executable code
 *
 * Copyright (C) 2003 Patrick Mauritz, Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "libopenbios/openbios.h"
#include "libopenbios/bindings.h"
#include "asm/types.h"
#include "dict.h"
#include "kernel/kernel.h"
#include "kernel/stack.h"
#include "libopenbios/sys_info.h"
#include "openbios.h"
#include "relocate.h"

void boot(void);

#define DICTIONARY_SIZE (256*1024)      /* 256K for the dictionary   */
static char intdict[DICTIONARY_SIZE];

static void init_memory(void)
{
	/* push start and end of available memory to the stack
	 * so that the forth word QUIT can initialize memory
	 * management. For now we use hardcoded memory between
	 * 0x10000 and 0x9ffff (576k). If we need more memory
	 * than that we have serious bloat.
	 */

	PUSH(0x10000);
	PUSH(0x9FFFF);
}

static void
arch_init( void )
{
	void setup_timers(void);

	openbios_init();
	modules_init();
#ifdef CONFIG_DRIVER_IDE
	setup_timers();
	ob_ide_init("/pci/pci-ata", 0x1f0, 0x3f6, 0x170, 0x376);
#endif
	device_end();
	bind_func("platform-boot", boot );
}

extern struct _console_ops arch_console_ops;

int openbios(void)
{
#ifdef CONFIG_DEBUG_CONSOLE
	init_console(arch_console_ops);
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	uart_init(CONFIG_SERIAL_PORT, CONFIG_SERIAL_SPEED);
#endif
	/* Clear the screen.  */
	cls();
#endif

        collect_sys_info(&sys_info);

	dict=intdict;
	dictlimit = DICTIONARY_SIZE;

	load_dictionary((char *)sys_info.dict_start,
			sys_info.dict_end-sys_info.dict_start);
	forth_init();

	relocate(&sys_info);

#ifdef CONFIG_DEBUG_CONSOLE
	video_init();
#endif
#ifdef CONFIG_DEBUG_BOOT
	printk("forth started.\n");
	printk("initializing memory...");
#endif

	init_memory();

#ifdef CONFIG_DEBUG_BOOT
	printk("done\n");
#endif

	PUSH_xt( bind_noname_func(arch_init) );
	fword("PREPOST-initializer");

	PC = (ucell)findword("initialize-of");

	if (!PC) {
		printk("panic: no dictionary entry point.\n");
		return -1;
	}
#ifdef CONFIG_DEBUG_DICTIONARY
	printk("done (%d bytes).\n", dicthead);
	printk("Jumping to dictionary...\n");
#endif

	enterforth((xt_t)PC);

	return 0;
}
