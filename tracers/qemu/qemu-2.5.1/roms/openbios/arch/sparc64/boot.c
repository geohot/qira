/*
 *
 */
#undef BOOTSTRAP
#include "config.h"
#include "libopenbios/bindings.h"
#include "arch/common/nvram.h"
#include "libc/diskio.h"
#include "libc/vsprintf.h"
#include "libopenbios/sys_info.h"
#include "boot.h"

uint64_t kernel_image;
uint64_t kernel_size;
uint64_t qemu_cmdline;
uint64_t cmdline_size;
char boot_device;

extern int sparc64_of_client_interface( int *params );


void go(void)
{
	ucell address, type, size;
	int image_retval = 0;

	/* Get the entry point and the type (see forth/debugging/client.fs) */
	feval("saved-program-state >sps.entry @");
	address = POP();
	feval("saved-program-state >sps.file-type @");
	type = POP();
	feval("saved-program-state >sps.file-size @");
	size = POP();

	printk("\nJumping to entry point " FMT_ucellx " for type " FMT_ucellx "...\n", address, type);

	switch (type) {
		case 0x0:
			/* Start ELF boot image */
			image_retval = start_elf(address, (uint64_t)&elf_boot_notes);
			break;

		case 0x1:
			/* Start ELF image */
			image_retval = start_client_image(address, (uint64_t)&sparc64_of_client_interface);
			break;

		case 0x5:
			/* Start a.out image */
			image_retval = start_client_image(address, (uint64_t)&sparc64_of_client_interface);
			break;

		case 0x10:
			/* Start Fcode image */
			printk("Evaluating FCode...\n");
			PUSH(address);
			PUSH(1);
			fword("byte-load");
			image_retval = 0;
			break;

		case 0x11:
			/* Start Forth image */
			PUSH(address);
			PUSH(size);
			fword("eval2");
			image_retval = 0;
			break;
	}

	printk("Image returned with return value %#x\n", image_retval);
}

/* ( path len -- path len ) */

void boot(void)
{
	char *path, *param;

	/* Copy the incoming path */
	fword("2dup");
	path = pop_fstr_copy();

	/* Boot preloaded kernel */
        if (kernel_size) {
            void (*entry)(unsigned long p1, unsigned long p2, unsigned long p3,
                          unsigned long p4, unsigned long p5);

            printk("[sparc64] Kernel already loaded\n");
            entry = (void *) (unsigned long)kernel_image;
            entry(0, 0, 0, 0, (unsigned long)&sparc64_of_client_interface);
        }

	/* Invoke Linux directly -- probably not supported */
	if(!path) {
            /* No path specified, so grab defaults from /chosen */
            push_str("bootpath");
	    push_str("/chosen");
            fword("(find-dev)");
            POP();
            fword("get-package-property");
            POP();
	    /* Update our local copy of path as well as the one on the stack */
	    fword("2dup");
            path = pop_fstr_copy();
	}

        if (path) {
            param = strchr(path, ' ');
            if(param) {
                *param = '\0';
                param++;
            } else if (cmdline_size) {
                param = (char *)qemu_cmdline;
            } else {
                push_str("boot-args");
                push_str("/options");
                fword("(find-dev)");
                POP();
                fword("get-package-property");
                POP();
                param = pop_fstr_copy();
            }

            /* Invoke platform-specific Linux loader */
            linux_load(&sys_info, path, param);

            free(path);
        }
}
