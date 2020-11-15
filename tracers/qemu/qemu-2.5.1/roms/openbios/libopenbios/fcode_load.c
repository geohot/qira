/*
 * FCode boot loader
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/bindings.h"
#include "libopenbios/fcode_load.h"
#include "libopenbios/sys_info.h"
#include "libc/diskio.h"
#define printf printk
#define debug printk

static int fd;

int 
is_fcode(unsigned char *fcode)
{
	return (fcode[0] == 0xf0	// start0
		|| fcode[0] == 0xf1	// start1 
		|| fcode[0] == 0xf2	// start2
		|| fcode[0] == 0xf3	// start4
		|| fcode[0] == 0xfd);	// version1
}

int 
fcode_load(ihandle_t dev)
{
    int retval = -1;
    uint8_t fcode_header[8];
    unsigned long start, size;
    unsigned int offset;

    /* Mark the saved-program-state as invalid */
    feval("0 state-valid !");

    fd = open_ih(dev);
    if (fd == -1) {
        goto out;
    }

    for (offset = 0; offset < 16 * 512; offset += 512) {
        seek_io(fd, offset);
        if (read_io(fd, &fcode_header, sizeof(fcode_header))
            != sizeof(fcode_header)) {
            debug("Can't read FCode header from ihandle " FMT_ucellx "\n", dev);
            retval = LOADER_NOT_SUPPORT;
            goto out;
        }

	if (is_fcode(fcode_header))
            goto found;
    }

    debug("Not a bootable FCode image\n");
    retval = LOADER_NOT_SUPPORT;
    goto out;

 found:
    size = (fcode_header[4] << 24) | (fcode_header[5] << 16) |
        (fcode_header[6] << 8) | fcode_header[7];

    fword("load-base");
    start = POP();

    printf("\nLoading FCode image...\n");

    seek_io(fd, offset);

    if ((size_t)read_io(fd, (void *)start, size) != size) {
        printf("Can't read file (size 0x%lx)\n", size);
        goto out;
    }

    debug("Loaded %lu bytes\n", size);
    debug("entry point is %#lx\n", start);
    
    // Initialise saved-program-state
    PUSH(start);
    feval("saved-program-state >sps.entry !");
    PUSH(size);
    feval("saved-program-state >sps.file-size !");
    feval("fcode saved-program-state >sps.file-type !");

    feval("-1 state-valid !");

out:
    close_io(fd);
    return retval;
}

void 
fcode_init_program(void)
{
	/* If the payload is Fcode then we execute it immediately */
	ucell address;

	fword("load-base");
	address = POP();

	if (!is_fcode((unsigned char *)address)) {
		debug("Not a valid Fcode memory image\n");
		return;
	}

	PUSH(address);
	PUSH(1);
	fword("byte-load");
}
