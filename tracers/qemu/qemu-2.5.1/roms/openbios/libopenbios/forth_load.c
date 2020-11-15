/* tag: forth source loader
 *
 * Copyright (C) 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/bindings.h"
#include "libopenbios/sys_info.h"
#include "libc/diskio.h"
#include "libopenbios/forth_load.h"
#define printk printk
#define debug printk

static int fd;
static char *forthtext=NULL;

int is_forth(char *forth)
{
	return (forth[0] == '\\' && forth[1] == ' ');
}

int forth_load(ihandle_t dev)
{
    char magic[2];
    unsigned long forthsize;
    int retval = -1;

    /* Mark the saved-program-state as invalid */
    feval("0 state-valid !");

    fd = open_ih(dev);
    if (fd == -1) {
	goto out;
    }

    if (read_io(fd, magic, 2) != 2) {
	debug("Can't read magic header\n");
	retval = LOADER_NOT_SUPPORT;
	goto out;
    }

    if (!is_forth(magic)) {
	debug("No forth source image\n");
	retval = LOADER_NOT_SUPPORT;
	goto out;
    }

    /* Calculate the file size by seeking to the end of the file */
    seek_io(fd, -1);
    forthsize = tell(fd);
    forthtext = malloc(forthsize+1);
    seek_io(fd, 0);

    printk("Loading forth source ...");
    if ((size_t)read_io(fd, forthtext, forthsize) != forthsize) {
	printk("Can't read forth text\n");
	goto out;
    }
    forthtext[forthsize]=0;
    printk("ok\n");

    // Initialise saved-program-state
    PUSH((ucell)forthtext);
    feval("saved-program-state >sps.entry !");
    PUSH((ucell)forthsize);
    feval("saved-program-state >sps.file-size !");
    feval("forth saved-program-state >sps.file-type !");

    feval("-1 state-valid !");

    retval=0;

out:
    //if (forthtext)
    //	free(forthtext);
    return retval;
}

void 
forth_init_program(void)
{
	// Currently not implemented
	feval("0 state-valid !");
}
